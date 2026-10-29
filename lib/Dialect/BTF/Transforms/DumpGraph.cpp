//===- DumpGraph.cpp - compare intended BTF IR with emitted ELF types --------===//
//
// Print roots in the btfgraph format used to read ELF BTF, permitting
// structural comparison through lowering. Reflect BPF backend conventions:
// array index is unsigned four-byte __ARRAY_SIZE_TYPE__, char is signed INT,
// and linkage follows the emitted globals/functions. DATASEC sizes/offsets
// are loader-filled, so omit them on both sides and compare variable order.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/BTF/Transforms/Passes.h"

#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"

#include <map>

namespace mlir {
namespace btf {
#define GEN_PASS_DEF_BTFDUMPGRAPH
#include "bpf-mlir/Dialect/BTF/Transforms/Passes.h.inc"
} // namespace btf
} // namespace mlir

using namespace mlir;
using namespace mlir::btf;

namespace {

struct Dumper {
  ModuleOp module;

  std::string intDesc(StringRef name, uint64_t bits, StringRef enc) {
    StringRef e = enc == "unsigned" ? "unsigned" : "signed"; // LLVM BTF treats char as signed.
    return ("int(\"" + name + "\"," + Twine(bits / 8) + "," + e + ")").str();
  }
  std::string body(uint64_t sizeBits, ArrayRef<MemberAttr> ms) {
    std::string parts;
    for (auto [i, m] : llvm::enumerate(ms)) {
      if (i)
        parts += " ";
      parts += (m.getName() + "@" + Twine(m.getOffsetBits()) + ":" + desc(m.getType())).str();
    }
    return "struct{size=" + std::to_string(sizeBits / 8) + " " + parts + "}";
  }
  std::string desc(Attribute t) {
    if (isa<VoidAttr>(t))
      return "void";
    if (auto i = dyn_cast<IntAttr>(t))
      return intDesc(i.getName(), i.getBits(), i.getEncoding());
    if (auto p = dyn_cast<PtrAttr>(t))
      return "*" + desc(p.getPointee());
    if (auto c = dyn_cast<ConstAttr>(t))
      return "const " + desc(c.getBase());
    if (auto tt = dyn_cast<TypeTagAttr>(t))
      return ("type_tag(" + tt.getTag() + ") ").str() + desc(tt.getBase());
    if (auto a = dyn_cast<ArrayOfAttr>(t))
      return "[" + std::to_string(a.getCount()) + "]" + desc(a.getElement()) + "{index=" +
             intDesc("__ARRAY_SIZE_TYPE__", 32, "unsigned") + "}";
    if (auto r = dyn_cast<RefAttr>(t))
      return ("struct " + r.getTarget().getLeafReference().getValue()).str();
    if (auto s = dyn_cast<AnonStructAttr>(t))
      return body(s.getSizeBits(), s.getMembers());
    return "?";
  }
  std::string structBody(StructOp st) {
    SmallVector<MemberAttr> ms;
    for (Attribute a : st.getMembers())
      ms.push_back(cast<MemberAttr>(a));
    return body(st.getSizeBits(), ms);
  }

  std::vector<std::string> roots() {
    std::vector<std::string> out;
    std::map<std::string, std::vector<std::string>> secs; // Section -> ordered variables.
    std::vector<std::string> secOrder;
    module.walk([&](Operation *op) {
      if (auto st = dyn_cast<StructOp>(op))
        out.push_back(("struct " + st.getSymName() + " = " + structBody(st)).str());
      else if (auto f = dyn_cast<FuncOp>(op)) {
        std::string ps;
        for (auto [i, a] : llvm::enumerate(f.getParams())) {
          auto p = cast<ParamAttr>(a);
          if (i)
            ps += ", ";
          ps += (p.getName() + ":" + desc(p.getType())).str();
        }
        // Match btfgraph argtags=index:tag spelling, including FUNC/argument associations.
        std::string at;
        for (auto [i, a] : llvm::enumerate(f.getParams()))
          if (ArrayAttr ts = cast<ParamAttr>(a).getTags())
            for (Attribute t : ts)
              at += (at.empty() ? " argtags=" : ",") + std::to_string(i) + ":" +
                    cast<StringAttr>(t).getValue().str();
        out.push_back(("func " + f.getSymName() + " linkage=" + f.getLinkage() + " = fn(" + ps + ") " +
                       desc(f.getResult()) + at)
                          .str());
      } else if (auto v = dyn_cast<VarOp>(op)) {
        out.push_back(("var " + v.getSymName() + " linkage=global = " + desc(v.getType())).str());
        std::string s = v.getSection().str();
        if (!secs.count(s))
          secOrder.push_back(s);
        secs[s].push_back(v.getSymName().str());
      }
    });
    for (const std::string &s : secOrder) {
      std::string line = "datasec " + s + " {";
      for (auto [i, n] : llvm::enumerate(secs[s]))
        line += (i ? " " : "") + n;
      out.push_back(line + "}");
    }
    std::sort(out.begin(), out.end());
    return out;
  }
};

struct BTFDumpGraphPass : public mlir::btf::impl::BTFDumpGraphBase<BTFDumpGraphPass> {
  using Base::Base;
  void runOnOperation() override {
    Dumper d{getOperation()};
    std::string text = "# .BTF (roots, independent of type IDs)\n";
    for (const std::string &r : d.roots())
      text += r + "\n";
    if (out == "-") {
      llvm::outs() << text;
      return;
    }
    std::error_code ec;
    llvm::raw_fd_ostream os(out, ec, llvm::sys::fs::OF_Text);
    if (ec) {
      getOperation().emitError() << "cannot write " << out << ": " << ec.message();
      return signalPassFailure();
    }
    os << text;
  }
};

} // namespace
