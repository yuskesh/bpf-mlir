//===- VerifyKPtr.cpp - match kernel pointers/fields with BTF declarations ---===//
//
// kptr<S> names btf.struct S in btf.scope @kernel, generated from schema
// kernel_types. kfield.load members must exist with matching integer widths.
// Signless MLIR integers cannot express signedness: kfield requirements and
// load-time CheckKFields own that check.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h"

#include "bpf-mlir/Dialect/BTF/IR/BTFDialect.h"
#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"
#include "bpf-mlir/Dialect/EBPF/Transforms/RecordPath.h"
#include "bpf-mlir/Support/KernelFieldPath.h"

#include "llvm/ADT/SetVector.h"

namespace mlir {
namespace ebpf {
#define GEN_PASS_DEF_EBPFVERIFYKPTR
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h.inc"
} // namespace ebpf
} // namespace mlir

using namespace mlir;
using namespace mlir::ebpf;

namespace {

struct EBPFVerifyKPtrPass : public mlir::ebpf::impl::EBPFVerifyKPtrBase<EBPFVerifyKPtrPass> {
  void runOnOperation() override {
    ModuleOp module = getOperation();
    btf::ScopeOp kernel, records;
    for (auto sc : module.getOps<btf::ScopeOp>()) {
      if (sc.getSymName() == "kernel")
        kernel = sc;
      if (sc.getSymName() == "records")
        records = sc;
    }
    auto lookup = [&](StringRef name) -> btf::StructOp {
      if (!kernel)
        return nullptr;
      return dyn_cast_or_null<btf::StructOp>(SymbolTable::lookupSymbolIn(kernel, name));
    };
    bool bad = false;
    auto pathMember = [&](Operation *op, btf::StructOp st, StringRef path) -> btf::MemberAttr {
      if (!bpfmlir::validKernelFieldPath(path)) {
        bad = true; op->emitOpError("kernel field path must have 1 to 3 identifier segments"); return {};
      }
      SmallVector<StringRef> parts;
      path.split(parts, '.', -1, true);
      btf::MemberAttr member;
      for (auto [i, part] : llvm::enumerate(parts)) {
        member = {};
        for (Attribute a : st.getMembers())
          if (cast<btf::MemberAttr>(a).getName() == part) member = cast<btf::MemberAttr>(a);
        if (!member) return {};
        if (i + 1 < parts.size()) {
          auto ref = dyn_cast<btf::RefAttr>(member.getType());
          st = ref ? lookup(ref.getTarget().getLeafReference()) : btf::StructOp();
          if (!st) {
            bad = true; op->emitOpError() << "intermediate kernel field \"" << part << "\" must be an embedded kernel struct"; return {};
          }
        }
      }
      return member;
    };
    auto checkKPtr = [&](Operation *op, KPtrType kp) -> btf::StructOp {
      btf::StructOp st = lookup(kp.getStructName());
      if (!st) {
        bad = true;
        op->emitOpError() << "kernel type \"" << kp.getStructName()
                          << "\" has no declaration btf.struct @kernel::@" << kp.getStructName()
                          << " (schema core.kernel_types)";
      }
      return st;
    };
    module.walk([&](Operation *op) {
      if (auto addr = dyn_cast<KPtrAddrOp>(op)) {
        Type t = addr.getPtr().getType();
        StringRef name = isa<KRefType>(t) ? cast<KRefType>(t).getStructName() : cast<KPtrType>(t).getStructName();
        checkKPtr(op, KPtrType::get(op->getContext(), name));
        return;
      }
      if (auto arg = dyn_cast<CtxArgOp>(op)) {
        if (auto kp = dyn_cast<KPtrType>(arg.getResult().getType())) // Integer arguments are not kernel pointers.
          checkKPtr(op, kp);
        else if (auto kn = dyn_cast<KPtrOrNullType>(arg.getResult().getType()))
          checkKPtr(op, KPtrType::get(op->getContext(), kn.getStructName()));
        return;
      }
      // Context struct-pointer fields (netfilter state/skb) require S in @kernel.
      if (auto cf = dyn_cast<CtxFieldOp>(op)) {
        if (auto kp = dyn_cast<KPtrType>(cf.getResult().getType()))
          checkKPtr(op, kp);
        return;
      }
      // kfield.copy requires N eight-bit integer elements on both the kernel
      // member and the destination record path's one-dimensional array.
      if (auto kc = dyn_cast<KFieldCopyOp>(op)) {
        btf::StructOp st = checkKPtr(op, kc.getPtr().getType());
        if (!st)
          return;
        btf::MemberAttr member = pathMember(op, st, kc.getField());
        auto arr = member ? dyn_cast<btf::ArrayOfAttr>(member.getType()) : btf::ArrayOfAttr();
        auto el = arr ? dyn_cast<btf::IntAttr>(arr.getElement()) : btf::IntAttr();
        if (!el || el.getBits() != 8) {
          bad = true;
          kc.emitOpError() << "field \"" << st.getSymName() << "." << kc.getField()
                           << "\" is not an array of 8-bit integers in btf.struct @kernel::@" << st.getSymName()
                           << " (schema core.kernel_types — {\"kind\": \"array\", \"count\": N, \"element\": {int 8}})";
          return;
        }
        RecordType rt = kc.getDstRecord(); // Borrowed or reserved record; the op verifier guarantees record type.
        auto rst = records ? dyn_cast_or_null<btf::StructOp>(SymbolTable::lookupSymbolIn(records, rt.getSymbol())) : btf::StructOp();
        std::string err;
        FailureOr<RecordTemplate> t = rst ? resolveRecordTemplate(records, rst, indexTemplate(kc.getPath()), err)
                                          : FailureOr<RecordTemplate>(failure());
        if (failed(t) || t->dims.size() != 1 || t->bits != 8 || t->dims[0].count != arr.getCount()) {
          bad = true;
          kc.emitOpError() << "destination \"" << kc.getPath() << "\" of record \"" << rt.getSymbol()
                           << "\" must be a one-dimensional array of " << arr.getCount()
                           << " 8-bit integers (the length of the kernel field \"" << kc.getField() << "\")"
                           << (err.empty() ? "" : " — " + err);
        }
        return;
      }
      // kernel.read_str requires char*: BTF PTR -> eight-bit INT.
      if (auto rs = dyn_cast<KernelReadStrOp>(op)) {
        btf::StructOp st = checkKPtr(op, rs.getPtr().getType());
        if (!st)
          return;
        btf::MemberAttr member = pathMember(op, st, rs.getField());
        auto pt = member ? dyn_cast<btf::PtrAttr>(member.getType()) : btf::PtrAttr();
        auto ci = pt ? dyn_cast<btf::IntAttr>(pt.getPointee()) : btf::IntAttr();
        if (!ci || ci.getBits() != 8) {
          bad = true;
          rs.emitOpError() << "field \"" << st.getSymName() << "." << rs.getField()
                           << "\" is not a char * (strptr) field in btf.struct @kernel::@" << st.getSymName()
                           << " (schema core.kernel_types — {\"kind\": \"strptr\"})";
        }
        return;
      }
      // kfield.ptr requires S's member to point to @kernel::T and returns kptr_or_null<T>.
      if (auto kf = dyn_cast<KFieldPtrOp>(op)) {
        btf::StructOp st = checkKPtr(op, cast<KPtrType>(kf.getPtr().getType()));
        if (!st)
          return;
        btf::MemberAttr member = pathMember(op, st, kf.getField());
        auto want = cast<KPtrOrNullType>(kf.getResult().getType()).getStructName();
        auto pt = member ? dyn_cast<btf::PtrAttr>(member.getType()) : btf::PtrAttr();
        auto ref = pt ? dyn_cast<btf::RefAttr>(pt.getPointee()) : btf::RefAttr();
        if (!ref || ref.getTarget().getLeafReference() != want) {
          bad = true;
          kf.emitOpError() << "field \"" << st.getSymName() << "." << kf.getField()
                           << "\" is not a pointer to kernel type \"" << want
                           << "\" in btf.struct @kernel::@" << st.getSymName() << " (schema core.kernel_types — {\"kind\": \"kptr\", \"struct\": \"" << want << "\"})";
        }
        return;
      }
      // kfield.store matches an integer member's width with the stored value.
      if (auto ks = dyn_cast<KFieldStoreOp>(op)) {
        if (ks.getField().contains('.')) { bad = true; ks.emitOpError("nested kernel stores are not supported"); return; }
        btf::StructOp st = checkKPtr(op, cast<KPtrType>(ks.getPtr().getType()));
        if (!st)
          return;
        btf::MemberAttr member;
        for (Attribute a : st.getMembers())
          if (cast<btf::MemberAttr>(a).getName() == ks.getField())
            member = cast<btf::MemberAttr>(a);
        if (!member) {
          bad = true;
          ks.emitOpError() << "btf.struct @kernel::@" << st.getSymName() << " has no field \"" << ks.getField() << "\" (schema core.kernel_types)";
          return;
        }
        auto it = dyn_cast<btf::IntAttr>(member.getType());
        unsigned w = cast<IntegerType>(ks.getValue().getType()).getWidth();
        if (!it || it.getBits() != w) {
          bad = true;
          ks.emitOpError() << "field \"" << st.getSymName() << "." << member.getName() << "\" is " << member.getType()
                           << " in btf.struct @kernel::@" << st.getSymName() << " but written as " << ks.getValue().getType();
        }
        return;
      }
      // kfunc kref/kref_or_null argument and result structs must be declared in
      // @kernel: ObjectEmitter represents FUNC_PROTO struct pointers with
      // local CO-RE types. kptr arguments were checked at ctx.arg or their origin.
      if (isa<KfuncCallOp, KPtrXchgOp>(op)) { // Include the new reference and result type of kptr.xchg.
        auto structOf = [](Type t) -> StringRef {
          if (auto r = dyn_cast<KRefType>(t))
            return r.getStructName();
          if (auto r = dyn_cast<KRefOrNullType>(t))
            return r.getStructName();
          return {};
        };
        SmallVector<Type> tys(op->getOperandTypes());
        tys.append(op->getResultTypes().begin(), op->getResultTypes().end());
        llvm::SmallSetVector<StringRef, 2> names; // Diagnose each struct once; acquire may share its argument and result type.
        for (Type t : tys)
          if (StringRef s = structOf(t); !s.empty())
            names.insert(s);
        for (StringRef s : names)
          checkKPtr(op, KPtrType::get(op->getContext(), s));
        return;
      }
      auto ld = dyn_cast<KFieldLoadOp>(op);
      if (!ld)
        return;
      // Reads from acquired kref values use the same matching rules.
      Type pt = ld.getPtr().getType();
      btf::StructOp st = checkKPtr(op, isa<KRefType>(pt) ? KPtrType::get(op->getContext(), cast<KRefType>(pt).getStructName())
                                                         : cast<KPtrType>(pt));
      if (!st)
        return;
      btf::MemberAttr member = pathMember(op, st, ld.getField());
      if (!member) {
        bad = true;
        ld.emitOpError() << "btf.struct @kernel::@" << st.getSymName() << " has no field \""
                         << ld.getField() << "\" (schema core.kernel_types)";
        return;
      }
      auto it = dyn_cast<btf::IntAttr>(member.getType());
      unsigned w = cast<IntegerType>(ld.getResult().getType()).getWidth();
      if (!it || it.getBits() != w) {
        bad = true;
        ld.emitOpError() << "field \"" << st.getSymName() << "." << member.getName() << "\" is "
                         << member.getType() << " in btf.struct @kernel::@" << st.getSymName()
                         << " but read as " << ld.getResult().getType();
      }
    });
    if (bad)
      signalPassFailure();
  }
};

} // namespace
