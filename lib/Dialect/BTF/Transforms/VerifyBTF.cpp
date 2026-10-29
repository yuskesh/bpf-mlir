//===- VerifyBTF.cpp - kernel and loader BTF rule checks ---------------------===//
//
// Kernel rules follow kernel/bpf/btf.c (7.1.8; corresponding checks also in
// 6.12.111/6.6.157). Rule IDs remain stable for diagnostics.
// K1: named structs, members, FUNC/VAR/argument names match
//     [A-Za-z_.][A-Za-z0-9_.]*, at most 512 characters
//     (btf_name_valid_identifier).
// K2: FUNC arguments require names, static or global (btf_func_check).
// K3: struct member bit offsets cannot decrease (btf_struct_check_meta).
// K4: offset+member size must fit the struct (btf_struct_check_meta/resolve).
// K5: VAR linkage is static/global_allocated (btf_var_check_meta); compiler
//     emits only global_allocated.
// K6: global generic integer/struct pointer args cannot use arg:nullable.
// K7: supported arg tags are ctx/trusted/untrusted/nonnull/nullable/arena.
// K8: pointer tags require pointer arguments. K6..K8 follow btf_prepare_func_args;
//     6.6.157 ignores arg: semantics.
// K9: map-definition array byte sizes must fit U32_MAX (btf_array_resolve).
//     For int (*max_entries)[N], N <= 1073741823; this also rejects 2^30-byte
//     ring buffers. Restrict this rule to map-definition members.
//
// Loader contracts: L1 fills zero DATASEC sizes/VAR offsets from ELF; kernel
// rejects size zero. L2 requires anonymous .maps structs with pointer members
// type/max_entries and optional key/value. L3 requires FUNC/func_info for each
// program definition.
//
// Compiler rules: C1 allows 8/16/32/64-bit integers; C2 requires nonempty unique
// member names (kernel accepts unnamed/duplicate members); C3 requires nonempty
// arrays; C4 permits void only as pointee; C5 rejects ignored static argument
// tags; C6 emits only global pointer arg:nonnull. Dialect verification already
// handles C1/C3/C4, part of K4 and nonempty pointer-only struct TYPE_TAG shape.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/BTF/Transforms/Passes.h"
#include "bpf-mlir/Support/CheckResult.h"

#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringSet.h"

namespace mlir {
namespace btf {
#define GEN_PASS_DEF_BTFVERIFY
#include "bpf-mlir/Dialect/BTF/Transforms/Passes.h.inc"
} // namespace btf
} // namespace mlir

using namespace mlir;
using namespace mlir::btf;
using bpfmlir::CheckTally;
using bpfmlir::CheckVerdict;

namespace {

bool validIdentifier(StringRef n) {
  if (n.empty() || n.size() > 512)
    return false;
  auto ok = [](char c, bool first) {
    return (first ? llvm::isAlpha(c) : llvm::isAlnum(c)) || c == '_' || c == '.';
  };
  if (!ok(n[0], true))
    return false;
  for (char c : n.drop_front())
    if (!ok(c, false))
      return false;
  return true;
}

struct Checker {
  CheckTally tally;
  void verdict(Operation *op, bool ok, StringRef rule, const Twine &what) {
    if (ok) {
      tally.add(CheckVerdict::Verified);
      return;
    }
    tally.add(CheckVerdict::Rejected);
    op->emitOpError() << "[" << rule << "] " << what;
  }
  void name(Operation *op, StringRef n, StringRef rule, StringRef kind) {
    verdict(op, validIdentifier(n), rule,
            kind + " name \"" + n + "\" is not a valid BTF identifier ([A-Za-z_.][A-Za-z0-9_.]*, at most 512 chars); "
                                   "the kernel rejects the BTF (libbpf then silently drops it)");
  }

  void structOp(StructOp st) {
    name(st, st.getSymName(), "K1", "struct");
    llvm::StringSet<> seen;
    uint64_t last = 0;
    for (Attribute a : st.getMembers()) {
      auto m = cast<MemberAttr>(a);
      name(st, m.getName(), "K1", "member");
      verdict(st, seen.insert(m.getName()).second, "C2",
              "member \"" + m.getName() + "\" appears twice");
      verdict(st, m.getOffsetBits() >= last, "K3",
              "member \"" + m.getName() + "\" at bit " + Twine(m.getOffsetBits()) +
                  " comes before the previous member (bit " + Twine(last) +
                  "); the kernel rejects decreasing bit offsets (Invalid member bits_offset)");
      last = m.getOffsetBits();
      verdict(st, m.getOffsetBits() + m.getSizeBits() <= (uint64_t)st.getSizeBits(), "K4",
              "member \"" + m.getName() + "\" ends past the struct");
    }
  }

  void varOp(VarOp v) {
    name(v, v.getSymName(), "K1", "variable");
    // K5: emitted globals use global_allocated linkage.
    tally.add(CheckVerdict::Verified);
    // L1: loader fills DATASEC sizes/offsets from ELF.
    tally.add(CheckVerdict::Conditional);
    if (v.getSection() == ".maps") {
      auto s = dyn_cast<AnonStructAttr>(v.getType());
      bool ok = s && s.getMembers().size() >= 2 && s.getMembers()[0].getName() == "type" &&
                s.getMembers()[1].getName() == "max_entries";
      if (ok)
        for (auto [i, m] : llvm::enumerate(s.getMembers())) {
          // Map-in-map values must be the final member: a zero-element array of
          // pointers to an anonymous template map definition, matching
          // libbpf __array(values,struct inner). cilium rejects other positions.
          if (m.getName() == "values") {
            auto arr = dyn_cast<ArrayOfAttr>(m.getType());
            auto p = arr ? dyn_cast<PtrAttr>(arr.getElement()) : PtrAttr();
            ok &= i + 1 == s.getMembers().size() && arr && arr.getCount() == 0 && p && isa<AnonStructAttr>(p.getPointee());
            continue;
          }
          ok &= isa<PtrAttr>(m.getType()) &&
                (m.getName() == "type" || m.getName() == "max_entries" ||
                 m.getName() == "key" || m.getName() == "value" ||
                 m.getName() == "map_flags" || // Nonzero flags, such as lpm_trie NO_PREALLOC.
                 m.getName() == "key_size" || m.getName() == "value_size"); // prog_array untyped key/value sizes.
        }
      verdict(v, ok, "L2",
              "a map definition must be an anonymous struct of pointer members type / max_entries "
              "(and key / value / map_flags / key_size / value_size, and a last values member for map-in-map) — the libbpf / cilium map definition convention");
      if (s)
        for (MemberAttr m : s.getMembers()) {
          auto p = dyn_cast<PtrAttr>(m.getType());
          auto arr = p ? dyn_cast<ArrayOfAttr>(p.getPointee()) : ArrayOfAttr();
          auto elem = arr ? dyn_cast<IntAttr>(arr.getElement()) : IntAttr();
          if (!elem)
            continue;
          uint64_t eb = elem.getBits() / 8, total = eb * arr.getCount();
          verdict(v, total <= UINT32_MAX, "K9",
                  "map " + v.getSymName() + ": definition member \"" + m.getName() + "\" is " + elem.getName() +
                      " (*)[" + Twine(arr.getCount()) + "], an array of " + Twine(total) +
                      " bytes over U32_MAX; the kernel's BTF check rejects it (Array size overflows U32_MAX) and libbpf "
                      "then silently drops the whole BTF — " + m.getName() + " must be at most " +
                      Twine(UINT32_MAX / eb) + " (clang's __uint() emits the same BTF)");
        }
    }
  }

  void funcOp(FuncOp f, ModuleOp module) {
    name(f, f.getSymName(), "K1", "function");
    for (auto [i, a] : llvm::enumerate(f.getParams())) {
      auto p = cast<ParamAttr>(a);
      if (ArrayAttr tags = p.getTags()) {
        bool isPtr = isa<PtrAttr>(p.getType());
        for (Attribute ta : tags) {
          StringRef t = cast<StringAttr>(ta).getValue();
          std::string at =
              ("argument #" + Twine(i) + " of @" + f.getSymName() + " has decl tag \"" + t + "\"").str();
          verdict(f, f.getLinkage() == "global", "C5",
                  at + " but the FUNC is static; the kernel ignores tags on static functions");
          if (!t.starts_with("arg:"))
            continue; // Non-arg: declaration tags are outside kernel argument checks; C6 rejects them.
          StringRef k = t.drop_front(4);
          bool known = k == "ctx" || k == "trusted" || k == "untrusted" || k == "nonnull" ||
                       k == "nullable" || k == "arena";
          verdict(f, known, "K7", at + ", which the kernel does not know (has unsupported set of tags)");
          verdict(f, !known || k == "ctx" || k == "arena" || isPtr, "K8",
                  at + " but the argument is not a pointer (has pointer tag, but is not a pointer type)");
          bool genericPtr = isPtr && !isa<VoidAttr>(cast<PtrAttr>(p.getType()).getPointee());
          verdict(f, !(k == "nullable" && genericPtr && f.getLinkage() == "global"), "K6",
                  at + " on a generic pointer; the kernel rejects it (invalid combination of tags) — "
                       "a generic pointer without a tag is already nullable");
          verdict(f, t == "arg:nonnull" && isPtr && f.getLinkage() == "global", "C6",
                  at + "; this compiler only emits arg:nonnull on pointer arguments of global functions");
        }
      }
      verdict(f, !p.getName().empty(), "K2",
              "argument #" + Twine(i + 1) + " has no name (Invalid arg#" + Twine(i + 1) + ")");
      if (!p.getName().empty())
        name(f, p.getName(), "K1", "argument");
    }
    verdict(f, (bool)module.lookupSymbol<LLVM::LLVMFuncOp>(f.getSymName()), "L3",
            "no program function @" + f.getSymName() + " for this FUNC");
  }
};

struct BTFVerifyPass : public mlir::btf::impl::BTFVerifyBase<BTFVerifyPass> {
  using Base::Base;
  void runOnOperation() override {
    ModuleOp module = getOperation();
    Checker c;
    module.walk([&](Operation *op) {
      if (auto st = dyn_cast<StructOp>(op))
        c.structOp(st);
      else if (auto v = dyn_cast<VarOp>(op))
        c.varOp(v);
      else if (auto f = dyn_cast<FuncOp>(op))
        c.funcOp(f, module);
    });
    // L3: every defined program llvm.func needs a BTF FUNC.
    for (auto fn : module.getOps<LLVM::LLVMFuncOp>()) {
      if (fn.isExternal())
        continue;
      bool has = false;
      module.walk([&](FuncOp f) { has |= f.getSymName() == fn.getSymName(); });
      c.verdict(fn, has, "L3", "program @" + fn.getSymName() + " has no btf.func (no FUNC / func_info)");
    }
    if (report)
      module.emitRemark() << "btf-verify: " << c.tally.str();
    if (c.tally.rejected)
      signalPassFailure();
  }
};

} // namespace
