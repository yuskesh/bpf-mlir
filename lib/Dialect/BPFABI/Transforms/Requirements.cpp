//===- Requirements.cpp - per-program kernel capability requirements --------===//
//
// Compiler decisions do not depend on kernel versions. Record required program
// types and helpers for ObjectEmitter's .ebpf_requirements; precheck matches
// them with target capabilities before load.
//
// Count helpers transitively through llvm.call and function-address edges
// (bpf_loop callbacks). bpfabi.subprogram functions have no independent
// requirements because programs are the load units. Keep llvm.call distinct
// from bpfabi.helper_call. ObjectEmitter owns map requirements, since it
// determines emitted maps from schema.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/BPFABI/Transforms/Passes.h"

#include "bpf-mlir/Dialect/BPFABI/IR/BPFABIDialect.h"
#include "bpf-mlir/Dialect/BPFABI/KernelABI.h"
#include "bpf-mlir/Support/CheckResult.h"

#include "mlir/Dialect/LLVMIR/LLVMDialect.h"
#include "llvm/ADT/STLExtras.h"

#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSet.h"

#include <functional>
#include <set>

namespace mlir {
namespace bpfabi {
#define GEN_PASS_DEF_BPFABIREQUIREMENTS
#include "bpf-mlir/Dialect/BPFABI/Transforms/Passes.h.inc"
} // namespace bpfabi
} // namespace mlir

using namespace mlir;
using namespace mlir::bpfabi;
using bpfmlir::CheckTally;
using bpfmlir::CheckVerdict;

namespace {

struct BPFABIRequirementsPass
    : public mlir::bpfabi::impl::BPFABIRequirementsBase<BPFABIRequirementsPass> {
  using BPFABIRequirementsBase::BPFABIRequirementsBase;

  void runOnOperation() override {
    ModuleOp module = getOperation();
    CheckTally tally;
    Builder b(module.getContext());

    llvm::StringMap<LLVM::LLVMFuncOp> subprograms;
    module.walk([&](LLVM::LLVMFuncOp fn) {
      if (!fn.isExternal() && fn->hasAttr("bpfabi.subprogram"))
        subprograms[fn.getName()] = fn;
    });
    // Collect subprograms transitively reachable from fn, excluding fn itself.
    // Calls to programs or undefined functions are explicit errors.
    auto reachable = [&](LLVM::LLVMFuncOp fn, llvm::StringSet<> &seen) {
      bool ok = true;
      std::function<void(LLVM::LLVMFuncOp)> go = [&](LLVM::LLVMFuncOp f) {
        f.walk([&](LLVM::CallOp call) {
          auto callee = call.getCallee();
          auto it = callee ? subprograms.find(*callee) : subprograms.end();
          if (it == subprograms.end()) {
            call.emitOpError() << "calls something that is not a subprogram of "
                                  "this module; cannot attribute its requirements";
            ok = false;
            return;
          }
          if (seen.insert(*callee).second)
            go(it->second);
        });
        // Function-address loads form edges; addresses of map globals do not.
        f.walk([&](LLVM::AddressOfOp addr) {
          auto it = subprograms.find(addr.getGlobalName());
          if (it != subprograms.end() && seen.insert(addr.getGlobalName()).second)
            go(it->second);
        });
      };
      go(fn);
      return ok;
    };
    llvm::StringSet<> reachedByAny;

    module.walk([&](LLVM::LLVMFuncOp fn) {
      if (fn.isExternal() || fn->hasAttr("bpfabi.subprogram"))
        return;
      auto progType = fn->getAttrOfType<StringAttr>("bpfabi.prog_type");
      if (!progType) {
        // Helper requirements need a known program type; fail explicitly if
        // lowering produced an unclassified function that calls helpers.
        bool calls = false;
        fn.walk([&](HelperCallOp) { calls = true; });
        if (calls) {
          fn.emitOpError() << "calls helpers but has no bpfabi.prog_type; "
                              "cannot record its requirements";
          tally.add(CheckVerdict::Rejected);
        }
        return;
      }
      if (!lookupProgType(progType.getValue())) {
        fn.emitOpError() << "program type \"" << progType.getValue()
                         << "\" is not in the UAPI table";
        tally.add(CheckVerdict::Rejected);
        return;
      }
      tally.add(CheckVerdict::Conditional); // Target support for the program type.

      std::set<std::string> helpers; // Unique name order for reproducibility.
      fn.walk([&](HelperCallOp call) { helpers.insert(call.getCallee().str()); });
      llvm::StringSet<> seen;
      if (!reachable(fn, seen)) {
        tally.add(CheckVerdict::Rejected);
        return;
      }
      // Reachable bpfabi.nonnull_args require verifier interpretation of arg:nonnull.
      bool needsNonnull = false;
      for (const auto &e : seen) {
        reachedByAny.insert(e.getKey());
        LLVM::LLVMFuncOp sub = subprograms[e.getKey()];
        sub.walk([&](HelperCallOp call) { helpers.insert(call.getCallee().str()); });
        if (auto nn = sub->getAttrOfType<DenseBoolArrayAttr>("bpfabi.nonnull_args"))
          needsNonnull |= llvm::is_contained(nn.asArrayRef(), true);
      }
      SmallVector<Attribute> names;
      for (const std::string &h : helpers) {
        names.push_back(b.getStringAttr(h));
        tally.add(CheckVerdict::Conditional); // Target helper support for this program type.
      }
      SmallVector<NamedAttribute> req{
          b.getNamedAttr("prog_type", progType),
          b.getNamedAttr("helpers", b.getArrayAttr(names)),
      };
      if (needsNonnull) {
        // Require semantic interpretation of generic mem argument tags, not just BTF kind acceptance.
        req.push_back(b.getNamedAttr("arg_tags", b.getStrArrayAttr({"arg:nonnull mem"})));
        tally.add(CheckVerdict::Conditional);
      }
      // Context accesses occur only in entry program bodies. Record unique sorted
      // attach-type/struct/field/mode/width tuples; kernel-version-dependent
      // verifier support is queried through ctx_access before load.
      std::set<std::string> ctxAccess;
      fn.walk([&](Operation *op) {
        std::string mode;
        if (isa<CtxFieldLoadOp>(op))
          mode = "r";
        else if (isa<CtxFieldStoreOp>(op))
          mode = "w";
        else
          return;
        auto get = [&](StringRef n) { return op->getAttrOfType<StringAttr>(n).getValue().str(); };
        ctxAccess.insert(get("attach_type") + " " + get("strct") + " " + get("field") + " " + mode + " " +
                         std::to_string(op->getAttrOfType<IntegerAttr>("field_bytes").getInt()));
      });
      if (!ctxAccess.empty()) {
        SmallVector<StringRef> v(ctxAccess.begin(), ctxAccess.end());
        req.push_back(b.getNamedAttr("ctx_access", b.getStrArrayAttr(v)));
        for (size_t i = 0; i < ctxAccess.size(); ++i)
          tally.add(CheckVerdict::Conditional); // Target verifier support for this access.
      }
      // the private ctx read is part of tpbuf, not an implicit ctxaccess row.
      bool tpbuf = false;
      fn.walk([&](Operation *op) { tpbuf |= isa<TpBufferLoadOp, TpBufferStoreOp>(op); });
      if (tpbuf) {
        req.push_back(b.getNamedAttr("tpbuf", b.getStringAttr("i32")));
        tally.add(CheckVerdict::Conditional); // target pointee and writable_size are live facts.
      }
      // Unique sorted kfunc names from the program and reachable subprograms.
      // ObjectEmitter records ABI signatures for pre-load matching against
      // target BTF FUNC_PROTO: both presence and signature are kernel capabilities.
      std::set<std::string> kfuncs;
      fn.walk([&](KfuncCallOp call) { kfuncs.insert(call.getCallee().str()); });
      for (const auto &e : seen)
        subprograms[e.getKey()].walk([&](KfuncCallOp call) { kfuncs.insert(call.getCallee().str()); });
      if (!kfuncs.empty()) {
        SmallVector<StringRef> v(kfuncs.begin(), kfuncs.end());
        req.push_back(b.getNamedAttr("kfuncs", b.getStrArrayAttr(v)));
        for (size_t i = 0; i < kfuncs.size(); ++i)
          tally.add(CheckVerdict::Conditional); // Target presence of this kfunc with the required signature.
      }
      fn->setAttr("bpfabi.requires", b.getDictionaryAttr(req));
    });

    // Unreachable subprogram requirements have no owning program. Source call
    // graph verification should reject them; fail explicitly if they reach here.
    for (auto &e : subprograms)
      if (!reachedByAny.contains(e.getKey())) {
        e.getValue().emitOpError()
            << "is a subprogram that no program reaches; its requirements "
               "cannot be attributed";
        tally.add(CheckVerdict::Rejected);
      }

    if (report)
      module.emitRemark() << "bpfabi-requirements: " << tally.str();
    if (tally.rejected)
      signalPassFailure();
  }
};

} // namespace
