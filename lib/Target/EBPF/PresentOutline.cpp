//===- PresentOutline.cpp - outline large reservation present regions --------===//
//
// Deterministic names __ebpf_present_<function>_<reservation-order> must be
// unique. Up to five inputs+outputs use direct arguments; larger interfaces
// use CodeExtractor's stack aggregate passed by one pointer.
// Fill missing DISubprogram argument types and named retained variables:
// pointers are void*, integers are unsigned by width, names are a0/a1/etc.
// Kernel rejects BTF FUNC arguments without names.
//===----------------------------------------------------------------------===//

#include "bpf-mlir/Target/EBPF/PresentOutline.h"

#include "bpf-mlir/Target/EBPF/PresentCost.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"

#include <set>

using namespace llvm;

namespace ebpf {

namespace {

// Round integer widths to 8/16/32/64 for byte-sized BTF INTs; captured i1
// conditions must not become zero-byte integers.
DIBasicType *intType(DIBuilder &db, unsigned bits) {
  unsigned w = bits <= 8 ? 8 : bits <= 16 ? 16 : bits <= 32 ? 32 : 64;
  const char *name = w == 8 ? "unsigned char" : w == 16 ? "unsigned short" : w == 32 ? "unsigned int" : "unsigned long";
  return db.createBasicType(name, w, w == 8 ? dwarf::DW_ATE_unsigned_char : dwarf::DW_ATE_unsigned);
}

// Populate outlined DISubprogram argument types and names.
void fixSubprogram(Function &f) {
  DISubprogram *sp = f.getSubprogram();
  if (!sp)
    return;
  DIBuilder db(*f.getParent(), /*AllowUnresolved=*/false, sp->getUnit());
  SmallVector<Metadata *> types{nullptr}; // Return may be void or CodeExtractor's selector, including i16.
  if (!f.getReturnType()->isVoidTy())
    types[0] = intType(db, f.getReturnType()->getIntegerBitWidth());
  SmallVector<Metadata *> vars;
  for (Argument &a : f.args()) {
    DIType *t;
    if (a.getType()->isPointerTy())
      t = db.createPointerType(nullptr, 64);
    else
      t = intType(db, a.getType()->getIntegerBitWidth());
    types.push_back(t);
    vars.push_back(db.createParameterVariable(sp, "a" + std::to_string(a.getArgNo()), a.getArgNo() + 1,
                                              sp->getFile(), 0, t, /*AlwaysPreserve=*/true));
  }
  // BTF FUNC names come from DISubprogram. Match outlined ELF symbols by
  // updating operands two/three (name/linkageName).
  sp->replaceOperandWith(2, MDString::get(f.getContext(), f.getName()));
  sp->replaceOperandWith(3, MDString::get(f.getContext(), f.getName()));
  sp->replaceType(db.createSubroutineType(db.getOrCreateTypeArray(types)));
  sp->replaceRetainedNodes(MDTuple::get(f.getContext(), vars));
  db.finalizeSubprogram(sp);
  db.finalize();
}

} // namespace

bool outlineLargePresents(Module &m, uint64_t threshold, const std::function<void(const Twine &)> &error) {
  // Re-estimate after each outline: nested reservations move into the new
  // function. Bound iterations by present count and never select an already
  // outlined function/reservation pair again, even if its lone call exceeds
  // a very small threshold.
  std::set<std::pair<Function *, unsigned>> done;
  for (unsigned guard = 0; guard < 1024; ++guard) {
    SmallVector<PresentCost> pcs = estimatePresentCosts(m);
    PresentCost *pick = nullptr;
    for (PresentCost &pc : pcs)
      if (pc.estimate > threshold && !done.count({pc.fn, pc.index})) {
        pick = &pc;
        break;
      }
    if (!pick)
      return true;
    Function &parent = *pick->fn;
    std::string name = ("__ebpf_present_" + parent.getName() + "_" + Twine(pick->index)).str();
    if (m.getFunction(name)) {
      error("the outlined function name \"" + name + "\" for reservation #" + Twine(pick->index) + " of \"" +
            parent.getName() + "\" is already used in the module; rename the function (the __ebpf_present_ prefix is reserved)");
      return false;
    }
    DominatorTree dt(parent);
    CodeExtractorAnalysisCache ceac(parent);
    SetVector<Value *> inputs, outputs, sinks;
    {
      CodeExtractor probe(pick->blocks, &dt);
      if (!probe.isEligible()) {
        error("the present of reservation #" + Twine(pick->index) + " in \"" + parent.getName() +
              "\" is estimated at " + Twine(pick->estimate) + " BPF instructions (over " + Twine(threshold) +
              ") but cannot be moved to a function");
        return false;
      }
      probe.findInputsOutputs(inputs, outputs, sinks);
    }
    // Preserve explicit memcpy/memset alignment: outlined pointer arguments
      // otherwise lose alignment and expand to byte stores.
    for (BasicBlock *bb : pick->blocks)
      for (Instruction &i : *bb)
        if (auto *mi = dyn_cast<MemIntrinsic>(&i)) {
          const DataLayout &dl = m.getDataLayout();
          if (Align k = mi->getRawDest()->getPointerAlignment(dl); k > mi->getDestAlign().valueOrOne())
            mi->setDestAlignment(k);
          if (auto *mt = dyn_cast<MemTransferInst>(mi))
            if (Align k = mt->getRawSource()->getPointerAlignment(dl); k > mt->getSourceAlign().valueOrOne())
              mt->setSourceAlignment(k);
        }
    bool aggregate = inputs.size() + outputs.size() > kMaxBPFArgs;
    CodeExtractor ce(pick->blocks, &dt, aggregate);
    SetVector<Value *> in2, out2;
    Function *f = ce.extractCodeRegion(ceac, in2, out2);
    if (!f) {
      error("the present of reservation #" + Twine(pick->index) + " in \"" + parent.getName() +
            "\" could not be moved to a function by LLVM's CodeExtractor");
      return false;
    }
    if (f->arg_size() > kMaxBPFArgs) {
      error("the function outlined from reservation #" + Twine(pick->index) + " of \"" + parent.getName() + "\" takes " +
            Twine(f->arg_size()) + " arguments; BPF passes at most 5");
      return false;
    }
    f->setName(name);
    f->setLinkage(GlobalValue::InternalLinkage);
    f->addFnAttr(Attribute::NoInline);
    f->removeFnAttr(Attribute::OptimizeForSize);
    f->removeFnAttr(Attribute::MinSize);
    fixSubprogram(*f);
    done.insert({&parent, pick->index});
  }
  error("too many reservations to outline");
  return false;
}

} // namespace ebpf
