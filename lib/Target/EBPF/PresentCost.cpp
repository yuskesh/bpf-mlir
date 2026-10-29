//===- PresentCost.cpp - reservation present-region instruction estimate -----===//
//
// Conservative weights from observed BPF instruction shapes:
// stores cost two for signed-32-bit constants (mov+stx) or nonconstants
// (including reload), three for wider constants (ld_imm64+store). Add two when
// constant pointer offsets exceed signed-16-bit store offsets. GEP costs zero
// because its offset folds into stores. Calls cost one plus argument count.
// memset/memcpy cost length/alignment stores (alignment capped at eight), plus
// one for memset or doubled for memcpy loads/stores. Lifetime costs zero;
// other operations cost one; region entry/exit adds two.
//
// Outline overhead uses CodeExtractor findInputsOutputs, shared with
// PresentOutline. Aggregated input+output counts above kMaxBPFArgs add three
// per field (entry load plus worst-case spill/reload), and every output adds
// two for exit stores through direct or aggregate pointers.
//===----------------------------------------------------------------------===//

#include "bpf-mlir/Target/EBPF/PresentCost.h"

#include "bpf-mlir/Dialect/BPFABI/KernelABI.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"

using namespace llvm;

namespace ebpf {

namespace {

// Helper ID N from call inttoptr(i64 N to ptr).
std::optional<uint64_t> helperId(const CallInst &ci) {
  if (auto *ce = dyn_cast<ConstantExpr>(ci.getCalledOperand()))
    if (ce->getOpcode() == Instruction::IntToPtr)
      if (auto *n = dyn_cast<ConstantInt>(ce->getOperand(0)))
        return n->getZExtValue();
  return std::nullopt;
}

uint64_t storeCost(const StoreInst &st, const DataLayout &dl) {
  uint64_t c = 2; // Nonconstant stores cost two, including a possible spill reload.
  if (auto *k = dyn_cast<ConstantInt>(st.getValueOperand()))
    c = k->getValue().isSignedIntN(32) ? 2 : 3; // Constants also move into a register before stx; immediate ST is not used.
  APInt off(dl.getIndexTypeSizeInBits(st.getPointerOperandType()), 0);
  st.getPointerOperand()->stripAndAccumulateConstantOffsets(dl, off, /*AllowNonInbounds=*/true);
  if (off.getSExtValue() >= 32768)
    c += 2;
  return c;
}

// memset/memcpy from stack zeroing/record copies use length/alignment stores
// (and loads). Take the greater of explicit and known pointer alignment, capped
// at eight. Nonconstant lengths receive a large conservative estimate.
uint64_t memCost(const MemIntrinsic &mi, const DataLayout &dl) {
  auto *len = dyn_cast<ConstantInt>(mi.getLength());
  if (!len)
    return 1u << 20;
  auto alignOf = [&](const Value *p, MaybeAlign a) {
    uint64_t k = std::max<uint64_t>(a.valueOrOne().value(), p->getPointerAlignment(dl).value());
    return std::min<uint64_t>(k, 8);
  };
  uint64_t a = alignOf(mi.getRawDest(), mi.getDestAlign());
  if (auto *mt = dyn_cast<MemTransferInst>(&mi))
    a = std::min(a, alignOf(mt->getRawSource(), mt->getSourceAlign()));
  uint64_t n = (len->getZExtValue() + a - 1) / a;
  return isa<MemSetInst>(mi) ? n + 1 : 2 * n;
}

uint64_t instCost(const Instruction &i, const DataLayout &dl) {
  if (isa<GetElementPtrInst>(i))
    return 0;
  if (auto *mi = dyn_cast<MemIntrinsic>(&i))
    return memCost(*mi, dl);
  if (auto *ii = dyn_cast<IntrinsicInst>(&i))
    if (ii->isLifetimeStartOrEnd() || ii->isAssumeLikeIntrinsic())
      return 0;
  if (auto *st = dyn_cast<StoreInst>(&i))
    return storeCost(*st, dl);
  if (auto *ci = dyn_cast<CallInst>(&i))
    return 1 + ci->arg_size();
  return 1;
}

// Use the same CodeExtractor inputs/outputs as PresentOutline for aggregate
// entry loads and output stores. Ineligible regions are not outlined and get
// explicit errors there, so add no outline overhead here.
uint64_t outlineBoundaryCost(ArrayRef<BasicBlock *> blocks, DominatorTree &dt) {
  CodeExtractor probe(blocks, &dt);
  if (!probe.isEligible())
    return 0;
  SetVector<Value *> inputs, outputs, sinks;
  probe.findInputsOutputs(inputs, outputs, sinks);
  uint64_t fields = inputs.size() + outputs.size();
  uint64_t c = 2 * outputs.size();
  if (fields > kMaxBPFArgs)
    c += 3 * fields;
  return c;
}

} // namespace

SmallVector<PresentCost> estimatePresentCosts(Module &m) {
  SmallVector<PresentCost> out;
  const auto *reserve = mlir::bpfabi::lookupHelper("ringbuf_reserve");
  if (!reserve)
    return out;
  const DataLayout &dl = m.getDataLayout();
  for (Function &f : m) {
    if (f.isDeclaration())
      continue;
    DominatorTree dt(f);
    unsigned index = 0;
    for (Instruction &i : instructions(f)) {
      auto *ci = dyn_cast<CallInst>(&i);
      if (!ci || helperId(*ci) != std::optional<uint64_t>(static_cast<uint64_t>(reserve->id)))
        continue;
      unsigned myIndex = index++;
      // Null check: icmp eq/ne r,null followed by branch.
      for (User *u : ci->users()) {
        auto *cmp = dyn_cast<ICmpInst>(u);
        if (!cmp || !isa<ConstantPointerNull>(cmp->getOperand(1)))
          continue;
        for (User *cu : cmp->users()) {
          auto *br = dyn_cast<CondBrInst>(cu);
          if (!br)
            continue;
          BasicBlock *entry = cmp->getPredicate() == ICmpInst::ICMP_NE ? br->getSuccessor(0) : br->getSuccessor(1);
          PresentCost pc;
          pc.fn = &f;
          pc.index = myIndex;
          pc.entry = entry;
          pc.estimate = 2; // Fixed present entry/exit overhead: outlined callee exit and branching.
          for (BasicBlock &bb : f)
            if (dt.dominates(entry, &bb)) {
              pc.blocks.push_back(&bb);
              for (Instruction &x : bb)
                pc.estimate += instCost(x, dl);
            }
          pc.estimate += outlineBoundaryCost(pc.blocks, dt);
          out.push_back(std::move(pc));
        }
      }
    }
  }
  return out;
}

} // namespace ebpf
