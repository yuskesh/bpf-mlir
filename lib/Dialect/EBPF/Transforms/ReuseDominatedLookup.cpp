//===- ReuseDominatedLookup.cpp - reuse a dominating array lookup ----===//
//
// Stage 2, after region expansion and before the structured exit check.
// A loop body cannot capture an outer borrowed value, so stage-1 inputs repeat
// `map.lookup %m[%k]` + `ref.check` inside the loop. After
// expansion, each repeated lookup adds a NULL branch per iteration. When the
// map is an `array`, the map and key are the same SSA values, and an
// assume_present of an earlier such lookup properly dominates the repeated
// lookup, the repeated lookup returns the same pointer: an in-range array index
// names a fixed cell that cannot be deleted. The rewrite keeps the dominating
// lookup and its NULL check, and all field operations in their positions.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h"

#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"

#include "mlir/Dialect/ControlFlow/IR/ControlFlowOps.h"
#include "mlir/IR/Dominance.h"
#include "mlir/IR/PatternMatch.h"
#include "mlir/Transforms/RegionUtils.h"

namespace mlir {
namespace ebpf {
#define GEN_PASS_DEF_EBPFREUSEDOMINATEDLOOKUP
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h.inc"
} // namespace ebpf
} // namespace mlir

using namespace mlir;
using namespace mlir::ebpf;

namespace {

bool isArrayMap(Value m) {
  auto t = dyn_cast<MapType>(m.getType());
  return t && t.getKind() == "array";
}

// (d): every use of the lookup is is_present (whose uses are only cf.cond_br
// conditions) or assume_present.
bool onlyCheckedUses(MapLookupOp l) {
  for (Operation *u : l.getResult().getUsers()) {
    if (auto p = dyn_cast<IsPresentOp>(u)) {
      for (OpOperand &use : p.getResult().getUses()) {
        auto br = dyn_cast<cf::CondBranchOp>(use.getOwner());
        if (!br || use.getOperandNumber() != 0)
          return false;
      }
      continue;
    }
    if (isa<AssumePresentOp>(u))
      continue;
    return false;
  }
  return true;
}

// (b), (c): an assume_present of another lookup with the same map and key SSA
// values, in the same region, properly dominating `l` as an operation.
AssumePresentOp findDominating(MapLookupOp l, DominanceInfo &dom) {
  for (Operation *u : l.getMap().getUsers()) {
    auto other = dyn_cast<MapLookupOp>(u);
    if (!other || other == l || other.getMap() != l.getMap() || other.getKey() != l.getKey())
      continue;
    for (Operation *ou : other.getResult().getUsers()) {
      auto b = dyn_cast<AssumePresentOp>(ou);
      if (!b || b->getParentRegion() != l->getParentRegion())
        continue;
      if (dom.properlyDominates(b.getOperation(), l.getOperation()))
        return b;
    }
  }
  return {};
}

struct EBPFReuseDominatedLookupPass
    : public ebpf::impl::EBPFReuseDominatedLookupBase<EBPFReuseDominatedLookupPass> {
  void runOnOperation() override {
    ModuleOp module = getOperation();
    // One rewrite per round with fresh dominance: erasing blocks invalidates it.
    bool changed = true;
    while (changed) {
      changed = false;
      DominanceInfo dom(module);
      SmallVector<std::pair<MapLookupOp, AssumePresentOp>> work;
      module.walk([&](MapLookupOp l) {
        if (!isArrayMap(l.getMap()) || !onlyCheckedUses(l))
          return;
        if (AssumePresentOp b = findDominating(l, dom))
          work.push_back({l, b});
      });
      if (work.empty())
        break;
      // Rewrite one lookup per round: later candidates may name this one.
      auto [l, b] = work.front();
      IRRewriter rewriter(module.getContext());
      Region *region = l->getParentRegion();
      for (Operation *u : llvm::make_early_inc_range(l.getResult().getUsers())) {
        if (auto p = dyn_cast<IsPresentOp>(u)) {
          for (Operation *bu : llvm::make_early_inc_range(p.getResult().getUsers())) {
            auto br = cast<cf::CondBranchOp>(bu);
            rewriter.setInsertionPoint(br);
            rewriter.replaceOpWithNewOp<cf::BranchOp>(br, br.getTrueDest(), br.getTrueDestOperands());
          }
          rewriter.eraseOp(p);
          continue;
        }
        auto a = cast<AssumePresentOp>(u);
        if (a.getResult().getType() != b.getResult().getType()) {
          a.emitError("reuse-dominated-lookup: dominating assume_present has a different type");
          return signalPassFailure();
        }
        rewriter.replaceOp(a, b.getResult());
      }
      rewriter.eraseOp(l);
      (void)eraseUnreachableBlocks(rewriter, MutableArrayRef<Region>(*region));
      changed = true;
    }
  }
};

} // namespace
