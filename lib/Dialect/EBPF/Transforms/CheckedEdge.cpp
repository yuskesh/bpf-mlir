//===- CheckedEdge.cpp - shared placement conditions for checked values ------===//
//
// Shared by structured verification and semantic-fact diagnostics.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/CheckedEdge.h"

#include "mlir/Dialect/ControlFlow/IR/ControlFlowOps.h"

using namespace mlir;
using namespace mlir::ebpf;

Operation *mlir::ebpf::trueEdgeConditionOp(Block *blk) {
  Block *pred = blk->getSinglePredecessor();
  auto br = pred ? dyn_cast<cf::CondBranchOp>(pred->getTerminator()) : cf::CondBranchOp();
  // Redundant guard: duplicate true/false edges already make MLIR's
  // getSinglePredecessor return null, even from the same predecessor block.
  if (!br || br.getTrueDest() != blk || br.getFalseDest() == blk)
    return nullptr;
  return br.getCondition().getDefiningOp();
}

bool mlir::ebpf::assumePresentPlacementHolds(AssumePresentOp a) {
  auto test = dyn_cast_or_null<IsPresentOp>(trueEdgeConditionOp(a->getBlock()));
  return test && test.getValue() == a.getValue();
}

bool mlir::ebpf::elemAtPlacementHolds(ElemAtOp at) {
  Block *blk = at->getBlock();
  for (int64_t k = static_cast<int64_t>(at.getIndices().size()) - 1; k >= 0; --k) {
    auto test = dyn_cast_or_null<ElemInRangeOp>(trueEdgeConditionOp(blk));
    if (!test || test.getRef() != at.getRef() || test.getField() != at.getField() || test.getIndex() != at.getIndices()[k] ||
        test.getDim().value_or(0) != static_cast<uint64_t>(k))
      return false;
    blk = blk->getSinglePredecessor();
  }
  return true;
}
