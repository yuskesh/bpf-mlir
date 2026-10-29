// Stage-2 checked values (assume_present/elem.at) must live in blocks entered
// only on the true edge of a single checking cf.cond_br. Verification and
// semantic-facts diagnostics share this predicate; it returns facts, not errors.
// Changes alter both acceptance and reported facts: compare both lit suites
// and developer facts-snapshot output when changing this contract.
#ifndef BPF_MLIR_DIALECT_EBPF_TRANSFORMS_CHECKEDEDGE_H
#define BPF_MLIR_DIALECT_EBPF_TRANSFORMS_CHECKEDEDGE_H

#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"

namespace mlir::ebpf {

// Return the condition-defining op only when blk has one predecessor's true
// cf.cond_br edge and is not also its false destination; otherwise nullptr.
Operation *trueEdgeConditionOp(Block *blk);

// assume_present must follow the true edge of is_present on the same value.
bool assumePresentPlacementHolds(AssumePresentOp a);

// elem.at requires one true-edge elem.in_range check per dimension, traced
// backwards from last to first, matching ref/field/index/dim. This checks
// placement only, not the separate elem.load/elem.store-only use restriction.
bool elemAtPlacementHolds(ElemAtOp at);

} // namespace mlir::ebpf

#endif
