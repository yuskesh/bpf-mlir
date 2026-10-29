// Reject high-level arithmetic that may cause LLVM UB/poison, with op/reason
// diagnostics. IntegerRangeAnalysis uses upstream value ranges, not narrowing
// from branch conditions; constants use their values directly. This is compiler
// legality, not a kernel-verifier proof. Division/remainder must exclude zero;
// signed variants must additionally exclude divisor -1 or dividend MinInt.
// Shift umax must be below width. Reject nsw/nuw/exact flags and non-integer
// operand/results (float/index/vector) by type. See docs/arith_contract.md.
#ifndef BPF_MLIR_DIALECT_EBPF_TRANSFORMS_ARITHLEGALITY_H
#define BPF_MLIR_DIALECT_EBPF_TRANSFORMS_ARITHLEGALITY_H

#include "mlir/IR/BuiltinOps.h"

namespace mlir::ebpf {

// Check every arithmetic op, emitting one error per rejection and failing if any.
LogicalResult verifyArithLegality(ModuleOp module);

} // namespace mlir::ebpf

#endif
