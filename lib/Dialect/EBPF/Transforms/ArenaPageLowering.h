#ifndef BPF_MLIR_ARENA_PAGE_LOWERING_H
#define BPF_MLIR_ARENA_PAGE_LOWERING_H

#include "mlir/Dialect/LLVMIR/LLVMDialect.h"

namespace mlir::ebpf::detail {
// Full user address equality is mandatory, even though AS1 accesses use low32.
// Kept in one builder so the native witness and BPF lowering test the same graph.
inline Value arenaAllocationMatches(OpBuilder &b, Location loc, Value actual, Value requested) {
  Value zero = LLVM::ConstantOp::create(b, loc, b.getI64Type(), b.getI64IntegerAttr(0));
  Value nonnull = LLVM::ICmpOp::create(b, loc, LLVM::ICmpPredicate::ne, actual, zero);
  Value full = LLVM::ICmpOp::create(b, loc, LLVM::ICmpPredicate::eq, actual, requested);
  Value actualLow = LLVM::TruncOp::create(b, loc, b.getI32Type(), actual);
  Value requestedLow = LLVM::TruncOp::create(b, loc, b.getI32Type(), requested);
  Value low = LLVM::ICmpOp::create(b, loc, LLVM::ICmpPredicate::eq, actualLow, requestedLow);
  Value exact = LLVM::AndOp::create(b, loc, full, low);
  return LLVM::AndOp::create(b, loc, nonnull, exact);
}
} // namespace mlir::ebpf::detail
#endif
