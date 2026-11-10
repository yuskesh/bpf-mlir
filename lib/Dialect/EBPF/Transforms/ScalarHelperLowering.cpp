#include "ScalarHelperLowering.h"
#include "mlir/Dialect/LLVMIR/LLVMDialect.h"

using namespace mlir;

Value mlir::ebpf::detail::scalarOutputSlot(OpBuilder &b, Block *entry,
                                           Location loc, Type type,
                                           unsigned alignment) {
  OpBuilder::InsertionGuard guard(b);
  b.setInsertionPointToStart(entry);
  Value one =
      LLVM::ConstantOp::create(b, loc, b.getI64Type(), b.getI64IntegerAttr(1));
  return LLVM::AllocaOp::create(
      b, loc, LLVM::LLVMPointerType::get(b.getContext()), type, one, alignment);
}

void mlir::ebpf::detail::clearScalarOutput(OpBuilder &b, Location loc,
                                           Value slot, Type type,
                                           unsigned alignment) {
  LLVM::StoreOp::create(b, loc, LLVM::ZeroOp::create(b, loc, type), slot,
                        alignment);
}

Value mlir::ebpf::detail::scalarOutputValue(OpBuilder &b, Location loc,
                                            Value slot, IntegerType loadType,
                                            IntegerType resultType,
                                            Value status, unsigned alignment) {
  Value value = LLVM::LoadOp::create(b, loc, loadType, slot, alignment);
  if (loadType != resultType)
    value = LLVM::TruncOp::create(b, loc, resultType, value);
  Value zeroStatus = LLVM::ZeroOp::create(b, loc, status.getType());
  Value ok =
      LLVM::ICmpOp::create(b, loc, LLVM::ICmpPredicate::eq, status, zeroStatus);
  return LLVM::SelectOp::create(b, loc, ok, value,
                                LLVM::ZeroOp::create(b, loc, resultType));
}
