#ifndef BPF_MLIR_TP_BUFFER_LOWERING_INTERNAL_H
#define BPF_MLIR_TP_BUFFER_LOWERING_INTERNAL_H

#include "mlir/Dialect/LLVMIR/LLVMDialect.h"
#include "mlir/IR/BuiltinOps.h"
#include "llvm/ADT/ArrayRef.h"

namespace mlir::bpfabi::detail {
enum class TpBufferDirection { Load, Store };
enum class TpBufferCheckPhase { BeforeErase, AfterErase };
struct TpBufferExpected {
  Operation *origin = nullptr;
  LLVM::LLVMFuncOp function;
  Block *block = nullptr;
  BlockArgument entryCtx;
  unsigned sourceOrdinal = 0, blockOrdinal = 0;
  TpBufferDirection direction;
  StringAttr progType, attachType;
  int64_t ctxOffset, ctxBytes, bufferOffset, bufferBytes;
  Type scalarType;
  unsigned storeOperandIndex = 1;
  Value storeValueAfterRAUW;
};
struct TpBufferGenerated {
  Operation *ctxGEP = nullptr, *ctxRead = nullptr, *rawToPtr = nullptr;
  Operation *bufferGEP = nullptr, *access = nullptr;
};
LogicalResult collectTpBufferExpected(ModuleOp, llvm::SmallVectorImpl<TpBufferExpected> &);
LogicalResult expandTpBuffer(const TpBufferExpected &, TpBufferGenerated &);
LogicalResult checkTpBufferLowering(ModuleOp, const TpBufferExpected &, const TpBufferGenerated &, TpBufferCheckPhase);
LogicalResult finalizeTpBufferLowering(ModuleOp, llvm::MutableArrayRef<TpBufferExpected>, llvm::ArrayRef<TpBufferGenerated>);
} // namespace mlir::bpfabi::detail
#endif
