//===- BPFABIDialect.cpp - registration and local operation verification -----===//
//
// Verify local result counts and type shapes. VerifyABI independently checks
// numeric UAPI table agreement with four-valued results at the stage exit.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/BPFABI/IR/BPFABIDialect.h"
#include "bpf-mlir/Dialect/BPFABI/KernelABI.h"
#include "bpf-mlir/Support/ProgramKinds.h"
#include "mlir/Dialect/LLVMIR/LLVMDialect.h"

#include "mlir/IR/Builders.h"
#include "mlir/IR/DialectImplementation.h"
#include "mlir/IR/OpImplementation.h"

using namespace mlir;
using namespace mlir::bpfabi;

#include "bpf-mlir/Dialect/BPFABI/IR/BPFABIOpsDialect.cpp.inc"

#define GET_OP_CLASSES
#include "bpf-mlir/Dialect/BPFABI/IR/BPFABIOps.cpp.inc"

void BPFABIDialect::initialize() {
  addOperations<
#define GET_OP_LIST
#include "bpf-mlir/Dialect/BPFABI/IR/BPFABIOps.cpp.inc"
      >();
}

LogicalResult HelperCallOp::verify() {
  // Helpers return at most one value in R0.
  if (getNumResults() > 1)
    return emitOpError() << "a helper returns at most one value (R0), got "
                         << getNumResults();
  if (getId() <= 0)
    return emitOpError() << "helper id must be positive, got " << getId();
  return success();
}

// kfuncs also return at most one R0 value and take at most five register
// arguments. VerifyABI owns signature-table agreement.
LogicalResult KfuncCallOp::verify() {
  if (getCallee().empty())
    return emitOpError() << "needs a kfunc name";
  if (getNumResults() > 1)
    return emitOpError() << "a kfunc returns at most one value (R0), got " << getNumResults();
  if (getArgs().size() > 5)
    return emitOpError() << "a kfunc takes at most 5 arguments (R1-R5), got " << getArgs().size();
  return success();
}

LogicalResult CtxPacketOp::verify() {
  if (getFieldBytes() != 4 && getFieldBytes() != 8)
    return emitOpError() << "field_bytes must be 4 or 8, got "
                         << getFieldBytes();
  if (getDataOffset() % getFieldBytes() != 0 ||
      getDataEndOffset() % getFieldBytes() != 0)
    return emitOpError() << "data / data_end offsets must be multiples of "
                         << "field_bytes";
  return success();
}

LogicalResult CtxArgOp::verify() {
  if (getIndex() < 0)
    return emitOpError() << "argument index must be non-negative";
  return success();
}

// Reject forged ABI-stage buffer shapes, including another program's entry context.
template <typename Op> static LogicalResult verifyTpBufferABI(Op op) {
  auto ptr = dyn_cast<LLVM::LLVMPointerType>(op.getCtx().getType());
  auto fn = op->template getParentOfType<LLVM::LLVMFuncOp>();
  auto *f = lookupStructField("bpf_raw_tracepoint_args", "args");
  auto *a = lookupCtxAccess(op.getProgType(), op.getAttachType(), "bpf_raw_tracepoint_args", "args", "r");
  std::string attach;
  const bpfmlir::ProgramAttachInfo *row = nullptr;
  const auto *kind = fn && fn.getSection() ? bpfmlir::kindOfSection(*fn.getSection(), attach, &row) : nullptr;
  auto pt = fn ? fn->template getAttrOfType<StringAttr>("bpfabi.prog_type") : StringAttr();
  if (!ptr || ptr.getAddressSpace() != 0 || !fn || fn.isExternal() || fn->hasAttr("bpfabi.subprogram") ||
      fn.getBody().front().getNumArguments() != 1 || op.getCtx() != fn.getBody().front().getArgument(0) ||
      !kind || !bpfmlir::kindAllows(kind->name, "tp.buffer") || !row || !pt || pt.getValue() != kind->progType ||
      op.getProgType() != kind->progType || op.getAttachType() != bpfmlir::attachTypeOf(*row, attach) ||
      !f || !a || f->count != 0 || f->kind != "int" || op.getCtxOffset() != f->offset ||
      op.getCtxBytes() != f->bytes || f->bytes != a->bytes || op.getBufferOffset() != 0 || op.getBufferBytes() != 4)
    return op.emitOpError("tp.buffer: ABI shape mismatch");
  return success();
}

LogicalResult TpBufferLoadOp::verify() { return verifyTpBufferABI(*this); }
LogicalResult TpBufferStoreOp::verify() { return verifyTpBufferABI(*this); }

LogicalResult CoreFieldLoadOp::verify() {
  if (getStructName().empty() || getField().empty())
    return emitOpError() << "needs a struct and a field name";
  return success();
}
