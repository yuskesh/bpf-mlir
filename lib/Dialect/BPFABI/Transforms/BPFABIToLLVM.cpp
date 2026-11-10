//===- BPFABIToLLVM.cpp - expand kernel ABI operations into LLVM -------------===//
//
// Helper calls use libbpf's integer-to-function-pointer convention:
// inttoptr helper_id followed by an indirect call, lowered by BPF to call imm.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/BPFABI/Transforms/Passes.h"
#include "TpBufferLoweringInternal.h"

#include "bpf-mlir/Dialect/BPFABI/IR/BPFABIDialect.h"

#include "mlir/Dialect/LLVMIR/LLVMDialect.h"
#include "mlir/IR/Builders.h"

namespace mlir {
namespace bpfabi {
#define GEN_PASS_DEF_CONVERTBPFABITOLLVM
#include "bpf-mlir/Dialect/BPFABI/Transforms/Passes.h.inc"
} // namespace bpfabi
} // namespace mlir

using namespace mlir;
using namespace mlir::bpfabi;
namespace tpbuffer = mlir::bpfabi::detail;

namespace {

void expandHelperCall(HelperCallOp op) {
  OpBuilder b(op);
  Location loc = op.getLoc();
  auto ptrTy = LLVM::LLVMPointerType::get(op.getContext());
  Value num = LLVM::ConstantOp::create(b, loc, b.getI64Type(),
                                       b.getI64IntegerAttr(op.getId()));
  Value fn = LLVM::IntToPtrOp::create(b, loc, ptrTy, num);
  SmallVector<Type> argTys(op.getArgs().getTypes());
  Type resTy = op.getNumResults() ? op.getResult(0).getType() : Type();
  auto fnTy = LLVM::LLVMFunctionType::get(
      resTy ? resTy : LLVM::LLVMVoidType::get(op.getContext()), argTys);
  SmallVector<Value> callArgs;
  callArgs.push_back(fn);
  callArgs.append(op.getArgs().begin(), op.getArgs().end());
  auto call = LLVM::CallOp::create(b, loc, fnTy, callArgs);
  if (resTy)
    op.getResult(0).replaceAllUsesWith(call.getResult());
  op.erase();
}

// kfuncs directly call named extern functions in .ksyms, like clang __ksym.
// BPF emits call -1 with src_reg=1, R_BPF_64_32 relocation, extern BTF FUNC and
// .ksyms DATASEC. ObjectEmitter attaches DISubprogram/section metadata because
// MLIR translation drops declaration sections; bpfabi.kfunc identifies them.
// Loader resolves kernel BTF IDs by name.
LogicalResult expandKfuncCall(KfuncCallOp op, ModuleOp module) {
  SmallVector<Type> argTys(op.getArgs().getTypes());
  Type resTy = op.getNumResults() ? op.getResult(0).getType() : Type();
  auto fnTy = LLVM::LLVMFunctionType::get(resTy ? resTy : LLVM::LLVMVoidType::get(op.getContext()), argTys);
  auto fn = module.lookupSymbol<LLVM::LLVMFuncOp>(op.getCallee());
  if (!fn) {
    if (Operation *other = module.lookupSymbol(op.getCallee()))
      return op.emitOpError() << "kfunc \"" << op.getCallee() << "\" collides with another symbol of the same name ("
                              << other->getName() << ")";
    OpBuilder mb(module.getBodyRegion());
    mb.setInsertionPointToStart(module.getBody());
    fn = LLVM::LLVMFuncOp::create(mb, op.getLoc(), op.getCallee(), fnTy);
    fn.setSection(StringRef(".ksyms"));
    fn->setAttr("bpfabi.kfunc", mb.getUnitAttr());
  } else if (!fn->hasAttr("bpfabi.kfunc") || fn.getFunctionType() != fnTy) {
    return op.emitOpError() << "kfunc \"" << op.getCallee() << "\" is called with type " << fnTy
                            << " but the module already has @" << op.getCallee() << " of type " << fn.getFunctionType();
  }
  OpBuilder b(op);
  auto call = LLVM::CallOp::create(b, op.getLoc(), fn, op.getArgs());
  if (resTy)
    op.getResult(0).replaceAllUsesWith(call.getResult());
  op.erase();
  return success();
}

void expandCtxPacket(CtxPacketOp op) {
  OpBuilder b(op);
  Location loc = op.getLoc();
  auto ptrTy = LLVM::LLVMPointerType::get(op.getContext());
  int64_t w = op.getFieldBytes();
  Type fieldTy = b.getIntegerType(w * 8);
  // Index context as an array of field-width integers, matching the C ctx->data width.
  Value dataP = LLVM::GEPOp::create(
      b, loc, ptrTy, fieldTy, op.getCtx(),
      ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(op.getDataOffset() / w)});
  Value endP = LLVM::GEPOp::create(
      b, loc, ptrTy, fieldTy, op.getCtx(),
      ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(op.getDataEndOffset() / w)});
  // Read u32, widen to 64 bits, then convert to pointer: (void *)(long)ctx->data.
  auto asPtr = [&](Value raw) -> Value {
    Value wide = raw;
    if (w < 8)
      wide = LLVM::ZExtOp::create(b, loc, b.getI64Type(), raw);
    return LLVM::IntToPtrOp::create(b, loc, ptrTy, wide);
  };
  // Context fields are naturally aligned. Explicit field-width alignment is
  // essential: default i64 alignment four makes BPF split eight-byte pointer
  // reads, which cg_sockopt_is_valid_access rejects for optval/optval_end.
  // Four-byte xdp_md/__sk_buff data fields retain alignment four.
  Value data = asPtr(LLVM::LoadOp::create(b, loc, fieldTy, dataP, /*alignment=*/w));
  Value end = asPtr(LLVM::LoadOp::create(b, loc, fieldTy, endP, /*alignment=*/w));
  op.getData().replaceAllUsesWith(data);
  op.getDataEnd().replaceAllUsesWith(end);
  op.erase();
}

void expandCtxMeta(CtxMetaOp op) {
  OpBuilder b(op);
  Location loc = op.getLoc();
  auto ptrTy = LLVM::LLVMPointerType::get(op.getContext());
  int64_t w = op.getFieldBytes();
  Type fieldTy = b.getIntegerType(w * 8);
  Value metaP = LLVM::GEPOp::create(b, loc, ptrTy, fieldTy, op.getCtx(),
                                    ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(op.getMetaOffset() / w)});
  Value dataP = LLVM::GEPOp::create(b, loc, ptrTy, fieldTy, op.getCtx(),
                                    ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(op.getDataOffset() / w)});
  auto asPtr = [&](Value raw) -> Value {
    Value wide = LLVM::ZExtOp::create(b, loc, b.getI64Type(), raw);
    return LLVM::IntToPtrOp::create(b, loc, ptrTy, wide);
  };
  Value meta = asPtr(LLVM::LoadOp::create(b, loc, fieldTy, metaP, /*alignment=*/w));
  Value data = asPtr(LLVM::LoadOp::create(b, loc, fieldTy, dataP, /*alignment=*/w));
  op.getMeta().replaceAllUsesWith(meta);
  op.getData().replaceAllUsesWith(data);
  op.erase();
}

// arena window address = inttoptr (base + offset) into address space 1.
// No explicit addrspacecast: the BPF backend inserts addr_space_cast before
// the first access.
void expandArenaAddr(ArenaAddrOp op) {
  OpBuilder b(op);
  Location loc = op.getLoc();
  Value sum = LLVM::AddOp::create(b, loc, op.getBase(), op.getOffset());
  Value p = LLVM::IntToPtrOp::create(b, loc, op.getResult().getType(), sum);
  op.getResult().replaceAllUsesWith(p);
  op.erase();
}

// Tracing arguments read the indexed eight-byte context slot and convert to pointer.
void expandCtxArg(CtxArgOp op) {
  OpBuilder b(op);
  Location loc = op.getLoc();
  auto ptrTy = LLVM::LLVMPointerType::get(op.getContext());
  Type slotTy = b.getIntegerType(op.getFieldBytes() * 8);
  Value at = LLVM::GEPOp::create(
      b, loc, ptrTy, slotTy, op.getCtx(),
      ArrayRef<LLVM::GEPArg>{
          static_cast<int32_t>(op.getOffset() / op.getFieldBytes())});
  // Read the result type: argument pointer or fexit u64 return.
  Value raw = LLVM::LoadOp::create(b, loc, op.getResult().getType(), at, /*alignment=*/8);
  op.getResult().replaceAllUsesWith(raw);
  op.erase();
}

// Read eight bytes at the pt_regs offset guarded by pre-load ctxfield matching.
void expandKprobeArg(KprobeArgOp op) {
  OpBuilder b(op);
  Location loc = op.getLoc();
  auto ptrTy = LLVM::LLVMPointerType::get(op.getContext());
  Value at = LLVM::GEPOp::create(b, loc, ptrTy, b.getI8Type(), op.getCtx(),
                                 ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(op.getOffset())});
  Value raw = LLVM::LoadOp::create(b, loc, b.getI64Type(), at, /*alignment=*/8);
  op.getResult().replaceAllUsesWith(raw);
  op.erase();
}

// CO-RE reads become __ebpf_core.<struct>.<field>(ptr)->iN marker calls.
// LLVM dialect cannot represent the elementtype/local DI needed by
// llvm.preserve.struct.access.index, so ObjectEmitter expands markers in LLVM
// IR and rejects any unresolved marker before emission.
// a guarded site's marker ends in "@<id>,<id>…" (the provisional guard
// ids of ebpf-verify-schema); ObjectEmitter strips it and binds the kfield row.
std::string guardSuffix(Operation *op) {
  auto a = op->getAttrOfType<DenseI32ArrayAttr>("ebpf.guards");
  if (!a || a.empty())
    return "";
  std::string s = "@";
  for (auto [i, g] : llvm::enumerate(a.asArrayRef()))
    s += (i ? "," : "") + std::to_string(g);
  return s;
}

// __ebpf_core_enum.<enum>.<name>() -> i64. ObjectEmitter replaces it with
// llvm.bpf.preserve.enum.value (the local value is the UAPI table's, which it
// looks up by name). The call is not hoisted: it has no memory attributes.
void expandCoreEnumValue(CoreEnumValueOp op, ModuleOp module) {
  std::string name = ("__ebpf_core_enum." + op.getEnumName() + "." + op.getName()).str();
  auto fnTy = LLVM::LLVMFunctionType::get(IntegerType::get(op.getContext(), 64), {});
  auto fn = module.lookupSymbol<LLVM::LLVMFuncOp>(name);
  if (!fn) {
    OpBuilder mb(module.getBodyRegion());
    mb.setInsertionPointToStart(module.getBody());
    fn = LLVM::LLVMFuncOp::create(mb, op.getLoc(), name, fnTy);
  }
  OpBuilder b(op);
  auto call = LLVM::CallOp::create(b, op.getLoc(), fn, ValueRange{});
  op.getResult().replaceAllUsesWith(call.getResult());
  op.erase();
}

// __ebpf_core_exists.<type|field>.<struct>[.<field>]() -> i32.
void expandCoreExists(CoreExistsOp op, ModuleOp module) {
  std::string name = ("__ebpf_core_exists." + op.getKind() + "." + op.getStructName() +
                      (op.getField().empty() ? std::string() : "." + op.getField().str()))
                         .str();
  auto fnTy = LLVM::LLVMFunctionType::get(IntegerType::get(op.getContext(), 32), {});
  auto fn = module.lookupSymbol<LLVM::LLVMFuncOp>(name);
  if (!fn) {
    OpBuilder mb(module.getBodyRegion());
    mb.setInsertionPointToStart(module.getBody());
    fn = LLVM::LLVMFuncOp::create(mb, op.getLoc(), name, fnTy);
  }
  OpBuilder b(op);
  auto call = LLVM::CallOp::create(b, op.getLoc(), fn, ValueRange{});
  op.getResult().replaceAllUsesWith(call.getResult());
  op.erase();
}

// __ebpf_core_offset.<struct>.<field>[@guards]() -> i32.
void expandCoreFieldOffset(CoreFieldOffsetOp op, ModuleOp module) {
  std::string name = ("__ebpf_core_offset." + op.getStructName() + "." + op.getField()).str() + guardSuffix(op);
  auto fnTy = LLVM::LLVMFunctionType::get(IntegerType::get(op.getContext(), 32), {});
  auto fn = module.lookupSymbol<LLVM::LLVMFuncOp>(name);
  if (!fn) {
    OpBuilder mb(module.getBodyRegion());
    mb.setInsertionPointToStart(module.getBody());
    fn = LLVM::LLVMFuncOp::create(mb, op.getLoc(), name, fnTy);
  }
  OpBuilder b(op);
  auto call = LLVM::CallOp::create(b, op.getLoc(), fn, ValueRange{});
  op.getResult().replaceAllUsesWith(call.getResult());
  op.erase();
}

void expandCoreFieldLoad(CoreFieldLoadOp op, ModuleOp module) {
  std::string name =
      ("__ebpf_core." + op.getStructName() + "." + op.getField()).str() + guardSuffix(op);
  auto ptrTy = LLVM::LLVMPointerType::get(op.getContext());
  auto fnTy = LLVM::LLVMFunctionType::get(op.getResult().getType(), {ptrTy});
  auto fn = module.lookupSymbol<LLVM::LLVMFuncOp>(name);
  if (!fn) {
    OpBuilder mb(module.getBodyRegion());
    mb.setInsertionPointToStart(module.getBody());
    fn = LLVM::LLVMFuncOp::create(mb, op.getLoc(), name, fnTy);
  }
  OpBuilder b(op);
  auto call = LLVM::CallOp::create(b, op.getLoc(), fn, ValueRange{op.getPtr()});
  op.getResult().replaceAllUsesWith(call.getResult());
  op.erase();
}

// Address-only marker: __ebpf_core_addr.<S>.<field>(ptr)->ptr. ObjectEmitter
// expands preserve.struct.access.index without loading.
void expandCoreFieldAddr(CoreFieldAddrOp op, ModuleOp module) {
  std::string name = ("__ebpf_core_addr." + op.getStructName() + "." + op.getField()).str() + guardSuffix(op);
  auto ptrTy = LLVM::LLVMPointerType::get(op.getContext());
  auto fnTy = LLVM::LLVMFunctionType::get(ptrTy, {ptrTy});
  auto fn = module.lookupSymbol<LLVM::LLVMFuncOp>(name);
  if (!fn) {
    OpBuilder mb(module.getBodyRegion());
    mb.setInsertionPointToStart(module.getBody());
    fn = LLVM::LLVMFuncOp::create(mb, op.getLoc(), name, fnTy);
  }
  OpBuilder b(op);
  auto call = LLVM::CallOp::create(b, op.getLoc(), fn, ValueRange{op.getPtr()});
  op.getResult().replaceAllUsesWith(call.getResult());
  op.erase();
}

void expandReturn(ReturnOp op) {
  OpBuilder b(op);
  Location loc = op.getLoc();
  Value c = LLVM::ConstantOp::create(b, loc, b.getI32Type(),
                                     b.getI32IntegerAttr(op.getValue()));
  LLVM::ReturnOp::create(b, loc, ValueRange{c});
  op.erase();
}

// Access context integer fields once at ctx+offset with the declared width.
// Volatile prevents LLVM combining, splitting or removing accesses: verifier
// validation and rewriting depend on the original offset and width.
static Value ctxFieldAddr(OpBuilder &b, Location loc, Value ctx, int64_t offset) {
  auto ptrTy = LLVM::LLVMPointerType::get(ctx.getContext());
  return LLVM::GEPOp::create(b, loc, ptrTy, b.getI8Type(), ctx, ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(offset)});
}

void expandCtxFieldLoad(CtxFieldLoadOp op) {
  OpBuilder b(op);
  Value at = ctxFieldAddr(b, op.getLoc(), op.getCtx(), op.getOffset());
  Value v = LLVM::LoadOp::create(b, op.getLoc(), op.getResult().getType(), at, /*alignment=*/op.getFieldBytes(), /*isVolatile=*/true);
  op.getResult().replaceAllUsesWith(v);
  op.erase();
}

void expandCtxFieldStore(CtxFieldStoreOp op) {
  OpBuilder b(op);
  Value at = ctxFieldAddr(b, op.getLoc(), op.getCtx(), op.getOffset());
  LLVM::StoreOp::create(b, op.getLoc(), op.getValue(), at, /*alignment=*/op.getFieldBytes(), /*isVolatile=*/true);
  op.erase();
}

struct ConvertBPFABIToLLVMPass
    : public mlir::bpfabi::impl::ConvertBPFABIToLLVMBase<
          ConvertBPFABIToLLVMPass> {
  void runOnOperation() override {
    SmallVector<tpbuffer::TpBufferExpected> tpExpected;
    if (failed(tpbuffer::collectTpBufferExpected(getOperation(), tpExpected)))
      return signalPassFailure();
    SmallVector<tpbuffer::TpBufferGenerated> tpGenerated(tpExpected.size());
    llvm::DenseMap<Operation *, unsigned> tpIndex;
    for (unsigned i = 0; i < tpExpected.size(); ++i) tpIndex[tpExpected[i].origin] = i;
    SmallVector<Operation *> ops;
    getOperation().walk([&](Operation *op) {
      if (isa<HelperCallOp, CtxPacketOp, CtxMetaOp, ReturnOp, CtxArgOp, CoreFieldLoadOp, CoreFieldAddrOp, CoreExistsOp, CoreFieldOffsetOp, KprobeArgOp, CtxFieldLoadOp, CtxFieldStoreOp,
              KfuncCallOp, TpBufferLoadOp, TpBufferStoreOp, CoreEnumValueOp, ArenaAddrOp>(op))
        ops.push_back(op);
    });
    for (Operation *op : ops) {
      if (auto aa = dyn_cast<ArenaAddrOp>(op))
        expandArenaAddr(aa);
      else if (auto ec = dyn_cast<CoreEnumValueOp>(op)) // CO-RE enum value marker (was immediate).
        expandCoreEnumValue(ec, getOperation());
      else if (isa<TpBufferLoadOp, TpBufferStoreOp>(op)) {
        unsigned i = tpIndex.lookup(op);
        if (failed(tpbuffer::expandTpBuffer(tpExpected[i], tpGenerated[i]))) return signalPassFailure();
      }
      else if (auto h = dyn_cast<HelperCallOp>(op))
        expandHelperCall(h);
      else if (auto kf = dyn_cast<KfuncCallOp>(op)) {
        if (failed(expandKfuncCall(kf, getOperation())))
          return signalPassFailure();
      }
      else if (auto c = dyn_cast<CtxPacketOp>(op))
        expandCtxPacket(c);
      else if (auto cm = dyn_cast<CtxMetaOp>(op))
        expandCtxMeta(cm);
      else if (auto a = dyn_cast<CtxArgOp>(op))
        expandCtxArg(a);
      else if (auto f = dyn_cast<CoreFieldLoadOp>(op))
        expandCoreFieldLoad(f, getOperation());
      else if (auto fa = dyn_cast<CoreFieldAddrOp>(op))
        expandCoreFieldAddr(fa, getOperation());
      else if (auto ce = dyn_cast<CoreExistsOp>(op))
        expandCoreExists(ce, getOperation());
      else if (auto co = dyn_cast<CoreFieldOffsetOp>(op))
        expandCoreFieldOffset(co, getOperation());
      else if (auto cl = dyn_cast<CtxFieldLoadOp>(op))
        expandCtxFieldLoad(cl);
      else if (auto cs = dyn_cast<CtxFieldStoreOp>(op))
        expandCtxFieldStore(cs);
      else if (auto k = dyn_cast<KprobeArgOp>(op))
        expandKprobeArg(k);
      else
        expandReturn(cast<ReturnOp>(op));
    }
    if (failed(tpbuffer::finalizeTpBufferLowering(getOperation(), tpExpected, tpGenerated)))
      return signalPassFailure();
  }
};

} // namespace
