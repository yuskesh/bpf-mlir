#include "TpBufferLoweringInternal.h"
#include "bpf-mlir/Dialect/BPFABI/IR/BPFABIDialect.h"
#include "mlir/IR/Builders.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"

namespace mlir::bpfabi::detail {
namespace {
bool isTp(Operation *op) { return isa<TpBufferLoadOp, TpBufferStoreOp>(op); }
LogicalResult reject(const TpBufferExpected &e, StringRef reason) {
  return e.function->emitError() << "tp.buffer: " << reason;
}
SmallVector<Operation *> handles(const TpBufferGenerated &g) {
  return {g.ctxGEP, g.ctxRead, g.rawToPtr, g.bufferGEP, g.access};
}
bool soleUser(Value v, Operation *expected) {
  return v.hasOneUse() && *v.getUsers().begin() == expected;
}
bool gepAt(LLVM::GEPOp op, Value base, int64_t offset) {
  return op.getBase() == base && op.getElemType().isInteger(8) && op.getDynamicIndices().empty() &&
         op.getRawConstantIndices().size() == 1 && op.getRawConstantIndices()[0] == offset;
}
} // namespace

LogicalResult collectTpBufferExpected(ModuleOp module, llvm::SmallVectorImpl<TpBufferExpected> &out) {
  out.clear();
  llvm::DenseMap<Block *, unsigned> ordinals;
  WalkResult result = module.walk([&](Operation *op) -> WalkResult {
    if (!isTp(op)) return WalkResult::advance();
    bool load = isa<TpBufferLoadOp>(op);
    if (failed(load ? cast<TpBufferLoadOp>(op).verify() : cast<TpBufferStoreOp>(op).verify()))
      return WalkResult::interrupt();
    TpBufferExpected e;
    e.origin = op;
    e.function = op->getParentOfType<LLVM::LLVMFuncOp>();
    e.block = op->getBlock();
    e.entryCtx = e.function.getBody().front().getArgument(0);
    e.sourceOrdinal = out.size();
    e.blockOrdinal = ordinals[e.block]++;
    e.direction = load ? TpBufferDirection::Load : TpBufferDirection::Store;
    e.progType = op->getAttrOfType<StringAttr>("prog_type");
    e.attachType = op->getAttrOfType<StringAttr>("attach_type");
    auto number = [&](StringRef key) { return op->getAttrOfType<IntegerAttr>(key).getInt(); };
    e.ctxOffset = number("ctx_offset"); e.ctxBytes = number("ctx_bytes");
    e.bufferOffset = number("buffer_offset"); e.bufferBytes = number("buffer_bytes");
    e.scalarType = load ? op->getResult(0).getType() : op->getOperand(1).getType();
    out.push_back(e);
    return WalkResult::advance();
  });
  return failure(result.wasInterrupted());
}

LogicalResult expandTpBuffer(const TpBufferExpected &e, TpBufferGenerated &g) {
  OpBuilder b(e.origin);
  auto loc = e.origin->getLoc();
  auto ptr = LLVM::LLVMPointerType::get(b.getContext());
  auto ctx = LLVM::GEPOp::create(b, loc, ptr, b.getI8Type(), e.entryCtx,
                               ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(e.ctxOffset)});
  auto read = LLVM::LoadOp::create(b, loc, b.getIntegerType(e.ctxBytes * 8), ctx, e.ctxBytes, true);
  auto raw = LLVM::IntToPtrOp::create(b, loc, ptr, read.getResult());
  auto buffer = LLVM::GEPOp::create(b, loc, ptr, b.getI8Type(), raw,
                                  ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(e.bufferOffset)});
  g.ctxGEP = ctx; g.ctxRead = read; g.rawToPtr = raw; g.bufferGEP = buffer;
  if (e.direction == TpBufferDirection::Load) {
    auto load = LLVM::LoadOp::create(b, loc, e.scalarType, buffer, e.bufferBytes, true);
    g.access = load;
    e.origin->getResult(0).replaceAllUsesWith(load.getResult());
  } else {
    g.access = LLVM::StoreOp::create(b, loc, e.origin->getOperand(e.storeOperandIndex), buffer, e.bufferBytes, true);
  }
  return success(); // origin remains live until all RAUW and exit checks finish.
}

LogicalResult checkTpBufferLowering(ModuleOp module, const TpBufferExpected &e, const TpBufferGenerated &g,
                                   TpBufferCheckPhase phase) {
  llvm::DenseSet<Operation *> live;
  module.walk([&](Operation *op) { live.insert(op); });
  auto generated = handles(g);
  llvm::DenseSet<Operation *> unique;
  for (Operation *op : generated)
    if (!op || !live.contains(op) || !unique.insert(op).second || op->getBlock() != e.block ||
        op->getParentOfType<LLVM::LLVMFuncOp>() != e.function)
      return reject(e, "lowering coverage mismatch");
  if (phase == TpBufferCheckPhase::BeforeErase) {
    if (!e.origin || !live.contains(e.origin) || !isTp(e.origin) || e.origin->getBlock() != e.block ||
        e.origin->getOperand(0) != e.entryCtx)
      return reject(e, "lowering coverage mismatch");
    auto num = [&](StringRef k, int64_t want) {
      auto a = e.origin->getAttrOfType<IntegerAttr>(k); return a && a.getInt() == want;
    };
    if (e.origin->getAttr("prog_type") != e.progType || e.origin->getAttr("attach_type") != e.attachType ||
        !num("ctx_offset", e.ctxOffset) || !num("ctx_bytes", e.ctxBytes) ||
        !num("buffer_offset", e.bufferOffset) || !num("buffer_bytes", e.bufferBytes))
      return reject(e, "ABI shape mismatch");
  } else if (e.origin) {
    return reject(e, "lowering coverage mismatch");
  }
  auto ctx = dyn_cast<LLVM::GEPOp>(g.ctxGEP);
  auto read = dyn_cast<LLVM::LoadOp>(g.ctxRead);
  auto raw = dyn_cast<LLVM::IntToPtrOp>(g.rawToPtr);
  auto buffer = dyn_cast<LLVM::GEPOp>(g.bufferGEP);
  if (!ctx || !read || !raw || !buffer || !gepAt(ctx, e.entryCtx, e.ctxOffset) ||
      ctx.getResult().getType() != e.entryCtx.getType() || buffer.getResult().getType() != e.entryCtx.getType() ||
      read.getAddr() != ctx.getResult() || !read.getResult().getType().isInteger(e.ctxBytes * 8) ||
      !read.getVolatile_() || read.getAlignment() != static_cast<uint64_t>(e.ctxBytes) ||
      raw.getArg() != read.getResult() || raw.getResult().getType() != e.entryCtx.getType() ||
      !gepAt(buffer, raw.getResult(), e.bufferOffset))
    return reject(e, "generated access shape mismatch");
  if (e.direction == TpBufferDirection::Load) {
    auto access = dyn_cast<LLVM::LoadOp>(g.access);
    if (!access || access.getAddr() != buffer.getResult() || access.getResult().getType() != e.scalarType ||
        !access.getVolatile_() || access.getAlignment() != static_cast<uint64_t>(e.bufferBytes))
      return reject(e, "generated access shape mismatch");
    if (phase == TpBufferCheckPhase::BeforeErase && !e.origin->getResult(0).use_empty())
      return reject(e, "lowering coverage mismatch");
  } else {
    auto access = dyn_cast<LLVM::StoreOp>(g.access);
    if (!access || access.getAddr() != buffer.getResult() || access.getValue().getType() != e.scalarType ||
        !access.getVolatile_() || access.getAlignment() != static_cast<uint64_t>(e.bufferBytes))
      return reject(e, "generated access shape mismatch");
    Value expected = phase == TpBufferCheckPhase::BeforeErase ? e.origin->getOpOperand(e.storeOperandIndex).get()
                                                              : e.storeValueAfterRAUW;
    if (!expected || access.getValue() != expected)
      return reject(e, "generated store input mismatch");
  }
  if (!soleUser(ctx.getResult(), read) || !soleUser(read.getResult(), raw) ||
      !soleUser(raw.getResult(), buffer) || !soleUser(buffer.getResult(), g.access))
    return reject(e, "private pointer escape");
  for (unsigned i = 1; i < generated.size(); ++i)
    if (generated[i - 1]->getNextNode() != generated[i])
      return reject(e, "generated access order mismatch");
  if (phase == TpBufferCheckPhase::BeforeErase && g.access->getNextNode() != e.origin)
    return reject(e, "generated access order mismatch");
  return success();
}

LogicalResult finalizeTpBufferLowering(ModuleOp module, llvm::MutableArrayRef<TpBufferExpected> expected,
                                      llvm::ArrayRef<TpBufferGenerated> generated) {
  auto coverageFailure = [&]() -> LogicalResult { return module.emitError("tp.buffer: lowering coverage mismatch"); };
  if (expected.size() != generated.size()) return coverageFailure();
  llvm::DenseSet<Operation *> origins, generatedSet;
  llvm::DenseMap<Block *, unsigned> blockOrdinals;
  llvm::DenseMap<Block *, Operation *> previousAccess;
  for (unsigned i = 0; i < expected.size(); ++i) {
    auto &e = expected[i];
    if (e.sourceOrdinal != i || e.blockOrdinal != blockOrdinals[e.block]++ || !origins.insert(e.origin).second)
      return coverageFailure();
    for (auto *h : handles(generated[i]))
      if (!generatedSet.insert(h).second) return coverageFailure();
    if (failed(checkTpBufferLowering(module, e, generated[i], TpBufferCheckPhase::BeforeErase))) return failure();
    auto *prev = previousAccess.lookup(e.block);
    if (prev && !prev->isBeforeInBlock(generated[i].ctxGEP))
      return reject(e, "generated access order mismatch");
    previousAccess[e.block] = generated[i].access;
  }
  llvm::DenseSet<Operation *> actual;
  module.walk([&](Operation *op) { if (isTp(op)) actual.insert(op); });
  if (actual != origins) return coverageFailure();
  for (auto &e : expected) {
    if (e.direction != TpBufferDirection::Store) continue;
    e.storeValueAfterRAUW = e.origin->getOpOperand(e.storeOperandIndex).get();
    if (origins.contains(e.storeValueAfterRAUW.getDefiningOp()))
      return reject(e, "generated store input mismatch");
  }
  for (auto &e : expected) {
    auto *origin = e.origin;
    e.origin = nullptr;
    origin->erase();
  }
  for (unsigned i = 0; i < expected.size(); ++i)
    if (failed(checkTpBufferLowering(module, expected[i], generated[i], TpBufferCheckPhase::AfterErase))) return failure();
  bool unexpanded = false;
  module.walk([&](Operation *op) { unexpanded |= op->getName().getDialectNamespace() == "bpfabi"; });
  return unexpanded ? coverageFailure() : success();
}
} // namespace mlir::bpfabi::detail
