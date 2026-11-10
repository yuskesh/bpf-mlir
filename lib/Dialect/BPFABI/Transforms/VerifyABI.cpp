//===- VerifyABI.cpp - kernel ABI stage exit checks -------------------------===//
//
// Match explicit ABI numbers against KernelABI.h, independently of lowering
// that emits from the same table. This catches lowering defects and malformed
// handwritten ABI IR, including wrong context widths. Match return shapes
// (void/integer/pointer); unresolved table nullability remains Unknown.
// Nullable helper results may be used only under the non-null checked edge,
// independently verifying the structure established by earlier stages.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/BPFABI/Transforms/Passes.h"

#include "bpf-mlir/Dialect/BPFABI/IR/BPFABIDialect.h"
#include "bpf-mlir/Dialect/BPFABI/KernelABI.h"
#include "bpf-mlir/Support/CheckResult.h"
#include "bpf-mlir/Support/ProgramKinds.h"

#include "mlir/Dialect/LLVMIR/LLVMDialect.h"
#include "mlir/IR/Dominance.h"
#include "mlir/IR/Matchers.h"

namespace mlir {
namespace bpfabi {
#define GEN_PASS_DEF_BPFABIVERIFY
#include "bpf-mlir/Dialect/BPFABI/Transforms/Passes.h.inc"
} // namespace bpfabi
} // namespace mlir

using namespace mlir;
using namespace mlir::bpfabi;
using bpfmlir::CheckTally;
using bpfmlir::CheckVerdict;

namespace {

CheckVerdict checkHelper(HelperCallOp op) {
  const HelperABI *h = lookupHelper(op.getCallee());
  if (!h) {
    op.emitOpError() << "helper \"" << op.getCallee()
                     << "\" is not in the UAPI table";
    return CheckVerdict::Rejected;
  }
  if (static_cast<int64_t>(op.getId()) != h->id) {
    op.emitOpError() << "helper \"" << h->name << "\" has id " << h->id
                     << " in the UAPI table, but the IR calls id "
                     << op.getId();
    return CheckVerdict::Rejected;
  }
  auto [minArgs, maxArgs] = helperArgumentRange(*h);
  if (op.getArgs().size() < minArgs || op.getArgs().size() > maxArgs) {
    auto diag = op.emitOpError();
    diag << "helper \"" << h->name << "\" takes " << minArgs;
    if (minArgs != maxArgs)
      diag << ".." << maxArgs;
    diag << " argument(s), got " << op.getArgs().size();
    return CheckVerdict::Rejected;
  }
  // Return shape.
  bool shapeOk = false;
  switch (h->retKind) {
  case RetKind::Void:
    shapeOk = op.getNumResults() == 0;
    break;
  case RetKind::Int:
    shapeOk = op.getNumResults() == 1 && op.getResult(0).getType().isInteger();
    break;
  case RetKind::Ptr:
    shapeOk = op.getNumResults() == 1 &&
              isa<LLVM::LLVMPointerType>(op.getResult(0).getType());
    break;
  }
  if (!shapeOk) {
    const char *want = h->retKind == RetKind::Void  ? "no result (void)"
                       : h->retKind == RetKind::Int ? "one integer result"
                                                    : "one pointer result";
    op.emitOpError() << "helper \"" << h->name << "\" returns " << want
                     << " according to the UAPI table";
    return CheckVerdict::Rejected;
  }
  bool wantNullable = h->retKind == RetKind::Ptr && h->markNullable();
  if (op.getRetNullable() != wantNullable) {
    op.emitOpError() << "helper \"" << h->name << "\" "
                     << (wantNullable ? "can return NULL" : "never returns NULL")
                     << " according to the UAPI table, but the IR marks it "
                     << (op.getRetNullable() ? "nullable" : "non-null");
    return CheckVerdict::Rejected;
  }
  // Unknown table nullability remains Unknown even though IR conservatively
  // models the result as nullable; do not report Verified.
  if (h->retKind == RetKind::Ptr && h->nullability == Nullability::Unknown)
    return CheckVerdict::Unknown;
  return CheckVerdict::Verified;
}

// Match kfunc argument count, return shape and ret_null flag against ABI rows.
// Availability and signatures remain kernel-dependent, so table agreement is
// Unknown here rather than Verified; loading must establish acceptance.
CheckVerdict checkKfunc(KfuncCallOp op) {
  const KfuncABI *k = lookupKfunc(op.getCallee());
  if (!k) {
    op.emitOpError() << "kfunc \"" << op.getCallee() << "\" is not in the UAPI table";
    return CheckVerdict::Rejected;
  }
  if (op.getArgs().size() != k->paramList().size()) {
    op.emitOpError() << "kfunc \"" << k->name << "\" takes " << k->paramList().size() << " argument(s), got " << op.getArgs().size();
    return CheckVerdict::Rejected;
  }
  llvm::StringRef ret = k->ret;
  bool shapeOk = ret == "void" ? op.getNumResults() == 0
                 : ret.starts_with("*") ? op.getNumResults() == 1 && isa<LLVM::LLVMPointerType>(op.getResult(0).getType())
                                        : op.getNumResults() == 1 && op.getResult(0).getType().isInteger();
  if (!shapeOk) {
    op.emitOpError() << "kfunc \"" << k->name << "\" returns " << ret << " according to the UAPI table";
    return CheckVerdict::Rejected;
  }
  bool wantNullable = ret.starts_with("*") && k->hasFlag("ret_null");
  if (op.getRetNullable() != wantNullable) {
    op.emitOpError() << "kfunc \"" << k->name << "\" " << (wantNullable ? "can return NULL" : "never returns NULL")
                     << " according to the UAPI table, but the IR marks it " << (op.getRetNullable() ? "nullable" : "non-null");
    return CheckVerdict::Rejected;
  }
  return CheckVerdict::Unknown;
}

// Recognize icmp ne r,null in either operand order; eq also sets *isEq.
bool isNullTestOf(Value cond, Value r, bool *isEq) {
  auto cmp = cond.getDefiningOp<LLVM::ICmpOp>();
  if (!cmp)
    return false;
  auto isZero = [](Value v) { return v.getDefiningOp<LLVM::ZeroOp>() != nullptr; };
  bool match = (cmp.getLhs() == r && isZero(cmp.getRhs())) ||
               (cmp.getRhs() == r && isZero(cmp.getLhs()));
  if (!match)
    return false;
  if (cmp.getPredicate() == LLVM::ICmpPredicate::ne) {
    *isEq = false;
    return true;
  }
  if (cmp.getPredicate() == LLVM::ICmpPredicate::eq) {
    *isEq = true;
    return true;
  }
  return false;
}

// Require nullable helper result r to be used only below its non-null edge:
// cond_br(icmp ne r,null)'s true successor, or eq's false successor, with that
// edge as the successor's sole predecessor. The check's own icmp is allowed.
template <typename CallT> CheckVerdict checkNullGuard(CallT op, DominanceInfo &dom, const char *what = "helper") {
  Value r = op.getResult(0);
  SmallVector<Block *> guarded;
  for (Operation *user : r.getUsers()) {
    bool isEq = false;
    if (user->getNumResults() != 1 || !isNullTestOf(user->getResult(0), r, &isEq))
      continue;
    for (Operation *br : user->getResult(0).getUsers()) {
      auto cbr = dyn_cast<LLVM::CondBrOp>(br);
      if (!cbr || cbr.getCondition() != user->getResult(0))
        continue;
      Block *safe = isEq ? cbr.getFalseDest() : cbr.getTrueDest();
      Block *other = isEq ? cbr.getTrueDest() : cbr.getFalseDest();
      if (safe != other && safe->getSinglePredecessor() == cbr->getBlock())
        guarded.push_back(safe);
    }
  }
  for (Operation *user : r.getUsers()) {
    bool isEq = false;
    if (user->getNumResults() == 1 && isNullTestOf(user->getResult(0), r, &isEq))
      continue;
    // Passing to an explicitly nullable argument is not a dereference; the
      // callee owns checking it (bpfabi.nullable_args from maybe_ref arguments).
    if (auto call = dyn_cast<LLVM::CallOp>(user); call && call.getCallee()) {
      auto callee = SymbolTable::lookupNearestSymbolFrom<LLVM::LLVMFuncOp>(
          call, call.getCalleeAttr());
      auto nullable = callee ? callee->getAttrOfType<DenseBoolArrayAttr>(
                                   "bpfabi.nullable_args")
                             : DenseBoolArrayAttr();
      if (nullable) {
        bool allNullable = true;
        for (auto [i, v] : llvm::enumerate(call.getArgOperands()))
          if (v == r && (i >= (size_t)nullable.size() || !nullable[i]))
            allNullable = false;
        if (allNullable)
          continue;
      }
    }
    bool ok = llvm::any_of(guarded, [&](Block *g) {
      return dom.dominates(g, user->getBlock());
    });
    if (!ok) {
      auto d = user->emitOpError()
               << "uses the result of " << what << " \"" << op.getCallee()
               << "\", which can return NULL, on a path that has not "
                  "checked it for NULL";
      d.attachNote(op.getLoc())
          << "the kernel rejects this (e.g. `R1 type=ringbuf_mem_or_null "
             "expected=ringbuf_mem`)";
      return CheckVerdict::Rejected;
    }
  }
  return CheckVerdict::Verified;
}

CheckVerdict checkCtxMeta(CtxMetaOp op) {
  auto ctx = lookupMetaCtx(op.getKind());
  if (!ctx) {
    op.emitOpError() << "program kind \"" << op.getKind() << "\" has no data_meta in the UAPI table";
    return CheckVerdict::Rejected;
  }
  if (static_cast<int64_t>(op.getFieldBytes()) != ctx->fieldBytes ||
      static_cast<int64_t>(op.getMetaOffset()) != ctx->metaOffset ||
      static_cast<int64_t>(op.getDataOffset()) != ctx->dataOffset) {
    auto d = op.emitOpError() << "the " << op.getKind() << " context reads data_meta at offset " << op.getMetaOffset()
                              << " / data at offset " << op.getDataOffset() << " with " << op.getFieldBytes()
                              << "-byte loads, but the UAPI table says offsets " << ctx->metaOffset << " / " << ctx->dataOffset
                              << " with " << ctx->fieldBytes << "-byte fields";
    d.attachNote() << "the kernel rejects a context access whose width does not match the field";
    return CheckVerdict::Rejected;
  }
  return CheckVerdict::Verified;
}

CheckVerdict checkCtxPacket(CtxPacketOp op) {
  auto ctx = lookupPacketCtx(op.getKind());
  if (!ctx) {
    op.emitOpError() << "program kind \"" << op.getKind()
                     << "\" has no packet in the UAPI table";
    return CheckVerdict::Rejected;
  }
  if (static_cast<int64_t>(op.getFieldBytes()) != ctx->fieldBytes ||
      static_cast<int64_t>(op.getDataOffset()) != ctx->dataOffset ||
      static_cast<int64_t>(op.getDataEndOffset()) != ctx->dataEndOffset) {
    auto d = op.emitOpError()
             << "the " << op.getKind() << " context reads data at offset "
             << op.getDataOffset() << " / data_end at offset "
             << op.getDataEndOffset() << " with " << op.getFieldBytes()
             << "-byte loads, but the UAPI table says offsets "
             << ctx->dataOffset << " / " << ctx->dataEndOffset << " with "
             << ctx->fieldBytes << "-byte fields";
    d.attachNote() << "the kernel rejects a context access whose width does "
                      "not match the field (e.g. `invalid bpf_context access "
                      "off=4 size=8`)";
    return CheckVerdict::Rejected;
  }
  return CheckVerdict::Verified;
}

// Context integer offsets follow ABI ctxfield rows; widths/modes follow
// capability rows. Fixed UAPI offsets are Verified across targets.
template <typename OpT>
CheckVerdict checkCtxField(OpT op, StringRef mode, Type valueType, std::optional<int64_t> index = std::nullopt) {
  const StructFieldABI *f = lookupStructField(op.getStrct(), op.getField());
  const CtxAccessABI *a = lookupCtxAccess(op.getProgType(), op.getAttachType(), op.getStrct(), op.getField(), mode);
  int64_t bytes = static_cast<int64_t>(op.getFieldBytes());
  // BTF struct-pointer context fields are eight-byte pointer reads. Flexible
  // arrays (count zero) require index in 0..kMaxFlexCtxIndex-1 and offset
  // field_offset+index*element_width. Other fields are single, unindexed values.
  bool btfPtr = mode == "r" && isa<LLVM::LLVMPointerType>(valueType) &&
                lookupCtxBTFPtr(op.getProgType(), op.getAttachType(), op.getStrct(), op.getField());
  bool idxOK = f && (f->count == 0 ? index && *index >= 0 && *index < kMaxFlexCtxIndex : f->count == 1 && !index);
  int64_t want = f ? f->offset + (index ? *index * f->bytes : 0) : -1;
  bool shapeOk = idxOK && (btfPtr ? (f->kind == "ptr" && bytes == 8)
                                  : (f->kind == "int" && valueType.isInteger(static_cast<unsigned>(bytes * 8))));
  if (!shapeOk || !a || static_cast<int64_t>(op.getOffset()) != want || bytes != a->bytes) {
    op.emitOpError() << "accesses " << op.getStrct() << "." << op.getField() << " (" << mode << ") at offset " << op.getOffset() << " with "
                     << bytes << " bytes, which the UAPI table (ctxfield) and the ctx access table (" << op.getProgType() << " / "
                     << op.getAttachType() << ") do not allow";
    return CheckVerdict::Rejected;
  }
  return CheckVerdict::Verified;
}

CheckVerdict checkReturn(ReturnOp op) {
  // Resolve attachment verdicts through the enclosing function section.
  // Handwritten ABI without a matching section may fall back only when every
  // row for the kind shares a family; ambiguity returns nullopt and fails below.
  const bpfmlir::ProgramAttachInfo *row = nullptr;
  if (auto fn = op->getParentOfType<LLVM::LLVMFuncOp>(); fn && fn.getSection()) {
    std::string attach;
    const bpfmlir::ProgramAttachInfo *r = nullptr;
    if (const bpfmlir::ProgramKindInfo *k = bpfmlir::kindOfSection(*fn.getSection(), attach, &r); k && k->name == op.getKind())
      row = r;
  }
  auto v = lookupVerdictValue(op.getKind(), row, op.getAction());
  if (!v) {
    op.emitOpError() << "verdict \"" << op.getAction()
                     << "\" is not in the UAPI table for program kind \""
                     << op.getKind() << "\"";
    return CheckVerdict::Rejected;
  }
  if (static_cast<int32_t>(op.getValue()) != *v) {
    op.emitOpError() << "verdict \"" << op.getAction() << "\" is " << *v
                     << " in the UAPI table, but the IR returns "
                     << op.getValue();
    return CheckVerdict::Rejected;
  }
  return CheckVerdict::Verified;
}

// Tracing arguments read kTracingArgBytes (eight) bytes at 8*index.
CheckVerdict checkCtxArg(CtxArgOp op) {
  if (static_cast<int64_t>(op.getFieldBytes()) != kTracingArgBytes ||
      static_cast<int64_t>(op.getOffset()) !=
          kTracingArgBytes * static_cast<int64_t>(op.getIndex())) {
    op.emitOpError() << "tracing argument " << op.getIndex() << " is read at offset "
                     << op.getOffset() << " with " << op.getFieldBytes()
                     << "-byte loads, but it lives at offset "
                     << kTracingArgBytes * static_cast<int64_t>(op.getIndex())
                     << " with " << kTracingArgBytes << " bytes";
    return CheckVerdict::Rejected;
  }
  return CheckVerdict::Verified;
}

// Probe arguments use architecture-specific ABI offsets/sizes. Agreement is
// Conditional: ctxfield requirements must match target BTF pt_regs before load.
CheckVerdict checkKprobeArg(KprobeArgOp op) {
  // n=0 selects the kretprobe/uretprobe return register from ABI kproberet.
  const KprobeArgABI *k = op.getN() == 0 ? lookupKprobeRet(op.getArch()) : lookupKprobeArg(op.getArch(), static_cast<int>(op.getN()));
  if (!k) {
    op.emitOpError() << "argument " << op.getN() << " has no register on arch \"" << op.getArch() << "\" in the UAPI table";
    return CheckVerdict::Rejected;
  }
  if (static_cast<int64_t>(op.getOffset()) != k->offset || static_cast<int64_t>(op.getFieldBytes()) != k->bytes) {
    op.emitOpError() << "argument " << op.getN() << " is read at offset " << op.getOffset() << " with " << op.getFieldBytes()
                     << " bytes, but the UAPI table puts it in " << k->uapiField << " at offset " << k->offset << " with " << k->bytes
                     << " bytes";
    return CheckVerdict::Rejected;
  }
  return CheckVerdict::Conditional;
}

// CO-RE field offsets resolve from target BTF at load. This stage establishes
// only the declared integer width; field presence, width and sign remain
// Conditional and are recorded as kfield requirements.
CheckVerdict checkCoreFieldLoad(CoreFieldLoadOp op) {
  if (!isa<LLVM::LLVMPointerType>(op.getPtr().getType())) {
    op.emitOpError() << "reads through a non-pointer";
    return CheckVerdict::Rejected;
  }
  if (isa<LLVM::LLVMPointerType>(op.getResult().getType())) // Pointer field.
    return CheckVerdict::Conditional;
  auto rt = dyn_cast<IntegerType>(op.getResult().getType());
  unsigned w = rt ? rt.getWidth() : 0;
  if (w != 8 && w != 16 && w != 32 && w != 64) {
    op.emitOpError() << "only 8 / 16 / 32 / 64-bit CO-RE field reads are supported";
    return CheckVerdict::Rejected;
  }
  return CheckVerdict::Conditional;
}

// an arena window address is made only on the true edge of its range
// compare — its block's sole predecessor ends in llvm.cond_br on
// `icmp ule offset, <constant size − len>` with this block as the true
// destination. The size comes from the schema (③); the shape is checked here.
CheckVerdict checkArenaAddr(ArenaAddrOp op) {
  Block *blk = op->getBlock();
  Block *pred = blk->getSinglePredecessor();
  auto br = pred ? dyn_cast<LLVM::CondBrOp>(pred->getTerminator()) : LLVM::CondBrOp();
  auto cmp = br ? br.getCondition().getDefiningOp<LLVM::ICmpOp>() : LLVM::ICmpOp();
  APInt lim;
  if (!br || br.getTrueDest() != blk || br.getFalseDest() == blk || !cmp || cmp.getPredicate() != LLVM::ICmpPredicate::ule ||
      cmp.getLhs() != op.getOffset() || !matchPattern(cmp.getRhs(), m_ConstantInt(&lim))) {
    op.emitOpError() << "the arena address must be made only in the block entered through the true edge of "
                        "`icmp ule <offset>, <size - len>` on the same offset";
    return CheckVerdict::Rejected;
  }
  return CheckVerdict::Verified;
}

struct BPFABIVerifyPass
    : public mlir::bpfabi::impl::BPFABIVerifyBase<BPFABIVerifyPass> {
  using BPFABIVerifyBase::BPFABIVerifyBase;

  void runOnOperation() override {
    ModuleOp module = getOperation();
    CheckTally tally;
    module.walk([&](Operation *op) {
      if (auto h = dyn_cast<HelperCallOp>(op)) {
        CheckVerdict v = checkHelper(h);
        tally.add(v);
        if (v != CheckVerdict::Rejected && h.getRetNullable() &&
            h.getNumResults() == 1) {
          Operation *fn = h->getParentWithTrait<OpTrait::IsIsolatedFromAbove>();
          DominanceInfo dom(fn);
          tally.add(checkNullGuard(h, dom));
        }
      }
      else if (auto kf = dyn_cast<KfuncCallOp>(op)) {
        CheckVerdict v = checkKfunc(kf);
        tally.add(v);
        if (v != CheckVerdict::Rejected && kf.getRetNullable() && kf.getNumResults() == 1) {
          Operation *fn = kf->getParentWithTrait<OpTrait::IsIsolatedFromAbove>();
          DominanceInfo dom(fn);
          tally.add(checkNullGuard(kf, dom, "kfunc"));
        }
      }
      else if (auto c = dyn_cast<CtxPacketOp>(op))
        tally.add(checkCtxPacket(c));
      else if (auto cm = dyn_cast<CtxMetaOp>(op))
        tally.add(checkCtxMeta(cm));
      else if (auto r = dyn_cast<ReturnOp>(op))
        tally.add(checkReturn(r));
      else if (auto a = dyn_cast<CtxArgOp>(op))
        tally.add(checkCtxArg(a));
      else if (auto f = dyn_cast<CoreFieldLoadOp>(op))
        tally.add(checkCoreFieldLoad(f));
      else if (auto aa = dyn_cast<ArenaAddrOp>(op))
        tally.add(checkArenaAddr(aa));
      else if (isa<CoreFieldAddrOp, CoreExistsOp, CoreFieldOffsetOp>(op)) // core_exists and core_field_offset are Conditional on the loader resolving the relocation.
        tally.add(CheckVerdict::Conditional); // Conditional on target BTF matching the kfield byte-array requirement.
      else if (auto tp = dyn_cast<TpBufferLoadOp>(op))
        tally.add(succeeded(tp.verify()) ? CheckVerdict::Conditional : CheckVerdict::Rejected);
      else if (auto tp = dyn_cast<TpBufferStoreOp>(op))
        tally.add(succeeded(tp.verify()) ? CheckVerdict::Conditional : CheckVerdict::Rejected);
      else if (auto cl = dyn_cast<CtxFieldLoadOp>(op))
        tally.add(checkCtxField(cl, "r", cl.getResult().getType(),
                                cl.getIndex() ? std::optional<int64_t>(static_cast<int64_t>(*cl.getIndex())) : std::nullopt));
      else if (auto cs = dyn_cast<CtxFieldStoreOp>(op))
        tally.add(checkCtxField(cs, "w", cs.getValue().getType()));
      else if (auto k = dyn_cast<KprobeArgOp>(op))
        tally.add(checkKprobeArg(k));
    });
    if (report)
      module.emitRemark() << "bpfabi-verify: " << tally.str();
    if (tally.rejected)
      signalPassFailure();
  }
};

} // namespace
