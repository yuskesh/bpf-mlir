//===- ExpandRegions.cpp - lower checked regions to explicit CFG ------------===//
//
// Source borrowed references/reservations exist only as present-region block
// arguments. Expand checks to is_present, cond_br and assume_present below
// the sole true edge; merge yielded results through continuation arguments.
// map.atomic_add similarly expands hidden lookup/null handling into explicit
// branching and ref.atomic_add.
// Preserve block order: current, present, absent, continuation, with nested
// present blocks immediately afterward. Later lowering retains this order.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h"
#include "bpf-mlir/Dialect/EBPF/Transforms/PacketNeutral.h"
#include "bpf-mlir/Dialect/EBPF/Transforms/WindowPath.h"

#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"

#include "mlir/Dialect/ControlFlow/IR/ControlFlowOps.h"
#include "mlir/Dialect/Arith/IR/Arith.h"
#include "mlir/Dialect/SCF/IR/SCF.h"
#include "mlir/IR/Dominance.h"
#include "mlir/IR/IRMapping.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/StringSet.h"
#include "mlir/IR/Builders.h"

namespace mlir {
namespace ebpf {
#define GEN_PASS_DEF_EBPFEXPANDREGIONS
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h.inc"
} // namespace ebpf
} // namespace mlir

using namespace mlir;
using namespace mlir::ebpf;

namespace {

void eraseUnreachable(Region &body);
void threadI1Joins(Region &body);

bool isStageOneControl(Operation *op) {
  return isa<RefCheckOp, KPtrCheckOp, KRefCheckOp, SockRefCheckOp, RingbufIfReservedOp, MapAtomicAddOp, scf::IfOp, LoopOp, IfOp, RefIndexOp, PacketCheckOp, MetaCheckOp, ArenaCheckOp, ArenaAllocOp, VerdictIfOp, TailCallOp, SpinRegionOp, IterNumOp, IterScxDsqOp, RcuRegionOp, KsymPerCpuLoadOp>(op);
}

class Expander {
public:
  bool sinkLoads = false; // Sink-window-loads tuning.
  bool maskCheckedIndex = true; // Checked-index masking, enabled by default.
  bool maskSkipConstantIndex = true; // Skip masking direct constant indices by default.
  bool backedgeSpill = true;   // Spill bounded-loop IVs at iteration entry through a dedicated volatile slot.
  bool backedgeRotate = false; // Optional rotated bounded loops start at body and compare at latch.
  // Scan current operations; each expansion moves the remainder into cont,
  // where traversal resumes.
  LogicalResult expandFrom(Block *cur) {
    for (auto it = cur->begin(); it != cur->end();) {
      Operation *op = &*it;
      ++it;
      Block *cont = nullptr;
      if (auto rc = dyn_cast<RefCheckOp>(op)) {
        if (failed(expandCheck(op, rc.getRef(), rc.getPresentRegion(),
                               rc.getAbsentRegion(), rc.getResults(), cont)))
          return failure();
      } else if (auto kc = dyn_cast<KPtrCheckOp>(op)) {
        // kptr.check shares ref.check expansion: checked true edge and merged results.
        if (failed(expandCheck(op, kc.getPtr(), kc.getPresentRegion(), kc.getAbsentRegion(), kc.getResults(), cont)))
          return failure();
      } else if (auto s = dyn_cast<SockRefCheckOp>(op)) {
        if (failed(expandCheck(op, s.getPtr(), s.getPresentRegion(), s.getAbsentRegion(), s.getResults(), cont)))
          return failure();
      } else if (auto rc2 = dyn_cast<KRefCheckOp>(op)) {
        // kref.check likewise creates present kref through assume_present.
        if (failed(expandCheck(op, rc2.getPtr(), rc2.getPresentRegion(), rc2.getAbsentRegion(), rc2.getResults(), cont)))
          return failure();
      } else if (auto ir = dyn_cast<RingbufIfReservedOp>(op)) {
        // Results become continuation block arguments, like ref.check.
        if (failed(expandCheck(op, ir.getReservation(), ir.getPresentRegion(),
                               ir.getAbsentRegion(), ir.getResults(), cont)))
          return failure();
      } else if (auto ri = dyn_cast<RefIndexOp>(op)) {
        if (failed(expandIndex(ri, cont)))
          return failure();
      } else if (auto pc = dyn_cast<PacketCheckOp>(op)) {
        if (failed(expandPacketCheck(pc, cont)))
          return failure();
      } else if (auto mc = dyn_cast<MetaCheckOp>(op)) {
        if (failed(expandMetaCheck(mc, cont)))
          return failure();
      } else if (auto allocation = dyn_cast<ArenaAllocOp>(op)) {
        if (failed(expandArenaAlloc(allocation, cont)))
          return failure();
      } else if (auto ac = dyn_cast<ArenaCheckOp>(op)) {
        if (failed(expandArenaCheck(ac, cont)))
          return failure();
      } else if (auto pl = dyn_cast<KsymPerCpuLoadOp>(op)) {
        if (failed(expandPerCpuLoad(pl, cont)))
          return failure();
      } else if (auto vi = dyn_cast<VerdictIfOp>(op)) {
        expandVerdictIf(vi);
        continue;
      } else if (auto rd = dyn_cast<RedirectOp>(op); rd && rd.getCond()) {
        cur = expandRedirectWhen(rd);
        it = cur->begin();
        continue;
      } else if (auto rm = dyn_cast<RedirectMapOp>(op); rm && rm.getCond()) {
        expandRedirectMapWhen(rm);
        continue;
      } else if (auto sr = dyn_cast<SkRedirectOp>(op); sr && sr.getCond()) {
        expandSockRedirectWhen(sr);
        continue;
      } else if (auto mr = dyn_cast<MsgRedirectOp>(op); mr && mr.getCond()) {
        expandSockRedirectWhen(mr);
        continue;
      } else if (auto sr = dyn_cast<SpinRegionOp>(op)) {
        // Emit spin.lock/body/spin.unlock. Body arithmetic/field accesses need no expansion.
        it = std::next(expandSpinRegion(sr)->getIterator());
        continue;
      } else if (auto tc = dyn_cast<TailCallOp>(op)) {
        // Continue expanding fallback operations such as verdict.if, under the
        // true-edge block when conditional.
        Operation *tr = expandTailCall(tc);
        cur = tr->getBlock();
        it = std::next(tr->getIterator());
        continue;
      } else if (auto add = dyn_cast<MapAtomicAddOp>(op)) {
        cont = expandAtomicAdd(add);
      } else if (auto sif = dyn_cast<scf::IfOp>(op)) {
        if (failed(expandIf(sif, cont)))
          return failure();
      } else if (auto eif = dyn_cast<IfOp>(op)) {
        if (failed(expandEbpfIf(eif, cont)))
          return failure();
      } else if (auto loop = dyn_cast<LoopOp>(op)) {
        if (failed(expandLoop(loop, cont)))
          return failure();
      } else if (auto iter = dyn_cast<IterNumOp>(op)) {
        if (failed(expandIterNum(iter, cont)))
          return failure();
      } else if (auto dsq = dyn_cast<IterScxDsqOp>(op)) {
        if (failed(expandIterScxDsq(dsq, cont)))
          return failure();
      } else if (auto rr = dyn_cast<RcuRegionOp>(op)) {
        if (failed(expandRcuRegion(rr, cont)))
          return failure();
      } else if (auto fe = dyn_cast<MapForEachOp>(op)) {
        if (failed(expandForEach(fe, cont)))
          return failure();
      } else if (auto fv = dyn_cast<TaskFindVmaOp>(op)) {
        if (failed(expandFindVma(fv, cont)))
          return failure();
      } else {
        continue;
      }
      cur = cont;
      it = cur->begin();
    }
    return success();
  }

private:
  // Innermost loop targets last. break exits; continue reaches the bounded
  // latch or the current unrolled copy's continuation.
  struct LoopExits {
    Block *brk;
    Block *next;
  };
  SmallVector<LoopExits> loops;

  // Replace an arm's break/continue with a branch to the nearest loop target.
  // Return false for other terminators.
  FailureOr<bool> branchEscape(Operation *owner, Operation *t) {
    Block *dest = nullptr;
    ValueRange vals;
    if (auto br = dyn_cast<BreakOp>(t)) {
      dest = loops.empty() ? nullptr : loops.back().brk;
      vals = br.getValues();
    } else if (auto c = dyn_cast<ContinueOp>(t)) {
      dest = loops.empty() ? nullptr : loops.back().next;
      vals = c.getValues();
    } else {
      return false;
    }
    if (!dest)
      return owner->emitOpError() << "ebpf.break / ebpf.continue outside an ebpf.loop being expanded";
    OpBuilder b(t);
    cf::BranchOp::create(b, t->getLoc(), dest, vals);
    t->erase();
    return true;
  }

  // Move the region's block to dst and replace yield with a branch to cont.
  LogicalResult spliceArm(Operation *owner, Region &region, Block *dst,
                          Block *cont) {
    if (!region.hasOneBlock())
      return owner->emitOpError()
             << "a check region with more than one block is not supported "
                "by ebpf-expand-regions";
    Block &src = region.front();
    dst->getOperations().splice(dst->end(), src.getOperations());
    FailureOr<bool> escaped = branchEscape(owner, dst->getTerminator());
    if (failed(escaped))
      return failure();
    if (*escaped)
      return success();
    auto yield = dyn_cast<YieldOp>(dst->getTerminator());
    if (!yield)
      return owner->emitOpError()
             << "a check region must end with ebpf.yield, ebpf.break or ebpf.continue";
    OpBuilder b(yield);
    cf::BranchOp::create(b, yield.getLoc(), cont, yield.getResults());
    yield.erase();
    return success();
  }

  LogicalResult expandCheck(Operation *op, Value maybe, Region &present,
                            Region &absent, ValueRange results, Block *&cont) {
    Location loc = op->getLoc();
    Block *cur = op->getBlock();
    Region *parent = cur->getParent();

    OpBuilder b(op);
    Value test = IsPresentOp::create(b, loc, b.getI1Type(), maybe);

    cont = cur->splitBlock(op);
    auto *presentBlk = new Block();
    parent->getBlocks().insert(cont->getIterator(), presentBlk);
    auto *absentBlk = new Block();
    parent->getBlocks().insert(cont->getIterator(), absentBlk);
    for (Value r : results)
      r.replaceAllUsesWith(cont->addArgument(r.getType(), loc));

    b.setInsertionPointToEnd(cur);
    cf::CondBranchOp::create(b, loc, test, presentBlk, ValueRange{}, absentBlk,
                             ValueRange{});

    // Replace the checked present-region argument with assume_present.
    if (present.empty() || present.front().getNumArguments() != 1)
      return op->emitOpError() << "the present region must take one argument";
    BlockArgument checked = present.front().getArgument(0);
    b.setInsertionPointToStart(presentBlk);
    Value assumed =
        AssumePresentOp::create(b, loc, checked.getType(), maybe);
    checked.replaceAllUsesWith(assumed);
    if (failed(spliceArm(op, present, presentBlk, cont)) ||
        failed(spliceArm(op, absent, absentBlk, cont)))
      return failure();
    op->erase();

    // Nested present blocks are inserted immediately after present and before absent.
    if (failed(expandFrom(presentBlk)) || failed(expandFrom(absentBlk)))
      return failure();
    return success();
  }

  // Zero-extend each i32 index once to u64 and share that value between the
  // bounds check and true-edge element address. ABI lowering resolves counts/
  // offsets from @records; this stage owns no layout. Order is cur/in/out/cont.
  LogicalResult expandIndex(RefIndexOp ri, Block *&cont) {
    Location loc = ri.getLoc();
    Block *cur = ri->getBlock();
    Region *parent = cur->getParent();
    // Stack per-dimension zero-extensions and conditional checks; any false edge reaches out.
    OpBuilder b(ri);
    SmallVector<Value> izs;
    for (Value i : ri.getIndices())
      izs.push_back(arith::ExtUIOp::create(b, loc, b.getI64Type(), i));
    cont = cur->splitBlock(ri.getOperation());
    SmallVector<Block *> checks{cur};
    for (size_t k = 1; k < izs.size(); ++k) {
      auto *c = new Block();
      parent->getBlocks().insert(cont->getIterator(), c);
      checks.push_back(c);
    }
    auto *inBlk = new Block();
    parent->getBlocks().insert(cont->getIterator(), inBlk);
    auto *outBlk = new Block();
    parent->getBlocks().insert(cont->getIterator(), outBlk);
    for (Value r : ri.getResults())
      r.replaceAllUsesWith(cont->addArgument(r.getType(), loc));
    for (size_t k = 0; k < izs.size(); ++k) {
      b.setInsertionPointToEnd(checks[k]);
      Value test = ElemInRangeOp::create(b, loc, b.getI1Type(), ri.getRef(), ri.getFieldAttr(), izs[k],
                                         k == 0 ? IntegerAttr() : b.getI64IntegerAttr(k));
      Block *next = k + 1 < izs.size() ? checks[k + 1] : inBlk;
      cf::CondBranchOp::create(b, loc, test, next, ValueRange{}, outBlk, ValueRange{});
    }
    // On the checked edge, elem.mask applies a barrier and power-of-two mask,
    // then rechecks elem.in_range before elem.at. Valid indices keep their
    // values. Rechecking the new bounded value leaves a genuine false edge
    // to out, avoiding constant/unknown path merges at pointer addition that
    // speculative non-root verification rejects with REASON_PATHS.
    if (maskCheckedIndex) {
      SmallVector<Value> ms;
      // Direct constants (including unrolled IVs) need no mask: verifier already
      // knows their exact values. Barriers would prevent folding and add five
      // or six instructions per copy. Mixed phi/select origins remain masked.
      SmallVector<bool> masked;
      b.setInsertionPointToEnd(inBlk);
      for (size_t k = 0; k < izs.size(); ++k) {
        bool skip = maskSkipConstantIndex && matchPattern(ri.getIndices()[k], m_Constant());
        masked.push_back(!skip);
        ms.push_back(skip ? izs[k]
                          : ElemMaskOp::create(b, loc, b.getI64Type(), ri.getRef(), ri.getFieldAttr(), izs[k],
                                               k == 0 ? IntegerAttr() : b.getI64IntegerAttr(k))
                                .getResult());
      }
      Block *cur2 = inBlk;
      for (size_t k = 0; k < ms.size(); ++k) {
        if (!masked[k])
          continue;
        auto *next = new Block();
        parent->getBlocks().insert(cont->getIterator(), next);
        b.setInsertionPointToEnd(cur2);
        Value test = ElemInRangeOp::create(b, loc, b.getI1Type(), ri.getRef(), ri.getFieldAttr(), ms[k],
                                           k == 0 ? IntegerAttr() : b.getI64IntegerAttr(k));
        cf::CondBranchOp::create(b, loc, test, next, ValueRange{}, outBlk, ValueRange{});
        cur2 = next;
      }
      izs = ms;
      inBlk = cur2;
    }
    BlockArgument e = ri.getInRange().front().getArgument(0);
    b.setInsertionPointToStart(inBlk);
    Value at = ElemAtOp::create(b, loc, e.getType(), ri.getRef(), ri.getFieldAttr(), izs);
    e.replaceAllUsesWith(at);
    if (failed(spliceArm(ri, ri.getInRange(), inBlk, cont)) ||
        failed(spliceArm(ri, ri.getOutOfRange(), outBlk, cont)))
      return failure();
    ri->erase();
    if (failed(expandFrom(inBlk)) || failed(expandFrom(outBlk)))
      return failure();
    return success();
  }

  // Expand packet.check to pkt.check_br with one zero-extended offset shared
  // by comparison and window address. Convert direct-entry packet.load only
  // when ctx/base/load offsets and length prove the read wholly in range:
  // loadOff>=base and width<=len-(loadOff-base). Do not convert nested,
  // variable-offset, out-of-window or post-nonneutral reads. The original
  // out-of-range zero result cannot occur within the proven range.
  void windowLoads(PacketCheckOp pc) {
    APInt baseC;
    if (!matchPattern(pc.getOffset(), m_ConstantInt(&baseC)) || baseC.getActiveBits() > 63)
      return;
    uint64_t base = baseC.getZExtValue(), len = pc.getLen();
    Block &in = pc.getInRange().front();
    Value w = in.getArgument(0);
    for (Operation &o : llvm::make_early_inc_range(in)) {
      // Stop replacement after any non-neutral operation, including adjust_head
      // or unknown effects; an old checked window cannot justify a later read.
      if (!isa<PacketLoadOp>(&o) && !isPacketNeutral(&o))
        break;
      auto ld = dyn_cast<PacketLoadOp>(&o);
      if (!ld || ld.getCtx() != pc.getCtx())
        continue;
      APInt offC;
      if (!matchPattern(ld.getOffset(), m_ConstantInt(&offC)) || offC.getActiveBits() > 63)
        continue;
      uint64_t off = offC.getZExtValue(), bytes = ld.getResult().getType().getIntOrFloatBitWidth() / 8;
      if (off < base || off - base > len || bytes > len - (off - base))
        continue;
      OpBuilder b(ld);
      auto wl = PacketWindowLoadOp::create(b, ld.getLoc(), ld.getResult().getType(), w, b.getI64IntegerAttr(off - base));
      ld.getResult().replaceAllUsesWith(wl.getResult());
      ld->erase();
    }
  }

  // C1 sinks window_load immediately before its first-use-containing operation.
  // Descend only single-block if/ref.check/if_reserved arms, never loops or
  // callbacks, preserving execution count. Stop when uses split across
  // operations/regions: retain the common dominator without duplication.
  // Every potentially crossed operation, including nested ones, must be
  // PacketNeutral. Never cross writes, pointer invalidators or unknown calls.
  static bool crossable(Operation *op) { return isPacketNeutral(op); }
  void sinkWindowLoads(PacketCheckOp pc) {
    Block &in = pc.getInRange().front();
    SmallVector<PacketWindowLoadOp> loads;
    for (Operation &o : in)
      if (auto wl = dyn_cast<PacketWindowLoadOp>(&o))
        loads.push_back(wl);
    for (PacketWindowLoadOp wl : loads) {
      if (wl->use_empty())
        continue;
      Block *blk = &in;
      Operation *from = wl->getNextNode(); // Cross from here, inclusive, to immediately before the target operation.
      Operation *target = nullptr;         // Insert immediately before this operation.
      while (true) {
        // Direct children of blk containing uses, found through ancestor operations.
        SmallPtrSet<Operation *, 4> anc;
        for (Operation *u : wl->getUsers())
          if (Operation *a = blk->findAncestorOpInBlock(*u))
            anc.insert(a);
        Operation *first = nullptr;
        for (Operation &o : *blk)
          if (anc.contains(&o)) {
            first = &o;
            break;
          }
        if (!first)
          break;
        // Is every crossed operation from from to before first whitelisted?
        bool ok = true;
        for (Operation *o = from; o && o != first; o = o->getNextNode())
          ok &= crossable(o);
        if (!ok)
          break;
        target = first;
        // Descend when all uses belong to one block of one region of one operation.
        if (anc.size() != 1 || !isa<IfOp, RefCheckOp, RingbufIfReservedOp>(first))
          break;
        Region *only = nullptr;
        bool single = true;
        for (Operation *u : wl->getUsers()) {
          Region *r = u->getParentRegion();
          while (r && r->getParentOp() != first)
            r = r->getParentOp()->getParentRegion();
          if (!r || (only && only != r)) {
            single = false;
            break;
          }
          only = r;
        }
        if (!single || !only || !only->hasOneBlock())
          break;
        // On descent, start crossing at the selected block entry. Other regions
      // of first are alternative arms, not executed along this path.
        blk = &only->front();
        from = blk->empty() ? nullptr : &blk->front();
      }
      if (target && target != wl->getNextNode())
        wl->moveBefore(target);
    }
  }

  LogicalResult expandPacketCheck(PacketCheckOp pc, Block *&cont) {
    windowLoads(pc);
    if (sinkLoads)
      sinkWindowLoads(pc);
    Location loc = pc.getLoc();
    Block *cur = pc->getBlock();
    Region *parent = cur->getParent();
    OpBuilder b(pc);
    Value off = pc.getOffset();
    Value off64 = off.getType() == b.getI64Type() ? off : arith::ExtUIOp::create(b, loc, b.getI64Type(), off).getResult();
    cont = cur->splitBlock(pc.getOperation());
    auto *inBlk = new Block();
    parent->getBlocks().insert(cont->getIterator(), inBlk);
    auto *outBlk = new Block();
    parent->getBlocks().insert(cont->getIterator(), outBlk);
    for (Value r : pc.getResults())
      r.replaceAllUsesWith(cont->addArgument(r.getType(), loc));
    BlockArgument w = pc.getInRange().front().getArgument(0);
    w.replaceAllUsesWith(inBlk->addArgument(w.getType(), loc));
    b.setInsertionPointToEnd(cur);
    PktCheckBrOp::create(b, loc, pc.getCtx(), off64, pc.getLenAttr(), inBlk, outBlk);
    if (failed(spliceArm(pc, pc.getInRange(), inBlk, cont)) || failed(spliceArm(pc, pc.getOutOfRange(), outBlk, cont)))
      return failure();
    pc->erase();
    if (failed(expandFrom(inBlk)) || failed(expandFrom(outBlk)))
      return failure();
    return success();
  }

  // arena.check becomes arena.check_br like packet.check (zero-extended
  // offset, ^in(%w) / ^out, results on the continuation). No window-load
  // rewrites — W0 / C1 / W1 are packet optimizations.
  LogicalResult expandArenaAlloc(ArenaAllocOp allocation, Block *&cont) {
    Location loc = allocation.getLoc();
    Block *cur = allocation->getBlock();
    Region *parent = cur->getParent();
    OpBuilder b(allocation);
    // Resolve each checked free while the lexical proof still has its owner.
    SmallVector<ArenaFreeOp> frees;
    allocation.walk([&](ArenaFreeOp op) { frees.push_back(op); });
    for (ArenaFreeOp op : frees) {
      b.setInsertionPoint(op);
      ArenaFreePagesOp::create(b, op.getLoc(), allocation.getMap(), allocation.getPageOffsetAttr(), allocation.getPageCountAttr());
      op.erase();
    }
    allocation.getAllocated().front().eraseArgument(0);
    cont = cur->splitBlock(allocation.getOperation());
    auto *in = new Block();
    parent->getBlocks().insert(cont->getIterator(), in);
    auto *out = new Block();
    parent->getBlocks().insert(cont->getIterator(), out);
    for (Value r : allocation.getResults())
      r.replaceAllUsesWith(cont->addArgument(r.getType(), loc));
    b.setInsertionPointToEnd(cur);
    ArenaAllocBrOp::create(b, loc, allocation.getMap(), allocation.getPageOffsetAttr(), allocation.getPageCountAttr(), in, out);
    if (failed(spliceArm(allocation, allocation.getAllocated(), in, cont)) ||
        failed(spliceArm(allocation, allocation.getFailed(), out, cont)))
      return failure();
    allocation.erase();
    if (failed(expandFrom(in)) || failed(expandFrom(out)))
      return failure();
    return success();
  }

  // xdp.meta_check becomes meta.check_br (no window-load rewrites — the
  // packet optimizations do not apply to the metadata window; no results).
  LogicalResult expandMetaCheck(MetaCheckOp mc, Block *&cont) {
    Location loc = mc.getLoc();
    Block *cur = mc->getBlock();
    Region *parent = cur->getParent();
    OpBuilder b(mc);
    cont = cur->splitBlock(mc.getOperation());
    auto *inBlk = new Block();
    parent->getBlocks().insert(cont->getIterator(), inBlk);
    auto *outBlk = new Block();
    parent->getBlocks().insert(cont->getIterator(), outBlk);
    BlockArgument w = mc.getInRange().front().getArgument(0);
    w.replaceAllUsesWith(inBlk->addArgument(w.getType(), loc));
    b.setInsertionPointToEnd(cur);
    MetaCheckBrOp::create(b, loc, mc.getCtx(), mc.getLenAttr(), inBlk, outBlk);
    if (failed(spliceArm(mc, mc.getInRange(), inBlk, cont)) || failed(spliceArm(mc, mc.getOutOfRange(), outBlk, cont)))
      return failure();
    mc->erase();
    if (failed(expandFrom(inBlk)) || failed(expandFrom(outBlk)))
      return failure();
    return success();
  }

  LogicalResult expandArenaCheck(ArenaCheckOp ac, Block *&cont) {
    Location loc = ac.getLoc();
    Block *cur = ac->getBlock();
    Region *parent = cur->getParent();
    OpBuilder b(ac);
    Value off = ac.getOffset();
    Value off64 = off.getType() == b.getI64Type() ? off : arith::ExtUIOp::create(b, loc, b.getI64Type(), off).getResult();
    cont = cur->splitBlock(ac.getOperation());
    auto *inBlk = new Block();
    parent->getBlocks().insert(cont->getIterator(), inBlk);
    auto *outBlk = new Block();
    parent->getBlocks().insert(cont->getIterator(), outBlk);
    for (Value r : ac.getResults())
      r.replaceAllUsesWith(cont->addArgument(r.getType(), loc));
    BlockArgument w = ac.getInRange().front().getArgument(0);
    w.replaceAllUsesWith(inBlk->addArgument(w.getType(), loc));
    b.setInsertionPointToEnd(cur);
    ArenaCheckBrOp::create(b, loc, ac.getBase(), off64, ac.getLenAttr(), inBlk, outBlk);
    if (failed(spliceArm(ac, ac.getInRange(), inBlk, cont)) || failed(spliceArm(ac, ac.getOutOfRange(), outBlk, cont)))
      return failure();
    ac->erase();
    if (failed(expandFrom(inBlk)) || failed(expandFrom(outBlk)))
      return failure();
    return success();
  }

  // per_cpu_load becomes the per_cpu_br terminator (helper, NULL test and
  // slot load at ③) with the present arm receiving the slot value.
  LogicalResult expandPerCpuLoad(KsymPerCpuLoadOp pl, Block *&cont) {
    Location loc = pl.getLoc();
    Block *cur = pl->getBlock();
    Region *parent = cur->getParent();
    OpBuilder b(pl);
    cont = cur->splitBlock(pl.getOperation());
    auto *inBlk = new Block();
    parent->getBlocks().insert(cont->getIterator(), inBlk);
    auto *outBlk = new Block();
    parent->getBlocks().insert(cont->getIterator(), outBlk);
    for (Value r : pl.getResults())
      r.replaceAllUsesWith(cont->addArgument(r.getType(), loc));
    BlockArgument s = pl.getPresentRegion().front().getArgument(0);
    s.replaceAllUsesWith(inBlk->addArgument(s.getType(), loc));
    b.setInsertionPointToEnd(cur);
    auto br = KsymPerCpuBrOp::create(b, loc, pl.getNameAttr(), pl.getCpu(), inBlk, outBlk);
    br->setDiscardableAttrs(pl->getDiscardableAttrDictionary()); // ebpf.weak / ebpf.extern_type for ③.
    if (failed(spliceArm(pl, pl.getPresentRegion(), inBlk, cont)) || failed(spliceArm(pl, pl.getAbsentRegion(), outBlk, cont)))
      return failure();
    pl->erase();
    if (failed(expandFrom(inBlk)) || failed(expandFrom(outBlk)))
      return failure();
    return success();
  }

  // verdict.if becomes cond_br and two verdict terminators; nothing follows it.
  void expandVerdictIf(VerdictIfOp vi) {
    Location loc = vi.getLoc();
    Block *cur = vi->getBlock();
    Region *parent = cur->getParent();
    auto *thenBlk = new Block();
    parent->getBlocks().insert(std::next(cur->getIterator()), thenBlk);
    auto *elseBlk = new Block();
    parent->getBlocks().insert(std::next(thenBlk->getIterator()), elseBlk);
    OpBuilder b(vi);
    cf::CondBranchOp::create(b, loc, vi.getCond(), thenBlk, ValueRange{}, elseBlk, ValueRange{});
    b.setInsertionPointToEnd(thenBlk);
    VerdictOp::create(b, loc, vi.getThenActionAttr());
    b.setInsertionPointToEnd(elseBlk);
    VerdictOp::create(b, loc, vi.getElseActionAttr());
    vi->erase();
  }

  // Split conditional redirect into cond_br and unconditional redirect/verdict.
  Block *expandRedirectWhen(RedirectOp rd) {
    Location loc = rd.getLoc();
    Block *cur = rd->getBlock();
    Region *parent = cur->getParent();
    auto *thenBlk = new Block();
    parent->getBlocks().insert(std::next(cur->getIterator()), thenBlk);
    auto *elseBlk = new Block();
    parent->getBlocks().insert(std::next(thenBlk->getIterator()), elseBlk);
    OpBuilder b(rd);
    cf::CondBranchOp::create(b, loc, rd.getCond(), thenBlk, ValueRange{}, elseBlk, ValueRange{});
    b.setInsertionPointToEnd(thenBlk);
    RedirectOp::create(b, loc, rd.getIfindex(), Value(), StringAttr(), rd.getFlagsAttr(), rd.getViaAttr());
    b.setInsertionPointToEnd(elseBlk);
    if (rd.getFallback().empty())
      VerdictOp::create(b, loc, rd.getElseActionAttr());
    else
      elseBlk->getOperations().splice(elseBlk->end(), rd.getFallback().front().getOperations());
    rd->erase();
    return elseBlk;
  }

  // tail_call becomes nonterminating tail_call.try followed by fallback:
  // only failure returns to subsequent operations.
  // Closed critical regions become lock/body/unlock. Verification guarantees
  // one block ending in yield, hence exactly one exit path.
  Operation *expandSpinRegion(SpinRegionOp sr) {
    OpBuilder b(sr);
    SpinLockOp::create(b, sr.getLoc(), sr.getRef(), sr.getLockAttr());
    Block &body = sr.getBody().front();
    body.back().erase(); // yield
    Block *cur = sr->getBlock();
    cur->getOperations().splice(Block::iterator(sr), body.getOperations());
    b.setInsertionPoint(sr);
    auto un = SpinUnlockOp::create(b, sr.getLoc(), sr.getRef(), sr.getLockAttr());
    sr->erase();
    return un;
  }

  // when c else verdict becomes a branch to true-side tail_call.try/fallback
    // or a false-side verdict block.
  Operation *expandTailCall(TailCallOp tc) {
    Location loc = tc.getLoc();
    Block *cur = tc->getBlock();
    OpBuilder b(tc);
    if (tc.getCond()) {
      Region *parent = cur->getParent();
      auto *thenBlk = new Block();
      parent->getBlocks().insert(std::next(cur->getIterator()), thenBlk);
      auto *elseBlk = new Block();
      parent->getBlocks().insert(std::next(thenBlk->getIterator()), elseBlk);
      cf::CondBranchOp::create(b, loc, tc.getCond(), thenBlk, ValueRange{}, elseBlk, ValueRange{});
      b.setInsertionPointToEnd(elseBlk);
      VerdictOp::create(b, loc, tc.getElseActionAttr());
      b.setInsertionPointToEnd(thenBlk);
      cur = thenBlk;
    }
    auto tr = TailCallTryOp::create(b, loc, tc.getCtx(), tc.getMap(), tc.getIndex());
    cur->getOperations().splice(cur->end(), tc.getFallback().front().getOperations());
    tc->erase();
    return tr;
  }

  // Split conditional socket/message redirects into cond_br and
  // unconditional redirect/verdict, like ordinary redirect.
  template <typename OpT> void expandSockRedirectWhen(OpT rd) {
    Location loc = rd.getLoc();
    Block *cur = rd->getBlock();
    Region *parent = cur->getParent();
    auto *thenBlk = new Block();
    parent->getBlocks().insert(std::next(cur->getIterator()), thenBlk);
    auto *elseBlk = new Block();
    parent->getBlocks().insert(std::next(thenBlk->getIterator()), elseBlk);
    OpBuilder b(rd);
    cf::CondBranchOp::create(b, loc, rd.getCond(), thenBlk, ValueRange{}, elseBlk, ValueRange{});
    b.setInsertionPointToEnd(thenBlk);
    // Use named Op::create calls: reference generation counts stage-two creations
      // against Stage1OpsCreatedByPasses.tsv.
    if constexpr (std::is_same_v<OpT, SkRedirectOp>)
      SkRedirectOp::create(b, loc, rd.getCtx(), rd.getMap(), rd.getKey(), rd.getIngressAttr(), Value(), StringAttr());
    else
      MsgRedirectOp::create(b, loc, rd.getCtx(), rd.getMap(), rd.getKey(), rd.getIngressAttr(), Value(), StringAttr());
    b.setInsertionPointToEnd(elseBlk);
    VerdictOp::create(b, loc, rd.getElseActionAttr());
    rd->erase();
  }

  // Split conditional redirect_map into cond_br and unconditional redirect/verdict.
  void expandRedirectMapWhen(RedirectMapOp rm) {
    Location loc = rm.getLoc();
    Block *cur = rm->getBlock();
    Region *parent = cur->getParent();
    auto *thenBlk = new Block();
    parent->getBlocks().insert(std::next(cur->getIterator()), thenBlk);
    auto *elseBlk = new Block();
    parent->getBlocks().insert(std::next(thenBlk->getIterator()), elseBlk);
    OpBuilder b(rm);
    cf::CondBranchOp::create(b, loc, rm.getCond(), thenBlk, ValueRange{}, elseBlk, ValueRange{});
    b.setInsertionPointToEnd(thenBlk);
    RedirectMapOp::create(b, loc, rm.getMap(), rm.getKey(), rm.getFallbackAttr(), Value(), StringAttr(), rm.getRedirectFlagsAttr());
    b.setInsertionPointToEnd(elseBlk);
    VerdictOp::create(b, loc, rm.getElseActionAttr());
    rm->erase();
  }

  // Expand scalar scf.if in cur/then/else/cont order. Without else, branch
  // directly to continuation.
  LogicalResult expandIf(scf::IfOp sif, Block *&cont) {
    Location loc = sif.getLoc();
    Block *cur = sif->getBlock();
    Region *parent = cur->getParent();
    cont = cur->splitBlock(sif.getOperation());
    auto *thenBlk = new Block();
    parent->getBlocks().insert(cont->getIterator(), thenBlk);
    Block *elseBlk = nullptr;
    if (!sif.getElseRegion().empty()) {
      elseBlk = new Block();
      parent->getBlocks().insert(cont->getIterator(), elseBlk);
    }
    for (Value r : sif.getResults())
      r.replaceAllUsesWith(cont->addArgument(r.getType(), loc));
    OpBuilder b(sif.getContext());
    b.setInsertionPointToEnd(cur);
    cf::CondBranchOp::create(b, loc, sif.getCondition(), thenBlk, ValueRange{},
                             elseBlk ? elseBlk : cont, ValueRange{});
    auto splice = [&](Region &region, Block *dst) -> LogicalResult {
      Block &src = region.front();
      dst->getOperations().splice(dst->end(), src.getOperations());
      auto y = dyn_cast<scf::YieldOp>(dst->getTerminator());
      if (!y)
        return sif.emitOpError() << "an scf.if arm must end with scf.yield";
      OpBuilder yb(y);
      cf::BranchOp::create(yb, y.getLoc(), cont, y.getResults());
      y.erase();
      return success();
    };
    if (failed(splice(sif.getThenRegion(), thenBlk)) ||
        (elseBlk && failed(splice(sif.getElseRegion(), elseBlk))))
      return failure();
    sif.erase();
    if (failed(expandFrom(thenBlk)) || (elseBlk && failed(expandFrom(elseBlk))))
      return failure();
    return success();
  }

  // Expand ebpf.if in cur/then/else/cont order. if.yield branches to cont;
  // break/continue target the nearest loop without contributing cont values.
  LogicalResult expandEbpfIf(IfOp eif, Block *&cont) {
    Location loc = eif.getLoc();
    Block *cur = eif->getBlock();
    Region *parent = cur->getParent();
    cont = cur->splitBlock(eif.getOperation());
    auto *thenBlk = new Block();
    parent->getBlocks().insert(cont->getIterator(), thenBlk);
    auto *elseBlk = new Block();
    parent->getBlocks().insert(cont->getIterator(), elseBlk);
    for (Value r : eif.getResults())
      r.replaceAllUsesWith(cont->addArgument(r.getType(), loc));
    OpBuilder b(eif.getContext());
    b.setInsertionPointToEnd(cur);
    cf::CondBranchOp::create(b, loc, eif.getCond(), thenBlk, ValueRange{}, elseBlk, ValueRange{});
    auto splice = [&](Region &region, Block *dst) -> LogicalResult {
      Block &src = region.front();
      dst->getOperations().splice(dst->end(), src.getOperations());
      FailureOr<bool> escaped = branchEscape(eif, dst->getTerminator());
      if (failed(escaped))
        return failure();
      if (*escaped)
        return success();
      auto y = dyn_cast<IfYieldOp>(dst->getTerminator());
      if (!y)
        return eif.emitOpError() << "an ebpf.if arm must end with ebpf.if.yield, ebpf.break or ebpf.continue";
      OpBuilder yb(y);
      cf::BranchOp::create(yb, y.getLoc(), cont, y.getValues());
      y.erase();
      return success();
    };
    if (failed(splice(eif.getThenRegion(), thenBlk)) || failed(splice(eif.getElseRegion(), elseBlk)))
      return failure();
    eif.erase();
    if (failed(expandFrom(thenBlk)) || failed(expandFrom(elseBlk)))
      return failure();
    return success();
  }

  // Expand loop bodies recursively after placing them in CFG blocks.
  // N=0 retains initial values without body; N=1 runs once at IV zero without
  // back-edge. Unrolled loops clone N copies with constant IVs. Bounded N>=2
  // loops use unsigned i<N at header, body, and a back-edge carrying i+1/yields.
  LogicalResult expandLoop(LoopOp loop, Block *&cont) {
    if (loop.getCallback())
      return expandCallbackLoop(loop, cont);
    Location loc = loop.getLoc();
    Block *cur = loop->getBlock();
    Region *parent = cur->getParent();
    int64_t n = loop.getCount();
    cont = cur->splitBlock(loop.getOperation());
    SmallVector<Value> finals;
    for (Value r : loop.getResults())
      finals.push_back(cont->addArgument(r.getType(), loc));
    for (auto [r, f] : llvm::zip(loop.getResults(), finals))
      r.replaceAllUsesWith(f);
    Block &src = loop.getBody().front();
    OpBuilder b(loop.getContext());
    Type i32 = b.getI32Type();

    // Clone one body into dst with IV/iter_args replacements and return yield
    // values. Leave dst at the removed yield; stopOut is optional stop condition.
    Value stopOut;
    auto cloneBody = [&](Block *dst, Value iv, ValueRange args, SmallVector<Value> &out) {
      IRMapping m;
      m.map(src.getArgument(0), iv);
      for (auto [a, v] : llvm::zip(src.getArguments().drop_front(), args))
        m.map(a, v);
      b.setInsertionPointToEnd(dst);
      for (Operation &op : src.without_terminator())
        b.clone(op, m);
      auto y = cast<LoopYieldOp>(src.getTerminator());
      out.clear();
      for (Value v : y.getValues())
        out.push_back(m.lookupOrDefault(v));
      stopOut = y.getStop() ? m.lookupOrDefault(y.getStop()) : Value();
    };

    // Preserve yield values as branch operands before expansion replaces them
    // with join arguments. C++ Value variables could retain erased definitions.
    auto blockWithArgs = [&](ValueRange like) {
      auto *blk = new Block();
      parent->getBlocks().insert(cont->getIterator(), blk);
      for (Value v : like)
        blk->addArgument(v.getType(), loc);
      return blk;
    };
    // Evaluate the i32 runtime bound once as unsigned. Check i<bound before
    // every iteration, not a mask. Retain even for N=1 so bound zero skips body.
    Value bound = loop.getBound();
    SmallVector<Value> vals(loop.getInits().begin(), loop.getInits().end());
    if (loop.getUnroll() || n <= 1) {
      // Linear copies: cur -> c0 -> j0(values) -> c1 -> j1(values) -> cont.
      Block *prev = cur;
      for (int64_t k = 0; k < n; ++k) {
        auto *copy = new Block();
        parent->getBlocks().insert(cont->getIterator(), copy);
        b.setInsertionPointToEnd(prev);
        if (bound) {
          // Before copy k, test k<n; false skips remaining copies with current values.
          Value kc = arith::ConstantOp::create(b, loc, i32, b.getI32IntegerAttr(k));
          Value go = arith::CmpIOp::create(b, loc, arith::CmpIPredicate::ult, kc, bound);
          cf::CondBranchOp::create(b, loc, go, copy, ValueRange{}, cont, vals);
        } else {
          cf::BranchOp::create(b, loc, copy);
        }
        b.setInsertionPointToEnd(copy);
        Value iv = arith::ConstantOp::create(b, loc, i32, b.getI32IntegerAttr(k));
        SmallVector<Value> next;
        cloneBody(copy, iv, vals, next);
        Block *join = blockWithArgs(vals);
        b.setInsertionPointToEnd(copy);
        if (stopOut)
          // Stop exits all copies with this iteration's values; otherwise continue.
          cf::CondBranchOp::create(b, loc, stopOut, cont, next, join, next);
        else
          cf::BranchOp::create(b, loc, join, next);
        // break exits all copies; continue reaches this copy's join and next guard.
        loops.push_back({cont, join});
        LogicalResult r = expandFrom(copy);
        loops.pop_back();
        if (failed(r))
          return failure();
        vals.assign(join->getArguments().begin(), join->getArguments().end());
        prev = join;
      }
      b.setInsertionPointToEnd(prev);
      cf::BranchOp::create(b, loc, cont, vals);
      loop.erase();
      return success();
    }

    // Bounded loops use header/body/latch. Rotation starts at body, with only
    // a 0<n entry guard for runtime bounds (N>=2 already holds). Latch checks
    // i+1<n then i+1<N before returning to body, reducing speculative pushes
    // on the constant-bound path. break still exits; continue still reaches latch.
    // Optional backedgeSpill stores IV at iteration entry in a dedicated volatile
    // stack slot, forming a nospec_result barrier without changing values.
    auto *body = new Block();
    parent->getBlocks().insert(cont->getIterator(), body);
    Block *header = nullptr;
    Value iv;
    SmallVector<Value> hargs; // Iteration values are header arguments, or body arguments when rotated.
    if (!backedgeRotate) {
      header = new Block();
      parent->getBlocks().insert(body->getIterator(), header);
      iv = header->addArgument(i32, loc);
      for (Value v : vals)
        hargs.push_back(header->addArgument(v.getType(), loc));
    } else {
      iv = body->addArgument(i32, loc);
      for (Value v : vals)
        hargs.push_back(body->addArgument(v.getType(), loc));
    }
    b.setInsertionPointToEnd(cur);
    Value zero = arith::ConstantOp::create(b, loc, i32, b.getI32IntegerAttr(0));
    SmallVector<Value> entryArgs{zero};
    entryArgs.append(vals.begin(), vals.end());
    if (!backedgeRotate) {
      cf::BranchOp::create(b, loc, header, entryArgs);
      b.setInsertionPointToEnd(header);
      if (backedgeSpill)
        LoopSpillOp::create(b, loc, iv); // Spill at header entry, before comparison.
      Value lim = arith::ConstantOp::create(b, loc, i32, b.getI32IntegerAttr(n)); // Keep constants inside header to preserve output when tuning is disabled.
      Value c = arith::CmpIOp::create(b, loc, arith::CmpIPredicate::ult, iv, lim);
      if (bound) {
        // Header checks both constant i<N for verifier bounds and runtime i<n.
        auto *check = new Block();
        parent->getBlocks().insert(cont->getIterator(), check);
        cf::CondBranchOp::create(b, loc, c, check, ValueRange{}, cont, hargs);
        b.setInsertionPointToEnd(check);
        Value c2 = arith::CmpIOp::create(b, loc, arith::CmpIPredicate::ult, iv, bound);
        cf::CondBranchOp::create(b, loc, c2, body, ValueRange{}, cont, hargs);
      } else {
        cf::CondBranchOp::create(b, loc, c, body, ValueRange{}, cont, hargs);
      }
    } else if (bound) {
      // Rotated entry needs only 0<n; false returns initial values (i=0 already satisfies N>=2).
      Value g = arith::CmpIOp::create(b, loc, arith::CmpIPredicate::ult, zero, bound);
      cf::CondBranchOp::create(b, loc, g, body, entryArgs, cont, vals);
    } else {
      cf::BranchOp::create(b, loc, body, entryArgs);
    }
    SmallVector<Value> next;
    cloneBody(body, iv, hargs, next);
    if (backedgeRotate && backedgeSpill) {
      b.setInsertionPointToStart(body);
      LoopSpillOp::create(b, loc, iv); // Rotated iteration starts at body entry.
    }
    Block *latch = blockWithArgs(hargs);
    b.setInsertionPointToEnd(body);
    if (stopOut)
      // Stop exits with current values; otherwise latch advances IV toward header.
      cf::CondBranchOp::create(b, loc, stopOut, cont, next, latch, next);
    else
      cf::BranchOp::create(b, loc, latch, next);
    // break exits; continue reaches latch, advances once and rechecks at
    // header, or at the rotated latch.
    loops.push_back({cont, latch});
    LogicalResult r = expandFrom(body);
    loops.pop_back();
    if (failed(r))
      return failure();
    b.setInsertionPointToEnd(latch);
    Value one = arith::ConstantOp::create(b, loc, i32, b.getI32IntegerAttr(1));
    Value inc = arith::AddIOp::create(b, loc, iv, one);
    SmallVector<Value> back{inc};
    back.append(latch->getArguments().begin(), latch->getArguments().end());
    if (!backedgeRotate) {
      cf::BranchOp::create(b, loc, header, back);
    } else {
      // Rotated latch checks i+1<n then i+1<N; either false exits with latch values.
      SmallVector<Value> largs(latch->getArguments().begin(), latch->getArguments().end());
      if (bound) {
        auto *check = new Block();
        parent->getBlocks().insert(cont->getIterator(), check);
        Value c2 = arith::CmpIOp::create(b, loc, arith::CmpIPredicate::ult, inc, bound);
        cf::CondBranchOp::create(b, loc, c2, check, ValueRange{}, cont, largs);
        b.setInsertionPointToEnd(check);
      }
      Value lim = arith::ConstantOp::create(b, loc, i32, b.getI32IntegerAttr(n));
      Value c = arith::CmpIOp::create(b, loc, arith::CmpIPredicate::ult, inc, lim);
      cf::CondBranchOp::create(b, loc, c, body, back, cont, largs);
    }
    loop.erase();
    return success();
  }

  // order. begin (slot + new) ends cur; the header's next_br enters the body
  // with the index or goes to nul on NULL; the body's iter.yield reaches the
  // latch, which returns to the header; break reaches done and continue the
  // latch. done is the one block with end (destroy), reached by nul and break,
  // so destroy runs once on every exit — including after a failed new.
  LogicalResult expandIterNum(IterNumOp it, Block *&cont) {
    return expandIterator(
        it, it.getInits(), it.getBody(), cont, IntegerType::get(it.getContext(), 32),
        [&](OpBuilder &b) { return IterNumBeginOp::create(b, it.getLoc(), IterNumSlotType::get(it.getContext()), it.getLo(), it.getHi()); },
        [&](OpBuilder &b, Value slot, Block *body, Block *nul) { IterNumNextBrOp::create(b, it.getLoc(), slot, body, nul); },
        [&](OpBuilder &b, Value slot) { IterNumEndOp::create(b, it.getLoc(), slot); });
  }

  // ebpf.iter.scx_dsq shares the iterator expansion; the body takes
  // the task (!ebpf.rcu_ptr<"task_struct">) where iter.num takes the index.
  LogicalResult expandIterScxDsq(IterScxDsqOp it, Block *&cont) {
    return expandIterator(
        it, it.getInits(), it.getBody(), cont, RcuPtrType::get(it.getContext(), "task_struct"),
        [&](OpBuilder &b) { return IterScxDsqBeginOp::create(b, it.getLoc(), IterScxDsqSlotType::get(it.getContext()), it.getDsqId()); },
        [&](OpBuilder &b, Value slot, Block *body, Block *nul) { IterScxDsqNextBrOp::create(b, it.getLoc(), slot, body, nul); },
        [&](OpBuilder &b, Value slot) { IterScxDsqEndOp::create(b, it.getLoc(), slot); });
  }

  LogicalResult expandIterator(Operation *it, ValueRange inits, Region &bodyRegion, Block *&cont, Type elemTy,
                               llvm::function_ref<Value(OpBuilder &)> begin,
                               llvm::function_ref<void(OpBuilder &, Value, Block *, Block *)> nextBr,
                               llvm::function_ref<void(OpBuilder &, Value)> end) {
    Location loc = it->getLoc();
    Block *cur = it->getBlock();
    Region *parent = cur->getParent();
    cont = cur->splitBlock(it);
    for (Value r : it->getResults())
      r.replaceAllUsesWith(cont->addArgument(r.getType(), loc));
    auto blockWithTypes = [&](TypeRange types) {
      auto *blk = new Block();
      parent->getBlocks().insert(cont->getIterator(), blk);
      for (Type t : types)
        blk->addArgument(t, loc);
      return blk;
    };
    TypeRange carried = inits.getTypes();
    Block *header = blockWithTypes(carried);
    Block *body = blockWithTypes({});
    Block *latch = blockWithTypes(carried);
    Block *nul = blockWithTypes({});
    Block *done = blockWithTypes(carried);
    OpBuilder b(it->getContext());
    b.setInsertionPointToEnd(cur);
    Value slot = begin(b);
    cf::BranchOp::create(b, loc, header, inits);
    b.setInsertionPointToEnd(header);
    nextBr(b, slot, body, nul);
    Value idx = body->addArgument(elemTy, loc);
    // Move the body: the element and carried arguments become idx and the header's.
    Block &src = bodyRegion.front();
    src.getArgument(0).replaceAllUsesWith(idx);
    for (auto [a, h] : llvm::zip(src.getArguments().drop_front(), header->getArguments()))
      a.replaceAllUsesWith(h);
    body->getOperations().splice(body->end(), src.getOperations());
    auto y = cast<IterYieldOp>(body->getTerminator());
    b.setInsertionPoint(y);
    cf::BranchOp::create(b, loc, latch, y.getValues());
    y.erase();
    b.setInsertionPointToEnd(latch);
    cf::BranchOp::create(b, loc, header, latch->getArguments());
    b.setInsertionPointToEnd(nul);
    cf::BranchOp::create(b, loc, done, header->getArguments());
    b.setInsertionPointToEnd(done);
    end(b, slot);
    cf::BranchOp::create(b, loc, cont, done->getArguments());
    it->erase();
    loops.push_back({done, latch});
    LogicalResult r = expandFrom(body);
    loops.pop_back();
    return r;
  }

  // ebpf.rcu.region becomes rcu.lock at the end of cur, the body, and
  // rcu.unlock just before the branch to cont that replaces the one yield (the
  // op verifier rejects every other exit, so this is the only unlock).
  LogicalResult expandRcuRegion(RcuRegionOp rr, Block *&cont) {
    Location loc = rr.getLoc();
    Block *cur = rr->getBlock();
    Region *parent = cur->getParent();
    cont = cur->splitBlock(rr.getOperation());
    for (Value r : rr.getResults())
      r.replaceAllUsesWith(cont->addArgument(r.getType(), loc));
    auto *inner = new Block();
    parent->getBlocks().insert(cont->getIterator(), inner);
    OpBuilder b(rr.getContext());
    b.setInsertionPointToEnd(cur);
    RcuLockOp::create(b, loc);
    cf::BranchOp::create(b, loc, inner);
    inner->getOperations().splice(inner->end(), rr.getBody().front().getOperations());
    auto y = cast<YieldOp>(inner->getTerminator());
    b.setInsertionPoint(y);
    RcuUnlockOp::create(b, loc);
    cf::BranchOp::create(b, loc, cont, y.getResults());
    y.erase();
    rr.erase();
    return expandFrom(inner);
  }

  // Helper loops move bodies into module-level loop_callback and emit bpf_loop.
  // Callback args are i32 IV, carried values, first-use-ordered captured
  // integers and maps rebound by owner symbols. End/continue returns zero;
  // break/true stop writes values back and returns one. Runtime count is
  // unsigned min(n,N) through compare/select, not masking.
  LogicalResult expandCallbackLoop(LoopOp loop, Block *&cont) {
    Location loc = loop.getLoc();
    // Owner may be program, func or an outer helper-loop callback.
    Operation *owner = loop->getParentOp();
    while (owner && !isa<ProgramOp, LoopCallbackOp, SubprogramOp>(owner))
      owner = owner->getParentOp();
    if (!owner || !root)
      return loop.emitOpError() << "a callback loop has no owning program, callback or func";
    Block &ownerEntry = owner->getRegion(0).front();
    // Rebind captured map arguments to symbols in owner map order.
    auto mapSymbolOf = [&](BlockArgument arg) -> Attribute {
      if (arg.getOwner() != &ownerEntry)
        return {};
      int64_t base;
      ArrayAttr syms;
      if (auto p = dyn_cast<ProgramOp>(owner)) {
        base = 1;
        syms = p.getMapSymbolsAttr();
      } else if (auto c = dyn_cast<LoopCallbackOp>(owner)) {
        base = ((c.getForEach() || c.getFindVma()) ? 2 : 1) + c.getNumCarried() + c.getNumCaptured(); // for_each callback arguments begin with key and value.
        syms = c.getMapSymbols();
      } else {
        auto f = cast<SubprogramOp>(owner);
        base = f.getFunctionType().getNumInputs();
        syms = f.getMapSymbolsAttr();
      }
      int64_t idx = static_cast<int64_t>(arg.getArgNumber()) - base;
      if (!syms || idx < 0 || idx >= static_cast<int64_t>(syms.size()))
        return {};
      return syms[idx];
    };
    Block &src = loop.getBody().front();
    llvm::SetVector<Value> captured;
    loop.getBody().walk([&](Operation *op) {
      for (Value v : op->getOperands())
        if (!loop.getBody().isAncestor(v.getParentRegion()))
          captured.insert(v);
    });
    SmallVector<Value> ints, maps;
    SmallVector<Attribute> mapSyms;
    for (Value v : captured) {
      if (isa<IntegerType>(v.getType())) {
        ints.push_back(v);
        continue;
      }
      auto arg = dyn_cast<BlockArgument>(v);
      Attribute sym = (arg && isa<MapType>(v.getType())) ? mapSymbolOf(arg) : Attribute();
      if (!sym)
        return loop.emitOpError() << "captures " << v.getType()
                                  << ", which cannot be passed to a bpf_loop callback";
      maps.push_back(v);
      mapSyms.push_back(sym);
    }
    OpBuilder b(loop.getContext());
    Type i32 = b.getI32Type();
    SmallVector<Type> carried(loop.getInits().getTypes());

    // Name callbacks by expansion-root program/func and per-root sequence,
    // shared by nested helper loops. Insert before the root operation.
    b.setInsertionPoint(root);
    std::string name = ("__ebpf_loop_cb_" + rootName + "_" + Twine(callbackCount++)).str();
    auto cb = LoopCallbackOp::create(b, loc, b.getStringAttr(name),
                                     b.getI64IntegerAttr(carried.size()), b.getI64IntegerAttr(ints.size()),
                                     b.getArrayAttr(mapSyms));
    auto *entry = new Block();
    cb.getBody().push_back(entry);
    IRMapping m;
    m.map(src.getArgument(0), entry->addArgument(i32, loc));
    for (BlockArgument a : src.getArguments().drop_front())
      m.map(a, entry->addArgument(a.getType(), loc));
    for (Value v : ints)
      m.map(v, entry->addArgument(v.getType(), loc));
    for (Value v : maps)
      m.map(v, entry->addArgument(v.getType(), loc));
    // Return blocks take carried values: next=0, break=1.
    auto retBlock = [&](int64_t stop) {
      auto *blk = new Block();
      cb.getBody().push_back(blk);
      SmallVector<Value> vals;
      for (Type t : carried)
        vals.push_back(blk->addArgument(t, loc));
      OpBuilder rb = OpBuilder::atBlockEnd(blk);
      CallbackReturnOp::create(rb, loc, rb.getI64IntegerAttr(stop), vals);
      return blk;
    };
    Block *next = retBlock(0), *brk = retBlock(1);
    b.setInsertionPointToEnd(entry);
    for (Operation &op : src.without_terminator())
      b.clone(op, m);
    auto y = cast<LoopYieldOp>(src.getTerminator());
    SmallVector<Value> vals;
    for (Value v : y.getValues())
      vals.push_back(m.lookupOrDefault(v));
    if (Value stop = y.getStop())
      cf::CondBranchOp::create(b, loc, m.lookupOrDefault(stop), brk, vals, next, vals);
    else
      cf::BranchOp::create(b, loc, next, vals);
    loops.push_back({brk, next});
    LogicalResult r = expandFrom(entry);
    loops.pop_back();
    if (failed(r))
      return failure();
    eraseUnreachable(cb.getBody());

    // Replace loop with count and bpf_loop.
    b.setInsertionPoint(loop);
    Value n = arith::ConstantOp::create(b, loc, i32, b.getI32IntegerAttr(loop.getCount()));
    Value count = n;
    if (Value bound = loop.getBound()) {
      Value lt = arith::CmpIOp::create(b, loc, arith::CmpIPredicate::ult, bound, n);
      count = arith::SelectOp::create(b, loc, lt, bound, n);
    }
    auto call = BpfLoopOp::create(b, loc, TypeRange(carried), FlatSymbolRefAttr::get(cb.getSymNameAttr()),
                                  count, loop.getInits(), ints);
    loop.replaceAllUsesWith(call.getResults());
    cont = loop->getBlock(); // No split: preceding operations are already expanded, so rescanning is harmless.
    loop.erase();
    return success();
  }
  // for_each moves its body into a module callback marked for_each and emits
  // for_each_map_elem. Args are key, borrowed value, carried values, captured
  // integers and symbol-rebound maps. for_each.yield returns zero to continue
  // or one for true stop. Only program/func owners are permitted; op verification
  // excludes loop/callback nesting.
  LogicalResult expandForEach(MapForEachOp fe, Block *&cont) {
    Location loc = fe.getLoc();
    Operation *owner = fe->getParentOp();
    while (owner && !isa<ProgramOp, SubprogramOp>(owner))
      owner = owner->getParentOp();
    if (!owner || !root)
      return fe.emitOpError() << "ebpf.map.for_each has no owning program or func";
    Block &ownerEntry = owner->getRegion(0).front();
    auto mapSymbolOf = [&](BlockArgument arg) -> Attribute {
      if (arg.getOwner() != &ownerEntry)
        return {};
      int64_t base;
      ArrayAttr syms;
      if (auto p = dyn_cast<ProgramOp>(owner)) {
        base = 1;
        syms = p.getMapSymbolsAttr();
      } else {
        auto f = cast<SubprogramOp>(owner);
        base = f.getFunctionType().getNumInputs();
        syms = f.getMapSymbolsAttr();
      }
      int64_t idx = static_cast<int64_t>(arg.getArgNumber()) - base;
      if (!syms || idx < 0 || idx >= static_cast<int64_t>(syms.size()))
        return {};
      return syms[idx];
    };
    Block &src = fe.getBody().front();
    llvm::SetVector<Value> captured;
    fe.getBody().walk([&](Operation *op) {
      for (Value v : op->getOperands())
        if (!fe.getBody().isAncestor(v.getParentRegion()))
          captured.insert(v);
    });
    SmallVector<Value> ints, maps;
    SmallVector<Attribute> mapSyms;
    for (Value v : captured) {
      if (isa<IntegerType>(v.getType())) {
        ints.push_back(v);
        continue;
      }
      auto arg = dyn_cast<BlockArgument>(v);
      Attribute sym = (arg && isa<MapType>(v.getType())) ? mapSymbolOf(arg) : Attribute();
      if (!sym)
        return fe.emitOpError() << "captures " << v.getType() << ", which cannot be passed to a for_each_map_elem callback";
      maps.push_back(v);
      mapSyms.push_back(sym);
    }
    OpBuilder b(fe.getContext());
    SmallVector<Type> carried(fe.getInits().getTypes());
    b.setInsertionPoint(root);
    std::string name = ("__ebpf_foreach_cb_" + rootName + "_" + Twine(callbackCount++)).str();
    auto cb = LoopCallbackOp::create(b, loc, b.getStringAttr(name), b.getI64IntegerAttr(carried.size()), b.getI64IntegerAttr(ints.size()),
                                     b.getArrayAttr(mapSyms), b.getUnitAttr());
    auto *entry = new Block();
    cb.getBody().push_back(entry);
    IRMapping m;
    for (BlockArgument a : src.getArguments())
      m.map(a, entry->addArgument(a.getType(), loc));
    for (Value v : ints)
      m.map(v, entry->addArgument(v.getType(), loc));
    for (Value v : maps)
      m.map(v, entry->addArgument(v.getType(), loc));
    auto retBlock = [&](int64_t stop) {
      auto *blk = new Block();
      cb.getBody().push_back(blk);
      SmallVector<Value> vals;
      for (Type t : carried)
        vals.push_back(blk->addArgument(t, loc));
      OpBuilder rb = OpBuilder::atBlockEnd(blk);
      CallbackReturnOp::create(rb, loc, rb.getI64IntegerAttr(stop), vals);
      return blk;
    };
    Block *next = retBlock(0), *brk = retBlock(1);
    b.setInsertionPointToEnd(entry);
    for (Operation &op : src.without_terminator())
      b.clone(op, m);
    auto y = cast<MapForEachYieldOp>(src.getTerminator());
    SmallVector<Value> vals;
    for (Value v : y.getValues())
      vals.push_back(m.lookupOrDefault(v));
    if (Value stop = y.getStop())
      cf::CondBranchOp::create(b, loc, m.lookupOrDefault(stop), brk, vals, next, vals);
    else
      cf::BranchOp::create(b, loc, next, vals);
    if (failed(expandFrom(entry)))
      return failure();
    eraseUnreachable(cb.getBody());
    b.setInsertionPoint(fe);
    auto call = ForEachMapElemOp::create(b, loc, fe->getResultTypes(), FlatSymbolRefAttr::get(cb.getSymNameAttr()), fe.getMap(),
                                         fe.getInits(), ints);
    fe.replaceAllUsesWith(call->getResults());
    cont = fe->getBlock();
    fe.erase();
    return success();
  }
  // task.find_vma moves its body into a module callback marked
  // find_vma and emits find_vma_call. The entry takes the task, the vma, the
  // carried values and the captured integers (the verifier rejects any other
  // capture and any map); the yield becomes callback.return 0.
  LogicalResult expandFindVma(TaskFindVmaOp fv, Block *&cont) {
    Location loc = fv.getLoc();
    if (!root)
      return fv.emitOpError() << "ebpf.task.find_vma has no owning program";
    Block &src = fv.getBody().front();
    llvm::SetVector<Value> captured;
    fv.getBody().walk([&](Operation *op) {
      for (Value v : op->getOperands())
        if (!fv.getBody().isAncestor(v.getParentRegion()))
          captured.insert(v);
    });
    SmallVector<Value> ints;
    for (Value v : captured) {
      if (!isa<IntegerType>(v.getType()))
        return fv.emitOpError() << "captures " << v.getType() << ", which cannot be passed to a find_vma callback";
      ints.push_back(v);
    }
    OpBuilder b(fv.getContext());
    SmallVector<Type> carried(fv.getInits().getTypes());
    b.setInsertionPoint(root);
    std::string name = ("__ebpf_findvma_cb_" + rootName + "_" + Twine(callbackCount++)).str();
    auto cb = LoopCallbackOp::create(b, loc, b.getStringAttr(name), b.getI64IntegerAttr(carried.size()), b.getI64IntegerAttr(ints.size()),
                                     b.getArrayAttr({}), UnitAttr(), b.getUnitAttr());
    auto *entry = new Block();
    cb.getBody().push_back(entry);
    IRMapping m;
    for (BlockArgument a : src.getArguments())
      m.map(a, entry->addArgument(a.getType(), loc));
    for (Value v : ints)
      m.map(v, entry->addArgument(v.getType(), loc));
    auto *next = new Block();
    cb.getBody().push_back(next);
    SmallVector<Value> nextArgs;
    for (Type t : carried)
      nextArgs.push_back(next->addArgument(t, loc));
    {
      OpBuilder rb = OpBuilder::atBlockEnd(next);
      CallbackReturnOp::create(rb, loc, rb.getI64IntegerAttr(0), nextArgs);
    }
    b.setInsertionPointToEnd(entry);
    for (Operation &op : src.without_terminator())
      b.clone(op, m);
    auto y = cast<TaskFindVmaYieldOp>(src.getTerminator());
    SmallVector<Value> vals;
    for (Value v : y.getValues())
      vals.push_back(m.lookupOrDefault(v));
    cf::BranchOp::create(b, loc, next, vals);
    eraseUnreachable(cb.getBody());
    b.setInsertionPoint(fv);
    auto call = FindVmaCallOp::create(b, loc, fv->getResultTypes(), FlatSymbolRefAttr::get(cb.getSymNameAttr()), fv.getTask(), fv.getAddr(),
                                      fv.getInits(), ints);
    fv.replaceAllUsesWith(call->getResults());
    cont = fv->getBlock();
    fv.erase();
    return success();
  }
  unsigned callbackCount = 0;

public:
  Operation *root = nullptr; // Expansion root: program or func.
  std::string rootName;

private:

  // atomic_add is lookup, no-op on null, then atomic addition.
  Block *expandAtomicAdd(MapAtomicAddOp add) {
    Location loc = add.getLoc();
    MLIRContext *ctx = add.getContext();
    Block *cur = add->getBlock();
    auto mapTy = cast<MapType>(add.getMap().getType());
    Type valueTy = mapTy.getValueType();

    OpBuilder b(add);
    Value maybe = MapLookupOp::create(b, loc, MaybeRefType::get(ctx, valueTy),
                                      add.getMap(), add.getKey());
    Value test = IsPresentOp::create(b, loc, b.getI1Type(), maybe);

    Block *cont = cur->splitBlock(add.getOperation());
    auto *addBlk = new Block();
    cur->getParent()->getBlocks().insert(cont->getIterator(), addBlk);

    b.setInsertionPointToEnd(cur);
    cf::CondBranchOp::create(b, loc, test, addBlk, ValueRange{}, cont,
                             ValueRange{});
    b.setInsertionPointToStart(addBlk);
    Value ref = AssumePresentOp::create(b, loc, BorrowedType::get(ctx, valueTy),
                                        maybe);
    RefAtomicAddOp::create(b, loc, ref, add.getDelta());
    cf::BranchOp::create(b, loc, cont);
    add.erase();
    return cont;
  }
};

// Remove unreachable continuation after both arms escape. Keep declared
// helper requirements consistent with ELF instructions, where LLVM removes
// unreachable blocks.
void eraseUnreachable(Region &body) {
  llvm::SmallPtrSet<Block *, 16> seen;
  SmallVector<Block *> work{&body.front()};
  while (!work.empty()) {
    Block *blk = work.pop_back_val();
    if (!seen.insert(blk).second)
      continue;
    for (Block *s : blk->getSuccessors())
      work.push_back(s);
  }
  SmallVector<Block *> dead;
  for (Block &blk : body)
    if (!seen.contains(&blk))
      dead.push_back(&blk);
  for (Block *blk : dead)
    blk->dropAllReferences();
  for (Block *blk : dead) {
    blk->dropAllDefinedValueUses();
    blk->erase();
  }
}

// Fold constants and add/sub/mul/ext/trunc in the result-width APInt domain.
// Arithmetic wraps at its width; extui zero-extends, extsi sign-extends and
// trunci truncates. Host int64 arithmetic would incorrectly fold i8 100+100
// followed by extsi as 200 instead of -56.
std::optional<APInt> foldConstInt(Value v, int depth = 0) {
  if (depth > 16 || !v.getType().isSignlessInteger())
    return std::nullopt;
  APInt c;
  if (matchPattern(v, m_ConstantInt(&c)))
    return c;
  Operation *d = v.getDefiningOp();
  if (!d)
    return std::nullopt;
  unsigned w = v.getType().getIntOrFloatBitWidth();
  if (isa<arith::ExtUIOp, arith::ExtSIOp, arith::TruncIOp>(d)) {
    auto x = foldConstInt(d->getOperand(0), depth + 1);
    if (!x)
      return std::nullopt;
    if (isa<arith::ExtUIOp>(d))
      return x->zext(w);
    if (isa<arith::ExtSIOp>(d))
      return x->sext(w);
    return x->trunc(w);
  }
  if (isa<arith::AddIOp, arith::SubIOp, arith::MulIOp>(d)) {
    auto a = foldConstInt(d->getOperand(0), depth + 1), b = foldConstInt(d->getOperand(1), depth + 1);
    if (!a || !b || a->getBitWidth() != w || b->getBitWidth() != w)
      return std::nullopt;
    return isa<arith::AddIOp>(d) ? *a + *b : isa<arith::SubIOp>(d) ? *a - *b : *a * *b;
  }
  return std::nullopt;
}

// Packet offsets match lowering's zero-extended u64; widths above 64 are unsupported.
std::optional<uint64_t> foldOffset(Value v) {
  auto x = foldConstInt(v);
  if (!x || x->getBitWidth() > 64)
    return std::nullopt;
  return x->getZExtValue();
}

// W1 replaces constant-foldable packet loads dominated by pkt.check_br
// in_range when ctx matches and the full read lies within the checked window.
// Expanded unrolled IV expressions may become constant only at this stage.
// All crossed operations must be PacketNeutral, including every operation
// in predecessor blocks and the full use block: operations after use may
// precede its next execution through a loop. WindowPath DominatedBackward
// supplies that conservative path set. New pointer-invalidating operations
// require negative controls in window-load-nested.mlir.
bool pathIsPacketNeutral(Block *in, Operation *load, DominanceInfo &dom) {
  bool neutral = true;
  WindowPath(in, load, WindowPathKind::DominatedBackward, UseBlockOps::All, &dom).forEachOp([&](Operation *o) {
    neutral = isPacketNeutral(o);
    return neutral;
  });
  return neutral;
}

// Optional i1 join threading (disabled by default) evaluates per-predecessor
// constant conditions through at most sixteen pure arithmetic operations,
// excluding division/remainder. Redirect cf.br predecessors to the selected
// side: clone join operations for a single predecessor or form a small
// unconditional join for multiple predecessors. External join-value uses must
// be dominated by one selected side. Flatten forwarding blocks and clone
// small pure pre-join blocks when their i1 arguments evaluate per predecessor.
// Run after W1/C1 so threading does not change window-load replacement.
namespace {
std::optional<bool> constI1(Value v) {
  if (auto k = v.getDefiningOp<arith::ConstantOp>())
    if (auto b = dyn_cast<IntegerAttr>(k.getValue()); b && b.getType().isInteger(1))
      return !b.getValue().isZero();
  return std::nullopt;
}

// Evaluate v in block j using known i1 arguments. Constants may belong to
// other blocks because unrolled copies share them.
std::optional<bool> evalI1(Value v, Block *j, ArrayRef<std::optional<bool>> argConst) {
  if (auto ba = dyn_cast<BlockArgument>(v))
    return ba.getOwner() == j ? argConst[ba.getArgNumber()] : std::nullopt;
  if (auto c = constI1(v))
    return c;
  Operation *d = v.getDefiningOp();
  if (!d || d->getBlock() != j || !isa<arith::XOrIOp, arith::AndIOp, arith::OrIOp>(d))
    return std::nullopt;
  auto l = evalI1(d->getOperand(0), j, argConst), r = evalI1(d->getOperand(1), j, argConst);
  if (!l || !r)
    return std::nullopt;
  if (isa<arith::XOrIOp>(d))
    return *l != *r;
  return isa<arith::AndIOp>(d) ? (*l && *r) : (*l || *r);
}

SmallVector<std::optional<bool>> argConsts(cf::BranchOp br) {
  SmallVector<std::optional<bool>> out;
  for (Value a : br.getDestOperands())
    out.push_back(constI1(a));
  return out;
}

bool isDupSafe(Operation &op) {
  if (!op.getDialect() || op.getDialect()->getNamespace() != "arith")
    return false;
  return !isa<arith::DivUIOp, arith::DivSIOp, arith::RemUIOp, arith::RemSIOp, arith::CeilDivSIOp, arith::CeilDivUIOp,
              arith::FloorDivSIOp>(op);
}

bool smallPure(Block &b) {
  return b.getOperations().size() <= 17 && llvm::all_of(b.without_terminator(), [](Operation &op) { return isDupSafe(op); });
}

// Clone from at b, sharing constants. Fold constant i1 logic and constant-condition select.
void cloneFolding(Block &from, OpBuilder &b, IRMapping &map) {
  for (Operation &op : from.without_terminator()) {
    if (isa<arith::ConstantOp>(op))
      continue;
    if (isa<arith::XOrIOp, arith::AndIOp, arith::OrIOp>(op) && op.getResult(0).getType().isInteger(1)) {
      auto l = constI1(map.lookupOrDefault(op.getOperand(0))), r = constI1(map.lookupOrDefault(op.getOperand(1)));
      if (l && r) {
        bool v = isa<arith::XOrIOp>(op) ? *l != *r : isa<arith::AndIOp>(op) ? (*l && *r) : (*l || *r);
        map.map(op.getResult(0), arith::ConstantOp::create(b, op.getLoc(), b.getBoolAttr(v)).getResult());
        continue;
      }
    }
    if (auto sel = dyn_cast<arith::SelectOp>(op))
      if (auto c = constI1(map.lookupOrDefault(sel.getCondition()))) {
        map.map(sel.getResult(), map.lookupOrDefault(*c ? sel.getTrueValue() : sel.getFalseValue()));
        continue;
      }
    b.clone(op, map);
  }
}

// Hoist block constants to entry so other blocks can share them.
void hoistConstants(Block &b, Region &body) {
  for (Operation &op : llvm::make_early_inc_range(b.without_terminator()))
    if (isa<arith::ConstantOp>(op))
      op.moveBefore(&body.front(), body.front().begin());
}

// Clone a small pure predecessor P into its cf.br predecessors when each
// can evaluate values forwarded to J's i1 arguments. P must end in cf.br J,
// with its own values used only internally or by its terminator. Includes
// forwarding-only blocks.
bool tailDupInto(Block &j, Region &body) {
  SmallVector<unsigned> condArgs;
  for (BlockArgument a : j.getArguments())
    if (a.getType().isInteger(1))
      condArgs.push_back(a.getArgNumber());
  if (condArgs.empty())
    return false;
  for (Block *p : llvm::to_vector(j.getPredecessors())) {
    if (p->isEntryBlock() || p->hasNoPredecessors() || !smallPure(*p))
      continue;
    auto pbr = dyn_cast<cf::BranchOp>(p->getTerminator());
    if (!pbr || pbr.getDest() != &j)
      continue;
    bool ok = true;
    for (Operation &op : p->without_terminator())
      for (Operation *u : op.getUsers())
        ok &= u->getBlock() == p || isa<arith::ConstantOp>(op);
    for (BlockArgument a : p->getArguments())
      for (Operation *u : a.getUsers())
        ok &= u->getBlock() == p;
    for (Block *pp : p->getPredecessors()) {
      auto br = dyn_cast<cf::BranchOp>(pp->getTerminator());
      if (!br || br.getDest() != p) {
        ok = false;
        break;
      }
      auto ac = argConsts(br);
      for (unsigned i : condArgs)
        ok &= evalI1(pbr.getDestOperands()[i], p, ac).has_value();
    }
    if (!ok)
      continue;
    hoistConstants(*p, body);
    for (Block *pp : llvm::to_vector(p->getPredecessors())) {
      auto br = cast<cf::BranchOp>(pp->getTerminator());
      IRMapping map;
      for (BlockArgument a : p->getArguments())
        map.map(a, br.getDestOperands()[a.getArgNumber()]);
      OpBuilder b(br);
      cloneFolding(*p, b, map);
      SmallVector<Value> ops;
      for (Value v : pbr.getDestOperands())
        ops.push_back(map.lookupOrDefault(v));
      cf::BranchOp::create(b, br.getLoc(), &j, ops);
      br.erase();
    }
    p->dropAllDefinedValueUses();
    p->erase();
    return true;
  }
  return false;
}

bool threadOne(Region &body) {
  DominanceInfo dom(body.getParentOp());
  for (Block &j : body) {
    auto cbr = dyn_cast<cf::CondBranchOp>(j.getTerminator());
    if (!cbr || j.isEntryBlock() || !smallPure(j))
      continue;
    Block *t = cbr.getTrueDest(), *f = cbr.getFalseDest();
    if (t == f || t == &j || f == &j || !t->getSinglePredecessor() || !f->getSinglePredecessor())
      continue;
    if (tailDupInto(j, body))
      return true;
    // Every predecessor is cf.br J and can evaluate the condition independently.
    SmallVector<cf::BranchOp> toT, toF;
    bool all = !j.hasNoPredecessors();
    for (Block *p : j.getPredecessors()) {
      auto br = dyn_cast<cf::BranchOp>(p->getTerminator());
      std::optional<bool> r;
      if (br && br.getDest() == &j)
        r = evalI1(cbr.getCondition(), &j, argConsts(br));
      if (!r) {
        all = false;
        break;
      }
      (*r ? toT : toF).push_back(br);
    }
    if (!all)
      continue;
    // Join arguments/nonconstant results used outside J must be dominated by
        // one selected T/F side, with at least one predecessor taking that side.
    SmallVector<Value> jvals(j.getArguments().begin(), j.getArguments().end());
    for (Operation &op : j.without_terminator())
      if (!isa<arith::ConstantOp>(op))
        llvm::append_range(jvals, op.getResults());
    bool usesOK = true;
    for (Value v : jvals)
      for (OpOperand &u : v.getUses()) {
        Block *ub = u.getOwner()->getBlock();
        if (ub == &j)
          continue;
        bool inT = dom.dominates(t, ub), inF = dom.dominates(f, ub);
        usesOK &= (inT && !toT.empty()) || (inF && !toF.empty());
      }
    if (!usesOK)
      continue;
    hoistConstants(j, body);
    // Per side: clone J into a sole predecessor, or create a small
        // unconditional join carrying J's arguments/operations for multiple predecessors.
    auto side = [&](SmallVector<cf::BranchOp> &brs, Block *dest, OperandRange destOps, Block *sideRoot) {
      if (brs.empty())
        return;
      IRMapping map;
      Block *merge = nullptr;
      if (brs.size() == 1) {
        for (BlockArgument a : j.getArguments())
          map.map(a, brs[0].getDestOperands()[a.getArgNumber()]);
        OpBuilder b(brs[0]);
        cloneFolding(j, b, map);
      } else {
        merge = new Block();
        body.getBlocks().insert(Region::iterator(dest), merge);
        for (BlockArgument a : j.getArguments())
          map.map(a, merge->addArgument(a.getType(), a.getLoc()));
        OpBuilder b = OpBuilder::atBlockEnd(merge);
        cloneFolding(j, b, map);
      }
      for (Value v : jvals)
        for (OpOperand &u : llvm::make_early_inc_range(v.getUses())) {
          Block *ub = u.getOwner()->getBlock();
          if (ub != &j && dom.dominates(sideRoot, ub))
            u.set(map.lookupOrDefault(v));
        }
      SmallVector<Value> ops;
      for (Value v : destOps)
        ops.push_back(map.lookupOrDefault(v));
      if (merge) {
        OpBuilder b = OpBuilder::atBlockEnd(merge);
        cf::BranchOp::create(b, cbr.getLoc(), dest, ops);
      }
      for (cf::BranchOp br : brs) {
        SmallVector<Value> o = merge ? SmallVector<Value>(br.getDestOperands()) : ops;
        OpBuilder b(br);
        cf::BranchOp::create(b, br.getLoc(), merge ? merge : dest, o);
        br.erase();
      }
    };
    side(toT, t, cbr.getTrueDestOperands(), t);
    side(toF, f, cbr.getFalseDestOperands(), f);
    j.dropAllDefinedValueUses();
    j.dropAllUses();
    j.erase();
    return true;
  }
  return false;
}
} // namespace

void threadI1Joins(Region &body) {
  while (threadOne(body)) {
  }
  eraseUnreachable(body);
}

void nestedWindowLoads(Operation *prog) {
  DominanceInfo dom(prog);
  SmallVector<PktCheckBrOp> checks;
  prog->walk([&](PktCheckBrOp pk) { checks.push_back(pk); });
  for (PktCheckBrOp pk : checks) {
    auto base = foldOffset(pk.getOffset());
    if (!base)
      continue;
    uint64_t len = pk.getLen();
    Block *in = pk.getInRange();
    Value w = in->getArgument(0);
    SmallVector<PacketLoadOp> loads;
    for (Block &b : *in->getParent())
      if (dom.dominates(in, &b))
        for (Operation &o : b)
          if (auto ld = dyn_cast<PacketLoadOp>(&o); ld && ld.getCtx() == pk.getCtx())
            loads.push_back(ld);
    for (PacketLoadOp ld : loads) {
      auto off = foldOffset(ld.getOffset());
      uint64_t bytes = ld.getResult().getType().getIntOrFloatBitWidth() / 8;
      if (!off || *off < *base || *off - *base > len || bytes > len - (*off - *base))
        continue;
      if (!pathIsPacketNeutral(in, ld, dom))
        continue;
      OpBuilder b(ld);
      auto wl = PacketWindowLoadOp::create(b, ld.getLoc(), ld.getResult().getType(), w, b.getI64IntegerAttr(static_cast<int64_t>(*off - *base)));
      ld.getResult().replaceAllUsesWith(wl.getResult());
      ld->erase();
    }
  }
}

struct EBPFExpandRegionsPass
    : public mlir::ebpf::impl::EBPFExpandRegionsBase<EBPFExpandRegionsPass> {
  using Base::Base; // Tuning-option constructor. Reachability includes transitive ebpf.call
  // edges and calls inside outlined helper callbacks.
  static llvm::StringSet<> reachableFuncs(ModuleOp module) {
    llvm::StringMap<SubprogramOp> funcs;
    for (auto fn : module.getOps<SubprogramOp>())
      funcs[fn.getSymName()] = fn;
    llvm::StringSet<> seen;
    std::function<void(Operation *)> go = [&](Operation *owner) {
      owner->walk([&](CallOp call) {
        auto it = funcs.find(call.getCallee());
        if (it != funcs.end() && seen.insert(call.getCallee()).second)
          go(it->second);
      });
      owner->walk([&](Operation *op) { // callbackOf handles both bpf_loop and for_each_map_elem.
        if (FlatSymbolRefAttr ref = callbackOf(op))
          if (auto cb = SymbolTable::lookupNearestSymbolFrom<LoopCallbackOp>(op, ref))
            go(cb);
      });
    };
    for (auto prog : module.getOps<ProgramOp>())
      go(prog);
    // ': a timer callback is an entry too — a function the program
    // calls only inside an N = 0 loop body and the callback calls stays.
    for (auto cb : module.getOps<TimerCallbackOp>())
      go(cb);
    return seen;
  }

  void runOnOperation() override {
    // Require neutral-table helpers to exist in ABI and not be pktinval;
    // fail explicitly on compiler-table inconsistencies.
    if (std::optional<std::string> why = checkPacketNeutralTable()) {
      getOperation().emitError() << *why;
      return signalPassFailure();
    }
    // Save pre-expansion reachability: calls only inside N=0 bodies disappear.
    llvm::StringSet<> before = reachableFuncs(getOperation());
    // Expand program, func and timer callback bodies, including callback ifs
    // used by bounded periodic timers.
    SmallVector<Operation *> programs;
    getOperation().walk([&](Operation *op) {
      if (isa<ProgramOp, SubprogramOp, TimerCallbackOp>(op))
        programs.push_back(op);
    });
    for (Operation *prog : programs) {
      Region &body = prog->getRegion(0);
      if (!body.hasOneBlock()) {
        // Already-expanded input needs no work. Reject multi-block source input
        // with remaining region controls: mixed source/CFG expansion is unsupported.
        Operation *stageOne = nullptr;
        prog->walk([&](Operation *op) {
          if (!stageOne && isStageOneControl(op))
            stageOne = op;
        });
        if (stageOne) {
          // Name the actual remaining source-control operation, not a partial fixed list.
          prog->emitOpError()
              << "a program with more than one block that still contains a stage ① control op ('"
              << stageOne->getName() << "') is not supported (stage ① programs "
                 "express control only through check regions)";
          return signalPassFailure();
        }
        continue;
      }
      Expander ex;
      ex.sinkLoads = sinkWindowLoads;
      ex.maskCheckedIndex = maskCheckedIndex;
      ex.maskSkipConstantIndex = maskSkipConstantIndex;
      ex.backedgeSpill = backedgeSpill;
      ex.backedgeRotate = backedgeRotate;
      ex.root = prog;
      ex.rootName = prog->getAttrOfType<StringAttr>(SymbolTable::getSymbolAttrName()).getValue().str();
      if (failed(ex.expandFrom(&body.front())))
        return signalPassFailure();
      eraseUnreachable(body);
      if (windowLoadNested)
        nestedWindowLoads(prog);
      if (threadI1Join)
        threadI1Joins(body);
    }
    // Include helper-loop callbacks created during expansion.
    if (threadI1Join)
      getOperation().walk([&](LoopCallbackOp cb) {
        if (!cb->getRegion(0).empty() && !cb->getRegion(0).hasOneBlock())
          threadI1Joins(cb->getRegion(0));
      });
    // Remove funcs made unreachable by expansion (for example calls only in
    // N=0 bodies), but only if reachable before expansion. Source-unreachable
    // funcs belong to VerifyCallGraph rejection, not silent elimination.
    llvm::StringSet<> after = reachableFuncs(getOperation());
    SmallVector<SubprogramOp> dead;
    for (auto fn : getOperation().getOps<SubprogramOp>())
      if (before.contains(fn.getSymName()) && !after.contains(fn.getSymName()))
        dead.push_back(fn);
    for (auto fn : dead)
      fn.erase();
  }
};

} // namespace
