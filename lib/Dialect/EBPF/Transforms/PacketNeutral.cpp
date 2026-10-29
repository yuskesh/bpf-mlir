//===- PacketNeutral.cpp - packet-neutral operation classification ----------===//
//
// C1/W1 motion and replacement use an explicit neutral whitelist, including
// expanded cf.br/cf.cond_br control flow. Extending it requires an inventory
// of changed input results. Adding a packet-pointer-invalidating operation
// requires a real negative control within in_range showing C1 cannot cross it
// and W1 cannot replace across it.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/PacketNeutral.h"

#include "bpf-mlir/Dialect/BPFABI/KernelABI.h"
#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"

#include "mlir/Dialect/ControlFlow/IR/ControlFlowOps.h"
#include "mlir/IR/SymbolTable.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/TypeSwitch.h"
#include <functional>

using namespace mlir;
using namespace mlir::ebpf;

namespace {
// ABI helper names whose effects preserve packet contents.
constexpr llvm::StringLiteral kLookup[] = {"map_lookup_elem"};
constexpr llvm::StringLiteral kUpdate[] = {"map_update_elem"};
constexpr llvm::StringLiteral kDelete[] = {"map_delete_elem"};
constexpr llvm::StringLiteral kKtime[] = {"ktime_get_ns"};
constexpr llvm::StringLiteral kReserve[] = {"ringbuf_reserve"};
constexpr llvm::StringLiteral kSubmit[] = {"ringbuf_submit"};
constexpr llvm::StringLiteral kDiscard[] = {"ringbuf_discard"};
// register helper effects without making this reservation-writing op crossable.
constexpr llvm::StringLiteral kUserRead[] = {"probe_read_user"};
// Helper effects for non-neutral operations drive invalidation predicates.
// Names must match ABI lowering helperCall: operations emitting pktinval
// helpers must classify as invalidating, checked by lowering.
constexpr llvm::StringLiteral kAdjustHead[] = {"xdp_adjust_head"};
constexpr llvm::StringLiteral kAdjustTail[] = {"xdp_adjust_tail"};
constexpr llvm::StringLiteral kTailCall[] = {"tail_call"};
// All three lwt_seg6local seg6 helpers invalidate packet pointers.
constexpr llvm::StringLiteral kSeg6Store[] = {"lwt_seg6_store_bytes"};
constexpr llvm::StringLiteral kSeg6Adjust[] = {"lwt_seg6_adjust_srh"};
constexpr llvm::StringLiteral kSeg6Action[] = {"lwt_seg6_action"};
// effect registration does not make this side-effecting helper crossable.
constexpr llvm::StringLiteral kSysctlSet[] = {"sysctl_set_new_value"};
// sk_reuseport socket-cookie queries do not invalidate pointers. They appear
// in the effects table but not the neutral whitelist: no window input path
// requires motion across them, so do not broaden that contract.
constexpr llvm::StringLiteral kSockCookie[] = {"get_socket_cookie"};
// sk_msg pull/pop invalidate packet pointers. apply/cork do not invalidate,
// but their message-verdict side effects still exclude C1/W1 crossing.
constexpr llvm::StringLiteral kMsgApply[] = {"msg_apply_bytes"};
constexpr llvm::StringLiteral kMsgCork[] = {"msg_cork_bytes"};
constexpr llvm::StringLiteral kMsgPull[] = {"msg_pull_data"};
constexpr llvm::StringLiteral kMsgPop[] = {"msg_pop_data"};
// All classified helpers for consistency checks.
constexpr llvm::StringLiteral kAllHelpers[] = {"map_lookup_elem", "map_update_elem", "map_delete_elem", "ktime_get_ns",
                                               "ringbuf_reserve", "ringbuf_submit", "ringbuf_discard"};
} // namespace

std::optional<PacketNeutralClass> mlir::ebpf::packetNeutralClass(Operation *op) {
  if (op->getDialect() && op->getDialect()->getNamespace() == "arith")
    return PacketNeutralClass{{}, false};
  using R = std::optional<PacketNeutralClass>;
  return llvm::TypeSwitch<Operation *, R>(op)
      .Case<MapLookupOp, MapAtomicAddOp>([](auto) { return PacketNeutralClass{kLookup, false}; }) // Expansion turns atomic_add into lookup -> ref.atomic_add.
      .Case<MapUpdateOp, MapTryUpdateOp>([](auto) { return PacketNeutralClass{kUpdate, false}; })
      .Case<MapDeleteOp, MapTryDeleteOp>([](auto) { return PacketNeutralClass{kDelete, false}; })
      .Case<KtimeOp>([](auto) { return PacketNeutralClass{kKtime, false}; })
      .Case<RingbufReserveOp>([](auto) { return PacketNeutralClass{kReserve, false}; })
      .Case<RingbufSubmitOp>([](auto) { return PacketNeutralClass{kSubmit, false}; })
      .Case<RingbufDiscardOp>([](auto) { return PacketNeutralClass{kDiscard, false}; })
      // Helper-free operations: record construction, borrowed map-value access
    // (normal/once), reservation writes, packet reads and structural operations.
      .Case<RecordMakeOp, RefCheckOp, RefLoadOp, RefStoreOp, RefFieldLoadOp, RefFieldStoreOp, RefFieldAtomicAddOp, RefAtomicAddOp, YieldOp, IfOp,
            IfYieldOp, RingbufIfReservedOp, RingbufStoreFieldOp, RingbufStoreRecordOp, PacketLoadOp, PacketWindowLoadOp>(
          [](auto) { return PacketNeutralClass{{}, false}; })
      // Stores preserve pointer validity but write packets, bounding C1/W1 motion.
      .Case<PacketStoreOp>([](auto) { return PacketNeutralClass{{}, true}; })
      // Expanded CFG control flow lets W1 examine paths. No helpers or packet
      // writes; C1 runs before expansion and is unaffected.
      .Case<cf::BranchOp, cf::CondBranchOp>([](auto) { return PacketNeutralClass{{}, false}; })
      // Expanded null-check structure: is_present compares pointer with null;
      // assume_present only replaces values and emits no instruction. Like
      // source ref.check/if_reserved, neither calls helpers/kfuncs nor writes
      // packets. VerifyStructured separately owns placement/non-null proof.
      // Do not add pkt.check_br: no input path needs that new-window terminator.
      .Case<IsPresentOp, AssumePresentOp>([](auto) { return PacketNeutralClass{{}, false}; })
      .Default([](Operation *) { return R(); });
}

std::optional<llvm::ArrayRef<llvm::StringLiteral>> mlir::ebpf::packetEffectHelpers(Operation *op) {
  if (std::optional<PacketNeutralClass> c = packetNeutralClass(op))
    return c->helpers;
  using R = std::optional<llvm::ArrayRef<llvm::StringLiteral>>;
  return llvm::TypeSwitch<Operation *, R>(op)
      .Case<UserReadOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kUserRead); })
      .Case<XdpAdjustHeadOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kAdjustHead); })
      .Case<XdpAdjustTailOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kAdjustTail); })
      // tail_call expands to tail_call.try plus fallback; both invoke tail_call,
    // whose failed path invalidates packet pointers too.
      .Case<TailCallOp, TailCallTryOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kTailCall); })
      // seg6 helpers invalidate packet pointers on success and failure.
      .Case<LwtSeg6StoreBytesOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSeg6Store); })
      .Case<LwtSeg6AdjustSrhOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSeg6Adjust); })
      .Case<LwtSeg6ActionOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSeg6Action); })
      .Case<SysctlSetNewValueOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSysctlSet); })
      .Case<SkReuseportCookieOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSockCookie); })
      .Case<MsgApplyBytesOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kMsgApply); })
      .Case<MsgCorkBytesOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kMsgCork); })
      .Case<MsgPullDataOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kMsgPull); })
      .Case<MsgPopDataOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kMsgPop); })
      .Default([](Operation *) { return R(); });
}

bool mlir::ebpf::helpersInvalidatePacketPointers(llvm::ArrayRef<llvm::StringRef> helpers) {
  for (llvm::StringRef h : helpers)
    if (bpfabi::isPacketInvalidatingHelper(h))
      return true;
  return false;
}

bool mlir::ebpf::opInvalidatesPacketPointers(Operation *op) {
  // Calls invalidate if any transitive callee does: kernel clears pointers in
  // every frame. Current funcs cannot accept ctx, so cannot invalidate (false);
  // keep this rule ready for context-argument support.
  if (auto call = dyn_cast<CallOp>(op)) {
    auto *callee = SymbolTable::lookupNearestSymbolFrom(op, call.getCalleeAttr());
    if (!callee || !isa<SubprogramOp>(callee))
      return false;
    llvm::SmallPtrSet<Operation *, 8> seen;
    std::function<bool(Operation *)> inv = [&](Operation *fn) -> bool {
      if (!seen.insert(fn).second)
        return false;
      return fn->walk([&](Operation *o) {
                 if (auto c = dyn_cast<CallOp>(o)) {
                   auto *t = SymbolTable::lookupNearestSymbolFrom(o, c.getCalleeAttr());
                   if (t && isa<SubprogramOp>(t) && inv(t))
                     return WalkResult::interrupt();
                   return WalkResult::advance();
                 }
                 std::optional<llvm::ArrayRef<llvm::StringLiteral>> h = packetEffectHelpers(o);
                 if (!h)
                   return WalkResult::advance();
                 SmallVector<llvm::StringRef> n(h->begin(), h->end());
                 return helpersInvalidatePacketPointers(n) ? WalkResult::interrupt() : WalkResult::advance();
               })
          .wasInterrupted();
    };
    return inv(callee);
  }
  std::optional<llvm::ArrayRef<llvm::StringLiteral>> hs = packetEffectHelpers(op);
  if (!hs)
    return false;
  SmallVector<llvm::StringRef> names(hs->begin(), hs->end());
  return helpersInvalidatePacketPointers(names);
}

bool mlir::ebpf::invalidatesPacketPointers(Operation *op) {
  return op->walk([](Operation *o) { return opInvalidatesPacketPointers(o) ? WalkResult::interrupt() : WalkResult::advance(); })
      .wasInterrupted();
}

bool mlir::ebpf::isPacketNeutral(Operation *op) {
  bool ok = true;
  op->walk([&](Operation *o) {
    std::optional<PacketNeutralClass> c = packetNeutralClass(o);
    if (!c || c->writesPacket) {
      ok = false;
      return WalkResult::interrupt();
    }
    for (llvm::StringRef h : c->helpers)
      if (!bpfabi::lookupHelper(h) || bpfabi::isPacketInvalidatingHelper(h)) {
        ok = false;
        return WalkResult::interrupt();
      }
    return WalkResult::advance();
  });
  return ok;
}

std::optional<std::string> mlir::ebpf::checkPacketNeutralTable() {
  for (llvm::StringRef h : kAllHelpers) {
    if (!bpfabi::lookupHelper(h))
      return ("packet-neutral table: helper '" + h + "' is not in the UAPI table").str();
    if (bpfabi::isPacketInvalidatingHelper(h))
      return ("packet-neutral table: helper '" + h + "' invalidates packet pointers (pktinval)").str();
  }
  return std::nullopt;
}
