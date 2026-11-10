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
constexpr llvm::StringLiteral kTrace[] = {"trace_printk"};
constexpr llvm::StringLiteral kSkbLoad[] = {"skb_load_bytes"};
constexpr llvm::StringLiteral kSkbRelative[] = {"skb_load_bytes_relative"};
constexpr llvm::StringLiteral kVlanPush[] = {"skb_vlan_push"};
constexpr llvm::StringLiteral kVlanPop[] = {"skb_vlan_pop"};
constexpr llvm::StringLiteral kCheckMtu[] = {"check_mtu"};
constexpr llvm::StringLiteral kCsumLevel[] = {"csum_level"};
constexpr llvm::StringLiteral kSetHash[] = {"set_hash"};
constexpr llvm::StringLiteral kSetHashInvalid[] = {"set_hash_invalid"};
constexpr llvm::StringLiteral kEcnSetCe[] = {"skb_ecn_set_ce"};
constexpr llvm::StringLiteral kSkbAdjust[] = {"skb_adjust_room"};
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
constexpr llvm::StringLiteral kAdjustMeta[] = {"xdp_adjust_meta"};
constexpr llvm::StringLiteral kAdjustTail[] = {"xdp_adjust_tail"};
constexpr llvm::StringLiteral kCloneRedirect[] = {"clone_redirect"};
constexpr llvm::StringLiteral kSkbStore[] = {"skb_store_bytes"};
constexpr llvm::StringLiteral kL3Csum[] = {"l3_csum_replace"};
// sched_cls / xdp packet helpers. Invalidation follows the UAPI
// pktinval rows mechanically; none of these is in the neutral whitelist.
constexpr llvm::StringLiteral kL4Csum[] = {"l4_csum_replace"};
constexpr llvm::StringLiteral kSkbPull[] = {"skb_pull_data"};
constexpr llvm::StringLiteral kSkbChangeTail[] = {"skb_change_tail"};
constexpr llvm::StringLiteral kSkbChangeHead[] = {"skb_change_head"};
constexpr llvm::StringLiteral kSkbChangeProto[] = {"skb_change_proto"};
constexpr llvm::StringLiteral kSkbChangeType[] = {"skb_change_type"};
constexpr llvm::StringLiteral kCsumUpdate[] = {"csum_update"};
constexpr llvm::StringLiteral kCsumDiff[] = {"csum_diff"};
constexpr llvm::StringLiteral kHashRecalc[] = {"get_hash_recalc"};
constexpr llvm::StringLiteral kCgroupClassid[] = {"get_cgroup_classid"};
constexpr llvm::StringLiteral kNetnsCookie[] = {"get_netns_cookie"};
// not in pktinval and not in the neutral whitelist.
constexpr llvm::StringLiteral kSocketUid[] = {"get_socket_uid"};
constexpr llvm::StringLiteral kSkbCgroupId[] = {"skb_cgroup_id"};
constexpr llvm::StringLiteral kSkbAncestorCgroupId[] = {"skb_ancestor_cgroup_id"};
constexpr llvm::StringLiteral kSockOpsCbFlagsSet[] = {"sock_ops_cb_flags_set"};
constexpr llvm::StringLiteral kXdpBuffLen[] = {"xdp_get_buff_len"};
constexpr llvm::StringLiteral kXdpLoad[] = {"xdp_load_bytes"};
constexpr llvm::StringLiteral kXdpStore[] = {"xdp_store_bytes"};
// fib_lookup reads ctx and its own params buffer; not in pktinval.
constexpr llvm::StringLiteral kFibLookup[] = {"fib_lookup"};
// tunnel key get / set read ctx and their own 44-byte buffer; not in pktinval.
constexpr llvm::StringLiteral kTunnelGet[] = {"skb_get_tunnel_key"};
constexpr llvm::StringLiteral kTunnelSet[] = {"skb_set_tunnel_key"};
// setsockopt / getsockopt read ctx and their own 4-byte slot; not in pktinval.
constexpr llvm::StringLiteral kSetsockopt[] = {"setsockopt"};
constexpr llvm::StringLiteral kGetsockopt[] = {"getsockopt"};
// sk_lookup_tcp / _udp read ctx and the tuple; not in pktinval.
constexpr llvm::StringLiteral kSkLookupTcp[] = {"sk_lookup_tcp"};
constexpr llvm::StringLiteral kSkLookupUdp[] = {"sk_lookup_udp"};
constexpr llvm::StringLiteral kSkcLookupTcp[] = {"skc_lookup_tcp"};
constexpr llvm::StringLiteral kGetFuncRet[] = {"get_func_ret"}; // fexit — not packet-neutral (default), not pktinval
constexpr llvm::StringLiteral kFuncIp[] = {"get_func_ip"};
constexpr llvm::StringLiteral kFuncArg[] = {"get_func_arg"};
constexpr llvm::StringLiteral kFuncArgCnt[] = {"get_func_arg_cnt"};
constexpr llvm::StringLiteral kCgroupRetval[] = {"get_retval"};
constexpr llvm::StringLiteral kCgroupSetRetval[] = {"set_retval"};
constexpr llvm::StringLiteral kNsPidTgid[] = {"get_ns_current_pid_tgid"};
constexpr llvm::StringLiteral kSendSignal[] = {"send_signal"};
constexpr llvm::StringLiteral kSendSignalThread[] = {"send_signal_thread"};
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
constexpr llvm::StringLiteral kAllHelpers[] = {
    "map_lookup_elem", "map_update_elem", "map_delete_elem", "ktime_get_ns",
    "ringbuf_reserve", "ringbuf_submit",  "ringbuf_discard", "trace_printk"};
} // namespace

std::optional<PacketNeutralClass> mlir::ebpf::packetNeutralClass(Operation *op) {
  if (op->getDialect() && op->getDialect()->getNamespace() == "arith")
    return PacketNeutralClass{{}, false};
  using R = std::optional<PacketNeutralClass>;
  return llvm::TypeSwitch<Operation *, R>(op)
      .Case<MapLookupOp, MapAtomicAddOp>([](auto) {
        return PacketNeutralClass{kLookup, false};
      }) // Expansion turns atomic_add into lookup -> ref.atomic_add.
      .Case<MapUpdateOp, MapTryUpdateOp>(
          [](auto) { return PacketNeutralClass{kUpdate, false}; })
      .Case<MapDeleteOp, MapTryDeleteOp>(
          [](auto) { return PacketNeutralClass{kDelete, false}; })
      .Case<TracePrintkOp>(
          [](auto) { return PacketNeutralClass{kTrace, false}; })
      .Case<KtimeOp>([](auto) { return PacketNeutralClass{kKtime, false}; })
      .Case<RingbufReserveOp>(
          [](auto) { return PacketNeutralClass{kReserve, false}; })
      .Case<RingbufSubmitOp>(
          [](auto) { return PacketNeutralClass{kSubmit, false}; })
      .Case<RingbufDiscardOp>(
          [](auto) { return PacketNeutralClass{kDiscard, false}; })
      // Helper-free operations: record construction, borrowed map-value access
      // (normal/once), reservation writes, packet reads and structural
      // operations.
      .Case<RecordMakeOp, RefCheckOp, RefLoadOp, RefStoreOp, RefFieldLoadOp,
            RefFieldStoreOp, RefFieldAtomicAddOp, RefFieldCmpxchgOp, RefFieldAtomicOrOp, RefAtomicAddOp, YieldOp, IfOp,
            IfYieldOp, RingbufIfReservedOp, RingbufStoreFieldOp,
            RingbufStoreRecordOp, PacketLoadOp, PacketWindowLoadOp>(
          [](auto) { return PacketNeutralClass{{}, false}; })
      // Stores preserve pointer validity but write packets, bounding C1/W1
      // motion.
      .Case<PacketStoreOp>([](auto) { return PacketNeutralClass{{}, true}; })
      // Expanded CFG control flow lets W1 examine paths. No helpers or packet
      // writes; C1 runs before expansion and is unaffected.
      .Case<cf::BranchOp, cf::CondBranchOp>(
          [](auto) { return PacketNeutralClass{{}, false}; })
      // Expanded null-check structure: is_present compares pointer with null;
      // assume_present only replaces values and emits no instruction. Like
      // source ref.check/if_reserved, neither calls helpers/kfuncs nor writes
      // packets. VerifyStructured separately owns placement/non-null proof.
      // Do not add pkt.check_br: no input path needs that new-window
      // terminator.
      .Case<IsPresentOp, AssumePresentOp>(
          [](auto) { return PacketNeutralClass{{}, false}; })
      .Default([](Operation *) { return R(); });
}

std::optional<llvm::ArrayRef<llvm::StringLiteral>> mlir::ebpf::packetEffectHelpers(Operation *op) {
  if (std::optional<PacketNeutralClass> c = packetNeutralClass(op))
    return c->helpers;
  using R = std::optional<llvm::ArrayRef<llvm::StringLiteral>>;
  return llvm::TypeSwitch<Operation *, R>(op)
      .Case<SkbLoadBytesOp>(
          [](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSkbLoad); })
      .Case<SkbLoadBytesRelativeOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSkbRelative); })
      .Case<SkbVlanPushOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kVlanPush); })
      .Case<SkbVlanPopOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kVlanPop); })
      .Case<SkbCheckMtuOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kCheckMtu); })
      .Case<SkbCsumLevelOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kCsumLevel); })
      .Case<SkbSetHashOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSetHash); })
      .Case<SkbSetHashInvalidOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSetHashInvalid); })
      .Case<SkbEcnSetCeOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kEcnSetCe); })
      .Case<SkbAdjustRoomOp>(
          [](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSkbAdjust); })
      .Case<UserReadOp>(
          [](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kUserRead); })
      .Case<XdpAdjustHeadOp>(
          [](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kAdjustHead); })
      .Case<XdpAdjustMetaOp>(
          [](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kAdjustMeta); })
      .Case<XdpAdjustTailOp>(
          [](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kAdjustTail); })
      .Case<CloneRedirectOp>([](auto) {
        return llvm::ArrayRef<llvm::StringLiteral>(kCloneRedirect);
      })
      .Case<SkbStoreBytesOp>(
          [](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSkbStore); })
      .Case<L3CsumReplaceOp>(
          [](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kL3Csum); })
      .Case<L4CsumReplaceOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kL4Csum); })
      .Case<SkbPullDataOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSkbPull); })
      .Case<SkbChangeTailOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSkbChangeTail); })
      .Case<SkbChangeHeadOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSkbChangeHead); })
      .Case<SkbChangeProtoOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSkbChangeProto); })
      .Case<SkbChangeTypeOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSkbChangeType); })
      .Case<CsumUpdateOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kCsumUpdate); })
      .Case<CsumDiffOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kCsumDiff); })
      .Case<SkbHashRecalcOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kHashRecalc); })
      .Case<SkbCgroupClassidOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kCgroupClassid); })
      .Case<SkbNetnsCookieOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kNetnsCookie); })
      .Case<SkbSocketUidOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSocketUid); })
      .Case<SkbCgroupIdOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSkbCgroupId); })
      .Case<SkbAncestorCgroupIdOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSkbAncestorCgroupId); })
      .Case<SockOpsCbFlagsSetOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSockOpsCbFlagsSet); })
      .Case<XdpBuffLenOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kXdpBuffLen); })
      .Case<XdpLoadBytesOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kXdpLoad); })
      .Case<XdpStoreBytesOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kXdpStore); })
      .Case<FibLookupOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kFibLookup); })
      .Case<SkbGetTunnelKeyOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kTunnelGet); })
      .Case<SkbSetTunnelKeyOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kTunnelSet); })
      .Case<SockOpsSetsockoptOp, SockOpsSetsockoptNameOp, SockAddrSetsockoptOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSetsockopt); })
      .Case<SockOpsGetsockoptOp, SockAddrGetsockoptOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kGetsockopt); })
      .Case<SockLookupTcpOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSkLookupTcp); })
      .Case<SockLookupUdpOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSkLookupUdp); })
      .Case<SockSkcLookupTcpOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSkcLookupTcp); })
      .Case<CtxFuncRetOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kGetFuncRet); })
      .Case<CtxFuncIpOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kFuncIp); })
      .Case<CtxFuncArgOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kFuncArg); })
      .Case<CtxFuncArgCntOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kFuncArgCnt); })
      .Case<CgroupRetvalOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kCgroupRetval); })
      .Case<CgroupSetRetvalOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kCgroupSetRetval); })
      .Case<TaskNsPidTgidOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kNsPidTgid); })
      .Case<TaskSendSignalOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSendSignal); })
      .Case<TaskSendSignalThreadOp>([](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSendSignalThread); })
      // tail_call expands to tail_call.try plus fallback; both invoke
      // tail_call,
      // whose failed path invalidates packet pointers too.
      .Case<TailCallOp, TailCallTryOp>(
          [](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kTailCall); })
      // seg6 helpers invalidate packet pointers on success and failure.
      .Case<LwtSeg6StoreBytesOp>(
          [](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSeg6Store); })
      .Case<LwtSeg6AdjustSrhOp>(
          [](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSeg6Adjust); })
      .Case<LwtSeg6ActionOp>(
          [](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSeg6Action); })
      .Case<SysctlSetNewValueOp>(
          [](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSysctlSet); })
      .Case<SkReuseportCookieOp>(
          [](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kSockCookie); })
      .Case<MsgApplyBytesOp>(
          [](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kMsgApply); })
      .Case<MsgCorkBytesOp>(
          [](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kMsgCork); })
      .Case<MsgPullDataOp>(
          [](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kMsgPull); })
      .Case<MsgPopDataOp>(
          [](auto) { return llvm::ArrayRef<llvm::StringLiteral>(kMsgPop); })
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
