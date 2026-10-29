//===- VerifyStructured.cpp - expanded CFG exit checks ----------------------===//
//
// After region expansion, independently preserve source structural guarantees:
// assume_present must sit exclusively below its value's is_present true edge.
// Nullable values flow only through permitted checks/assumptions. Reservations
// need one check and one checked SSA copy; aliases could otherwise hide a
// submit/discard double-consumption from per-value tracking.
// Checked values have restricted users, not branch operands/block arguments.
// MLIR SSA verification already enforces dominance of their uses. Every taken
// reservation must submit/discard once on all paths after assume_present.
// Finally, the combined program/func/callback graph must be acyclic and within
// kMaxFrames, counting callbacks and entry. Source call-graph checks cannot see
// outlined callback edges, so this check follows outlining.
// These structural checks yield Verified/Rejected, not kernel-dependent or
// approximate Conditional/Unknown results.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h"
#include "bpf-mlir/Dialect/EBPF/Transforms/CheckedEdge.h"
#include "bpf-mlir/Dialect/EBPF/Transforms/PacketNeutral.h"
#include "bpf-mlir/Dialect/EBPF/Transforms/WindowPath.h"

#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"
#include "bpf-mlir/Support/CheckResult.h"

#include "mlir/Dialect/ControlFlow/IR/ControlFlowOps.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringMap.h"

#include <functional>

namespace mlir {
namespace ebpf {
#define GEN_PASS_DEF_EBPFVERIFYSTRUCTURED
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h.inc"
} // namespace ebpf
} // namespace mlir

using namespace mlir;
using namespace mlir::ebpf;
using bpfmlir::CheckTally;
using bpfmlir::CheckVerdict;

namespace {

bool isMaybe(Type t) { return isa<MaybeRefType, MaybeReservationType, SockRefOrNullType>(t); }
bool isChecked(Type t) { return isa<BorrowedType, ReservationType, ElemType, SockRefType>(t); }

// elem.at must sit solely below the true edge of matching ref/field/index
// elem.in_range. Its result is restricted to elem.load/store. For multiple
// dimensions, walk backward from the last dimension through each checked edge.
// CheckedEdge shares these placement rules with fact diagnostics.
CheckVerdict checkElemAt(ElemAtOp at) {
  if (!elemAtPlacementHolds(at)) {
    at.emitOpError() << "must be in a block entered only through the true edge of a cf.cond_br on "
                        "ebpf.elem.in_range of the same reference, field and index"
                     << (at.getIndices().size() > 1 ? " (for every dimension, in order)" : "");
    return CheckVerdict::Rejected;
  }
  for (Operation *user : at.getResult().getUsers())
    if (!isa<ElemLoadOp, ElemStoreOp>(user)) {
      at.emitOpError() << "a checked element may only be used by ebpf.elem.load / ebpf.elem.store, but it is used by '"
                       << user->getName() << "'";
      return CheckVerdict::Rejected;
    }
  return CheckVerdict::Verified;
}

// assume_present placement uses the shared CheckedEdge rules.
CheckVerdict checkAssumePlacement(AssumePresentOp a) {
  if (!assumePresentPlacementHolds(a)) {
    auto d = a.emitOpError()
             << "must be in a block entered only through the true edge of a "
                "cf.cond_br on ebpf.is_present of the same value";
    d.attachNote() << "otherwise a possibly-null reference or reservation "
                      "reaches a path where it was never checked";
    return CheckVerdict::Rejected;
  }
  return CheckVerdict::Verified;
}

// Nullable-value use restrictions.
CheckVerdict checkMaybe(Value v) {
  unsigned tests = 0, assumes = 0;
  for (Operation *user : v.getUsers()) {
    if (isa<IsPresentOp>(user)) {
      ++tests;
      continue;
    }
    if (isa<AssumePresentOp>(user)) {
      ++assumes;
      continue;
    }
    // Nullable map references may enter untagged nullable subprogram arguments;
  // the callee must check them.
    if (isa<MaybeRefType>(v.getType()) && isa<CallOp>(user))
      continue;
    v.getDefiningOp()->emitOpError()
        << "an unchecked " << v.getType()
        << " may only be used by ebpf.is_present / ebpf.assume_present"
        << (isa<MaybeRefType>(v.getType()) ? " (or passed to ebpf.call)" : "")
        << " at the structural stage, but it is used by '"
        << user->getName() << "'";
    return CheckVerdict::Rejected;
  }
  // Each test's true edge needs exactly one checked copy. Aggregate counts
  // miss two aliases on one arm and a leak on another.
  if (isa<SockRefOrNullType>(v.getType())) {
    for (Operation *user : v.getUsers()) {
      auto test = dyn_cast<IsPresentOp>(user);
      if (!test)
        continue;
      if (!test.getResult().hasOneUse()) {
        test.emitOpError() << "a socket test must guard exactly one cf.cond_br";
        return CheckVerdict::Rejected;
      }
      auto branch = dyn_cast<cf::CondBranchOp>(*test.getResult().getUsers().begin());
      if (!branch || branch.getCondition() != test.getResult()) {
        test.emitOpError() << "a socket test must be the condition of cf.cond_br";
        return CheckVerdict::Rejected;
      }
      unsigned copies = 0;
      for (Operation &op : *branch.getTrueDest())
        if (auto assume = dyn_cast<AssumePresentOp>(op))
          if (assume.getValue() == v)
            ++copies;
      if (copies != 1) {
        test.emitOpError() << "a socket test needs exactly one assume_present in its true-edge block";
        return CheckVerdict::Rejected;
      }
    }
  }
  if (isa<SockRefOrNullType>(v.getType()) && (tests == 0 || tests != assumes)) {
    v.getDefiningOp()->emitOpError() << "a socket reference must have one assume_present for each is_present";
    return CheckVerdict::Rejected;
  }

  if (isa<MaybeReservationType>(v.getType()) && tests != 1) {
    v.getDefiningOp()->emitOpError()
        << "a ring buffer reservation must be tested exactly once by "
           "ebpf.is_present, found "
        << tests;
    return CheckVerdict::Rejected;
  }
  if (isa<MaybeReservationType>(v.getType()) && assumes != 1) {
    auto d = v.getDefiningOp()->emitOpError()
             << "a ring buffer reservation must be taken out exactly once by "
                "ebpf.assume_present, found "
             << assumes;
    if (assumes == 0)
      d.attachNote() << "a reservation that is never taken out on the success "
                        "path is never consumed and leaks ring buffer space";
    else
      d.attachNote() << "two checked copies of one reservation let it be "
                        "consumed once per copy (e.g. submit one, discard "
                        "the other)";
    return CheckVerdict::Rejected;
  }
  return CheckVerdict::Verified;
}

// Checked-value use restrictions; SSA already guarantees dominance.
CheckVerdict checkCheckedUses(AssumePresentOp a) {
  Value v = a.getResult();
  bool isRes = isa<ReservationType>(v.getType());
  if (isa<SockRefType>(v.getType())) {
    for (Operation *user : v.getUsers())
      if (!isa<SockReleaseOp, SkAssignOp>(user)) { // sk.assign is non-consuming.
        a.emitOpError() << "a checked socket reference may only be used by ebpf.sock.release or ebpf.sk.assign";
        return CheckVerdict::Rejected;
      }
    return CheckVerdict::Verified;
  }

  // Present kernel pointers may be used only by supported kernel-pointer operations.
  if (isa<KPtrType>(v.getType())) {
    for (Operation *user : v.getUsers())
      if (!isa<KFieldLoadOp, KFieldPtrOp, KFieldCopyOp, KPtrAddrOp, KernelReadStrOp, SeqWriteOp, KFieldStoreOp, StorageGetOp, StorageDeleteOp>(
              user)) { // Includes field traversal/copy/string reads, seq_file writes, field stores and storage owners.
        a.emitOpError() << "a checked " << v.getType()
                        << " may only be used by ebpf.kfield.load / ebpf.kfield.ptr / ebpf.kfield.copy / ebpf.kernel.read_str / ebpf.kfield.store / "
                           "ebpf.seq.write / ebpf.storage.get / ebpf.storage.delete, but it is used by '"
                        << user->getName() << "'";
        return CheckVerdict::Rejected;
      }
    return CheckVerdict::Verified;
  }
  // Present krefs permit kfunc arguments and field reads; source ownership
    // verification separately owns consumption counts.
  if (isa<KRefType>(v.getType())) {
    for (Operation *user : v.getUsers())
      if (!isa<KfuncCallOp, KFieldLoadOp, KPtrAddrOp, KPtrXchgOp>(user)) { // addr is a non-consuming borrow.
        a.emitOpError() << "a checked " << v.getType() << " may only be used by ebpf.kfunc.call / ebpf.kfield.load, but it is used by '"
                        << user->getName() << "'";
        return CheckVerdict::Rejected;
      }
    return CheckVerdict::Verified;
  }
  for (Operation *user : v.getUsers()) {
    // Checked references may enter calls; callees cannot return pointers, so no escape.
    bool allowed =
        isRes ? isa<RingbufStoreFieldOp, RingbufStoreRecordOp, TaskCommOp, UserReadStrOp, UserReadOp, KFieldCopyOp, TpFieldCopyOp, KernelReadStrOp, RingbufSubmitOp,
                    RingbufDiscardOp>(user) // kfield.copy and kernel.read_str destinations.
              : isa<RefLoadOp, RefStoreOp, RefAtomicAddOp, RefFieldLoadOp, RefFieldStoreOp, RefFieldAtomicAddOp, CallOp,
                    ElemInRangeOp, ElemAtOp, ElemMaskOp, SpinLockOp, SpinUnlockOp, // Expanded lock/unlock and elem.mask.
                    TimerInitOp, TimerSetCallbackOp, TimerStartOp, // Timer helpers receive a timer within the value.
                    KFieldCopyOp, TpFieldCopyOp, MapInnerOp, KPtrXchgOp>(user); // Destination records, inner-map handles and kptr fields.
    if (!allowed) {
      a.emitOpError() << "a checked " << v.getType() << " may only be used by "
                      << (isRes ? "ebpf.ringbuf.{store_field,store_record,submit,discard}, ebpf.task.comm, ebpf.user.read_str, ebpf.kfield.copy or "
                                  "ebpf.kernel.read_str"
                                : "ebpf.ref.{load,store,atomic_add} or ebpf.call")
                      << ", but it is used by '" << user->getName()
                      << "' (forwarding it lets it escape the checked path"
                      << (isRes ? ")" : "; ebpf.ref.field.{load,store} are allowed for records)");
      return CheckVerdict::Rejected;
    }
  }
  return CheckVerdict::Verified;
}

// Walk every CFG path immediately after assume_present for reservation linearity.
CheckVerdict checkLinear(Operation *origin, Value res, bool socketTest = false) {
  bool socket = isa<SockRefType, SockRefOrNullType>(res.getType());
  StringRef noun = socket ? "a socket reference" : "a ring buffer reservation";
  auto consumes = [&](Operation &op) {
    return (socketTest ? isa<IsPresentOp>(op) : socket ? isa<SockReleaseOp>(op)
                                                               : isa<RingbufSubmitOp, RingbufDiscardOp>(op)) &&
           op.getOperand(0) == res;
  };

  // Does this operation or any nested operation take the reservation as an operand?
  auto usesRes = [&](Operation &op) {
    bool found = false;
    op.walk([&](Operation *o) {
      if (llvm::is_contained(o->getOperands(), res)) {
        found = true;
        return WalkResult::interrupt();
      }
      return WalkResult::advance();
    });
    return found;
  };

  // Walk one block. Double consumption and non-consuming use after consumption
  // return false with the offending operation in twice, independently checking
  // source ownership's store/task.comm/user.read_str restrictions.
  auto walk = [&](Block::iterator from, Block::iterator to, bool &consumed,
                  Operation *&twice) {
    for (auto it = from; it != to; ++it) {
      if (consumes(*it)) {
        if (consumed) {
          twice = &*it;
          return false;
        }
        consumed = true;
      } else if (!socketTest && consumed && usesRes(*it)) {
        twice = &*it;
        return false;
      }
    }
    return true;
  };
  auto reportWalk = [&](Operation *op) {
    if (consumes(*op))
      op->emitOpError()
          << noun << (socketTest ? " is checked twice on this path" : " is consumed twice on this path");
    else
      op->emitOpError() << noun << " is used by '"
                        << op->getName()
                        << "' after it was consumed on this path";
  };

  Block *home = origin->getBlock();
  bool consumed = false;
  Operation *twice = nullptr;
  if (!walk(std::next(origin->getIterator()), home->end(), consumed, twice)) {
    reportWalk(twice);
    return CheckVerdict::Rejected;
  }

  llvm::DenseMap<Block *, bool> inState;
  SmallVector<Block *> worklist;
  bool consumedExit = false, reservedExit = false;
  auto visitSuccessors = [&](Block *b, bool st) {
    Operation *t = b->getTerminator();
    if (t->getNumSuccessors() == 0) {
      (st ? consumedExit : reservedExit) = true;
      return true;
    }
    for (Block *succ : t->getSuccessors()) {
      auto it = inState.find(succ);
      if (it == inState.end()) {
        inState[succ] = st;
        worklist.push_back(succ);
      } else if (it->second != st) {
        return false;
      }
    }
    return true;
  };

  if (!visitSuccessors(home, consumed)) {
    origin->emitOpError() << noun << " is consumed on some paths "
                       "but not others (the states disagree where control "
                       "flow merges)";
    return CheckVerdict::Rejected;
  }
  llvm::DenseSet<Block *> visited;
  while (!worklist.empty()) {
    Block *b = worklist.pop_back_val();
    if (!visited.insert(b).second)
      continue;
    bool st = inState[b];
    if (!walk(b->begin(), b->end(), st, twice)) {
      reportWalk(twice);
      return CheckVerdict::Rejected;
    }
    if (!visitSuccessors(b, st)) {
      origin->emitOpError() << noun << " is consumed on some "
                         "paths but not others (the states disagree where "
                         "control flow merges)";
      return CheckVerdict::Rejected;
    }
  }
  if (reservedExit) {
    origin->emitOpError() << noun << (consumedExit ? " is consumed on some paths but not others"
                                                    : " is not consumed on this path");
    return CheckVerdict::Rejected;
  }
  return CheckVerdict::Verified;
}

// Reject window uses when any executable path from pkt.check_br in_range
// contains a PacketNeutral invalidator: include conditional arms, joins and
// loops, not just dominators. Helpers invalidate on success and failure. Uses
// before them and freshly checked windows after them remain valid.
CheckVerdict checkPacketInvalidation(Operation *prog) {
  SmallVector<Operation *> invalidators;
  prog->walk([&](Operation *op) {
    if (opInvalidatesPacketPointers(op)) // Shared PacketNeutral invalidation predicate.
      invalidators.push_back(op);
  });
  if (invalidators.empty())
    return CheckVerdict::Verified;
  // WindowPath MayExecute plus operations before use. Preserve walk order so
  // multiple invalidators keep the same diagnostic-note operation.
  CheckVerdict v = CheckVerdict::Verified;
  prog->walk([&](PktCheckBrOp pk) {
    Block *in = pk.getInRange();
    Value w = in->getArgument(0);
    for (Operation *use : w.getUsers()) {
      if (!isa<PacketStoreOp, PacketWindowLoadOp, CallOp>(use)) // Passing a window to a call is also a use, including stale-window transfer.
        continue;
      WindowPath path(in, use, WindowPathKind::MayExecute, UseBlockOps::BeforeUse);
      for (Operation *h : invalidators) {
        if (path.contains(h)) {
          InFlightDiagnostic d = use->emitOpError()
                                 << "uses a packet window that '" << h->getName()
                                 << "' may have invalidated (a path from the ebpf.packet.check to this use passes through it; "
                                    "the helper invalidates packet pointers whether it succeeds or fails — check the packet again after it)";
          d.attachNote(h->getLoc()) << "the packet pointers are invalidated here";
          v = CheckVerdict::Rejected;
          break;
        }
      }
    }
  });
  return v;
}

struct EBPFVerifyStructuredPass
    : public mlir::ebpf::impl::EBPFVerifyStructuredBase<
          EBPFVerifyStructuredPass> {
  using EBPFVerifyStructuredBase::EBPFVerifyStructuredBase;

  void runOnOperation() override {
    ModuleOp module = getOperation();
    CheckTally tally;

    // Verify subprogram bodies like program bodies.
    module.walk([&](Operation *prog) {
      // Include bpf_loop callback bodies.
      if (!isa<ProgramOp, SubprogramOp, LoopCallbackOp>(prog))
        return;
      prog->walk([&](Operation *op) {
        // Remaining source-stage operations indicate wrong-stage input.
        if (isa<SockRefCheckOp, RefCheckOp, RingbufIfReservedOp, MapAtomicAddOp, YieldOp, LoopOp, LoopYieldOp, IfOp,
              IfYieldOp, BreakOp, ContinueOp, RefIndexOp, PacketCheckOp, VerdictIfOp, TailCallOp, SpinRegionOp, MapForEachOp,
              MapForEachYieldOp>(op)) { // map.for_each
          op->emitOpError() << "is a stage ① op; run ebpf-expand-regions "
                               "before ebpf-verify-structured";
          tally.add(CheckVerdict::Rejected);
          return;
        }
        for (Value r : op->getResults())
          if (isMaybe(r.getType())) {
            tally.add(checkMaybe(r));
            if (isa<SockRefOrNullType>(r.getType()))
              tally.add(checkLinear(op, r, true));
          }
        if (auto at = dyn_cast<ElemAtOp>(op))
          tally.add(checkElemAt(at));
        if (auto a = dyn_cast<AssumePresentOp>(op)) {
          tally.add(checkAssumePlacement(a));
          tally.add(checkCheckedUses(a));
          if (isa<ReservationType, SockRefType>(a.getResult().getType()))
            tally.add(checkLinear(a, a.getResult()));
        }
      });

      tally.add(checkPacketInvalidation(prog));

      // Checked values cannot circulate through block arguments outside proof
      // dominance. Subprogram entry borrows are different: callers checked them.
      for (Block &blk : prog->getRegion(0))
        for (BlockArgument arg : blk.getArguments())
          if (isChecked(arg.getType()) &&
              !((isa<SubprogramOp>(prog) || (isa<LoopCallbackOp>(prog) && cast<LoopCallbackOp>(prog).getForEach())) && blk.isEntryBlock())) { // for_each callback value.
            prog->emitOpError() << "a checked " << arg.getType()
                               << " must not be carried across blocks as a "
                                  "block argument";
            tally.add(CheckVerdict::Rejected);
          }
    });

    // Combine calls and callback edges under the conservative compiler frame
    // bound. Kernel counting differs (7.1.8 resets frames at global subprograms).
    {
      constexpr unsigned kMaxFrames = 8;
      llvm::StringMap<Operation *> nodes;
      for (Operation &op : module.getBody()->getOperations())
        if (auto sym = op.getAttrOfType<StringAttr>(SymbolTable::getSymbolAttrName()))
          if (isa<SubprogramOp, LoopCallbackOp>(op))
            nodes[sym.getValue()] = &op;
      auto succs = [&](Operation *owner) {
        SmallVector<std::pair<Operation *, Operation *>> out; // (site, callee)
        owner->walk([&](Operation *op) {
          StringRef callee;
          if (auto c = dyn_cast<CallOp>(op))
            callee = c.getCallee();
          else if (FlatSymbolRefAttr cb = callbackOf(op)) // Both bpf_loop and for_each_map_elem callbacks.
            callee = cb.getValue();
          else
            return;
          if (Operation *n = nodes.lookup(callee))
            out.push_back({op, n});
        });
        return out;
      };
      llvm::DenseMap<Operation *, unsigned> onPath, best;
      bool stop = false;
      std::function<void(Operation *, unsigned, SmallVector<std::string> &)> visit =
          [&](Operation *owner, unsigned frames, SmallVector<std::string> &path) {
            for (auto [site, callee] : succs(owner)) {
              if (stop)
                return;
              std::string name =
                  "@" + callee->getAttrOfType<StringAttr>(SymbolTable::getSymbolAttrName()).getValue().str();
              path.push_back(name + (isa<BpfLoopOp>(site) ? " (bpf_loop callback)" : isa<ForEachMapElemOp>(site) ? " (for_each_map_elem callback)" : ""));
              if (onPath.count(callee)) {
                site->emitOpError() << "makes the call / callback graph recursive ("
                                    << llvm::join(path, " -> ") << ")";
                tally.add(CheckVerdict::Rejected);
                stop = true;
              } else if (frames + 1 > kMaxFrames) {
                site->emitOpError() << "reaches a call depth of " << frames + 1
                                    << " frames (entry included; a bpf_loop callback counts as a frame) along "
                                    << llvm::join(path, " -> ")
                                    << "; this compiler supports at most " << kMaxFrames
                                    << " (a conservative limit of its own; the kernel verifier has the final say)";
                tally.add(CheckVerdict::Rejected);
                stop = true;
              } else if (best.lookup(callee) < frames + 1) {
                best[callee] = frames + 1;
                onPath[callee] = 1;
                visit(callee, frames + 1, path);
                onPath.erase(callee);
              }
              path.pop_back();
            }
          };
      for (auto prog : module.getOps<ProgramOp>()) {
        SmallVector<std::string> path{"@" + prog.getSymName().str()};
        visit(prog, 1, path);
      }
    }

    if (report)
      module.emitRemark() << "ebpf-verify-structured: " << tally.str();
    if (tally.rejected)
      signalPassFailure();
  }
};

} // namespace
