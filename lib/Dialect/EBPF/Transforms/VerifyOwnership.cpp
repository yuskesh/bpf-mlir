//===- VerifyOwnership.cpp - path-sensitive linear ownership ---------------===//
//
// Every path after a reservation must submit or discard exactly once. Counting
// uses alone would accept submission on only one branch. Nested regions must
// either all consume or all preserve the value; mixed consumption fails.
// Acquired kfunc references obey the same analysis: nullable results are checked
// exactly once, and present references are released exactly once. Consumption
// predicates and diagnostic vocabulary vary by resource kind. Reservation and
// dynptr texts are kept byte-stable.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h"

#include "bpf-mlir/Dialect/BPFABI/KernelABI.h"
#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"

#include <functional>
#include <string>

namespace mlir {
namespace ebpf {
#define GEN_PASS_DEF_EBPFVERIFYOWNERSHIP
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h.inc"
} // namespace ebpf
} // namespace mlir

using namespace mlir;
using namespace mlir::ebpf;

namespace {

// How an operation consumes v.
// Escapes: every region of the op leaves by break / continue — the rest of the block never runs.
enum class Consumes { No, All, Some, Escapes };

// Exit state when walking a region from Reserved. Escaped: every exit is a
// break / continue, so no path reaches the enclosing operation's join.
enum class Exit { Reserved, Consumed, Mixed, Escaped };

// break / continue leave the iteration the value lives in (a live value
// never crosses a loop — analyzeLinear; a reference may cross an
// ebpf.iter.num, whose own break / continue consumeKind does not count), so it
// must be consumed before them and those exits do not reach the join of the
// enclosing operation.
bool isIterationEscape(Operation *t) { return isa<BreakOp, ContinueOp>(t); }

// Diagnostic vocabulary per linear resource kind.
struct Words {
  std::string noun;       // "a ring buffer reservation"
  std::string consumed;   // Verb used with twice or on some paths.
  std::string afterWhat;  // Phrase following use after.
  std::string tailNoun;   // Tail-call diagnostic resource noun.
  std::string tailWhat;   // Tail-call diagnostic description of a still-live resource.
  std::string taken;      // remark "the reservation is taken here"
};

Words reservationWords() {
  return {"a ring buffer reservation", "consumed", "submitted or discarded", "a ring buffer dynptr",
          "not yet submitted or discarded", "the reservation is taken here"};
}

struct Analysis {
  Value v;
  // Check consumption by this operation only; consumeKind walks nested regions.
  std::function<bool(Operation *)> consumes;
  Words w;
  InFlightDiagnostic *diag = nullptr;
  bool failed = false;
};

// before: whether v was already consumed when control entered the region
// (break / continue check the absolute state).
Exit analyzeRegion(Region &region, Analysis &a, bool before);

// Reject non-consuming uses after submit/discard too, including stores,
// task.comm and user.read_str. Consumption counts alone miss use-after-consume.
bool usesValue(Operation *op, Value v) {
  bool used = false;
  op->walk([&](Operation *o) {
    for (Value x : o->getOperands())
      if (x == v)
        used = true;
  });
  return used;
}

void emitUseAfterConsume(Operation *op, const Words &w) {
  op->emitOpError() << "uses " << w.noun << " after it was " << w.afterWhat << " on this path";
}

Consumes consumeKind(Operation *op, Analysis &a, bool before) {
  if (a.consumes(op))
    return Consumes::All;
  if (op->getNumRegions() == 0)
    return Consumes::No;
  // a reference that is not a reservation may cross ebpf.iter.num
  // (crossedByLive). The body cannot capture it, and a break / continue in
  // the body leaves or continues that iterator — not the iteration the value
  // lives in — so the iterator neither consumes the value nor escapes.
  if (isa<IterNumOp>(op) && !usesValue(op, a.v))
    return Consumes::No;

  // Nested regions: All if every region consumes; Some for mixed consumption.
  bool any = false, all = true, seen = false, escaped = false;
  for (Region &r : op->getRegions()) {
    if (r.empty())
      continue;
    Exit e = analyzeRegion(r, a, before);
    if (e == Exit::Escaped) {
      escaped = true; // No path through this region reaches the join.
      continue;
    }
    seen = true;
    if (e == Exit::Mixed) {
      a.failed = true;
      op->emitOpError() << a.w.noun << " is " << a.w.consumed << " on some paths but not others inside this operation";
      return Consumes::Some;
    }
    (e == Exit::Consumed ? any : all) = (e == Exit::Consumed);
    if (e == Exit::Consumed)
      any = true;
    else
      all = false;
  }
  if (!seen)
    return escaped ? Consumes::Escapes : Consumes::No; // every region escapes — nothing after the op runs.
  if (all && any)
    return Consumes::All;
  if (any) {
    // Partial regional consumption is path-dependent; report it explicitly here.
    a.failed = true;
    op->emitOpError() << a.w.noun << " is " << a.w.consumed << " in only some of this operation's regions, so whether it is "
                      << a.w.consumed << " depends on the path taken at run time";
    return Consumes::Some;
  }
  return Consumes::No;
}

// Walk the block CFG from Reserved and collect every exit state.
Exit analyzeRegion(Region &region, Analysis &a, bool before) {
  if (region.empty())
    return Exit::Reserved;

  DenseMap<Block *, bool> inState; // true means Consumed on arrival.
  SmallVector<Block *> worklist;
  inState[&region.front()] = false;
  worklist.push_back(&region.front());

  bool sawConsumedExit = false, sawReservedExit = false, sawJoinExit = false;
  DenseSet<Block *> visited;

  while (!worklist.empty()) {
    Block *b = worklist.pop_back_val();
    bool consumed = inState[b];
    if (!visited.insert(b).second && consumed == inState[b]) {
      // Stop revisiting identical states so loops converge.
    }

    bool escapedHere = false;
    for (Operation &op : *b) {
      if (consumed && usesValue(&op, a.v)) {
        a.failed = true;
        emitUseAfterConsume(&op, a.w);
        return Exit::Mixed;
      }
      Consumes c = consumeKind(&op, a, before || consumed);
      if (c == Consumes::Some) {
        a.failed = true;
        return Exit::Mixed;
      }
      if (c == Consumes::Escapes) {
        escapedHere = true;
        break;
      }
      if (c != Consumes::All)
        continue;
      if (consumed) {
        a.failed = true;
        op.emitOpError() << a.w.noun << " is " << a.w.consumed << " twice on this path";
        return Exit::Mixed;
      }
      consumed = true;
    }
    if (escapedHere)
      continue;

    Operation *term = b->getTerminator();
    if (isIterationEscape(term)) {
      if (!before && !consumed) {
        a.failed = true;
        term->emitOpError() << "leaves the iteration while " << a.w.noun << " is not " << a.w.consumed
                            << " (" << a.w.noun << " must be " << a.w.consumed << " before ebpf.break / ebpf.continue)";
        return Exit::Mixed;
      }
      continue; // Does not reach the enclosing operation's join.
    }
    if (term->getNumSuccessors() == 0) {
      sawJoinExit = true;
      (consumed ? sawConsumedExit : sawReservedExit) = true;
      continue;
    }
    for (Block *succ : term->getSuccessors()) {
      auto it = inState.find(succ);
      if (it == inState.end()) {
        inState[succ] = consumed;
        worklist.push_back(succ);
      } else if (it->second != consumed) {
        // Different join states mean only some incoming paths consumed the value.
        a.failed = true;
        succ->getParentOp()->emitOpError() << a.w.noun << " is " << a.w.consumed
                                           << " on some paths but not others (the states disagree where control flow merges)";
        return Exit::Mixed;
      }
    }
  }

  if (!sawJoinExit)
    return Exit::Escaped;
  if (sawConsumedExit && sawReservedExit)
    return Exit::Mixed;
  return sawConsumedExit ? Exit::Consumed : Exit::Reserved;
}

// The ops a live resource must not cross: loops and iterators — and, for
// a ring buffer reservation, the RCU section.
// a resource that is not a reservation (a kfunc
// kernel reference, a socket reference) may cross ebpf.iter.num, wherever the
// iterator stands (an ebpf.iter.scx_dsq body, a program / function / callback
// body) — the verifier's refsafe compares only the reference set at the
// iterator's next (7.3.1 states.c:868-919), and a reference held from before
// the iterator keeps its id. Premise: the iterator body cannot capture the
// reference (iterator captures are integers, context and map handles —
// EBPFDialect.cpp capturable()), so it is neither used nor released inside.
// If the capture rule grows, re-check this. A reservation still may not
// cross it; ebpf.loop and ebpf.iter.scx_dsq stay rejected for every resource.
bool crossedByLive(Operation *l, bool reservation) {
  return isa<LoopOp, IterScxDsqOp>(l) || (reservation && isa<IterNumOp, RcuRegionOp>(l));
}

// the ops a live resource must not reach through
// a call. A reservation (if_reserved and reserve_dynptr): all of crossedByLive
// (loops, iterators, the RCU section). A socket or kernel reference: only the
// iterators opened to function bodies — a callee holding ebpf.loop is not
// followed for references (outside) — and only
// ebpf.iter.scx_dsq (a callee's ebpf.iter.num runs like one at the call — the
// crossing crossedByLive accepts).
bool crossedByLiveThroughCall(Operation *l, bool reservation) {
  return reservation ? crossedByLive(l, reservation) : isa<IterScxDsqOp>(l);
}

// the first op crossedByLiveThroughCall reaches through
// fn's body and the functions it calls (any depth); path receives the callee
// chain (fn first). seen stops at a revisit (ebpf-verify-call-graph runs later
// and names a recursion).
Operation *reachedCrossedByLive(SubprogramOp fn, bool reservation, SmallVectorImpl<StringRef> &path,
                                DenseSet<Operation *> &seen) {
  if (!seen.insert(fn.getOperation()).second)
    return nullptr;
  path.push_back(fn.getSymName());
  Operation *found = nullptr;
  fn.walk<WalkOrder::PreOrder>([&](Operation *op) {
    if (crossedByLiveThroughCall(op, reservation)) {
      found = op;
      return WalkResult::interrupt();
    }
    if (auto call = dyn_cast<CallOp>(op))
      if (auto callee = SymbolTable::lookupNearestSymbolFrom<SubprogramOp>(call, call.getCalleeAttr()))
        if ((found = reachedCrossedByLive(callee, reservation, path, seen)))
          return WalkResult::interrupt();
    return WalkResult::advance();
  });
  if (!found)
    path.pop_back();
  return found;
}

// A release-flagged kfunc argument consumes v. kptr.xchg also consumes its new
// reference by transferring ownership to the map.
bool releasesKRef(Operation *op, Value v) {
  if (auto x = dyn_cast<GlobalKPtrXchgOp>(op)) // a kptr global takes it too.
    return x.getNewRef() == v;
  if (auto x = dyn_cast<KPtrXchgOp>(op))
    return x.getNewRef() == v;
  auto call = dyn_cast<KfuncCallOp>(op);
  if (!call)
    return false;
  const bpfabi::KfuncABI *k = bpfabi::lookupKfunc(call.getCallee());
  if (!k || !k->hasFlag("release"))
    return false;
  return llvm::is_contained(call.getArgs(), v);
}

struct EBPFVerifyOwnershipPass
    : public mlir::ebpf::impl::EBPFVerifyOwnershipBase<
          EBPFVerifyOwnershipPass> {
  void runOnOperation() override {
    ModuleOp module = getOperation();
    bool bad = false;

    // Taken reservations exist only as if_reserved present-region arguments,
    // so tracking is confined to that region. Apply equally inside program
    // and subprogram bodies.
    module.walk([&](Operation *prog) {
      // a timer callback body is a root too (a sched_ext_ops owner's
      // callback takes and releases references, iterates and enters RCU).
      if (!isa<ProgramOp, SubprogramOp, TimerCallbackOp>(prog))
        return;
      // anchor identifies the diagnostic operation; v is linear; home/first
      // start traversal. Dynptr traversal starts after reserve_dynptr and
      // continues to its enclosing region exit. consumes/w specialize the
      // consumption predicate and vocabulary.
      auto analyzeLinear = [&](Operation *anchor, Value v, Block *home, Operation *first,
                               std::function<bool(Operation *)> consumes, const Words &w) {
        Analysis a{v, consumes, w};
        bool consumed = false;
        for (Operation *op = first; op; op = op->getNextNode()) {
          // A live dynptr cannot cross a tail call: fallback consumption does not
          // cover successful calls, which never return. Ordinary reservation
          // regions cannot contain tail_call, so that case cannot reach here.
          if (!consumed && isa<TailCallOp>(op)) {
            bad = true;
            op->emitOpError() << "is reached while " << w.tailNoun << " is still live (" << w.tailWhat
                              << "); a tail call does not return, so the "
                              << (w.tailNoun == "a ring buffer dynptr" ? std::string("dynptr") : std::string("reference"))
                              << " would never be released";
            anchor->emitRemark() << w.taken;
            return;
          }
          // Live reservations cannot span ebpf.loop: this analysis does not model
          // loop ownership, even without an explicit capture. Loops after
          // consumption are allowed.
          if (!consumed) {
            bool reservation = w.noun == "a ring buffer reservation";
            Operation *loop = nullptr;
            // an iterator is a loop for ownership; an RCU section is
            // crossed by no live reservation (H5 (c)).
            op->walk([&](Operation *l) {
              if (crossedByLive(l, reservation)) {
                loop = l;
                return WalkResult::interrupt();
              }
              return WalkResult::advance();
            });
            if (loop) {
              bad = true;
              loop->emitOpError() << "is reached while " << w.noun << " is still live (" << w.tailWhat << "); a live "
                                  << (reservation ? std::string("reservation") : std::string("reference")) << " must not cross "
                                  << loop->getName() << " (the ownership check does not follow "
                                  << (isa<RcuRegionOp>(loop) ? "it — a reservation may not cross the RCU section" : "loops") << ")";
              anchor->emitRemark() << w.taken;
              return;
            }
            // nor through a call — a callee (any
            // depth) that holds such an op runs while the resource is live, as
            // if the op stood at the call. A callee without one is accepted.
            // Every resource is followed to iterators; only a reservation also
            // to loops and the RCU section (crossedByLiveThroughCall).
            {
              CallOp via;
              Operation *reached = nullptr;
              SmallVector<StringRef> path;
              op->walk<WalkOrder::PreOrder>([&](CallOp call) {
                auto callee = SymbolTable::lookupNearestSymbolFrom<SubprogramOp>(call, call.getCalleeAttr());
                if (!callee)
                  return WalkResult::advance(); // The call verifier names an unknown callee.
                DenseSet<Operation *> seen;
                path.clear();
                if ((reached = reachedCrossedByLive(callee, reservation, path, seen))) {
                  via = call;
                  return WalkResult::interrupt();
                }
                return WalkResult::advance();
              });
              if (reached) {
                bad = true;
                std::string route = "@?";
                if (auto s = prog->getAttrOfType<StringAttr>(SymbolTable::getSymbolAttrName()))
                  route = ("@" + s.getValue()).str();
                for (StringRef p : path)
                  route += (" -> @" + p).str();
                auto d = via.emitOpError() << "calls @" << via.getCallee() << " while " << w.noun << " is still live ("
                                           << w.tailWhat << "), and @" << path.back() << " holds '" << reached->getName()
                                           << "' (call path " << route << "); a live "
                                           << (reservation ? std::string("reservation") : std::string("reference"))
                                           << " must not cross "
                                           << reached->getName() << ", also through a call (the ownership check does not follow "
                                           << (isa<RcuRegionOp>(reached) ? "it — a reservation may not cross the RCU section"
                                                                         : "loops")
                                           << ")";
                d.attachNote(reached->getLoc()) << "the callee's '" << reached->getName() << "' is here";
                d.report();
                anchor->emitRemark() << w.taken;
                return;
              }
            }
          }
          if (consumed && usesValue(op, v)) {
            bad = true;
            emitUseAfterConsume(op, w);
            return;
          }
          Consumes c = consumeKind(op, a, consumed);
          if (c == Consumes::Some) {
            bad = true;
            return;
          }
          if (c == Consumes::Escapes)
            return; // the rest of the block never runs; each escape was checked.
          if (c != Consumes::All)
            continue;
          if (consumed) {
            bad = true;
            op->emitOpError() << w.noun << " is " << w.consumed << " twice on this path";
            return;
          }
          consumed = true;
        }

        Operation *term = home->getTerminator();
        if (term->getNumSuccessors() == 0) {
          if (!consumed) {
            bad = true;
            anchor->emitOpError() << w.noun << " is not " << w.consumed << " on this path";
          }
          return;
        }

        // Walk successors.
        DenseMap<Block *, bool> inState;
        SmallVector<Block *> worklist;
        for (Block *succ : term->getSuccessors()) {
          inState[succ] = consumed;
          worklist.push_back(succ);
        }
        DenseSet<Block *> visited;
        bool sawConsumedExit = false, sawReservedExit = false;
        while (!worklist.empty()) {
          Block *b = worklist.pop_back_val();
          if (!visited.insert(b).second)
            continue;
          bool st = inState[b];
          bool escapedHere = false;
          for (Operation &op : *b) {
            if (st && usesValue(&op, v)) {
              bad = true;
              emitUseAfterConsume(&op, w);
              return;
            }
            Consumes c = consumeKind(&op, a, st);
            if (c == Consumes::Some) {
              bad = true;
              return;
            }
            if (c == Consumes::Escapes) {
              escapedHere = true;
              break;
            }
            if (c != Consumes::All)
              continue;
            if (st) {
              bad = true;
              op.emitOpError() << w.noun << " is " << w.consumed << " twice on this path";
              return;
            }
            st = true;
          }
          if (escapedHere)
            continue;
          Operation *t = b->getTerminator();
          if (isIterationEscape(t)) {
            if (!st) {
              bad = true;
              t->emitOpError() << "leaves the iteration while " << w.noun << " is not " << w.consumed;
              return;
            }
            continue;
          }
          if (t->getNumSuccessors() == 0) {
            (st ? sawConsumedExit : sawReservedExit) = true;
            continue;
          }
          for (Block *succ : t->getSuccessors()) {
            auto it = inState.find(succ);
            if (it == inState.end()) {
              inState[succ] = st;
              worklist.push_back(succ);
            } else if (it->second != st) {
              bad = true;
              anchor->emitOpError() << w.noun << " is " << w.consumed << " on some paths but not others";
              return;
            }
          }
        }
        if (a.failed)
          bad = true;
        if (sawConsumedExit && sawReservedExit) {
          bad = true;
          anchor->emitOpError() << w.noun << " is " << w.consumed << " on some paths but not others";
        } else if (sawReservedExit) {
          bad = true;
          anchor->emitOpError() << w.noun << " is not " << w.consumed << " on this path";
        }
      };
      // Ordinary and dynptr reservations consume through their respective submit/
      // discard operations. Distinct values keep the resource kinds separate.
      auto consumesReservation = [](Value v) {
        return [v](Operation *op) {
          return isa<RingbufSubmitOp, RingbufDiscardOp, RingbufSubmitDynptrOp, RingbufDiscardDynptrOp>(op) && op->getOperand(0) == v;
        };
      };
      prog->walk([&](RingbufIfReservedOp ifres) {
        // Walk from the present region's entry block.
        Block *home = &ifres.getPresentRegion().front();
        Value v = home->getArgument(0);
        analyzeLinear(ifres, v, home, &home->front(), consumesReservation(v), reservationWords());
      });
      // Dynptr reservations require consumption even on failure. Start after
      // the definition; there is no null-check region.
      prog->walk([&](RingbufReserveDynptrOp rd) {
        Value v = rd.getDynptr();
        analyzeLinear(rd, v, rd->getBlock(), rd->getNextNode(), consumesReservation(v), reservationWords());
      });
      // Check nullable sockets once on every path; release each present reference once.
      prog->walk([&](Operation *lookup) {
        if (!isa<SockMapLookupOp, SockLookupTcpOp, SockLookupUdpOp, SockSkcLookupTcpOp>(lookup))
          return;
        Value v = lookup->getResult(0);
        Words w{"an acquired socket reference", "checked by ebpf.sock.ref_check", "checked", "a socket reference",
                "not yet checked and released", "the socket reference is acquired here"};
        analyzeLinear(lookup, v, lookup->getBlock(), lookup->getNextNode(),
                      [v](Operation *op) { return isa<SockRefCheckOp>(op) && op->getOperand(0) == v; }, w);
      });
      prog->walk([&](SockRefCheckOp check) {
        Block *home = &check.getPresentRegion().front();
        Value v = home->getArgument(0);
        Words w{"an acquired socket reference", "released", "released by ebpf.sock.release", "a socket reference",
                "not yet released", "the socket reference is checked here"};
        analyzeLinear(check, v, home, &home->front(),
                      [v](Operation *op) { return isa<SockReleaseOp>(op) && op->getOperand(0) == v; }, w);
      });

      // Nullable kfunc acquire results require exactly one kref.check.
      // Non-nullable acquire results require exactly one release. Start
      // traversal immediately after the definition in either case.
      prog->walk([&](KfuncCallOp call) {
        if (call->getNumResults() != 1)
          return;
        Value r = call->getResult(0);
        if (auto kn = dyn_cast<KRefOrNullType>(r.getType())) {
          Words w{"an acquired kernel reference " + ("!ebpf.kref_or_null<\"" + kn.getStructName() + "\">").str(),
                  "checked by ebpf.kref.check", "checked", "an acquired kernel reference",
                  "not yet checked and released", "the reference is acquired here"};
          analyzeLinear(call, r, call->getBlock(), call->getNextNode(),
                        [r](Operation *op) { return isa<KRefCheckOp>(op) && op->getOperand(0) == r; }, w);
        } else if (auto kr = dyn_cast<KRefType>(r.getType())) {
          Words w{"an acquired kernel reference " + ("!ebpf.kref<\"" + kr.getStructName() + "\">").str(),
                  "released", "released by a KF_RELEASE kfunc", "an acquired kernel reference", "not yet released",
                  "the reference is acquired here"};
          analyzeLinear(call, r, call->getBlock(), call->getNextNode(), [r](Operation *op) { return releasesKRef(op, r); }, w);
        }
      });
      // References removed from maps by kptr.xchg require one check, like acquire results.
      prog->walk([&](KPtrXchgOp x) {
        Value r = x.getOld();
        auto kn = cast<KRefOrNullType>(r.getType());
        Words w{"a kernel reference taken out of a map value " + ("!ebpf.kref_or_null<\"" + kn.getStructName() + "\">").str(),
                "checked by ebpf.kref.check", "checked", "a kernel reference taken out of a map value",
                "not yet checked and released", "the reference is taken out of the map value here"};
        analyzeLinear(x, r, x->getBlock(), x->getNextNode(),
                      [r](Operation *op) { return isa<KRefCheckOp>(op) && op->getOperand(0) == r; }, w);
      });
      // references removed from kptr globals follow the same contract.
      prog->walk([&](GlobalKPtrXchgOp x) {
        Value r = x.getOld();
        auto kn = cast<KRefOrNullType>(r.getType());
        Words w{"a kernel reference taken out of a kptr global " + ("!ebpf.kref_or_null<\"" + kn.getStructName() + "\">").str(),
                "checked by ebpf.kref.check", "checked", "a kernel reference taken out of a kptr global",
                "not yet checked and released", "the reference is taken out of the kptr global here"};
        analyzeLinear(x, r, x->getBlock(), x->getNextNode(),
                      [r](Operation *op) { return isa<KRefCheckOp>(op) && op->getOperand(0) == r; }, w);
      });
      // A kref.check present reference requires exactly one release on every
      // path within its region, like an if_reserved reservation.
      prog->walk([&](KRefCheckOp kc) {
        Block *home = &kc.getPresentRegion().front();
        Value v = home->getArgument(0);
        auto kr = cast<KRefType>(v.getType());
        Words w{"an acquired kernel reference " + ("!ebpf.kref<\"" + kr.getStructName() + "\">").str(),
                "released", "released by a KF_RELEASE kfunc", "an acquired kernel reference", "not yet released",
                "the reference is checked here"};
        analyzeLinear(kc, v, home, &home->front(), [v](Operation *op) { return releasesKRef(op, v); }, w);
      });
    });

    if (bad)
      signalPassFailure();
  }
};

} // namespace
