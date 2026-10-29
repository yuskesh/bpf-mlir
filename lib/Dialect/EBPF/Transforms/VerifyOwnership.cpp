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
enum class Consumes { No, All, Some };

// Exit state when walking a region from Reserved.
enum class Exit { Reserved, Consumed, Mixed };

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

Exit analyzeRegion(Region &region, Analysis &a);

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

Consumes consumeKind(Operation *op, Analysis &a) {
  if (a.consumes(op))
    return Consumes::All;
  if (op->getNumRegions() == 0)
    return Consumes::No;

  // Nested regions: All if every region consumes; Some for mixed consumption.
  bool any = false, all = true, seen = false;
  for (Region &r : op->getRegions()) {
    if (r.empty())
      continue;
    seen = true;
    Exit e = analyzeRegion(r, a);
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
    return Consumes::No;
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
Exit analyzeRegion(Region &region, Analysis &a) {
  if (region.empty())
    return Exit::Reserved;

  DenseMap<Block *, bool> inState; // true means Consumed on arrival.
  SmallVector<Block *> worklist;
  inState[&region.front()] = false;
  worklist.push_back(&region.front());

  bool sawConsumedExit = false, sawReservedExit = false;
  DenseSet<Block *> visited;

  while (!worklist.empty()) {
    Block *b = worklist.pop_back_val();
    bool consumed = inState[b];
    if (!visited.insert(b).second && consumed == inState[b]) {
      // Stop revisiting identical states so loops converge.
    }

    for (Operation &op : *b) {
      if (consumed && usesValue(&op, a.v)) {
        a.failed = true;
        emitUseAfterConsume(&op, a.w);
        return Exit::Mixed;
      }
      Consumes c = consumeKind(&op, a);
      if (c == Consumes::Some) {
        a.failed = true;
        return Exit::Mixed;
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

    Operation *term = b->getTerminator();
    if (term->getNumSuccessors() == 0) {
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

  if (sawConsumedExit && sawReservedExit)
    return Exit::Mixed;
  return sawConsumedExit ? Exit::Consumed : Exit::Reserved;
}

// A release-flagged kfunc argument consumes v. kptr.xchg also consumes its new
// reference by transferring ownership to the map.
bool releasesKRef(Operation *op, Value v) {
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
      if (!isa<ProgramOp, SubprogramOp>(prog))
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
            Operation *loop = nullptr;
            op->walk([&](LoopOp l) {
              loop = l;
              return WalkResult::interrupt();
            });
            if (loop) {
              bad = true;
              loop->emitOpError() << "is reached while " << w.noun << " is still live (" << w.tailWhat << "); a live "
                                  << (w.noun == "a ring buffer reservation" ? std::string("reservation") : std::string("reference"))
                                  << " must not cross ebpf.loop (the ownership check does not follow loops)";
              anchor->emitRemark() << w.taken;
              return;
            }
          }
          if (consumed && usesValue(op, v)) {
            bad = true;
            emitUseAfterConsume(op, w);
            return;
          }
          Consumes c = consumeKind(op, a);
          if (c == Consumes::Some) {
            bad = true;
            return;
          }
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
          for (Operation &op : *b) {
            if (st && usesValue(&op, v)) {
              bad = true;
              emitUseAfterConsume(&op, w);
              return;
            }
            Consumes c = consumeKind(&op, a);
            if (c == Consumes::Some) {
              bad = true;
              return;
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
          Operation *t = b->getTerminator();
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
      prog->walk([&](SockMapLookupOp lookup) {
        Value v = lookup.getResult();
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
