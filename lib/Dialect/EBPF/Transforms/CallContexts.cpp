//===- CallContexts.cpp - the contexts that reach each ebpf.func ---===//
//
// See CallContexts.h. Roots: every ebpf.program body (its own context) and
// every ebpf.timer.callback once per owner (the programs whose
// ebpf.timer.set_callback names it). Each ebpf.call passes the caller's
// context, adjusted by the regions around the call site, to the callee; a
// worklist runs to the fixed point (contexts are deduplicated by key). :
// the root contexts of a timer callback are kept for its own body too, and a
// global callee drops the caller's RCU guarantee (rcuHeld) and the nesting
// guard (rcuNestGuard) but not the sleepable constraint (inRcu).
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/CallContexts.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/Support/raw_ostream.h"

#include <deque>
#include <utility>

using namespace mlir;
using namespace mlir::ebpf;

StringRef CallContext::kind() const {
  ProgramOp p = owner;
  return p.getKind();
}

bool CallContext::sameAs(const CallContext &o) const {
  Operation *a = owner, *b = o.owner;
  return a == b && entry == o.entry && entryKind == o.entryKind &&
         inRcu == o.inRcu && rcuHeld == o.rcuHeld && rcuNestGuard == o.rcuNestGuard && inUnfollowed == o.inUnfollowed && inIterNum == o.inIterNum && inScxDsq == o.inScxDsq &&
         inScfIf == o.inScfIf && inLoopBody == o.inLoopBody && otherRegion == o.otherRegion && nearest == o.nearest;
}

namespace {
// Apply the regions between op and top (exclusive) to c, innermost first. The
// regions of this layer (nearer the op) override the "nearest" facts of the
// outer layers already in c.
void applyEnclosing(CallContext &c, Operation *op, Operation *top) {
  bool nearestSet = false, callbackSet = false, loopishSet = false, otherSet = false;
  for (Operation *p = op->getParentOp(); p && p != top; p = p->getParentOp()) {
    CallNearest n = CallNearest::None;
    if (isa<RcuRegionOp>(p)) {
      c.inRcu = true;
      c.rcuHeld = true;
      c.rcuNestGuard = true;
      n = CallNearest::Rcu;
    } else if (isa<IterNumOp>(p)) {
      c.inIterNum = true;
      n = CallNearest::IterNum;
      if (!loopishSet) {
        c.inLoopBody = false;
        loopishSet = true;
      }
    } else if (isa<IterScxDsqOp>(p)) {
      c.inScxDsq = true;
      n = CallNearest::ScxDsq;
      if (!loopishSet) {
        c.inLoopBody = false;
        loopishSet = true;
      }
    } else if (auto loop = dyn_cast<LoopOp>(p)) {
      if (loop.getCallback()) {
        // A helper callback is its own entry (bpf_loop): the innermost one.
        if (!callbackSet) {
          c.entryKind = CallEntry::LoopCallback;
          c.entry = p;
          callbackSet = true;
        }
      } else {
        c.inUnfollowed = true;
        n = CallNearest::Unfollowed;
        if (!loopishSet) {
          c.inLoopBody = true;
          loopishSet = true;
        }
      }
    } else if (isa<MapForEachOp>(p)) { // A helper callback too (its body rejects calls today).
      if (!callbackSet) {
        c.entryKind = CallEntry::LoopCallback;
        c.entry = p;
        callbackSet = true;
      }
    } else if (p->getName().getStringRef() == "scf.if") {
      c.inUnfollowed = true;
      c.inScfIf = true;
      n = CallNearest::Unfollowed;
    } else if (!isa<IfOp, RefCheckOp, KPtrCheckOp, KRefCheckOp>(p)) {
      // a region the sched_ext ops' ancestor allowlist does not
      // hold (ebpf.ringbuf.if_reserved, ebpf.packet.check, ...).
      if (!otherSet) {
        c.otherRegion = p->getName().getStringRef();
        otherSet = true;
      }
    }
    if (n != CallNearest::None && !nearestSet) {
      c.nearest = n;
      nearestSet = true;
    }
  }
}

StringRef symbolOf(Operation *op) {
  if (auto s = op ? op->getAttrOfType<StringAttr>(SymbolTable::getSymbolAttrName()) : StringAttr())
    return s.getValue();
  return "?";
}
} // namespace

CallContexts::CallContexts(ModuleOp module) {
  llvm::StringMap<SubprogramOp> funcs;
  for (auto fn : module.getOps<SubprogramOp>())
    funcs[fn.getSymName()] = fn;

  std::deque<std::pair<SubprogramOp, CallContext>> work;
  auto add = [&](SubprogramOp fn, CallContext c) {
    auto &list = byFunc_[fn.getOperation()];
    for (const CallContext &have : list)
      if (have.sameAs(c))
        return;
    list.push_back(c);
    work.emplace_back(fn, std::move(c));
  };
  // Pass `from` (the context of root) to the callee of every call in root.
  auto spread = [&](Operation *root, const CallContext &from) {
    root->walk([&](CallOp call) {
      auto it = funcs.find(call.getCallee());
      if (it == funcs.end())
        return; // The call verifier names an unknown callee.
      CallContext c = from;
      applyEnclosing(c, call, root);
      // a global callee is verified once with the program's sleepable
      // flag (7.1.8 / 6.12.111 / 6.6.157), so it does not inherit the caller's
      // RCU section as a guarantee, and it may open its own section without
      // nesting in the caller's (the global-function boundary — verified from a fresh
      // state); the constraint (inRcu) and the placement / ownership marks
      // stay. A static callee is verified on the caller's state.
      if (it->second.getLinkage() == "global") {
        c.rcuHeld = false;
        c.rcuNestGuard = false;
      }
      c.path.push_back(it->second.getSymName());
      add(it->second, std::move(c));
    });
  };

  for (auto prog : module.getOps<ProgramOp>()) {
    CallContext c;
    c.owner = prog;
    c.entry = prog;
    c.entryKind = CallEntry::ProgramBody;
    c.path.push_back(prog.getSymName());
    spread(prog, c);
  }
  // A timer callback starts its own context per owner — it does not inherit
  // the owner's program-body context.
  for (auto cb : module.getOps<TimerCallbackOp>()) {
    SmallVector<ProgramOp> owners;
    module.walk([&](TimerSetCallbackOp s) {
      auto prog = s->getParentOfType<ProgramOp>();
      if (prog && s.getCallback() == cb.getSymName() && !llvm::is_contained(owners, prog))
        owners.push_back(prog);
    });
    for (ProgramOp o : owners) {
      CallContext c;
      c.owner = o;
      c.entry = cb;
      c.entryKind = CallEntry::TimerCallback;
      c.path.push_back(cb.getSymName());
      // the callback body itself is checked per owner context (a top
      // like an ebpf.func body).
      byFunc_[cb.getOperation()].push_back(c);
      spread(cb, c);
    }
  }
  while (!work.empty()) {
    std::pair<SubprogramOp, CallContext> item = std::move(work.front());
    work.pop_front();
    spread(item.first, item.second);
  }
}

ArrayRef<CallContext> CallContexts::of(SubprogramOp fn) const { return of(fn.getOperation()); }

ArrayRef<CallContext> CallContexts::of(Operation *top) const {
  auto it = byFunc_.find(top);
  if (it == byFunc_.end())
    return {};
  return it->second;
}

CallContext mlir::ebpf::callContextAt(const CallContext &c, Operation *op, Operation *top) {
  CallContext r = c;
  applyEnclosing(r, op, top);
  return r;
}

std::string mlir::ebpf::describeCallContext(const CallContext &c, StringRef member, std::optional<bool> ownerSleepable) {
  std::string s;
  llvm::raw_string_ostream os(s);
  ProgramOp owner = c.owner;
  os << "in the context reached from @" << owner.getSymName() << " (kind \"" << owner.getKind() << "\"";
  if (!member.empty())
    os << ", " << member;
  os << ")";
  switch (c.entryKind) {
  case CallEntry::ProgramBody:
    os << " through its program body";
    break;
  case CallEntry::TimerCallback:
    os << " through ebpf.timer.callback @" << symbolOf(c.entry);
    break;
  case CallEntry::LoopCallback:
    os << " through a helper callback (" << (c.entry ? c.entry->getName().getStringRef() : StringRef("?")) << ")";
    break;
  }
  os << ", call path ";
  for (auto [i, p] : llvm::enumerate(c.path))
    os << (i ? " -> @" : "@") << p;
  SmallVector<StringRef> regions;
  if (c.inRcu)
    regions.push_back("ebpf.rcu.region");
  if (c.inIterNum)
    regions.push_back("ebpf.iter.num");
  if (c.inScxDsq)
    regions.push_back("ebpf.iter.scx_dsq");
  if (c.inUnfollowed)
    regions.push_back("ebpf.loop / scf.if");
  if (!c.otherRegion.empty())
    regions.push_back(c.otherRegion);
  if (!regions.empty()) {
    os << " (inside ";
    for (auto [i, r] : llvm::enumerate(regions))
      os << (i ? ", " : "") << r;
    os << " on the way)";
  }
  if (ownerSleepable) {
    os << ", sleepable: ";
    if (c.entryKind == CallEntry::TimerCallback)
      os << "no (a timer callback is not sleepable)";
    else if (c.entryKind == CallEntry::LoopCallback)
      os << "no (a helper callback)";
    else if (c.inRcu)
      os << "no (a call on the path is inside ebpf.rcu.region)";
    else if (!*ownerSleepable)
      os << "no (the program is not loaded sleepable)";
    else
      os << "yes";
  }
  return os.str();
}

bool mlir::ebpf::isContextDependentOp(Operation *op) {
  if (op->getName().getStringRef().starts_with("ebpf.scx."))
    return true;
  return isa<KfuncCallOp, KRefCheckOp, IterNumOp, IterScxDsqOp, RcuRegionOp, KPtrXchgOp, GlobalKPtrXchgOp, KPtrLoadRcuOp,
             GlobalKPtrLoadRcuOp, TracePrintkOp>(op);
}
