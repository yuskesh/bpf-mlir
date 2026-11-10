//===- VerifyCallContexts.cpp - context-dependent ops of ebpf.func ---===//
//
// - an op whose acceptance depends on where it
// runs (CallContexts.h isContextDependentOp) is accepted in an ebpf.func body
// only if every context that reaches the function allows it there. The op
// verifiers check what does not depend on the caller (types, the regions
// inside the function); this pass checks the kind-level rules per context,
// as the op verifier checks them in a program body: kfunc program types, the
// OPS tags "scx", "scx.<op>", "trace.printk" and "sleepable", the /
// iterator and ownership placement through calls, and no RCU section
// entered twice. the ancestor rules of the program body hold at
// the call sites too — the sched_ext ops' allowlist of ancestors (a call inside
// ebpf.ringbuf.if_reserved, ebpf.packet.check, ...), scf.if around an iterator
// or RCU section, and the loop body's allowlist (no ebpf.rcu.region). The
// schema-level rules (sched_ext_ops member, the schema's
// sleepable flag) are in ebpf-verify-schema with the same contexts.
//
// a timer callback entry (sched_ext_ops owners) follows the
// same rules plus its own context — not sleepable, no RCU unless an
// ebpf.rcu.region is held (a global callee does not inherit the caller's), and
// the sched_ext ops limited to kScxTimerCallbackOps (a compiler subset, not the
// kernel's filter). The callback body is walked like an ebpf.func body. A
// helper callback (bpf_loop) entry still rejects all of these ops (the program
// body rejects them in a callback too).
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h"

#include "bpf-mlir/Dialect/BPFABI/KernelABI.h"
#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"
#include "bpf-mlir/Dialect/EBPF/Transforms/CallContexts.h"
#include "bpf-mlir/Support/ProgramKinds.h"
#include "bpf-mlir/Support/ScxContract.h"

#include "llvm/ADT/Twine.h"

namespace mlir {
namespace ebpf {
#define GEN_PASS_DEF_EBPFVERIFYCALLCONTEXTS
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h.inc"
} // namespace ebpf
} // namespace mlir

using namespace mlir;
using namespace mlir::ebpf;

namespace {

// the DSQ iterator body's ownership exception covers every
// kfunc acquire / release and kref.check (EBPFDialect.cpp's scxDsqRefOp) —
// there is no per-kfunc filter to copy here any more.

// Ops that take, check or hand back a kernel reference (verifyOwnershipInIter's set).
bool ownershipOp(Operation *op) {
  if (isa<KRefCheckOp, KPtrXchgOp, GlobalKPtrXchgOp>(op))
    return true;
  if (auto call = dyn_cast<KfuncCallOp>(op))
    if (const bpfabi::KfuncABI *k = bpfabi::lookupKfunc(call.getCallee()))
      return k->hasFlag("acquire") || k->hasFlag("release");
  return false;
}

// the tail naming why a caller's ebpf.rcu.region does not count.
std::string globalRcuNote(const CallContext &c) {
  if (c.inRcu && !c.rcuHeld)
    return "; the caller's ebpf.rcu.region does not reach into a global function (7.1.8 / 6.12.111 / 6.6.157 verify a "
           "global function once with the program's sleepable flag — put the section in the global function's body)";
  return {};
}

// an RCU-dependent op without a held section in a timer callback context.
std::string rcuMissing(const CallContext &c, const std::string &what) {
  return what +
         " outside ebpf.rcu.region in an ebpf.timer.callback context, which assumes no RCU read section (6.12.111 runs a "
         "sleepable owner's callback outside RCU — the compiler takes the side every version accepts: put it inside an "
         "ebpf.rcu.region)" +
         globalRcuNote(c);
}

// Empty when c allows op; otherwise the reason (the context is named by the caller).
std::string violation(Operation *op, const CallContext &c) {
  // an ebpf.loop is not a context-dependent op (a function
  // reached from a helper callback may hold one), but the DSQ iterator
  // body excludes it (closed set — a compiler limit) and the rule holds
  // through calls.
  if (isa<LoopOp>(op))
    return c.inScxDsq ? "is reached through a call inside an ebpf.iter.scx_dsq body, which does not allow ebpf.loop "
                        "(the DSQ iterator body's closed op set; the rule holds through calls)"
                      : std::string();
  if (!isContextDependentOp(op))
    return {};
  StringRef name = op->getName().getStringRef();
  bool scx = name.starts_with("ebpf.scx.");
  if (c.entryKind == CallEntry::LoopCallback)
    return "is not allowed in a function reached from a helper callback (a callback ebpf.loop body does not allow it "
           "either)";
  bool timer = c.entryKind == CallEntry::TimerCallback;
  // only sched_ext_ops owners open the timer callback's op set (the
  // callback's op verifier keeps the set for the other owners, which
  // cannot call a function).
  if (timer && !bpfmlir::kindAllows(c.kind(), "scx"))
    return "is not allowed in an ebpf.timer.callback context whose owner is not a " + bpfmlir::kindsAllowing("scx") +
           " program (only sched_ext_ops owners open the callback's op set)";
  StringRef kind = c.kind();
  StringRef ptype = programTypeOf(kind);
  auto kfuncRule = [&](StringRef kfunc) -> std::string {
    const bpfabi::KfuncABI *k = bpfabi::lookupKfunc(kfunc);
    if (!k)
      return ("needs the kfunc \"" + kfunc + "\", which is not in the kfunc table").str();
    if (!k->allowsProgType(ptype))
      return ("lowers to the kfunc \"" + kfunc + "\", which is not registered for program type " + ptype + " (kind \"" +
              kind + "\"); the kfunc table allows " + StringRef(k->progTypes))
          .str();
    return {};
  };

  // Regions on the call path, as if the op stood at the call site.
  if (c.inUnfollowed && (scx || isa<KfuncCallOp, KRefCheckOp, KPtrXchgOp, GlobalKPtrXchgOp, KPtrLoadRcuOp, GlobalKPtrLoadRcuOp>(op)))
    return "is reached through a call inside ebpf.loop or scf.if; like the op itself there, it is only allowed outside "
           "loops and scf.if (the ownership check does not follow them)";
  // the program body's ancestor rules hold at the call sites too.
  // verifyScxCommon's allowlist of ancestors (a call inside
  // ebpf.ringbuf.if_reserved, ebpf.packet.check, ... does not bypass it).
  if (scx && !c.otherRegion.empty())
    return ("is reached through a call inside '" + c.otherRegion +
            "'; sched_ext kfunc ops are only allowed in the body of an ebpf.program and its ebpf.if, ebpf.ref.check and "
            "ebpf.kptr.check regions (and ebpf.iter.num / ebpf.iter.scx_dsq / ebpf.rcu.region bodies, ebpf.kref.check "
            "regions) — the rule holds through calls")
        .str();
  // closedRegionOwner: scf.if cannot hold an iterator or an RCU section.
  if (isa<IterNumOp, RcuRegionOp>(op) && c.inScfIf)
    return ("is reached through a call inside 'scf.if'; " + name +
            " is only allowed in an ebpf.program body or an ebpf.func body (callbacks, map.for_each, spin.region and scf.if "
            "cannot hold it — the compiler checks it region-locally; the rule holds through calls)")
        .str();
  // LoopOp::verify's body allowlist has no ebpf.rcu.region (an iterator body in
  // between has its own allowlist, which has it).
  if (isa<RcuRegionOp>(op) && c.inLoopBody)
    return "is reached through a call inside an ebpf.loop body; ebpf.rcu.region is not allowed inside ebpf.loop (the loop "
           "body's allowlist does not hold it — the rule holds through calls)";
  if (ownershipOp(op)) {
    if (c.nearest == CallNearest::IterNum)
      return "takes, checks or hands back a kernel reference in a function reached from an ebpf.iter.num body with no "
             "ebpf.rcu.region in between; inside an iterator a kernel reference may only be taken and released in an "
             "ebpf.rcu.region with no iterator or loop in between (the rule holds through calls)";
    // from an ebpf.iter.scx_dsq body any kfunc acquire /
    // release and kref.check (closed in the function — ebpf-verify-ownership);
    // kptr.xchg stays rejected by the body rule below.
  }
  // a callee's ebpf.iter.num is accepted (the DSQ iterator's body holds
  // one; ebpf-verify-call-graph counts the depth); the callee's ops keep the
  // DSQ body's exclusions — and an iter.num's body is checked as such (nearest).
  if (c.inScxDsq && isa<IterScxDsqOp, RcuRegionOp, KPtrXchgOp, KPtrLoadRcuOp, GlobalKPtrXchgOp, GlobalKPtrLoadRcuOp>(op))
    return "is reached through a call inside an ebpf.iter.scx_dsq body, which does not allow it (iterators, "
           "ebpf.rcu.region and the kptr reads / exchanges; ebpf.iter.num is the one iterator allowed)";
  if (isa<IterScxDsqOp>(op) && (c.inUnfollowed || c.inIterNum))
    return "is reached through a call inside ebpf.loop, scf.if or ebpf.iter.num; ebpf.iter.scx_dsq is not supported "
           "inside them";
  // only a section the verifier sees — a global callee
  // starts from a fresh state (rcuNestGuard dropped), a static one does not.
  if (isa<RcuRegionOp>(op) && c.rcuNestGuard)
    return "is reached through a call inside another ebpf.rcu.region; nested RCU sections are rejected (6.6.157 / "
           "6.12.111 reject a nested bpf_rcu_read_lock — the compiler takes the strict side)";

  // the timer callback context — not sleepable, and no RCU
  // read section unless an ebpf.rcu.region is held (a global callee does not
  // inherit its caller's). The sched_ext ops: the product of "in
  // kScxTimerCallbackOps" and "inside ebpf.rcu.region when RCU-dependent".
  if (timer) {
    if (isa<TracePrintkOp>(op))
      return "is not allowed in an ebpf.timer.callback context (trace.printk is rejected inside ebpf.timer.callback itself, "
             "and the rule holds through calls)";
    if (scx) {
      StringRef scxOp = name.drop_front(StringRef("ebpf.scx.").size());
      if (const bpfmlir::ScxKfuncInfo *info = bpfmlir::lookupScxOp(scxOp))
        if (const bpfabi::KfuncABI *k = bpfabi::lookupKfunc(info->kfunc); k && k->hasFlag("sleepable"))
          return ("calls " + StringRef(info->kfunc) +
                  " (KF_SLEEPABLE) in an ebpf.timer.callback context, which is not sleepable (7.3.1 / 7.1.8 never run a timer "
                  "callback sleepable)")
              .str();
      if (!bpfmlir::scxTimerCallbackAllows(scxOp))
        return "is not in the timer callback's sched_ext op set (" + bpfmlir::scxTimerCallbackOps() +
               " — ScxContract.h kScxTimerCallbackOps, a conservative subset of the compiler, not the kernel's filter; an "
               "RCU-section op such as scx.cpu_curr or scx.dsq_peek stays outside it also inside ebpf.rcu.region)";
      if (bpfmlir::scxNeedsRcuSection(scxOp) && !c.rcuHeld)
        return rcuMissing(c, "needs the RCU read section");
    }
    if (isa<IterScxDsqOp>(op) && !c.rcuHeld)
      return rcuMissing(c, "starts bpf_iter_scx_dsq_new (KF_RCU_PROTECTED)");
    if (isa<KPtrLoadRcuOp, GlobalKPtrLoadRcuOp>(op) && !c.rcuHeld)
      return rcuMissing(c, std::string("reads a ") + (isa<KPtrLoadRcuOp>(op) ? "kptr field" : "kptr global"));
  }

  // Kind-level permissions, as in a program body of the owner's kind.
  if (auto call = dyn_cast<KfuncCallOp>(op)) {
    const bpfabi::KfuncABI *k = bpfabi::lookupKfunc(call.getCallee());
    if (k && !k->allowsProgType(ptype))
      return ("kfunc \"" + call.getCallee() + "\" is not registered for program type " + ptype + " (kind \"" + kind +
              "\"); the kfunc table allows " + StringRef(k->progTypes))
          .str();
    return {};
  }
  if (isa<IterNumOp>(op))
    return kfuncRule("bpf_iter_num_new");
  if (isa<RcuRegionOp>(op))
    return kfuncRule("bpf_rcu_read_lock");
  if (isa<IterScxDsqOp>(op)) {
    if (!bpfmlir::kindAllows(kind, "scx"))
      return "is only for " + bpfmlir::kindsAllowing("scx") + " programs implementing a sched_ext_ops member (kind \"" +
             kind.str() + "\" — the iterator in tp_btf / fentry / syscall programs is out of scope)";
    return kfuncRule("bpf_iter_scx_dsq_new");
  }
  if (scx) {
    StringRef scxOp = name.drop_front(StringRef("ebpf.scx.").size());
    // the kind's OPS tag "scx" or the op's own "scx.<op>"
    // (scxKindRule — the same rule and text as the program body).
    if (std::string why = bpfmlir::scxKindRule(scxOp, kind); !why.empty())
      return why;
    if (scxOp == "const" || scxOp == "exit_info") // Neither calls a kfunc.
      return {};
    const bpfmlir::ScxKfuncInfo *info = bpfmlir::lookupScxOp(scxOp);
    if (!info)
      return "has no row in ScxContract.def";
    const bpfabi::KfuncABI *k = bpfabi::lookupKfunc(info->kfunc);
    if (!k)
      return ("needs kfunc \"" + StringRef(info->kfunc) + "\", which is not in the kfunc table").str();
    if (!k->allowsProgType(ptype))
      return ("kfunc \"" + StringRef(info->kfunc) + "\" is not registered for program type " + ptype +
              "; the kfunc table allows " + StringRef(k->progTypes))
          .str();
    return {};
  }
  if (isa<TracePrintkOp>(op)) {
    // a struct_ops owner must also implement a sched_ext_ops member —
    // a schema fact, checked per context by ebpf-verify-schema (same text as
    // the program body).
    if (!bpfmlir::kindAllows(kind, "trace.printk"))
      return "requires a supported enclosing program: trace.printk is only for " + bpfmlir::kindsAllowing("trace.printk") +
             " programs (kind \"" + kind.str() + "\")";
    return {};
  }
  if (isa<KPtrLoadRcuOp, GlobalKPtrLoadRcuOp>(op)) {
    // the guarantee (rcuHeld), not the constraint — a caller's
    // ebpf.rcu.region does not reach into a global callee.
    if (bpfmlir::kindAllows(kind, "sleepable") && !c.rcuHeld)
      return std::string("reads a ") + (isa<KPtrLoadRcuOp>(op) ? "kptr field" : "kptr global") +
             " outside ebpf.rcu.region in a context of a " + kind.str() +
             " program, which is loaded sleepable — the verifier marks it untrusted there (only inside the section)" +
             globalRcuNote(c);
    return {};
  }
  return {};
}

struct EBPFVerifyCallContextsPass
    : public mlir::ebpf::impl::EBPFVerifyCallContextsBase<EBPFVerifyCallContextsPass> {
  void runOnOperation() override {
    ModuleOp module = getOperation();
    CallContexts contexts(module);
    bool bad = false;
    // the tops are the ebpf.func bodies and the ebpf.timer.callback
    // bodies (one context per owner) — the callback's direct ops and the ops
    // of the functions it reaches follow the same rules.
    SmallVector<Operation *> tops;
    for (auto fn : module.getOps<SubprogramOp>())
      tops.push_back(fn);
    for (auto cb : module.getOps<TimerCallbackOp>())
      tops.push_back(cb);
    for (Operation *fn : tops) {
      ArrayRef<CallContext> cs = contexts.of(fn);
      if (cs.empty())
        continue; // ebpf-verify-call-graph owns a function no entry reaches.
      fn->walk([&](Operation *op) {
        if (!isContextDependentOp(op) && !isa<LoopOp>(op)) // ebpf.loop for the DSQ body rule only.
          return;
        for (const CallContext &c0 : cs) {
          CallContext c = callContextAt(c0, op, fn);
          std::string why = violation(op, c);
          if (why.empty())
            continue;
          bad = true;
          op->emitOpError() << why << " — " << describeCallContext(c);
          break; // One context per op.
        }
      });
    }
    if (bad)
      signalPassFailure();
  }
};

} // namespace
