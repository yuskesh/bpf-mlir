//===- CallContexts.h - the contexts that reach each ebpf.func -*- C++ -*-===//
//
// An ebpf.func runs in every context its callers give it, and
// a context-dependent op in its body is accepted only when every such context
// allows it. The regions around the call sites are the op's ancestors as far as
// the program body's placement rules go (a call does not bypass
// them — ebpf.ringbuf.if_reserved, scf.if and the loop body included). A context is the owner program (and so its kind; the sched_ext_ops
// member and the schema's sleepable flag are looked up from the owner by
// ebpf-verify-schema), the entry the call path starts from (the program body,
// an ebpf.timer.callback — async, or a callback ebpf.loop — sync), and the
// regions the call sites on the path lie in (ebpf.rcu.region makes the callee
// non-sleepable — the kernel's in_sleepable_context; ebpf.loop / scf.if, the
// iterator bodies). A callback entry does not inherit its owner's context: the
// context starts at the callback (the owner's sleepable flag and member table
// never flow into the callback side).
//
// a timer callback context is not sleepable and does
// not assume RCU (7.3.1 never runs a timer callback sleepable; 6.12.111 runs a
// sleepable owner's callback sleepable, outside RCU) — a sleepable op is
// rejected there and an RCU-dependent op needs an explicit ebpf.rcu.region.
// The body of an ebpf.timer.callback is a top like an ebpf.func body: it has
// one context per owner (CallContexts::of(cb)).
//
// RCU states (the global-function boundary): inRcu is the
// constraint a call site inside ebpf.rcu.region puts on the path (no sleepable
// op) and survives every call; rcuHeld is the guarantee an RCU-dependent op may
// rely on, and rcuNestGuard rejects an ebpf.rcu.region that would nest in the
// caller's section. A global callee inherits neither of the last two from its
// caller (7.1.8 / 6.12.111 / 6.6.157 verify a global function once, from a
// fresh state with the program's sleepable flag, so the verifier sees no
// caller's section there; a nested bpf_rcu_read_lock at run time is correct).
// A static callee is verified on the caller's state and inherits all three.
//
// Contexts propagate through ebpf.call to a fixed point over a finite key set
// (owner, entry, entry kind, region flags), so the computation terminates also
// on a recursive graph (ebpf-verify-call-graph rejects recursion first).
//
// Users: ebpf-verify-call-contexts (kind-level rules, no schema) and
// ebpf-verify-schema (member and sleepable rules). E-c builds on the same
// contexts for the closed regions.
//===----------------------------------------------------------------------===//
#ifndef BPF_MLIR_DIALECT_EBPF_TRANSFORMS_CALLCONTEXTS_H
#define BPF_MLIR_DIALECT_EBPF_TRANSFORMS_CALLCONTEXTS_H

#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"

#include "mlir/IR/BuiltinOps.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"

#include <optional>
#include <string>

namespace mlir {
namespace ebpf {

// Where the call path starts.
enum class CallEntry {
  ProgramBody,   // the owner program's own body
  TimerCallback, // an ebpf.timer.callback the owner registers (async, not sleepable)
  LoopCallback,  // a callback ebpf.loop (bpf_loop — sync, treated as not sleepable)
};

// The innermost ownership-relevant region around the call sites of the path
// (seen from the callee: a nearer call site's region overrides an outer one).
// The rule "acquire / release only when no iterator or loop lies between
// the op and the innermost rcu.region" applies through calls with it.
enum class CallNearest {
  None,
  Rcu,        // ebpf.rcu.region
  IterNum,    // an ebpf.iter.num body
  ScxDsq,     // an ebpf.iter.scx_dsq body
  Unfollowed, // ebpf.loop (not a callback) or scf.if — the ownership check does not follow them
};

struct CallContext {
  ProgramOp owner;                            // the program whose verification covers the context
  Operation *entry = nullptr;                 // ProgramOp, TimerCallbackOp or the callback LoopOp
  CallEntry entryKind = CallEntry::ProgramBody;
  bool inRcu = false;                         // a call site on the path is inside ebpf.rcu.region
  // the RCU section an RCU-dependent op may rely on — set by an
  // ebpf.rcu.region around the call site or the op, dropped at the entry of a
  // global callee (inRcu stays: the constraint does not end at the boundary).
  bool rcuHeld = false;
  // an ebpf.rcu.region here would nest in a caller's
  // section the verifier sees (6.6.157 / 6.12.111 reject a nested
  // bpf_rcu_read_lock) — set like rcuHeld, dropped at the entry of a global
  // callee (verified from a fresh state). Not the sleepable constraint (inRcu).
  bool rcuNestGuard = false;
  bool inUnfollowed = false;                  // ... inside ebpf.loop (not a callback) or scf.if
  bool inIterNum = false;                     // ... inside an ebpf.iter.num body
  bool inScxDsq = false;                      // ... inside an ebpf.iter.scx_dsq body
  // the placement rules of the program body hold through
  // calls, so the call sites' regions those rules look at are recorded too.
  bool inScfIf = false;                       // ... inside scf.if (the closed regions' place rule)
  // The nearest of ebpf.loop (not a callback), ebpf.iter.num and
  // ebpf.iter.scx_dsq on the path is an ebpf.loop: the loop body's allowlist
  // applies (ebpf.rcu.region is not in it; an iterator body in between has its own).
  bool inLoopBody = false;
  // The nearest call-site region that none of the flags above names and that
  // the sched_ext ops' allowlist of ancestors (ebpf.if, ref.check, kptr.check,
  // kref.check, the iterator bodies, rcu.region) does not hold — e.g.
  // ebpf.ringbuf.if_reserved, ebpf.packet.check, ebpf.ref.index. Empty: none.
  llvm::StringRef otherRegion;
  CallNearest nearest = CallNearest::None;
  llvm::SmallVector<llvm::StringRef, 4> path; // entry symbol, then the callees (the first path found)

  llvm::StringRef kind() const;
  // Same key (the path is not part of it).
  bool sameAs(const CallContext &o) const;
  // in_sleepable_context: the program body of a sleepable owner with no RCU
  // section on the way. ownerSleepable is the kind's OPS tag "sleepable" or the
  // schema program's "sleepable" (struct_ops).
  bool sleepable(bool ownerSleepable) const {
    return entryKind == CallEntry::ProgramBody && !inRcu && ownerSleepable;
  }
  // an RCU-dependent op (iter.scx_dsq, kptr.load_rcu, global.kptr_load_rcu,
  // task_struct.cpus_ptr, the RCU-section sched_ext ops) is accepted: in a
  // program body context, when the owner is not loaded sleepable (the whole
  // program is the read section) or an ebpf.rcu.region is held; in a callback
  // context only when an ebpf.rcu.region is held (the callback
  // assumes no RCU).
  bool rcuGuaranteed(bool ownerSleepable) const {
    if (entryKind == CallEntry::ProgramBody)
      return !ownerSleepable || rcuHeld;
    return rcuHeld;
  }
};

// The contexts of every ebpf.func of a module (empty for a function no entry
// reaches — ebpf-verify-call-graph's reachability rule owns that case).
class CallContexts {
public:
  explicit CallContexts(ModuleOp module);
  llvm::ArrayRef<CallContext> of(SubprogramOp fn) const;
  // the contexts of a top — an ebpf.func, or an ebpf.timer.callback (one
  // root context per owner; empty for a callback no program registers).
  llvm::ArrayRef<CallContext> of(Operation *top) const;

private:
  llvm::DenseMap<Operation *, llvm::SmallVector<CallContext, 2>> byFunc_;
};

// c as seen at op inside top (the ebpf.func): op's own enclosing regions in top
// apply as a call site's would.
CallContext callContextAt(const CallContext &c, Operation *op, Operation *top);

// The diagnostic tail naming c: owner, kind, member (when given), entry, call
// path, the regions on the path and — when ownerSleepable is given — sleepable.
std::string describeCallContext(const CallContext &c, llvm::StringRef member = {},
                                std::optional<bool> ownerSleepable = std::nullopt);

// The ops whose acceptance in an ebpf.func body depends on its contexts: kfunc.call, kref.check, iter.num, iter.scx_dsq, rcu.region, the kptr
// exchanges and RCU reads, trace.printk and the sched_ext ops.
bool isContextDependentOp(Operation *op);

} // namespace ebpf
} // namespace mlir

#endif // BPF_MLIR_DIALECT_EBPF_TRANSFORMS_CALLCONTEXTS_H
