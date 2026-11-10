//===- ScxContract.h - sched_ext kfunc contract lookups ---*- C++ -*-===//
//
// Lookups over ScxContract.def: which kfunc an ebpf.scx.* op calls, which
// sched_ext_ops members may call it, and which members may be sleepable.
// The only family is "insert" (module attribute ebpf.scx_kfuncs).
#ifndef BPF_MLIR_SUPPORT_SCXCONTRACT_H
#define BPF_MLIR_SUPPORT_SCXCONTRACT_H

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include <cstdint>
#include <string>

namespace bpfmlir {

enum ScxGroup : uint32_t {
  ScxUnlocked = 1u << 0,
  ScxCpuRelease = 1u << 1,
  ScxDispatch = 1u << 2,
  ScxEnqueue = 1u << 3,
  ScxSelectCpu = 1u << 4,
  ScxAny = 1u << 5, // scx_kfunc_ids_any: allowed in every sched_ext_ops member.
  ScxIdle = 1u << 6, // scx_kfunc_ids_idle — the filter allows it like any (7.3.1 ext/ext.c:11087).
};

inline constexpr llvm::StringLiteral kScxFamilyAttr = "ebpf.scx_kfuncs";
inline constexpr llvm::StringLiteral kScxFamilyInsert = "insert";
inline constexpr llvm::StringLiteral kScxOpsType = "sched_ext_ops";

struct ScxKfuncInfo {
  llvm::StringLiteral op;
  llvm::StringLiteral kfunc;
  uint32_t groups;
};
struct ScxMemberInfo {
  llvm::StringLiteral opsType;
  llvm::StringLiteral member;
  uint32_t allow;
  bool sleepable;
};

inline constexpr ScxKfuncInfo kScxKfuncTable[] = {
#define EBPF_SCX_KFUNC(OP, KFUNC, GROUPS) {OP, KFUNC, static_cast<uint32_t>(GROUPS)},
#define EBPF_SCX_MEMBER(OPSTYPE, MEMBER, ALLOW, SLEEPABLE)
#define EBPF_SCX_GENERIC_KFUNC(KFUNC)
#define EBPF_SCX_TASKARGS(OPSTYPE, MEMBER, MASK)
#include "bpf-mlir/Support/ScxContract.def"
#undef EBPF_SCX_KFUNC
#undef EBPF_SCX_MEMBER
#undef EBPF_SCX_GENERIC_KFUNC
#undef EBPF_SCX_TASKARGS
};
inline constexpr ScxMemberInfo kScxMemberTable[] = {
#define EBPF_SCX_KFUNC(OP, KFUNC, GROUPS)
#define EBPF_SCX_MEMBER(OPSTYPE, MEMBER, ALLOW, SLEEPABLE) {OPSTYPE, MEMBER, static_cast<uint32_t>(ALLOW), SLEEPABLE},
#define EBPF_SCX_GENERIC_KFUNC(KFUNC)
#define EBPF_SCX_TASKARGS(OPSTYPE, MEMBER, MASK)
#include "bpf-mlir/Support/ScxContract.def"
#undef EBPF_SCX_KFUNC
#undef EBPF_SCX_MEMBER
#undef EBPF_SCX_GENERIC_KFUNC
#undef EBPF_SCX_TASKARGS
};
// sched_ext kfuncs of the generic ebpf.kfunc.call (struct_ops: sched_ext_ops only).
inline constexpr llvm::StringLiteral kScxGenericKfuncs[] = {
#define EBPF_SCX_KFUNC(OP, KFUNC, GROUPS)
#define EBPF_SCX_MEMBER(OPSTYPE, MEMBER, ALLOW, SLEEPABLE)
#define EBPF_SCX_GENERIC_KFUNC(KFUNC) KFUNC,
#define EBPF_SCX_TASKARGS(OPSTYPE, MEMBER, MASK)
#include "bpf-mlir/Support/ScxContract.def"
#undef EBPF_SCX_KFUNC
#undef EBPF_SCX_MEMBER
#undef EBPF_SCX_GENERIC_KFUNC
#undef EBPF_SCX_TASKARGS
};
// the members whose task arguments are in
// current->scx.kf_tasks[] (bit i = argument i), and the kfunc that needs it.
struct ScxTaskArgsInfo {
  llvm::StringLiteral opsType;
  llvm::StringLiteral member;
  uint32_t mask;
};
inline constexpr ScxTaskArgsInfo kScxTaskArgsTable[] = {
#define EBPF_SCX_KFUNC(OP, KFUNC, GROUPS)
#define EBPF_SCX_MEMBER(OPSTYPE, MEMBER, ALLOW, SLEEPABLE)
#define EBPF_SCX_GENERIC_KFUNC(KFUNC)
#define EBPF_SCX_TASKARGS(OPSTYPE, MEMBER, MASK) {OPSTYPE, MEMBER, static_cast<uint32_t>(MASK)},
#include "bpf-mlir/Support/ScxContract.def"
#undef EBPF_SCX_KFUNC
#undef EBPF_SCX_MEMBER
#undef EBPF_SCX_GENERIC_KFUNC
#undef EBPF_SCX_TASKARGS
};
inline constexpr llvm::StringLiteral kScxTaskCgroupKfunc = "scx_bpf_task_cgroup";
// 0 when the member has no task in kf_tasks (init_task, cgroup_prep_move, ...).
inline uint32_t scxTaskArgMask(llvm::StringRef opsType, llvm::StringRef member) {
  for (const ScxTaskArgsInfo &t : kScxTaskArgsTable)
    if (t.opsType == opsType && t.member == member)
      return t.mask;
  return 0;
}
inline std::string scxTaskArgMembers() {
  std::string out;
  for (const ScxTaskArgsInfo &t : kScxTaskArgsTable)
    out += (out.empty() ? "" : ", ") + t.member.str();
  return out;
}
inline bool isScxGenericKfunc(llvm::StringRef kfunc) {
  for (llvm::StringRef k : kScxGenericKfuncs)
    if (k == kfunc)
      return true;
  return false;
}

inline const ScxKfuncInfo *lookupScxOp(llvm::StringRef op) {
  for (const ScxKfuncInfo &k : kScxKfuncTable)
    if (k.op == op)
      return &k;
  return nullptr;
}
inline const ScxKfuncInfo *lookupScxKfunc(llvm::StringRef kfunc) {
  for (const ScxKfuncInfo &k : kScxKfuncTable)
    if (k.kfunc == kfunc)
      return &k;
  return nullptr;
}
inline const ScxMemberInfo *lookupScxMember(llvm::StringRef opsType, llvm::StringRef member) {
  for (const ScxMemberInfo &m : kScxMemberTable)
    if (m.opsType == opsType && m.member == member)
      return &m;
  return nullptr;
}
// Whether member (of sched_ext_ops) may call the kfunc of k: the kernel filter
// allows ANY everywhere, and otherwise a group of k that the member's allow
// flags include.
inline bool scxMemberAllows(const ScxKfuncInfo &k, llvm::StringRef opsType, llvm::StringRef member) {
  if (opsType != kScxOpsType)
    return false;
  if (k.groups & (ScxAny | ScxIdle))
    return true;
  const ScxMemberInfo *m = lookupScxMember(opsType, member);
  return m && (m->allow & k.groups);
}
// ops whose kfunc needs the RCU read section. KF_RCU_PROTECTED kfuncs
// (cpu_curr, dsq_peek) are rejected outside it, and pick_idle_cpu's cpumask
// (task->cpus_ptr, a BTF_TYPE_SAFE_RCU field) is MEM_RCU only inside it. The
// compiler has no explicit RCU lock (B2), so the section is the whole
// non-sleepable program (!in_sleepable(env) in 6.12.111 / 7.1.8 / 7.3.1).
// The rule is this contract, not the table's rcu_protected flag.
inline bool scxNeedsRcuSection(llvm::StringRef op) {
  return op == "cpu_curr" || op == "dsq_peek" || op == "pick_idle_cpu";
}
// the compiler allows scx.dump only in the dump members. The kernel puts
// scx_bpf_dump_bstr in the any set and fails it with scx_error outside
// ops.dump* (7.3.1 ext/ext.c:10225) — the compiler is the stricter side.
inline constexpr llvm::StringLiteral kScxDumpMembers[] = {"dump", "dump_cpu", "dump_task"};
inline bool scxDumpMember(llvm::StringRef opsType, llvm::StringRef member) {
  if (opsType != kScxOpsType)
    return false;
  for (llvm::StringRef m : kScxDumpMembers)
    if (m == member)
      return true;
  return false;
}
// the sched_ext ops a timer.callback owned by sched_ext_ops programs
// may use — ScxAny rows (the filter allows any in every member, 7.3.1
// ext/ext.c:11084-11085, and a callback inherits its owner's program —
// verifier.c:13407) without a context rule of their own: not dump (dump
// members only), not the RCU-section ops (scxNeedsRcuSection), no task
// argument (a callback has no task), no sleepable kfunc (the callback is not
// sleepable), and scx.const (no kfunc). Closed by name; the lowering-table unit
// test checks each row against the kfunc table and those rules.
inline constexpr llvm::StringLiteral kScxTimerCallbackOps[] = {
    "const", "error", "exit", "kick_cpu", "dsq_nr_queued", "now", "cpuperf_cap", "cpuperf_set", "dsq_reenq"};
inline bool scxTimerCallbackAllows(llvm::StringRef op) {
  for (llvm::StringRef o : kScxTimerCallbackOps)
    if (o == op)
      return true;
  return false;
}
inline std::string scxTimerCallbackOps() {
  std::string out;
  for (llvm::StringRef o : kScxTimerCallbackOps)
    out += (out.empty() ? "ebpf.scx." : ", ebpf.scx.") + o.str();
  return out;
}
inline bool scxSleepableMember(llvm::StringRef opsType, llvm::StringRef member) {
  const ScxMemberInfo *m = lookupScxMember(opsType, member);
  return m && m->sleepable;
}
// Members of opsType that may call k, in table order, for diagnostics.
inline std::string scxMembersAllowing(const ScxKfuncInfo &k) {
  if (k.groups & (ScxAny | ScxIdle))
    return "every sched_ext_ops member";
  std::string out;
  for (const ScxMemberInfo &m : kScxMemberTable)
    if (m.allow & k.groups)
      out += (out.empty() ? "" : ", ") + m.member.str();
  return out;
}
inline std::string scxSleepableMembers() {
  std::string out;
  for (const ScxMemberInfo &m : kScxMemberTable)
    if (m.sleepable)
      out += (out.empty() ? "" : ", ") + m.opsType.str() + "." + m.member.str();
  return out;
}

} // namespace bpfmlir

#endif
