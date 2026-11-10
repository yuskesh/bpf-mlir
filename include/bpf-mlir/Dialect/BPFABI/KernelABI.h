// UAPI contracts, not a kernel-version matrix. Existing numeric values remain
// stable across additions; per-target helper availability is a load-time
// requirement, never a compiler decision here. KernelABITable.inc is generated
// from abi/uapi.tsv: helper prototypes from uapi/linux/bpf.h, nullability from
// bpf_func_proto.ret_type, context layouts/verdicts and program/map type numbers
// from vmlinux BTF. Regenerate with developer ebpf-abigen extract/render.
#ifndef BPF_MLIR_DIALECT_BPFABI_KERNELABI_H
#define BPF_MLIR_DIALECT_BPFABI_KERNELABI_H

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace bpfmlir {
struct ProgramAttachInfo; // Attach rows are shared with bpf-mlir/Support/ProgramKinds.h.
} // namespace bpfmlir

namespace mlir {
namespace bpfabi {

// Helper result shape from the bpf.h prototype.
enum class RetKind { Void, Int, Ptr };

// Return nullability. If kernel sources do not establish it, lowering treats
// Unknown as nullable and bpfabi-verify reports Unknown.
enum class Nullability { NonNull, Nullable, Unknown };

struct HelperABI {
  llvm::StringLiteral name; // Name without bpf_, e.g. map_lookup_elem.
  int64_t id;               // enum bpf_func_id value.
  unsigned numArgs;
  RetKind retKind;
  Nullability nullability;

  // Add ret_nullable to IR, conservatively including Unknown.
  bool markNullable() const { return nullability != Nullability::NonNull; }
};

// Missing helpers return nullptr.
const HelperABI *lookupHelper(llvm::StringRef name);

// A prototype-derived range for variadic helpers; fixed helpers retain exact
// arity.
std::pair<unsigned, unsigned> helperArgumentRange(const HelperABI &helper);

struct PacketCtxABI {
  int64_t dataOffset;    // Context data byte offset.
  int64_t dataEndOffset; // Context data_end byte offset.
  int64_t fieldBytes;    // Required common data/data_end width.
};

// Return nullopt for kinds without data/data_end packet fields.
std::optional<PacketCtxABI> lookupPacketCtx(llvm::StringRef programKind);

// xdp_md data_meta / data offsets (UAPI ctxfield rows). nullopt for kinds without xdp_md.
struct MetaCtxABI {
  int64_t metaOffset; // Context data_meta byte offset.
  int64_t dataOffset; // Context data byte offset.
  int64_t fieldBytes; // Required common width.
};
std::optional<MetaCtxABI> lookupMetaCtx(llvm::StringRef programKind);

// Resolve a verdict name to its return value, else nullopt. Prefer the supplied
// attach row's family; without one require uniformVerdictFamily across all
// attaches. Names outside the kind table, such as redirect_map's xdp fallback,
// are interpreted as family names.
std::optional<int32_t> lookupVerdictValue(llvm::StringRef programKind,
                                          const bpfmlir::ProgramAttachInfo *row,
                                          llvm::StringRef action);
inline std::optional<int32_t> lookupVerdictValue(llvm::StringRef programKind,
                                                 llvm::StringRef action) {
  return lookupVerdictValue(programKind, nullptr, action);
}
// Verdict names in UAPI/HandVerdicts table order; done has only 'done'.
std::vector<std::string> verdictActions(llvm::StringRef family);

// Guaranteed helper-result alignment in bytes is kernel implementation
// evidence, not UAPI: array values round value_size to 8, hash values follow
// round_up(key_size,8), and ring reservations follow an 8-byte header with
// round_up(size+header,8). Annotate only this guaranteed load/store alignment.
inline constexpr unsigned kMapValueAlignment = 8;
// Packet-pointer variable umax above MAX_PACKET_OFF (0xffff) prevents
// data_end comparisons from establishing bounds. This is verifier
// implementation behavior (find_good_pkt_pointers), not UAPI.
inline constexpr int64_t kMaxPacketOffset = 0xffff;
// tp_btf contexts pack arguments into u64 slots (bpf_trace_run*): argument i
// is an 8-byte read at 8*i, like BPF_PROG. Kernel implementation, not UAPI.
inline constexpr int64_t kTracingArgBytes = 8;
// BPF_TRACE_RAW_TP return values are neither checked nor used. The compiler
// fixes non-verdict done to zero (verifier return_retval_range implementation).
inline constexpr int32_t kTpBtfDoneValue = 0;
// fentry returns must be zero: retval_range(0,0) on newer kernels and
// tnum_const(0) on 6.6.157. Verifier implementation contract, not UAPI.
inline constexpr int32_t kFentryDoneValue = 0;
// kprobe returns are unrestricted, but trace_kprobe omits perf samples for
// zero. done uses zero, matching the C oracle; kernel behavior, not UAPI.
inline constexpr int32_t kKprobeDoneValue = 0;
// raw_tp without attach_btf_id has no verifier return range, and
// __bpf_trace_run ignores its return. done is zero; implementation, not UAPI.
inline constexpr int32_t kRawTpDoneValue = 0;
// Iterators permit 0..1; bpf_iter_run_prog maps 1 to read -EAGAIN. done
// uses zero to continue. Kernel/verifier implementation, not UAPI.
inline constexpr int32_t kIterDoneValue = 0;
// syscall returns are unrestricted and become BPF_PROG_TEST_RUN retval.
// done is zero; ebpf.return supplies other values.
inline constexpr int32_t kSyscallDoneValue = 0;
// fmod_ret zero calls the original function; nonzero bypasses it and becomes
// the function result (invoke_bpf_mod_ret/BPF_MODIFY_RETURN). done is zero.
inline constexpr int32_t kFmodRetDoneValue = 0;
// Integer BPF_LSM_MAC hooks allow zero or deny with negative errno. The
// verifier enforces -MAX_ERRNO..0 via bpf_lsm_get_retval_range. done is zero.
// Kernel implementation behavior, not UAPI.
inline constexpr int32_t kLsmDoneValue = 0;
// Tracepoint returns have no verifier range. perf_trace_run_bpf_submit and
// perf_syscall_enter discard perf records when trace_call_bpf returns zero.
// done is zero (no record), like kprobe; implementation behavior, not UAPI.
inline constexpr int32_t kTracepointDoneValue = 0;
// tp_prog_is_valid_access limits tracepoint offsets below PERF_MAX_TRACE_SIZE
// (8192 in supported kernel sources). Conservatively require offset+width <=8192.
// The first sizeof(void*) bytes (8) become a pt_regs pointer and are unreadable.
// This is kernel implementation evidence, not UAPI.
inline constexpr int64_t kTracepointMaxCtx = 8192;
inline constexpr int64_t kTracepointFirstField = 8;
// perf_event returns have no verifier range. __perf_event_overflow drops the
// sample when bpf_overflow_handler returns zero; done is zero.
// Kernel implementation behavior, not UAPI.
inline constexpr int32_t kPerfEventDoneValue = 0;
// raw_tp.w follows raw_tp: unrestricted, ignored return; done is zero.
inline constexpr int32_t kRawTpWritableDoneValue = 0;
// lirc_mode2 ignores returns in lirc_bpf_run and has no special verifier
// range. done is zero, as in kernel selftests; implementation, not UAPI.
inline constexpr int32_t kLircMode2DoneValue = 0;
// struct_ops void members ignore R0; integer members have no verifier return
// range. check_return_code requires zero only for void/pointer return cases.
// done is zero for void members; integer members use ebpf.return.
// Kernel implementation behavior, not UAPI.
inline constexpr int32_t kStructOpsDoneValue = 0;
// struct_ops argument promotions live in StructOpsTypes.def PROMOTION rows
// and StructOpsTypes.h's structOpsArgBTFName.
inline constexpr unsigned kRingbufSampleAlignment = 8;

// Program/map enum values from lowercase names without UAPI prefixes, as in
// bpftool feature probe (xdp, array, percpu_array, ringbuf). Unknown is nullopt.
std::optional<int64_t> lookupProgType(llvm::StringRef name);
std::optional<int64_t> lookupMapType(llvm::StringRef name);
// Map update flags any/noexist/exist, or nullopt for unknown names.
std::optional<int64_t> lookupUpdateFlag(llvm::StringRef name);
// bpf_get_stackid flags: skip_field_mask/reuse_stackid from UAPI.
std::optional<int64_t> lookupStackFlag(llvm::StringRef name);
// Map-create flags: stack_build_id/no_prealloc from UAPI.
std::optional<int64_t> lookupMapFlag(llvm::StringRef name);
// Storage-get create flag: BPF_LOCAL_STORAGE_GET_F_CREATE.
std::optional<int64_t> lookupStorageFlag(llvm::StringRef name);
// sk_lookup bpf_sk_assign flags replace/no_reuseport (BPF_SK_LOOKUP_F_*).
std::optional<int64_t> lookupSkLookupFlag(llvm::StringRef name);
// bpf_l4_csum_replace flags pseudo_hdr/mark_mangled_0 (BPF_F_*).
std::optional<int64_t> lookupCsumFlag(llvm::StringRef name);
// bpf_skb_adjust_room modes net/mac (BPF_ADJ_ROOM_*).
std::optional<int64_t> lookupAdjRoomMode(llvm::StringRef name);
std::optional<int64_t> lookupHeaderStart(llvm::StringRef name);
std::optional<int64_t> lookupCsumLevel(llvm::StringRef name);
// fib_lookup flags — "none" is 0, "direct" is BPF_FIB_LOOKUP_DIRECT from
// the UAPI table; any other name is nullopt (outside the compiler's capability).
std::optional<int64_t> lookupFibFlag(llvm::StringRef name);
// the 11 named views of struct bpf_fib_lookup (UAPI fibfield rows), in
// offset order, covering the struct without gaps. Elem is the element width in
// bytes, Count the number of elements (1 for scalars).
struct FibFieldABI {
  llvm::StringLiteral Name;
  int64_t Offset, Elem, Count;
};
llvm::ArrayRef<FibFieldABI> fibFields();
// bpf_skb_{get,set}_tunnel_key flags by UAPI name without the BPF_F_
// prefix (tuninfo_ipv6, tuninfo_flags, zero_csum_tx, dont_fragment, seq_number,
// no_tunnel_key); "none" is 0. Any other name is nullopt. tuninfo_flags and
// no_tunnel_key share one bit (get and set use it differently).
std::optional<int64_t> lookupTunnelFlag(llvm::StringRef name);
// a comma-separated, duplicate-free flag set ("none", or names from the
// get set {tuninfo_ipv6, tuninfo_flags} / the set set {tuninfo_ipv6,
// zero_csum_tx, dont_fragment, seq_number, no_tunnel_key}) as its UAPI value;
// nullopt for an unknown, duplicated or wrong-direction name.
std::optional<int64_t> tunnelFlagsValue(llvm::StringRef spec, bool forSet);
// True when the set contains tuninfo_ipv6 (selects the "v6" view).
bool tunnelFlagsIpv6(llvm::StringRef spec);
// the leaves of the non-overlapping "v4" / "v6" views of struct
// bpf_tunnel_key (UAPI tunnelfield rows). A view does not cover the struct
// without gaps (v4 leaves skip the unused IPv6 words).
struct TunnelFieldABI {
  llvm::StringLiteral View, Name;
  int64_t Offset, Elem, Count;
};
llvm::ArrayRef<TunnelFieldABI> tunnelFields();
// the closed setsockopt / getsockopt option table (UAPI sockopt rows).
// Get is false for a set-only option.
struct SockOptABI {
  llvm::StringLiteral Name;
  int64_t Level, Optname;
  bool Get;
};
llvm::ArrayRef<SockOptABI> sockOptions();
// The row of `name`, or nullptr for a name outside the closed table.
const SockOptABI *lookupSockOption(llvm::StringRef name);
// the closed table of string socket options (UAPI sockoptname rows), set
// through a constant name.
struct SockOptNameABI {
  llvm::StringLiteral Name;
  int64_t Level, Optname;
};
llvm::ArrayRef<SockOptNameABI> sockOptionNames();
const SockOptNameABI *lookupSockOptionName(llvm::StringRef name);
// The compiler's conservative limit on the name's bytes, not a kernel contract:
// TCP_CA_NAME_MAX (16, include/net/tcp.h, not UAPI) minus the NUL. The kernel
// silently truncates a longer name, so a longer one is rejected here.
inline constexpr unsigned kSockOptNameMaxBytes = 15;
// bpf_sk_lookup_tcp / _udp netns values (current_netns = BPF_F_CURRENT_NETNS,
// −1) and the leaves of struct bpf_sock_tuple per family (ipv4 / ipv6).
std::optional<int64_t> lookupSkLookupNetns(llvm::StringRef name);
struct SockTupleFieldABI {
  llvm::StringLiteral Family, Name;
  int64_t Offset, Elem, Count;
};
llvm::ArrayRef<SockTupleFieldABI> sockTupleFields();
// firstmember rows — struct `from`'s offset-0 member is struct `to` (the
// verifier's btf_struct_ids_match walks it for a non-strict kfunc argument), so
// a pointer to `from` may be passed where a pointer to `to` is expected.
bool isFirstMemberOf(llvm::StringRef from, llvm::StringRef to);
// Pointer-free bpf_sys_bpf commands: map_create/map_get_fd_by_id/map_freeze.
std::optional<int64_t> lookupBpfCmd(llvm::StringRef name);
// SysBpfAttr.def bounds record size before the command's first pointer field.
// FirstPtr is a field name or '-' for no pointers; unknown cmd returns nullptr.
struct SysBpfAttrLimit {
  llvm::StringLiteral Cmd;
  int64_t MaxBytes;
  llvm::StringLiteral FirstPtr;
};
const SysBpfAttrLimit *lookupSysBpfAttrLimit(llvm::StringRef cmd);
// SEG6_LOCAL_ACTION_* names: end_x/end_t/end_dt6/end_b6/end_b6_encap.
std::optional<int64_t> lookupSeg6Action(llvm::StringRef name);
// Sockmap/sockhash redirect ingress flag: BPF_F_INGRESS.
std::optional<int64_t> lookupRedirFlag(llvm::StringRef name);
// perf_event_output current_cpu flag: BPF_F_CURRENT_CPU.
std::optional<int64_t> lookupPerfFlag(llvm::StringRef name);
// Ring record header hdr_sz: BPF_RINGBUF_HDR_SZ.
std::optional<int64_t> lookupRingbufConst(llvm::StringRef name);
// UAPI struct size, including map-value bpf_spin_lock BTF.
std::optional<int64_t> lookupUapiStructSize(llvm::StringRef name);
// timer_init clock monotonic: UAPI CLOCK_MONOTONIC; unknown is nullopt.
std::optional<int64_t> lookupClockId(llvm::StringRef name);
// timer_init clock names from the UAPI clockid rows ("monotonic" / "boottime"), quoted and joined for diagnostics.
std::string clockIdNames();
// Packet-pointer invalidating helpers from UAPI pktinval rows: the union of
// supported kernels' bpf_helper_changes_pkt_data source evidence.
bool isPacketInvalidatingHelper(llvm::StringRef name);
// GPL-only helpers from UAPI helpergpl rows: every proto the primary
// tree's get_func_proto returns has .gpl_only = true. Helpers whose protos mix
// or cannot be read have no row and are left to the kernel.
bool isGPLOnlyHelper(llvm::StringRef name);
// UAPI bpf_timer is __u64 __opaque[2], aligned(8). BTF lacks alignment, so
// this explicit value matches the kernel's offset % __alignof__(bpf_timer) check.
inline constexpr unsigned kTimerAlignment = 8;

// One-based kprobe argument n's pt_regs field, with UAPI offset and kernel
// name for target-BTF checking. Calling conventions are arch-specific; the
// current table covers x86_64 only. Unknown arch/n returns nullptr.
struct KprobeArgABI {
  llvm::StringLiteral arch;
  int n;
  llvm::StringLiteral uapiField, kernelField;
  int64_t offset, bytes;
};
const KprobeArgABI *lookupKprobeArg(llvm::StringRef arch, int n);
// Build __<pfx>_sys_<name> from UAPI syscallpfx (libbpf architecture prefix).
// Unknown arch returns nullopt.
std::optional<std::string> syscallWrapperSymbol(llvm::StringRef arch, llvm::StringRef name);
// One-based syscall argument n's user pt_regs field follows UAPI
// ksyscallarg/__PT_PARMn_SYSCALL_REG. It is an offset in the pt_regs pointed
// to by wrapper argument one, not the wrapper context itself. Unknown arch/n
// returns nullptr.
const KprobeArgABI *lookupKsyscallArg(llvm::StringRef arch, int n);
// Syscall argument count (six on x86_64), zero for unknown architectures.
int ksyscallArgCount(llvm::StringRef arch);
// Function argument count (six on x86_64), zero for unknown architectures.
int kprobeArgCount(llvm::StringRef arch);
// Return-register pt_regs field from UAPI kproberet/__PT_RC_REG. KprobeArgABI
// uses n=0 for return reads. Unknown arch returns nullptr.
const KprobeArgABI *lookupKprobeRet(llvm::StringRef arch);
// USDT argument registers follow libbpf reg_map order excluding rip. Index is
// the spec value's reg byte; names are comma-separated note spellings. Return
// architecture rows in index order (loader contract, specification section 8).
struct UsdtRegABI {
  llvm::StringLiteral arch;
  int index;
  llvm::StringLiteral uapiField, kernelField;
  int64_t offset, bytes;
  llvm::StringLiteral names;
};
llvm::ArrayRef<UsdtRegABI> usdtRegs();
// Compiler-defined USDT statuses, using errno-base ENOENT/EINVAL values, not
// helper results: lookup NULL for a cookie outside max_entries is -ENOENT.
// Kind zero (unwritten/unsupported location), unknown kind or unknown register
// is -EINVAL.
inline constexpr int64_t kUsdtNoSpecStatus = -2;
inline constexpr int64_t kUsdtBadSpecStatus = -22;
// Exclusive index bound for flexible context arrays (ctxfield count zero).
// bpf_tracing_ctx_access requires offset <8*MAX_BPF_FUNC_ARGS (12). This is
// implementation, not UAPI; attach can still reject a maximum read offset
// beyond actual tracepoint arity with bpf_probe_register -EINVAL.
inline constexpr int64_t kMaxFlexCtxIndex = 12;


// kfunc table: prototypes from vmlinux BTF, flags/program types from source
// BTF_ID_FLAGS/register_btf_kfunc_id_set. Flags are lowercase KF_* without
// prefix, comma-separated or '-'; types are void/i8..u64/*<struct>. Params
// are comma-separated <name>:<type> or '-'; progTypes uses bpf_prog_type names.
struct KfuncABI {
  llvm::StringLiteral name, flags, ret, params, progTypes;
  bool hasFlag(llvm::StringRef f) const;
  bool allowsProgType(llvm::StringRef progType) const;
  // Ordered argument (name,type) pairs.
  std::vector<std::pair<llvm::StringRef, llvm::StringRef>> paramList() const;
};
const KfuncABI *lookupKfunc(llvm::StringRef name);
// Generic-call diagnostics omit arena-role functions that only dedicated ops use.
std::string listKfuncs(bool genericCandidates = false);
// The whole kfunc table (the lowering-only / sleepable unit tests walk it).
llvm::ArrayRef<KfuncABI> kfuncTable();

// sched_ext enum constants for ebpf.scx.const: name, enum and the
// 64-bit pattern from vmlinux BTF ENUM / ENUM64 (UAPI table scxenum rows).
struct ScxEnumABI {
  llvm::StringLiteral name, enumName;
  uint64_t value;
};
const ScxEnumABI *lookupScxEnum(llvm::StringRef name);
std::string listScxEnums();

// struct_ops member facts from vmlinux BTF; kind is fptr or data.
struct StructOpsMemberABI {
  llvm::StringLiteral type, member, kind;
  int64_t bits;
};
const StructOpsMemberABI *lookupStructOpsMember(llvm::StringRef type, llvm::StringRef member);
// Is this type's bpf_struct_ops_<type> value represented in the UAPI member table?
bool hasStructOpsType(llvm::StringRef type);

// Context fields: flattened anonymous offsets, element width/count and
// int/ptr/struct kind from UAPI ctxfield rows.
struct StructFieldABI {
  llvm::StringLiteral strct, field;
  int64_t offset, bytes, count;
  llvm::StringLiteral kind;
};
const StructFieldABI *lookupStructField(llvm::StringRef strct, llvm::StringRef field);
// All struct fields in table order, for diagnostics.
std::vector<StructFieldABI> structFieldsOf(llvm::StringRef strct);

// Compiler context-access capabilities from abi/ctxaccess.tsv, established by
// context probes. progType/attachType use UAPI names ('-' for no attach type);
// mode is r/w, bytes is an allowed access width.
struct CtxAccessABI {
  llvm::StringLiteral progType, attachType, strct, field, mode;
  int64_t bytes;
};
const CtxAccessABI *lookupCtxAccess(llvm::StringRef progType, llvm::StringRef attachType, llvm::StringRef strct,
                                    llvm::StringRef field, llvm::StringRef mode);
// BTF struct attached by the verifier to a context pointer field, from
// ctxaccess.tsv's btf column (e.g. bpf_nf_ctx.state -> nf_hook_state). Such
// fields may only be read as !ebpf.kptr<btfStruct>. Missing entries are nullptr.
struct CtxBTFPtrABI {
  llvm::StringLiteral progType, attachType, strct, field, btfStruct;
};
const CtxBTFPtrABI *lookupCtxBTFPtr(llvm::StringRef progType, llvm::StringRef attachType, llvm::StringRef strct,
                                    llvm::StringRef field);
// Format fields with matching progType/attachType/struct/mode and widths,
// or '(none)' when absent.
std::string listCtxAccess(llvm::StringRef progType, llvm::StringRef attachType, llvm::StringRef strct, llvm::StringRef mode);

} // namespace bpfabi
} // namespace mlir

#endif // BPF_MLIR_DIALECT_BPFABI_KERNELABI_H
