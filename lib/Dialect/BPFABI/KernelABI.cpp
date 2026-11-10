//===- KernelABI.cpp - UAPI table access -----------------------------------===//
//
// KernelABITable.inc is generated from abi/uapi.tsv, extracted from kernel
// source and vmlinux BTF. KernelABI.h and TSV source rows document provenance.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/BPFABI/KernelABI.h"
#include "bpf-mlir/Support/ProgramKinds.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallVector.h"

using namespace mlir;
using namespace mlir::bpfabi;

namespace {

constexpr HelperABI kHelpers[] = {
#define BPFABI_HELPER(name, id, nargs, ret, nullable)                          \
  {name, id, nargs, ret, nullable},
#include "KernelABITable.inc"
};

struct VariadicHelperABI {
  llvm::StringLiteral name;
  unsigned minArgs, maxArgs;
};
constexpr VariadicHelperABI kVariadicHelpers[] = {
#define BPFABI_HELPER_VARIADIC(name, minArgs, maxArgs) {name, minArgs, maxArgs},
#include "KernelABITable.inc"
};

struct CtxFieldABI {
  llvm::StringLiteral kind, field;
  int64_t offset, bytes;
};

constexpr CtxFieldABI kCtxFields[] = {
#define BPFABI_CTX_FIELD(kind, field, offset, bytes) {kind, field, offset, bytes},
#include "KernelABITable.inc"
};

struct VerdictABI {
  llvm::StringLiteral kind, action;
  int32_t value;
};

constexpr VerdictABI kVerdicts[] = {
#define BPFABI_VERDICT(kind, action, value) {kind, action, value},
#include "KernelABITable.inc"
};

struct KindABI {
  llvm::StringLiteral name;
  int64_t id;
};

constexpr KindABI kProgTypes[] = {
#define BPFABI_PROG_TYPE(name, id) {name, id},
#include "KernelABITable.inc"
};

constexpr KindABI kMapTypes[] = {
#define BPFABI_MAP_TYPE(name, id) {name, id},
#include "KernelABITable.inc"
};

// BPF_ANY/BPF_NOEXIST/BPF_EXIST map-update flags.
constexpr KindABI kUpdateFlags[] = {
#define BPFABI_UPDATE_FLAG(name, value) {name, value},
#include "KernelABITable.inc"
};

// bpf_get_stackid skip_field_mask/reuse_stackid flags.
constexpr KindABI kStackFlags[] = {
#define BPFABI_STACK_FLAG(name, value) {name, value},
#include "KernelABITable.inc"
};
// Map-creation stack_build_id flag from the anonymous UAPI enum.
constexpr KindABI kMapFlags[] = {
#define BPFABI_MAP_FLAG(name, value) {name, value},
#include "KernelABITable.inc"
};

// UAPI struct sizes, including bpf_spin_lock.
constexpr KindABI kUapiStructs[] = {
#define BPFABI_UAPI_STRUCT(name, size) {name, size},
#include "KernelABITable.inc"
};

// bpf_timer_init clocks, including monotonic.
constexpr KindABI kClockIds[] = {
#define BPFABI_CLOCK_ID(name, value) {name, value},
#include "KernelABITable.inc"
};

// Packet-pointer-invalidating helpers (pktinval).
constexpr KindABI kPktInval[] = {
#define BPFABI_PKT_INVAL(name, id) {name, id},
#include "KernelABITable.inc"
};

// GPL-only helpers (helpergpl).
constexpr KindABI kHelperGPL[] = {
#define BPFABI_HELPER_GPL(name, id) {name, id},
#include "KernelABITable.inc"
};

// bpf_perf_event_output current_cpu flag.
constexpr KindABI kPerfFlags[] = {
#define BPFABI_PERF_FLAG(name, value) {name, value},
#include "KernelABITable.inc"
};

// Ring-buffer record header size (hdr_sz).
constexpr KindABI kRingbufConsts[] = {
#define BPFABI_RINGBUF_CONST(name, value) {name, value},
#include "KernelABITable.inc"
};

// Storage-get create flag (BPF_LOCAL_STORAGE_GET_F_CREATE).
constexpr KindABI kStorageFlags[] = {
#define BPFABI_STORAGE_FLAG(name, value) {name, value},
#include "KernelABITable.inc"
};

// bpf_sk_assign sk_lookup replace/no_reuseport flags.
constexpr KindABI kSkLookupFlags[] = {
#define BPFABI_SK_LOOKUP_FLAG(name, value) {name, value},
#include "KernelABITable.inc"
};

// bpf_l4_csum_replace flags pseudo_hdr/mark_mangled_0.
constexpr KindABI kCsumFlags[] = {
#define BPFABI_CSUM_FLAG(name, value) {name, value},
#include "KernelABITable.inc"
};

// bpf_skb_adjust_room modes net/mac.
constexpr KindABI kAdjRoomModes[] = {
#define BPFABI_ADJ_ROOM_MODE(name, value) {name, value},
#include "KernelABITable.inc"
};

// bpf_fib_lookup flags (direct) and struct bpf_fib_lookup views.
constexpr KindABI kHeaderStarts[] = {
#define BPFABI_HEADER_START(name, value) {name, value},
#include "KernelABITable.inc"
};
constexpr KindABI kCsumLevels[] = {
#define BPFABI_CSUM_LEVEL(name, value) {name, value},
#include "KernelABITable.inc"
};
constexpr KindABI kFibFlags[] = {
#define BPFABI_FIB_FLAG(name, value) {name, value},
#include "KernelABITable.inc"
};
constexpr KindABI kTunnelFlags[] = {
#define BPFABI_TUNNEL_FLAG(name, value) {name, value},
#include "KernelABITable.inc"
};
constexpr mlir::bpfabi::TunnelFieldABI kTunnelFields[] = {
#define BPFABI_TUNNEL_FIELD(view, name, offset, elem, count) {view, name, offset, elem, count},
#include "KernelABITable.inc"
};
constexpr mlir::bpfabi::SockOptABI kSockOptions[] = {
#define BPFABI_SOCKOPT(name, level, optname, get) {name, level, optname, get},
#include "KernelABITable.inc"
};
constexpr mlir::bpfabi::SockOptNameABI kSockOptionNames[] = {
#define BPFABI_SOCKOPT_NAME(name, level, optname) {name, level, optname},
#include "KernelABITable.inc"
};
constexpr mlir::bpfabi::FibFieldABI kFibFields[] = {
#define BPFABI_FIB_FIELD(name, offset, elem, count) {name, offset, elem, count},
#include "KernelABITable.inc"
};

// bpf_sk_lookup_tcp / _udp netns value and struct bpf_sock_tuple leaves.
constexpr KindABI kSkLookupNetns[] = {
#define BPFABI_SK_LOOKUP_NETNS(name, value) {name, value},
#include "KernelABITable.inc"
};
constexpr mlir::bpfabi::SockTupleFieldABI kSockTupleFields[] = {
#define BPFABI_SOCK_TUPLE_FIELD(family, name, offset, elem, count) {family, name, offset, elem, count},
#include "KernelABITable.inc"
};

// bpf_sys_bpf commands: map_create/map_get_fd_by_id/map_freeze.
constexpr KindABI kBpfCmds[] = {
#define BPFABI_BPF_CMD(name, value) {name, value},
#include "KernelABITable.inc"
};

// Per-command attr size limits are owned exclusively by SysBpfAttr.def.
constexpr mlir::bpfabi::SysBpfAttrLimit kSysBpfAttrLimits[] = {
#define SYSBPF_ATTR(cmd, maxBytes, anchor, firstPtr, source) {llvm::StringLiteral(cmd), maxBytes, llvm::StringLiteral(firstPtr)},
#include "bpf-mlir/Dialect/BPFABI/SysBpfAttr.def"
};

// bpf_lwt_seg6_action actions.
constexpr KindABI kSeg6Actions[] = {
#define BPFABI_SEG6_ACTION(name, value) {name, value},
#include "KernelABITable.inc"
};
// Sockmap/sockhash redirect ingress flag (BPF_F_INGRESS).
constexpr KindABI kRedirFlags[] = {
#define BPFABI_REDIR_FLAG(name, value) {name, value},
#include "KernelABITable.inc"
};

// x86_64 pt_regs fields for kprobe arguments.
constexpr KprobeArgABI kKprobeArgs[] = {
#define BPFABI_KPROBE_ARG(arch, n, uapi, kernel, offset, bytes) {arch, n, uapi, kernel, offset, bytes},
#include "KernelABITable.inc"
};

// Return-probe register is KprobeArgABI index zero.
constexpr KprobeArgABI kKprobeRets[] = {
#define BPFABI_KPROBE_RET(arch, uapi, kernel, offset, bytes) {arch, 0, uapi, kernel, offset, bytes},
#include "KernelABITable.inc"
};

// USDT location registers ordered by spec-map register index.
constexpr UsdtRegABI kUsdtRegs[] = {
#define BPFABI_USDT_REG(arch, index, uapi, kernel, offset, bytes, names) {arch, index, uapi, kernel, offset, bytes, names},
#include "KernelABITable.inc"
};


// libbpf arch_specific_syscall_pfx forms wrappers as __<pfx>_sys_<name>.
struct SyscallPrefixABI {
  llvm::StringLiteral arch, prefix;
};
constexpr SyscallPrefixABI kSyscallPrefixes[] = {
#define BPFABI_SYSCALL_PREFIX(arch, prefix) {arch, prefix},
#include "KernelABITable.inc"
};

// User pt_regs syscall arguments follow __PT_PARMn_SYSCALL_REG; x86_64 arg4 uses r10.
constexpr KprobeArgABI kKsyscallArgs[] = {
#define BPFABI_KSYSCALL_ARG(arch, n, uapi, kernel, offset, bytes) {arch, n, uapi, kernel, offset, bytes},
#include "KernelABITable.inc"
};

// kfunc types come from vmlinux BTF; flags/program types come from kernel source.
constexpr KfuncABI kKfuncs[] = {
#define BPFABI_KFUNC(name, flags, ret, params, progTypes) {name, flags, ret, params, progTypes},
#include "KernelABITable.inc"
};

// Context struct fields and read/write capabilities.
constexpr StructFieldABI kStructFields[] = {
#define BPFABI_STRUCT_FIELD(strct, field, offset, bytes, count, kind) {strct, field, offset, bytes, count, kind},
#include "KernelABITable.inc"
};
constexpr CtxAccessABI kCtxAccess[] = {
#define BPFABI_CTX_ACCESS(ptype, atype, strct, field, mode, bytes) {ptype, atype, strct, field, mode, bytes},
#include "KernelABITable.inc"
};
// Context pointer pointees are abi/ctxaccess.tsv column eight (btf).
// The final empty sentinel permits an array even when no rows exist.
constexpr CtxBTFPtrABI kCtxBTFPtrs[] = {
#define BPFABI_CTX_BTF_PTR(ptype, atype, strct, field, btfStruct) {ptype, atype, strct, field, btfStruct},
#include "KernelABITable.inc"
    {"", "", "", "", ""},
};

template <size_t N>
std::optional<int64_t> lookupKind(const KindABI (&table)[N],
                                  llvm::StringRef name) {
  for (const KindABI &k : table)
    if (k.name == name)
      return k.id;
  return std::nullopt;
}

const CtxFieldABI *lookupField(llvm::StringRef kind, llvm::StringRef field) {
  for (const CtxFieldABI &f : kCtxFields)
    if (f.kind == kind && f.field == field)
      return &f;
  return nullptr;
}

} // namespace

const HelperABI *mlir::bpfabi::lookupHelper(llvm::StringRef name) {
  for (const HelperABI &h : kHelpers)
    if (h.name == name)
      return &h;
  return nullptr;
}

std::pair<unsigned, unsigned>
mlir::bpfabi::helperArgumentRange(const HelperABI &helper) {
  for (const auto &range : kVariadicHelpers)
    if (range.name == helper.name)
      return {range.minArgs, range.maxArgs};
  return {helper.numArgs, helper.numArgs};
}

std::optional<PacketCtxABI>
mlir::bpfabi::lookupPacketCtx(llvm::StringRef programKind) {
  // ProgramKinds.def PACKET selects bounds fields: data/data_end for xdp and
  // __sk_buff families, optval/optval_end for cgroup_sockopt.
  const bpfmlir::ProgramKindInfo *k = bpfmlir::lookupProgramKind(programKind);
  llvm::StringRef startName, endName;
  if (!k || !bpfmlir::packetRangeOf(*k, startName, endName))
    return std::nullopt;
  const CtxFieldABI *data = lookupField(programKind, startName);
  const CtxFieldABI *end = lookupField(programKind, endName);
  if (!data || !end || data->bytes != end->bytes)
    return std::nullopt;
  return PacketCtxABI{data->offset, end->offset, data->bytes};
}

// Non-UAPI-named verdict values; HandVerdicts.def rows carry source evidence.
struct HandVerdictABI {
  llvm::StringLiteral family, action;
  int32_t value;
};
constexpr HandVerdictABI kHandVerdicts[] = {
#define EBPF_HAND_VERDICT(family, action, value, why) {family, action, value},
#include "bpf-mlir/Support/HandVerdicts.def"
};

// Resolve through attachment verdict families: ABI verdict rows, hand values
// or done. Unlisted kind names (such as redirect_map fallback xdp) are treated
// as family names. Op verifiers own allowed verdict subsets; this only finds values.
std::optional<int32_t>
mlir::bpfabi::lookupVerdictValue(llvm::StringRef programKind,
                                 const bpfmlir::ProgramAttachInfo *row,
                                 llvm::StringRef action) {
  llvm::StringRef family = programKind;
  if (row) {
    llvm::SmallVector<llvm::StringRef> subset;
    family = bpfmlir::verdictFamily(*row, subset);
  } else if (const bpfmlir::ProgramKindInfo *k = bpfmlir::lookupProgramKind(programKind)) {
    // Without an attachment, resolve only if every row shares a verdict family.
  // Otherwise callers must reject the ambiguous value explicitly.
    std::optional<llvm::StringRef> f = bpfmlir::uniformVerdictFamily(*k);
    if (!f)
      return std::nullopt;
    family = *f;
  }
  for (const VerdictABI &v : kVerdicts)
    if (v.kind == family && v.action == action)
      return v.value;
  for (const HandVerdictABI &v : kHandVerdicts)
    if (v.family == family && v.action == action)
      return v.value;
  // Non-verdict done values are hand-maintained outside UAPI. ProgramKinds.def
  // DONE assigns them to kinds; KernelABI.h documents each constant's evidence.
  if (family == "done" && action == "done") {
#define EBPF_PROGRAM_KIND(NAME, PTYPE, ATTACH, ARCH, PACKET, CTX, SIG, OPS, DONE)                                                         \
  if (programKind == NAME)                                                                                             \
    return std::optional<int32_t>(DONE);
#include "bpf-mlir/Support/ProgramKinds.def"
  }
  return std::nullopt;
}

std::vector<std::string> mlir::bpfabi::verdictActions(llvm::StringRef family) {
  std::vector<std::string> out;
  if (family == "done")
    return {"done"};
  for (const VerdictABI &v : kVerdicts)
    if (v.kind == family)
      out.push_back(v.action.str());
  for (const HandVerdictABI &v : kHandVerdicts)
    if (v.family == family)
      out.push_back(v.action.str());
  return out;
}

std::optional<int64_t> mlir::bpfabi::lookupProgType(llvm::StringRef name) {
  return lookupKind(kProgTypes, name);
}

std::optional<int64_t> mlir::bpfabi::lookupMapType(llvm::StringRef name) {
  return lookupKind(kMapTypes, name);
}

std::optional<int64_t> mlir::bpfabi::lookupUapiStructSize(llvm::StringRef name) {
  return lookupKind(kUapiStructs, name);
}

bool mlir::bpfabi::isPacketInvalidatingHelper(llvm::StringRef name) {
  return lookupKind(kPktInval, name).has_value();
}

bool mlir::bpfabi::isGPLOnlyHelper(llvm::StringRef name) {
  return lookupKind(kHelperGPL, name).has_value();
}

std::optional<int64_t> mlir::bpfabi::lookupClockId(llvm::StringRef name) {
  return lookupKind(kClockIds, name);
}

std::string mlir::bpfabi::clockIdNames() {
  std::string out;
  for (const KindABI &k : kClockIds)
    out += (out.empty() ? "\"" : " / \"") + k.name.str() + "\"";
  return out;
}

std::optional<int64_t> mlir::bpfabi::lookupPerfFlag(llvm::StringRef name) {
  return lookupKind(kPerfFlags, name);
}

std::optional<int64_t> mlir::bpfabi::lookupRingbufConst(llvm::StringRef name) {
  return lookupKind(kRingbufConsts, name);
}

std::optional<int64_t> mlir::bpfabi::lookupStorageFlag(llvm::StringRef name) {
  return lookupKind(kStorageFlags, name);
}

std::optional<int64_t> mlir::bpfabi::lookupSkLookupFlag(llvm::StringRef name) {
  return lookupKind(kSkLookupFlags, name);
}

std::optional<int64_t> mlir::bpfabi::lookupCsumFlag(llvm::StringRef name) {
  return lookupKind(kCsumFlags, name);
}

std::optional<int64_t> mlir::bpfabi::lookupAdjRoomMode(llvm::StringRef name) {
  return lookupKind(kAdjRoomModes, name);
}
std::optional<int64_t> mlir::bpfabi::lookupHeaderStart(llvm::StringRef name) {
  return lookupKind(kHeaderStarts, name);
}
std::optional<int64_t> mlir::bpfabi::lookupCsumLevel(llvm::StringRef name) {
  return lookupKind(kCsumLevels, name);
}

std::optional<int64_t> mlir::bpfabi::lookupFibFlag(llvm::StringRef name) {
  if (name == "none")
    return 0;
  return lookupKind(kFibFlags, name);
}

llvm::ArrayRef<mlir::bpfabi::FibFieldABI> mlir::bpfabi::fibFields() { return kFibFields; }
std::optional<int64_t> mlir::bpfabi::lookupSkLookupNetns(llvm::StringRef name) {
  return lookupKind(kSkLookupNetns, name);
}
llvm::ArrayRef<mlir::bpfabi::SockTupleFieldABI> mlir::bpfabi::sockTupleFields() { return kSockTupleFields; }

std::optional<int64_t> mlir::bpfabi::lookupTunnelFlag(llvm::StringRef name) {
  if (name == "none")
    return 0;
  return lookupKind(kTunnelFlags, name);
}

std::optional<int64_t> mlir::bpfabi::tunnelFlagsValue(llvm::StringRef spec, bool forSet) {
  if (spec == "none")
    return 0;
  static const llvm::StringLiteral kGet[] = {"tuninfo_ipv6", "tuninfo_flags"};
  static const llvm::StringLiteral kSet[] = {"tuninfo_ipv6", "zero_csum_tx", "dont_fragment", "seq_number",
                                              "no_tunnel_key"};
  llvm::ArrayRef<llvm::StringLiteral> allowed = forSet ? llvm::ArrayRef<llvm::StringLiteral>(kSet)
                                                       : llvm::ArrayRef<llvm::StringLiteral>(kGet);
  int64_t value = 0;
  llvm::SmallVector<llvm::StringRef> seen;
  llvm::SmallVector<llvm::StringRef> parts;
  spec.split(parts, ',');
  for (llvm::StringRef p : parts) {
    if (!llvm::is_contained(allowed, p) || llvm::is_contained(seen, p))
      return std::nullopt;
    std::optional<int64_t> v = lookupKind(kTunnelFlags, p);
    if (!v)
      return std::nullopt;
    seen.push_back(p);
    value |= *v;
  }
  return value;
}

bool mlir::bpfabi::tunnelFlagsIpv6(llvm::StringRef spec) {
  llvm::SmallVector<llvm::StringRef> parts;
  spec.split(parts, ',');
  return llvm::is_contained(parts, "tuninfo_ipv6");
}

llvm::ArrayRef<mlir::bpfabi::TunnelFieldABI> mlir::bpfabi::tunnelFields() { return kTunnelFields; }

llvm::ArrayRef<mlir::bpfabi::SockOptABI> mlir::bpfabi::sockOptions() { return kSockOptions; }

const mlir::bpfabi::SockOptABI *mlir::bpfabi::lookupSockOption(llvm::StringRef name) {
  for (const SockOptABI &row : kSockOptions)
    if (row.Name == name)
      return &row;
  return nullptr;
}

llvm::ArrayRef<mlir::bpfabi::SockOptNameABI> mlir::bpfabi::sockOptionNames() { return kSockOptionNames; }

const mlir::bpfabi::SockOptNameABI *mlir::bpfabi::lookupSockOptionName(llvm::StringRef name) {
  for (const SockOptNameABI &row : kSockOptionNames)
    if (row.Name == name)
      return &row;
  return nullptr;
}

bool mlir::bpfabi::isFirstMemberOf(llvm::StringRef from, llvm::StringRef to) {
  struct Pair {
    llvm::StringLiteral From, To;
  };
  static constexpr Pair kFirstMembers[] = {
#define BPFABI_FIRST_MEMBER(outer, inner) {outer, inner},
#include "KernelABITable.inc"
  };
  for (const Pair &p : kFirstMembers)
    if (p.From == from && p.To == to)
      return true;
  return false;
}

std::optional<int64_t> mlir::bpfabi::lookupBpfCmd(llvm::StringRef name) {
  return lookupKind(kBpfCmds, name);
}

const mlir::bpfabi::SysBpfAttrLimit *mlir::bpfabi::lookupSysBpfAttrLimit(llvm::StringRef cmd) {
  for (const SysBpfAttrLimit &l : kSysBpfAttrLimits)
    if (l.Cmd == cmd)
      return &l;
  return nullptr;
}

std::optional<int64_t> mlir::bpfabi::lookupSeg6Action(llvm::StringRef name) {
  return lookupKind(kSeg6Actions, name);
}

std::optional<int64_t> mlir::bpfabi::lookupRedirFlag(llvm::StringRef name) {
  return lookupKind(kRedirFlags, name);
}

std::optional<int64_t> mlir::bpfabi::lookupStackFlag(llvm::StringRef name) {
  return lookupKind(kStackFlags, name);
}

std::optional<int64_t> mlir::bpfabi::lookupMapFlag(llvm::StringRef name) {
  return lookupKind(kMapFlags, name);
}

std::optional<int64_t> mlir::bpfabi::lookupUpdateFlag(llvm::StringRef name) {
  return lookupKind(kUpdateFlags, name);
}

std::optional<std::string> mlir::bpfabi::syscallWrapperSymbol(llvm::StringRef arch, llvm::StringRef name) {
  for (const SyscallPrefixABI &s : kSyscallPrefixes)
    if (s.arch == arch)
      return ("__" + s.prefix + "_sys_" + name).str();
  return std::nullopt;
}

const KprobeArgABI *mlir::bpfabi::lookupKprobeArg(llvm::StringRef arch, int n) {
  for (const KprobeArgABI &k : kKprobeArgs)
    if (k.arch == arch && k.n == n)
      return &k;
  return nullptr;
}

const KprobeArgABI *mlir::bpfabi::lookupKsyscallArg(llvm::StringRef arch, int n) {
  for (const KprobeArgABI &k : kKsyscallArgs)
    if (k.arch == arch && k.n == n)
      return &k;
  return nullptr;
}

int mlir::bpfabi::ksyscallArgCount(llvm::StringRef arch) {
  int c = 0;
  for (const KprobeArgABI &k : kKsyscallArgs)
    c += k.arch == arch;
  return c;
}

const KprobeArgABI *mlir::bpfabi::lookupKprobeRet(llvm::StringRef arch) {
  for (const KprobeArgABI &k : kKprobeRets)
    if (k.arch == arch)
      return &k;
  return nullptr;
}

llvm::ArrayRef<UsdtRegABI> mlir::bpfabi::usdtRegs() { return kUsdtRegs; }

// Test membership in a comma-separated kfunc-table spelling.
static bool inCommaList(llvm::StringRef list, llvm::StringRef s) {
  llvm::SmallVector<llvm::StringRef> parts;
  list.split(parts, ',');
  return llvm::is_contained(parts, s);
}
bool KfuncABI::hasFlag(llvm::StringRef f) const { return flags != "-" && inCommaList(flags, f); }
bool KfuncABI::allowsProgType(llvm::StringRef progType) const { return inCommaList(progTypes, progType); }
std::vector<std::pair<llvm::StringRef, llvm::StringRef>> KfuncABI::paramList() const {
  std::vector<std::pair<llvm::StringRef, llvm::StringRef>> out;
  if (params == "-")
    return out;
  llvm::SmallVector<llvm::StringRef> parts;
  llvm::StringRef(params).split(parts, ',');
  for (llvm::StringRef p : parts)
    out.push_back(p.split(':'));
  return out;
}
const KfuncABI *mlir::bpfabi::lookupKfunc(llvm::StringRef name) {
  for (const KfuncABI &k : kKfuncs)
    if (k.name == name)
      return &k;
  return nullptr;
}
namespace {
constexpr ScxEnumABI kScxEnums[] = {
#define BPFABI_SCX_ENUM(name, enumName, value) {name, enumName, value},
#include "KernelABITable.inc"
};
} // namespace
const ScxEnumABI *mlir::bpfabi::lookupScxEnum(llvm::StringRef name) {
  for (const ScxEnumABI &e : kScxEnums)
    if (e.name == name)
      return &e;
  return nullptr;
}
std::string mlir::bpfabi::listScxEnums() {
  std::string out;
  for (const ScxEnumABI &e : kScxEnums)
    out += (out.empty() ? "" : ", ") + e.name.str();
  return out;
}
// struct_ops members from ABI structopsmember rows.
namespace {
constexpr StructOpsMemberABI kStructOpsMembers[] = {
#define BPFABI_STRUCT_OPS_MEMBER(type, member, kind, bits) {type, member, kind, bits},
#include "KernelABITable.inc"
};
} // namespace
const StructOpsMemberABI *mlir::bpfabi::lookupStructOpsMember(llvm::StringRef type, llvm::StringRef member) {
  for (const StructOpsMemberABI &m : kStructOpsMembers)
    if (m.type == type && m.member == member)
      return &m;
  return nullptr;
}
bool mlir::bpfabi::hasStructOpsType(llvm::StringRef type) {
  for (const StructOpsMemberABI &m : kStructOpsMembers)
    if (m.type == type)
      return true;
  return false;
}
llvm::ArrayRef<mlir::bpfabi::KfuncABI> mlir::bpfabi::kfuncTable() { return kKfuncs; }
std::string mlir::bpfabi::listKfuncs(bool genericCandidates) {
  std::string out;
  for (const KfuncABI &k : kKfuncs) {
    if (genericCandidates && (k.hasFlag("arena_arg2") || k.hasFlag("arena_ret")))
      continue;
    out += (out.empty() ? "\"" : ", \"") + k.name.str() + "\"";
  }
  return out;
}

int mlir::bpfabi::kprobeArgCount(llvm::StringRef arch) {
  int c = 0;
  for (const KprobeArgABI &k : kKprobeArgs)
    if (k.arch == arch)
      ++c;
  return c;
}

const StructFieldABI *mlir::bpfabi::lookupStructField(llvm::StringRef strct, llvm::StringRef field) {
  for (const StructFieldABI &f : kStructFields)
    if (f.strct == strct && f.field == field)
      return &f;
  return nullptr;
}

std::vector<StructFieldABI> mlir::bpfabi::structFieldsOf(llvm::StringRef strct) {
  std::vector<StructFieldABI> out;
  for (const StructFieldABI &f : kStructFields)
    if (f.strct == strct)
      out.push_back(f);
  return out;
}

const CtxAccessABI *mlir::bpfabi::lookupCtxAccess(llvm::StringRef progType, llvm::StringRef attachType, llvm::StringRef strct,
                                                  llvm::StringRef field, llvm::StringRef mode) {
  for (const CtxAccessABI &a : kCtxAccess)
    if (a.progType == progType && a.attachType == attachType && a.strct == strct && a.field == field && a.mode == mode)
      return &a;
  return nullptr;
}

const CtxBTFPtrABI *mlir::bpfabi::lookupCtxBTFPtr(llvm::StringRef progType, llvm::StringRef attachType, llvm::StringRef strct,
                                                  llvm::StringRef field) {
  for (const CtxBTFPtrABI &p : kCtxBTFPtrs)
    if (!p.btfStruct.empty() && p.progType == progType && p.attachType == attachType && p.strct == strct && p.field == field)
      return &p;
  return nullptr;
}

std::string mlir::bpfabi::listCtxAccess(llvm::StringRef progType, llvm::StringRef attachType, llvm::StringRef strct,
                                        llvm::StringRef mode) {
  std::string out;
  for (const CtxAccessABI &a : kCtxAccess)
    if (a.progType == progType && a.attachType == attachType && a.strct == strct && a.mode == mode) {
      if (!out.empty())
        out += ", ";
      out += "\"" + a.field.str() + "\" (" + std::to_string(a.bytes) + " bytes)";
    }
  return out.empty() ? "(none)" : out;
}

// only xdp has a data_meta field in the packet context (xdp_md); the
// offsets come from the UAPI ctxfield rows, not from a constant here.
std::optional<mlir::bpfabi::MetaCtxABI>
mlir::bpfabi::lookupMetaCtx(llvm::StringRef programKind) {
  if (programKind != "xdp")
    return std::nullopt;
  const StructFieldABI *meta = lookupStructField("xdp_md", "data_meta");
  const StructFieldABI *data = lookupStructField("xdp_md", "data");
  if (!meta || !data || meta->bytes != data->bytes)
    return std::nullopt;
  return MetaCtxABI{meta->offset, data->offset, meta->bytes};
}
