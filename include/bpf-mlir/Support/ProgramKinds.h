// Header-only queries shared by schema, op verification and ABI lowering.
// ProgramKinds.def owns kind properties; ProgramAttaches.def owns sections,
// attach types, requirements and verdicts. Per-op restrictions stay in verifiers.
#ifndef BPF_MLIR_SUPPORT_PROGRAMKINDS_H
#define BPF_MLIR_SUPPORT_PROGRAMKINDS_H

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/STLFunctionalExtras.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"

#include <optional>
#include <string>
#include <tuple>

namespace bpfmlir {

// Attach shapes: directions/hooks are enumerated by ProgramAttaches.def, not
// duplicate lists. MapSymbol values come from schema attach_target, never the
// section. TracefsEvent uses exactly <category>/<event>. ProgFunc identifies
// the global BPF replacement function; its entry uses the replacement signature
// and ebpf.ext.arg rather than a context pointer. StructOpsMap names a schema
// map absent from the program's ordinary maps and from its section; member
// implementations come from struct_ops.ops. CgroupHook's empty row supplies
// the default hook when omitted. Multi kernel/user name lists live in
// attach_list/schema attach_target, not section suffixes; index i is mtarget i
// and the loader cookie, as specified in docs/requirements_format.md section 8.
enum class AttachForm { None, Tracepoint, KernelFunc, UserSymbol, TcxDirection, CgroupDirection, IterTarget, SockoptHook, LsmHook, MapSymbol, TracefsEvent, ProgFunc, StructOpsMap, CgroupHook,
                        KernelFuncList, UserSymbolList, UsdtProbe, ReuseportHook, SyscallName };
// ReuseportHook defaults to select (empty row); migrate selects
// select_or_migrate. UsdtProbe uses C identifiers <provider>:<name> in schema,
// not in the suffix-free usdt section; point locations come from binary notes.
// SyscallName is an unprefixed C identifier, excluding sys_/__ prefixes. Its
// section is ksyscall/<name>; emitted requirements name the kernel wrapper
// derived from schema architecture and UAPI syscallpfx.
inline bool isSyscallName(llvm::StringRef v) {
  if (v.empty() || v.starts_with("sys_") || v.starts_with("__") || !(llvm::isAlpha(v.front()) || v.front() == '_'))
    return false;
  return llvm::all_of(v, [](char c) { return llvm::isAlnum(c) || c == '_'; });
}

// Multi-probe attach values are name lists.
inline bool isAttachList(AttachForm f) { return f == AttachForm::KernelFuncList || f == AttachForm::UserSymbolList; }
// User symbol families: uprobe/uretprobe and their multi variants.
inline bool attachesUserSymbol(AttachForm f) { return f == AttachForm::UserSymbol || f == AttachForm::UserSymbolList; }
// User binary families with schema binary_sha256: symbol probes and USDT.
inline bool attachesUserBinary(AttachForm f) { return attachesUserSymbol(f) || f == AttachForm::UsdtProbe; }

// USDT <provider>:<name> requires two C identifiers, as in requirements.
inline bool isUsdtProbeName(llvm::StringRef v) {
  auto ident = [](llvm::StringRef s) {
    if (s.empty() || !(llvm::isAlpha(s[0]) || s[0] == '_'))
      return false;
    return llvm::all_of(s, [](char c) { return llvm::isAlnum(c) || c == '_'; });
  };
  auto [prov, name] = v.split(':');
  return v.count(':') == 1 && ident(prov) && ident(name);
}

// Tracefs <category>/<event>: two nonempty names and exactly one slash.
inline bool isTracefsEventName(llvm::StringRef v) {
  auto [cat, ev] = v.split('/');
  return !cat.empty() && !ev.empty() && !ev.contains('/');
}

// Most entries take one context pointer. ext entries take the replacement's
// arguments, read by ebpf.ext.arg: ABI registers are i64, while BTF FUNC_PROTO
// follows the schema signature.
inline bool entryTakesCtx(AttachForm f) { return f != AttachForm::ProgFunc; }

// Schema-map attach values must be recovered from attach_target, not ELF section.
inline bool attachFromSchemaMap(AttachForm f) { return f == AttachForm::MapSymbol || f == AttachForm::StructOpsMap; }

// Schema signature families: return probes, iterators and integer fmod_ret args.
enum class SigFamily { None, TpArgs, FuncArgs, FuncRet, Probe, ProbeRet, Iter, IntArgs, HookArgs, ExtSig, OpsSig }; // LSM struct/integer/nullable args, ext count/return/args and struct_ops
// count/integer-or-void-return/args.

struct ProgramKindInfo {
  llvm::StringLiteral name, progType;
  AttachForm attach; // Attach value shape; concrete values/sections come from attach rows.
  bool arch;
  llvm::StringLiteral packetRange; // Context packet bounds: data,data_end or optval,optval_end; '-' means absent.
  llvm::StringLiteral ctxStruct;   // '-' means absent.
  SigFamily sig;
  llvm::StringLiteral ops;         // Space-separated tags for kind-limited operations.
};

inline constexpr ProgramKindInfo kProgramKindTable[] = {
#define EBPF_PROGRAM_KIND(NAME, PTYPE, ATTACH, ARCH, PACKET, CTX, SIG, OPS, DONE)                                                         \
  {NAME, PTYPE, AttachForm::ATTACH, ARCH, PACKET, CTX, SigFamily::SIG, OPS},
#include "bpf-mlir/Support/ProgramKinds.def"
};

// One ProgramAttaches.def row; every kind has at least one.
struct ProgramAttachInfo {
  llvm::StringLiteral kind;       // NAME in the kind table.
  llvm::StringLiteral attach;     // Empty (omitted), '*' (free value), or an enumerated value.
  llvm::StringLiteral section;    // '{}' substitutes the free value on '*' rows.
  llvm::StringLiteral attachType; // expected_attach_type spelling, or '-'.
  llvm::StringLiteral reqAttach;  // Requirements '<type> <target>', or '-'.
  llvm::StringLiteral verdicts;   // Verdict family: <family>[:<verdict>,...][|int[:<range>]].
};

inline constexpr ProgramAttachInfo kProgramAttachTable[] = {
#define EBPF_PROGRAM_ATTACH(KIND, ATTACH, SECTION, ATYPE, REQATTACH, VERDICTS) {KIND, ATTACH, SECTION, ATYPE, REQATTACH, VERDICTS},
#include "bpf-mlir/Support/ProgramAttaches.def"
};

// Rows sharing SECTION (default and explicit enumerated values) must agree
// on ATTACHTYPE, REQATTACH and VERDICTS. kindOfSection returns the first row;
// disagreement would silently change requirements or ABI verdict checks.
// Enforce the same invariant as the developer Go checkProgramAttaches check.
namespace detail {
constexpr bool sameLiteral(llvm::StringLiteral a, llvm::StringLiteral b) {
  if (a.size() != b.size())
    return false;
  for (size_t i = 0; i < a.size(); ++i)
    if (a.data()[i] != b.data()[i])
      return false;
  return true;
}
constexpr bool sameSectionRowsAgree() {
  for (const ProgramAttachInfo &a : kProgramAttachTable)
    for (const ProgramAttachInfo &b : kProgramAttachTable)
      if (sameLiteral(a.section, b.section) &&
          !(sameLiteral(a.attachType, b.attachType) && sameLiteral(a.reqAttach, b.reqAttach) && sameLiteral(a.verdicts, b.verdicts)))
        return false;
  return true;
}
} // namespace detail
static_assert(detail::sameSectionRowsAgree(),
              "ProgramAttaches.def: rows sharing a SECTION must agree on ATTACHTYPE, REQATTACH and VERDICTS");

inline const ProgramKindInfo *lookupProgramKind(llvm::StringRef name) {
  for (const ProgramKindInfo &k : kProgramKindTable)
    if (k.name == name)
      return &k;
  return nullptr;
}

// Attach rows for a kind, in table order.
inline llvm::SmallVector<const ProgramAttachInfo *, 2> attachRowsOf(const ProgramKindInfo &k) {
  llvm::SmallVector<const ProgramAttachInfo *, 2> out;
  for (const ProgramAttachInfo &a : kProgramAttachTable)
    if (a.kind == k.name)
      out.push_back(&a);
  return out;
}

// Only '*' rows with '{}' in SECTION embed an attach value. Empty/enumerated
// sections are literal; MapSymbol/StructOpsMap free values are not embedded.
inline bool attachInSection(const ProgramAttachInfo &a) { return llvm::StringRef(a.section).contains("{}"); }

// True if any row accepts a nonempty attach value. None and default-only
// CgroupHook kinds do not.
inline bool kindTakesAttach(const ProgramKindInfo &k) {
  return llvm::any_of(attachRowsOf(k), [](const ProgramAttachInfo *a) { return !llvm::StringRef(a->attach).empty(); });
}

// Hook-prefixed free rows use <hook>:*, currently only MapSymbol. Program
// input retains <hook>:<value>; section/type/requirements substitutions and
// map symbols use the suffix after stripping <hook>:.
inline bool isHookPrefixedRow(const ProgramAttachInfo &a) {
  llvm::StringRef s(a.attach);
  return s.size() > 2 && s.ends_with(":*");
}
inline llvm::StringRef hookPrefixOf(const ProgramAttachInfo &a) { return llvm::StringRef(a.attach).drop_back(1); } // <hook>:

// Strip a free row's hook prefix, otherwise retain the value.
inline llvm::StringRef attachFreeValue(const ProgramAttachInfo &a, llvm::StringRef attach) {
  return isHookPrefixedRow(a) && attach.starts_with(hookPrefixOf(a)) ? attach.drop_front(hookPrefixOf(a).size()) : attach;
}

// Enumerated attach values in table order, excluding empty, '*' and <hook>:* rows.
inline llvm::SmallVector<llvm::StringRef, 4> attachValuesOf(const ProgramKindInfo &k) {
  llvm::SmallVector<llvm::StringRef, 4> out;
  for (const ProgramAttachInfo *a : attachRowsOf(k))
    if (!llvm::StringRef(a->attach).empty() && a->attach != "*" && !isHookPrefixedRow(*a))
      out.push_back(a->attach);
  return out;
}

// Resolve attach rows: exact empty/enumerated match first, then a nonempty
// <hook>: suffix match, then a nonempty '*' value (TracefsEvent validates its
// category/event shape). Return nullptr for a verifier to diagnose by shape.
inline const ProgramAttachInfo *lookupProgramAttach(const ProgramKindInfo &k, llvm::StringRef attach) {
  for (const ProgramAttachInfo *a : attachRowsOf(k))
    if (a->attach != "*" && !isHookPrefixedRow(*a) && a->attach == attach)
      return a;
  if (attach.empty() || (k.attach == AttachForm::TracefsEvent && !isTracefsEventName(attach)) || (k.attach == AttachForm::SyscallName && !isSyscallName(attach)))
    return nullptr;
  for (const ProgramAttachInfo *a : attachRowsOf(k))
    if (isHookPrefixedRow(*a) && attach.starts_with(hookPrefixOf(*a)) && attach.size() > hookPrefixOf(*a).size())
      return a;
  for (const ProgramAttachInfo *a : attachRowsOf(k))
    if (a->attach == "*")
      return a;
  return nullptr;
}

// Recover the MapSymbol attach value, stripping <hook>: for prefixed rows.
// If no row matches, return the original value.
inline llvm::StringRef mapSymbolOfAttach(const ProgramKindInfo &k, llvm::StringRef attach) {
  const ProgramAttachInfo *a = lookupProgramAttach(k, attach);
  return a ? attachFreeValue(*a, attach) : attach;
}
inline const ProgramAttachInfo *lookupProgramAttach(llvm::StringRef kind, llvm::StringRef attach) {
  const ProgramKindInfo *k = lookupProgramKind(kind);
  return k ? lookupProgramAttach(*k, attach) : nullptr;
}

// Return PACKET context start/end field names for packet operations, or false.
inline bool packetRangeOf(const ProgramKindInfo &k, llvm::StringRef &start, llvm::StringRef &end) {
  llvm::StringRef r(k.packetRange);
  if (r == "-" || r.empty())
    return false;
  std::tie(start, end) = r.split(',');
  return !start.empty() && !end.empty();
}

// Format matching kind names in table order with quote/sep/lastSep for
// diagnostics, e.g. xdp, tp_btf and sched_cls.
inline std::string joinProgramKinds(llvm::function_ref<bool(const ProgramKindInfo &)> pred, llvm::StringRef quote,
                                    llvm::StringRef sep, llvm::StringRef lastSep) {
  llvm::SmallVector<llvm::StringRef> names;
  for (const ProgramKindInfo &k : kProgramKindTable)
    if (pred(k))
      names.push_back(k.name);
  std::string out;
  for (size_t i = 0; i < names.size(); ++i) {
    if (i)
      out += (i + 1 == names.size() ? lastSep : sep).str();
    out += quote.str() + names[i].str() + quote.str();
  }
  return out;
}

// Substitute the attach value for '{}'; empty/enumerated rows are literal.
inline std::string substAttach(llvm::StringRef spelling, llvm::StringRef attach) {
  std::string s = spelling.str();
  if (size_t at = s.find("{}"); at != std::string::npos)
    s.replace(at, 2, attach.str());
  return s;
}

// ELF section from the attach row, substituting '{}' only for free rows.
inline std::string sectionOf(const ProgramAttachInfo &a, llvm::StringRef attach) { return substAttach(a.section, attachFreeValue(a, attach)); }

// Parse <family>[:<verdict>,...] from this attach's VERDICTS. Empty subset
// permits every verdict in the family.
inline llvm::StringRef verdictFamily(const ProgramAttachInfo &a, llvm::SmallVectorImpl<llvm::StringRef> &subset) {
  llvm::StringRef named = llvm::StringRef(a.verdicts).split('|').first; // The named-verdict family precedes |int[:<range>].
  auto [family, rest] = named.split(':');
  subset.clear();
  if (!rest.empty())
    rest.split(subset, ',', -1, /*KeepEmpty=*/false);
  return family;
}

// Return the common family only if all attach rows agree. Without a section,
// handwritten ABI returns cannot select among differing families and must be
// rejected by the caller. No rows likewise returns nullopt.
inline std::optional<llvm::StringRef> uniformVerdictFamily(const ProgramKindInfo &k) {
  std::optional<llvm::StringRef> family;
  llvm::SmallVector<llvm::StringRef> subset;
  for (const ProgramAttachInfo *a : attachRowsOf(k)) {
    llvm::StringRef f = verdictFamily(*a, subset);
    if (family && *family != f)
      return std::nullopt;
    family = f;
  }
  return family;
}

// Check whether |int[:<range>] permits an integer ebpf.return. range is any
// (also the omitted default), u32, or signed <lo>..<hi>.
inline bool intReturnOf(const ProgramAttachInfo &a, llvm::StringRef &range) {
  auto [named, intPart] = llvm::StringRef(a.verdicts).split('|');
  (void)named;
  if (!intPart.consume_front("int"))
    return false;
  range = intPart.consume_front(":") ? intPart : llvm::StringRef("any");
  return true;
}
// True if any attach row permits an integer terminal, for kind diagnostics.
inline bool kindHasIntReturn(const ProgramKindInfo &k) {
  llvm::StringRef range;
  return llvm::any_of(attachRowsOf(k), [&](const ProgramAttachInfo *a) { return intReturnOf(*a, range); });
}

// expected_attach_type from the attach row, substituting '{}', or '-'.
inline std::string attachTypeOf(const ProgramAttachInfo &a, llvm::StringRef attach) { return substAttach(a.attachType, attachFreeValue(a, attach)); }

// Check a kind's whitespace-separated OPS tags.
inline bool kindAllows(const ProgramKindInfo &k, llvm::StringRef tag) {
  llvm::SmallVector<llvm::StringRef> words;
  llvm::StringRef(k.ops).split(words, ' ', -1, /*KeepEmpty=*/false);
  return llvm::is_contained(words, tag);
}
inline bool kindAllows(llvm::StringRef kind, llvm::StringRef tag) {
  const ProgramKindInfo *k = lookupProgramKind(kind);
  return k && kindAllows(*k, tag);
}
// Format kind names bearing the tag in table order for diagnostics.
inline std::string kindsAllowing(llvm::StringRef tag) {
  return joinProgramKinds([&](const ProgramKindInfo &k) { return kindAllows(k, tag); }, "", ", ", " and ");
}

// Resolve an ELF section to a kind/attach row. Exact literal sections take
// priority over nonempty '{}' prefix/suffix matches, preventing unknown
// enumerated values from matching. Empty or section-free map attach values
// are recovered by the caller from schema attach_target.
inline const ProgramKindInfo *kindOfSection(llvm::StringRef section, std::string &attach, const ProgramAttachInfo **row = nullptr) {
  auto found = [&](const ProgramAttachInfo &a, llvm::StringRef value) {
    attach = value.str();
    if (row)
      *row = &a;
    return lookupProgramKind(a.kind);
  };
  for (const ProgramAttachInfo &a : kProgramAttachTable)
    if (!attachInSection(a) && section == a.section)
      return found(a, a.attach == "*" || isHookPrefixedRow(a) ? llvm::StringRef() : llvm::StringRef(a.attach)); // Prefixed free values also come from schema.
  for (const ProgramAttachInfo &a : kProgramAttachTable) {
    if (!attachInSection(a))
      continue;
    auto [prefix, suffix] = llvm::StringRef(a.section).split("{}");
    if (section.size() > prefix.size() + suffix.size() && section.starts_with(prefix) && section.ends_with(suffix))
      return found(a, section.drop_front(prefix.size()).drop_back(suffix.size()));
  }
  return nullptr;
}

// Typed attach families with companion rows, matching requirements.AttachTypes
// and docs/requirements_format.md section 4. Others use generic attach rows.
inline bool isCompanionAttachType(llvm::StringRef type) {
  // Format-11 families emit tpfield/arch/signature companions. Format-12
  // multi families emit arch/ctxfield/binary/mtarget and argument companions.
  for (llvm::StringRef t : {"trace_raw_tp", "trace_fentry", "trace_fexit", "kprobe", "uprobe", "tcx", "kretprobe", "uretprobe", "trace_fmod_ret",
                            "trace_tp", "trace_perf", "trace_lsm", "freplace", "trace_struct_ops",
                            "kprobe_multi", "kretprobe_multi", "uprobe_multi", "uretprobe_multi",
                            "usdt", // USDT companions: arch, ctxfield, binary, usdtsem and usdtarg.
                            "ksyscall", "trace_lsm_cgroup"}) // Format 13: ksyscall arch/ctxfield/sysarg; trace_lsm_cgroup farg.
    if (t == type)
      return true;
  return false;
}

// Upgrade a generic row to its typed family only when schema supplies the
// companion-check evidence; otherwise keep the generic row and its format.
// Typed families retain generic attach_type/attach_target checks, so upgrading
// must never lose a check. Return empty when no mapping exists.
inline llvm::StringRef companionFamilyOf(llvm::StringRef genericType) {
  if (genericType == "lsm_mac")
    return "trace_lsm";
  if (genericType == "lsm_cgroup") // Format-13 typed companion for generic lsm_cgroup lsm:<hook>.
    return "trace_lsm_cgroup";
  return {};
}

// Produce requirements attach type/target from REQATTACH, substituting the
// program's attach value. REQATTACH '-' returns false.
struct RequirementsAttach {
  std::string type, target;
};
inline bool requirementsAttachOf(const ProgramAttachInfo &a, llvm::StringRef attach, RequirementsAttach &out) {
  llvm::StringRef spec(a.reqAttach);
  if (spec == "-")
    return false;
  auto [type, target] = spec.split(' ');
  out.type = substAttach(type, attachFreeValue(a, attach)); // Strip <hook>: for prefixed free rows.
  out.target = substAttach(target, attachFreeValue(a, attach));
  return true;
}

} // namespace bpfmlir

#endif // BPF_MLIR_SUPPORT_PROGRAMKINDS_H
