//===- EBPFDialect.cpp - dialect registration and operation verification -----===//
//
// Custom verification covers constraints not expressible with standard
// dialects; schema and cross-stage checks remain in their owning passes.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"
#include "bpf-mlir/Support/ProgramKinds.h"
#include "bpf-mlir/Support/LocalStorage.h"
#include "bpf-mlir/Support/KeylessMaps.h"
#include "bpf-mlir/Support/Usdt.h"
#include "bpf-mlir/Support/RejectedMapKinds.h"
#include "bpf-mlir/Dialect/BPFABI/KernelABI.h"

#include "mlir/IR/Builders.h"
#include "mlir/IR/DialectImplementation.h"
#include "mlir/IR/Matchers.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/ADT/TypeSwitch.h"
#include <functional>

using namespace mlir;
using namespace mlir::ebpf;

#include "bpf-mlir/Dialect/EBPF/IR/EBPFOpsDialect.cpp.inc"

#define GET_TYPEDEF_CLASSES
#include "bpf-mlir/Dialect/EBPF/IR/EBPFOpsTypes.cpp.inc"

#include "bpf-mlir/Dialect/EBPF/IR/EBPFOpsInterfaces.cpp.inc"

// program attach is a string or a multi-probe name array; omitted means neither.
static ParseResult parseProgramAttach(OpAsmParser &parser, StringAttr &attach, ArrayAttr &attachList) {
  if (failed(parser.parseOptionalKeyword("attach")))
    return success();
  if (succeeded(parser.parseOptionalLSquare())) {
    SmallVector<Attribute> names;
    if (failed(parser.parseOptionalRSquare())) {
      do {
        std::string s;
        if (parser.parseString(&s))
          return failure();
        names.push_back(parser.getBuilder().getStringAttr(s));
      } while (succeeded(parser.parseOptionalComma()));
      if (parser.parseRSquare())
        return failure();
    }
    attachList = parser.getBuilder().getArrayAttr(names);
    return success();
  }
  std::string s;
  if (parser.parseString(&s))
    return failure();
  attach = parser.getBuilder().getStringAttr(s);
  return success();
}
static void printProgramAttach(OpAsmPrinter &p, Operation *, StringAttr attach, ArrayAttr attachList) {
  if (attach) {
    p << "attach ";
    p.printAttributeWithoutType(attach);
  } else if (attachList) {
    p << "attach [";
    llvm::interleaveComma(attachList, p, [&](Attribute a) { p.printAttributeWithoutType(a); });
    p << "]";
  }
}

#define GET_OP_CLASSES
#include "bpf-mlir/Dialect/EBPF/IR/EBPFOps.cpp.inc"

// Supported sets.
namespace {

// ProgramKinds.def owns program properties; ProgramAttaches.def owns
// verdict families/subsets. Values come from ABI verdict rows and
// HandVerdicts.def. sched_cls permits pass/drop; redirect comes only from
// its helper operation. Non-verdict kinds use done. MapKinds.def MAPTYPE
// selects !ebpf.map spellings in diagnostic order.
struct MapKindRow {
  llvm::StringLiteral name;
  bool mapType;
};
constexpr MapKindRow kMapKindRows[] = {
#define EBPF_MAP_KIND(ENUM, NAME, MAPTYPE) {NAME, MAPTYPE},
#include "bpf-mlir/Support/MapKinds.def"
};
llvm::SmallVector<llvm::StringLiteral> mapTypeKinds() {
  llvm::SmallVector<llvm::StringLiteral> out;
  for (const MapKindRow &k : kMapKindRows)
    if (k.mapType)
      out.push_back(k.name);
  return out;
}

// Allowed verdict spellings per attachment, in subset order or full-family order.
std::vector<std::string> verdictsOf(const bpfmlir::ProgramAttachInfo &a) {
  llvm::SmallVector<llvm::StringRef> subset;
  llvm::StringRef family = bpfmlir::verdictFamily(a, subset);
  if (!subset.empty())
    return std::vector<std::string>(subset.begin(), subset.end());
  return mlir::bpfabi::verdictActions(family);
}

std::string join(llvm::ArrayRef<llvm::StringLiteral> xs) {
  std::string out;
  for (auto [i, x] : llvm::enumerate(xs)) {
    if (i)
      out += ", ";
    out += "\"";
    out += x.str();
    out += "\"";
  }
  return out;
}

std::string joinStrings(llvm::ArrayRef<std::string> xs) {
  std::string out;
  for (auto [i, x] : llvm::enumerate(xs)) {
    if (i)
      out += ", ";
    out += "\"" + x + "\"";
  }
  return out;
}

bool contains(llvm::ArrayRef<llvm::StringLiteral> xs, llvm::StringRef v) {
  return llvm::is_contained(xs, v);
}

} // namespace

namespace mlir {
namespace ebpf {

bool isKnownProgramKind(llvm::StringRef kind) { return bpfmlir::lookupProgramKind(kind) != nullptr; }
bool isKnownMapKind(llvm::StringRef kind) { return contains(mapTypeKinds(), kind); }

bool isVerdictAllowedFor(llvm::StringRef programKind, llvm::StringRef attach, llvm::StringRef action) {
  const bpfmlir::ProgramAttachInfo *a = bpfmlir::lookupProgramAttach(programKind, attach);
  return a && llvm::is_contained(verdictsOf(*a), action.str());
}

// Direct packet access requires a kind with PACKET context bounds.
bool supportsPacketAccess(llvm::StringRef programKind) {
  const bpfmlir::ProgramKindInfo *k = bpfmlir::lookupProgramKind(programKind);
  llvm::StringRef start, end; // PACKET names the context bounds-field pair.
  return k && bpfmlir::packetRangeOf(*k, start, end);
}

std::string knownProgramKinds() {
  return bpfmlir::joinProgramKinds([](const bpfmlir::ProgramKindInfo &) { return true; }, "\"", ", ", ", ");
}
std::string knownMapKinds() { return join(mapTypeKinds()); }
std::string knownVerdicts(llvm::StringRef programKind, llvm::StringRef attach) {
  const bpfmlir::ProgramAttachInfo *a = bpfmlir::lookupProgramAttach(programKind, attach);
  if (!a)
    return "(none)";
  return joinStrings(verdictsOf(*a));
}

} // namespace ebpf
} // namespace mlir

// Dialect registration.
void EBPFDialect::initialize() {
  addTypes<
#define GET_TYPEDEF_LIST
#include "bpf-mlir/Dialect/EBPF/IR/EBPFOpsTypes.cpp.inc"
      >();
  addOperations<
#define GET_OP_LIST
#include "bpf-mlir/Dialect/EBPF/IR/EBPFOps.cpp.inc"
      >();
}

// Shared program/subprogram verification.
namespace {

// Match handle arguments with maps[] symbols. leading describes preceding
// arguments: program context or typed subprogram arguments.
LogicalResult verifyMapBindings(Operation *op, ArrayAttr syms,
                                Block::BlockArgListType mapArgs,
                                llvm::StringRef leading) {
  for (BlockArgument arg : mapArgs) {
    // Explicitly reject attempts to bind a context argument as a map.
    if (isa<ContextType>(arg.getType()))
      return op->emitOpError() << "only the first entry block argument may be a "
                               << "context; argument #" << arg.getArgNumber()
                               << " is another !ebpf.ctx and cannot be bound to a "
                               << "map symbol";
    if (!isa<MapType>(arg.getType()))
      return op->emitOpError() << "entry block arguments after " << leading << " must be "
                           << "!ebpf.map<...> (map handles), got "
                           << arg.getType();
  }

  // Check binding structure/uniqueness only. VerifySchema separately owns
  // symbol existence and kind/key/value agreement.
  size_t numSyms = syms ? syms.size() : 0;
  if (numSyms != mapArgs.size())
    return op->emitOpError() << "every map argument must be bound to a schema symbol: "
                         << mapArgs.size() << " map argument(s) but " << numSyms
                         << " symbol(s) in `maps`";
  llvm::SmallDenseSet<llvm::StringRef> seenSyms;
  if (syms) {
    for (Attribute a : syms) {
      auto flat = dyn_cast<FlatSymbolRefAttr>(a);
      if (!flat)
        return op->emitOpError() << "map symbols must be flat symbol references, got "
                             << a;
      if (!seenSyms.insert(flat.getValue()).second)
        return op->emitOpError() << "map symbol @" << flat.getValue()
                             << " is bound twice";
    }
  }

  return success();
}

// Check nullable reservation uses and reject reservations inside scf.if regions.
LogicalResult verifyReservationUses(Region &region) {
  // Unchecked reservations may flow only to if_reserved. Taken reservations
  // occur as present-region arguments, with linearity checked there.
  bool bad = false;
  region.walk([&](Operation *op) {
    for (Value res : op->getResults()) {
      if (!isa<MaybeReservationType>(res.getType()))
        continue;
      // Expanded checks use is_present/assume_present. VerifyStructured owns
      // exact check counts and true-edge placement because they require CFG
      // reasoning; do not count them a second time here.
      if (llvm::any_of(res.getUsers(), [](Operation *u) {
            return isa<IsPresentOp, AssumePresentOp>(u);
          }))
        continue;
      unsigned checks = 0;
      for (Operation *user : res.getUsers()) {
        if (isa<RingbufIfReservedOp>(user)) {
          ++checks;
          continue;
        }
        bad = true;
        auto d = op->emitOpError()
                 << "an unchecked ring buffer reservation may only be consumed "
                 << "by ebpf.ringbuf.if_reserved, but it is used by '"
                 << user->getName() << "'";
        d.attachNote() << "bpf_ringbuf_reserve can return NULL; the kernel "
                          "rejects storing to or submitting a possibly-null "
                          "reservation";
      }
      if (checks != 1) {
        bad = true;
        auto d = op->emitOpError()
                 << "a ring buffer reservation must be checked exactly once by "
                 << "ebpf.ringbuf.if_reserved, found " << checks;
        if (checks == 0)
          d.attachNote() << "an unchecked reservation leaks ring buffer space";
      }
    }
  });
  // Scalar scf.if may not contain reservations: source ownership analysis
  // does not traverse its regions.
  region.walk([&](Operation *op) {
    if (op->getName().getStringRef() != "scf.if")
      return;
    // Diagnose the first offending operation per scf.if, avoiding duplicate reasons.
    op->walk([&](Operation *inner) {
      auto kc = dyn_cast<KFieldCopyOp>(inner); // Include kfield.copy into reservations; borrowed destinations are allowed.
      auto tc = dyn_cast<TpFieldCopyOp>(inner);
      if (isa<RingbufReserveOp, RingbufIfReservedOp, RingbufSubmitOp,
              RingbufDiscardOp, RingbufStoreFieldOp, RingbufStoreRecordOp, TaskCommOp, UserReadStrOp, UserReadOp, KernelReadStrOp,
              RingbufReserveDynptrOp, RingbufSubmitDynptrOp, RingbufDiscardDynptrOp>(inner) || // Include dynptr reservation and consumption.
          (kc && kc.writesReservation()) || (tc && tc.writesReservation())) {
        bad = true;
        inner->emitOpError()
            << "ring buffer reservations inside scf.if are not supported "
               "(the ownership check does not follow scf.if regions)";
        return WalkResult::interrupt();
      }
      return WalkResult::advance();
    });
  });
  return failure(bad);
}

} // namespace

// Programs.
LogicalResult ProgramOp::verify() {
  // Reject unknown program kinds.
  const bpfmlir::ProgramKindInfo *info = bpfmlir::lookupProgramKind(getKind());
  if (!info)
    return emitOpError() << "unknown program kind \"" << getKind()
                         << "\" (known: " << knownProgramKinds() << ")";

  // Resolve attachment shapes and choices from ProgramKinds/ProgramAttaches.
  // Explicit attach empty-string is invalid even when an omitted default
  // exists. Multi-probes require arrays of explicit names: reject empty lists,
  // empty names, duplicates and globs. Glob expansion depends on target state
  // and cannot provide fixed compile-time mtarget rows. Name order determines
  // requirement target indices and loader cookies. User-binary paths remain
  // loader inputs; schema fixes content through SHA-256.
  if (bpfmlir::isAttachList(info->attach)) {
    llvm::StringRef what = info->attach == bpfmlir::AttachForm::KernelFuncList ? "kernel function" : "symbol";
    if (getAttach() || !getAttachListAttr())
      return emitOpError() << "a " << getKind() << " program needs `attach [\"<" << what << ">\", ...]` (a list of " << what
                           << " names)";
    ArrayAttr names = getAttachListAttr();
    if (names.empty())
      return emitOpError() << "the attach list of a " << getKind() << " program must name at least one " << what << "";
    llvm::StringSet<> seen;
    for (auto [i, a] : llvm::enumerate(names)) {
      StringRef n = cast<StringAttr>(a).getValue();
      if (n.empty())
        return emitOpError() << "attach list entry #" << i << " is empty";
      if (n.find_first_of("*?[") != StringRef::npos)
        return emitOpError() << "attach list entry \"" << n << "\" has a glob character ('*', '?' or '['); list each " << what
                             << " by name (glob patterns are not supported)";
      if (!seen.insert(n).second)
        return emitOpError() << "attach list names \"" << n << "\" twice";
    }
  } else if (getAttachListAttr()) {
    return emitOpError() << "`attach [...]` (a list of names) is only for "
                         << bpfmlir::joinProgramKinds([](auto &k) { return bpfmlir::isAttachList(k.attach); }, "", ", ", " and ")
                         << " programs; write `attach \"<name>\"`";
  }
  bool explicitEmpty = getAttach() && getAttach()->empty();
  if (explicitEmpty || !bpfmlir::lookupProgramAttach(*info, getAttachValue())) {
    // Enumerated attachment suggestions in diagnostic order.
    auto valuesText = [&] {
      llvm::SmallVector<llvm::StringRef, 4> vals = bpfmlir::attachValuesOf(*info);
      std::string out;
      for (size_t i = 0; i < vals.size(); ++i)
        out += (i ? (i + 1 == vals.size() ? " or " : ", ") : "") + ("`attach \"" + vals[i] + "\"`").str();
      return out;
    };
    if (getAttach() && !bpfmlir::kindTakesAttach(*info))
      return emitOpError() << "`attach` is only for " << bpfmlir::joinProgramKinds([](auto &k) { return bpfmlir::kindTakesAttach(k); }, "", ", ", " and ")
                           << " programs";
    switch (info->attach) {
    case bpfmlir::AttachForm::Tracepoint:
      return emitOpError() << "a " << getKind() << " program needs `attach \"<tracepoint>\"`";
    case bpfmlir::AttachForm::KernelFunc:
      return emitOpError() << "a " << getKind() << " program needs `attach \"<kernel function>\"`";
    case bpfmlir::AttachForm::UserSymbol:
      return emitOpError() << "a " << getKind() << " program needs `attach \"<symbol>\"` (the function symbol in the user binary)";
    case bpfmlir::AttachForm::TcxDirection:
      return emitOpError() << "a " << getKind() << " program needs " << valuesText() << " (the tcx direction)";
    case bpfmlir::AttachForm::CgroupDirection: // cgroup_skb (cgroup_inet_ingress / egress)
      return emitOpError() << "a " << getKind() << " program needs " << valuesText() << " (the cgroup attach direction)";
    case bpfmlir::AttachForm::SockoptHook: // cgroup_sockopt (cgroup_getsockopt / cgroup_setsockopt)
      return emitOpError() << "a " << getKind() << " program needs " << valuesText() << " (the sockopt hook)";
    case bpfmlir::AttachForm::CgroupHook: { // An empty cgroup-hook row selects the omitted attachment's default hook.
      const bpfmlir::ProgramAttachInfo *dflt = bpfmlir::lookupProgramAttach(*info, "");
      return emitOpError() << "a " << getKind() << " program needs " << valuesText() << " (the cgroup socket hook)"
                           << (dflt ? (", or no `attach` for section \"" + dflt->section + "\"").str() : std::string());
    }
    case bpfmlir::AttachForm::IterTarget: // Iterator target names bpf_iter_<target> FUNC, such as bpf_map_elem.
      return emitOpError() << "a " << getKind() << " program needs `attach \"<iter target>\"` (e.g. \"bpf_map_elem\")";
    case bpfmlir::AttachForm::LsmHook: // LSM hook names map to bpf_lsm_<hook> BTF functions.
      return emitOpError() << "a " << getKind() << " program needs `attach \"<LSM hook>\"` (the LSM hook name, e.g. \"socket_create\")";
    case bpfmlir::AttachForm::MapSymbol: // Socket-hook map symbols are matched against maps below.
      return emitOpError() << "a " << getKind()
                           << " program needs `attach \"<map>\"` (the sockmap / sockhash it is attached to, also in its maps)";
    case bpfmlir::AttachForm::TracefsEvent: // Tracefs event group/name, matching link.Tracepoint.
      return emitOpError() << "a " << getKind()
                           << " program needs `attach \"<category>/<event>\"` (the tracefs event, e.g. \"syscalls/sys_enter_getppid\")";
    case bpfmlir::AttachForm::ProgFunc: // ext names a global function in a loader-supplied BPF program.
      return emitOpError() << "a " << getKind()
                           << " program needs `attach \"<function>\"` (the global function of the BPF program it replaces)";
    case bpfmlir::AttachForm::StructOpsMap: // struct_ops operation tables are matched by schema parsing and VerifySchema.
      return emitOpError() << "a " << getKind()
                           << " program needs `attach \"<struct_ops map>\"` (the struct_ops map whose member it implements — schema core.maps)";
    case bpfmlir::AttachForm::ReuseportHook: // sk_reuseport defaults to select; other rows include select_or_migrate.
      return emitOpError() << "a " << getKind() << " program needs no `attach` (select) or " << valuesText() << " (the reuseport hook)";
    case bpfmlir::AttachForm::UsdtProbe: // Validate USDT provider/name spelling below.
      return emitOpError() << "a " << getKind() << " program needs `attach \"<provider>:<name>\"` (the USDT probe in the user binary's notes)";
    case bpfmlir::AttachForm::SyscallName: // ksyscall names an unprefixed syscall; compiler adds the architecture prefix.
      return emitOpError() << "a " << getKind()
                           << " program needs `attach \"<syscall>\"` (the syscall name without the arch prefix, e.g. \"getppid\" — not \"sys_…\" or \"__…\"; "
                              "the compiler names the wrapper from the arch)";
    case bpfmlir::AttachForm::KernelFuncList: // Lists were checked above; only kinds lacking a matching row reach here.
    case bpfmlir::AttachForm::UserSymbolList:
    case bpfmlir::AttachForm::None:
      break;
    }
    return emitOpError() << "a " << getKind() << " program has no attach row for "
                         << (getAttach() ? ("`attach \"" + *getAttach() + "\"`").str() : std::string("no `attach`")) << " (kind table)";
  }
  // USDT provider:name uses two C identifiers, matching requirement targets.
  if (info->attach == bpfmlir::AttachForm::UsdtProbe && !bpfmlir::isUsdtProbeName(getAttachValue()))
    return emitOpError() << "attach \"" << getAttachValue() << "\" of a " << getKind()
                         << " program must be \"<provider>:<name>\" (two C identifiers — the USDT probe)";
  // ARCH determines which kinds require calling-convention/pt_regs architecture.
  if (info->arch && (!getArch() || getArch()->empty()))
    return emitOpError() << "a " << getKind() << " program needs `arch \"<arch>\"` (the calling convention of pt_regs, e.g. \"x86_64\")";
  if (!info->arch && getArch())
    return emitOpError() << "`arch` is only for " << bpfmlir::joinProgramKinds([](auto &k) { return k.arch; }, "", ", ", " and ")
                         << " programs";

  // Entry arguments are one context followed by loader-supplied map handles.
  // Maps enter through this boundary rather than declaration operations.
  Block &entry = getBody().front();
  if (entry.getNumArguments() < 1)
    return emitOpError() << "entry block must take a context argument";

  auto ctxTy = dyn_cast<ContextType>(entry.getArgument(0).getType());
  if (!ctxTy)
    return emitOpError() << "first entry block argument must be !ebpf.ctx<...>, "
                         << "got " << entry.getArgument(0).getType();
  if (ctxTy.getKind() != getKind())
    return emitOpError() << "context kind \"" << ctxTy.getKind()
                         << "\" does not match program kind \"" << getKind()
                         << "\"";
  // ext context is only a marker for replacement argument registers, not an
  // ordinary context pointer. Only ext.arg may use it; reject forwarding it
  // to static functions or other context consumers.
  if (!bpfmlir::entryTakesCtx(info->attach)) {
    for (Operation *user : entry.getArgument(0).getUsers())
      if (!isa<ExtArgOp>(user))
        return emitOpError() << "a " << getKind() << " program uses its context only with ebpf.ext.arg (its arguments are those of the "
                                "function it replaces), but it is used by '" << user->getName() << "'";
    // All returns in one ext program must share the replacement return type.
    Type retTy;
    WalkResult wr = getBody().walk([&](ReturnOp r) {
      if (r->getParentOp() != getOperation())
        return WalkResult::advance();
      if (retTy && retTy != r.getValue().getType())
        return WalkResult::interrupt();
      retTy = r.getValue().getType();
      return WalkResult::advance();
    });
    if (wr.wasInterrupted())
      return emitOpError() << "a " << getKind() << " program returns one type (that of the function it replaces), but its ebpf.return "
                              "values differ in type";
  }
  auto mapArgs = entry.getArguments().drop_front();
  if (failed(verifyMapBindings(getOperation(), getMapSymbolsAttr(), mapArgs,
                               "the context")))
    return failure();
  // Socket-hook attachments must name bound sockmap/sockhash handles.
  // Lowering emits .maps placeholders even when otherwise unused, keeping
  // requirement map rows before the corresponding attachment rows.
  if (info->attach == bpfmlir::AttachForm::MapSymbol) {
    ArrayAttr syms = getMapSymbolsAttr();
    MapType target;
    StringRef sym = bpfmlir::mapSymbolOfAttach(*info, *getAttach()); // Strip stream_parser: before resolving the map symbol.
    for (auto [i, a] : llvm::enumerate(mapArgs))
      if (syms && i < syms.size() && cast<FlatSymbolRefAttr>(syms[i]).getValue() == sym)
        target = dyn_cast<MapType>(a.getType());
    if (!target)
      return emitOpError() << "attach \"" << *getAttach() << "\" must name one of the program's maps (the sockmap / sockhash it is attached to"
                           << (sym != *getAttach() ? ("; map \"" + sym + "\"").str() : std::string()) << ")";
    if (target.getKind() != "sockmap" && target.getKind() != "sockhash")
      return emitOpError() << "attach \"" << *getAttach() << "\" is a \"" << target.getKind() << "\" map; a " << getKind()
                           << " program is attached to a sockmap or sockhash";
  }

  // Every successor-free program exit must have a supported terminator.
  // Source has one block; expansion produces a multi-block CFG.
  for (Block &blk : getBody()) {
    if (blk.empty() || !blk.back().hasTrait<OpTrait::IsTerminator>())
      return emitOpError() << "every block must end with a terminator";
    Operation *term = &blk.back();
    if (term->getNumSuccessors() == 0 && !isa<VerdictOp, VerdictIfOp, ReturnOp, RedirectOp, RedirectMapOp, TailCallOp, SkRedirectOp, MsgRedirectOp>(term)) // Include socket/message redirects.
      return emitOpError() << "must be terminated by ebpf.verdict / verdict.if / return / redirect / redirect_map / tail_call / sk.redirect / msg.redirect, got "
                           << term->getName();
  }

  return verifyReservationUses(getBody());
}

// Verdicts. Resolve the program attachment value, empty for omitted defaults.
static StringRef programAttachOf(ProgramOp prog) { return prog ? prog.getAttachValue() : StringRef(); } // Use the first name for multi-target lists.
static StringRef programAttachOf(Operation *op) { return programAttachOf(op->getParentOfType<ProgramOp>()); }

// Diagnostics name attachments only when allowed verdicts differ across
// rows, such as allow-only cgroup_sock_addr recvmsg. Otherwise name the kind.
static std::string verdictKindPhrase(StringRef kind, StringRef attach) {
  std::string s = "program kind \"" + kind.str() + "\"";
  const bpfmlir::ProgramKindInfo *k = bpfmlir::lookupProgramKind(kind);
  if (!k || attach.empty())
    return s;
  auto rows = bpfmlir::attachRowsOf(*k);
  if (llvm::any_of(rows, [&](const bpfmlir::ProgramAttachInfo *r) { return r->verdicts != rows.front()->verdicts; }))
    s += " attach \"" + attach.str() + "\"";
  return s;
}

LogicalResult VerdictOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog)
    return emitOpError() << "must be inside ebpf.program";
  llvm::StringRef kind = prog.getKind();
  if (!isKnownProgramKind(kind))
    return success(); // Already rejected by program verification; avoid duplicate diagnostics.
  StringRef attach = programAttachOf(prog); // Verdict rules belong to the program's attachment row.
  if (!bpfmlir::lookupProgramAttach(kind, attach))
    return success(); // Missing attachment row was already rejected by program verification.
  if (knownVerdicts(kind, attach).empty()) // Some kinds, such as ext, have only unnamed integer returns.
    return emitOpError() << "program kind \"" << kind << "\" has no named verdicts; it returns an integer with ebpf.return";
  if (!isVerdictAllowedFor(kind, attach, getAction()))
    return emitOpError() << "verdict \"" << getAction() << "\" is not valid for " << verdictKindPhrase(kind, attach)
                         << " (known: " << knownVerdicts(kind, attach) << ")";
  return success();
}

// Map operations: kind and key/value agreement.
namespace {

LogicalResult checkMapKind(Operation *op, MapType map) {
  // cgroup_array is not a payload array; use dedicated ancestry helpers.
  if (map.getKind() == "cgroup_array")
    return op->emitOpError() << "a cgroup_array is only used by ebpf.task.under_cgroup / ebpf.skb.under_cgroup; userspace sets its cgroup fds";
  // Userspace populates devmap. Programs may only redirect_map, not perform
  // lookup/update/delete/atomic_add.
  if (map.getKind() == "devmap")
    return op->emitOpError() << "a devmap is only used by ebpf.redirect_map; its entries are set by userspace";
  // devmap_hash/cpumap/xskmap share the redirect-only compiler restriction,
  // even when kernel permits some lookup variants.
  if (map.getKind() == "devmap_hash" || map.getKind() == "xskmap")
    return op->emitOpError() << "a " << map.getKind() << " map is only used by ebpf.redirect_map / ebpf."
                             << (map.getKind() == "devmap_hash" ? "devmap.lookup" : "xsk.lookup")
                             << "; its entries are set by userspace";
  if (map.getKind() == "cpumap")
    return op->emitOpError() << "a " << map.getKind() << " map is only used by ebpf.redirect_map; its entries are set by userspace";
  // prog_array is used only by tail_call; loaders populate declared slots.
  if (map.getKind() == "prog_array")
    return op->emitOpError() << "a prog_array is only used by ebpf.tail_call; its slots are set by the loader";
  // stack_trace is used only by get_stackid; userspace reads values by ID.
  if (map.getKind() == "stack_trace")
    return op->emitOpError() << "a stack_trace map is only used by ebpf.stack.kernel_id / ebpf.stack.user_id; userspace reads it by the id";
  // perf_event_array is used only by perf_event_output; loaders populate FD slots.
  if (map.getKind() == "perf_event_array")
    return op->emitOpError() << "a perf_event_array map is only used by ebpf.perf.output; its slots are set by the loader (the perf reader)";
  // sockmap/sockhash attach sk_skb/sk_msg. Userspace supplies socket FDs;
  // program support is limited to redirects and sock_ops updates rather than
  // ordinary lookup/update/delete/atomic_add.
  if (map.getKind() == "sockmap" || map.getKind() == "sockhash")
    return op->emitOpError() << "a " << map.getKind()
                             << " is only the attach target of sk_skb / sk_msg programs and only used by ebpf.sk.redirect / ebpf.msg.redirect / "
                                "ebpf.sock.map_update / ebpf.sock.map_lookup / ebpf.map.delete / ebpf.map.try_delete in programs (lookup: xdp / sk_lookup, delete: xdp); userspace sets the other entries (socket fds)";
  // reuseport_sockarray is used only by sk_select_reuseport; userspace supplies socket FDs.
  if (map.getKind() == "reuseport_sockarray")
    return op->emitOpError() << "a reuseport_sockarray map is only used by ebpf.sk.select_reuseport; its entries (sockets) are set by userspace";
  // Local storage uses its get/delete helpers and owner pointers, not keys.
  if (std::optional<StringRef> owner = bpfmlir::localStorageOwner(map.getKind()))
    return op->emitOpError() << "a " << map.getKind() << " map is only used by ebpf.storage.get / ebpf.storage.delete (its value belongs to a "
                             << *owner << " — the owner pointer is the key)";
  // Keyless queue/stack/bloom maps use dedicated push/pop/peek helpers.
  if (bpfmlir::isKeylessMapKind(map.getKind()))
    return op->emitOpError() << "a " << map.getKind()
                             << " map has no key; it is only used by ebpf.map.push / ebpf.map.pop / ebpf.map.peek / ebpf.bloom.peek";
  // Outer map-in-map permits only lookup, returning one-level inner-map
  // handles. Userspace inserts the inner maps.
  if (map.getKind() == "array_of_maps" || map.getKind() == "hash_of_maps") {
    if (!isa<MapLookupOp>(op))
      return op->emitOpError() << "a " << map.getKind()
                               << " map is only looked up in programs (ebpf.map.lookup → ebpf.ref.check → ebpf.map.inner); userspace inserts the inner maps";
    auto inner = dyn_cast<MapType>(map.getValueType());
    if (!inner || inner.getKind() == "array_of_maps" || inner.getKind() == "hash_of_maps")
      return op->emitOpError() << "a " << map.getKind() << " map's value type must be the inner map handle !ebpf.map<\"…\", K, V> (one level), got "
                               << map.getValueType();
    return success();
  }
  // RejectedMapKinds.def names intentionally unsupported kinds and alternatives.
  if (std::optional<std::string> msg = bpfmlir::rejectedMapKindMessage(map.getKind()))
    return op->emitOpError() << *msg;
  if (!isKnownMapKind(map.getKind()))
    return op->emitOpError() << "unknown map kind \"" << map.getKind()
                             << "\" (known: " << knownMapKinds() << ")";
  return success();
}

LogicalResult checkKey(Operation *op, MapType map, Type key) {
  if (key != map.getKeyType())
    return op->emitOpError() << "key type " << key
                             << " does not match map key type "
                             << map.getKeyType();
  return success();
}

bool isHashFamily(StringRef k) {
  return k == "hash" || k == "percpu_hash" || k == "lru_hash" || k == "lru_percpu_hash";
}

// Hash-family record keys must come from record.make, initializing every
// byte with zero padding. Equal logical keys must have equal bytes for lookup.
LogicalResult checkRecordKey(Operation *op, MapType map, Value key) {
  if (!isa<RecordType>(key.getType()))
    return success();
  // lpm_trie also uses record keys; schema verifies prefixlen/address shape.
  if (!isHashFamily(map.getKind()) && map.getKind() != "lpm_trie")
    return op->emitOpError() << "a record key is only supported for a hash map (\"hash\", "
                                "\"percpu_hash\", \"lru_hash\" or \"lru_percpu_hash\") or a lpm_trie, got \""
                             << map.getKind() << "\"";
  if (!key.getDefiningOp<RecordMakeOp>())
    return op->emitOpError() << "a record key must be built by ebpf.record.make (every byte, padding "
                                "zeroed), got one from "
                             << (key.getDefiningOp() ? key.getDefiningOp()->getName().getStringRef()
                                                     : StringRef("a block argument"));
  return success();
}

// lpm_trie entries are userspace-populated and immutable within supported
// programs, a compiler restriction beyond kernel capabilities.
LogicalResult checkLpmReadOnly(Operation *op, MapType map) {
  if (map.getKind() == "lpm_trie")
    return op->emitOpError() << "a lpm_trie is read-only in programs (its entries are set by userspace — a compiler restriction; "
                                "the kernel would allow it)";
  return success();
}

LogicalResult checkValue(Operation *op, MapType map, Type value) {
  if (value != map.getValueType())
    return op->emitOpError() << "value type " << value
                             << " does not match map value type "
                             << map.getValueType();
  return success();
}

} // namespace

LogicalResult MapLookupOp::verify() {
  auto map = cast<MapType>(getMap().getType());
  if (failed(checkMapKind(*this, map)) ||
      failed(checkKey(*this, map, getKey().getType())) ||
      failed(checkRecordKey(*this, map, getKey())))
    return failure();
  auto res = cast<MaybeRefType>(getResult().getType());
  if (res.getPointee() != map.getValueType())
    return emitOpError() << "result " << getResult().getType()
                         << " does not reference the map value type "
                         << map.getValueType();
  return success();
}

LogicalResult MapUpdateOp::verify() {
  auto map = cast<MapType>(getMap().getType());
  if (failed(checkLpmReadOnly(*this, map)) || failed(checkMapKind(*this, map)) ||
      failed(checkKey(*this, map, getKey().getType())) ||
      failed(checkRecordKey(*this, map, getKey())))
    return failure();
  // Record values must originate at record.make, including zeroed padding.
  // checkValue owns nominal name/size agreement.
  if (isa<RecordType>(getValue().getType()) && !getValue().getDefiningOp<RecordMakeOp>())
    return emitOpError() << "a record value must be built by ebpf.record.make (every byte, padding "
                            "zeroed), got one from "
                         << (getValue().getDefiningOp()
                                 ? getValue().getDefiningOp()->getName().getStringRef()
                                 : StringRef("a block argument"));
  return checkValue(*this, map, getValue().getType());
}

// Result-bearing update shares kind/key/value rules and three flag names.
// Do not preemptively reject array NOEXIST: in-range returns -EEXIST but
// out-of-range can return -E2BIG. Preserve the actual helper status.
LogicalResult MapTryUpdateOp::verify() {
  auto map = cast<MapType>(getMap().getType());
  if (failed(checkLpmReadOnly(*this, map)) || failed(checkMapKind(*this, map)) || failed(checkKey(*this, map, getKey().getType())) ||
      failed(checkRecordKey(*this, map, getKey())))
    return failure();
  if (isa<RecordType>(getValue().getType()) && !getValue().getDefiningOp<RecordMakeOp>())
    return emitOpError() << "a record value must be built by ebpf.record.make (every byte, padding "
                            "zeroed), got one from "
                         << (getValue().getDefiningOp()
                                 ? getValue().getDefiningOp()->getName().getStringRef()
                                 : StringRef("a block argument"));
  if (failed(checkValue(*this, map, getValue().getType())))
    return failure();
  StringRef f = getFlags();
  if (f != "any" && f != "noexist" && f != "exist")
    return emitOpError() << "flags must be \"any\", \"noexist\" or \"exist\", got \"" << f << "\"";
  return success();
}

static LogicalResult verifyRegionResultWidths(Operation *op);

// Socket ownership cannot cross callbacks/loops. ProgramKinds.def OPS
  // selects supported kinds (xdp and sk_lookup) and diagnostics.
static LogicalResult checkLookupScope(Operation *op, StringRef tag) {
  auto p = op->getParentOfType<ProgramOp>();
  if (!p || !bpfmlir::kindAllows(p.getKind(), tag))
    return op->emitOpError() << "is only for " << bpfmlir::kindsAllowing(tag) << " programs";
  for (Operation *a = op->getParentOp(); a != p; a = a->getParentOp())
    if (!isa<IfOp, SockRefCheckOp>(a))
      return op->emitOpError() << "is only in the program body or ebpf.if / ebpf.sock.ref_check";
  return success();
}
static LogicalResult checkSocketMapKey(Operation *op, Value mapV, Value key) {
  auto m = cast<MapType>(mapV.getType());
  if (m.getKind() != "sockmap" && m.getKind() != "sockhash")
    return op->emitOpError() << "needs a sockmap or sockhash map";
  if ((m.getKind() == "sockmap" && !m.getKeyType().isInteger(32)) || !isa<IntegerType>(m.getKeyType()) ||
      (!m.getValueType().isInteger(32) && !m.getValueType().isInteger(64)))
    return op->emitOpError() << "needs an integer key (sockmap: i32) and i32/i64 socket fd value";
  return checkKey(op, m, key.getType());
}
LogicalResult SockMapLookupOp::verify() {
  if (failed(checkLookupScope(*this, "sock.map_lookup")) || failed(checkSocketMapKey(*this, getMap(), getKey())))
    return failure();
  bool stage2 = llvm::any_of(getResult().getUsers(), [](Operation *u) { return isa<IsPresentOp, AssumePresentOp>(u); });
  for (Operation *u : getResult().getUsers())
    if (stage2 ? !isa<IsPresentOp, AssumePresentOp>(u) : !isa<SockRefCheckOp>(u))
      return u->emitOpError() << "uses an unchecked socket reference; check it with ebpf.sock.ref_check first";
  return success(); // Whole-CFG ownership verification enforces exactly one check.
}
LogicalResult SockRefCheckOp::verify() {
  if (failed(checkLookupScope(*this, "sock.map_lookup")) || failed(verifyRegionResultWidths(*this)))
    return failure();
  if (getPresentRegion().empty() || getAbsentRegion().empty())
    return emitOpError() << "both the present and absent regions must have a body";
  Block &present = getPresentRegion().front();
  if (present.getNumArguments() != 1 || !isa<SockRefType>(present.getArgument(0).getType()))
    return emitOpError() << "the present region must take exactly one !ebpf.sock_ref argument";
  if (getAbsentRegion().front().getNumArguments() != 0)
    return emitOpError() << "the absent region must take no arguments";
  for (Region *r : {&getPresentRegion(), &getAbsentRegion()})
    if (r->front().empty() || !isa<YieldOp>(r->front().back()))
      return emitOpError() << "each region must end with ebpf.yield";
  for (OpOperand &use : present.getArgument(0).getUses()) {
    Operation *u = use.getOwner();
    if (!isa<SockReleaseOp, SkAssignOp>(u) || !getPresentRegion().isAncestor(u->getParentRegion())) // sk.assign is non-consuming.
      return u->emitOpError() << "a socket reference may only be released inside its present region (ebpf.sk.assign may also use it before the release)";
  }
  return success();
}

// sk.assign requires an OPS-enabled entry context and checked socket from
// ref_check present or expanded assume_present. Ownership verification rejects
// use after release.
LogicalResult SkAssignOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || !bpfmlir::kindAllows(prog.getKind(), "sk.assign") || cast<ContextType>(getCtx().getType()).getKind() != prog.getKind() ||
      prog.getBody().empty() || prog.getBody().front().getNumArguments() == 0 || getCtx() != prog.getBody().front().getArgument(0) ||
      (*this)->getParentOfType<SubprogramOp>() || (*this)->getParentOfType<LoopCallbackOp>())
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("sk.assign")
                         << " programs with their own entry context (bpf_sk_assign selects the socket of the running lookup)";
  if (auto a = dyn_cast<BlockArgument>(getSock())) {
    auto c = dyn_cast_or_null<SockRefCheckOp>(a.getOwner()->getParentOp());
    if (c && a.getOwner() == &c.getPresentRegion().front())
      return success();
  } else if (getSock().getDefiningOp<AssumePresentOp>()) {
    return success(); // VerifyStructured checks expanded true-edge placement and uses.
  }
  return emitOpError() << "needs the checked socket of an ebpf.sock.ref_check present region";
}
// sys.bpf/sys.close require the OPS-enabled program's own entry context.
static LogicalResult checkSyscallEntry(Operation *op, Value ctx, StringRef tag) {
  auto prog = op->getParentOfType<ProgramOp>();
  if (!prog || !bpfmlir::kindAllows(prog.getKind(), tag) || cast<ContextType>(ctx.getType()).getKind() != prog.getKind() ||
      prog.getBody().empty() || prog.getBody().front().getNumArguments() == 0 || ctx != prog.getBody().front().getArgument(0) ||
      op->getParentOfType<SubprogramOp>() || op->getParentOfType<LoopCallbackOp>())
    return op->emitOpError() << "is only for " << bpfmlir::kindsAllowing(tag)
                             << " programs with their own entry context (the kernel gives bpf_sys_bpf / bpf_sys_close to syscall programs)";
  return success();
}
LogicalResult SysBpfOp::verify() {
  if (failed(checkSyscallEntry(*this, getCtx(), "sys.bpf")))
    return failure();
  if (!bpfabi::lookupBpfCmd(getCmd()))
    return emitOpError() << "has cmd \"" << getCmd()
                         << "\", which is not a bpfcmd of the UAPI table (map_create / map_freeze / map_get_fd_by_id — the commands whose attr has no "
                            "pointer before the limit)";
  const bpfabi::SysBpfAttrLimit *lim = bpfabi::lookupSysBpfAttrLimit(getCmd());
  if (!lim)
    return emitOpError() << "has cmd \"" << getCmd() << "\" without a SysBpfAttr.def limit";
  if (!getAttr().getDefiningOp<RecordMakeOp>())
    return emitOpError() << "needs the attr built by ebpf.record.make";
  int64_t size = cast<RecordType>(getAttr().getType()).getSize();
  if (size > lim->MaxBytes) {
    InFlightDiagnostic d = emitOpError() << "passes a " << size << "-byte attr for " << getCmd() << ", over the limit " << lim->MaxBytes;
    if (lim->FirstPtr != "-")
      d << " — the kernel reads the pointer field " << lim->FirstPtr << " at offset " << lim->MaxBytes << " as a kernel pointer";
    else
      d << " — the end of the " << getCmd() << " attr";
    return d << " (SysBpfAttr.def)";
  }
  return success();
}
LogicalResult SysCloseOp::verify() { return checkSyscallEntry(*this, getCtx(), "sys.close"); }
LogicalResult SockReleaseOp::verify() {
  if (failed(checkLookupScope(*this, "sock.map_lookup")))
    return failure();
  if (auto a = dyn_cast<BlockArgument>(getPtr())) {
    auto c = dyn_cast_or_null<SockRefCheckOp>(a.getOwner()->getParentOp());
    if (c && a.getOwner() == &c.getPresentRegion().front())
      return success();
  } else if (getPtr().getDefiningOp<AssumePresentOp>()) {
    return success(); // VerifyStructured checks expanded true-edge placement and uses.
  }
  return emitOpError() << "needs a socket reference from the present region of ebpf.sock.ref_check";
}
static LogicalResult checkScalarMapLookup(Operation *op, Value mapV, Value key, StringRef kind, StringRef tag) {
  auto m = cast<MapType>(mapV.getType());
  if (failed(checkLookupScope(op, tag)))
    return failure();
  if (m.getKind() != kind || !m.getKeyType().isInteger(32) || !m.getValueType().isInteger(32))
    return op->emitOpError() << "needs a " << kind << " map with i32 key/value";
  return checkKey(op, m, key.getType());
}
LogicalResult DevmapLookupOp::verify() { return checkScalarMapLookup(*this, getMap(), getKey(), "devmap_hash", "devmap.lookup"); }
LogicalResult XskLookupOp::verify() { return checkScalarMapLookup(*this, getMap(), getKey(), "xskmap", "xsk.lookup"); }

// delete/try_delete support hash families only. Arrays cannot delete elements
// (kernel merely returns -EINVAL), and ring buffers have no keys.
static LogicalResult checkDelete(Operation *op, Value mapV, Value key) {
  auto map = cast<MapType>(mapV.getType());
  if (map.getKind() == "sockmap" || map.getKind() == "sockhash")
    return failed(checkLookupScope(op, "sock.map_delete")) ? failure() : checkSocketMapKey(op, mapV, key);
  if (failed(checkLpmReadOnly(op, map)) || failed(checkMapKind(op, map)) || failed(checkKey(op, map, key.getType())) ||
      failed(checkRecordKey(op, map, key)))
    return failure();
  StringRef k = map.getKind();
  if (!isHashFamily(k))
    return op->emitOpError() << "cannot delete from a \"" << k
                             << "\" map (only hash maps have deletable elements; an array element "
                                "cannot be deleted)";
  return success();
}

LogicalResult MapDeleteOp::verify() { return checkDelete(*this, getMap(), getKey()); }

LogicalResult MapTryDeleteOp::verify() { return checkDelete(*this, getMap(), getKey()); }

// Memory values and packet offsets require BPF widths 8/16/32/64. Reject
// other widths here instead of crashing later or silently emitting arbitrary
// byte counts without a supported contract.
static bool isMemWidth(Type t) {
  auto it = dyn_cast<IntegerType>(t);
  if (!it || !it.isSignless())
    return false;
  unsigned w = it.getWidth();
  return w == 8 || w == 16 || w == 32 || w == 64;
}

LogicalResult MapAtomicAddOp::verify() {
  auto map = cast<MapType>(getMap().getType());
  if (failed(checkLpmReadOnly(*this, map)) || failed(checkMapKind(*this, map)) ||
      failed(checkKey(*this, map, getKey().getType())) ||
      failed(checkValue(*this, map, getDelta().getType())))
    return failure();
  // Atomic addition requires integer values.
  if (!map.getValueType().isSignlessInteger())
    return emitOpError() << "atomic add requires a signless integer map value "
                         << "type, got " << map.getValueType();
  // BPF atomics are 32/64-bit only; narrower types can abort codegen.
  // See docs/memory_semantics.md.
  if (!map.getValueType().isInteger(32) && !map.getValueType().isInteger(64))
    return emitOpError() << "atomic add is 32 / 64 bit only (BPF atomics), got " << map.getValueType() << "";
  return success();
}

// Storage maps accept only the four owner kinds and checked kernel pointers
// to the corresponding owner structs.
static LogicalResult checkStorage(Operation *op, MapType map, KPtrType owner) {
  std::optional<StringRef> want = bpfmlir::localStorageOwner(map.getKind());
  // Deprecated cgroup_storage names suggest cgrp_storage explicitly.
  if (!want)
    if (std::optional<std::string> msg = bpfmlir::rejectedMapKindMessage(map.getKind()))
      return op->emitOpError() << *msg;
  if (!want)
    return op->emitOpError() << "needs a local storage map (\"sk_storage\", \"task_storage\", \"inode_storage\" or \"cgrp_storage\"), got \""
                             << map.getKind() << "\"";
  if (owner.getStructName() != *want)
    return op->emitOpError() << "a " << map.getKind() << " value belongs to a " << *want << " — the owner must be !ebpf.kptr<\"" << *want
                             << "\">, got " << owner << "";
  return success();
}

LogicalResult StorageGetOp::verify() {
  auto map = cast<MapType>(getMap().getType());
  if (failed(checkStorage(*this, map, cast<KPtrType>(getOwner().getType()))))
    return failure();
  auto res = cast<MaybeRefType>(getResult().getType());
  if (res.getPointee() != map.getValueType())
    return emitOpError() << "result " << getResult().getType() << " does not reference the map value type " << map.getValueType();
  return success();
}

// Per-CPU lookup supports three per-CPU map kinds; key/result rules match lookup.
LogicalResult MapLookupPercpuOp::verify() {
  auto map = cast<MapType>(getMap().getType());
  StringRef k = map.getKind();
  if (k != "percpu_array" && k != "percpu_hash" && k != "lru_percpu_hash")
    return emitOpError() << "needs a per-CPU map (\"percpu_array\", \"percpu_hash\" or \"lru_percpu_hash\"), got \"" << k << "\"";
  if (failed(checkKey(*this, map, getKey().getType())) || failed(checkRecordKey(*this, map, getKey())))
    return failure();
  auto res = cast<MaybeRefType>(getResult().getType());
  if (res.getPointee() != map.getValueType())
    return emitOpError() << "result " << getResult().getType() << " does not reference the map value type " << map.getValueType();
  return success();
}

// Keyless operations require one of kinds, key type none, and a map-matching
// integer value/result of 8/16/32/64 bits.
static LogicalResult checkKeylessMap(Operation *op, MapType map, bool ok, StringRef kinds, Type value) {
  if (!ok)
    return op->emitOpError() << "needs a " << kinds << " map, got \"" << map.getKind() << "\"";
  if (!isa<NoneType>(map.getKeyType()))
    return op->emitOpError() << "a " << map.getKind() << " map has no key — its handle is !ebpf.map<\"" << map.getKind()
                             << "\", none, V>, got key type " << map.getKeyType() << "";
  if (value != map.getValueType())
    return op->emitOpError() << "value type " << value << " does not match map value type " << map.getValueType();
  if (!isMemWidth(value))
    return op->emitOpError() << "needs an 8 / 16 / 32 / 64-bit integer value, got " << value << "";
  return success();
}

LogicalResult MapPushOp::verify() {
  auto map = cast<MapType>(getMap().getType());
  if (failed(checkKeylessMap(*this, map, bpfmlir::isKeylessMapKind(map.getKind()), "queue / stack / bloom_filter", getValue().getType())))
    return failure();
  StringRef f = getFlags();
  // Reject flags kernel would only answer with -EINVAL: queue/stack NOEXIST
    // and bloom flags other than ANY.
  if (map.getKind() == "bloom_filter" ? f != "any" : (f != "any" && f != "exist"))
    return emitOpError() << "flags for a " << map.getKind() << " map must be "
                         << (map.getKind() == "bloom_filter" ? "\"any\"" : "\"any\" or \"exist\" (exist overwrites the oldest element when full)")
                         << ", got \"" << f << "\" (the kernel returns -EINVAL otherwise)";
  return success();
}

LogicalResult MapPopOp::verify() {
  auto map = cast<MapType>(getMap().getType());
  return checkKeylessMap(*this, map, bpfmlir::isQueueOrStackMapKind(map.getKind()), "queue / stack", getValue().getType());
}

LogicalResult MapPeekOp::verify() {
  auto map = cast<MapType>(getMap().getType());
  if (map.getKind() == "bloom_filter")
    return emitOpError() << "a bloom_filter is peeked with a value — use ebpf.bloom.peek";
  return checkKeylessMap(*this, map, bpfmlir::isQueueOrStackMapKind(map.getKind()), "queue / stack", getValue().getType());
}

LogicalResult BloomPeekOp::verify() {
  auto map = cast<MapType>(getMap().getType());
  return checkKeylessMap(*this, map, map.getKind() == "bloom_filter", "bloom_filter", getValue().getType());
}

// map.inner takes a checked borrow of an outer element and returns its
// inner handle type. Keep it within the checked region.
LogicalResult MapInnerOp::verify() {
  auto b = cast<BorrowedType>(getRef().getType());
  auto inner = dyn_cast<MapType>(b.getPointee());
  if (!inner)
    return emitOpError() << "takes a checked map-in-map element !ebpf.borrowed<!ebpf.map<…>>, got " << getRef().getType() << "";
  if (inner != getInner().getType())
    return emitOpError() << "result " << getInner().getType() << " must be the borrowed inner map type " << inner << "";
  for (Operation *user : getInner().getUsers()) {
    if (isa<YieldOp, IfYieldOp, LoopYieldOp, CallOp, ReturnOp>(user))
      return emitOpError() << "an inner map handle must not leave the region where its outer element was checked (used by '"
                           << user->getName() << "')";
    // Compiler restriction: loop bodies cannot capture inner handles; callback
  // loop interfaces cannot carry them.
    if (auto loop = user->getParentOfType<LoopOp>(); loop && !loop->isProperAncestor(*this))
      return emitOpError() << "an inner map handle is not captured into an ebpf.loop body (a compiler restriction)";
  }
  return success();
}

LogicalResult StorageDeleteOp::verify() {
  return checkStorage(*this, cast<MapType>(getMap().getType()), cast<KPtrType>(getOwner().getType()));
}

// Nullable references must be checked before direct use. Shared region result
// widths are i1 and 8/16/32/64 across if/ref.check/if_reserved/packet.check/ref.index.
static LogicalResult verifyRegionResultWidths(Operation *op) {
  for (Type t : op->getResultTypes())
    if (auto it = dyn_cast<IntegerType>(t)) {
      unsigned w = it.getWidth();
      if (w != 1 && w != 8 && w != 16 && w != 32 && w != 64)
        return op->emitOpError() << "region results must be i1 or 8 / 16 / 32 / 64-bit integers, got " << t << "";
    }
  return success();
}

// kptr.check present has one kptr<S> argument, absent none; both arms yield.
LogicalResult KPtrCheckOp::verify() {
  if (failed(verifyRegionResultWidths(*this)))
    return failure();
  auto in = cast<KPtrOrNullType>(getPtr().getType());
  if (getPresentRegion().empty() || getAbsentRegion().empty())
    return emitOpError() << "both the present and absent regions must have a body";
  Block &present = getPresentRegion().front();
  if (present.getNumArguments() != 1)
    return emitOpError() << "the present region must take exactly one argument (the checked kernel pointer), got "
                         << present.getNumArguments();
  auto kp = dyn_cast<KPtrType>(present.getArgument(0).getType());
  if (!kp || kp.getStructName() != in.getStructName())
    return emitOpError() << "the present region argument must be !ebpf.kptr<\"" << in.getStructName() << "\">, got "
                         << present.getArgument(0).getType();
  if (getAbsentRegion().front().getNumArguments() != 0)
    return emitOpError() << "the absent region must take no arguments (there is no pointer), got "
                         << getAbsentRegion().front().getNumArguments();
  for (Region *r : {&getPresentRegion(), &getAbsentRegion()})
    if (r->front().empty() || !isa<YieldOp>(r->front().back()))
      return emitOpError() << "each region must end with ebpf.yield";
  return success();
}

// kref.check shares the checked-region shape with present kref<S>.
// Kfunc verification owns allowed uses; ownership verification owns path/counts.
static LogicalResult verifyKRefUses(KRefCheckOp kc);
LogicalResult KRefCheckOp::verify() {
  if (failed(verifyRegionResultWidths(*this)))
    return failure();
  auto in = cast<KRefOrNullType>(getPtr().getType());
  if (getPresentRegion().empty() || getAbsentRegion().empty())
    return emitOpError() << "both the present and absent regions must have a body";
  Block &present = getPresentRegion().front();
  if (present.getNumArguments() != 1)
    return emitOpError() << "the present region must take exactly one argument (the checked kernel reference), got "
                         << present.getNumArguments();
  auto kr = dyn_cast<KRefType>(present.getArgument(0).getType());
  if (!kr || kr.getStructName() != in.getStructName())
    return emitOpError() << "the present region argument must be !ebpf.kref<\"" << in.getStructName() << "\">, got "
                         << present.getArgument(0).getType();
  if (getAbsentRegion().front().getNumArguments() != 0)
    return emitOpError() << "the absent region must take no arguments (there is no reference), got "
                         << getAbsentRegion().front().getNumArguments();
  for (Region *r : {&getPresentRegion(), &getAbsentRegion()})
    if (r->front().empty() || !isa<YieldOp>(r->front().back()))
      return emitOpError() << "each region must end with ebpf.yield";
  return verifyKRefUses(*this);
}

// kfunc rows own names/types/flags/program types. Supported type spellings
// are void, i8..u64 and *struct. Check owned-reference use shapes here;
// ownership verification separately checks counts and paths.
static std::optional<StringRef> kfuncStructOf(StringRef spelling) {
  if (spelling.size() > 1 && spelling.front() == '*')
    return spelling.drop_front();
  return std::nullopt;
}
static std::optional<unsigned> kfuncIntBits(StringRef spelling) {
  unsigned bits = 0;
  if (spelling.size() < 2 || (spelling.front() != 'i' && spelling.front() != 'u') || spelling.drop_front().getAsInteger(10, bits))
    return std::nullopt;
  return bits;
}
// Generic kfunc.call supports void/integer/struct-pointer signatures.
// Session bool, void* and integer-pointer signatures use dedicated session ops.
static bool kfuncGenericSpelling(StringRef s, bool ret) {
  if (s == "void")
    return ret;
  if (kfuncIntBits(s))
    return true;
  std::optional<StringRef> st = kfuncStructOf(s);
  return st && *st != "void" && !kfuncIntBits(*st);
}

LogicalResult KfuncCallOp::verify() {
  const bpfabi::KfuncABI *k = bpfabi::lookupKfunc(getCallee());
  if (!k)
    return emitOpError() << "calls \"" << getCallee() << "\", which is not in the kfunc table (UAPI table kfunc rows: "
                         << bpfabi::listKfuncs() << ")";
  bool generic = kfuncGenericSpelling(k->ret, /*ret=*/true);
  for (auto &[pname, ptype] : k->paramList())
    generic = generic && kfuncGenericSpelling(ptype, /*ret=*/false);
  if (!generic)
    return emitOpError() << "kfunc \"" << getCallee() << "\" has a bool, void * or integer pointer in its signature ("
                         << k->ret << " (" << k->params << ")); call it through its own op (ebpf.session.*)";
  // Reject unknown kfunc flags rather than silently calling unsupported contracts.
  if (k->flags != "-") {
    SmallVector<StringRef> fs;
    StringRef(k->flags).split(fs, ',');
    for (StringRef f : fs)
      if (f != "acquire" && f != "release" && f != "ret_null" && f != "rcu")
        return emitOpError() << "kfunc \"" << getCallee() << "\" has the flag KF_" << f.upper()
                             << ", which the compiler does not model";
  }
  bool acquire = k->hasFlag("acquire"), release = k->hasFlag("release"), retNull = k->hasFlag("ret_null");
  // Require program bodies; ownership does not traverse arbitrary regions, funcs or callbacks.
  Operation *top = *this;
  for (Operation *p = (*this)->getParentOp(); p; p = p->getParentOp()) {
    if (isa<ProgramOp>(p)) {
      top = p;
      break;
    }
    if (isa<LoopOp, MapForEachOp, SpinRegionOp>(p) || p->getName().getStringRef() == "scf.if")
      return emitOpError() << "calls a kfunc inside '" << p->getName()
                           << "'; kfunc calls are only allowed in the body of an ebpf.program outside loops, map.for_each, "
                              "spin.region and scf.if (the ownership check does not follow them)";
    top = p;
  }
  auto prog = dyn_cast<ProgramOp>(top);
  if (!prog)
    return emitOpError() << "calls a kfunc outside an ebpf.program (ebpf.func and callbacks cannot call kfuncs)";
  StringRef ptype = programTypeOf(prog.getKind());
  if (!k->allowsProgType(ptype))
    return emitOpError() << "kfunc \"" << getCallee() << "\" is not registered for program type " << ptype << " (kind \""
                         << prog.getKind() << "\"); the kfunc table allows " << k->progTypes << "";
  // Arguments.
  auto params = k->paramList();
  if (params.size() != getArgs().size())
    return emitOpError() << "kfunc \"" << getCallee() << "\" takes " << params.size() << " argument(s), got " << getArgs().size();
  unsigned released = 0;
  for (auto [i, pv] : llvm::enumerate(params)) {
    auto [pname, ptyp] = pv;
    Type got = getArgs()[i].getType();
    if (std::optional<unsigned> bits = kfuncIntBits(ptyp)) {
      if (!got.isInteger(*bits))
        return emitOpError() << "kfunc \"" << getCallee() << "\" argument " << i << " (" << pname << ") is " << ptyp << ", got " << got;
      continue;
    }
    StringRef s = *kfuncStructOf(ptyp);
    if (release) {
      auto kr = dyn_cast<KRefType>(got);
      if (!kr || kr.getStructName() != s)
        return emitOpError() << "kfunc \"" << getCallee() << "\" releases argument " << i << " (" << pname
                             << "); pass the acquired reference !ebpf.kref<\"" << s << "\">, got " << got;
      ++released;
      continue;
    }
    StringRef have = isa<KRefType>(got) ? cast<KRefType>(got).getStructName()
                     : isa<KPtrType>(got) ? cast<KPtrType>(got).getStructName()
                                          : StringRef();
    if (have != s || have.empty())
      return emitOpError() << "kfunc \"" << getCallee() << "\" argument " << i << " (" << pname << ") is a pointer to struct " << s
                           << "; pass !ebpf.kref<\"" << s << "\"> or !ebpf.kptr<\"" << s << "\">, got " << got;
  }
  if (release && released != 1)
    return emitOpError() << "kfunc \"" << getCallee() << "\" is a KF_RELEASE kfunc with " << released
                         << " struct pointer arguments; the compiler models exactly one released reference";
  // Results.
  StringRef ret = k->ret;
  if (ret == "void") {
    if (getNumResults() != 0)
      return emitOpError() << "kfunc \"" << getCallee() << "\" returns void, got " << getNumResults() << " result(s)";
  } else if (std::optional<unsigned> bits = kfuncIntBits(ret)) {
    if (getNumResults() != 1 || !getResult(0).getType().isInteger(*bits))
      return emitOpError() << "kfunc \"" << getCallee() << "\" returns " << ret << " (one i" << *bits << " result)";
  } else {
    StringRef s = *kfuncStructOf(ret);
    if (!acquire)
      return emitOpError() << "kfunc \"" << getCallee() << "\" returns a struct pointer without KF_ACQUIRE; the compiler only "
                              "models acquired references";
    Type want = retNull ? Type(KRefOrNullType::get(getContext(), s)) : Type(KRefType::get(getContext(), s));
    if (getNumResults() != 1 || getResult(0).getType() != want)
      return emitOpError() << "kfunc \"" << getCallee() << "\" returns an acquired " << (retNull ? "possibly-NULL " : "")
                           << "reference to struct " << s << "; the result must be " << want;
  }
  if (acquire && ret == "void")
    return emitOpError() << "kfunc \"" << getCallee() << "\" is KF_ACQUIRE but returns void";
  // Nullable owned references require one kref.check. Present refs permit
  // supported kfunc arguments and kernel field reads.
  if (getNumResults() == 1) {
    Value r = getResult(0);
    // VerifyStructured owns uses after expansion into is_present/assume_present.
    bool stage2 = llvm::any_of(r.getUsers(), [](Operation *u) { return isa<IsPresentOp, AssumePresentOp>(u); });
    if (isa<KRefOrNullType>(r.getType()) && !stage2) {
      unsigned checks = 0;
      for (OpOperand &use : r.getUses()) {
        if (isa<KRefCheckOp>(use.getOwner())) {
          ++checks;
          continue;
        }
        return use.getOwner()->emitOpError() << "uses an unchecked kernel reference " << r.getType()
                                             << "; check it with ebpf.kref.check first";
      }
      if (checks != 1)
        return emitOpError() << "the acquired reference " << r.getType() << " must be checked exactly once by ebpf.kref.check, found "
                             << checks << " (an unchecked reference leaks)";
    }
  }
  return success();
}

// Present krefs permit kfunc arguments and supported kernel-field operations.
static LogicalResult verifyKRefUses(KRefCheckOp kc) {
  Value v = kc.getPresentRegion().front().getArgument(0);
  for (OpOperand &use : v.getUses()) {
    Operation *u = use.getOwner();
    if (isa<KfuncCallOp>(u) || (isa<KFieldLoadOp, KPtrAddrOp>(u) && use.getOperandNumber() == 0))
      continue;
    if (auto x = dyn_cast<KPtrXchgOp>(u); x && x.getNewRef() == v) // Transferring to a map consumes ownership.
      continue;
    return u->emitOpError() << "uses the kernel reference " << v.getType()
                            << "; a kref may only be an argument of ebpf.kfunc.call, the pointer of ebpf.kfield.load or the new "
                               "reference of ebpf.kptr.xchg (it must not be yielded, passed to ebpf.call or captured)";
  }
  return success();
}

// kptr.xchg exchanges a record kptr field and reference. VerifyRecords owns
// field/type matching, VerifyKPtr owns target declarations, and ownership
// analysis owns new-reference consumption and result-check counts.
LogicalResult KPtrXchgOp::verify() {
  auto b = dyn_cast<BorrowedType>(getRef().getType());
  if (!b || !isa<RecordType>(b.getPointee()))
    return emitOpError() << "takes a checked borrow of a map value record (!ebpf.borrowed<!ebpf.record<…>> — the block argument of "
                            "ebpf.ref.check), got "
                         << getRef().getType() << "";
  SmallVector<StringRef> fields;
  getField().split(fields, '.', -1, true);
  if (fields.size() > 3 || getField().contains('[') || getField().contains(']') ||
      llvm::any_of(fields, [](StringRef f) { return f.empty(); }))
    return emitOpError() << "field \"" << getField()
                         << "\" must be a non-empty dotted path of at most 3 record fields, without array indices";
  StringRef t = cast<KRefOrNullType>(getOld().getType()).getStructName();
  if (Value n = getNewRef()) {
    auto kr = cast<KRefType>(n.getType());
    if (kr.getStructName() != t)
      return emitOpError() << "puts a !ebpf.kref<\"" << kr.getStructName() << "\"> into a field whose result is "
                           << getOld().getType() << "; the struct must be the same";
  }
  // Like kfunc.call, restrict to program bodies covered by ownership traversal.
  Operation *top = *this;
  for (Operation *p = (*this)->getParentOp(); p; p = p->getParentOp()) {
    if (isa<ProgramOp>(p)) {
      top = p;
      break;
    }
    if (isa<LoopOp, MapForEachOp, SpinRegionOp>(p) || p->getName().getStringRef() == "scf.if")
      return emitOpError() << "is inside '" << p->getName()
                           << "'; ebpf.kptr.xchg is only allowed in the body of an ebpf.program outside loops, map.for_each, "
                              "spin.region and scf.if (the ownership check does not follow them)";
    top = p;
  }
  if (!isa<ProgramOp>(top))
    return emitOpError() << "is outside an ebpf.program (ebpf.func and callbacks cannot exchange kptrs)";
  // The removed reference needs one kref.check, like acquire results; expanded
  // checks are verified by VerifyStructured.
  Value r = getOld();
  bool stage2 = llvm::any_of(r.getUsers(), [](Operation *u) { return isa<IsPresentOp, AssumePresentOp>(u); });
  if (!stage2) {
    unsigned checks = 0;
    for (OpOperand &use : r.getUses()) {
      if (isa<KRefCheckOp>(use.getOwner())) {
        ++checks;
        continue;
      }
      return use.getOwner()->emitOpError() << "uses an unchecked kernel reference " << r.getType()
                                           << " taken out of a map value; check it with ebpf.kref.check first";
    }
    if (checks != 1)
      return emitOpError() << "the reference taken out of the map value " << r.getType()
                           << " must be checked exactly once by ebpf.kref.check, found " << checks
                           << " (an unchecked reference leaks)";
  }
  return success();
}

LogicalResult RefCheckOp::verify() {
  if (failed(verifyRegionResultWidths(*this)))
    return failure();
  auto in = cast<MaybeRefType>(getRef().getType());

  if (getPresentRegion().empty() || getAbsentRegion().empty())
    return emitOpError() << "both the present and absent regions must have a body";

  Block &present = getPresentRegion().front();
  if (present.getNumArguments() != 1)
    return emitOpError() << "the present region must take exactly one argument "
                         << "(the borrowed reference), got "
                         << present.getNumArguments();
  auto borrowed = dyn_cast<BorrowedType>(present.getArgument(0).getType());
  if (!borrowed)
    return emitOpError() << "the present region argument must be "
                         << "!ebpf.borrowed<...>, got "
                         << present.getArgument(0).getType();
  if (borrowed.getPointee() != in.getPointee())
    return emitOpError() << "the borrowed reference must keep the pointee type: "
                         << in.getPointee() << " vs " << borrowed.getPointee();

  Block &absent = getAbsentRegion().front();
  if (absent.getNumArguments() != 0)
    return emitOpError() << "the absent region must take no arguments (there is "
                         << "no reference to borrow), got "
                         << absent.getNumArguments();

  // break/continue arms supply no result. If both arms escape, results are forbidden.
  if (getNumResults() != 0 && !present.empty() && !absent.empty() &&
      isa<BreakOp, ContinueOp>(present.back()) && isa<BreakOp, ContinueOp>(absent.back()))
    return emitOpError() << "cannot have results when both regions leave the loop (no edge "
                            "reaches the join)";

  // Borrowed references live only within the present region; reject escape.
  BlockArgument ref = present.getArgument(0);
  // Outer-map element borrows may only become inner handles through map.inner.
  if (isa<MapType>(in.getPointee())) {
    for (Operation *user : ref.getUsers())
      if (!isa<MapInnerOp>(user))
        return emitOpError() << "a borrowed inner map may only be consumed by ebpf.map.inner, but it is used by '" << user->getName() << "'";
  }
  for (Operation *user : ref.getUsers()) {
    // Calls complete inside the region and cannot return pointers. ref.index
    // elements and closed spin regions also end within it. Timer operations
    // pass only the embedded timer pointer; kfield.copy writes bytes without
    // retaining the destination reference.
    if (!isa<RefLoadOp, RefStoreOp, RefAtomicAddOp, RefFieldLoadOp, RefFieldStoreOp, RefFieldAtomicAddOp, CallOp, RefIndexOp, SpinRegionOp,
             TimerInitOp, TimerSetCallbackOp, TimerStartOp, KFieldCopyOp, TpFieldCopyOp, MapInnerOp, KPtrXchgOp>(user)) // map.inner for validated outer-map borrows, and kptr.xchg.
      return emitOpError() << "a borrowed reference may only be consumed by "
                           << "ebpf.ref.{load,store,atomic_add} (ebpf.ref.field.{load,store} for records), ebpf.ref.index, ebpf.spin.region, "
                           << "ebpf.timer.{init,set_callback,start}, or passed to ebpf.call, but it is used by '"
                           << user->getName()
                           << "' (storing or forwarding it lets it escape the "
                              "check region)";
    if (!getPresentRegion().isAncestor(user->getParentRegion()))
      return emitOpError() << "a borrowed reference must be used inside the "
                           << "present region of its own ebpf.ref.check";
  }

  // Do not circulate checked references through block arguments.
  for (Block &blk : getPresentRegion())
    if (&blk != &present)
      for (BlockArgument arg : blk.getArguments())
        if (isa<BorrowedType>(arg.getType()))
          return emitOpError() << "a borrowed reference must not be carried "
                               << "across blocks as a block argument";

  return success();
}

// Context kind comes from the enclosing program, or a static subprogram's
// typed ctx argument (matching its caller). Otherwise no kind is established.
static StringRef ctxOwnerKind(Operation *op, Value ctx) {
  if (auto prog = op->getParentOfType<ProgramOp>())
    return prog.getKind();
  if (op->getParentOfType<SubprogramOp>())
    return cast<ContextType>(ctx.getType()).getKind();
  return StringRef();
}

// ctx.field/store require the entry context, a CTX struct integer member,
// and an ABI ctxaccess capability row matching program/attach/struct/field/
// mode and width.
static LogicalResult verifyCtxFieldAccess(Operation *op, Value ctx, StringRef field, Type valueType, StringRef mode,
                                          std::optional<uint64_t> index = std::nullopt) {
  auto prog = op->getParentOfType<ProgramOp>();
  if (!prog || prog.getBody().empty() || prog.getBody().front().getNumArguments() < 1 || ctx != prog.getBody().front().getArgument(0))
    return op->emitOpError() << "needs the context argument of the enclosing ebpf.program (the readable fields depend on the program's attach "
                                "type — not in a static ebpf.func)";
  const bpfmlir::ProgramKindInfo *info = bpfmlir::lookupProgramKind(prog.getKind());
  if (!info)
    return op->emitOpError() << "unknown program kind \"" << prog.getKind() << "\"";
  if (info->ctxStruct == "-")
    return op->emitOpError() << "a " << prog.getKind() << " program has no struct context (ebpf.ctx.field reads "
                             << bpfmlir::joinProgramKinds([](auto &k) { return k.ctxStruct != "-"; }, "", ", ", " and ") << " contexts)";
  StringRef strct = info->ctxStruct;
  const mlir::bpfabi::StructFieldABI *f = mlir::bpfabi::lookupStructField(strct, field);
  if (!f)
    return op->emitOpError() << "\"" << field << "\" is not a field of " << strct << " in the UAPI table";
  // Flexible arrays require constant indices below kMaxFlexCtxIndex; scalar
  // fields forbid indices. Fixed arrays such as __sk_buff cb are unsupported
  // here because capability probes cover only their first element.
  if (f->count == 0) {
    if (!index)
      return op->emitOpError() << strct << "." << field << " is a flexible array — read an element with a constant index (\"" << field
                               << "\"[i])";
    if (static_cast<int64_t>(*index) < 0 || static_cast<int64_t>(*index) >= mlir::bpfabi::kMaxFlexCtxIndex)
      return op->emitOpError() << "index " << static_cast<int64_t>(*index) << " of " << strct << "." << field << " is out of range (0.."
                               << mlir::bpfabi::kMaxFlexCtxIndex - 1 << " — the kernel accepts ctx offsets below 8 × MAX_BPF_FUNC_ARGS)";
  } else if (index) {
    return op->emitOpError() << strct << "." << field << (f->count == 1 ? " is not an array — it takes no index"
                                                                         : " is a fixed-length array — element reads are not supported");
  } else if (f->count != 1) {
    return op->emitOpError() << strct << "." << field << " is a fixed-length array — element reads are not supported";
  }
  // expected_attach_type comes from the program's attachment row, validated there.
  const bpfmlir::ProgramAttachInfo *arow = bpfmlir::lookupProgramAttach(*info, programAttachOf(prog));
  if (!arow)
    return success();
  std::string atype = bpfmlir::attachTypeOf(*arow, programAttachOf(prog));
  // Capability btf pointee names permit only matching kptr reads; fields
  // without such evidence cannot be read as kernel pointers.
  const mlir::bpfabi::CtxBTFPtrABI *bp = mlir::bpfabi::lookupCtxBTFPtr(info->progType, atype, strct, field);
  // Do not expose pointer context fields as integers: they contain kernel
  // addresses. Only fields with capability BTF pointee evidence permit kptr reads.
  if (f->kind != "int" && !bp)
    return op->emitOpError() << strct << "." << field << " is a " << f->kind
                             << " field in the UAPI table; ebpf.ctx.field reads and writes integer fields only, "
                                "or pointer fields with a BTF struct in the ctx access table";
  const mlir::bpfabi::CtxAccessABI *a = mlir::bpfabi::lookupCtxAccess(info->progType, atype, strct, field, mode);
  if (!a)
    return op->emitOpError() << (mode == "r" ? "cannot read " : "cannot write ") << strct << "." << field << " in a " << prog.getKind()
                             << " program (program type " << info->progType << ", attach type " << atype
                             << "); the compiler's ctx access table (abi/ctxaccess.tsv) has "
                             << (mode == "r" ? "readable" : "writable") << " fields "
                             << mlir::bpfabi::listCtxAccess(info->progType, atype, strct, mode);
  if (auto kp = dyn_cast<KPtrType>(valueType)) {
    if (!bp)
      return op->emitOpError() << strct << "." << field << " is not a pointer field with a BTF struct in the ctx access table "
                                  "(abi/ctxaccess.tsv column btf) — it cannot be read as "
                               << valueType;
    if (kp.getStructName() != bp->btfStruct)
      return op->emitOpError() << strct << "." << field << " points to struct " << bp->btfStruct
                               << " (the verifier's BTF type in the ctx access table) — read it as !ebpf.kptr<\"" << bp->btfStruct
                               << "\">, got " << valueType;
    return success();
  }
  if (bp)
    return op->emitOpError() << strct << "." << field << " is a pointer to struct " << bp->btfStruct << " — read it as !ebpf.kptr<\""
                             << bp->btfStruct << "\"> (an integer read would expose the kernel address), got " << valueType;
  if (!valueType.isInteger(static_cast<unsigned>(a->bytes * 8)))
    return op->emitOpError() << strct << "." << field << " is " << a->bytes << " bytes wide in the ctx access table — use i"
                             << a->bytes * 8 << ", got " << valueType;
  return success();
}

static LogicalResult checkCgroupArray(Operation *op, MapType map) {
  if (map.getKind() != "cgroup_array" || !map.getKeyType().isInteger(32) || !map.getValueType().isInteger(32))
    return op->emitOpError() << "needs a cgroup_array map with i32 key and value";
  return success();
}

LogicalResult TaskUnderCgroupOp::verify() { return checkCgroupArray(*this, cast<MapType>(getMap().getType())); }

LogicalResult SkbUnderCgroupOp::verify() {
  if (cast<ContextType>(getCtx().getType()).getKind() != "sched_cls")
    return emitOpError() << "only for sched_cls entry contexts";
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || prog.getBody().empty() || prog.getBody().front().getNumArguments() == 0 ||
      getCtx() != prog.getBody().front().getArgument(0))
    return emitOpError() << "needs the context argument of the enclosing ebpf.program";
  return checkCgroupArray(*this, cast<MapType>(getMap().getType()));
}

LogicalResult SysctlSetNewValueOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  auto ct = cast<ContextType>(getCtx().getType());
  if (!prog || !bpfmlir::kindAllows(prog.getKind(), "sysctl.set") ||
      ct.getKind() != prog.getKind() || getCtx() != prog.getBody().front().getArgument(0) ||
      (*this)->getParentOfType<SubprogramOp>() || (*this)->getParentOfType<LoopCallbackOp>())
    return emitOpError("requires own cgroup_sysctl entry context");
  if ((*this)->getParentOfType<LoopOp>())
    return emitOpError("is not allowed inside ebpf.loop");
  if (getLiteral().empty() || getLiteral().size() > 64)
    return emitOpError("requires a 1..64 byte literal (raw bytes, no implicit NUL)");
  return success();
}

static LogicalResult verifyTpBufferAccess(Operation *op, Value ctx, int64_t offset, Type scalar) {
  auto prog = op->getParentOfType<ProgramOp>();
  auto ct = dyn_cast<ContextType>(ctx.getType());
  if (!ct || !prog || prog.getBody().empty() || prog.getBody().front().getNumArguments() < 1 ||
      ctx != prog.getBody().front().getArgument(0) || !bpfmlir::kindAllows(prog.getKind(), "tp.buffer") ||
      ct.getKind() != prog.getKind())
    return op->emitOpError("tp.buffer: requires own raw_tp_writable entry context");
  if (offset != 0)
    return op->emitOpError("tp.buffer: requires buffer byte offset 0");
  if (!scalar.isSignlessInteger(32))
    return op->emitOpError("tp.buffer: requires signless i32");
  return success();
}

LogicalResult TpBufferLoadOp::verify() { return verifyTpBufferAccess(*this, getCtx(), getOffset(), getResult().getType()); }
LogicalResult TpBufferStoreOp::verify() { return verifyTpBufferAccess(*this, getCtx(), getOffset(), getValue().getType()); }

LogicalResult CtxFieldOp::verify() {
  return verifyCtxFieldAccess(*this, getCtx(), getField(), getResult().getType(), "r",
                              getIndex() ? std::optional<uint64_t>(*getIndex()) : std::nullopt);
}
LogicalResult CtxFieldStoreOp::verify() { return verifyCtxFieldAccess(*this, getCtx(), getField(), getValue().getType(), "w"); }

// flow_keys requires an OPS-enabled entry context and ABI bpf_flow_keys
// integer members with matching width. Four-element fields require constant
// indices in 0..count-1.
static LogicalResult verifyFlowKeysAccess(Operation *op, Value ctx, StringRef field, std::optional<uint64_t> index, Type valueType) {
  auto ct = cast<ContextType>(ctx.getType());
  if (!bpfmlir::kindAllows(ct.getKind(), "flow_keys"))
    return op->emitOpError() << "flow_keys is only for " << bpfmlir::kindsAllowing("flow_keys") << " programs, not \"" << ct.getKind()
                             << "\" (the ctx's flow_keys points to struct bpf_flow_keys only in a flow dissector)";
  auto prog = op->getParentOfType<ProgramOp>();
  if (!prog || prog.getBody().empty() || prog.getBody().front().getNumArguments() < 1 || ctx != prog.getBody().front().getArgument(0))
    return op->emitOpError() << "needs the context argument of the enclosing ebpf.program (not in a static ebpf.func)";
  static constexpr llvm::StringLiteral kStruct = "bpf_flow_keys";
  const mlir::bpfabi::StructFieldABI *f = mlir::bpfabi::lookupStructField(kStruct, field);
  if (!f || f->kind != "int") {
    std::string known;
    for (const mlir::bpfabi::StructFieldABI &g : mlir::bpfabi::structFieldsOf(kStruct))
      known += std::string(known.empty() ? "" : ", ") + "\"" + g.field.str() + "\"";
    return op->emitOpError() << "\"" << field << "\" is not a field of struct bpf_flow_keys in the UAPI table (known: " << known << ")";
  }
  if (f->count == 1 && index)
    return op->emitOpError() << "bpf_flow_keys." << field << " is not an array — it takes no index";
  if (f->count != 1) {
    if (!index)
      return op->emitOpError() << "bpf_flow_keys." << field << " is an array of " << f->count << " — access an element with a constant index (\""
                               << field << "\"[i])";
    if (static_cast<int64_t>(*index) < 0 || static_cast<int64_t>(*index) >= f->count)
      return op->emitOpError() << "index " << static_cast<int64_t>(*index) << " of bpf_flow_keys." << field << " is out of range (0.."
                               << f->count - 1 << ")";
  }
  if (!valueType.isInteger(static_cast<unsigned>(f->bytes * 8)))
    return op->emitOpError() << "bpf_flow_keys." << field << " is " << f->bytes << " bytes wide in the UAPI table — use i" << f->bytes * 8
                             << ", got " << valueType;
  return success();
}

LogicalResult FlowKeysLoadOp::verify() {
  return verifyFlowKeysAccess(*this, getCtx(), getField(), getIndex() ? std::optional<uint64_t>(*getIndex()) : std::nullopt,
                              getResult().getType());
}
LogicalResult FlowKeysStoreOp::verify() {
  return verifyFlowKeysAccess(*this, getCtx(), getField(), getIndex() ? std::optional<uint64_t>(*getIndex()) : std::nullopt,
                              getValue().getType());
}

// Kind-specific operations require an OPS capability and matching context kind.
static bool ownerKindAllows(Operation *op, Value ctx, StringRef tag) {
  StringRef k = ctxOwnerKind(op, ctx);
  return !k.empty() && bpfmlir::kindAllows(k, tag) && cast<ContextType>(ctx.getType()).getKind() == k;
}

static LogicalResult verifyUserArrayUses(Operation *op, Value value) {
  if (!isa<UserStrArrayType>(value.getType()))
    return success();
  for (Operation *user : value.getUsers())
    if (!isa<UserStrAtOp>(user))
      return op->emitOpError("user_str_array may only be used directly by user.str_at (no cast, select, store or escape)");
  return success();
}

LogicalResult UserStrAtOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || !bpfmlir::kindAllows(prog.getKind(), "user.str_at"))
    return emitOpError("requires a tracepoint or ksyscall program (not a static function)");
  if ((*this)->getParentOfType<LoopOp>())
    return emitOpError("is not allowed inside ebpf.loop");
  int64_t index = static_cast<int64_t>(getIndex());
  if (index < 0 || index > 19)
    return emitOpError("index must be a constant attribute in 0..19");
  Operation *source = getArray().getDefiningOp();
  if (!source || !isa<TpFieldOp, KsyscallArgOp>(source) || source->getParentOfType<ProgramOp>() != prog)
    return emitOpError("array must be the direct tp.field or ksyscall.arg result of this program");
  return verifyUserArrayUses(source, getArray());
}

// perf.output requires its supported context, i32/i32 perf_event_array and
// a record.make value with every byte initialized.
LogicalResult PerfOutputOp::verify() {
  if (!ownerKindAllows(*this, getCtx(), "perf.output"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("perf.output") << " programs";
  auto m = dyn_cast<MapType>(getMap().getType());
  if (!m || m.getKind() != "perf_event_array")
    return emitOpError() << "needs a perf_event_array map, got " << getMap().getType();
  if (!m.getKeyType().isInteger(32) || !m.getValueType().isInteger(32))
    return emitOpError() << "a perf_event_array map has an i32 key and an i32 value (the perf event fd — the payload is the record)";
  if (!getRecord().getDefiningOp<RecordMakeOp>())
    return emitOpError() << "the data must be built by ebpf.record.make (every byte, padding zeroed)";
  return success();
}

// sk_reuseport requires the OPS context and reuseport_sockarray with i32
// keys and i32/i64 socket-FD values; key operands match the handle type.
static LogicalResult checkSockMapKey(Operation *op, Value mapV, Value key);

// Sockmap/sockhash selection is also allowed with their key rules; sockets
  // outside the reuseport group yield -EINVAL.
LogicalResult SkSelectReuseportOp::verify() {
  if (!ownerKindAllows(*this, getCtx(), "sk.select_reuseport"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("sk.select_reuseport") << " programs with their own context";
  auto m = dyn_cast<MapType>(getMap().getType());
  if (m && (m.getKind() == "sockmap" || m.getKind() == "sockhash"))
    return checkSockMapKey(*this, getMap(), getKey());
  if (!m || m.getKind() != "reuseport_sockarray")
    return emitOpError() << "needs a reuseport_sockarray, sockmap or sockhash map, got " << getMap().getType();
  if (!m.getKeyType().isInteger(32) || !(m.getValueType().isInteger(32) || m.getValueType().isInteger(64)))
    return emitOpError() << "a reuseport_sockarray map has an i32 key and an i32 or i64 value (the socket — set by userspace)";
  if (getKey().getType() != m.getKeyType())
    return emitOpError() << "key type " << getKey().getType() << " does not match map key type " << m.getKeyType();
  return success();
}

// Reuseport socket-cookie fields are limited to sk and migrating_sk.
LogicalResult SkReuseportCookieOp::verify() {
  if (!ownerKindAllows(*this, getCtx(), "sk.reuseport_cookie"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("sk.reuseport_cookie") << " programs with their own context";
  if (getField() != "sk" && getField() != "migrating_sk")
    return emitOpError() << "reads the cookie of the socket pointer field \"sk\" or \"migrating_sk\", got \"" << getField()
                         << "\" (integer fields are read with ebpf.ctx.field)";
  return success();
}

// sockmap keys are i32 (redirect passes a value; update passes its address).
// sockhash passes a pointer to its declared key type. Operand types must agree.
static LogicalResult checkSockMapKey(Operation *op, Value mapV, Value key) {
  auto m = dyn_cast<MapType>(mapV.getType());
  if (!m || (m.getKind() != "sockmap" && m.getKind() != "sockhash"))
    return op->emitOpError() << "needs a sockmap or sockhash map, got " << mapV.getType();
  if (m.getKind() == "sockmap" && !m.getKeyType().isInteger(32))
    return op->emitOpError() << "a sockmap map has an i32 key (the slot), got " << m.getKeyType();
  if (key.getType() != m.getKeyType())
    return op->emitOpError() << "key type " << key.getType() << " does not match map key type " << m.getKeyType();
  return success();
}

// Socket/message redirect terminators require their OPS and enclosing-kind
// context; conditional when also requires an else verdict.
static LogicalResult verifySockRedirect(Operation *op, StringRef tag, StringRef helperFamily, Value ctx, Value mapV, Value key, Value cond,
                                        std::optional<StringRef> elseAction) {
  llvm::StringRef kind = op->getParentOfType<ProgramOp>().getKind();
  if (!bpfmlir::kindAllows(kind, tag) || cast<ContextType>(ctx.getType()).getKind() != kind)
    return op->emitOpError() << "is only for " << bpfmlir::kindsAllowing(tag) << " programs with their own context (" << helperFamily
                             << "), not \"" << kind << "\"";
  if (failed(checkSockMapKey(op, mapV, key)))
    return failure();
  if (cond && !elseAction)
    return op->emitOpError() << "`when` needs an `else` verdict";
  if (elseAction && !isVerdictAllowedFor(kind, programAttachOf(op), *elseAction))
    return op->emitOpError() << "verdict \"" << *elseAction << "\" is not valid for program kind \"" << kind
                             << "\" (known: " << knownVerdicts(kind, programAttachOf(op)) << ")";
  return success();
}

LogicalResult SkRedirectOp::verify() {
  return verifySockRedirect(*this, "sk.redirect", "bpf_sk_redirect_map / bpf_sk_redirect_hash", getCtx(), getMap(), getKey(), getCond(),
                            getElseAction() ? std::optional<StringRef>(*getElseAction()) : std::nullopt);
}

LogicalResult MsgRedirectOp::verify() {
  return verifySockRedirect(*this, "msg.redirect", "bpf_msg_redirect_map / bpf_msg_redirect_hash", getCtx(), getMap(), getKey(), getCond(),
                            getElseAction() ? std::optional<StringRef>(*getElseAction()) : std::nullopt);
}

// sk_msg helpers require the OPS-enabled program's own entry context, not
// static funcs/callbacks: pull/pop invalidate caller windows across calls.
// apply/cork share that restriction. Loop allowed-op checks reject them too.
static LogicalResult verifyMsgHelperOp(Operation *op, Value ctx, StringRef tag) {
  auto prog = op->getParentOfType<ProgramOp>();
  if (!prog || !bpfmlir::kindAllows(prog.getKind(), tag) || cast<ContextType>(ctx.getType()).getKind() != prog.getKind() ||
      prog.getBody().empty() || prog.getBody().front().getNumArguments() == 0 || ctx != prog.getBody().front().getArgument(0) ||
      op->getParentOfType<SubprogramOp>() || op->getParentOfType<LoopCallbackOp>())
    return op->emitOpError() << "is only for " << bpfmlir::kindsAllowing(tag)
                             << " programs with their own entry context (the bpf_msg_* helpers act on the message of the running sk_msg program)";
  return success();
}

LogicalResult MsgApplyBytesOp::verify() { return verifyMsgHelperOp(*this, getCtx(), "msg.apply_bytes"); }
LogicalResult MsgCorkBytesOp::verify() { return verifyMsgHelperOp(*this, getCtx(), "msg.cork_bytes"); }
LogicalResult MsgPullDataOp::verify() { return verifyMsgHelperOp(*this, getCtx(), "msg.pull_data"); }
LogicalResult MsgPopDataOp::verify() { return verifyMsgHelperOp(*this, getCtx(), "msg.pop_data"); }

// sock_ops updates require matching OPS context, sockmap/sockhash and one
// of three update flags; ABI lowering resolves numeric values.
LogicalResult SockMapUpdateOp::verify() {
  if (!ownerKindAllows(*this, getCtx(), "sock.map_update"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("sock.map_update")
                         << " programs with their own context (bpf_sock_map_update / bpf_sock_hash_update)";
  if (failed(checkSockMapKey(*this, getMap(), getKey())))
    return failure();
  StringRef f = getFlags();
  if (f != "any" && f != "noexist" && f != "exist")
    return emitOpError() << "flags must be \"any\", \"noexist\" or \"exist\", got \"" << f << "\"";
  return success();
}

// Kernel stack IDs require supported context, stack_trace i32/stack<D>,
// and nonnegative skip; ABI lowering checks the upper bound.
LogicalResult StackKernelIdOp::verify() {
  if (!ownerKindAllows(*this, getCtx(), "stack.kernel_id"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("stack.kernel_id") << " programs (other kinds take the stack differently)";
  auto m = dyn_cast<MapType>(getMap().getType());
  if (!m || m.getKind() != "stack_trace")
    return emitOpError() << "needs a stack_trace map, got " << getMap().getType();
  // Kernel-stack build-ID maps silently produce only IP status, so reject them here.
  if (isa<StackBuildIdType>(m.getValueType()))
    return emitOpError() << "a build id stack_trace map (!ebpf.stack_build_id) is only for ebpf.stack.user_id — a kernel stack falls back to status IP for every entry";
  auto st = dyn_cast<StackType>(m.getValueType());
  if (!m.getKeyType().isInteger(32) || !st || st.getDepth() < 1)
    return emitOpError() << "a stack_trace map has an i32 key and a !ebpf.stack<depth> value (depth >= 1)";
  // I64Attr getters return uint64_t; inspect negative values as signed.
  if (static_cast<int64_t>(getSkip()) < 0)
    return emitOpError() << "skip must be >= 0, got " << static_cast<int64_t>(getSkip());
  return success();
}

// User-stack IDs require matching program/context kinds and kernel_id map/skip rules.
LogicalResult StackUserIdOp::verify() {
  if (!ownerKindAllows(*this, getCtx(), "stack.user_id")) // OPS selects support; retain the existing diagnostic kind order.
    return emitOpError() << "is only for uprobe, kprobe and fentry programs with their own context";
  auto m = dyn_cast<MapType>(getMap().getType());
  if (!m || m.getKind() != "stack_trace")
    return emitOpError() << "needs a stack_trace map, got " << getMap().getType();
  // user_id additionally permits stack_build_id<D> maps.
  int64_t depth = 0;
  if (auto st = dyn_cast<StackType>(m.getValueType()))
    depth = st.getDepth();
  else if (auto sb = dyn_cast<StackBuildIdType>(m.getValueType()))
    depth = sb.getDepth();
  if (!m.getKeyType().isInteger(32) || depth < 1)
    return emitOpError() << "a stack_trace map has an i32 key and a !ebpf.stack<depth> or !ebpf.stack_build_id<depth> value (depth >= 1)";
  if (static_cast<int64_t>(getSkip()) < 0)
    return emitOpError() << "skip must be >= 0, got " << static_cast<int64_t>(getSkip());
  return success();
}

// tail_call is a top-level program terminator with i32 slot/FD prog_array.
// Fallback has one block ending in verdict/verdict.if. Failure invalidates
// packet pointers; fallback reads must reload them from ctx.
LogicalResult TailCallOp::verify() {
  llvm::StringRef kind = (*this)->getParentOfType<ProgramOp>().getKind();
  if (!bpfmlir::kindAllows(kind, "tail_call"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("tail_call") << " programs (a prog_array of xdp programs), not \"" << kind << "\"";
  if (cast<ContextType>(getCtx().getType()).getKind() != kind)
    return emitOpError() << "needs the " << kind << " context";
  auto m = dyn_cast<MapType>(getMap().getType());
  if (!m || m.getKind() != "prog_array")
    return emitOpError() << "needs a prog_array, got " << getMap().getType();
  if (!m.getKeyType().isInteger(32) || !m.getValueType().isInteger(32))
    return emitOpError() << "a prog_array has an i32 key (the slot) and an i32 value (the program)";
  Block &fb = getFallback().front();
  for (Operation &o : fb)
    if (isa<TailCallOp>(o))
      return emitOpError() << "a tail call inside the fallback is not supported (a compiler restriction)";
  if (fb.empty() || !isa<VerdictOp, VerdictIfOp>(fb.back()))
    return emitOpError() << "the fallback must end with ebpf.verdict or ebpf.verdict.if (it runs only when the tail call fails)";
  if (getCond() && !getElseAction())
    return emitOpError() << "`when` needs an `else` verdict";
  if (getElseAction() && !isVerdictAllowedFor(kind, programAttachOf(*this), *getElseAction()))
    return emitOpError() << "verdict \"" << *getElseAction() << "\" is not valid for program kind \"" << kind << "\"";
  return success();
}

LogicalResult RedirectMapOp::verify() {
  llvm::StringRef kind = (*this)->getParentOfType<ProgramOp>().getKind();
  if (!bpfmlir::kindAllows(kind, "redirect_map"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("redirect_map") << " programs (bpf_redirect_map with a devmap), not \"" << kind << "\"";
  auto m = dyn_cast<MapType>(getMap().getType());
  // redirect_map targets devmap/devmap_hash/cpumap/xskmap.
  if (!m || !bpfmlir::isRedirectMapKind(m.getKind()))
    return emitOpError() << "needs a devmap, devmap_hash, cpumap or xskmap, got " << getMap().getType();
  if (m.getKeyType() != getKey().getType() || !m.getKeyType().isInteger(32) || !m.getValueType().isInteger(32))
    return emitOpError() << "a " << m.getKind() << " has an i32 key and an i32 value ("
                         << (m.getKind() == "cpumap" ? "the qsize" : m.getKind() == "xskmap" ? "the AF_XDP socket fd" : "the ifindex") << ")";
  // Low flag bits encode XDP fallback aborted/drop/pass/tx.
  if (auto flags = getRedirectFlags()) {
    if (*flags != "broadcast" && *flags != "broadcast_exclude_ingress")
      return emitOpError() << "redirect_flags must be broadcast or broadcast_exclude_ingress";
    if (m.getKind() != "devmap" && m.getKind() != "devmap_hash")
      return emitOpError() << "redirect_flags only supports devmap or devmap_hash";
  }
  if (getFallback() != "aborted" && getFallback() != "drop" && getFallback() != "pass" && getFallback() != "tx")
    return emitOpError() << "the fallback \"" << getFallback() << "\" must be aborted, drop, pass or tx (the low bits of the flags)";
  if (getCond() && !getElseAction())
    return emitOpError() << "`when` needs an `else` verdict";
  if (getElseAction() && !isVerdictAllowedFor(kind, programAttachOf(*this), *getElseAction()))
    return emitOpError() << "verdict \"" << *getElseAction() << "\" is not valid for program kind \"" << kind << "\"";
  return success();
}

// Require matching enclosing-program and XDP context kinds.
LogicalResult XdpAdjustHeadOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || !bpfmlir::kindAllows(prog.getKind(), "xdp.adjust") || cast<ContextType>(getCtx().getType()).getKind() != prog.getKind())
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("xdp.adjust") << " programs (bpf_xdp_adjust_head moves the head of an XDP packet)";
  return success();
}

LogicalResult XdpAdjustTailOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || !bpfmlir::kindAllows(prog.getKind(), "xdp.adjust") || cast<ContextType>(getCtx().getType()).getKind() != prog.getKind())
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("xdp.adjust") << " programs (bpf_xdp_adjust_tail moves the end of an XDP packet)";
  // Compiler restriction: delta is a direct i32 constant <=0, shrinking only.
  // Driver tailroom for growth is unverified; even provably negative dynamic
  // deltas are unsupported. Use a matcher without dialect-level arith dependency.
  llvm::APInt v;
  if (!matchPattern(getDelta(), m_ConstantInt(&v)))
    return emitOpError() << "delta must be a direct arith.constant i32 <= 0 (the compiler only supports shrinking the tail and "
                            "cannot prove the sign of a computed delta)";
  if (v.sgt(0))
    return emitOpError() << "delta " << v.getSExtValue()
                         << " grows the packet; growing the tail is outside the compiler's range (drivers' tailroom is not measured)";
  return success();
}

LogicalResult RedirectOp::verify() {
  llvm::StringRef kind = (*this)->getParentOfType<ProgramOp>().getKind();
  if (!bpfmlir::kindAllows(kind, "redirect"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("redirect") << " programs (bpf_redirect to an ifindex), not \"" << kind << "\"";
  if (getCond() && !getElseAction())
    return emitOpError() << "`when` needs an `else` verdict";
  if (getElseAction() && !isVerdictAllowedFor(kind, programAttachOf(*this), *getElseAction()))
    return emitOpError() << "verdict \"" << *getElseAction() << "\" is not valid for program kind \"" << kind
                         << "\" (known: " << knownVerdicts(kind, programAttachOf(*this)) << ")";
  return success();
}

// seg6 helpers require lwt.seg6 OPS and the program's own entry context.
// Static funcs are excluded because invalidation would cross caller windows.
static LogicalResult verifySeg6Op(Operation *op, Value ctx) {
  auto prog = op->getParentOfType<ProgramOp>();
  if (!prog || !bpfmlir::kindAllows(prog.getKind(), "lwt.seg6") || cast<ContextType>(ctx.getType()).getKind() != prog.getKind())
    return op->emitOpError() << "is only for " << bpfmlir::kindsAllowing("lwt.seg6")
                             << " programs with their own context (the bpf_lwt_seg6_* helpers act on the SRH of a seg6local End.BPF packet)";
  return success();
}

LogicalResult LwtSeg6StoreBytesOp::verify() {
  if (failed(verifySeg6Op(*this, getCtx())))
    return failure();
  if (!getRecord().getDefiningOp<RecordMakeOp>())
    return emitOpError() << "the data must be built by ebpf.record.make (every byte, padding zeroed)";
  return success();
}

LogicalResult LwtSeg6AdjustSrhOp::verify() { return verifySeg6Op(*this, getCtx()); }

// Support three actions: end_x uses 16-byte in6_addr; end_t/end_dt6 use
// four-byte table IDs. end_b6/end_b6_encap exist in ABI but are unsupported.
// Lowering resolves action values through seg6action.
LogicalResult LwtSeg6ActionOp::verify() {
  if (failed(verifySeg6Op(*this, getCtx())))
    return failure();
  if (!getParam().getDefiningOp<RecordMakeOp>())
    return emitOpError() << "the param must be built by ebpf.record.make (every byte, padding zeroed)";
  StringRef a = getAction();
  int64_t want;
  if (a == "end_x")
    want = 16;
  else if (a == "end_t" || a == "end_dt6")
    want = 4;
  else if (a == "end_b6" || a == "end_b6_encap")
    return emitOpError() << "action \"" << a << "\" takes an SRH as its param, which this compiler does not build (supported: \"end_x\", \"end_t\", \"end_dt6\")";
  else
    return emitOpError() << "unknown seg6local action \"" << a << "\" (supported: \"end_x\", \"end_t\", \"end_dt6\")";
  int64_t got = cast<RecordType>(getParam().getType()).getSize();
  if (got != want)
    return emitOpError() << "action \"" << a << "\" takes a " << want << "-byte param ("
                         << (a == "end_x" ? "the next hop's IPv6 address" : "the route table id (int)") << "), got a " << got << "-byte record";
  return success();
}

LogicalResult VerdictIfOp::verify() {
  llvm::StringRef kind = (*this)->getParentOfType<ProgramOp>().getKind();
  if (!isKnownProgramKind(kind) || !bpfmlir::lookupProgramAttach(kind, programAttachOf(*this))) // Missing attachment rows are already rejected by program verification.
    return success();
  for (llvm::StringRef a : {getThenAction(), getElseAction()})
    if (!isVerdictAllowedFor(kind, programAttachOf(*this), a))
      return emitOpError() << "verdict \"" << a << "\" is not valid for " << verdictKindPhrase(kind, programAttachOf(*this))
                           << " (known: " << knownVerdicts(kind, programAttachOf(*this)) << ")";
  return success();
}

// MAX_PACKET_OFF matches KernelABI.h kMaxPacketOffset; dialect avoids a BPFABI dependency.
static constexpr int64_t kPacketWindowMax = 0xffff;

LogicalResult PacketCheckOp::verify() {
  if (failed(verifyRegionResultWidths(*this)))
    return failure();
  auto ctx = cast<ContextType>(getCtx().getType());
  if (!supportsPacketAccess(ctx.getKind()))
    return emitOpError() << "program kind \"" << ctx.getKind() << "\" has no packet to check";
  // packet.store requires own XDP/cgroup_sockopt entry. Other packet-readable
// kinds such as sched_cls do not gain writes.
  bool writable = bpfmlir::kindAllows(ctx.getKind(), "packet.store");
  if (getLen() < 1 || getLen() > kPacketWindowMax)
    return emitOpError() << "the window length " << getLen() << " must be in 1.." << kPacketWindowMax;
  // Offset widths follow packet.load restrictions.
  if (!isMemWidth(getOffset().getType()))
    return emitOpError() << "the offset must be an i8 / i16 / i32 / i64, got " << getOffset().getType() << "";
  // Use subtraction after proving len<=MAX: offset+len can wrap, for example
  // zero-extended -1 plus a positive length.
  APInt c;
  if (matchPattern(getOffset(), m_ConstantInt(&c)) &&
      (c.getActiveBits() > 64 || c.getZExtValue() > static_cast<uint64_t>(kPacketWindowMax) - getLen()))
    return emitOpError() << "the window at constant offset " << c.getZExtValue() << " (" << c.getSExtValue() << " signed) with " << getLen()
                         << " bytes exceeds MAX_PACKET_OFF (" << kPacketWindowMax << "); the kernel verifier cannot prove it in bounds";
  if (getInRange().empty() || getOutOfRange().empty())
    return emitOpError() << "both the in_range and out_of_range regions must have a body";
  Block &in = getInRange().front();
  if (in.getNumArguments() != 1)
    return emitOpError() << "the in_range region must take exactly one argument (the checked window), got " << in.getNumArguments();
  auto wt = dyn_cast<PktWindowType>(in.getArgument(0).getType());
  if (!wt || wt.getLen() != static_cast<int64_t>(getLen()))
    return emitOpError() << "the in_range region argument must be !ebpf.pkt_window<" << getLen() << ">, got "
                         << in.getArgument(0).getType();
  if (getOutOfRange().front().getNumArguments() != 0)
    return emitOpError() << "the out_of_range region must take no arguments (there is no window)";
  for (Operation *user : in.getArgument(0).getUsers()) {
    if (isa<PacketStoreOp>(user) && ctx.getKind() == "cgroup_sockopt" && (*this)->getParentOfType<SubprogramOp>())
      return emitOpError() << "cgroup_sockopt packet.store is only allowed through the checked window in the entry program, not in a static ebpf.func";
    if (isa<PacketStoreOp>(user) && !writable)
      return emitOpError() << "packet writes (ebpf.packet.store) are only for xdp programs, not \"" << ctx.getKind()
                           << "\" (the sched_cls packet.check is read-only)";
    // Static-call window operands must match the callee's checked length N.
    if (!isa<PacketStoreOp, PacketWindowLoadOp, CallOp>(user))
      return emitOpError() << "a checked window may only be used by ebpf.packet.store, ebpf.packet.window_load, or passed to a "
                              "static ebpf.func by ebpf.call, but it is used by '" << user->getName()
                           << "' (forwarding it lets it escape the range check)";
    if (!getInRange().isAncestor(user->getParentRegion()))
      return emitOpError() << "a checked window must be used inside the in_range region of its own ebpf.packet.check";
  }
  for (Region *r : {&getInRange(), &getOutOfRange()})
    for (Block &blk : *r)
      for (BlockArgument arg : blk.getArguments())
        if (&blk != &in && isa<PktWindowType>(arg.getType()))
          return emitOpError() << "a checked window must not be carried across blocks as a block argument";
  return success();
}

// Reads are 1/2/4/8 bytes, fully inside the window using subtraction bounds.
LogicalResult PacketWindowLoadOp::verify() {
  unsigned w = getResult().getType().getIntOrFloatBitWidth();
  if (w != 8 && w != 16 && w != 32 && w != 64)
    return emitOpError() << "reads an i8 / i16 / i32 / i64, got " << getResult().getType();
  int64_t len = cast<PktWindowType>(getWindow().getType()).getLen();
  uint64_t idx = getIndex(), bytes = w / 8, ulen = static_cast<uint64_t>(len);
  if (idx > ulen || bytes > ulen - idx)
    return emitOpError() << "reads " << bytes << " bytes at index " << static_cast<int64_t>(idx) << ", outside the checked window of " << len << " bytes";
  return success();
}

LogicalResult PacketStoreOp::verify() {
  unsigned w = getValue().getType().getIntOrFloatBitWidth();
  if (w != 8 && w != 16 && w != 32 && w != 64)
    return emitOpError() << "stores an i8 / i16 / i32 / i64, got " << getValue().getType();
  int64_t len = cast<PktWindowType>(getWindow().getType()).getLen();
  // Subtract rather than add width to index: UINT64_MAX+width can wrap and
  // wrongly pass the range check.
  uint64_t idx = getIndex(), bytes = w / 8, ulen = static_cast<uint64_t>(len);
  if (idx > ulen || bytes > ulen - idx)
    return emitOpError() << "writes " << bytes << " bytes at index " << static_cast<int64_t>(idx) << ", outside the checked window of "
                         << len << " bytes";
  return success();
}

LogicalResult PktCheckBrOp::verify() {
  Block *in = getInRange();
  if (in->getNumArguments() != 1 || !isa<PktWindowType>(in->getArgument(0).getType()) ||
      cast<PktWindowType>(in->getArgument(0).getType()).getLen() != static_cast<int64_t>(getLen()))
    return emitOpError() << "the in_range successor must take exactly one !ebpf.pkt_window<" << getLen() << "> argument";
  if (getOutOfRange()->getNumArguments() != 0)
    return emitOpError() << "the out_of_range successor must take no arguments";
  return success();
}

LogicalResult YieldOp::verify() {
  // kptr.check yields must match parent results without escaping kernel pointers.
  if (auto kc = dyn_cast<KPtrCheckOp>((*this)->getParentOp())) {
    for (Value v : getResults())
      if (isa<KPtrType, KPtrOrNullType>(v.getType()))
        return emitOpError() << "a kernel pointer must not escape ebpf.kptr.check (it is only valid inside the present region)";
    if (getResults().getTypes() != kc.getResultTypes())
      return emitOpError() << "yielded types do not match the results of the enclosing ebpf.kptr.check";
    return success();
  }
  if (auto c = dyn_cast<SockRefCheckOp>((*this)->getParentOp())) {
    for (Type t : getResults().getTypes())
      if (!isa<IntegerType>(t))
        return emitOpError() << "only scalar integers may escape ebpf.sock.ref_check";
    if (getResults().getTypes() != c.getResultTypes())
      return emitOpError() << "yielded types do not match ebpf.sock.ref_check results";
    return success();
  }

  // kref.check yields cannot escape ownership beyond present; result types match parent.
  if (auto kc = dyn_cast<KRefCheckOp>((*this)->getParentOp())) {
    for (Value v : getResults())
      if (isa<KRefType, KRefOrNullType>(v.getType()))
        return emitOpError() << "a kernel reference must not escape ebpf.kref.check (it is owned inside the present region and "
                                "released there)";
    if (getResults().getTypes() != kc.getResultTypes())
      return emitOpError() << "yielded types do not match the results of the enclosing ebpf.kref.check";
    return success();
  }
  // packet.check yields cannot escape windows.
  if (auto pc = dyn_cast<PacketCheckOp>((*this)->getParentOp())) {
    for (Value v : getResults())
      if (isa<PktWindowType>(v.getType()))
        return emitOpError() << "a checked window must not escape ebpf.packet.check (it is only valid inside its region)";
    if (getResults().getTypes() != pc.getResultTypes())
      return emitOpError() << "yielded types do not match the results of the enclosing ebpf.packet.check";
    return success();
  }
  // ref.index yields cannot escape elements or borrows.
  if (auto ri = dyn_cast<RefIndexOp>((*this)->getParentOp())) {
    for (Value v : getResults())
      if (isa<BorrowedType, ElemType>(v.getType()))
        return emitOpError() << "a checked element or borrowed reference must not escape "
                                "ebpf.ref.index (it is only valid inside its region)";
    if (getResults().getTypes() != ri.getResultTypes())
      return emitOpError() << "yielded types do not match the results of the enclosing ebpf.ref.index";
    return success();
  }
  // if_reserved yields match parent results and cannot escape reservations.
// Resultless regions yield no values.
  if (auto ir = dyn_cast<RingbufIfReservedOp>((*this)->getParentOp())) {
    for (Value v : getResults())
      if (isa<ReservationType, MaybeReservationType>(v.getType()))
        return emitOpError() << "a reservation must not escape ebpf.ringbuf.if_reserved (it is only valid "
                                "inside the present region)";
    if (getResults().getTypes() != ir.getResultTypes())
      return emitOpError() << "yielded types (" << getResults().getTypes()
                           << ") do not match the results of the enclosing ebpf.ringbuf.if_reserved ("
                           << ir.getResultTypes() << ")";
    return success();
  }
  auto parent = dyn_cast<RefCheckOp>((*this)->getParentOp());
  if (!parent) {
    // spin.region returns no values.
    if (!getResults().empty())
      return emitOpError() << "ebpf.spin.region yields no values";
    return success();
  }
  // Reject the direct borrowed-reference escape through a region result.
  for (Value v : getResults())
    if (isa<BorrowedType>(v.getType()))
      return emitOpError() << "a borrowed reference must not escape the check "
                           << "region (it is only valid inside the present "
                              "region of ebpf.ref.check)";
  if (getResults().getTypes() != parent.getResultTypes())
    return emitOpError() << "yielded types do not match the results of the "
                         << "enclosing ebpf.ref.check";
  return success();
}

// Verify index structure here; VerifyRecords matches integer-array fields
// and element widths against @records.
LogicalResult RefIndexOp::verify() {
  if (failed(verifyRegionResultWidths(*this)))
    return failure();
  auto borrowed = cast<BorrowedType>(getRef().getType());
  if (!isa<RecordType>(borrowed.getPointee()))
    return emitOpError() << "indexes a record field; the reference must borrow a record, got "
                         << borrowed.getPointee();
  if (getIndices().empty())
    return emitOpError() << "needs at least one index";
  if (getInRange().empty() || getOutOfRange().empty())
    return emitOpError() << "both the in_range and out_of_range regions must have a body";
  Block &in = getInRange().front();
  if (in.getNumArguments() != 1)
    return emitOpError() << "the in_range region must take exactly one argument (the checked element), got "
                         << in.getNumArguments();
  auto et = dyn_cast<ElemType>(in.getArgument(0).getType());
  if (!et || !isa<IntegerType>(et.getElement()) || !cast<IntegerType>(et.getElement()).isSignless())
    return emitOpError() << "the in_range region argument must be !ebpf.elem<iN>, got "
                         << in.getArgument(0).getType();
  if (getOutOfRange().front().getNumArguments() != 0)
    return emitOpError() << "the out_of_range region must take no arguments (there is no element)";
  BlockArgument e = in.getArgument(0);
  for (Operation *user : e.getUsers()) {
    if (!isa<ElemLoadOp, ElemStoreOp>(user))
      return emitOpError() << "a checked element may only be used by ebpf.elem.load / ebpf.elem.store, "
                              "but it is used by '"
                           << user->getName() << "' (forwarding it lets it escape the range check)";
    if (!getInRange().isAncestor(user->getParentRegion()))
      return emitOpError() << "a checked element must be used inside the in_range region of its own ebpf.ref.index";
  }
  for (Region *r : {&getInRange(), &getOutOfRange()})
    for (Block &blk : *r)
      for (BlockArgument arg : blk.getArguments())
        if (&blk != &in && isa<ElemType>(arg.getType()))
          return emitOpError() << "a checked element must not be carried across blocks as a block argument";
  return success();
}

LogicalResult ElemLoadOp::verify() {
  if (getResult().getType() != cast<ElemType>(getElem().getType()).getElement())
    return emitOpError() << "result " << getResult().getType() << " does not match the element type "
                         << cast<ElemType>(getElem().getType()).getElement();
  return success();
}

LogicalResult ElemStoreOp::verify() {
  if (getValue().getType() != cast<ElemType>(getElem().getType()).getElement())
    return emitOpError() << "value " << getValue().getType() << " does not match the element type "
                         << cast<ElemType>(getElem().getType()).getElement();
  return success();
}

LogicalResult RefLoadOp::verify() {
  Type t = getRef().getType();
  if (isa<MaybeRefType>(t)) {
    auto d = emitOpError() << "operand is an unchecked nullable reference " << t;
    d.attachNote() << "check it with ebpf.ref.check first; the kernel verifier "
                      "rejects dereferencing a possibly-null map lookup result";
    return failure();
  }
  auto b = dyn_cast<BorrowedType>(t);
  if (!b)
    return emitOpError() << "operand must be !ebpf.borrowed<...>, got " << t;
  // Read record fields by name, not whole-record values.
  if (isa<RecordType>(b.getPointee()))
    return emitOpError() << "cannot load a whole record (" << b.getPointee()
                         << "); read its fields with ebpf.ref.field.load";
  if (b.getPointee() != getResult().getType())
    return emitOpError() << "result type " << getResult().getType()
                         << " does not match the borrowed pointee "
                         << b.getPointee();
  return success();
}

LogicalResult RingbufIfReservedOp::verify() {
  if (failed(verifyRegionResultWidths(*this)))
    return failure();
  auto in = cast<MaybeReservationType>(getReservation().getType());

  if (getPresentRegion().empty() || getAbsentRegion().empty())
    return emitOpError() << "both the present and absent regions must have a body";

  Block &present = getPresentRegion().front();
  if (present.getNumArguments() != 1)
    return emitOpError() << "the present region must take exactly one argument "
                         << "(the reservation), got " << present.getNumArguments();
  auto got = dyn_cast<ReservationType>(present.getArgument(0).getType());
  if (!got)
    return emitOpError() << "the present region argument must be "
                         << "!ebpf.reservation<...>, got "
                         << present.getArgument(0).getType();
  if (got.getRecordType() != in.getRecordType())
    return emitOpError() << "the reservation must keep the record type: "
                         << in.getRecordType() << " vs " << got.getRecordType();

  Block &absent = getAbsentRegion().front();
  if (absent.getNumArguments() != 0)
    return emitOpError() << "the absent region must take no arguments (there is "
                         << "no reservation), got " << absent.getNumArguments();

  // Absent has no reservation, so cannot store, submit or discard one.
  bool bad = false;
  getAbsentRegion().walk([&](Operation *op) {
    auto kc = dyn_cast<KFieldCopyOp>(op); // Include writes into outer reservations through kfield.copy; borrows are allowed.
    auto tc = dyn_cast<TpFieldCopyOp>(op);
    if (isa<RingbufStoreFieldOp, RingbufStoreRecordOp, TaskCommOp, UserReadStrOp, UserReadOp, KernelReadStrOp, RingbufSubmitOp, RingbufDiscardOp>(op) ||
        (kc && kc.writesReservation()) || (tc && tc.writesReservation())) {
      bad = true;
      op->emitOpError() << "cannot be used in the absent region: there is no "
                           "reservation when the reserve failed";
    }
  });
  if (bad)
    return failure();

  // Taken reservations cannot escape their region.
  BlockArgument res = present.getArgument(0);
  for (Operation *user : res.getUsers()) {
    if (!isa<RingbufStoreFieldOp, RingbufStoreRecordOp, TaskCommOp, UserReadStrOp, UserReadOp, KFieldCopyOp, TpFieldCopyOp, KernelReadStrOp, RingbufSubmitOp,
             RingbufDiscardOp>(
            user)) // A reservation can occur only as kfield.copy's destination, never its kptr source.
      return emitOpError() << "a reservation may only be used by "
                           << "ebpf.ringbuf.{store_field,store_record,submit,discard}, ebpf.task.comm, ebpf.user.read_str, ebpf.kfield.copy or "
                              "ebpf.kernel.read_str, but it is "
                           << "used by '" << user->getName() << "'";
    if (!getPresentRegion().isAncestor(user->getParentRegion()))
      return emitOpError() << "a reservation must be used inside the present "
                           << "region of its own ebpf.ringbuf.if_reserved";
  }
  for (Block &blk : getPresentRegion())
    if (&blk != &present)
      for (BlockArgument arg : blk.getArguments())
        if (isa<ReservationType>(arg.getType()))
          return emitOpError() << "a reservation must not be carried across "
                               << "blocks as a block argument";

  // Require at least one consumer here, allowing submit/discard on distinct
  // arms. Exactly one on every CFG path, including double-consume/use-after,
  // is owned by unconditional VerifyOwnership and expanded checkLinear.
  // ebpf-opt operation verification alone does not establish path linearity.
  unsigned consumers = 0;
  for (Operation *user : res.getUsers())
    if (isa<RingbufSubmitOp>(user) || isa<RingbufDiscardOp>(user))
      ++consumers;
  if (consumers < 1) {
    auto d = emitOpError()
             << "the reservation must be consumed exactly once by "
             << "ebpf.ringbuf.submit or ebpf.ringbuf.discard, found "
             << consumers;
    d.attachNote() << "an unconsumed reservation leaks ring buffer space";
    return failure();
  }
  return success();
}

LogicalResult RingbufStoreFieldOp::verify() {
  auto res = cast<ReservationType>(getReservation().getType());
  auto rec = dyn_cast<RecordType>(res.getRecordType());
  if (!rec)
    return emitOpError() << "field stores need a record reservation "
                         << "(!ebpf.record<...>), got " << res.getRecordType()
                         << " — a ring buffer carries a schema record; a single "
                         << "integer is a one-field record";
  int64_t off = getOffset();
  unsigned bytes = cast<IntegerType>(getValue().getType()).getWidth() / 8;
  if (off < 0 || off + (int64_t)bytes > rec.getSize())
    return emitOpError() << "field store at offset " << off << " (" << bytes
                         << " bytes) does not fit record \"" << rec.getSymbol()
                         << "\" (" << rec.getSize() << " bytes)";
  return success();
}

// Require a record reservation here; VerifyRecords checks the byte-array field shape.
LogicalResult TaskCommOp::verify() {
  auto res = cast<ReservationType>(getReservation().getType());
  if (!isa<RecordType>(res.getRecordType()))
    return emitOpError() << "needs a record reservation (!ebpf.record<...>) to write a field of, got "
                         << res.getRecordType();
  return success();
}

// Nominal record name/size must match the reservation, from full-byte record.make.
LogicalResult RingbufStoreRecordOp::verify() {
  auto res = cast<ReservationType>(getReservation().getType());
  auto want = dyn_cast<RecordType>(res.getRecordType());
  if (!want)
    return emitOpError() << "needs a record reservation (!ebpf.record<...>), got "
                         << res.getRecordType();
  auto got = cast<RecordType>(getValue().getType());
  if (got != want)
    return emitOpError() << "stores record " << got << " into a reservation of " << want
                         << " (the record must be the one the reservation carries)";
  if (!getValue().getDefiningOp<RecordMakeOp>())
    return emitOpError() << "a record stored into a reservation must be built by ebpf.record.make "
                            "(every byte, padding zeroed), got one from "
                         << (getValue().getDefiningOp()
                                 ? getValue().getDefiningOp()->getName().getStringRef()
                                 : StringRef("a block argument"));
  return success();
}

// Byte swaps permit only 16/32/64 bits: eight has nothing to swap; other widths lack BPF_END.
static LogicalResult checkByteorderWidth(Operation *op, Type t) {
  unsigned w = cast<IntegerType>(t).getWidth();
  if (w != 16 && w != 32 && w != 64)
    return op->emitOpError() << "converts i16 / i32 / i64 only (the widths of BPF_END), got " << t;
  return success();
}

LogicalResult ByteorderToBeOp::verify() { return checkByteorderWidth(*this, getValue().getType()); }

LogicalResult ByteorderFromBeOp::verify() { return checkByteorderWidth(*this, getValue().getType()); }

// Trace a borrow through ref.check to its map.lookup to detect lpm_trie origin.
static bool borrowsLpmTrie(Value ref) {
  auto arg = dyn_cast<BlockArgument>(ref);
  if (!arg)
    return false;
  auto rc = dyn_cast_or_null<RefCheckOp>(arg.getOwner()->getParentOp());
  if (!rc)
    return false;
  auto lk = rc.getRef().getDefiningOp<MapLookupOp>();
  return lk && cast<MapType>(lk.getMap().getType()).getKind() == "lpm_trie";
}

// Detect writes through v, checked-region borrows, expanded assumptions
// and transitive forwarding to callees.
static bool refValueWritten(SymbolTableCollection &st, Operation *from, Value v, llvm::SmallPtrSet<Operation *, 8> &seen);
static bool calleeWritesArg(SymbolTableCollection &st, SubprogramOp fn, unsigned i, llvm::SmallPtrSet<Operation *, 8> &seen) {
  if (!seen.insert(fn.getOperation()).second || fn.getBody().empty() || i >= fn.getBody().front().getNumArguments())
    return false;
  return refValueWritten(st, fn, fn.getBody().front().getArgument(i), seen);
}
static bool refValueWritten(SymbolTableCollection &st, Operation *from, Value v, llvm::SmallPtrSet<Operation *, 8> &seen) {
  for (OpOperand &use : v.getUses()) {
    Operation *u = use.getOwner();
    if (isa<RefStoreOp, RefFieldStoreOp, RefAtomicAddOp, RefFieldAtomicAddOp, KPtrXchgOp>(u)) // kptr.xchg also writes a field.
      return true;
    if (auto rc = dyn_cast<RefCheckOp>(u)) {
      if (refValueWritten(st, from, rc.getPresentRegion().front().getArgument(0), seen))
        return true;
      continue;
    }
    if (auto ap = dyn_cast<AssumePresentOp>(u)) {
      if (refValueWritten(st, from, ap.getResult(), seen))
        return true;
      continue;
    }
    if (auto call = dyn_cast<CallOp>(u)) {
      auto t = dyn_cast_or_null<SubprogramOp>(st.lookupNearestSymbolFrom(from, call.getCalleeAttr()));
      if (t && calleeWritesArg(st, t, use.getOperandNumber(), seen))
        return true;
    }
  }
  return false;
}

static LogicalResult checkNotLpmValue(Operation *op, Value ref) {
  if (borrowsLpmTrie(ref))
    return op->emitOpError() << "writes a lpm_trie value; a lpm_trie is read-only in programs (a compiler restriction — entries are set by userspace)";
  return success();
}

LogicalResult RefStoreOp::verify() {
  if (failed(checkNotLpmValue(*this, getRef())))
    return failure();
  Type t = getRef().getType();
  if (isa<MaybeRefType>(t)) {
    auto d = emitOpError() << "operand is an unchecked nullable reference " << t;
    d.attachNote() << "check it with ebpf.ref.check first; the kernel verifier "
                      "rejects dereferencing a possibly-null map lookup result";
    return failure();
  }
  auto b = dyn_cast<BorrowedType>(t);
  if (!b)
    return emitOpError() << "operand must be !ebpf.borrowed<...>, got " << t;
  if (isa<RecordType>(b.getPointee()))
    return emitOpError() << "cannot store a whole record (" << b.getPointee()
                         << "); write its fields with ebpf.ref.field.store";
  if (b.getPointee() != getValue().getType())
    return emitOpError() << "stored value type " << getValue().getType()
                         << " does not match the borrowed pointee "
                         << b.getPointee();
  return success();
}

// Packet reads, tracing arguments and kernel struct field operations.
LogicalResult CtxArgOp::verify() {
  auto ctx = cast<ContextType>(getCtx().getType());
  // OPS selects ctx.arg support; FuncArgs requires nullable kernel pointers.
  const bpfmlir::ProgramKindInfo *kinfo = bpfmlir::lookupProgramKind(ctx.getKind());
  if (!kinfo || !bpfmlir::kindAllows(*kinfo, "ctx.arg"))
    return emitOpError() << "program kind \"" << ctx.getKind()
                         << "\" has no typed arguments (only " << bpfmlir::kindsAllowing("ctx.arg") << ")";
  if (kinfo->sig == bpfmlir::SigFamily::HookArgs || kinfo->sig == bpfmlir::SigFamily::OpsSig) { // struct_ops and LSM share btf_ctx_access slots. Unknown struct nullability
    // always yields kptr_or_null and requires a check; integers truncate u64 slots.
    if (isa<KPtrType>(getResult().getType()))
      return emitOpError() << "a " << ctx.getKind() << " struct argument is read as !ebpf.kptr_or_null<...> (a hook argument may be NULL — "
                              "check it with ebpf.kptr.check), got " << getResult().getType();
  }
  if (kinfo->sig == bpfmlir::SigFamily::FuncArgs) {
    // fentry pointers use PROBE_MEM, which can silently read null as zero.
    // Always require nullable types and kptr.check.
    if (!isa<KPtrOrNullType, IntegerType>(getResult().getType()))
      return emitOpError() << "a " << ctx.getKind() << " argument is read as !ebpf.kptr_or_null<...> (a function argument may be NULL — "
                              "check it with ebpf.kptr.check), got " << getResult().getType();
  }
  if (kinfo->sig == bpfmlir::SigFamily::Iter) {
    // Iterator argument zero is non-null bpf_iter_meta* by DEFINE_BPF_ITER_FUNC.
    // Later target-dependent nullable arguments lack matching rows and cannot be read.
    auto kp = dyn_cast<KPtrType>(getResult().getType());
    if (getIndex() != 0 || !kp || kp.getStructName() != "bpf_iter_meta")
      return emitOpError() << "an " << ctx.getKind() << " program reads only argument 0 as !ebpf.kptr<\"bpf_iter_meta\"> (the target's "
                              "own arguments are not supported), got argument " << getIndex() << " as " << getResult().getType();
  }
  if (kinfo->sig == bpfmlir::SigFamily::IntArgs && !isa<IntegerType>(getResult().getType())) {
    // fmod_ret permits integer arguments only; unsupported pointer contracts
    // could pass the verifier while reading the wrong struct.
    return emitOpError() << "a " << ctx.getKind() << " argument is read as an integer (i8 / i16 / i32 / i64 — struct arguments are not "
                            "supported), got " << getResult().getType();
  }
  // Kernel MAX_BPF_FUNC_ARGS is twelve; tracepoints can have fewer arguments.
  if (getIndex() < 0 || getIndex() >= 12)
    return emitOpError() << "argument index " << getIndex()
                         << " is out of range (0..11)";
  return success();
}

// ext.arg requires its OPS and an index within BPF's five argument registers.
LogicalResult ExtArgOp::verify() {
  auto ctx = cast<ContextType>(getCtx().getType());
  if (!bpfmlir::kindAllows(ctx.getKind(), "ext.arg"))
    return emitOpError() << "program kind \"" << ctx.getKind() << "\" has no replaced-function arguments (only "
                         << bpfmlir::kindsAllowing("ext.arg") << ")";
  if (getIndex() < 0 || getIndex() >= 5)
    return emitOpError() << "argument index " << getIndex() << " is out of range (0..4 — a BPF function takes at most 5 arguments)";
  return success();
}

LogicalResult KprobeArgOp::verify() {
  auto ctx = cast<ContextType>(getCtx().getType());
  if (!bpfmlir::kindAllows(ctx.getKind(), "kprobe.arg"))
    return emitOpError() << "program kind \"" << ctx.getKind() << "\" has no pt_regs (only " << bpfmlir::kindsAllowing("kprobe.arg") << ")";
  if (getN() < 1)
    return emitOpError() << "the argument number " << getN() << " must be >= 1 (1-based)";
  unsigned w = getResult().getType().getIntOrFloatBitWidth();
  if (w != 8 && w != 16 && w != 32 && w != 64)
    return emitOpError() << "reads an i8 / i16 / i32 / i64 argument, got " << getResult().getType();
  return success();
}

LogicalResult UprobeArgOp::verify() {
  auto ctx = cast<ContextType>(getCtx().getType());
  if (!bpfmlir::kindAllows(ctx.getKind(), "uprobe.arg"))
    return emitOpError() << "program kind \"" << ctx.getKind() << "\" is not a uprobe (kprobe reads with ebpf.kprobe.arg)";
  if (getN() < 1)
    return emitOpError() << "the argument number " << getN() << " must be >= 1 (1-based)";
  if (isa<UserBufType>(getResult().getType())) {
    for (Operation *user : getResult().getUsers())
      if (!isa<UserReadOp>(user))
        return emitOpError("user_buf may only be read by ebpf.user.read (no cast, select, store or escape)");
    return success();
  }
  // User-string pointers are distinct from integers and restricted to supported string readers.
  if (isa<UserStrType>(getResult().getType()))
    return success();
  unsigned w = getResult().getType().getIntOrFloatBitWidth();
  if (w != 8 && w != 16 && w != 32 && w != 64)
    return emitOpError() << "reads an i8 / i16 / i32 / i64 argument, got " << getResult().getType();
  return success();
}

// spin.region uses a borrowed record, ends in valueless yield, and allows
// only arithmetic and field accesses through that same reference. VerifyRecords
// establishes the lock field's bpf_spin_lock type.
LogicalResult SpinRegionOp::verify() {
  // Only semantic structure is checked here. VerifyTargetLegality spinLegality
  // separately owns compiler-kind support and target-profile restrictions.
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog)
    return emitOpError() << "is only inside an ebpf.program (not in ebpf.func or a callback)";
  auto bt = cast<BorrowedType>(getRef().getType());
  if (!isa<RecordType>(bt.getPointee()))
    return emitOpError() << "needs a borrowed record map value, got " << getRef().getType();
  Block &b = getBody().front();
  if (b.empty() || !isa<YieldOp>(b.back()) || b.back().getNumOperands() != 0)
    return emitOpError() << "the region must end with ebpf.yield without values";
  for (Operation &op : b) {
    if (&op == &b.back())
      continue;
    if (op.getDialect() && op.getDialect()->getNamespace() == "arith")
      continue;
    if (auto ld = dyn_cast<RefFieldLoadOp>(op)) {
      if (ld.getRef() != getRef())
        return ld.emitOpError() << "reads a map value other than the one whose lock this ebpf.spin.region holds";
      continue;
    }
    if (auto st = dyn_cast<RefFieldStoreOp>(op)) {
      if (st.getRef() != getRef())
        return st.emitOpError() << "writes a map value other than the one whose lock this ebpf.spin.region holds";
      continue;
    }
    return op.emitOpError() << "is not allowed inside ebpf.spin.region (only arith and field loads / stores of the locked value — "
                               "the verifier rejects calls while a lock is held)";
  }
  return success();
}

// Find map.lookup through source ref.check present arguments or expanded
// assume_present; return null for other origins.
static MapLookupOp lookupOfBorrow(Value ref) {
  Value m;
  if (auto arg = dyn_cast<BlockArgument>(ref)) {
    if (auto rc = dyn_cast_or_null<RefCheckOp>(arg.getOwner()->getParentOp()))
      m = rc.getRef();
  } else if (auto ap = ref.getDefiningOp<AssumePresentOp>()) {
    m = ap.getValue();
  }
  return m ? m.getDefiningOp<MapLookupOp>() : MapLookupOp();
}

// Timer operations require borrowed records from lookup. VerifyRecords
// establishes timer fields; VerifyTargetLegality owns program-kind restrictions.
llvm::StringRef mlir::ebpf::programTypeOf(llvm::StringRef kind) {
  // PTYPE maps uprobe to kprobe and tracing families to tracing; unknown kinds pass through.
  if (const bpfmlir::ProgramKindInfo *k = bpfmlir::lookupProgramKind(kind))
    return k->progType;
  return kind;
}

// Timer semantics are kind-independent. TargetProfile timerLegality owns
// compiler support and target-verifier policy.
static FailureOr<MapLookupOp> checkTimerOp(Operation *op, Value ref) {
  // Callback timer.start may restart only its own value's timer; map comes
  // from the callback's map attribute.
  if (auto cb = op->getParentOfType<TimerCallbackOp>(); cb && isa<TimerStartOp>(op)) {
    if (ref != cb.getBody().front().getArgument(0))
      return op->emitOpError() << "inside ebpf.timer.callback must start the timer of the callback's own map value (its block argument)";
    return MapLookupOp();
  }
  auto prog = op->getParentOfType<ProgramOp>();
  if (!prog)
    return op->emitOpError() << "is only inside an ebpf.program (not in ebpf.func or a callback — the timer's map is resolved through the program's maps)";
  if (!isa<RecordType>(cast<BorrowedType>(ref.getType()).getPointee()))
    return op->emitOpError() << "needs a borrowed record map value, got " << ref.getType();
  MapLookupOp lk = lookupOfBorrow(ref);
  if (!lk)
    return op->emitOpError() << "needs the map value borrowed directly from ebpf.map.lookup (through ebpf.ref.check) — the timer is tied to that map";
  return lk;
}

LogicalResult TimerInitOp::verify() {
  FailureOr<MapLookupOp> lk = checkTimerOp(*this, getRef());
  if (failed(lk))
    return failure();
  if (lk->getMap() != getMap())
    return emitOpError() << "initializes the timer with a map other than the one the value was looked up in (the kernel verifier rejects it too)";
  if (getClock() != "monotonic")
    return emitOpError() << "clock \"" << getClock() << "\" is not supported (only \"monotonic\")";
  return success();
}

LogicalResult TimerSetCallbackOp::verify() {
  FailureOr<MapLookupOp> lk = checkTimerOp(*this, getRef());
  if (failed(lk))
    return failure();
  auto cb = SymbolTable::lookupNearestSymbolFrom<TimerCallbackOp>(*this, getCallbackAttr());
  if (!cb)
    return emitOpError() << "does not name an ebpf.timer.callback";
  Type rec = cast<BorrowedType>(getRef().getType()).getPointee();
  if (cb.getRecord() != rec)
    return emitOpError() << "callback @" << cb.getSymName() << " takes " << cb.getRecord() << ", but the timer is in " << rec;
  // Entry map arguments correspond positionally to schema maps[] symbols.
  auto arg = dyn_cast<BlockArgument>(lk->getMap());
  auto prog = (*this)->getParentOfType<ProgramOp>();
  ArrayAttr syms = prog.getMapSymbolsAttr();
  if (!arg || arg.getOwner() != &prog.getBody().front() || arg.getArgNumber() == 0 || !syms ||
      arg.getArgNumber() - 1 >= syms.size())
    return emitOpError() << "cannot resolve the map of the timer to a program map symbol";
  auto sym = cast<FlatSymbolRefAttr>(syms[arg.getArgNumber() - 1]);
  if (sym.getValue() != cb.getMap())
    return emitOpError() << "callback @" << cb.getSymName() << " is for map @" << cb.getMap() << ", but the timer is in map @"
                         << sym.getValue();
  return success();
}

LogicalResult TimerStartOp::verify() { return failure(failed(checkTimerOp(*this, getRef()))); }

// Timer callbacks take one borrowed record and allow arithmetic, its field
// accesses and ktime.ns, ending with timer.done.
LogicalResult TimerCallbackOp::verify() {
  auto rt = dyn_cast<RecordType>(getRecord());
  if (!rt)
    return emitOpError() << "record must be an !ebpf.record, got " << getRecord();
  if (getBody().empty())
    return emitOpError() << "has no body";
  Block &b = getBody().front();
  if (b.getNumArguments() != 1 || b.getArgument(0).getType() != BorrowedType::get(getContext(), rt))
    return emitOpError() << "takes exactly one argument of type " << BorrowedType::get(getContext(), rt) << " (the map value)";
  // Source callbacks have one timer.done block. Expanded ifs permit multiple
  // blocks ending in CFG branches/timer.done, without non-entry arguments:
  // callback ifs carry no results.
  bool expanded = !getBody().hasOneBlock();
  bool done = false;
  for (Block &blk : getBody()) {
    if (blk.empty())
      return emitOpError() << "must end with ebpf.timer.done";
    Operation &term = blk.back();
    if (isa<TimerDoneOp>(term))
      done = true;
    else if (!expanded || !(term.getDialect() && term.getDialect()->getNamespace() == "cf"))
      return emitOpError() << "must end with ebpf.timer.done";
    if (&blk != &b && blk.getNumArguments() != 0)
      return emitOpError() << "an expanded callback block takes no arguments";
  }
  if (!done)
    return emitOpError() << "must end with ebpf.timer.done";
  Value v = b.getArgument(0);
  // Diagnose restarting another map's value before rejecting its producing operation.
  WalkResult starts = getBody().walk([&](TimerStartOp s) {
    if (s.getRef() != v) {
      s.emitOpError() << "inside ebpf.timer.callback must start the timer of the callback's own map value (its block argument)";
      return WalkResult::interrupt();
    }
    return WalkResult::advance();
  });
  if (starts.wasInterrupted())
    return failure();
  // Apply the same operation whitelist recursively through nested if regions.
  std::function<LogicalResult(Block &)> check = [&](Block &blk) -> LogicalResult {
    for (Operation &op : blk) {
      if (isa<TimerDoneOp, IfYieldOp>(op))
        continue;
      if (op.getDialect() && op.getDialect()->getNamespace() == "arith")
        continue;
      // CFG branches are permitted only after expansion, matching terminator checks.
      if (expanded && op.getDialect() && op.getDialect()->getNamespace() == "cf")
        continue;
      if (auto ld = dyn_cast<RefFieldLoadOp>(op); ld && ld.getRef() == v)
        continue;
      if (auto st = dyn_cast<RefFieldStoreOp>(op); st && st.getRef() == v)
        continue;
      // ktime.ns is the only reading helper: no ctx and available before XDP privilege checks.
      if (isa<KtimeOp>(op))
        continue;
      // Restart the already-validated own timer, with conditionals for bounded periodic use.
      if (isa<TimerStartOp>(op))
        continue;
      if (auto iff = dyn_cast<IfOp>(op)) {
        for (Region &r : iff->getRegions())
          for (Block &inner : r)
            if (failed(check(inner)))
              return failure();
        continue;
      }
      return op.emitOpError() << "is not allowed inside ebpf.timer.callback (only arith, field loads / stores of its map value and ebpf.ktime.ns; "
                                 "also ebpf.timer.start of its own timer and ebpf.if around them)";
    }
    return success();
  };
  for (Block &blk : getBody())
    if (failed(check(blk)))
      return failure();
  return success();
}

// VerifyRecords owns destination byte-array shape; VerifyOwnership rejects
// reads into reservations after consumption.
LogicalResult UserReadOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || !bpfmlir::kindAllows(prog.getKind(), "user.read"))
    return emitOpError("is only for uprobe/uprobe_multi programs");
  if (getField().empty() || getField().contains('.') || getField().contains('['))
    return emitOpError("needs a direct byte array field name (no slice or nested path)");
  if (!isa<RecordType>(cast<ReservationType>(getReservation().getType()).getRecordType()))
    return emitOpError("needs a record reservation");
  auto lenTy = dyn_cast<IntegerType>(getLen().getType());
  if (!lenTy || !lenTy.isSignless() ||
      (lenTy.getWidth() != 8 && lenTy.getWidth() != 16 && lenTy.getWidth() != 32 && lenTy.getWidth() != 64))
    return emitOpError("length must be signless i8/i16/i32/i64 interpreted as signed");
  Operation *source = getPtr().getDefiningOp();
  if (!source || !isa<UprobeArgOp, ProbeTargetArgOp>(source) || source->getParentOfType<ProgramOp>() != prog)
    return emitOpError("pointer must be a direct user_buf argument of the same program");
  Value ctx = isa<UprobeArgOp>(source) ? cast<UprobeArgOp>(source).getCtx() : cast<ProbeTargetArgOp>(source).getCtx();
  if (prog.getBody().empty() || prog.getBody().front().getNumArguments() == 0 ||
      ctx != prog.getBody().front().getArgument(0))
    return emitOpError("buffer argument must use the same program entry context");
  return success();
}

LogicalResult UserReadStrOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || !bpfmlir::kindAllows(prog.getKind(), "user.read_str"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("user.read_str") << " programs (a user string pointer comes from a typed user address source)";
  if (getField().empty())
    return emitOpError() << "needs a field name";
  return success();
}

// Require nonempty field/path and record reservation. VerifyKPtr checks
// strptr field type; VerifyRecords checks the destination array path.
LogicalResult KernelReadStrOp::verify() {
  if (getField().empty() || getPath().empty())
    return emitOpError() << "needs a kernel field name and a destination path";
  auto res = cast<ReservationType>(getReservation().getType());
  if (!isa<RecordType>(res.getRecordType()))
    return emitOpError() << "needs a record reservation (!ebpf.record<...>) to write a field of, got " << res.getRecordType();
  return success();
}

LogicalResult KernelReadScalarOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || !bpfmlir::kindAllows(prog.getKind(), "kernel.read_scalar") || !prog.getArch() || *prog.getArch() != "x86_64")
    return emitOpError("requires an ordinary x86_64 kprobe program");
  auto arg = getAddr().getDefiningOp<KprobeArgOp>();
  if (!arg || arg->getParentOfType<ProgramOp>() != prog)
    return emitOpError("address must be the direct result of ebpf.kprobe.arg (no constant, arith, cast or block argument)");
  if (prog.getBody().empty() || prog.getBody().front().getNumArguments() == 0 ||
      arg.getCtx() != prog.getBody().front().getArgument(0))
    return emitOpError("kprobe.arg must use the same program entry context");
  if (getOffset() < 0 || getOffset() > 4095)
    return emitOpError("offset must be a constant in 0..4095");
  unsigned w = getValue().getType().getIntOrFloatBitWidth();
  if (w != 8 && w != 16 && w != 32 && w != 64)
    return emitOpError("value must be i8, i16, i32 or i64");
  return success();
}

// fexit alone has the return slot. Bound nargs by MAX_BPF_FUNC_ARGS (twelve).
LogicalResult CtxRetvalOp::verify() {
  auto ctx = cast<ContextType>(getCtx().getType());
  if (!bpfmlir::kindAllows(ctx.getKind(), "ctx.retval"))
    return emitOpError() << "program kind \"" << ctx.getKind() << "\" has no return value in its context (only " << bpfmlir::kindsAllowing("ctx.retval") << ")";
  if (getNargs() < 0 || getNargs() > 12)
    return emitOpError() << "the number of arguments " << getNargs() << " is out of range (0..12)";
  unsigned w = getResult().getType().getIntOrFloatBitWidth();
  if (w != 8 && w != 16 && w != 32 && w != 64)
    return emitOpError() << "reads an i8 / i16 / i32 / i64 return value, got " << getResult().getType();
  return success();
}

// probe.retval reads the raw eight-byte return register, truncating to i8/i16/i32/i64.
LogicalResult ProbeRetvalOp::verify() {
  auto ctx = cast<ContextType>(getCtx().getType());
  if (!bpfmlir::kindAllows(ctx.getKind(), "probe.retval"))
    return emitOpError() << "program kind \"" << ctx.getKind() << "\" does not run at a function's return (only "
                         << bpfmlir::kindsAllowing("probe.retval") << ")";
  unsigned w = getResult().getType().getIntOrFloatBitWidth();
  if (w != 8 && w != 16 && w != 32 && w != 64)
    return emitOpError() << "reads an i8 / i16 / i32 / i64 return value, got " << getResult().getType();
  return success();
}

// probe.target_index uses the own entry context and OPS-enabled multi family.
// Loader supplies mtarget index cookies. Single probes lack that contract;
// static context arguments cannot inherit attachment-dependent semantics.
LogicalResult ProbeTargetIndexOp::verify() {
  if (!ownerKindAllows(*this, getCtx(), "probe.target_index"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("probe.target_index")
                         << " programs with their own context (the index in the attach list is the attach cookie the loader sets)";
  return success();
}

// Session operations require own program ctx, session OPS and supported
// kfunc program types.
static LogicalResult verifySessionOp(Operation *op, Value ctx, StringRef kfunc) {
  if (!ownerKindAllows(op, ctx, "session"))
    return op->emitOpError() << "is only for " << bpfmlir::kindsAllowing("session")
                             << " programs with their own context (the session kfuncs run in a kprobe session or fsession)";
  const bpfabi::KfuncABI *k = bpfabi::lookupKfunc(kfunc);
  if (!k)
    return op->emitOpError() << "needs kfunc \"" << kfunc << "\", which is not in the kfunc table";
  StringRef kind = cast<ContextType>(ctx.getType()).getKind();
  StringRef ptype = programTypeOf(kind);
  if (!k->allowsProgType(ptype))
    return op->emitOpError() << "kfunc \"" << kfunc << "\" is not registered for program type " << ptype << " (kind \"" << kind
                             << "\"); the kfunc table allows " << k->progTypes << "";
  return success();
}
LogicalResult SessionIsReturnOp::verify() { return verifySessionOp(*this, getCtx(), "bpf_session_is_return"); }
LogicalResult SessionCookieLoadOp::verify() { return verifySessionOp(*this, getCtx(), "bpf_session_cookie"); }
LogicalResult SessionCookieStoreOp::verify() { return verifySessionOp(*this, getCtx(), "bpf_session_cookie"); }

LogicalResult SockAddrSetSunPathOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || !ownerKindAllows(*this, getCtx(), "sock_addr.set_sun_path") ||
      prog.getAttach().value_or("") != "connect_unix" ||
      getCtx() != prog.getBody().front().getArgument(0) ||
      (*this)->getParentOfType<SubprogramOp>() || (*this)->getParentOfType<LoopCallbackOp>())
    return emitOpError("requires its own cgroup_sock_addr connect_unix entry context");
  for (Operation *p = (*this)->getParentOp(); p && p != prog.getOperation(); p = p->getParentOp())
    if (isa<LoopOp, MapForEachOp, SpinRegionOp>(p) || p->getName().getStringRef() == "scf.if")
      return emitOpError("cannot run in a loop, callback or spin region");
  if (getLiteral().empty() || getLiteral().size() > 108)
    return emitOpError("requires a literal of 1..108 bytes (NUL bytes count)");
  for (StringRef name : {StringRef("bpf_cast_to_kern_ctx"), StringRef("bpf_sock_addr_set_sun_path")}) {
    const bpfabi::KfuncABI *k = bpfabi::lookupKfunc(name);
    if (!k || !k->allowsProgType("cgroup_sock_addr"))
      return emitOpError() << "requires registered kfunc " << name;
  }
  return success();
}

// Per-target arguments require own entry context, probe.target_arg OPS and
// target index below the explicit attachment-list length.
LogicalResult ProbeTargetArgOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || !ownerKindAllows(*this, getCtx(), "probe.target_arg"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("probe.target_arg")
                         << " programs with their own context (the attach list index i is the attach cookie the loader sets)";
  size_t targets = prog.getAttachList() ? prog.getAttachList()->size() : 0;
  if (getTarget() < 0 || static_cast<size_t>(getTarget()) >= targets)
    return emitOpError() << "target " << getTarget() << " is not in the attach list of @" << prog.getSymName() << " (" << targets
                         << " target(s))";
  if (getN() < 1)
    return emitOpError() << "the argument number " << getN() << " must be >= 1 (1-based)";
  if (isa<UserBufType>(getValue().getType())) {
    if (prog.getKind() != "uprobe_multi")
      return emitOpError("user_buf is only for uprobe_multi target arguments");
    for (Operation *user : getValue().getUsers())
      if (!isa<UserReadOp>(user))
        return emitOpError("user_buf may only be read by ebpf.user.read (no cast, select, store or escape)");
  }
  // a per-target string is still a typed user address, never a kernel pointer or integer.
  if (isa<UserStrType>(getValue().getType()) && !bpfmlir::kindAllows(prog.getKind(), "user.read_str"))
    return emitOpError() << "reads a per-target user string only in a kind with user.read_str";
  return success();
}

// ksyscall.arg requires own entry context, ksyscall.arg OPS and one-based n in 1..6.
LogicalResult KsyscallArgOp::verify() {
  if (!ownerKindAllows(*this, getCtx(), "ksyscall.arg"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("ksyscall.arg")
                         << " programs with their own context (the syscall arguments are behind the wrapper's pt_regs pointer)";
  if (getN() < 1 || getN() > 6)
    return emitOpError() << "argument " << getN() << " must be 1..6 (a syscall takes at most 6 arguments)";
  return verifyUserArrayUses(*this, getResult());
}

// usdt.arg uses own entry context and loader-populated cookie specs.
// Require usdt.arg OPS and n in 1..12; VerifySchema matches declared n/width.
LogicalResult UsdtArgOp::verify() {
  if (!ownerKindAllows(*this, getCtx(), "usdt.arg"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("usdt.arg")
                         << " programs with their own context (the loader writes each point's argument spec and passes the point index as the attach cookie)";
  if (getN() < 1 || getN() > ::ebpf::kUsdtMaxArgs)
    return emitOpError() << "argument " << getN() << " must be 1.." << ::ebpf::kUsdtMaxArgs << " (a USDT probe has at most "
                         << ::ebpf::kUsdtMaxArgs << " arguments)";
  return success();
}

// seq.write requires iterator OPS, kptr<seq_file>, and full-byte record.make data.
LogicalResult SeqWriteOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || !bpfmlir::kindAllows(prog.getKind(), "seq.write"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("seq.write")
                         << " programs (bpf_seq_write is only for BPF_TRACE_ITER)";
  if (cast<KPtrType>(getSeq().getType()).getStructName() != "seq_file")
    return emitOpError() << "writes to a !ebpf.kptr<\"seq_file\"> (bpf_iter_meta's seq, checked with ebpf.kptr.check), got "
                         << getSeq().getType();
  if (!getRecord().getDefiningOp<RecordMakeOp>())
    return emitOpError() << "the data must be built by ebpf.record.make (every byte, padding zeroed)";
  return success();
}

// ringbuf.output takes full-byte record.make data and named ABI ring flags.
// VerifySchema owns map name, record agreement and size bounds.
LogicalResult RingbufOutputOp::verify() {
  if (!getRecord().getDefiningOp<RecordMakeOp>())
    return emitOpError() << "the data must be built by ebpf.record.make (every byte, padding zeroed)";
  if (auto f = getFlags(); f && *f != "no_wakeup" && *f != "force_wakeup")
    return emitOpError() << "flags must be \"no_wakeup\" or \"force_wakeup\" (BPF_RB_*), got \"" << *f << "\"";
  return success();
}

// Dynptr values originate only at reserve_dynptr and may feed supported
// read/write/submit/discard operands, never yields, calls, block arguments or
// loop captures. Ownership analysis checks counts and use after consumption.
static bool isDynptrWidth(Type t) {
  auto it = dyn_cast<IntegerType>(t);
  return it && it.isSignless() && (it.getWidth() == 8 || it.getWidth() == 16 || it.getWidth() == 32 || it.getWidth() == 64);
}

LogicalResult RingbufReserveDynptrOp::verify() {
  if (cast<DynptrType>(getDynptr().getType()).getKind() != "ringbuf")
    return emitOpError() << "makes a !ebpf.dynptr<\"ringbuf\">, got " << getDynptr().getType();
  for (OpOperand &use : getDynptr().getUses()) {
    Operation *user = use.getOwner();
    if (isa<DynptrWriteOp, DynptrReadOp, RingbufSubmitDynptrOp, RingbufDiscardDynptrOp>(user) && use.getOperandNumber() == 0)
      continue;
    return user->emitOpError() << "uses a ring buffer dynptr; a dynptr may only be the dynptr of ebpf.dynptr.write / "
                                  "dynptr.read / ringbuf.submit_dynptr / ringbuf.discard_dynptr (it is a stack slot the "
                                  "kernel verifier tracks — it does not flow through yield, call or loop values)";
  }
  return success();
}

LogicalResult DynptrWriteOp::verify() {
  if (cast<DynptrType>(getDynptr().getType()).getKind() != "ringbuf")
    return emitOpError() << "writes only to a !ebpf.dynptr<\"ringbuf\"> (from ebpf.ringbuf.reserve_dynptr), got "
                         << getDynptr().getType();
  if (!isDynptrWidth(getValue().getType()))
    return emitOpError() << "writes an i8 / i16 / i32 / i64 value, got " << getValue().getType();
  return success();
}

LogicalResult DynptrReadOp::verify() {
  StringRef k = cast<DynptrType>(getDynptr().getType()).getKind();
  if (k != "ringbuf" && k != "user_ringbuf")
    return emitOpError() << "reads a !ebpf.dynptr<\"ringbuf\"> or !ebpf.dynptr<\"user_ringbuf\">, got " << getDynptr().getType();
  if (!isDynptrWidth(getValue().getType()))
    return emitOpError() << "reads an i8 / i16 / i32 / i64 value, got " << getValue().getType();
  return success();
}

LogicalResult RingbufSubmitDynptrOp::verify() {
  if (cast<DynptrType>(getDynptr().getType()).getKind() != "ringbuf")
    return emitOpError() << "consumes a !ebpf.dynptr<\"ringbuf\"> (from ebpf.ringbuf.reserve_dynptr), got " << getDynptr().getType();
  return success();
}

LogicalResult RingbufDiscardDynptrOp::verify() {
  if (cast<DynptrType>(getDynptr().getType()).getKind() != "ringbuf")
    return emitOpError() << "consumes a !ebpf.dynptr<\"ringbuf\"> (from ebpf.ringbuf.reserve_dynptr), got " << getDynptr().getType();
  return success();
}

// User-ringbuf callbacks have one sample-dynptr argument and done terminator.
// Allow only arithmetic, sample dynptr.read, global reads/additions and ktime.ns.
LogicalResult UserRingbufCallbackOp::verify() {
  Block &b = getBody().front();
  auto dt = DynptrType::get(getContext(), "user_ringbuf");
  if (b.getNumArguments() != 1 || b.getArgument(0).getType() != dt)
    return emitOpError() << "takes exactly one argument of type " << dt << " (the sample)";
  if (b.empty() || !isa<UserRingbufDoneOp>(b.back()))
    return emitOpError() << "must end with ebpf.user_ringbuf.done";
  Value d = b.getArgument(0);
  for (Operation &op : b) {
    if (&op == &b.back())
      continue;
    if (op.getDialect() && op.getDialect()->getNamespace() == "arith")
      continue;
    if (auto rd = dyn_cast<DynptrReadOp>(op); rd && rd.getDynptr() == d)
      continue;
    if (isa<GlobalLoadOp, GlobalAtomicAddOp, KtimeOp>(op))
      continue;
    return op.emitOpError() << "is not allowed inside ebpf.user_ringbuf.callback (only arith, ebpf.dynptr.read of its sample, "
                               "ebpf.global.load / global.atomic_add and ebpf.ktime.ns)";
  }
  for (Operation *user : d.getUsers())
    if (!isa<DynptrReadOp>(user))
      return user->emitOpError() << "uses the user_ringbuf sample dynptr; it may only be read with ebpf.dynptr.read";
  return success();
}

LogicalResult UserRingbufDrainOp::verify() {
  if (!(*this)->getParentOfType<ProgramOp>())
    return emitOpError() << "is only allowed in the body of an ebpf.program";
  auto cb = SymbolTable::lookupNearestSymbolFrom<UserRingbufCallbackOp>(*this, getCallbackAttr());
  if (!cb)
    return emitOpError() << "callback @" << getCallback() << " is not an ebpf.user_ringbuf.callback";
  return success();
}

// ctx.load reads fixed offsets in user-supplied syscall context through own entry ctx.
LogicalResult CtxLoadOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || prog.getBody().empty() || prog.getBody().front().getNumArguments() < 1 ||
      getCtx() != prog.getBody().front().getArgument(0))
    return emitOpError() << "needs the context argument of the enclosing ebpf.program (not in a static ebpf.func)";
  if (!bpfmlir::kindAllows(prog.getKind(), "ctx.load"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("ctx.load")
                         << " programs (a context of raw bytes from the caller — struct contexts are read with ebpf.ctx.field)";
  unsigned w = getResult().getType().getIntOrFloatBitWidth();
  if (w != 8 && w != 16 && w != 32 && w != 64)
    return emitOpError() << "reads an i8 / i16 / i32 / i64 value, got " << getResult().getType();
  int64_t off = static_cast<int64_t>(getOffset()), bytes = w / 8;
  if (off < 0 || off % bytes != 0)
    return emitOpError() << "offset " << off << " must be >= 0 and a multiple of the width " << bytes << "";
  if (off + bytes > 65535)
    return emitOpError() << "offset " << off << " + " << bytes << " bytes is beyond the 65535-byte context the kernel accepts (U16_MAX)";
  return success();
}

// lirc sample is u32 at context offset zero; ODS requires an i32 result.
LogicalResult LircSampleOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || prog.getBody().empty() || prog.getBody().front().getNumArguments() < 1 ||
      getCtx() != prog.getBody().front().getArgument(0))
    return emitOpError() << "needs the context argument of the enclosing ebpf.program (not in a static ebpf.func)";
  if (!bpfmlir::kindAllows(prog.getKind(), "lirc.sample"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("lirc.sample")
                         << " programs (the context is the u32 IR sample of an rc-core raw device)";
  return success();
}

// Tracepoint field offset/width is matched to schema by VerifySchema.
// tp_prog_is_valid_access requires offset>=pointer size, offset<8192 and
// width alignment; compiler conservatively also requires offset+width<=8192.
LogicalResult TpFieldOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || prog.getBody().empty() || prog.getBody().front().getNumArguments() < 1 ||
      getCtx() != prog.getBody().front().getArgument(0))
    return emitOpError() << "needs the context argument of the enclosing ebpf.program (not in a static ebpf.func)";
  if (!bpfmlir::kindAllows(prog.getKind(), "tp.field"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("tp.field")
                         << " programs (the context is the record of a tracefs event)";
  if (getField().empty())
    return emitOpError() << "needs the field name (the schema fields of the program declare its offset and type)";
  unsigned w = isa<UserStrType, UserStrArrayType>(getResult().getType()) ? 64 : getResult().getType().getIntOrFloatBitWidth();
  if (w != 8 && w != 16 && w != 32 && w != 64)
    return emitOpError() << "reads an i8 / i16 / i32 / i64 value, got " << getResult().getType();
  int64_t off = static_cast<int64_t>(getOffset()), bytes = w / 8;
  if (off < mlir::bpfabi::kTracepointFirstField)
    return emitOpError() << "offset " << off << " is in the first 8 bytes of the record (common_type / common_flags / common_preempt_count / "
                         << "common_pid), which the kernel replaces with a pt_regs pointer — a tracepoint program reads from offset 8";
  if (off % bytes != 0)
    return emitOpError() << "offset " << off << " must be a multiple of the width " << bytes << " (the kernel rejects a misaligned ctx read)";
  if (off + bytes > mlir::bpfabi::kTracepointMaxCtx)
    return emitOpError() << "offset " << off << " + " << bytes << " bytes is beyond the " << mlir::bpfabi::kTracepointMaxCtx
                         << "-byte record the kernel lets a tracepoint program read (PERF_MAX_TRACE_SIZE)";
  return verifyUserArrayUses(*this, getResult());
}

LogicalResult TpFieldCopyOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || prog.getBody().empty() || prog.getBody().front().getNumArguments() == 0 ||
      getCtx() != prog.getBody().front().getArgument(0) || !bpfmlir::kindAllows(prog.getKind(), "tp.field.copy"))
    return emitOpError("needs its own tracepoint entry context (not a static func or callback)");
  for (Operation *p = (*this)->getParentOp(); p && p != prog.getOperation(); p = p->getParentOp())
    if (isa<LoopOp, MapForEachOp, SubprogramOp, LoopCallbackOp>(p))
      return emitOpError("cannot run in a loop or callback");
  if (getField().empty() || getPath().empty() || !getDstRecord())
    return emitOpError("needs field/path names and a borrowed record or record reservation destination");
  if (getOffset() < mlir::bpfabi::kTracepointFirstField || getOffset() >= mlir::bpfabi::kTracepointMaxCtx)
    return emitOpError("offset must be from 8 to 8191 (tracepoint context)");
  return success();
}

RecordType TpFieldCopyOp::getDstRecord() {
  if (auto b = dyn_cast<BorrowedType>(getDst().getType()))
    return dyn_cast<RecordType>(b.getPointee());
  if (auto r = dyn_cast<ReservationType>(getDst().getType()))
    return dyn_cast<RecordType>(r.getRecordType());
  return {};
}

LogicalResult KFieldCopyOp::verify() {
  if (getField().empty() || getPath().empty())
    return emitOpError() << "needs a field name and a destination path";
  if (!getDstRecord())
    return emitOpError() << "the destination must be a borrowed record (!ebpf.borrowed<!ebpf.record<...>>) or a record reservation "
                            "(!ebpf.reservation<!ebpf.record<...>>), got "
                         << getDst().getType();
  return success();
}

// Destination record from a borrowed pointee or reservation; otherwise null.
RecordType KFieldCopyOp::getDstRecord() {
  if (auto b = dyn_cast<BorrowedType>(getDst().getType()))
    return dyn_cast<RecordType>(b.getPointee());
  if (auto r = dyn_cast<ReservationType>(getDst().getType()))
    return dyn_cast<RecordType>(r.getRecordType());
  return {};
}

LogicalResult KFieldPtrOp::verify() {
  if (getField().empty())
    return emitOpError() << "needs a field name";
  return success();
}

LogicalResult KPtrAddrOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || !bpfmlir::kindAllows(prog.getKind(), "kptr.addr"))
    return emitOpError("requires a tracing program body (tp_btf / fentry / fexit / iter / fmod_ret / fsession)");
  for (Operation *p = (*this)->getParentOp(); p && p != prog.getOperation(); p = p->getParentOp())
    if (isa<SubprogramOp, LoopCallbackOp, TimerCallbackOp, UserRingbufCallbackOp, LoopOp, MapForEachOp, BpfLoopOp>(p))
      return emitOpError("is not supported inside a func, callback or loop");
  return success();
}

LogicalResult KFieldLoadOp::verify() {
  if (getField().empty())
    return emitOpError() << "needs a field name";
  unsigned w = cast<IntegerType>(getResult().getType()).getWidth();
  if (w != 8 && w != 16 && w != 32 && w != 64)
    return emitOpError() << "reads an 8 / 16 / 32 / 64-bit integer field, got "
                         << getResult().getType();
  return success();
}

// Kernel integer stores require kfield.store OPS (struct_ops). Reject funcs
// conservatively rather than infer calling-program kinds; target kernel
// btf_struct_access owns actual write support.
LogicalResult KFieldStoreOp::verify() {
  if (getField().empty())
    return emitOpError() << "needs a field name";
  if (getField().contains('.'))
    return emitOpError("nested kernel stores are not supported");
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || !bpfmlir::kindAllows(prog.getKind(), "kfield.store"))
    return emitOpError() << "writes a kernel struct field, which is only for " << bpfmlir::kindsAllowing("kfield.store")
                         << " programs (the kernel allows writes through a BTF pointer only for those program types)";
  return success();
}

LogicalResult PacketLoadOp::verify() {
  auto ctx = cast<ContextType>(getCtx().getType());
  if (!isKnownProgramKind(ctx.getKind()))
    return emitOpError() << "unknown context kind \"" << ctx.getKind()
                         << "\" (known: " << knownProgramKinds() << ")";
  if (!supportsPacketAccess(ctx.getKind()))
    return emitOpError() << "program kind \"" << ctx.getKind()
                         << "\" has no packet to read";
  if (!isMemWidth(getResult().getType()))
    return emitOpError() << "reads an i8 / i16 / i32 / i64, got " << getResult().getType() << "";
  if (!isMemWidth(getOffset().getType()))
    return emitOpError() << "the offset must be an i8 / i16 / i32 / i64, got " << getOffset().getType() << "";
  return success();
}

// Expanded operations. BPF atomic addition permits only 32/64 bits.
LogicalResult GlobalAtomicAddOp::verify() {
  unsigned w = getDelta().getType().getIntOrFloatBitWidth();
  if (w != 32 && w != 64)
    return emitOpError() << "atomic add is 32 or 64 bits (BPF atomic), got i" << w;
  return success();
}

LogicalResult RefAtomicAddOp::verify() {
  if (failed(checkNotLpmValue(*this, getRef())))
    return failure();
  Type t = getRef().getType();
  if (isa<MaybeRefType>(t)) {
    auto d = emitOpError() << "operand is an unchecked nullable reference " << t;
    d.attachNote() << "check it with ebpf.ref.check first; the kernel verifier "
                      "rejects dereferencing a possibly-null map lookup result";
    return failure();
  }
  auto b = dyn_cast<BorrowedType>(t);
  if (!b)
    return emitOpError() << "operand must be !ebpf.borrowed<...>, got " << t;
  if (b.getPointee() != getDelta().getType())
    return emitOpError() << "delta type " << getDelta().getType()
                         << " does not match the borrowed pointee "
                         << b.getPointee();
  // BPF atomics permit only 32/64 bits, like map.atomic_add.
  if (!getDelta().getType().isInteger(32) && !getDelta().getType().isInteger(64))
    return emitOpError() << "atomic add is 32 / 64 bit only (BPF atomics), got " << getDelta().getType() << "";
  return success();
}

LogicalResult IsPresentOp::verify() {
  Type t = getValue().getType();
  if (!isa<MaybeRefType, MaybeReservationType, KPtrOrNullType, KRefOrNullType, SockRefOrNullType>(t)) // kptr.check and kref.check.
    return emitOpError() << "operand must be !ebpf.maybe_ref<...> or "
                         << "!ebpf.maybe_reservation<...>, got " << t;
  return success();
}

LogicalResult AssumePresentOp::verify() {
  Type in = getValue().getType();
  Type out = getResult().getType();
  if (isa<SockRefOrNullType>(in)) {
    if (!isa<SockRefType>(out))
      return emitOpError() << "a checked socket must become !ebpf.sock_ref";
    return success();
  }
  if (auto m = dyn_cast<KPtrOrNullType>(in)) { // Present kptr from kptr.check.
    auto k = dyn_cast<KPtrType>(out);
    if (!k || k.getStructName() != m.getStructName())
      return emitOpError() << "a checked " << in << " must become !ebpf.kptr<\"" << m.getStructName() << "\">, got " << out;
    return success();
  }
  if (auto m = dyn_cast<KRefOrNullType>(in)) { // Present kref from kref.check.
    auto k = dyn_cast<KRefType>(out);
    if (!k || k.getStructName() != m.getStructName())
      return emitOpError() << "a checked " << in << " must become !ebpf.kref<\"" << m.getStructName() << "\">, got " << out;
    return success();
  }
  if (auto m = dyn_cast<MaybeRefType>(in)) {
    auto b = dyn_cast<BorrowedType>(out);
    if (!b || b.getPointee() != m.getPointee())
      return emitOpError() << "a checked " << in << " must become "
                           << "!ebpf.borrowed<" << m.getPointee() << ">, got "
                           << out;
    return success();
  }
  if (auto m = dyn_cast<MaybeReservationType>(in)) {
    auto r = dyn_cast<ReservationType>(out);
    if (!r || r.getRecordType() != m.getRecordType())
      return emitOpError() << "a checked " << in << " must become "
                           << "!ebpf.reservation<" << m.getRecordType()
                           << ">, got " << out;
    return success();
  }
  return emitOpError() << "operand must be !ebpf.maybe_ref<...> or "
                       << "!ebpf.maybe_reservation<...>, got " << in;
}


// Functions, returns and calls.
namespace {
// BPF arguments use R1..R5. LLVM cannot pass a sixth register argument;
// kernel MAX_BPF_FUNC_REG_ARGS is also five.
constexpr unsigned kMaxSubprogramArgs = 5;

// Supported subprogram scalars are signless 8/16/32/64-bit integers.
bool isSubprogramScalar(Type t) {
  auto it = dyn_cast<IntegerType>(t);
  if (!it || !it.isSignless())
    return false;
  unsigned w = it.getWidth();
  return w == 8 || w == 16 || w == 32 || w == 64;
}

// Arguments may be nullable or checked map-value references to integer
// scalars or records. VerifyRecords owns record shape restrictions.
bool isSubprogramRef(Type t) {
  Type p;
  if (auto m = dyn_cast<MaybeRefType>(t))
    p = m.getPointee();
  else if (auto b = dyn_cast<BorrowedType>(t))
    p = b.getPointee();
  else
    return false;
  return isSubprogramScalar(p) || isa<RecordType>(p);
}

// Borrowed arguments (direct or checked from nullable arguments) permit
// reads, supported stores/atomics and same-typed call forwarding. Nullable
// arguments permit only ref.check and calls. Call verification rejects
// forwarding read-only lpm_trie values into writing callees.
LogicalResult verifyReadOnlyRef(Operation *fn, Value v, unsigned argNo) {
  for (Operation *user : v.getUsers()) {
    if (isa<BorrowedType>(v.getType()) &&
        isa<RefLoadOp, RefFieldLoadOp, RefStoreOp, RefFieldStoreOp, RefAtomicAddOp, RefFieldAtomicAddOp, CallOp>(user))
      continue;
    if (isa<MaybeRefType>(v.getType())) {
      if (isa<CallOp>(user))
        continue;
      if (auto chk = dyn_cast<RefCheckOp>(user)) {
        if (failed(verifyReadOnlyRef(fn, chk.getPresentRegion().front().getArgument(0), argNo)))
          return failure();
        continue;
      }
      // Expanded ref.check uses is_present/assume_present; apply supported-use checks.
      if (isa<IsPresentOp>(user))
        continue;
      if (auto a = dyn_cast<AssumePresentOp>(user)) {
        if (failed(verifyReadOnlyRef(fn, a.getResult(), argNo)))
          return failure();
        continue;
      }
    }
    return fn->emitOpError()
           << "argument #" << argNo << " (" << v.getType()
           << ") is used by '" << user->getName()
           << "'; a subprogram may only read or write a map value it is passed "
              "(ebpf.ref.check / ebpf.ref.load / ebpf.ref.field.load / ebpf.ref.store / ebpf.ref.field.store / "
              "ebpf.ref.atomic_add / ebpf.ref.field.atomic_add, or pass it on with ebpf.call)";
  }
  return success();
}
} // namespace

LogicalResult SubprogramOp::verify() {
  if (getLinkage() != "static" && getLinkage() != "global")
    return emitOpError() << "unknown linkage \"" << getLinkage()
                         << "\" (known: \"static\", \"global\")";
  FunctionType ft = getFunctionType();
  if (ft.getNumInputs() > kMaxSubprogramArgs)
    return emitOpError() << "takes " << ft.getNumInputs()
                         << " arguments; a BPF subprogram takes at most "
                         << kMaxSubprogramArgs << " (R1..R5)";
  for (auto [i, t] : llvm::enumerate(ft.getInputs()))
    if (isa<PktWindowType>(t) && getLinkage() != "static")
      return emitOpError() << "argument #" << i << " is a packet window " << t
                           << "; only a static ebpf.func takes one — the kernel verifier checks a global function on its own "
                              "and treats a pointer argument as plain memory, not packet data";
  // Context arguments are static-only. Global callees are independently
// verified through BTF types; tracing contexts are not accepted there on 6.6.
  for (auto [i, t] : llvm::enumerate(ft.getInputs()))
    if (isa<ContextType>(t) && getLinkage() != "static")
      return emitOpError() << "argument #" << i << " is a context " << t
                           << "; only a static ebpf.func takes one — a global function is checked on its own from its BTF types, "
                              "and the tracing contexts have no type 6.6 accepts there";
  for (auto [i, t] : llvm::enumerate(ft.getInputs()))
    if (!isSubprogramScalar(t) && !isSubprogramRef(t) && !isa<PktWindowType>(t) && !isa<ContextType>(t))
      return emitOpError() << "argument #" << i << " has type " << t
                           << "; a subprogram argument must be i8 / i16 / i32 / i64, "
                              "!ebpf.maybe_ref / !ebpf.borrowed of one of them or of a record, "
                              "a packet window of a static function or the context of a static function";
  if (ft.getNumResults() != 1 || !isSubprogramScalar(ft.getResult(0)))
    return emitOpError() << "must return exactly one i8 / i16 / i32 / i64 "
                            "(a global BPF function returns a scalar)";

  Block &entry = getBody().front();
  unsigned nIn = ft.getNumInputs();
  if (entry.getNumArguments() < nIn)
    return emitOpError() << "entry block takes " << entry.getNumArguments()
                         << " argument(s) but the type has " << nIn;
  for (unsigned i = 0; i < nIn; ++i)
    if (entry.getArgument(i).getType() != ft.getInput(i))
      return emitOpError() << "entry block argument #" << i << " has type "
                           << entry.getArgument(i).getType() << " but the type says "
                           << ft.getInput(i);
  // Context belongs among typed arguments, never trailing map-binding arguments.
  for (BlockArgument a : entry.getArguments().drop_front(nIn))
    if (isa<ContextType>(a.getType()))
      return emitOpError() << "a subprogram does not take a context";
  if (failed(verifyMapBindings(getOperation(), getMapSymbolsAttr(),
                               entry.getArguments().drop_front(nIn),
                               "the typed arguments")))
    return failure();
  for (unsigned i = 0; i < nIn; ++i)
    if (isSubprogramRef(ft.getInput(i)) &&
        failed(verifyReadOnlyRef(getOperation(), entry.getArgument(i), i)))
      return failure();
  // Static contexts permit only attachment-independent operations/forwarding.
  // ctx.arg/retval and probe argument types rely on caller schema; another
  // attachment could bypass matching. Invalidating operations could clear
  // caller windows across calls, so reject them. Read such values in the
  // caller and pass integers instead.
  for (unsigned i = 0; i < nIn; ++i) {
    if (!isa<ContextType>(ft.getInput(i)))
      continue;
    for (Operation *user : entry.getArgument(i).getUsers()) {
      if (isa<PacketLoadOp, PacketCheckOp, PktCheckBrOp, StackKernelIdOp, StackUserIdOp, PerfOutputOp, CallOp>(user)) // pkt.check_br is the expanded packet.check.
        continue;
      if (isa<CtxArgOp, CtxRetvalOp, KprobeArgOp, UprobeArgOp>(user))
        return emitOpError() << "context argument #" << i << " is used by '" << user->getName()
                             << "', whose meaning depends on the attach point (the function signature or the tracepoint); "
                                "read it in the program and pass the value as an integer";
      if (isa<XdpAdjustHeadOp, XdpAdjustTailOp, TailCallOp, TailCallTryOp, LwtSeg6StoreBytesOp, LwtSeg6AdjustSrhOp, LwtSeg6ActionOp,
                MsgPullDataOp, MsgPopDataOp>(user)) // Include seg6 and message pull/pop invalidators.
        return emitOpError() << "context argument #" << i << " is used by '" << user->getName()
                             << "', which invalidates the caller's packet pointers; call it in the program";
      return emitOpError() << "context argument #" << i << " may only be used by ebpf.packet.load, ebpf.packet.check, "
                              "ebpf.stack.kernel_id, ebpf.stack.user_id, ebpf.perf.output or passed on by ebpf.call, but it is used by '"
                           << user->getName() << "'";
    }
  }
  // Window arguments permit window_load, caller-qualified packet.store,
  // and forwarding to other static functions only.
  for (unsigned i = 0; i < nIn; ++i) {
    if (!isa<PktWindowType>(ft.getInput(i)))
      continue;
    for (Operation *user : entry.getArgument(i).getUsers())
      if (!isa<PacketWindowLoadOp, PacketStoreOp, CallOp>(user))
        return emitOpError() << "packet window argument #" << i << " may only be used by ebpf.packet.window_load, "
                                "ebpf.packet.store, or passed on by ebpf.call, but it is used by '"
                             << user->getName() << "' (it must not escape the range the caller checked)";
  }

  for (Block &blk : getBody()) {
    if (blk.empty() || !blk.back().hasTrait<OpTrait::IsTerminator>())
      return emitOpError() << "every block must end with a terminator";
    Operation *term = &blk.back();
    if (term->getNumSuccessors() == 0 && !isa<ReturnOp>(term))
      return emitOpError() << "must be terminated by ebpf.return, got "
                           << term->getName();
  }
  return verifyReservationUses(getBody());
}

LogicalResult ReturnOp::verify() {
  // Integer program returns require attachment VERDICTS |int[:range].
  if (auto prog = dyn_cast<ProgramOp>((*this)->getParentOp())) {
    const bpfmlir::ProgramKindInfo *k = bpfmlir::lookupProgramKind(prog.getKind());
    const bpfmlir::ProgramAttachInfo *row = k ? bpfmlir::lookupProgramAttach(*k, programAttachOf(prog)) : nullptr;
    if (!row)
      return success(); // Program verification already rejected missing kind/attachment rows.
    StringRef range;
    // Integer-return permission is attachment-specific, never inherited from
    // another row of the same kind.
    if (!bpfmlir::intReturnOf(*row, range)) {
      if (bpfmlir::kindHasIntReturn(*k))
        return emitOpError() << "returns a computed value, which the " << (programAttachOf(prog).empty() ? StringRef("default") : programAttachOf(prog))
                             << " attach of a " << prog.getKind() << " program does not allow (it returns a named verdict — ebpf.verdict; kind table)";
      return emitOpError() << "returns a computed value, which is only for "
                           << bpfmlir::joinProgramKinds([](auto &x) { return bpfmlir::kindHasIntReturn(x); }, "", ", ", " and ")
                           << " programs (program kind \"" << prog.getKind() << "\" returns a named verdict — ebpf.verdict)";
    }
    // ext returns match replacement width (i32/i64), with schema agreement checked separately.
    bool extRet = !bpfmlir::entryTakesCtx(k->attach);
    if (!getValue().getType().isInteger(32) && !(extRet && getValue().getType().isInteger(64)))
      return emitOpError() << "a " << prog.getKind() << " program returns an i32 value" << (extRet ? " or an i64 value" : "") << ", got "
                           << getValue().getType();
    // lo..hi checks constant values only; any/u32 accept all 32-bit patterns.
    auto [lo, hi] = range.split("..");
    int64_t l, h;
    APInt c;
    if (!hi.empty() && !lo.getAsInteger(10, l) && !hi.getAsInteger(10, h) && matchPattern(getValue(), m_ConstantInt(&c)) &&
        (c.getSExtValue() < l || c.getSExtValue() > h))
      return emitOpError() << "returns " << c.getSExtValue() << ", outside the range " << range << " of a " << prog.getKind()
                           << " program (kind table)";
    return success();
  }
  auto fn = (*this)->getParentOfType<SubprogramOp>();
  Type want = fn.getFunctionType().getNumResults() == 1
                  ? fn.getFunctionType().getResult(0)
                  : Type();
  if (getValue().getType() != want)
    return emitOpError() << "returns " << getValue().getType() << " but @"
                         << fn.getSymName() << " returns " << want;
  return success();
}

LogicalResult CallOp::verifySymbolUses(SymbolTableCollection &symbolTable) {
  Operation *target =
      symbolTable.lookupNearestSymbolFrom(getOperation(), getCalleeAttr());
  if (!target)
    return emitOpError() << "calls @" << getCallee()
                         << ", which is not defined in this module";
  if (isa<ProgramOp>(target))
    return emitOpError() << "calls @" << getCallee()
                         << ", which is an ebpf.program; programs are entry points "
                            "and cannot be called";
  auto fn = dyn_cast<SubprogramOp>(target);
  if (!fn)
    return emitOpError() << "calls @" << getCallee() << ", which is not an ebpf.func";
  FunctionType ft = fn.getFunctionType();
  if (TypeRange(getArgs().getTypes()) != TypeRange(ft.getInputs()) ||
      TypeRange(getResults().getTypes()) != TypeRange(ft.getResults()))
    return emitOpError() << "has type "
                         << FunctionType::get(getContext(), getArgs().getTypes(),
                                              getResults().getTypes())
                         << " but @" << getCallee() << " has type " << ft;
  // lpm_trie values are read-only in programs. Reject calls forwarding such
  // lookup references into arguments written by the callee.
  for (auto [i, a] : llvm::enumerate(getArgs())) {
    bool lpm = borrowsLpmTrie(a);
    if (auto lk = a.getDefiningOp<MapLookupOp>())
      lpm |= cast<MapType>(lk.getMap().getType()).getKind() == "lpm_trie";
    if (!lpm)
      continue;
    llvm::SmallPtrSet<Operation *, 8> seen;
    if (calleeWritesArg(symbolTable, fn, i, seen))
      return emitOpError() << "passes a lpm_trie value as argument #" << i << " to @" << getCallee()
                           << ", which writes it; a lpm_trie is read-only in programs (a compiler restriction — entries are set by userspace)";
  }
  return success();
}

// Record field loads/stores.
namespace {
// Field access requires a checked borrow pointing to a record.
LogicalResult checkRecordBorrow(Operation *op, Type t) {
  if (auto m = dyn_cast<MaybeRefType>(t)) {
    auto d = op->emitOpError() << "operand is an unchecked nullable reference " << t;
    d.attachNote() << "check it with ebpf.ref.check first; the kernel verifier "
                      "rejects dereferencing a possibly-null map lookup result";
    return failure();
  }
  auto b = dyn_cast<BorrowedType>(t);
  if (!b || !isa<RecordType>(b.getPointee()))
    return op->emitOpError() << "operand must be !ebpf.borrowed<!ebpf.record<...>>, got " << t;
  return success();
}
} // namespace

LogicalResult RefFieldLoadOp::verify() { return checkRecordBorrow(*this, getRef().getType()); }
LogicalResult RefFieldStoreOp::verify() {
  if (failed(checkNotLpmValue(*this, getRef())))
    return failure();
  return checkRecordBorrow(*this, getRef().getType());
}
// VerifyRecords owns atomic field path/width agreement and natural alignment.
LogicalResult RefFieldAtomicAddOp::verify() {
  if (failed(checkRecordBorrow(*this, getRef().getType())))
    return failure();
  if (failed(checkNotLpmValue(*this, getRef())))
    return failure();
  Type t = getDelta().getType();
  if (!t.isInteger(32) && !t.isInteger(64))
    return emitOpError() << "adds a " << t << "; a BPF atomic add is 32 or 64 bits wide";
  return success();
}

// Loops.
namespace {
// Conservative compiler support bound, not derived from kernel limits.
constexpr int64_t kMaxLoopCount = 64;
// Unrolled IR-copy cost bound.
constexpr uint64_t kMaxUnrolledOps = 4096;
// Nested depth <=2 and path product <=64 are compiler limits, not kernel
// limits or a proof of execution workload.
constexpr int64_t kMaxLoopDepth = 2;
constexpr int64_t kMaxNestedProduct = 64;
// Cost overhead: unrolled copies add IV constants/guards/join branches;
// bounded loops add entry/header/bound checks/latch.
constexpr uint64_t kUnrollCopyOverhead = 4;
constexpr uint64_t kBackedgeOverhead = 10;

uint64_t satAdd(uint64_t a, uint64_t b) { return std::min(a + b, kMaxUnrolledOps + 1); }
uint64_t satMul(uint64_t a, uint64_t b) {
  return (a != 0 && b > (kMaxUnrolledOps + 1) / a) ? kMaxUnrolledOps + 1 : std::min(a * b, kMaxUnrolledOps + 1);
}

uint64_t loopCost(LoopOp loop);
// Count expanded weights: atomic_add is six operations; checked regions
// and scalar/structured ifs conservatively cost four plus their arm contents.
uint64_t expandedWeight(Operation &op) {
  if (isa<MapAtomicAddOp>(op))
    return 6;
  if (isa<RefCheckOp, RingbufIfReservedOp, IfOp>(op) || op.getName().getStringRef() == "scf.if")
    return 4;
  return 1;
}
// Estimate expanded region size recursively through loopCost and operation
// weights, saturating at 4097.
uint64_t regionSize(Region &r) {
  uint64_t n = 0;
  for (Block &b : r)
    for (Operation &op : b) {
      if (auto l = dyn_cast<LoopOp>(op)) {
        n = satAdd(n, loopCost(l));
        continue;
      }
      n = satAdd(n, expandedWeight(op));
      for (Region &inner : op.getRegions())
        n = satAdd(n, regionSize(inner));
    }
  return n;
}
// Unrolled cost is N*(body+4); bounded cost is body+10. Do not discount
// runtime bounds, stop or break.
uint64_t loopCost(LoopOp loop) {
  uint64_t body = regionSize(loop.getBody());
  if (loop.getUnroll())
    return satMul(static_cast<uint64_t>(loop.getCount()), satAdd(body, kUnrollCopyOverhead));
  return satAdd(body, kBackedgeOverhead);
}

bool isLoopScalar(Type t) {
  auto it = dyn_cast<IntegerType>(t);
  return it && it.isSignless() &&
         (it.getWidth() == 8 || it.getWidth() == 16 || it.getWidth() == 32 || it.getWidth() == 64);
}

// Supported loop-body operations.
bool allowedInLoop(Operation *op) {
  // Match arith by name without linking its library into EBPF IR.
  if (op->getName().getDialectNamespace() == "arith")
    return true;
  StringRef n = op->getName().getStringRef();
  if (n == "scf.if" || n == "scf.yield")
    return true;
  return isa<MapLookupOp, MapUpdateOp, MapAtomicAddOp, RefCheckOp, YieldOp, RefLoadOp, RefStoreOp,
             RefAtomicAddOp, RefFieldLoadOp, RefFieldStoreOp, RefFieldAtomicAddOp, PacketLoadOp, KtimeOp, LoopYieldOp,
             IfOp, IfYieldOp, BreakOp, ContinueOp, LoopOp, CallOp, RecordMakeOp, MapTryUpdateOp,
             MapTryDeleteOp, ByteorderToBeOp, ByteorderFromBeOp, RefIndexOp, ElemLoadOp, ElemStoreOp,
             TaskPidTgidOp, TaskCgroupIdOp, TaskUnderCgroupOp, SkbUnderCgroupOp, CtxRetvalOp, GlobalLoadOp, GlobalAtomicAddOp, KprobeArgOp, UprobeArgOp>(op);
}

// Capture integers, context and map handles only. References, reservations
// and kernel pointers must remain within each iteration.
bool capturable(Type t) {
  return isa<IntegerType, IndexType, ContextType, MapType>(t);
}
} // namespace

LogicalResult LoopOp::verify() {
  int64_t n = getCount();
  if (n < 0 || n > kMaxLoopCount)
    return emitOpError() << "count " << n << " is out of the range this compiler supports (0.."
                         << kMaxLoopCount << ")";
  for (Type t : getInits().getTypes())
    if (!isLoopScalar(t))
      return emitOpError() << "a loop-carried value must be i8 / i16 / i32 / i64, got " << t;
  if (TypeRange(getInits().getTypes()) != TypeRange(getResults().getTypes()))
    return emitOpError() << "results must have the types of the loop-carried values";
  Block &body = getBody().front();
  if (body.getNumArguments() != getInits().size() + 1 ||
      !body.getArgument(0).getType().isSignlessInteger(32))
    return emitOpError() << "the body must take the induction variable (i32) followed by the "
                            "loop-carried values";
  for (auto [a, t] : llvm::zip(body.getArguments().drop_front(), getInits().getTypes()))
    if (a.getType() != t)
      return emitOpError() << "body argument type " << a.getType()
                           << " does not match the loop-carried value type " << t;
  auto y = dyn_cast<LoopYieldOp>(body.getTerminator());
  if (!y || TypeRange(y.getValues().getTypes()) != TypeRange(getInits().getTypes()))
    return emitOpError() << "the body must end with ebpf.loop.yield of the loop-carried types";

  // Compute nested depth and N product, treating zero as one so an outer
  // zero-trip loop cannot hide unsupported inner bounds.
  int64_t depth = 1, product = std::max<int64_t>(n, 1);
  for (auto outer = (*this)->getParentOfType<LoopOp>(); outer; outer = outer->getParentOfType<LoopOp>()) {
    ++depth;
    product *= std::max<int64_t>(outer.getCount(), 1); // Each N<=64, so a depth-two product cannot overflow.
  }
  if (depth > kMaxLoopDepth)
    return emitOpError() << "is nested " << depth << " deep; this compiler supports loops nested "
                         << kMaxLoopDepth << " deep";
  if (product > kMaxNestedProduct)
    return emitOpError() << "the counts along the nest multiply to " << product
                         << ", over the limit of " << kMaxNestedProduct
                         << " this compiler supports (a count of 0 is taken as 1)";

  // Helper-callback mode is exclusive with unroll. Mixed bounded/unrolled/
  // helper nesting and funcs use the same lexical depth/product restrictions.
  bool cb = getCallback();
  if (cb) {
    if (getUnroll())
      return emitOpError() << "cannot be both unroll and callback (pick one lowering; there is no "
                              "fallback between them)";
    // Helper loops are permitted in bounded/unrolled/helper loops and funcs,
    // subject to lexical depth/product limits.
    if (!(*this)->getParentOfType<ProgramOp>() && !(*this)->getParentOfType<SubprogramOp>())
      return emitOpError() << "a callback loop must be in an ebpf.program or an ebpf.func";
  }

  Region *self = &getBody();
  WalkResult w = getBody().walk([&](Operation *op) {
    // Callback calls are allowed; call-graph passes own frame and ring limits.
    // Mixed loop modes are allowed, but packet.check/window_load require all
    // enclosing loops to unroll, avoiding cyclic expanded window topology.
    // Each loop walks its own nested body, enforcing that all-enclosing condition.
    bool packetWalk = isa<PacketCheckOp, PacketWindowLoadOp>(op);
    if (packetWalk && !(getUnroll() && !cb)) {
      op->emitOpError() << "is only supported inside an unroll ebpf.loop (the unrolled copies have no cycle); "
                        << (cb ? "a callback loop (H)" : "a loop without unroll (B)")
                        << " cannot hold it yet — use unroll";
      return WalkResult::interrupt();
    }
    // Capture rules also apply to packet operations; windows cannot enter from outside loops.
    if (!packetWalk && !allowedInLoop(op)) {
      op->emitOpError() << "is not allowed inside ebpf.loop (arith, scf.if, map "
                           "lookup / update, ref.check and reads / writes of a checked "
                           "reference, packet.load, ktime.ns: ebpf.if, ebpf.break, "
                           "ebpf.continue: ebpf.loop to depth 2: ebpf.call to a subprogram "
                           "that reaches no ring buffer op (the callee's loops are checked on the call path): ebpf.record.make)";
      return WalkResult::interrupt();
    }
    for (Value v : op->getOperands()) {
      Region *def = v.getParentRegion();
      if (self->isAncestor(def))
        continue;
      // Helper callback bodies become separate functions: capture integers into
        // context slots and rebind map handles by symbol, nothing else.
      if (cb ? isa<IntegerType, MapType>(v.getType()) : capturable(v.getType()))
        continue;
      if (cb) {
        op->emitOpError() << "captures " << v.getType()
                          << " into a callback ebpf.loop; only integers and map handles can be "
                             "passed to the bpf_loop callback";
        return WalkResult::interrupt();
      }
      // record.make values cannot cross iterations; reconstruct each time.
      if (isa<RecordType>(v.getType())) {
        op->emitOpError() << "captures " << v.getType()
                          << " from outside the loop; a record must be built by ebpf.record.make "
                             "inside each iteration";
        return WalkResult::interrupt();
      }
      op->emitOpError() << "captures " << v.getType()
                        << " from outside the loop; a reference or reservation must be "
                           "looked up and checked inside each iteration";
      return WalkResult::interrupt();
    }
    return WalkResult::advance();
  });
  if (w.wasInterrupted())
    return failure();
  // Recursively estimate unrolled copies including nested loops, saturating at 4097.
  if (getUnroll()) {
    uint64_t body = regionSize(getBody());
    uint64_t cost = loopCost(*this);
    if (cost > kMaxUnrolledOps)
      return emitOpError() << "unrolling a body of " << body << " op(s) (+" << kUnrollCopyOverhead
                           << " per copy, inner loops counted with their own copies) " << n
                           << " times is estimated at more than the limit of " << kMaxUnrolledOps
                           << " op(s) this compiler supports";
  }
  return success();
}

// map.for_each becomes a helper callback with helper-loop capture rules.
// Its body uses the loop whitelist minus loop/call/break/continue; nested
// callbacks and calls are outside compiler support.
LogicalResult MapForEachOp::verify() {
  auto map = cast<MapType>(getMap().getType());
  StringRef k = map.getKind();
  if (k != "array" && k != "percpu_array" && k != "hash" && k != "percpu_hash" && k != "lru_hash" && k != "lru_percpu_hash")
    return emitOpError() << "needs an array / percpu_array / hash / percpu_hash / lru_hash / lru_percpu_hash map (the kernel's "
                            "map_for_each_callback), got \"" << k << "\"";
  if (!isLoopScalar(map.getKeyType()))
    return emitOpError() << "needs an integer key (8 / 16 / 32 / 64-bit — a record key is out of scope), got " << map.getKeyType() << "";
  if (!isa<IntegerType, RecordType>(map.getValueType()))
    return emitOpError() << "needs an integer or record value, got " << map.getValueType() << "";
  for (Type t : getInits().getTypes())
    if (!isLoopScalar(t))
      return emitOpError() << "a loop-carried value must be i8 / i16 / i32 / i64, got " << t;
  if (TypeRange(getInits().getTypes()) != TypeRange(getResults().getTypes()))
    return emitOpError() << "results must be the count (i64) followed by the types of the loop-carried values";
  if (!(*this)->getParentOfType<ProgramOp>() && !(*this)->getParentOfType<SubprogramOp>())
    return emitOpError() << "must be in an ebpf.program or an ebpf.func";
  Block &body = getBody().front();
  if (body.getNumArguments() != getInits().size() + 2 || body.getArgument(0).getType() != map.getKeyType() ||
      body.getArgument(1).getType() != BorrowedType::get(getContext(), map.getValueType()))
    return emitOpError() << "the body must take the key (" << map.getKeyType() << "), the value (!ebpf.borrowed<" << map.getValueType()
                         << ">) and the loop-carried values";
  for (auto [a, t] : llvm::zip(body.getArguments().drop_front(2), getInits().getTypes()))
    if (a.getType() != t)
      return emitOpError() << "body argument type " << a.getType() << " does not match the loop-carried value type " << t;
  auto y = dyn_cast<MapForEachYieldOp>(body.getTerminator());
  if (!y || TypeRange(y.getValues().getTypes()) != TypeRange(getInits().getTypes()))
    return emitOpError() << "the body must end with ebpf.map.for_each.yield of the loop-carried types";
  for (Operation *user : body.getArgument(1).getUsers())
    if (!isa<RefLoadOp, RefStoreOp, RefAtomicAddOp, RefFieldLoadOp, RefFieldStoreOp, RefFieldAtomicAddOp>(user))
      return emitOpError() << "the value may only be read or written by ebpf.ref.{load,store,atomic_add} / ebpf.ref.field.*, but it is used by '"
                           << user->getName() << "'";
  Region *self = &getBody();
  WalkResult w = getBody().walk([&](Operation *op) {
    if (isa<LoopOp, CallOp, BreakOp, ContinueOp, MapForEachOp>(op) || (!isa<MapForEachYieldOp>(op) && !allowedInLoop(op))) {
      op->emitOpError() << "is not allowed inside ebpf.map.for_each (the loop-body ops without ebpf.loop / ebpf.call / ebpf.break / "
                           "ebpf.continue — a compiler restriction)";
      return WalkResult::interrupt();
    }
    for (Value v : op->getOperands()) {
      if (self->isAncestor(v.getParentRegion()))
        continue;
      if (isa<IntegerType, MapType>(v.getType()))
        continue;
      op->emitOpError() << "captures " << v.getType()
                        << " into ebpf.map.for_each; only integers and map handles can be passed to the callback";
      return WalkResult::interrupt();
    }
    return WalkResult::advance();
  });
  return failure(w.wasInterrupted());
}

// Structured if, break and continue.
namespace {
bool isLoopEscape(Operation *op) { return isa<BreakOp, ContinueOp>(op); }

// Arm terminator, or null for an empty block.
Operation *armEnd(Region &r) {
  if (r.empty() || r.front().empty())
    return nullptr;
  return &r.front().back();
}

// break/continue target the nearest loop across only if/ref.check/scf.if.
// Ring-buffer operations are forbidden inside loops, so reservation-region
// escapes cannot occur here.
LogicalResult verifyLoopEscape(Operation *op, ValueRange vals) {
  Operation *p = op->getParentOp();
  while (p && (isa<IfOp, RefCheckOp>(p) || p->getName().getStringRef() == "scf.if"))
    p = p->getParentOp();
  auto loop = dyn_cast_or_null<LoopOp>(p);
  if (!loop)
    return op->emitOpError()
           << "must be inside ebpf.loop (only ebpf.if / ebpf.ref.check / scf.if may lie "
              "between it and the loop it leaves)";
  if (TypeRange(vals.getTypes()) != TypeRange(loop.getInits().getTypes()))
    return op->emitOpError() << "must carry the loop-carried values of the nearest ebpf.loop ("
                             << loop.getInits().getTypes() << "), got (" << vals.getTypes() << ")";
  return success();
}
} // namespace

LogicalResult IfOp::verify() {
  if (failed(verifyRegionResultWidths(*this)))
    return failure();
  bool joins = false;
  for (Region *r : {&getThenRegion(), &getElseRegion()}) {
    if (r->front().getNumArguments() != 0)
      return emitOpError() << "an arm takes no arguments";
    Operation *t = armEnd(*r);
    if (t && isa<IfYieldOp>(t))
      joins = true;
    else if (!t || !isLoopEscape(t))
      return emitOpError() << "an arm must end with ebpf.if.yield, ebpf.break or ebpf.continue";
  }
  if (!joins && getNumResults() != 0)
    return emitOpError() << "cannot have results when both arms leave the loop (no edge "
                            "reaches the join)";
  return success();
}

LogicalResult IfYieldOp::verify() {
  auto parent = cast<IfOp>((*this)->getParentOp());
  if (getValues().getTypes() != parent.getResultTypes())
    return emitOpError() << "yielded types do not match the results of the enclosing ebpf.if";
  return success();
}

LogicalResult BreakOp::verify() { return verifyLoopEscape(*this, getValues()); }
LogicalResult ContinueOp::verify() { return verifyLoopEscape(*this, getValues()); }

// Expanded helper loops: loop_callback, callback.return and bpf_loop.
// Entry prefixes are one IV for bpf_loop, or key/value for for_each.
static int64_t callbackLead(LoopCallbackOp cb) { return cb.getForEach() ? 2 : 1; }

LogicalResult LoopCallbackOp::verify() {
  if (getBody().empty())
    return emitOpError() << "has no body";
  Block &entry = getBody().front();
  int64_t nc = getNumCarried(), ncap = getNumCaptured(), lead = callbackLead(*this);
  size_t nmaps = getMapSymbols().size();
  if (nc < 0 || ncap < 0 || (int64_t)entry.getNumArguments() != lead + nc + ncap + (int64_t)nmaps)
    return emitOpError() << "entry block must take " << (getForEach() ? "the key and the value" : "the induction variable") << ", " << nc
                         << " loop-carried value(s), " << ncap << " captured integer(s) and "
                         << nmaps << " map(s)";
  if (getForEach()) {
    if (!isa<IntegerType>(entry.getArgument(0).getType()) || !isa<BorrowedType>(entry.getArgument(1).getType()))
      return emitOpError() << "a for_each callback takes the key (an integer) and the value (!ebpf.borrowed<...>) first";
  } else if (!entry.getArgument(0).getType().isSignlessInteger(32))
    return emitOpError() << "the induction variable must be i32";
  for (int64_t i = lead; i < lead + nc + ncap; ++i)
    if (!isa<IntegerType>(entry.getArgument(i).getType()))
      return emitOpError() << "argument #" << i << " must be an integer (a context slot)";
  for (auto [i, a] : llvm::enumerate(getMapSymbols())) {
    if (!isa<FlatSymbolRefAttr>(a))
      return emitOpError() << "map_symbols must be symbol references";
    if (!isa<MapType>(entry.getArgument(lead + nc + ncap + i).getType()))
      return emitOpError() << "argument #" << (lead + nc + ncap + i) << " must be a map";
  }
  return success();
}

LogicalResult CallbackReturnOp::verify() {
  auto cb = cast<LoopCallbackOp>((*this)->getParentOp());
  if (getStop() != 0 && getStop() != 1)
    return emitOpError() << "returns " << getStop() << "; a bpf_loop callback returns 0 or 1";
  Block &entry = cb.getBody().front();
  int64_t nc = cb.getNumCarried();
  if ((int64_t)getValues().size() != nc)
    return emitOpError() << "must write back " << nc << " loop-carried value(s)";
  for (auto [v, a] : llvm::zip(getValues(), entry.getArguments().slice(callbackLead(cb), nc)))
    if (v.getType() != a.getType())
      return emitOpError() << "writes back " << v.getType() << " into a slot of " << a.getType();
  return success();
}

// for_each requires a marked loop_callback with map-matching key/value
// arguments and matching carried/captured argument counts and types.
LogicalResult ForEachMapElemOp::verify() {
  if (TypeRange(getInits().getTypes()) != TypeRange(getResults().getTypes()))
    return emitOpError() << "results must be the count followed by the types of the loop-carried values";
  auto cb = SymbolTable::lookupNearestSymbolFrom<LoopCallbackOp>(*this, getCallbackAttr());
  if (!cb || !cb.getForEach())
    return emitOpError() << "does not name an ebpf.loop_callback with for_each";
  Block &entry = cb.getBody().front();
  auto map = cast<MapType>(getMap().getType());
  auto val = dyn_cast<BorrowedType>(entry.getArgument(1).getType());
  if (entry.getArgument(0).getType() != map.getKeyType() || !val || val.getPointee() != map.getValueType())
    return emitOpError() << "the callback's key / value arguments do not match " << getMap().getType();
  int64_t nc = cb.getNumCarried(), ncap = cb.getNumCaptured();
  if ((int64_t)getInits().size() != nc || (int64_t)getCaptures().size() != ncap)
    return emitOpError() << "passes " << getInits().size() << " loop-carried value(s) and " << getCaptures().size()
                         << " capture(s); the callback takes " << nc << " and " << ncap;
  for (auto [v, a] : llvm::zip(getInits(), entry.getArguments().slice(2, nc)))
    if (v.getType() != a.getType())
      return emitOpError() << "loop-carried value type " << v.getType() << " does not match " << a.getType();
  for (auto [v, a] : llvm::zip(getCaptures(), entry.getArguments().slice(2 + nc, ncap)))
    if (v.getType() != a.getType())
      return emitOpError() << "capture type " << v.getType() << " does not match " << a.getType();
  return success();
}

LogicalResult BpfLoopOp::verify() {
  if (TypeRange(getInits().getTypes()) != TypeRange(getResults().getTypes()))
    return emitOpError() << "results must have the types of the loop-carried values";
  auto cb = SymbolTable::lookupNearestSymbolFrom<LoopCallbackOp>(*this, getCallbackAttr());
  if (!cb || cb.getForEach())
    return emitOpError() << "does not name an ebpf.loop_callback";
  Block &entry = cb.getBody().front();
  int64_t nc = cb.getNumCarried(), ncap = cb.getNumCaptured();
  if ((int64_t)getInits().size() != nc || (int64_t)getCaptures().size() != ncap)
    return emitOpError() << "passes " << getInits().size() << " loop-carried value(s) and "
                         << getCaptures().size() << " capture(s); the callback takes " << nc
                         << " and " << ncap;
  for (auto [v, a] : llvm::zip(getInits(), entry.getArguments().slice(1, nc)))
    if (v.getType() != a.getType())
      return emitOpError() << "loop-carried value type " << v.getType() << " does not match "
                           << a.getType();
  for (auto [v, a] : llvm::zip(getCaptures(), entry.getArguments().slice(1 + nc, ncap)))
    if (v.getType() != a.getType())
      return emitOpError() << "capture type " << v.getType() << " does not match " << a.getType();
  return success();
}

// Record construction.
LogicalResult RecordMakeOp::verify() {
  if (getFields().size() != getValues().size())
    return emitOpError() << "names " << getFields().size() << " field(s) but gives "
                         << getValues().size() << " value(s)";
  llvm::StringSet<> seen;
  for (Attribute a : getFields())
    if (!seen.insert(cast<StringAttr>(a).getValue()).second)
      return emitOpError() << "gives field \"" << cast<StringAttr>(a).getValue() << "\" twice";
  // Record SSA values carry helper byte payloads, never block/yield/call/loop
  // state or arbitrary other uses.
  for (OpOperand &use : getResult().getUses()) {
    Operation *user = use.getOwner();
    if (auto up = dyn_cast<MapUpdateOp>(user); up && (up.getValue() == getResult() || up.getKey() == getResult()))
      continue;
    // Hash record keys, including delete keys.
    if (auto lk = dyn_cast<MapLookupOp>(user); lk && lk.getKey() == getResult())
      continue;
    if (auto dl = dyn_cast<MapDeleteOp>(user); dl && dl.getKey() == getResult())
      continue;
    // Result-bearing update/delete keys and values.
    if (auto tu = dyn_cast<MapTryUpdateOp>(user); tu && (tu.getKey() == getResult() || tu.getValue() == getResult()))
      continue;
    if (auto td = dyn_cast<MapTryDeleteOp>(user); td && td.getKey() == getResult())
      continue;
    // Whole-record copy into ring reservations.
    if (auto sr = dyn_cast<RingbufStoreRecordOp>(user); sr && sr.getValue() == getResult())
      continue;
    // perf_event_output full-byte stack payload.
    if (auto po = dyn_cast<PerfOutputOp>(user); po && po.getRecord() == getResult())
      continue;
    // seq_write full-byte stack payload.
    if (auto sw = dyn_cast<SeqWriteOp>(user); sw && sw.getRecord() == getResult())
      continue;
    // ringbuf_output payload, same shape.
    if (auto ro = dyn_cast<RingbufOutputOp>(user); ro && ro.getRecord() == getResult())
      continue;
    // seg6_store_bytes data and seg6_action parameters, as full-byte stack records.
    if (auto sb = dyn_cast<LwtSeg6StoreBytesOp>(user); sb && sb.getRecord() == getResult())
      continue;
    if (auto sa = dyn_cast<LwtSeg6ActionOp>(user); sa && sa.getParam() == getResult())
      continue;
    // sys.bpf attr payload with the SysBpfOp verifier size bound.
    if (auto sb = dyn_cast<SysBpfOp>(user); sb && sb.getAttr() == getResult())
      continue;
    return user->emitOpError() << "uses a record built by ebpf.record.make; a record value may only "
                                  "be the value of ebpf.map.update / try_update, ebpf.ringbuf.store_record, ebpf.perf.output, ebpf.seq.write, ebpf.ringbuf.output, "
                                  "ebpf.lwt.seg6_store_bytes, ebpf.lwt.seg6_action or ebpf.sys.bpf, or "
                                  "the key of ebpf.map.lookup / update / delete / try_update / try_delete";
  }
  return success();
}
