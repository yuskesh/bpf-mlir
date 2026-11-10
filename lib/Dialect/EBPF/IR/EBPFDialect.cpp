//===- EBPFDialect.cpp - dialect registration and operation verification -----===//
//
// Custom verification covers constraints not expressible with standard
// dialects; schema and cross-stage checks remain in their owning passes.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"
#include "bpf-mlir/Dialect/BPFABI/KernelABI.h"
#include "bpf-mlir/Support/DPathTargets.h"
#include "bpf-mlir/Support/KernelFieldPath.h"
#include "bpf-mlir/Support/KeylessMaps.h"
#include "bpf-mlir/Support/LocalStorage.h"
#include "bpf-mlir/Support/LoopBudget.h"
#include "bpf-mlir/Support/LoweringOnlyKfuncs.h"
#include "bpf-mlir/Support/ProgramKinds.h"
#include "bpf-mlir/Support/RejectedMapKinds.h"
#include "bpf-mlir/Support/ScxContract.h"
#include "bpf-mlir/Support/TraceFormat.h"
#include "bpf-mlir/Support/Usdt.h"

#include "mlir/IR/Builders.h"
#include "mlir/IR/BuiltinOps.h"
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

// an ebpf.timer.callback whose owners (the programs whose
// set_callback names it) are all sched_ext_ops programs (struct_ops). Its body
// is a top like an ebpf.func body: the ops whose acceptance depends on the
// context (kfunc.call, the iterators, rcu.region, the kptr ops) close inside
// it, and their kind, program type, sleepable and RCU rules are checked per
// owner context by ebpf-verify-call-contexts / ebpf-verify-schema.
static bool scxOwnedTimerCallback(Operation *op);
// A top of the context-dependent ops: an ebpf.program, an ebpf.func or such a
// callback.
static bool isOpsTop(Operation *op) { return isa<ProgramOp, SubprogramOp>(op) || scxOwnedTimerCallback(op); }

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
// kfield.ptr's base is a kptr (as before, printed stripped) or a nonnull kref (printed in full). Any other type
// keeps the parse error the single-constraint form gave (e603-scx-b1 N14).
static ParseResult parseKFieldPtrBase(OpAsmParser &parser, Type &t) {
  llvm::SMLoc loc = parser.getCurrentLocation();
  Type full;
  OptionalParseResult r = parser.parseOptionalType(full);
  if (r.has_value()) {
    if (failed(*r))
      return failure();
    if (!isa<KPtrType, KRefType>(full))
      return parser.emitError(loc) << "invalid kind of type specified: expected ebpf.kptr, but found " << full;
    t = full;
    return success();
  }
  t = KPtrType::parse(parser);
  return success(static_cast<bool>(t));
}
static void printKFieldPtrBase(OpAsmPrinter &p, Operation *, Type t) {
  if (auto k = dyn_cast<KPtrType>(t))
    p.printStrippedAttrOrType(k);
  else
    p << t;
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
              RingbufDiscardOp, RingbufStoreFieldOp, RingbufStoreRecordOp, TaskCommOp, CtxStackOp, KernelDPathOp, StrSnprintfOp, UserReadStrOp, UserCopyOp, UserCopyTaskOp, UserReadOp, KernelReadStrOp,
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

// ops that exist only for a particular attach row (kind × FLAGS), looked up
// by tag. The kind's OPS column cannot express this: the ordinary fentry/{} row
// must not get them. Today only the sleepable fentry row has a tag.
static bool attachAllows(ProgramOp prog, StringRef tag) {
  struct Row {
    StringLiteral kind, flags;
    ArrayRef<StringLiteral> tags;
  };
  static constexpr StringLiteral kSleepableFentryTags[] = {"user.copy", "user.addr", "user.copy_task"};
  static constexpr Row kRows[] = {{"fentry", "sleepable", kSleepableFentryTags}};
  for (const Row &r : kRows)
    if (prog.getKind() == r.kind && prog.getAttachFlags() == r.flags && llvm::is_contained(r.tags, tag))
      return true;
  return false;
}

// the closed whitelist of operations a sleepable fentry body may contain
// (stage ① names; stage-② internal operations and cf are what ebpf-expand-regions
// makes of them). Everything else is refused by name: sleepable changes what the
// verifier allows (RCU, kptr references, helpers), so an op that was validated
// for an ordinary fentry is not assumed valid here. The list is the set the
// cells use; extend it only with a measured reason.
static bool sleepableFentryAllowsOp(Operation *op) {
  if (isa<Stage2InternalOp>(op))
    return true;
  StringRef dialect = op->getName().getDialectNamespace();
  if (dialect == "arith" || dialect == "cf")
    return true;
  // the only kfuncs of a sleepable fentry body (the task of user.copy_task).
  if (auto call = dyn_cast<KfuncCallOp>(op))
    return call.getCallee() == "bpf_task_from_pid" || call.getCallee() == "bpf_task_release";
  static const char *const kNames[] = {"ebpf.user.copy_task",    "ebpf.task.current_btf",  "ebpf.kref.check",         "ebpf.user.copy",         "ebpf.user.addr",         "ebpf.global.load",        "ebpf.record.make",
                                       "ebpf.ringbuf.reserve",   "ebpf.ringbuf.if_reserved", "ebpf.ringbuf.store_record", "ebpf.ringbuf.store_field",
                                       "ebpf.ringbuf.submit",    "ebpf.ringbuf.discard",   "ebpf.verdict",            "ebpf.yield"};
  return llvm::is_contained(kNames, op->getName().getStringRef());
}

// The body of a sleepable fentry: only whitelisted operations, no user_addr
// block argument, no nested function/callback/loop (the leak routes of).
static LogicalResult verifySleepableFentryBody(ProgramOp prog) {
  bool bad = false;
  prog.getBody().walk([&](Operation *op) {
    if (!sleepableFentryAllowsOp(op)) {
      bad = true;
      op->emitOpError() << "is not allowed in a sleepable fentry program (the `fentry` x `sleepable` attach row admits only "
                           "ebpf.user.copy, ebpf.user.copy_task, ebpf.user.addr, ebpf.task.current_btf, ebpf.kref.check, ebpf.kfunc.call of bpf_task_from_pid / bpf_task_release, ebpf.global.load, ebpf.record.make, ebpf.ringbuf.{reserve,if_reserved,store_record,store_field,submit,discard}, "
                           "ebpf.verdict, ebpf.yield and arith)";
      return WalkResult::interrupt();
    }
    for (Region &region : op->getRegions())
      for (Block &block : region)
        for (BlockArgument arg : block.getArguments())
          if (isa<UserAddrType>(arg.getType())) {
            bad = true;
            op->emitOpError() << "a !ebpf.user_addr cannot be a block argument";
            return WalkResult::interrupt();
          }
    return WalkResult::advance();
  });
  return failure(bad);
}

// The placement shared by ebpf.user.addr and ebpf.user.copy: directly in the
// body of a fentry program written `sleepable` (not in a func, callback or loop).
static LogicalResult verifySleepableFentryPlacement(Operation *op, StringRef tag) {
  auto prog = op->getParentOfType<ProgramOp>();
  if (!prog || !attachAllows(prog, tag))
    return op->emitOpError() << "is only for a `fentry` program written `sleepable` (attach row FLAGS sleepable); an ordinary fentry/<function> program cannot sleep, so the helper is refused there";
  for (Operation *p = op->getParentOp(); p && p != prog.getOperation(); p = p->getParentOp())
    if (isa<SubprogramOp, LoopCallbackOp, TimerCallbackOp, UserRingbufCallbackOp, LoopOp, MapForEachOp, BpfLoopOp>(p))
      return op->emitOpError() << "is not supported inside a func, callback or loop (the sleepable context is not carried into them)";
  return success();
}

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
  if (getSleepable() && !bpfmlir::lookupProgramAttach(*info, getAttachValue(), getAttachFlags()))
    return emitOpError() << "`sleepable` is not available for a " << getKind() << " program with this attach (ProgramAttaches.def has no sleepable row for it)";
  if (explicitEmpty || !bpfmlir::lookupProgramAttach(*info, getAttachValue(), getAttachFlags())) {
    // Enumerated attachment suggestions in diagnostic order.
    auto valuesText = [&] {
      auto vals = bpfmlir::attachDiagnosticValuesOf(*info, getAttachValue());
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
      return emitOpError() << "a " << getKind() << " program needs " << valuesText()
                           << (getAttachValue().starts_with("netkit_") ? " (the netkit direction)" : " (the tcx direction)");
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

  if (getSleepable() && failed(verifySleepableFentryBody(*this)))
    return failure();
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
  // arena memory is addressed through its window base, not by key.
  if (map.getKind() == "arena")
    return op->emitOpError() << "an arena map has no key/value; it is only used by ebpf.arena.base (the program's window on the arena memory)";
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
// the checked reference may come from sock.map_lookup or sock.lookup_*, so
// sock.ref_check / sock.release are allowed in a kind holding either OPS token.
// Each acquiring op still checks its own token (sched_cls has no sock.map_lookup).
static LogicalResult checkSockRefScope(Operation *op) {
  auto holds = [](const bpfmlir::ProgramKindInfo &k) {
    return bpfmlir::kindAllows(k, "sock.map_lookup") || bpfmlir::kindAllows(k, "sock.lookup");
  };
  auto p = op->getParentOfType<ProgramOp>();
  const bpfmlir::ProgramKindInfo *k = p ? bpfmlir::lookupProgramKind(p.getKind()) : nullptr;
  if (!k || !holds(*k))
    return op->emitOpError() << "is only for " << bpfmlir::joinProgramKinds(holds, "", ", ", " and ") << " programs";
  for (Operation *a = op->getParentOp(); a != p; a = a->getParentOp())
    if (!isa<IfOp, SockRefCheckOp>(a))
      return op->emitOpError() << "is only in the program body or ebpf.if / ebpf.sock.ref_check";
  return success();
}
// An acquired nullable socket is only checked (② is_present / assume_present).
static LogicalResult checkAcquiredSockUses(Value result) {
  bool stage2 = llvm::any_of(result.getUsers(), [](Operation *u) { return isa<IsPresentOp, AssumePresentOp>(u); });
  for (Operation *u : result.getUsers())
    if (stage2 ? !isa<IsPresentOp, AssumePresentOp>(u) : !isa<SockRefCheckOp>(u))
      return u->emitOpError() << "uses an unchecked socket reference; check it with ebpf.sock.ref_check first";
  return success(); // Whole-CFG ownership verification enforces exactly one check.
}
// sk_lookup_tcp / _udp on the own entry context; the tuple is a
// record.make result (the exact view is checked by ebpf-verify-records).
static LogicalResult verifySockLookup(Operation *op, Value ctx, Value tuple, Value result) {
  if (failed(checkLookupScope(op, "sock.lookup")))
    return failure();
  auto prog = op->getParentOfType<ProgramOp>();
  if (prog.getBody().empty() || prog.getBody().front().getNumArguments() == 0 ||
      ctx != prog.getBody().front().getArgument(0))
    return op->emitOpError() << "requires the entry context of its program";
  if (!tuple.getDefiningOp<RecordMakeOp>())
    return op->emitOpError("tuple must be an ebpf.record.make result (a struct bpf_sock_tuple view; map values and "
                           "borrowed records are not accepted)");
  return checkAcquiredSockUses(result);
}
LogicalResult SockLookupTcpOp::verify() { return verifySockLookup(*this, getCtx(), getTuple(), getResult()); }
LogicalResult SockLookupUdpOp::verify() { return verifySockLookup(*this, getCtx(), getTuple(), getResult()); }
LogicalResult SockSkcLookupTcpOp::verify() { return verifySockLookup(*this, getCtx(), getTuple(), getResult()); }
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
  return checkAcquiredSockUses(getResult());
}
LogicalResult SockRefCheckOp::verify() {
  if (failed(checkSockRefScope(*this)) || failed(verifyRegionResultWidths(*this)))
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
  if (failed(checkSockRefScope(*this)))
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
// a guard's i1 (ksym.exists / core.type_exists / core.field_exists) is
// only the direct condition of one ebpf.if — the verifier prunes the false
// branch only for that compare, and the requirements guard rows bind to the
// then region (requirements_format.md §9).
static LogicalResult verifyGuardUse(Operation *op, StringRef what) {
  Value r = op->getResult(0);
  if (!r.hasOneUse())
    return op->emitOpError() << "the " << what
                             << " guard must have exactly one use, the condition of an ebpf.if (write !a || !b as nested ebpf.if)";
  Operation *u = *r.getUsers().begin();
  auto ifo = dyn_cast<IfOp>(u);
  // After stage ② the ebpf.if is cf.cond_br on the same i1 (operand 0).
  bool expandedIf = u->getName().getStringRef() == "cf.cond_br" && u->getOperand(0) == r;
  if (!expandedIf && (!ifo || ifo.getCond() != r))
    return op->emitOpError() << "the " << what << " guard is used by " << u->getName()
                             << "; it may only be the condition of an ebpf.if (stores, arith, call arguments and yield are rejected)";
  return success();
}

LogicalResult KsymExistsOp::verify() { return verifyGuardUse(*this, "ksym.exists"); }

LogicalResult CoreTypeExistsOp::verify() {
  if (getStructName().empty())
    return emitOpError() << "the struct name must not be empty";
  return verifyGuardUse(*this, "core.type_exists");
}

LogicalResult CoreFieldExistsOp::verify() {
  if (getStructName().empty() || getField().empty())
    return emitOpError() << "the struct name and field must not be empty";
  return verifyGuardUse(*this, "core.field_exists");
}

// an untrusted kernel address (a per-CPU slot's pointer value, or
// a kaddr.read / kaddr.container_of result) is used only by the kaddr ops —
// never by arithmetic, stores, call arguments, yield or loop carries.
static LogicalResult verifyKAddrUses(Value v, StringRef what) {
  for (OpOperand &use : v.getUses()) {
    Operation *u = use.getOwner();
    // a bss kaddr global caches the address (the stored value only).
    if (isa<KAddrNonNullOp, KAddrEqOp, KAddrReadOp, KAddrStrncmpOp, KAddrContainerOfOp, GlobalStoreOp>(u))
      continue;
    return u->emitOpError() << "uses the untrusted !ebpf.kaddr " << what
                            << "; only ebpf.kaddr.nonnull / ebpf.kaddr.eq / ebpf.kaddr.read / ebpf.kaddr.strncmp / ebpf.kaddr.container_of may use it "
                               "(and ebpf.global.store, which caches it in a bss kaddr global)";
  }
  return success();
}

// the compiler-owned bpf_strncmp literal (a NUL-terminated .rodata value).
static LogicalResult verifyStrncmpLiteral(Operation *op, StringRef lit) {
  if (lit.empty() || lit.size() > 64)
    return op->emitOpError() << "the strncmp literal must be 1 to 64 bytes, got " << lit.size();
  if (lit.contains('\0'))
    return op->emitOpError() << "the strncmp literal must not contain NUL (the compiler appends the terminator)";
  return success();
}

// the kaddr reads / strncmp / container_of live in the body of an
// ebpf.program or a static ebpf.func (H1 — a global func is verified alone by
// the kernel, and the callback bodies are not opened). The nearest isolated
// ancestor decides.
static LogicalResult verifyKAddrPlacement(Operation *op) {
  Operation *p = op->getParentOp();
  while (p && !p->hasTrait<OpTrait::IsIsolatedFromAbove>())
    p = p->getParentOp();
  if (p && isa<ProgramOp>(p))
    return success();
  if (auto f = dyn_cast_or_null<SubprogramOp>(p)) {
    if (f.getLinkage() == "static")
      return success();
    return op->emitOpError() << "is only in the body of an ebpf.program or a static ebpf.func, not the global ebpf.func @"
                             << f.getSymName();
  }
  return op->emitOpError() << "is only in the body of an ebpf.program or a static ebpf.func, not in "
                           << (p ? p->getName().getStringRef() : StringRef("a module"));
}

// an op reading through kaddr<"S"> needs a struct S (kaddr<""> is void *).
static LogicalResult verifyKAddrBase(Operation *op, Value a) {
  if (cast<KAddrType>(a.getType()).getStructName().empty())
    return op->emitOpError() << "cannot read through !ebpf.kaddr<\"\"> (a void * — only ebpf.kaddr.nonnull / ebpf.kaddr.eq take it)";
  return success();
}

LogicalResult KAddrReadOp::verify() {
  if (failed(verifyKAddrPlacement(*this)))
    return failure();
  if (failed(verifyKAddrBase(*this, getAddr())))
    return failure();
  if (!bpfmlir::validKernelFieldPath(getField()))
    return emitOpError() << "kernel field path must have 1 to 3 identifier segments, got \"" << getField() << "\"";
  Type t = getValue().getType();
  auto it = dyn_cast<IntegerType>(t);
  if (!isa<KAddrType>(t) && !(it && llvm::is_contained({8u, 16u, 32u, 64u}, it.getWidth())))
    return emitOpError() << "reads an i8 / i16 / i32 / i64 or !ebpf.kaddr field, got " << t;
  if (isa<KAddrType>(t))
    return verifyKAddrUses(getValue(), "read result");
  return success();
}

LogicalResult KAddrStrncmpOp::verify() {
  if (failed(verifyKAddrPlacement(*this)))
    return failure();
  if (failed(verifyKAddrBase(*this, getAddr())))
    return failure();
  if (!bpfmlir::validKernelFieldPath(getField()))
    return emitOpError() << "kernel field path must have 1 to 3 identifier segments, got \"" << getField() << "\"";
  return verifyStrncmpLiteral(*this, getLiteral());
}

// D1: bpf_strncmp's arg 1 is ARG_PTR_TO_MEM | MEM_RDONLY, which takes a BTF pointer only as
// PTR_TO_BTF_ID | PTR_TRUSTED (7.3.1 helpers.c:581, verifier.c:8162-8176). The trusted origins the compiler can show:
// task.current_btf (RET_PTR_TO_BTF_ID_TRUSTED) and an ebpf.ctx.arg of a kind whose arguments the verifier trusts
// (prog_args_trusted — tp_btf (TpArgs) and struct_ops (OpsSig)), directly or through kptr.check (① the present block
// argument, ② assume_present). A field traversal (kfield.ptr — SAFE_RCU / MEM_RCU, verifier.c:5869 / :6117) stays
// untrusted after the NULL check, and other ctx.arg / ctx.field pointers are not shown trusted: rejected by name.
static LogicalResult verifyStrncmpTrusted(KFieldStrncmpOp op) {
  Value v = op.getPtr();
  Value src = v;
  if (auto ap = v.getDefiningOp<AssumePresentOp>())
    src = ap.getValue();
  else if (auto ba = dyn_cast<BlockArgument>(v))
    if (auto kc = dyn_cast_or_null<KPtrCheckOp>(ba.getOwner()->getParentOp()); kc && ba.getOwner() == &kc.getPresentRegion().front())
      src = kc.getPtr();
  if (src.getDefiningOp<TaskCurrentBtfOp>())
    return success();
  auto arg = src.getDefiningOp<CtxArgOp>();
  const bpfmlir::ProgramKindInfo *k = arg ? bpfmlir::lookupProgramKind(cast<ContextType>(arg.getCtx().getType()).getKind()) : nullptr;
  if (k && (k->sig == bpfmlir::SigFamily::TpArgs || k->sig == bpfmlir::SigFamily::OpsSig))
    return success();
  Operation *def = src.getDefiningOp();
  return op.emitOpError() << "needs a trusted pointer (bpf_strncmp takes PTR_TO_BTF_ID only with PTR_TRUSTED): the pointer must be "
                             "ebpf.task.current_btf or an ebpf.ctx.arg of a tp_btf or struct_ops program (directly or through "
                             "ebpf.kptr.check), but it comes from "
                          << (def ? "'" + def->getName().getStringRef().str() + "'" : std::string("a block argument"))
                          << (arg ? " of a kind whose arguments are not trusted" : "");
}

LogicalResult KFieldStrncmpOp::verify() {
  if (failed(verifyKAddrPlacement(*this)))
    return failure();
  if (failed(verifyStrncmpTrusted(*this)))
    return failure();
  if (!bpfmlir::validKernelFieldPath(getField()))
    return emitOpError() << "kernel field path must have 1 to 3 identifier segments, got \"" << getField() << "\"";
  if (getLen() < 1 || getLen() > 64)
    return emitOpError() << "len must be 1 to 64 (bpf_strncmp's size is ARG_CONST_SIZE, not 0), got " << getLen();
  return verifyStrncmpLiteral(*this, getLiteral());
}

LogicalResult KAddrContainerOfOp::verify() {
  if (failed(verifyKAddrPlacement(*this)))
    return failure();
  if (failed(verifyKAddrBase(*this, getAddr())))
    return failure();
  if (getStructName().empty())
    return emitOpError() << "the containing struct name must not be empty";
  if (!bpfmlir::validKernelFieldPath(getField()))
    return emitOpError() << "kernel field path must have 1 to 3 identifier segments, got \"" << getField() << "\"";
  if (cast<KAddrType>(getResult().getType()).getStructName() != getStructName())
    return emitOpError() << "the result must be !ebpf.kaddr<\"" << getStructName() << "\">, got " << getResult().getType();
  return verifyKAddrUses(getResult(), "container_of result");
}

LogicalResult KsymPerCpuLoadOp::verify() {
  if (failed(verifyRegionResultWidths(*this)))
    return failure();
  if (getPresentRegion().empty() || getAbsentRegion().empty())
    return emitOpError() << "both the present and absent regions must have a body";
  Block &present = getPresentRegion().front();
  if (present.getNumArguments() != 1)
    return emitOpError() << "the present region must take exactly one argument (the slot value), got " << present.getNumArguments();
  Type t = present.getArgument(0).getType();
  auto it = dyn_cast<IntegerType>(t);
  if (!isa<KAddrType>(t) && !(it && llvm::is_contained({8u, 16u, 32u, 64u}, it.getWidth())))
    return emitOpError() << "the present region argument must be i8 / i16 / i32 / i64 or !ebpf.kaddr<\"S\">, got " << t;
  if (isa<KAddrType>(t) && failed(verifyKAddrUses(present.getArgument(0), "slot value")))
    return failure();
  if (getAbsentRegion().front().getNumArguments() != 0)
    return emitOpError() << "the absent region must take no arguments (bpf_per_cpu_ptr returned NULL), got "
                         << getAbsentRegion().front().getNumArguments();
  for (Region *r : {&getPresentRegion(), &getAbsentRegion()})
    if (r->front().empty() || !isa<YieldOp>(r->front().back()))
      return emitOpError() << "each region must end with ebpf.yield";
  return success();
}

LogicalResult KsymPerCpuBrOp::verify() {
  Block *p = getPresent();
  if (p->getNumArguments() != 1)
    return emitOpError() << "the present successor must take exactly one argument (the slot value)";
  if (getAbsent()->getNumArguments() != 0)
    return emitOpError() << "the absent successor must take no arguments";
  return success();
}

LogicalResult KPtrCheckOp::verify() {
  if (failed(verifyRegionResultWidths(*this)))
    return failure();
  // rcu_ptr_or_null<S> checks to rcu_ptr<S> (MEM_RCU stays untrusted).
  auto rin = dyn_cast<RcuPtrOrNullType>(getPtr().getType());
  StringRef sname = rin ? rin.getStructName() : cast<KPtrOrNullType>(getPtr().getType()).getStructName();
  if (getPresentRegion().empty() || getAbsentRegion().empty())
    return emitOpError() << "both the present and absent regions must have a body";
  Block &present = getPresentRegion().front();
  if (present.getNumArguments() != 1)
    return emitOpError() << "the present region must take exactly one argument (the checked kernel pointer), got "
                         << present.getNumArguments();
  Type want = rin ? Type(RcuPtrType::get(getContext(), sname)) : Type(KPtrType::get(getContext(), sname));
  if (present.getArgument(0).getType() != want)
    return emitOpError() << "the present region argument must be !ebpf." << (rin ? "rcu_ptr" : "kptr") << "<\"" << sname << "\">, got "
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
static LogicalResult verifyOwnershipInIter(Operation *op, StringRef what);
LogicalResult KRefCheckOp::verify() {
  if (failed(verifyRegionResultWidths(*this)))
    return failure();
  if (failed(verifyOwnershipInIter(*this, "checks an acquired kernel reference")))
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
  // an arm may also end with ebpf.break / ebpf.continue (LAVD's `if (!p) continue` and
  // release-then-continue); the escape verifier admits it only for ebpf.iter.scx_dsq, and
  // ownership requires the release before it.
  int escapes = 0;
  for (Region *r : {&getPresentRegion(), &getAbsentRegion()}) {
    if (r->front().empty() || !isa<YieldOp, BreakOp, ContinueOp>(r->front().back()))
      return emitOpError() << "each region must end with ebpf.yield (ebpf.break / ebpf.continue inside ebpf.iter.scx_dsq)";
    escapes += isa<BreakOp, ContinueOp>(r->front().back());
  }
  if (escapes == 2 && getNumResults() != 0)
    return emitOpError() << "cannot have results when both regions leave the iteration (no edge reaches the join)";
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
  if (s == "void" || s == "bool") // a bool result is i1 (③ reads the low byte, like session.is_return).
    return ret;
  if (kfuncIntBits(s))
    return true;
  std::optional<StringRef> st = kfuncStructOf(s);
  return st && *st != "void" && !kfuncIntBits(*st);
}

// Uses of a present kernel reference (a kref.check block argument, or a
// non-NULL acquire result of kfunc.call): kfunc arguments, the pointer of
// kfield.load / kptr.addr, or the new reference of kptr.xchg.
static LogicalResult verifyKRefValueUses(Value v) {
  for (OpOperand &use : v.getUses()) {
    Operation *u = use.getOwner();
    // scx.task_cpu (KF_RCU) and kfield.ptr read through the kref without consuming it.
    if (isa<KfuncCallOp>(u) || (isa<KFieldLoadOp, KPtrAddrOp, KFieldPtrOp, ScxTaskCpuOp>(u) && use.getOperandNumber() == 0))
      continue;
    if (isa<UserCopyTaskOp>(u) && use.getOperandNumber() == 2) // the task operand reads through the kref without consuming it.
      continue;
    if (auto x = dyn_cast<KPtrXchgOp>(u); x && x.getNewRef() == v) // Transferring to a map consumes ownership.
      continue;
    if (auto x = dyn_cast<GlobalKPtrXchgOp>(u); x && x.getNewRef() == v) // transferring to a kptr global too.
      continue;
    return u->emitOpError() << "uses the kernel reference " << v.getType()
                            << "; a kref may only be an argument of ebpf.kfunc.call, the pointer of ebpf.kfield.load or the new "
                               "reference of ebpf.kptr.xchg (it must not be yielded, passed to ebpf.call or captured)";
  }
  return success();
}

// The one mark that a nullable result has been through ② (its null check
// expanded into ebpf.is_present / ebpf.assume_present): VerifyStructured owns
// its uses then, and the ① shape checks (one check use, and for the RCU kptr
// reads the sleepable section) are not repeated on the expanded form.
static bool expandedNullCheck(Value r) {
  return llvm::any_of(r.getUsers(), [](Operation *u) { return isa<IsPresentOp, AssumePresentOp>(u); });
}

LogicalResult KfuncCallOp::verify() {
  const bpfabi::KfuncABI *k = bpfabi::lookupKfunc(getCallee());
  if (!k)
    return emitOpError() << "calls \"" << getCallee() << "\", which is not in the kfunc table (UAPI table kfunc rows: "
                         << bpfabi::listKfuncs(/*genericCandidates=*/true) << ")";
  // sched_ext kfuncs have their own ops (callback allow table, family);
  // the generic call would bypass that contract.
  if (const bpfmlir::ScxKfuncInfo *scx = bpfmlir::lookupScxKfunc(getCallee()))
    return emitOpError() << "kfunc \"" << getCallee() << "\" is a sched_ext kfunc; call it through ebpf.scx." << scx->op;
  // kfunc rows only an op's lowering emits (LoweringOnlyKfuncs.def).
  if (const bpfmlir::LoweringKfuncInfo *lo = bpfmlir::lookupLoweringOnlyKfunc(getCallee()))
    return emitOpError() << "kfunc \"" << getCallee() << "\" is emitted only by the lowering of " << lo->owner << "; write "
                         << lo->owner << " instead of calling it directly";
  // a void * followed by its __sz length is a memory region
  // (bpf_cpumask_populate); the generic call does not model memory arguments.
  {
    auto ps = k->paramList();
    for (size_t i = 0; i + 1 < ps.size(); ++i)
      if (StringRef(ps[i].second) == "*void" && StringRef(ps[i + 1].first).ends_with("__sz"))
        return emitOpError() << "kfunc \"" << getCallee() << "\" takes a memory region (" << ps[i].first << ", " << ps[i + 1].first
                             << "); the generic ebpf.kfunc.call does not model memory arguments";
  }
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
    // KF_IMPLICIT_ARGS (7.1.8 / 7.3.1 scx_bpf_task_cgroup) — the kernel
    // fills the trailing aux argument; the table's params already omit it (the
    // kfunc-normalized row, the BTF FUNC_PROTO the BPF side calls), as for
    // ebpf.scx.* lowering. Nothing else to model.
    for (StringRef f : fs)
      if (f != "acquire" && f != "release" && f != "ret_null" && f != "rcu" && f != "implicit_args")
        return emitOpError() << "kfunc \"" << getCallee() << "\" has the flag KF_" << f.upper()
                             << ", which the compiler does not model";
  }
  bool acquire = k->hasFlag("acquire"), release = k->hasFlag("release"), retNull = k->hasFlag("ret_null");
  if ((acquire || release) && failed(verifyOwnershipInIter(*this, release ? "releases a kernel reference" : "acquires a kernel reference")))
    return failure();
  // Require program or function bodies; ownership does not traverse arbitrary
  // regions or callbacks. in an ebpf.func the ownership closes in the
  // function (ebpf-verify-ownership walks it); the program type and the regions
  // of the callers' call sites are checked per reaching context by
  // ebpf-verify-call-contexts.
  Operation *top = *this;
  for (Operation *p = (*this)->getParentOp(); p; p = p->getParentOp()) {
    if (isOpsTop(p)) { // a sched_ext_ops owner's timer callback too (per owner context).
      top = p;
      break;
    }
    if (isa<LoopOp, MapForEachOp, SpinRegionOp>(p) || p->getName().getStringRef() == "scf.if")
      return emitOpError() << "calls a kfunc inside '" << p->getName()
                           << "'; kfunc calls are only allowed in the body of an ebpf.program outside loops, map.for_each, "
                              "spin.region and scf.if (the ownership check does not follow them)";
    top = p;
  }
  if (auto cb = dyn_cast<TimerCallbackOp>(top)) {
    // a callback has no task argument in current->scx.kf_tasks.
    if (getCallee() == bpfmlir::kScxTaskCgroupKfunc)
      return emitOpError() << "calls " << getCallee() << " in ebpf.timer.callback @" << cb.getSymName()
                           << "; the compiler allows it only in the body of a " << bpfmlir::kScxOpsType
                           << " member program, on a task argument the kernel puts in current->scx.kf_tasks (a callback has no such "
                              "argument)";
  } else if (auto fn = dyn_cast<SubprogramOp>(top)) {
    // kf_tasks position is a task argument of the member (ctx.arg); a
    // function has no such argument.
    if (getCallee() == bpfmlir::kScxTaskCgroupKfunc)
      return emitOpError() << "calls " << getCallee() << " in ebpf.func @" << fn.getSymName() << "; the compiler allows it only in the body of a "
                           << bpfmlir::kScxOpsType
                           << " member program, on a task argument the kernel puts in current->scx.kf_tasks (a function has no such "
                              "argument)";
  } else {
    auto prog = dyn_cast<ProgramOp>(top);
    if (!prog)
      return emitOpError() << "calls a kfunc outside an ebpf.program and an ebpf.func (callbacks cannot call kfuncs)";
    StringRef ptype = programTypeOf(prog.getKind());
    if (!k->allowsProgType(ptype))
      return emitOpError() << "kfunc \"" << getCallee() << "\" is not registered for program type " << ptype << " (kind \""
                           << prog.getKind() << "\"); the kfunc table allows " << k->progTypes << "";
    // scx_bpf_task_cgroup is
    // registered for struct_ops / tracing / syscall, but its task must be in
    // current->scx.kf_tasks — set only while a sched_ext_ops member runs. Outside
    // struct_ops no task can be (scx_error at run time); ebpf-verify-schema checks
    // the member and position for struct_ops.
    if (getCallee() == bpfmlir::kScxTaskCgroupKfunc && ptype != "struct_ops")
      return emitOpError() << "calls " << getCallee() << " in a program of type " << ptype << " (kind \"" << prog.getKind()
                           << "\"); the compiler allows it only in a " << bpfmlir::kScxOpsType
                           << " member, on a task argument the kernel puts in current->scx.kf_tasks (the kernel fails the scheduler "
                              "with scx_error on any other task)";
  }
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
    // an embedded cpumask (ref.field.addr) is map-value memory the kernel
    // checks as a fixed-size argument of its sizeof(struct bpf_cpumask) — for
    // *bpf_cpumask and *cpumask (offset-0 member) arguments of kfuncs that
    // neither acquire nor release (those take referenced kptrs).
    if (isa<CpumaskMemType>(got)) {
      if (s != "bpf_cpumask" && s != "cpumask")
        return emitOpError() << "kfunc \"" << getCallee() << "\" argument " << i << " (" << pname << ") is a pointer to struct " << s
                             << "; an embedded cpumask (" << got << ") is only a *bpf_cpumask / *cpumask argument";
      if (acquire)
        return emitOpError() << "kfunc \"" << getCallee() << "\" acquires a reference; an embedded cpumask (" << got
                             << ") is not a referenced object — pass it only to kfuncs that neither acquire nor release";
      continue;
    }
    // a checked RCU pointer is an argument of a KF_RCU kfunc only (the
    // verifier: "must be referenced or trusted" / "must be a rcu pointer").
    bool rcuArg = isa<RcuPtrType>(got);
    StringRef have = isa<KRefType>(got)   ? cast<KRefType>(got).getStructName()
                     : isa<KPtrType>(got) ? cast<KPtrType>(got).getStructName()
                     : rcuArg             ? cast<RcuPtrType>(got).getStructName()
                                          : StringRef();
    // the verifier walks to the offset-0 member for a non-strict argument
    // (UAPI firstmember rows); acquire (6.6) and release arguments are strict.
    bool viaFirst = !acquire && !release && !have.empty() && have != s && bpfabi::isFirstMemberOf(have, s);
    if ((have != s && !viaFirst) || have.empty())
      return emitOpError() << "kfunc \"" << getCallee() << "\" argument " << i << " (" << pname << ") is a pointer to struct " << s
                           << "; pass !ebpf.kref<\"" << s << "\"> or !ebpf.kptr<\"" << s << "\">, got " << got;
    if (rcuArg && !k->hasFlag("rcu"))
      return emitOpError() << "kfunc \"" << getCallee() << "\" is not KF_RCU; argument " << i << " (" << pname << ") is the RCU pointer "
                           << got << ", which only a KF_RCU kfunc takes (pass an acquired !ebpf.kref<\"" << have << "\">)";
  }
  if (release && released != 1)
    return emitOpError() << "kfunc \"" << getCallee() << "\" is a KF_RELEASE kfunc with " << released
                         << " struct pointer arguments; the compiler models exactly one released reference";
  // Results.
  StringRef ret = k->ret;
  if (ret == "void") {
    if (getNumResults() != 0)
      return emitOpError() << "kfunc \"" << getCallee() << "\" returns void, got " << getNumResults() << " result(s)";
  } else if (ret == "bool") {
    if (getNumResults() != 1 || !getResult(0).getType().isInteger(1))
      return emitOpError() << "kfunc \"" << getCallee() << "\" returns bool (one i1 result)";
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
    bool stage2 = expandedNullCheck(r);
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
    // a non-NULL acquire result (bpf_cpumask_acquire,
    // scx_bpf_get_online_cpumask) is a present reference from the start.
    if (isa<KRefType>(r.getType()) && failed(verifyKRefValueUses(r)))
      return failure();
  }
  return success();
}

// Present krefs permit kfunc arguments and supported kernel-field operations.
static LogicalResult verifyKRefUses(KRefCheckOp kc) { return verifyKRefValueUses(kc.getPresentRegion().front().getArgument(0)); }

static LogicalResult verifyKPtrXchgShape(Operation *op, Value r, StringRef opName, StringRef from);
static LogicalResult verifyKPtrLoadRcuShape(Operation *op, Value r, StringRef opName, StringRef what, StringRef from);

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
  return verifyKPtrXchgShape(*this, getOld(), "ebpf.kptr.xchg", "the map value");
}

// global.kptr_xchg shares kptr.xchg's placement and result rules; the
// schema (ebpf-verify-schema) owns the global's section and struct.
LogicalResult GlobalKPtrXchgOp::verify() {
  StringRef t = cast<KRefOrNullType>(getOld().getType()).getStructName();
  if (t != "bpf_cpumask")
    return emitOpError() << "exchanges a kptr global to struct " << t
                         << "; the compiler supports kptr globals only for bpf_cpumask";
  if (Value n = getNewRef()) {
    auto kr = cast<KRefType>(n.getType());
    if (kr.getStructName() != t)
      return emitOpError() << "puts a !ebpf.kref<\"" << kr.getStructName() << "\"> into a global whose result is "
                           << getOld().getType() << "; the struct must be the same";
  }
  return verifyKPtrXchgShape(*this, getOld(), "ebpf.global.kptr_xchg", "the kptr global");
}

// Shared by kptr.xchg and global.kptr_xchg: placement in a program body
// covered by ownership traversal, and one kref.check of the removed reference.
static LogicalResult verifyKPtrXchgShape(Operation *op, Value r, StringRef opName, StringRef from) {
  // Like kfunc.call, restrict to program or function bodies covered by
  // ownership traversal (a function's callers per context —
  // ebpf-verify-call-contexts).
  Operation *top = op;
  for (Operation *p = op->getParentOp(); p; p = p->getParentOp()) {
    if (isOpsTop(p)) { // a sched_ext_ops owner's timer callback too.
      top = p;
      break;
    }
    if (isa<LoopOp, MapForEachOp, SpinRegionOp>(p) || p->getName().getStringRef() == "scf.if")
      return op->emitOpError() << "is inside '" << p->getName()
                               << "'; " << opName << " is only allowed in the body of an ebpf.program outside loops, map.for_each, "
                                  "spin.region and scf.if (the ownership check does not follow them)";
    top = p;
  }
  if (!isOpsTop(top))
    return op->emitOpError() << "is outside an ebpf.program and an ebpf.func (callbacks cannot exchange kptrs)";
  if (failed(verifyOwnershipInIter(op, "exchanges a kernel reference")))
    return failure();
  // The removed reference needs one kref.check, like acquire results; expanded
  // checks are verified by VerifyStructured.
  bool stage2 = expandedNullCheck(r);
  if (!stage2) {
    unsigned checks = 0;
    for (OpOperand &use : r.getUses()) {
      if (isa<KRefCheckOp>(use.getOwner())) {
        ++checks;
        continue;
      }
      return use.getOwner()->emitOpError() << "uses an unchecked kernel reference " << r.getType()
                                           << " taken out of " << (from == "the map value" ? "a map value" : "a kptr global")
                                           << "; check it with ebpf.kref.check first";
    }
    if (checks != 1)
      return op->emitOpError() << "the reference taken out of " << from << " " << r.getType()
                               << " must be checked exactly once by ebpf.kref.check, found " << checks
                               << " (an unchecked reference leaks)";
  }
  return success();
}

// shared by kptr.load_rcu and global.kptr_load_rcu — placement,
// the sleepable RCU section, and one kptr.check of the result.
static LogicalResult verifyKPtrLoadRcuShape(Operation *op, Value r, StringRef opName, StringRef what, StringRef from) {
  Operation *top = op;
  bool inRcu = false;
  for (Operation *p = op->getParentOp(); p; p = p->getParentOp()) {
    if (isOpsTop(p)) { // a sched_ext_ops owner's timer callback too (its RCU rule per owner context).
      top = p;
      break;
    }
    if (isa<RcuRegionOp>(p))
      inRcu = true;
    if (isa<LoopOp, MapForEachOp, SpinRegionOp>(p) || p->getName().getStringRef() == "scf.if")
      return op->emitOpError() << "is inside '" << p->getName()
                               << "'; " << opName << " is only allowed in the body of an ebpf.program outside loops, map.for_each, "
                                  "spin.region and scf.if";
    top = p;
  }
  if (!isOpsTop(top))
    return op->emitOpError() << "is outside an ebpf.program and an ebpf.func (callbacks cannot read " << what << ")";
  // After ② the region is expanded to lock / unlock calls, so the section is
  // no longer a parent; the ① check covered it (the defect).
  // in an ebpf.func the sleepable kinds are checked per reaching context
  // (ebpf-verify-call-contexts; the schema's sleepable struct_ops members:
  // ebpf-verify-schema).
  bool stage2 = expandedNullCheck(r);
  auto prog = dyn_cast<ProgramOp>(top);
  if (prog && !stage2 && !inRcu && bpfmlir::kindAllows(prog.getKind(), "sleepable"))
    return op->emitOpError() << "reads a " << (what == "kptr fields" ? "kptr field" : "kptr global") << " in a " << prog.getKind()
                             << " program, which is loaded sleepable, outside ebpf.rcu.region — the verifier marks it untrusted there "
                                "(only inside the section)";
  if (stage2)
    return success(); // ② expansion: VerifyStructured checks the paths.
  unsigned checks = 0;
  for (Operation *u : r.getUsers()) {
    if (!isa<KPtrCheckOp>(u))
      return u->emitOpError() << "uses an unchecked " << r.getType() << " read from " << from << "; check it with ebpf.kptr.check first";
    ++checks;
  }
  if (checks != 1)
    return op->emitOpError() << "the RCU pointer " << r.getType() << " must be checked exactly once by ebpf.kptr.check, found " << checks;
  return success();
}

// a kptr field read as MEM_RCU. bpf_cpumask only; one kptr.check use;
// sleepable kinds (OPS tag `sleepable`) only inside ebpf.rcu.region (struct_ops
// members declared sleepable: ebpf-verify-schema).
LogicalResult KPtrLoadRcuOp::verify() {
  auto b = dyn_cast<BorrowedType>(getRef().getType());
  if (!b || !isa<RecordType>(b.getPointee()))
    return emitOpError() << "takes a checked borrow of a map value record (!ebpf.borrowed<!ebpf.record<…>> — the block argument of "
                            "ebpf.ref.check), got "
                         << getRef().getType();
  SmallVector<StringRef> fields;
  getField().split(fields, '.', -1, true);
  if (fields.size() > 3 || getField().contains('[') || getField().contains(']') ||
      llvm::any_of(fields, [](StringRef f) { return f.empty(); }))
    return emitOpError() << "field \"" << getField()
                         << "\" must be a non-empty dotted path of at most 3 record fields, without array indices";
  StringRef s = getPtr().getType().getStructName();
  if (s != "bpf_cpumask")
    return emitOpError() << "reads a kptr to struct " << s
                         << " as an RCU pointer; the compiler supports ebpf.kptr.load_rcu only for bpf_cpumask";
  return verifyKPtrLoadRcuShape(*this, getPtr(), "ebpf.kptr.load_rcu", "kptr fields", "a map value");
}

// a kptr global read as MEM_RCU, with kptr.load_rcu's rules.
LogicalResult GlobalKPtrLoadRcuOp::verify() {
  StringRef s = getPtr().getType().getStructName();
  if (s != "bpf_cpumask")
    return emitOpError() << "reads a kptr global to struct " << s
                         << " as an RCU pointer; the compiler supports kptr globals only for bpf_cpumask";
  return verifyKPtrLoadRcuShape(*this, getPtr(), "ebpf.global.kptr_load_rcu", "kptr globals", "a kptr global");
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
    if (!isa<RefLoadOp, RefStoreOp, RefAtomicAddOp, RefFieldLoadOp, RefFieldStoreOp, RefFieldAtomicAddOp, RefFieldCmpxchgOp, RefFieldAtomicOrOp, RefFieldAddrOp, CallOp, RefIndexOp, SpinRegionOp,
             TimerInitOp, TimerSetCallbackOp, TimerStartOp, TimerCancelOp, KFieldCopyOp, TpFieldCopyOp, MapInnerOp, KPtrXchgOp, KPtrLoadRcuOp>(user)) // map.inner for validated outer-map borrows, and kptr.xchg.
      return emitOpError() << "a borrowed reference may only be consumed by "
                           << "ebpf.ref.{load,store,atomic_add} (ebpf.ref.field.{load,store} for records), ebpf.ref.index, ebpf.spin.region, "
                           << "ebpf.timer.{init,set_callback,start,cancel}, or passed to ebpf.call, but it is used by '"
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

static bool insideStreamCallback(Operation *op) {
  for (Operation *p = op->getParentOp(); p; p = p->getParentOp())
    if (isa<LoopCallbackOp, BpfLoopOp, MapForEachOp, TimerCallbackOp,
            UserRingbufCallbackOp>(p) ||
        (isa<LoopOp>(p) && cast<LoopOp>(p).getCallback()))
      return true;
  return false;
}
static LogicalResult verifyStreamContext(Operation *op, Value ctx,
                                         StringRef tag) {
  auto prog = op->getParentOfType<ProgramOp>();
  if (!prog || prog.getBody().empty() ||
      prog.getBody().front().getNumArguments() == 0 ||
      ctx != prog.getBody().front().getArgument(0) ||
      !ownerKindAllows(op, ctx, tag))
    return op->emitOpError("requires its supported program's entry context "
                           "(not a static function)");
  if (insideStreamCallback(op))
    return op->emitOpError("is not supported in a helper callback");
  return success();
}
LogicalResult SkbLoadBytesOp::verify() {
  if (failed(verifyStreamContext(*this, getCtx(), "skb.load_bytes")))
    return failure();
  if (getLen() < 1 || getLen() > 8)
    return emitOpError("length must be a constant in 1..8");
  return success();
}
LogicalResult SkbAdjustRoomOp::verify() {
  if (failed(verifyStreamContext(*this, getCtx(), "skb.adjust_room")))
    return failure();
  // sched_cls takes a room mode word (UAPI adjroommode) and stays
  // outside loops; sk_skb keeps its zero mode/flags contract and loop use.
  if (cast<ContextType>(getCtx().getType()).getKind() == "sched_cls") {
    if (getMode() != 0 || getFlags() != 0)
      return emitOpError("sched_cls selects the mode with the mode word; numeric mode and flags must be zero");
    if (getRoomMode() && !bpfabi::lookupAdjRoomMode(*getRoomMode()))
      return emitOpError() << "unknown room mode \"" << *getRoomMode() << "\" (known: \"net\", \"mac\")";
    if ((*this)->getParentOfType<LoopOp>())
      return emitOpError("in sched_cls is not allowed inside ebpf.loop (it invalidates packet windows)");
    return success();
  }
  if (getRoomMode())
    return emitOpError("the mode word is only for sched_cls");
  if (getMode() != 0 || getFlags() != 0)
    return emitOpError("sk_skb mode and flags must both be zero");
  return success();
}

// sched_cls / xdp packet helpers. Entry context of a program
// whose kind has the OPS tag, outside loops and helper callbacks.
static LogicalResult verifyWave3Op(Operation *op, Value ctx, StringRef tag) {
  auto prog = op->getParentOfType<ProgramOp>();
  if (!prog || prog.getBody().empty() ||
      prog.getBody().front().getNumArguments() == 0 ||
      ctx != prog.getBody().front().getArgument(0) ||
      !ownerKindAllows(op, ctx, tag))
    return op->emitOpError() << "requires the entry context of a " << bpfmlir::kindsAllowing(tag)
                             << " program (not a static function)";
  if (insideStreamCallback(op))
    return op->emitOpError("is not supported in a helper callback");
  if (op->getParentOfType<LoopOp>())
    return op->emitOpError("is not allowed inside ebpf.loop");
  return success();
}
LogicalResult SkbPullDataOp::verify() { return verifyWave3Op(*this, getCtx(), "skb.resize"); }
// the new helpers deliberately exclude netkit, which shares sched_cls.
static LogicalResult verifySkbDatapath(Operation *op, Value ctx, bool allowLoop = false) {
  if (failed(verifyStreamContext(op, ctx, "skb.datapath")))
    return failure();
  auto prog = op->getParentOfType<ProgramOp>();
  StringRef attach = prog.getAttach() ? *prog.getAttach() : "";
  if (attach != "ingress" && attach != "egress")
    return op->emitOpError("requires TCX ingress or egress (not netkit)");
  if (!allowLoop && op->getParentOfType<LoopOp>())
    return op->emitOpError("is not allowed inside ebpf.loop");
  return success();
}
LogicalResult SkbVlanPushOp::verify() { return verifySkbDatapath(*this, getCtx()); }
LogicalResult SkbVlanPopOp::verify() { return verifySkbDatapath(*this, getCtx()); }
LogicalResult SkbLoadBytesRelativeOp::verify() {
  if (failed(verifySkbDatapath(*this, getCtx(), true))) return failure();
  if (getLen() < 1 || getLen() > 8) return emitOpError("len must be in 1..8");
  if (!bpfabi::lookupHeaderStart(getStart())) return emitOpError("start must be mac or net");
  return success();
}
LogicalResult SkbCheckMtuOp::verify() { return verifySkbDatapath(*this, getCtx()); }
LogicalResult SkbCsumLevelOp::verify() {
  if (failed(verifySkbDatapath(*this, getCtx()))) return failure();
  if (!bpfabi::lookupCsumLevel(getMode())) return emitOpError("mode must be query, inc, dec or reset");
  return success();
}
LogicalResult SkbSetHashOp::verify() { return verifySkbDatapath(*this, getCtx()); }
LogicalResult SkbSetHashInvalidOp::verify() { return verifySkbDatapath(*this, getCtx()); }
LogicalResult SkbEcnSetCeOp::verify() { return verifySkbDatapath(*this, getCtx()); }

// tunnel key get / set. The record is the exact 44-byte struct
// bpf_tunnel_key view of the flags' family (checked in ebpf-verify-records).
static LogicalResult verifyTunnelKeyOp(Operation *op, Value ctx, StringRef flags, bool forSet, Value in,
                                       RecordMakeOp &mk) {
  if (failed(verifySkbDatapath(op, ctx)))
    return failure();
  if (!bpfabi::tunnelFlagsValue(flags, forSet))
    return op->emitOpError() << "flags \"" << flags << "\" are not supported; \"none\" or a comma-separated subset of "
                             << (forSet ? "tuninfo_ipv6, zero_csum_tx, dont_fragment, seq_number, no_tunnel_key"
                                        : "tuninfo_ipv6, tuninfo_flags")
                             << " (each at most once; other flags and dynamic flags are outside the compiler's capability)";
  mk = in.getDefiningOp<RecordMakeOp>();
  if (!mk)
    return op->emitOpError("the record must be an ebpf.record.make result (the helper reads a compiler-owned copy; map values and borrowed records are not accepted)");
  return success();
}
LogicalResult SkbGetTunnelKeyOp::verify() {
  RecordMakeOp mk;
  if (failed(verifyTunnelKeyOp(*this, getCtx(), getFlags(), false, getInput(), mk)))
    return failure();
  if (getInput().getType() != getOutput().getType())
    return emitOpError("output record type must equal the input record type");
  for (Operation *user : getOutput().getUsers())
    if (!isa<RecordFieldOp>(user))
      return user->emitOpError() << "uses the output record of ebpf.skb.get_tunnel_key; it may only be read with ebpf.record.field";
  return success();
}
LogicalResult SkbSetTunnelKeyOp::verify() {
  RecordMakeOp mk;
  return verifyTunnelKeyOp(*this, getCtx(), getFlags(), true, getKey(), mk);
}
LogicalResult SkbChangeTailOp::verify() { return verifyWave3Op(*this, getCtx(), "skb.resize"); }
LogicalResult SkbChangeHeadOp::verify() { return verifyWave3Op(*this, getCtx(), "skb.resize"); }
LogicalResult SkbChangeProtoOp::verify() { return verifyWave3Op(*this, getCtx(), "skb.resize"); }
LogicalResult SkbChangeTypeOp::verify() { return verifyWave3Op(*this, getCtx(), "skb.meta"); }
LogicalResult CsumUpdateOp::verify() { return verifyWave3Op(*this, getCtx(), "skb.meta"); }
LogicalResult SkbHashRecalcOp::verify() { return verifyWave3Op(*this, getCtx(), "skb.meta"); }
LogicalResult SkbCgroupClassidOp::verify() { return verifyWave3Op(*this, getCtx(), "skb.meta"); }
LogicalResult SkbNetnsCookieOp::verify() { return verifyWave3Op(*this, getCtx(), "skb.meta"); }
// one OPS tag each; the allowed kinds differ per op.
LogicalResult SkbSocketUidOp::verify() { return verifyWave3Op(*this, getCtx(), "skb.socket_uid"); }
LogicalResult SkbCgroupIdOp::verify() { return verifyWave3Op(*this, getCtx(), "skb.cgroup_id"); }
LogicalResult SkbAncestorCgroupIdOp::verify() { return verifyWave3Op(*this, getCtx(), "skb.ancestor_cgroup_id"); }
LogicalResult SockOpsCbFlagsSetOp::verify() { return verifyWave3Op(*this, getCtx(), "sock_ops.cb_flags_set"); }

// the closed option table; the placement rules are the wave-3 ones.
static LogicalResult verifySockOption(Operation *op, Value ctx, StringRef name, bool forGet, StringRef tag = "sock_ops.sockopt") {
  if (failed(verifyWave3Op(op, ctx, tag)))
    return failure();
  const bpfabi::SockOptABI *row = bpfabi::lookupSockOption(name);
  if (!row) {
    auto diag = op->emitOpError() << "unknown socket option '" << name << "'; the closed table is ";
    llvm::interleaveComma(bpfabi::sockOptions(), diag, [&](const bpfabi::SockOptABI &r) { diag << r.Name; });
    return diag;
  }
  if (forGet && !row->Get)
    return op->emitOpError() << "socket option '" << name << "' is set-only and cannot be read with getsockopt";
  return success();
}

LogicalResult SockOpsSetsockoptOp::verify() { return verifySockOption(*this, getCtx(), getOption(), false); }

LogicalResult SockOpsGetsockoptOp::verify() { return verifySockOption(*this, getCtx(), getOption(), true); }

// the same closed table from cgroup_sock_addr, opened only on the two
// attaches selected; an omitted attach is not opened either.
static LogicalResult verifySockAddrOption(Operation *op, Value ctx, StringRef name, bool forGet) {
  if (failed(verifySockOption(op, ctx, name, forGet, "sock_addr.sockopt")))
    return failure();
  auto prog = op->getParentOfType<ProgramOp>();
  std::optional<StringRef> attach = prog.getAttach();
  if (!attach || (*attach != "connect4" && *attach != "bind4"))
    return op->emitOpError() << "requires attach \"connect4\" or \"bind4\" written on the program (the two selected attaches), not "
                             << (attach ? ("attach \"" + *attach + "\"").str() : std::string("no attach"));
  return success();
}

LogicalResult SockAddrSetsockoptOp::verify() { return verifySockAddrOption(*this, getCtx(), getOption(), false); }

LogicalResult SockAddrGetsockoptOp::verify() { return verifySockAddrOption(*this, getCtx(), getOption(), true); }

// the closed string-option table and the constant name's bytes.
LogicalResult SockOpsSetsockoptNameOp::verify() {
  if (failed(verifyWave3Op(*this, getCtx(), "sock_ops.sockopt")))
    return failure();
  if (!bpfabi::lookupSockOptionName(getOption())) {
    auto diag = emitOpError() << "unknown string socket option '" << getOption() << "'; the closed table is ";
    llvm::interleaveComma(bpfabi::sockOptionNames(), diag, [&](const bpfabi::SockOptNameABI &r) { diag << r.Name; });
    return diag;
  }
  StringRef name = getLiteral();
  if (name.empty() || name.size() > bpfabi::kSockOptNameMaxBytes)
    return emitOpError() << "name of " << name.size() << " bytes; the name is 1.." << bpfabi::kSockOptNameMaxBytes
                         << " bytes (the compiler's limit: the kernel silently truncates a longer name)";
  for (size_t i = 0; i < name.size(); ++i) {
    unsigned char c = name[i];
    if (c < 0x20 || c == 0x7f)
      return emitOpError() << "name byte " << i << " is NUL or a control character";
  }
  return success();
}
LogicalResult XdpBuffLenOp::verify() { return verifyWave3Op(*this, getCtx(), "xdp.bytes"); }
LogicalResult L4CsumReplaceOp::verify() { return verifyWave3Op(*this, getCtx(), "tc.mutation"); }
LogicalResult XdpLoadBytesOp::verify() {
  if (failed(verifyWave3Op(*this, getCtx(), "xdp.bytes")))
    return failure();
  if (getLen() < 1 || getLen() > 8)
    return emitOpError("length must be a constant in 1..8");
  return success();
}
LogicalResult XdpStoreBytesOp::verify() {
  if (failed(verifyWave3Op(*this, getCtx(), "xdp.bytes")))
    return failure();
  unsigned width = cast<IntegerType>(getValue().getType()).getWidth();
  if (!((getLen() == 1 && width == 8) || (getLen() == 4 && width == 32) ||
        ((getLen() == 6 || getLen() == 8) && width == 64)))
    return emitOpError("len/type must be 1/i8, 4/i32, 6/i64 or 8/i64");
  return success();
}
// fib_lookup on the own xdp entry context. Placement is the
// program body, ebpf.if or packet.check only (verifyWave3Op already rejects
// loops, callbacks and static functions); the output record feeds only
// ebpf.record.field. The exact 64-byte view is checked by ebpf-verify-records.
LogicalResult FibLookupOp::verify() {
  if (failed(verifyWave3Op(*this, getCtx(), "fib.lookup")))
    return failure();
  for (Operation *p = (*this)->getParentOp(); p && !isa<ProgramOp>(p); p = p->getParentOp())
    if (!isa<IfOp, PacketCheckOp>(p))
      return emitOpError() << "must be directly in the program body, an ebpf.if or an ebpf.packet.check region (not inside "
                           << p->getName() << ")";
  if (getFlags() != "none" && getFlags() != "direct")
    return emitOpError() << "flags \"" << getFlags()
                         << "\" are not supported; only \"none\" and \"direct\" (other FIB flags and dynamic flags are outside the compiler's capability)";
  if (!getInput().getDefiningOp<RecordMakeOp>())
    return emitOpError("input must be an ebpf.record.make result (the helper reads a compiler-owned copy; map values and borrowed records are not accepted)");
  if (getInput().getType() != getOutput().getType())
    return emitOpError("output record type must equal the input record type");
  for (Operation *user : getOutput().getUsers())
    if (!isa<RecordFieldOp>(user))
      return user->emitOpError() << "uses the output record of ebpf.fib.lookup; it may only be read with ebpf.record.field";
  return success();
}

// record.field reads only an ebpf.fib.lookup output (not a general
// record reader). Path syntax here; leaf, index range and type in ebpf-verify-records.
LogicalResult RecordFieldOp::verify() {
  auto fib = getRecord().getDefiningOp<FibLookupOp>();
  auto tun = getRecord().getDefiningOp<SkbGetTunnelKeyOp>();
  if (!((fib && fib.getOutput() == getRecord()) || (tun && tun.getOutput() == getRecord())))
    return emitOpError("reads only the output record of ebpf.fib.lookup or ebpf.skb.get_tunnel_key");
  StringRef p = getPath();
  StringRef name = p.take_until([](char c) { return c == '['; });
  if (name.empty() || name.contains('.'))
    return emitOpError() << "path \"" << p << "\" must name one leaf field, optionally with a constant index";
  StringRef rest = p.drop_front(name.size());
  if (!rest.empty()) {
    unsigned idx;
    if (!rest.consume_front("[") || !rest.consume_back("]") || rest.empty() || rest.getAsInteger(10, idx))
      return emitOpError() << "path \"" << p << "\" index must be a constant decimal like \"" << name << "[0]\"";
  }
  return success();
}

// csum_diff takes no context; the program kind must allow it (sched_cls / xdp).
LogicalResult CsumDiffOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || !bpfmlir::kindAllows(prog.getKind(), "csum.diff"))
    return emitOpError() << "requires an enclosing " << bpfmlir::kindsAllowing("csum.diff")
                         << " program (not a static function)";
  if (insideStreamCallback(*this))
    return emitOpError("is not supported in a helper callback");
  if ((*this)->getParentOfType<LoopOp>())
    return emitOpError("is not allowed inside ebpf.loop");
  if (!getFrom() && !getTo())
    return emitOpError("needs a from or a to value (both absent only returns the seed)");
  for (Value v : {getFrom(), getTo()})
    if (v) {
      unsigned w = cast<IntegerType>(v.getType()).getWidth();
      if (w != 32 && w != 64)
        return emitOpError("from / to values must be i32 or i64 (4 or 8 bytes)");
    }
  return success();
}
LogicalResult TracePrintkOp::verify() {
  // in an ebpf.func the kind is checked per reaching context
  // (ebpf-verify-call-contexts).
  auto prog = (*this)->getParentOfType<ProgramOp>();
  bool inFunc = !prog && (*this)->getParentOfType<SubprogramOp>();
  if (!inFunc && (!prog || !bpfmlir::kindAllows(prog.getKind(), "trace.printk")))
    return emitOpError(
        "requires a supported enclosing program (not a static function)");
  if (insideStreamCallback(*this))
    return emitOpError("is not supported in a helper callback");
  // the %s literals — string attributes without an embedded NUL.
  std::vector<StringRef> strs;
  if (ArrayAttr arr = getStrsAttr())
    for (auto [i, a] : llvm::enumerate(arr)) {
      auto s = dyn_cast<StringAttr>(a);
      if (!s)
        return emitOpError() << "strs element #" << i << " must be a string literal, got " << a;
      if (s.getValue().contains('\0'))
        return emitOpError() << "strs element #" << i << " must not contain an embedded NUL";
      strs.push_back(s.getValue());
    }
  std::string error;
  auto spec = bpfmlir::parseTraceFormat(getFormat(), error);
  if (!spec)
    return emitOpError() << error;
  unsigned nstr = llvm::count_if(*spec, [](const bpfmlir::TraceFormatArg &f) { return f.isString; });
  unsigned nint = spec->size() - nstr;
  if (nstr != strs.size())
    return emitOpError() << "%s conversion count must match the strs count (" << nstr << " %s conversions, " << strs.size()
                         << " strs elements — %% consumes no literal)";
  if (nint != getArgs().size())
    return emitOpError() << "format conversion count must match argument count (" << nint << " integer conversions, "
                         << getArgs().size() << " integer arguments)";
  auto arg = getArgs().begin();
  for (const bpfmlir::TraceFormatArg &format : *spec) {
    if (format.isString)
      continue;
    if (!(*arg).getType().isInteger(format.bits))
      return emitOpError() << "format conversion requires i" << format.bits;
    ++arg;
  }
  uint64_t bin = bpfmlir::traceBinArgsBytes(strs, nint);
  if (bin > bpfmlir::kTraceBinArgsBound)
    return emitOpError() << "needs " << bin << " bytes of bin_args (sum of %s literal length + 1 + 7, plus 8 per integer), "
                         << "above the compiler's bound " << bpfmlir::kTraceBinArgsBound
                         << " (a conservative bound over the kernel's MAX_BPRINTF_BIN_ARGS — the kernel may still accept this)";
  return success();
}

// ctx-free scalar helpers keep the task.pid_tgid placement (program,
// static function, B / U loop) but are not opened directly in helper
// callbacks. Reaching them through a static function called from a callback
// is not rejected (the kernel checks callbacks with the program's protos).
static LogicalResult verifyScalarHelperPlacement(Operation *op) {
  if (insideStreamCallback(op))
    return op->emitOpError("is not supported in a helper callback");
  return success();
}
LogicalResult CpuIdOp::verify() { return verifyScalarHelperPlacement(*this); }
LogicalResult RandomU32Op::verify() { return verifyScalarHelperPlacement(*this); }
LogicalResult NumaNodeIdOp::verify() { return verifyScalarHelperPlacement(*this); }
LogicalResult TaskUidGidOp::verify() { return verifyScalarHelperPlacement(*this); }
LogicalResult Jiffies64Op::verify() { return verifyScalarHelperPlacement(*this); }
LogicalResult KtimeBootNsOp::verify() { return verifyScalarHelperPlacement(*this); }
LogicalResult KtimeCoarseNsOp::verify() { return verifyScalarHelperPlacement(*this); }
LogicalResult KtimeTaiNsOp::verify() { return verifyScalarHelperPlacement(*this); }
LogicalResult TaskAncestorCgroupIdOp::verify() { return verifyScalarHelperPlacement(*this); }
LogicalResult TaskCurrentRawOp::verify() { return verifyScalarHelperPlacement(*this); }
LogicalResult TaskNsPidTgidOp::verify() { return verifyScalarHelperPlacement(*this); }
LogicalResult TaskSendSignalOp::verify() { return verifyScalarHelperPlacement(*this); }
LogicalResult TaskSendSignalThreadOp::verify() { return verifyScalarHelperPlacement(*this); }

LogicalResult CtxFuncIpOp::verify() {
  return verifyStreamContext(*this, getCtx(), "ctx.func_ip");
}
LogicalResult CtxFuncArgCntOp::verify() {
  return verifyStreamContext(*this, getCtx(), "ctx.func_arg_cnt");
}
LogicalResult CtxFuncArgOp::verify() {
  if (failed(verifyStreamContext(*this, getCtx(), "ctx.func_arg")))
    return failure();
  unsigned width = getValue().getType().getIntOrFloatBitWidth();
  if (width != 8 && width != 16 && width != 32 && width != 64)
    return emitOpError("value must be i8 / i16 / i32 / i64");
  return success();
}

static LogicalResult verifyCgroupRetval(Operation *op) {
  auto prog = op->getParentOfType<ProgramOp>();
  if (!prog || op->getParentOfType<SubprogramOp>() || insideStreamCallback(op))
    return op->emitOpError("requires a program body or non-callback loop");
  if (!bpfmlir::kindAllows(prog.getKind(), "cgroup.retval"))
    return op->emitOpError("requires a supported cgroup kind/hook");
  if (prog.getKind() == "cgroup_sock_addr") {
    StringRef hook = prog.getAttach().value_or("");
    // Empty selects the existing connect4 default. Receive/name hooks are
    // deliberately excluded by cgroup_common_func_proto.
    if (!hook.empty() && hook != "bind4" && hook != "bind6" &&
        hook != "connect4" && hook != "connect6" && hook != "connect_unix" &&
        hook != "sendmsg4" && hook != "sendmsg6")
      return op->emitOpError("requires a supported cgroup kind/hook");
  }
  return success();
}
LogicalResult CgroupRetvalOp::verify() { return verifyCgroupRetval(*this); }
LogicalResult CgroupSetRetvalOp::verify() { return verifyCgroupRetval(*this); }

// the placement of task.current_btf; the untrusted result reaches only kfield.load.
LogicalResult TaskPtRegsOp::verify() {
  if (getTask().getType().getStructName() != "task_struct")
    return emitOpError("takes !ebpf.kptr<\"task_struct\">");
  if (getResult().getType().getStructName() != "pt_regs")
    return emitOpError("returns !ebpf.kptr<\"pt_regs\">");
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog)
    return emitOpError("requires a program body (not a static function)");
  for (Operation *p = (*this)->getParentOp(); p && p != prog.getOperation(); p = p->getParentOp())
    if (isa<SubprogramOp, LoopCallbackOp, TimerCallbackOp, UserRingbufCallbackOp, LoopOp, MapForEachOp, BpfLoopOp>(p))
      return emitOpError("is not supported inside a func, callback or loop");
  for (OpOperand &use : getResult().getUses())
    if (!isa<KFieldLoadOp>(use.getOwner()))
      return emitOpError() << "the result may only be the pointer of ebpf.kfield.load (it is not a trusted pointer), but it is used by '"
                           << use.getOwner()->getName() << "'";
  return success();
}

// the typed current task stays in the program body, like kptr.addr's
// placement, without its tracing-kind restriction (availability is the
// requirements helper row at load).
LogicalResult TaskCurrentBtfOp::verify() {
  if (getResult().getType().getStructName() != "task_struct")
    return emitOpError("returns !ebpf.kptr<\"task_struct\">");
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog)
    return emitOpError("requires a program body (not a static function)");
  for (Operation *p = (*this)->getParentOp(); p && p != prog.getOperation();
       p = p->getParentOp())
    if (isa<SubprogramOp, LoopCallbackOp, TimerCallbackOp,
            UserRingbufCallbackOp, LoopOp, MapForEachOp, BpfLoopOp>(p))
      return emitOpError("is not supported inside a func, callback or loop");
  return success();
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

LogicalResult SkRedirectRequestOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || prog.getKind() != "sk_skb" || prog.getBody().empty() ||
      prog.getBody().front().getNumArguments() == 0 || getCtx() != prog.getBody().front().getArgument(0))
    return emitOpError("requires the entry context of an sk_skb program (not a static function)");
  for (Operation *p = (*this)->getParentOp(); p && p != prog; p = p->getParentOp()) {
    if (isa<LoopCallbackOp, BpfLoopOp>(p) || (isa<LoopOp>(p) && cast<LoopOp>(p).getCallback()))
      return emitOpError("is not supported in a helper callback");
  }
  return checkSockMapKey(*this, getMap(), getKey());
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

LogicalResult XdpAdjustMetaOp::verify() {
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog || !bpfmlir::kindAllows(prog.getKind(), "xdp.adjust") || cast<ContextType>(getCtx().getType()).getKind() != prog.getKind())
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("xdp.adjust") << " programs (bpf_xdp_adjust_meta moves the metadata start of an XDP packet)";
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

static LogicalResult verifyTcMutation(Operation *op, Value ctx) {
  auto prog = op->getParentOfType<ProgramOp>();
  if (!prog || !bpfmlir::kindAllows(prog.getKind(), "tc.mutation") || prog.getBody().empty() ||
      prog.getBody().front().getNumArguments() == 0 ||
      ctx != prog.getBody().front().getArgument(0))
    return op->emitOpError("requires the owning sched_cls entry context");
  if (op->getParentOfType<LoopOp>())
    return op->emitOpError("is not allowed inside ebpf.loop");
  return success();
}

LogicalResult CloneRedirectOp::verify() {
  if (failed(verifyTcMutation(*this, getCtx())))
    return failure();
  if (getFlags() != "egress" && getFlags() != "ingress")
    return emitOpError("flags must be egress or ingress");
  return success();
}

LogicalResult SkbStoreBytesOp::verify() {
  if (failed(verifyTcMutation(*this, getCtx())))
    return failure();
  unsigned width = cast<IntegerType>(getValue().getType()).getWidth();
  if (!((getLen() == 1 && width == 8) || (getLen() == 4 && width == 32) ||
        ((getLen() == 6 || getLen() == 8) && width == 64)))
    return emitOpError("len/type must be 1/i8, 4/i32, 6/i64 or 8/i64");
  if (getFlags() != 0)
    return emitOpError("flags must be zero");
  return success();
}

LogicalResult L3CsumReplaceOp::verify() {
  return verifyTcMutation(*this, getCtx());
}

LogicalResult RedirectOp::verify() {
  llvm::StringRef kind = (*this)->getParentOfType<ProgramOp>().getKind();
  if (programAttachOf(*this).starts_with("netkit_"))
    return emitOpError("terminal redirect is not supported for netkit programs");
  if (getFlags() && (kind != "sched_cls" || (*getFlags() != "egress" && *getFlags() != "ingress")))
    return emitOpError("explicit flags require sched_cls and must be egress or ingress");
  if (!bpfmlir::kindAllows(kind, "redirect"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("redirect") << " programs (bpf_redirect to an ifindex), not \"" << kind << "\"";
  if (auto via = getVia()) {
    // redirect_neigh / redirect_peer variants.
    if (getFlags())
      return emitOpError("via excludes flags");
    if (*via != "neigh" && *via != "peer")
      return emitOpError() << "unknown via \"" << *via << "\" (known: \"neigh\", \"peer\")";
    std::string tag = ("redirect." + *via).str();
    if (!bpfmlir::kindAllows(kind, tag))
      return emitOpError() << "via \"" << *via << "\" is only for " << bpfmlir::kindsAllowing(tag) << " programs, not \"" << kind << "\"";
    if (*via == "peer" && programAttachOf(*this) != "ingress")
      return emitOpError("via \"peer\" requires attach \"ingress\" (the kernel drops a peer redirect at egress)");
  }
  bool hasFallback = !getFallback().empty();
  if (hasFallback && (!getCond() || getElseAction()))
    return emitOpError("fallback requires when and excludes else");
  if (getElseAction() && !getCond())
    return emitOpError("else requires when");
  if (getCond() && !getElseAction() && !hasFallback)
    return emitOpError("`when` needs an `else` verdict or fallback");
  if (hasFallback) {
    if (!getFallback().hasOneBlock() || getFallback().front().getNumArguments())
      return emitOpError("fallback requires one block without arguments");
    Block &fb = getFallback().front();
    if (fb.empty() || !isa<VerdictOp, VerdictIfOp>(fb.back()))
      return emitOpError("fallback must end with ebpf.verdict or ebpf.verdict.if");
    for (Operation &op : fb.without_terminator())
      if (op.getName().getDialectNamespace() != "arith" || op.getNumRegions() ||
          llvm::any_of(op.getOperandTypes(), [](Type t) { return !isa<IntegerType>(t); }) ||
          llvm::any_of(op.getResultTypes(), [](Type t) { return !isa<IntegerType>(t); }))
        return emitOpError("fallback permits only integer arithmetic and a verdict terminator");
  }
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

// xdp.meta_check — the XDP metadata window. It checks `data_meta + len
// <= data`, so it is a different window (type, bound, uses) from packet.check.
static constexpr int64_t kMetaWindowMax = 255;

LogicalResult MetaCheckOp::verify() {
  auto ctx = cast<ContextType>(getCtx().getType());
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!bpfmlir::kindAllows(ctx.getKind(), "xdp.adjust") || !prog || prog.getKind() != ctx.getKind())
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("xdp.adjust")
                         << " programs and their entry context (the metadata window is not available in functions or callbacks)";
  if ((*this)->getParentOfType<SubprogramOp>())
    return emitOpError() << "is not allowed in a static ebpf.func (the metadata window never crosses a call)";
  if ((*this)->getParentOfType<LoopOp>())
    return emitOpError() << "is not allowed inside ebpf.loop";
  if (getLen() < 1 || getLen() > static_cast<uint64_t>(kMetaWindowMax))
    return emitOpError() << "the window length " << getLen() << " must be in 1.." << kMetaWindowMax;
  if (getInRange().empty() || getOutOfRange().empty())
    return emitOpError() << "both the in_range and out_of_range regions must have a body";
  Block &in = getInRange().front();
  if (in.getNumArguments() != 1)
    return emitOpError() << "the in_range region must take exactly one argument (the checked window), got " << in.getNumArguments();
  auto wt = dyn_cast<MetaWindowType>(in.getArgument(0).getType());
  if (!wt || wt.getLen() != static_cast<int64_t>(getLen()))
    return emitOpError() << "the in_range region argument must be !ebpf.meta_window<" << getLen() << ">, got "
                         << in.getArgument(0).getType();
  if (getOutOfRange().front().getNumArguments() != 0)
    return emitOpError() << "the out_of_range region must take no arguments (there is no window)";
  for (Operation *user : in.getArgument(0).getUsers()) {
    if (!isa<MetaStoreOp, MetaLoadOp>(user))
      return emitOpError() << "a checked meta window may only be used by ebpf.xdp.meta_store or ebpf.xdp.meta_load, but it is used by '"
                           << user->getName() << "' (forwarding it lets it escape the range check)";
    if (!getInRange().isAncestor(user->getParentRegion()))
      return emitOpError() << "a checked meta window must be used inside the in_range region of its own ebpf.xdp.meta_check";
  }
  for (Region *r : {&getInRange(), &getOutOfRange()})
    for (Block &blk : *r)
      for (BlockArgument arg : blk.getArguments())
        if (&blk != &in && isa<MetaWindowType>(arg.getType()))
          return emitOpError() << "a checked meta window must not be carried across blocks as a block argument";
  return success();
}

LogicalResult MetaLoadOp::verify() {
  unsigned w = getResult().getType().getIntOrFloatBitWidth();
  if (w != 8 && w != 16 && w != 32 && w != 64)
    return emitOpError() << "reads an i8 / i16 / i32 / i64, got " << getResult().getType();
  int64_t len = cast<MetaWindowType>(getWindow().getType()).getLen();
  uint64_t idx = getIndex(), bytes = w / 8, ulen = static_cast<uint64_t>(len);
  if (idx > ulen || bytes > ulen - idx) // Subtraction: idx + bytes can wrap.
    return emitOpError() << "reads " << bytes << " bytes at index " << static_cast<int64_t>(idx) << ", outside the checked meta window of "
                         << len << " bytes";
  return success();
}

LogicalResult MetaStoreOp::verify() {
  unsigned w = getValue().getType().getIntOrFloatBitWidth();
  if (w != 8 && w != 16 && w != 32 && w != 64)
    return emitOpError() << "stores an i8 / i16 / i32 / i64, got " << getValue().getType();
  int64_t len = cast<MetaWindowType>(getWindow().getType()).getLen();
  uint64_t idx = getIndex(), bytes = w / 8, ulen = static_cast<uint64_t>(len);
  if (idx > ulen || bytes > ulen - idx)
    return emitOpError() << "writes " << bytes << " bytes at index " << static_cast<int64_t>(idx) << ", outside the checked meta window of "
                         << len << " bytes";
  return success();
}

LogicalResult MetaCheckBrOp::verify() {
  auto ctx = cast<ContextType>(getCtx().getType());
  if (!bpfmlir::kindAllows(ctx.getKind(), "xdp.adjust"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("xdp.adjust") << " contexts";
  Block *in = getInRange();
  if (in->getNumArguments() != 1 || !isa<MetaWindowType>(in->getArgument(0).getType()) ||
      cast<MetaWindowType>(in->getArgument(0).getType()).getLen() != static_cast<int64_t>(getLen()))
    return emitOpError() << "the in_range successor must take exactly one !ebpf.meta_window<" << getLen() << "> argument";
  if (getOutOfRange()->getNumArguments() != 0)
    return emitOpError() << "the out_of_range successor must take no arguments";
  return success();
}

// arena.base / arena.check live only in an ebpf.program body (nested
// regions included). A body that becomes its own function — ebpf.func, the
// timer / user_ringbuf callbacks, a callback loop (H), map.for_each — is
// rejected by name: the window base and windows never cross a call.
static LogicalResult verifyArenaPlacement(Operation *op) {
  for (Operation *p = op->getParentOp(); p; p = p->getParentOp()) {
    if (isa<ProgramOp>(p))
      return success();
    if (auto l = dyn_cast<LoopOp>(p); l && l.getCallback())
      return op->emitOpError() << "is not allowed in a callback loop (H) body — the body becomes a separate bpf_loop callback "
                                  "function; arena ops are only in the ebpf.program body";
    if (isa<MapForEachOp>(p))
      return op->emitOpError() << "is not allowed in an ebpf.map.for_each body — the body becomes a separate callback "
                                  "function; arena ops are only in the ebpf.program body";
    if (isa<SubprogramOp, TimerCallbackOp, UserRingbufCallbackOp, LoopCallbackOp>(p))
      break;
  }
  return op->emitOpError() << "is only inside an ebpf.program body (not in ebpf.func, ebpf.timer.callback, "
                              "ebpf.user_ringbuf.callback or a callback body) — the arena window base is not passed "
                              "through calls";
}

LogicalResult ArenaAllocOp::verify() {
  auto prog = dyn_cast_or_null<ProgramOp>((*this)->getParentOp());
  if (!prog || prog.getKind() != "syscall" || (*this)->getBlock() != &prog.getBody().front())
    return emitOpError("requires the direct entry body of a sleepable syscall program");
  auto map = dyn_cast<BlockArgument>(getMap());
  if (!map || map.getOwner() != &prog.getBody().front() ||
      cast<MapType>(getMap().getType()).getKind() != "arena")
    return emitOpError("requires an entry-bound arena map");
  if (getPageOffsetAttr().getInt() < 0 || getPageCountAttr().getInt() <= 0 ||
      getPageOffset() > (uint64_t(1) << 20) || getPageCount() > (uint64_t(1) << 20))
    return emitOpError("requires a nonnegative page offset and a positive page count within 2^20 pages");
  if (failed(verifyRegionResultWidths(*this)))
    return failure();
  bool unsafe = false;
  prog.walk([&](Operation *op) {
    if (op == prog.getOperation() || op->getName().getDialectNamespace() == "arith")
      return;
    // A positive finite list: new ops do not silently gain a no-free summary.
    if (isa<ArenaAllocOp, ArenaFreeOp, ArenaBaseOp, ArenaCheckOp, ArenaLoadOp, ArenaStoreOp,
            YieldOp, VerdictOp, ReturnOp, IfOp, IfYieldOp,
            MapLookupOp, RefCheckOp, RefLoadOp, RefStoreOp>(op))
      return;
    op->emitOpError("is not in the finite no-unknown-free-effects scope of an arena lifecycle program");
    unsafe = true;
  });
  if (unsafe)
    return failure();
  if (!llvm::hasSingleElement(getAllocated()) || !llvm::hasSingleElement(getFailed()))
    return emitOpError("requires exactly one block in both allocated and failed regions");
  Block &in = getAllocated().front();
  if (in.getNumArguments() != 1 || !isa<ArenaPagesType>(in.getArgument(0).getType()) ||
      getFailed().front().getNumArguments() != 0)
    return emitOpError("allocated takes exactly one !ebpf.arena_pages proof; failed takes none");
  bool freed = false;
  for (Operation &op : in) {
    if (auto f = dyn_cast<ArenaFreeOp>(op)) {
      if (freed || f.getPages() != in.getArgument(0))
        return emitOpError("may free its own allocation proof at most once");
      freed = true;
    } else if (freed && !isa<YieldOp>(op) && op.getName().getDialectNamespace() != "arith") {
      return emitOpError("after free only independent scalar arithmetic and yield are permitted");
    }
  }
  for (Operation *user : in.getArgument(0).getUsers())
    if (!isa<ArenaFreeOp>(user) || user->getBlock() != &in)
      return emitOpError("allocation proof may only be freed directly in its own allocated block; no transport or branch release");
  return success();
}

LogicalResult ArenaFreeOp::verify() {
  auto arg = dyn_cast<BlockArgument>(getPages());
  auto owner = arg ? dyn_cast_or_null<ArenaAllocOp>(arg.getOwner()->getParentOp()) : ArenaAllocOp();
  if (!owner || arg.getOwner() != &owner.getAllocated().front() || (*this)->getBlock() != arg.getOwner())
    return emitOpError("requires its own direct allocation success proof, outside all windows and branches");
  return success();
}

LogicalResult ArenaAllocBrOp::verify() {
  if (getAllocated() == getFailed() || getAllocated()->getNumArguments() || getFailed()->getNumArguments())
    return emitOpError("requires distinct allocated/failed successors with no proof transport");
  return success();
}

LogicalResult ArenaBaseOp::verify() {
  auto mt = cast<MapType>(getMap().getType());
  if (mt.getKind() != "arena")
    return emitOpError() << "reads the window base of an arena map, but the map is \"" << mt.getKind() << "\"";
  return verifyArenaPlacement(*this);
}

// MAX window length — the same 16-bit bound as packet.check (the window is
// addressed with constant 16-bit instruction offsets).
static constexpr int64_t kArenaWindowMax = 0xffff;

LogicalResult ArenaCheckOp::verify() {
  if (failed(verifyRegionResultWidths(*this)))
    return failure();
  if (!getBase().getDefiningOp<ArenaBaseOp>())
    return emitOpError() << "the base must be the result of ebpf.arena.base";
  if (failed(verifyArenaPlacement(*this)))
    return failure();
  if (getLen() < 1 || getLen() > kArenaWindowMax)
    return emitOpError() << "the window length " << getLen() << " must be in 1.." << kArenaWindowMax;
  if (!isMemWidth(getOffset().getType()))
    return emitOpError() << "the offset must be an i8 / i16 / i32 / i64, got " << getOffset().getType();
  if (auto prog = (*this)->getParentOfType<ProgramOp>()) {
    bool lifecycle = false;
    prog.walk([&](ArenaAllocOp) { lifecycle = true; });
    if (lifecycle) {
      auto allocation = (*this)->getParentOfType<ArenaAllocOp>();
      if (!allocation || !allocation.getAllocated().isAncestor((*this)->getParentRegion()))
        return emitOpError("a lifecycle window requires its own live allocation success region; bounds alone do not prove allocation");
      auto base = getBase().getDefiningOp<ArenaBaseOp>();
      if (base.getMap() != allocation.getMap())
        return emitOpError("the window base must identify the same entry-bound arena as its allocation");
      APInt off;
      uint64_t begin = allocation.getPageOffset() * 4096, length = allocation.getPageCount() * 4096;
      if (!matchPattern(getOffset(), m_ConstantInt(&off)) || off.getActiveBits() > 64 ||
          off.getZExtValue() < begin || getLen() > length || off.getZExtValue() - begin > length - getLen())
        return emitOpError("a lifecycle window requires a constant range inside its own allocated pages");
      Operation *direct = getOperation();
      while (direct->getParentOp() != allocation)
        direct = direct->getParentOp();
      for (Operation &preceding : allocation.getAllocated().front()) {
        if (&preceding == direct)
          break;
        if (isa<ArenaFreeOp>(preceding))
          return emitOpError("allocation proof is invalid after free; a fresh check cannot recreate it");
      }
    }
  }
  // len ≤ size and a constant offset c ≤ size − len need the schema pages:
  // ebpf-verify-schema checks them.
  if (getInRange().empty() || getOutOfRange().empty())
    return emitOpError() << "both the in_range and out_of_range regions must have a body";
  Block &in = getInRange().front();
  if (in.getNumArguments() != 1)
    return emitOpError() << "the in_range region must take exactly one argument (the checked window), got " << in.getNumArguments();
  auto wt = dyn_cast<ArenaWindowType>(in.getArgument(0).getType());
  if (!wt || wt.getLen() != static_cast<int64_t>(getLen()))
    return emitOpError() << "the in_range region argument must be !ebpf.arena_window<" << getLen() << ">, got "
                         << in.getArgument(0).getType();
  if (getOutOfRange().front().getNumArguments() != 0)
    return emitOpError() << "the out_of_range region must take no arguments (there is no window)";
  for (Operation *user : in.getArgument(0).getUsers()) {
    if (!isa<ArenaLoadOp, ArenaStoreOp>(user))
      return emitOpError() << "a checked arena window may only be used by ebpf.arena.load or ebpf.arena.store, but it is used by '"
                           << user->getName() << "' (forwarding it lets it escape the range check)";
    if (!getInRange().isAncestor(user->getParentRegion()))
      return emitOpError() << "a checked arena window must be used inside the in_range region of its own ebpf.arena.check";
    // A loop body (a window cannot cross iterations) or a body that becomes
    // its own function (callback loop, map.for_each, any isolated op) between
    // the check and the use is a capture.
    for (Operation *p = user->getParentOp(); p && p != getOperation(); p = p->getParentOp())
      if (isa<LoopOp, MapForEachOp, IterNumOp, IterScxDsqOp>(p) || p->hasTrait<OpTrait::IsIsolatedFromAbove>()) {
        bool callback = isa<MapForEachOp>(p) || p->hasTrait<OpTrait::IsIsolatedFromAbove>() ||
                        (isa<LoopOp>(p) && cast<LoopOp>(p).getCallback());
        return emitOpError() << "a checked arena window must not be captured into "
                             << (callback ? "a callback body ('" : "a loop body ('") << p->getName()
                             << "'); check the window inside it";
      }
  }
  for (Region *r : {&getInRange(), &getOutOfRange()})
    for (Block &blk : *r)
      for (BlockArgument arg : blk.getArguments())
        if (&blk != &in && isa<ArenaWindowType>(arg.getType()))
          return emitOpError() << "a checked arena window must not be carried across blocks as a block argument";
  return success();
}

// Arena reads/writes are 1/2/4/8 bytes, fully inside the window (subtraction form).
static LogicalResult verifyArenaAccess(Operation *op, Type valueTy, Value window, uint64_t idx, StringRef verb) {
  unsigned w = valueTy.getIntOrFloatBitWidth();
  if (w != 8 && w != 16 && w != 32 && w != 64)
    return op->emitOpError() << verb << " an i8 / i16 / i32 / i64, got " << valueTy;
  int64_t len = cast<ArenaWindowType>(window.getType()).getLen();
  uint64_t bytes = w / 8, ulen = static_cast<uint64_t>(len);
  if (idx > ulen || bytes > ulen - idx)
    return op->emitOpError() << verb << " " << bytes << " bytes at index " << static_cast<int64_t>(idx)
                             << ", outside the checked arena window of " << len << " bytes";
  return success();
}

LogicalResult ArenaLoadOp::verify() {
  return verifyArenaAccess(*this, getResult().getType(), getWindow(), getIndex(), "reads");
}

LogicalResult ArenaStoreOp::verify() {
  return verifyArenaAccess(*this, getValue().getType(), getWindow(), getIndex(), "writes");
}

LogicalResult ArenaCheckBrOp::verify() {
  Block *in = getInRange();
  if (in->getNumArguments() != 1 || !isa<ArenaWindowType>(in->getArgument(0).getType()) ||
      cast<ArenaWindowType>(in->getArgument(0).getType()).getLen() != static_cast<int64_t>(getLen()))
    return emitOpError() << "the in_range successor must take exactly one !ebpf.arena_window<" << getLen() << "> argument";
  if (getOutOfRange()->getNumArguments() != 0)
    return emitOpError() << "the out_of_range successor must take no arguments";
  if (getInRange() == getOutOfRange())
    return emitOpError() << "the in_range and out_of_range successors must differ";
  return success();
}

LogicalResult YieldOp::verify() {
  if (auto allocation = dyn_cast<ArenaAllocOp>((*this)->getParentOp())) {
    if (getResults().getTypes() != allocation.getResultTypes())
      return emitOpError("yielded types do not match arena.alloc results");
    for (Type t : getResults().getTypes())
      if (!isa<IntegerType>(t))
        return emitOpError("only scalar integers may leave arena.alloc");
    return success();
  }
  // kptr.check yields must match parent results without escaping kernel pointers.
  if (auto kc = dyn_cast<KPtrCheckOp>((*this)->getParentOp())) {
    for (Value v : getResults())
      if (isa<KPtrType, KPtrOrNullType, RcuPtrType, RcuPtrOrNullType>(v.getType()))
        return emitOpError() << "a kernel pointer must not escape ebpf.kptr.check (it is only valid inside the present region)";
    if (getResults().getTypes() != kc.getResultTypes())
      return emitOpError() << "yielded types do not match the results of the enclosing ebpf.kptr.check";
    return success();
  }
  // rcu.region yields integers only — RCU pointers, references,
  // reservations and borrows stay inside the section (its one exit).
  if (auto rr = dyn_cast<RcuRegionOp>((*this)->getParentOp())) {
    for (Type t : getResults().getTypes())
      if (!isa<IntegerType>(t))
        return emitOpError() << "only scalar integers may leave ebpf.rcu.region (got " << t
                             << "); RCU pointers and references are only valid inside the section";
    if (getResults().getTypes() != rr.getResultTypes())
      return emitOpError() << "yielded types do not match the results of the enclosing ebpf.rcu.region";
    return success();
  }
  // per_cpu_load yields integers only — the slot value stays inside.
  if (auto pl = dyn_cast<KsymPerCpuLoadOp>((*this)->getParentOp())) {
    for (Type t : getResults().getTypes())
      if (!isa<IntegerType>(t))
        return emitOpError() << "only scalar integers may leave ebpf.ksym.per_cpu_load (got " << t << ")";
    if (getResults().getTypes() != pl.getResultTypes())
      return emitOpError() << "yielded types do not match the results of the enclosing ebpf.ksym.per_cpu_load";
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
  // xdp.meta_check yields nothing.
  if (isa<MetaCheckOp>((*this)->getParentOp())) {
    if (getNumOperands() != 0)
      return emitOpError() << "ebpf.xdp.meta_check yields no values";
    return success();
  }
  // arena.check yields cannot escape windows (or the base).
  if (auto ac = dyn_cast<ArenaCheckOp>((*this)->getParentOp())) {
    for (Value v : getResults())
      if (isa<ArenaWindowType, ArenaBaseType>(v.getType()))
        return emitOpError() << "a checked arena window must not escape ebpf.arena.check (it is only valid inside its region)";
    if (getResults().getTypes() != ac.getResultTypes())
      return emitOpError() << "yielded types do not match the results of the enclosing ebpf.arena.check";
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
  if (getOutOfRange().front().getNumArguments() != 0)
    return emitOpError() << "the out_of_range region must take no arguments (there is no element)";
  BlockArgument e = in.getArgument(0);
  // a record-array element is borrowed (ebpf-verify-records checks the
  // element record against @records). The borrow is used only inside in_range
  // and never leaves it (no yield, terminator or block-argument transport).
  if (auto bt = dyn_cast<BorrowedType>(e.getType())) {
    if (!isa<RecordType>(bt.getPointee()))
      return emitOpError() << "the in_range region argument must be !ebpf.elem<iN> or a borrowed record element, got " << e.getType();
    for (OpOperand &use : e.getUses()) {
      Operation *user = use.getOwner();
      if (!getInRange().isAncestor(user->getParentRegion()))
        return emitOpError() << "a borrowed element must be used inside the in_range region of its own ebpf.ref.index";
      if (user->hasTrait<OpTrait::IsTerminator>())
        return emitOpError() << "a borrowed element must not leave the in_range region, but it is passed to '" << user->getName()
                             << "' (it would escape the range check)";
    }
    for (Region *r : {&getInRange(), &getOutOfRange()})
      for (Block &blk : *r)
        for (BlockArgument arg : blk.getArguments())
          if (&blk != &in && isa<BorrowedType, ElemType>(arg.getType()))
            return emitOpError() << "a checked element must not be carried across blocks as a block argument";
    return success();
  }
  auto et = dyn_cast<ElemType>(e.getType());
  if (!et || !isa<IntegerType>(et.getElement()) || !cast<IntegerType>(et.getElement()).isSignless())
    return emitOpError() << "the in_range region argument must be !ebpf.elem<iN> or a borrowed record element, got "
                         << e.getType();
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
    if (isa<RingbufStoreFieldOp, RingbufStoreRecordOp, TaskCommOp, CtxStackOp, KernelDPathOp, StrSnprintfOp, UserReadStrOp, UserCopyOp, UserCopyTaskOp, UserReadOp, KernelReadStrOp, RingbufSubmitOp, RingbufDiscardOp>(op) ||
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
    if (!isa<RingbufStoreFieldOp, RingbufStoreRecordOp, TaskCommOp, CtxStackOp, KernelDPathOp, StrSnprintfOp, UserReadStrOp, UserCopyOp, UserCopyTaskOp, UserReadOp, KFieldCopyOp, TpFieldCopyOp, KernelReadStrOp, RingbufSubmitOp,
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

// Reservation buffer writers share the existing ownership/record machinery.
// Only structured nullable/reservation/if regions may separate them from the
// entry program; loops, callbacks and function bodies are deliberately closed.
static LogicalResult verifyBufferWriter(Operation *op, Value reservation,
                                       StringRef field, StringRef kind) {
  auto prog = op->getParentOfType<ProgramOp>();
  if (!prog || prog.getKind() != kind)
    return op->emitOpError() << "requires an ordinary " << kind << " program";
  StringRef capability = isa<CtxStackOp>(op) ? "ctx.stack" :
                         isa<KernelDPathOp>(op) ? "kernel.d_path" : "str.snprintf";
  if (!bpfmlir::kindAllows(prog.getKind(), capability))
    return op->emitOpError("program kind lacks the buffer helper capability");
  for (Operation *p = op->getParentOp(); p != prog; p = p->getParentOp())
    if (!isa<RingbufIfReservedOp, KPtrCheckOp, IfOp>(p))
      return op->emitOpError("is not supported in a function, loop, callback or untracked region");
  if (field.empty() || !isa<RecordType>(cast<ReservationType>(reservation.getType()).getRecordType()))
    return op->emitOpError("needs a nonempty field of a record reservation");
  return success();
}

LogicalResult CtxStackOp::verify() {
  if (failed(verifyBufferWriter(*this, getReservation(), getField(), "kprobe")))
    return failure();
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (getCtx() != prog.getBody().front().getArgument(0) ||
      cast<ContextType>(getCtx().getType()).getKind() != "kprobe")
    return emitOpError("requires the same kprobe entry context");
  return success();
}

LogicalResult KernelDPathOp::verify() {
  if (failed(verifyBufferWriter(*this, getReservation(), getField(), "fentry")))
    return failure();
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!isDPathTarget(prog.getAttach().value_or("")) ||
      cast<KPtrType>(getPtr().getType()).getStructName() != "path")
    return emitOpError("requires fentry/vfs_getattr or fentry/security_inode_getattr and a checked struct path pointer");
  Value src = getPtr();
  if (auto present = src.getDefiningOp<AssumePresentOp>())
    src = present.getValue();
  else if (auto ba = dyn_cast<BlockArgument>(src))
    if (auto check = dyn_cast_or_null<KPtrCheckOp>(ba.getOwner()->getParentOp());
        check && ba.getOwner() == &check.getPresentRegion().front())
      src = check.getPtr();
  auto arg = src.getDefiningOp<CtxArgOp>();
  if (!arg || arg.getIndex() != 0 || arg.getCtx() != prog.getBody().front().getArgument(0))
    return emitOpError("path must come from the same entry context's argument0 through kptr.check");
  return success();
}

LogicalResult StrSnprintfOp::verify() {
  if (failed(verifyBufferWriter(*this, getReservation(), getField(), "kprobe")))
    return failure();
  StringRef fmt = getFormat();
  if (fmt.size() > 128 || fmt.contains('\0') || getArgs().size() > 12)
    return emitOpError("needs a NUL-free literal of at most128 bytes and at most12 i64 arguments");
  unsigned count = 0;
  for (size_t i = 0; i < fmt.size(); ++i) {
    if (fmt[i] != '%')
      continue;
    if (++i < fmt.size() && fmt[i] == '%')
      continue;
    if (i + 2 >= fmt.size() || fmt[i] != 'l' || fmt[i + 1] != 'l' ||
        !StringRef("duxX").contains(fmt[i + 2]))
      return emitOpError("only %% / %lld / %llu / %llx / %llX conversions are supported");
    i += 2;
    ++count;
  }
  if (count != getArgs().size())
    return emitOpError("format conversion count must match the i64 argument count");
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
// visited callee arguments are keyed by (callee, argument position).
// Keying by the callee alone dropped a second argument of the same callee
// (f(v) -> leaf(v, v) writing arg0 passed when arg1 was visited first).
using CalleeArgSet = llvm::DenseSet<std::pair<Operation *, unsigned>>;
static bool refValueWritten(SymbolTableCollection &st, Operation *from, Value v, CalleeArgSet &seen);
static bool calleeWritesArg(SymbolTableCollection &st, SubprogramOp fn, unsigned i, CalleeArgSet &seen) {
  if (!seen.insert({fn.getOperation(), i}).second || fn.getBody().empty() || i >= fn.getBody().front().getNumArguments())
    return false;
  return refValueWritten(st, fn, fn.getBody().front().getArgument(i), seen);
}
static bool refValueWritten(SymbolTableCollection &st, Operation *from, Value v, CalleeArgSet &seen) {
  for (OpOperand &use : v.getUses()) {
    Operation *u = use.getOwner();
    if (isa<RefStoreOp, RefFieldStoreOp, RefAtomicAddOp, RefFieldAtomicAddOp, RefFieldCmpxchgOp, RefFieldAtomicOrOp, RefFieldAddrOp, KPtrXchgOp>(u)) // kptr.xchg also writes a field (cmpxchg / or too; the cpumask kfuncs write through ref.field.addr).
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
    // (d): a global function is verified on its own and the kernel
    // rejects a global call while a lock is held (6.12.111 / 7.1.8 / 7.3.1;
    // 6.6.157 rejects every call there) — named before the general rule.
    if (auto call = dyn_cast<CallOp>(op)) {
      auto fn = SymbolTable::lookupNearestSymbolFrom<SubprogramOp>(call, call.getCalleeAttr());
      if (fn && fn.getLinkage() == "global")
        return call.emitOpError() << "calls the global function @" << call.getCallee()
                                  << " inside ebpf.spin.region; the kernel verifier rejects a call of a global function while a "
                                     "bpf_spin_lock is held (the compiler takes this rule on every kernel version)";
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
  // the clocks are the UAPI table's clockid rows (monotonic, boottime — abigen from time.h).
  if (!bpfabi::lookupClockId(getClock()))
    return emitOpError() << "clock \"" << getClock() << "\" is not supported (only " << bpfabi::clockIdNames()
                         << " — the clockid rows of the UAPI table)";
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

// cancel has the same position rules as start in a program body, but is not allowed inside
// ebpf.timer.callback (a callback cancelling its own or another timer is -EDEADLK territory — outside this step).
LogicalResult TimerCancelOp::verify() {
  if ((*this)->getParentOfType<TimerCallbackOp>())
    return emitOpError() << "is not allowed inside ebpf.timer.callback (cancel from a callback, and its -EDEADLK, is outside the first step)";
  return failure(failed(checkTimerOp(*this, getRef())));
}

// the programs whose ebpf.timer.set_callback names cb (its owners).
// Owners with the kind tag "scx" (struct_ops) widen the callback's op set;
// mixing them with other owners is rejected (the sets differ).
static SmallVector<ProgramOp> timerCallbackOwners(TimerCallbackOp cb) {
  SmallVector<ProgramOp> owners;
  auto module = cb->getParentOfType<ModuleOp>();
  if (!module)
    return owners;
  module.walk([&](TimerSetCallbackOp s) {
    auto prog = s->getParentOfType<ProgramOp>();
    if (s.getCallback() == cb.getSymName() && prog && !llvm::is_contained(owners, prog))
      owners.push_back(prog);
  });
  return owners;
}
enum class TimerCallbackOwners { None, Scx, Other, Mixed };
static TimerCallbackOwners timerCallbackOwnerKind(TimerCallbackOp cb) {
  bool scx = false, other = false;
  for (ProgramOp p : timerCallbackOwners(cb))
    (bpfmlir::kindAllows(p.getKind(), "scx") ? scx : other) = true;
  if (scx && other)
    return TimerCallbackOwners::Mixed;
  return scx ? TimerCallbackOwners::Scx : other ? TimerCallbackOwners::Other : TimerCallbackOwners::None;
}
static bool scxOwnedTimerCallback(Operation *op) {
  auto cb = dyn_cast<TimerCallbackOp>(op);
  return cb && timerCallbackOwnerKind(cb) == TimerCallbackOwners::Scx;
}

// the ops a sched_ext_ops owner's timer callback body accepts on top of
// the base set — the E-a op set of an ebpf.func body: kfunc.call
// and kref.check, the closed regions (iter.num, iter.scx_dsq, rcu.region and
// their terminators), the kptr ops, kfield.load / kfield.ptr, the global ops,
// field ops on any borrowed record (a global record borrow too), ebpf.call and
// the sched_ext ops (verifyScxCommon keeps kScxTimerCallbackOps). Map ops stay
// out (the callback has no `maps`); the context rules (not sleepable, RCU only
// inside a held rcu.region, the call-site regions) are the passes'.
static bool scxTimerCallbackExtraOp(Operation &op) {
  if (op.getName().getStringRef().starts_with("ebpf.scx."))
    return true;
  return isa<CallOp, KfuncCallOp, KRefCheckOp, KPtrCheckOp, IterNumOp, IterScxDsqOp, RcuRegionOp, IterYieldOp, YieldOp, BreakOp,
             ContinueOp, KPtrXchgOp, GlobalKPtrXchgOp, KPtrLoadRcuOp, GlobalKPtrLoadRcuOp, KFieldLoadOp, KFieldPtrOp, GlobalLoadOp,
             GlobalStoreOp, GlobalRefOp, GlobalAtomicAddOp, GlobalCmpxchgOp, GlobalAtomicOrOp, RefFieldLoadOp, RefFieldStoreOp,
             RefFieldAtomicAddOp, RefFieldCmpxchgOp, RefFieldAtomicOrOp>(op);
}

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
  // callback ifs carry no results. a sched_ext_ops owner's callback may
  // hold the closed regions, whose ② forms end blocks with their own
  // terminators (iter_num.next_br, ...) and carry values in block arguments.
  bool scxBody = timerCallbackOwnerKind(*this) == TimerCallbackOwners::Scx;
  bool expanded = !getBody().hasOneBlock();
  bool done = false;
  for (Block &blk : getBody()) {
    if (blk.empty())
      return emitOpError() << "must end with ebpf.timer.done";
    Operation &term = blk.back();
    if (isa<TimerDoneOp>(term))
      done = true;
    else if (!expanded || !((term.getDialect() && term.getDialect()->getNamespace() == "cf") ||
                            (scxBody && isa<Stage2InternalOp>(&term))))
      return emitOpError() << "must end with ebpf.timer.done";
    if (&blk != &b && blk.getNumArguments() != 0 && !scxBody)
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
  // owners decide the set. sched_ext owners (struct_ops — VerifySchema
  // restricts their timer ops to sleepable sched_ext_ops members) add the E-a op
  // set (scxTimerCallbackExtraOp; each op's verifier and the context
  // passes check the rest).
  TimerCallbackOwners owners = timerCallbackOwnerKind(*this);
  if (owners == TimerCallbackOwners::Mixed)
    return emitOpError() << "is set as the callback by both " << bpfmlir::kindsAllowing("scx")
                         << " programs and programs of other kinds; the ops a callback may use differ between them, so one "
                            "callback cannot serve both (use two callbacks)";
  bool scxOwned = owners == TimerCallbackOwners::Scx;
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
      if (isa<KtimeOp, CoreEnumValueOp>(op)) // the CO-RE enum read is a constant to the verifier.
        continue;
      // Restart the already-validated own timer, with conditionals for bounded periodic use.
      if (isa<TimerStartOp>(op))
        continue;
      // sched_ext_ops owners — the E-a op set (scxTimerCallbackExtraOp),
      // nested regions with the same set. After ② the closed regions are their
      // stage-② forms (Stage2InternalOp — ebpf-compile rejects them in input).
      if (scxOwned && isa<Stage2InternalOp>(&op))
        continue;
      if (scxOwned && scxTimerCallbackExtraOp(op)) {
        for (Region &r : op.getRegions())
          for (Block &inner : r)
            if (failed(check(inner)))
              return failure();
        continue;
      }
      if (auto iff = dyn_cast<IfOp>(op)) {
        for (Region &r : iff->getRegions())
          for (Block &inner : r)
            if (failed(check(inner)))
              return failure();
        continue;
      }
      return op.emitOpError() << "is not allowed inside ebpf.timer.callback (only arith, field loads / stores of its map value and ebpf.ktime.ns; "
                                 "also ebpf.timer.start of its own timer and ebpf.if around them"
                              << (scxOwned ? std::string("; for sched_ext_ops owners also ebpf.call, ebpf.kfunc.call, ebpf.kref.check, "
                                                         "ebpf.kptr.check, ebpf.iter.num, ebpf.iter.scx_dsq, ebpf.rcu.region, the kptr "
                                                         "ops, ebpf.kfield.load / kfield.ptr, the global ops, field ops on any borrowed "
                                                         "record and ") +
                                                 bpfmlir::scxTimerCallbackOps()
                                           : std::string())
                              << ")";
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

LogicalResult UserAddrOp::verify() {
  if (failed(verifySleepableFentryPlacement(*this, "user.addr")))
    return failure();
  for (Operation *user : getResult().getUsers())
    if (!isa<UserCopyOp, UserCopyTaskOp>(user))
      return emitOpError() << "!ebpf.user_addr may only be used by ebpf.user.copy / ebpf.user.copy_task (no store, return, yield, call argument, region transport or integer operation), but it is used by '"
                           << user->getName() << "'";
  return success();
}

LogicalResult UserCopyOp::verify() {
  if (failed(verifySleepableFentryPlacement(*this, "user.copy")))
    return failure();
  if (getField().empty())
    return emitOpError() << "needs a field name";
  if (!getAddr().getDefiningOp<UserAddrOp>())
    return emitOpError() << "the address must be an ebpf.user.addr result";
  return success();
}

// the two task sources of user.copy_task. Stage ② turns kref.check into
// is_present / assume_present, so both forms of the present kref are accepted.
LogicalResult UserCopyTaskOp::verify() {
  if (failed(verifySleepableFentryPlacement(*this, "user.copy_task")))
    return failure();
  if (getField().empty())
    return emitOpError() << "needs a field name";
  if (!getAddr().getDefiningOp<UserAddrOp>())
    return emitOpError() << "the address must be an ebpf.user.addr result";
  Value task = getTask();
  if (auto kp = dyn_cast<KPtrType>(task.getType())) {
    if (kp.getStructName() != "task_struct")
      return emitOpError() << "takes a task_struct, got " << task.getType();
    if (!task.getDefiningOp<TaskCurrentBtfOp>())
      return emitOpError() << "a !ebpf.kptr<\"task_struct\"> task must be the result of ebpf.task.current_btf";
    return success();
  }
  if (auto kr = dyn_cast<KRefType>(task.getType())) {
    if (kr.getStructName() != "task_struct")
      return emitOpError() << "takes a task_struct, got " << task.getType();
    auto arg = dyn_cast<BlockArgument>(task);
    bool checked = (arg && isa_and_nonnull<KRefCheckOp>(arg.getOwner()->getParentOp())) || task.getDefiningOp<AssumePresentOp>();
    if (!checked)
      return emitOpError() << "a !ebpf.kref<\"task_struct\"> task must be the present block argument of ebpf.kref.check";
    return success();
  }
  return emitOpError() << "takes the task as the !ebpf.kptr<\"task_struct\"> of ebpf.task.current_btf or the checked !ebpf.kref<\"task_struct\"> of ebpf.kref.check, got "
                       << task.getType();
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

// !ebpf.str_buf values. The nearest enclosing op that is not one of
// the merge regions (if / kptr.check / kref.check / ref.check) — the
// definition and the dump must share it (no loop / iterator / callback / RCU
// section / function boundary between them).
static Operation *strBufBoundary(Operation *op) {
  Operation *p = op->getParentOp();
  while (p && isa<IfOp, KPtrCheckOp, KRefCheckOp, RefCheckOp>(p))
    p = p->getParentOp();
  return p;
}
static LogicalResult verifyStrBufUses(Operation *def, Value v) {
  for (OpOperand &use : v.getUses()) {
    Operation *u = use.getOwner();
    // Stage ②: ebpf-expand-regions turns the merges into branches (the ①
    // rules held on the input; ebpf-compile input has no cf ops).
    if (u->getName().getDialectNamespace() == "cf")
      continue;
    if (isa<ScxDumpOp>(u)) { // The %s position is ScxDumpOp's (scxFormat).
      if (strBufBoundary(u) != strBufBoundary(def))
        return u->emitOpError() << "uses the !ebpf.str_buf of '" << def->getName()
                                << "' across a loop, iterator, callback, RCU section or function boundary";
      continue;
    }
    if (isa<YieldOp, IfYieldOp>(u)) {
      Operation *p = u->getParentOp();
      if (isa<IfOp, KPtrCheckOp, KRefCheckOp, RefCheckOp>(p)) {
        if (failed(verifyStrBufUses(def, p->getResult(use.getOperandNumber()))))
          return failure();
        continue;
      }
    }
    return u->emitOpError() << "uses a !ebpf.str_buf; it may only be an ebpf.scx.dump argument at a %s conversion or yielded "
                               "from ebpf.if / ebpf.kptr.check / ebpf.kref.check / ebpf.ref.check";
  }
  return success();
}
// The size and the place: a sched_ext program body and its merge regions only
// (ebpf-verify-schema narrows it to the dump members, as scx.dump).
static LogicalResult verifyStrBufSize(Operation *op, StrBufType t) {
  if (t.getSize() < 1 || t.getSize() > 64)
    return op->emitOpError() << "makes a !ebpf.str_buf of " << t.getSize() << " bytes; the size is 1..64";
  Operation *top = strBufBoundary(op);
  auto prog = dyn_cast_or_null<ProgramOp>(top);
  if (!prog || !bpfmlir::kindAllows(prog.getKind(), "scx"))
    return op->emitOpError() << "is only in the body of a " << bpfmlir::kindsAllowing("scx")
                             << " program and its ebpf.if / ebpf.kptr.check / ebpf.kref.check / ebpf.ref.check regions (not '"
                             << (top ? top->getName().getStringRef() : StringRef("module")) << "')";
  return success();
}
LogicalResult StrBufLiteralOp::verify() {
  auto t = getBuf().getType();
  if (failed(verifyStrBufSize(*this, t)))
    return failure();
  StringRef lit = getLiteral();
  for (size_t i = 0; i < lit.size(); ++i) {
    unsigned char c = lit[i];
    if (c == 0 || (c < 0x80 && !llvm::isPrint(c) && !llvm::isSpace(c)))
      return emitOpError() << "literal byte " << i << " is NUL or an ASCII control character other than whitespace";
  }
  if (static_cast<int64_t>(lit.size()) + 1 > t.getSize())
    return emitOpError() << "literal of " << lit.size() << " bytes and its NUL do not fit !ebpf.str_buf<" << t.getSize() << ">";
  return verifyStrBufUses(*this, getBuf());
}
LogicalResult KernelReadStrBufOp::verify() {
  if (getField().empty())
    return emitOpError() << "needs a kernel field name";
  if (failed(verifyStrBufSize(*this, getBuf().getType())))
    return failure();
  return verifyStrBufUses(*this, getBuf());
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

// ctx.func_ret reads the return value through bpf_get_func_ret — no N.
// The kind table's OPS column admits fexit only; static funcs are rejected by
// FuncOp's context-argument rule (attach-dependent meaning).
LogicalResult CtxFuncRetOp::verify() {
  auto ctx = cast<ContextType>(getCtx().getType());
  if (!bpfmlir::kindAllows(ctx.getKind(), "ctx.func_ret"))
    return emitOpError() << "program kind \"" << ctx.getKind() << "\" has no traced function return value (only "
                         << bpfmlir::kindsAllowing("ctx.func_ret") << ")";
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

// sched_ext kfunc ops of the family "insert". The op verifier checks the
// family declaration, placement, kind and types; the member a program
// implements (and so the callback allow table and sleepable) is in the schema
// and is checked by ebpf-verify-schema.
static LogicalResult verifyScxCommon(Operation *op, StringRef scxOp) {
  auto module = op->getParentOfType<ModuleOp>();
  auto family = module ? module->getAttr(bpfmlir::kScxFamilyAttr) : Attribute();
  if (!family)
    return op->emitOpError() << "needs the sched_ext kfunc family declaration: add `module attributes {"
                             << bpfmlir::kScxFamilyAttr << " = \"" << bpfmlir::kScxFamilyInsert << "\"}`";
  // The attribute value itself is checked by the dialect attribute verifier.
  Operation *top = nullptr;
  for (Operation *p = op->getParentOp(); p; p = p->getParentOp()) {
    if (isa<ProgramOp, SubprogramOp>(p)) {
      top = p;
      break;
    }
    // a timer.callback owned by sched_ext_ops programs — a closed set
    // of ScxAny ops (ScxContract.h kScxTimerCallbackOps); the callback is not
    // sleepable and is outside the dump members' context.
    if (auto cb = dyn_cast<TimerCallbackOp>(p)) {
      if (timerCallbackOwnerKind(cb) != TimerCallbackOwners::Scx)
        return op->emitOpError() << "is inside ebpf.timer.callback @" << cb.getSymName()
                                 << ", whose owners are not " << bpfmlir::kindsAllowing("scx")
                                 << " programs; sched_ext ops in a callback need sched_ext_ops owners";
      if (!bpfmlir::scxTimerCallbackAllows(scxOp)) {
        // name the callback and its owners (the context), after the text.
        std::string owners;
        for (ProgramOp owner : timerCallbackOwners(cb))
          owners += (owners.empty() ? "@" : ", @") + owner.getSymName().str();
        return op->emitOpError() << "is not allowed inside ebpf.timer.callback (a callback is not sleepable and is outside the "
                                    "dump members and the program's task arguments; it may use only "
                                 << bpfmlir::scxTimerCallbackOps() << ") — in ebpf.timer.callback @" << cb.getSymName()
                                 << " of " << owners
                                 << " (kScxTimerCallbackOps is a conservative subset of the compiler, not the kernel's filter)";
      }
      if (scxOp == "const")
        return success();
      const bpfmlir::ScxKfuncInfo *info = bpfmlir::lookupScxOp(scxOp);
      const bpfabi::KfuncABI *k = info ? bpfabi::lookupKfunc(info->kfunc) : nullptr;
      if (!k || !(info->groups & bpfmlir::ScxAny))
        return op->emitOpError() << "has no ScxAny row in ScxContract.def with a kfunc table row";
      for (ProgramOp owner : timerCallbackOwners(cb))
        if (!k->allowsProgType(programTypeOf(owner.getKind())))
          return op->emitOpError() << "kfunc \"" << info->kfunc << "\" is not registered for the owner @" << owner.getSymName()
                                   << "'s program type; the kfunc table allows " << k->progTypes;
      return success();
    }
    if (!isa<IfOp, RefCheckOp, KPtrCheckOp, KRefCheckOp, IterNumOp, IterScxDsqOp, RcuRegionOp>(p)) // iterator bodies and RCU sections too; the DSQ iterator body: kref.check regions (a kref exists only there)
      return op->emitOpError() << "is inside '" << p->getName()
                               << "'; sched_ext kfunc ops are only allowed in the body of an ebpf.program and its ebpf.if, "
                                  "ebpf.ref.check and ebpf.kptr.check regions (and ebpf.iter.num / ebpf.iter.scx_dsq / "
                                  "ebpf.rcu.region bodies, ebpf.kref.check regions)";
  }
  // in an ebpf.func the kind, the kfunc's program type and (in
  // ebpf-verify-schema) the member and sleepable rules are checked per reaching
  // context (ebpf-verify-call-contexts); here only the rows.
  if (top && isa<SubprogramOp>(top)) {
    if (scxOp == "const" || scxOp == "exit_info")
      return success();
    const bpfmlir::ScxKfuncInfo *info = bpfmlir::lookupScxOp(scxOp);
    if (!info)
      return op->emitOpError() << "has no row in ScxContract.def";
    if (!bpfabi::lookupKfunc(info->kfunc))
      return op->emitOpError() << "needs kfunc \"" << info->kfunc << "\", which is not in the kfunc table";
    return success();
  }
  auto prog = dyn_cast_or_null<ProgramOp>(top);
  if (!prog)
    return op->emitOpError() << "is outside an ebpf.program and an ebpf.func (callbacks other than a sched_ext timer callback cannot call "
                                "sched_ext kfuncs)";
  // one sched_ext op is also allowed in the kinds with its own OPS
  // tag scx.<op> (scx.dsq_reenq: tp_btf — scx_kfunc_set_any is registered for
  // TRACING; scx.now: syscall — scx_kfunc_context_filter allows the in_any
  // kfuncs for SYSCALL). The kfunc table's program types are checked below.
  if (std::string why = bpfmlir::scxKindRule(scxOp, prog.getKind()); !why.empty())
    return op->emitOpError() << why;
  if (scxOp == "const" || scxOp == "exit_info") // neither calls a kfunc.
    return success();
  const bpfmlir::ScxKfuncInfo *info = bpfmlir::lookupScxOp(scxOp);
  if (!info)
    return op->emitOpError() << "has no row in ScxContract.def";
  const bpfabi::KfuncABI *k = bpfabi::lookupKfunc(info->kfunc);
  if (!k)
    return op->emitOpError() << "needs kfunc \"" << info->kfunc << "\", which is not in the kfunc table";
  StringRef ptype = programTypeOf(prog.getKind());
  if (!k->allowsProgType(ptype))
    return op->emitOpError() << "kfunc \"" << info->kfunc << "\" is not registered for program type " << ptype
                             << "; the kfunc table allows " << k->progTypes;
  return success();
}
static LogicalResult scxTask(Operation *op, Value v) {
  auto kp = dyn_cast<KPtrType>(v.getType());
  if (!kp || kp.getStructName() != "task_struct")
    return op->emitOpError() << "takes the task as a checked !ebpf.kptr<\"task_struct\"> (pass the present value of "
                                "ebpf.kptr.check), got "
                             << v.getType();
  return success();
}
static LogicalResult scxInt(Operation *op, Value v, StringRef what, unsigned bits) {
  if (!v.getType().isSignlessInteger(bits))
    return op->emitOpError() << what << " must be i" << bits << " (no implicit extension), got " << v.getType();
  return success();
}
LogicalResult ScxDsqInsertOp::verify() {
  if (failed(verifyScxCommon(*this, "dsq_insert")) || failed(scxTask(*this, getTask())) ||
      failed(scxInt(*this, getDsq(), "dsq", 64)) || failed(scxInt(*this, getSlice(), "slice", 64)) ||
      failed(scxInt(*this, getFlags(), "flags", 64)))
    return failure();
  return success();
}
LogicalResult ScxDsqInsertVtimeOp::verify() {
  if (failed(verifyScxCommon(*this, "dsq_insert_vtime")) || failed(scxTask(*this, getTask())) ||
      failed(scxInt(*this, getDsq(), "dsq", 64)) || failed(scxInt(*this, getSlice(), "slice", 64)) ||
      failed(scxInt(*this, getVtime(), "vtime", 64)) || failed(scxInt(*this, getFlags(), "flags", 64)))
    return failure();
  return success();
}
LogicalResult ScxDsqMoveToLocalOp::verify() {
  if (failed(verifyScxCommon(*this, "dsq_move_to_local")) || failed(scxInt(*this, getDsq(), "dsq", 64)) ||
      failed(scxInt(*this, getMoved(), "the result", 1)))
    return failure();
  return success();
}
LogicalResult ScxCreateDsqOp::verify() {
  if (failed(verifyScxCommon(*this, "create_dsq")) || failed(scxInt(*this, getDsq(), "dsq", 64)) ||
      failed(scxInt(*this, getNode(), "node", 32)) || failed(scxInt(*this, getStatus(), "the result", 32)))
    return failure();
  return success();
}
LogicalResult ScxSelectCpuDflOp::verify() {
  if (failed(verifyScxCommon(*this, "select_cpu_dfl")) || failed(scxTask(*this, getTask())) ||
      failed(scxInt(*this, getPrev(), "prev", 32)) || failed(scxInt(*this, getWake(), "wake", 64)) ||
      failed(scxInt(*this, getCpu(), "the cpu result", 32)) || failed(scxInt(*this, getIdle(), "the idle result", 1)))
    return failure();
  return success();
}
LogicalResult ScxTaskSetDsqVtimeOp::verify() {
  if (failed(verifyScxCommon(*this, "task_set_dsq_vtime")) || failed(scxTask(*this, getTask())) ||
      failed(scxInt(*this, getVtime(), "vtime", 64)))
    return failure();
  return success();
}
// MAX_BPRINTF_VARARGS (include/linux/bpf.h) bounds bstr_printf arguments.
static constexpr unsigned kScxErrorMaxArgs = 12;
static LogicalResult scxFormat(Operation *op, StringRef format, ValueRange args, bool dump); // below.
LogicalResult ScxErrorOp::verify() {
  if (failed(verifyScxCommon(*this, "error")))
    return failure();
  return scxFormat(*this, getFormat(), getArgs(), /*dump=*/false);
}
LogicalResult ScxConstOp::verify() {
  if (failed(verifyScxCommon(*this, "const")))
    return failure();
  if (!bpfabi::lookupScxEnum(getName()))
    return emitOpError() << "names \"" << getName() << "\", which is not a scxenum row of the UAPI table ("
                         << bpfabi::listScxEnums() << ")";
  return scxInt(*this, getValue(), "the result", 64);
}
// the kind-independent CO-RE enum read. The pair must be a scxenum row
// (its value is the relocation's local value); placement is that of arith.
LogicalResult CoreEnumValueOp::verify() {
  const bpfabi::ScxEnumABI *e = bpfabi::lookupScxEnum(getName());
  if (!e)
    return emitOpError() << "names \"" << getName() << "\", which is not a scxenum row of the UAPI table ("
                         << bpfabi::listScxEnums() << ")";
  if (e->enumName != getEnumName())
    return emitOpError() << "names " << getName() << " of enum \"" << getEnumName() << "\", but the UAPI table's scxenum row has it in enum \""
                         << e->enumName << "\"";
  return success(); // ebpf.spin.region's own allowed set rejects it there.
}
LogicalResult ScxExitInfoOp::verify() {
  if (failed(verifyScxCommon(*this, "exit_info")))
    return failure();
  if (getInfo().getType().getStructName() != "scx_exit_info")
    return emitOpError() << "takes the exit info as !ebpf.kptr<\"scx_exit_info\">, got " << getInfo().getType();
  return success();
}

//. The RCU-section and member rules need the schema
// (sleepable, member) and are in ebpf-verify-schema.
// MAX_BPRINTF_BIN_ARGS (7.3.1 include/linux/bpf.h:4121, 7.1.8 :3883,
// 6.12.111 kernel/bpf/helpers.c:764) bounds the bytes bpf_bprintf_prepare
// copies for one format; past it the kfunc fails with -ENOSPC and
// __bstr_format calls scx_error (7.3.1 ext.c:10093-10097).
static constexpr unsigned kScxBinArgsMax = 512;

// the classification scan of the whole format — never stops at an
// unsupported conversion, so a %p or %q cannot hide a later %s. After '%'
// ("%%" skipped) it skips the [0 +-] flags and the width and looks at one
// character: 's' is a real %s (with or without width), 'p' starts the %p
// family (%ps / %pks / %pus are not %s), '%' or the end is ambiguous (the
// kernel's -EINVAL), anything else is some other conversion.
namespace {
struct ScxFormatClass {
  bool realS = false, ambiguous = false;
};
} // namespace
static ScxFormatClass classifyScxFormat(StringRef f) {
  ScxFormatClass c;
  for (size_t i = 0; i < f.size(); ++i) {
    if (f[i] != '%')
      continue;
    if (i + 1 < f.size() && f[i + 1] == '%') {
      ++i;
      continue;
    }
    size_t j = i + 1;
    while (j < f.size() && (f[j] == '0' || f[j] == '+' || f[j] == '-' || f[j] == ' '))
      ++j;
    while (j < f.size() && f[j] >= '0' && f[j] <= '9')
      ++j;
    if (j >= f.size() || f[j] == '%')
      c.ambiguous = true;
    else if (f[j] == 's')
      c.realS = true;
    i = j < f.size() && f[j] == '%' ? j - 1 : j;
  }
  return c;
}

// the strict parser — a closed subset of bpf_bprintf_prepare's
// grammar (7.3.1 helpers.c:846-1049, the same in 7.1.8 and 6.12.111): plain
// text without non-whitespace ASCII control bytes (:854-857), "%%", and a
// conversion of [0 +-]* flags, an optional [1-9][0-9]* width, then either 's'
// (followed by NUL, whitespace or punctuation:975-980) or l{0,2} and one of
// i d u x X (:1019-1036). The %p family and %c are kernel conversions this
// compiler does not open: their bin_args size has no bound in the formula
// (%pB / %pi6 expand to text:912-967; %pks / %pus copy up to the rest).
namespace {
struct ScxConv {
  bool str;  // %s
  unsigned w; // integer bytes (4 or 8); 0 for %s
};
} // namespace
static LogicalResult parseScxFormatStrict(Operation *op, StringRef f, SmallVectorImpl<ScxConv> &out) {
  auto isCtl = [](unsigned char c) { return c < 0x80 && !llvm::isPrint(c) && !llvm::isSpace(c); };
  for (size_t i = 0; i < f.size(); ++i) {
    if (isCtl(f[i]))
      return op->emitOpError() << "format byte " << i << " is an ASCII control character other than whitespace (bpf_bprintf_prepare rejects it)";
    if (f[i] != '%')
      continue;
    if (i + 1 < f.size() && f[i + 1] == '%') {
      ++i;
      continue;
    }
    size_t at = i, j = i + 1;
    while (j < f.size() && (f[j] == '0' || f[j] == '+' || f[j] == '-' || f[j] == ' '))
      ++j;
    if (j < f.size() && f[j] >= '1' && f[j] <= '9')
      while (j < f.size() && f[j] >= '0' && f[j] <= '9')
        ++j;
    auto bad = [&](StringRef why) {
      return op->emitOpError() << "format conversion at byte " << at << " (\"" << f.substr(at, std::min<size_t>(j + 1, f.size()) - at)
                               << "\") " << why
                               << "; a format with %s or a !ebpf.str_buf argument allows only %%, [0 +-] flags, a width, %s and "
                                  "%[l[l]]{i,d,u,x,X}";
    };
    if (j >= f.size())
      return bad("ends the format");
    char c = f[j];
    if (c == 's') {
      if (j + 1 < f.size() && !llvm::isSpace(f[j + 1]) && !llvm::isPunct(f[j + 1]))
        return bad("is followed by a byte that is not NUL, whitespace or punctuation (the kernel accepts %s only before NUL, whitespace or punctuation)");
      out.push_back({true, 0});
      i = j;
      continue;
    }
    if (c == 'p')
      return bad("is in the %p family, which this compiler does not open");
    if (c == 'c')
      return bad("is %c, which this compiler does not open");
    if (c == '.')
      return bad("has a precision, which the kernel does not accept");
    unsigned w = 4;
    if (c == 'l') {
      w = 8, ++j;
      if (j < f.size() && f[j] == 'l')
        ++j;
    }
    if (j >= f.size() || !StringRef("iduxX").contains(f[j]))
      return bad("is not a conversion the kernel accepts");
    out.push_back({false, w});
    i = j;
  }
  return success();
}

static LogicalResult scxFormat(Operation *op, StringRef format, ValueRange args, bool dump) {
  if (format.empty() || format.contains('\0'))
    return op->emitOpError("needs a non-empty format literal without NUL bytes");
  if (args.size() > kScxErrorMaxArgs)
    return op->emitOpError() << "takes at most " << kScxErrorMaxArgs << " arguments (MAX_BPRINTF_VARARGS), got " << args.size();
  ScxFormatClass cls = classifyScxFormat(format);
  bool strBuf = llvm::any_of(args, [](Value a) { return isa<StrBufType>(a.getType()); });
  if (!strBuf && !cls.realS && !cls.ambiguous) { // The pre-path, unchanged.
    for (auto [i, a] : llvm::enumerate(args))
      if (failed(scxInt(op, a, "argument " + std::to_string(i), 64)))
        return failure();
    return success();
  }
  if (!dump)
    return op->emitOpError() << (strBuf ? "takes a !ebpf.str_buf argument" : "has a %s conversion (or an ambiguous '%')")
                             << "; %s and !ebpf.str_buf are only for ebpf.scx.dump";
  SmallVector<ScxConv> convs;
  if (failed(parseScxFormatStrict(op, format, convs)))
    return failure();
  if (convs.size() != args.size())
    return op->emitOpError() << "format has " << convs.size() << " conversion(s) but " << args.size()
                             << " argument(s); a format with %s or a !ebpf.str_buf argument needs exactly one argument per conversion";
  unsigned bin = 0;
  for (auto [i, cv] : llvm::enumerate(convs)) {
    Value a = args[i];
    if (cv.str) {
      auto sb = dyn_cast<StrBufType>(a.getType());
      if (!sb)
        return op->emitOpError() << "argument " << i << " is at a %s conversion and must be a !ebpf.str_buf, got " << a.getType();
      bin += static_cast<unsigned>(sb.getSize());
      continue;
    }
    if (isa<StrBufType>(a.getType()))
      return op->emitOpError() << "argument " << i << " is a !ebpf.str_buf at a non-%s conversion (only %s takes a string buffer)";
    if (failed(scxInt(op, a, "argument " + std::to_string(i), 64)))
      return failure();
    bin += 3 + cv.w; // 4-byte alignment (helpers.c:1040) and the value.
  }
  if (bin > kScxBinArgsMax)
    return op->emitOpError() << "may need up to " << bin << " bytes of bpf_bprintf_prepare bin_args (each %s its str_buf size, each "
                                                         "integer 3 + 4 / 8), over MAX_BPRINTF_BIN_ARGS "
                             << kScxBinArgsMax << " (the kernel fails the dump with -ENOSPC and scx_error)";
  return success();
}
static LogicalResult scxRcuTask(Operation *op, Type t, StringRef what) {
  auto r = dyn_cast<RcuPtrOrNullType>(t);
  if (!r || r.getStructName() != "task_struct")
    return op->emitOpError() << what << " must be !ebpf.rcu_ptr_or_null<\"task_struct\"> (KF_RCU_PROTECTED | KF_RET_NULL), got " << t;
  return success();
}
// The nullable operand that v is the checked form of, if any: the kptr.check
// present argument (①) or its ② expansion, assume_present.
static Value scxCheckedFrom(Value v) {
  if (auto ap = v.getDefiningOp<AssumePresentOp>())
    return ap.getValue();
  auto ba = dyn_cast<BlockArgument>(v);
  if (!ba)
    return {};
  auto kc = dyn_cast_or_null<KPtrCheckOp>(ba.getOwner()->getParentOp());
  if (!kc || ba.getOwner() != &kc.getPresentRegion().front())
    return {};
  return kc.getPtr();
}
LogicalResult ScxTaskCpuOp::verify() {
  if (failed(verifyScxCommon(*this, "task_cpu")))
    return failure();
  Type t = getTask().getType();
  auto kp = dyn_cast<KPtrType>(t);
  auto rp = dyn_cast<RcuPtrType>(t);
  auto kr = dyn_cast<KRefType>(t); // a referenced task is trusted (KF_RCU takes it).
  if (!((kp && kp.getStructName() == "task_struct") || (rp && rp.getStructName() == "task_struct") ||
        (kr && kr.getStructName() == "task_struct")))
    return emitOpError() << "takes the task as a checked !ebpf.kptr<\"task_struct\"> or !ebpf.rcu_ptr<\"task_struct\"> (KF_RCU), got " << t;
  return scxInt(*this, getCpu(), "the result", 32);
}
LogicalResult ScxKickCpuOp::verify() {
  if (failed(verifyScxCommon(*this, "kick_cpu")) || failed(scxInt(*this, getCpu(), "cpu", 32)) ||
      failed(scxInt(*this, getFlags(), "flags", 64)))
    return failure();
  return success();
}
LogicalResult ScxDsqNrQueuedOp::verify() {
  if (failed(verifyScxCommon(*this, "dsq_nr_queued")) || failed(scxInt(*this, getDsq(), "dsq", 64)) ||
      failed(scxInt(*this, getCount(), "the result", 32)))
    return failure();
  return success();
}
LogicalResult ScxDsqPeekOp::verify() {
  if (failed(verifyScxCommon(*this, "dsq_peek")) || failed(scxInt(*this, getDsq(), "dsq", 64)) ||
      failed(scxRcuTask(*this, getTask().getType(), "the result")))
    return failure();
  return success();
}
LogicalResult ScxTaskSetSliceOp::verify() {
  if (failed(verifyScxCommon(*this, "task_set_slice")) || failed(scxTask(*this, getTask())) ||
      failed(scxInt(*this, getSlice(), "slice", 64)))
    return failure();
  return success();
}
LogicalResult ScxNowOp::verify() {
  if (failed(verifyScxCommon(*this, "now")))
    return failure();
  return scxInt(*this, getNs(), "the result", 64);
}
LogicalResult ScxPickIdleCpuOp::verify() {
  if (failed(verifyScxCommon(*this, "pick_idle_cpu")) || failed(scxInt(*this, getFlags(), "flags", 64)) ||
      failed(scxInt(*this, getCpu(), "the result", 32)))
    return failure();
  auto cm = dyn_cast<KPtrType>(getCpus().getType());
  if (!cm || cm.getStructName() != "cpumask")
    return emitOpError() << "takes the cpumask as a checked !ebpf.kptr<\"cpumask\">, got " << getCpus().getType();
  // Only a callback-argument task's cpus_ptr: ctx.arg -> kptr.check ->
  // kfield.ptr "cpus_ptr" -> kptr.check (no other cpumask in B1).
  Value nullable = scxCheckedFrom(getCpus());
  auto fp = nullable ? nullable.getDefiningOp<KFieldPtrOp>() : KFieldPtrOp();
  Value taskNullable = fp && fp.getField() == "cpus_ptr" ? scxCheckedFrom(fp.getPtr()) : Value();
  auto arg = taskNullable ? taskNullable.getDefiningOp<CtxArgOp>() : CtxArgOp();
  if (!arg || cast<KPtrType>(fp.getPtr().getType()).getStructName() != "task_struct")
    return emitOpError() << "takes only the cpumask of a callback-argument task: the checked result of "
                            "`ebpf.kfield.ptr %t \"cpus_ptr\"` where %t is the checked !ebpf.kptr<\"task_struct\"> of an ebpf.ctx.arg";
  return success();
}
LogicalResult ScxCpuCurrOp::verify() {
  if (failed(verifyScxCommon(*this, "cpu_curr")) || failed(scxInt(*this, getCpu(), "cpu", 32)) ||
      failed(scxRcuTask(*this, getTask().getType(), "the result")))
    return failure();
  return success();
}
LogicalResult ScxCpuperfCapOp::verify() {
  if (failed(verifyScxCommon(*this, "cpuperf_cap")) || failed(scxInt(*this, getCpu(), "cpu", 32)) ||
      failed(scxInt(*this, getCap(), "the result", 32)))
    return failure();
  return success();
}
LogicalResult ScxCpuperfSetOp::verify() {
  if (failed(verifyScxCommon(*this, "cpuperf_set")) || failed(scxInt(*this, getCpu(), "cpu", 32)) ||
      failed(scxInt(*this, getPerf(), "perf", 32)))
    return failure();
  return success();
}
LogicalResult ScxDsqReenqOp::verify() {
  if (failed(verifyScxCommon(*this, "dsq_reenq")) || failed(scxInt(*this, getDsq(), "dsq", 64)) ||
      failed(scxInt(*this, getFlags(), "flags", 64)))
    return failure();
  APInt c;
  if (!matchPattern(getFlags(), m_ConstantInt(&c)) || !c.isZero())
    return emitOpError() << "takes reenq flags only as an arith.constant 0 (the SCX_REENQ_* flags are not supported)";
  return success();
}
LogicalResult ScxExitOp::verify() {
  if (failed(verifyScxCommon(*this, "exit")) || failed(scxInt(*this, getCode(), "the exit code", 64)))
    return failure();
  return scxFormat(*this, getFormat(), getArgs(), /*dump=*/false);
}
LogicalResult ScxDumpOp::verify() {
  if (failed(verifyScxCommon(*this, "dump")))
    return failure();
  return scxFormat(*this, getFormat(), getArgs(), /*dump=*/true);
}

// The only module attribute the dialect checks is the sched_ext family; other
// ebpf.* attributes (compiler-internal markers) are accepted unchanged.
LogicalResult EBPFDialect::verifyOperationAttribute(Operation *op, NamedAttribute attr) {
  if (attr.getName() != bpfmlir::kScxFamilyAttr)
    return success();
  if (!isa<ModuleOp>(op))
    return op->emitError() << attr.getName().getValue() << " is a module attribute";
  auto s = dyn_cast<StringAttr>(attr.getValue());
  if (!s || s.getValue() != bpfmlir::kScxFamilyInsert)
    return op->emitError() << attr.getName().getValue() << " = " << attr.getValue()
                           << " is not a sched_ext kfunc family this compiler has (it has \"" << bpfmlir::kScxFamilyInsert << "\")";
  return success();
}

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
    if (isa<GlobalLoadOp, GlobalAtomicAddOp, KtimeOp, CoreEnumValueOp>(op)) // CoreEnumValueOp.
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

// global cmpxchg / or share the BPF atomic widths (32 / 64);
// ebpf-verify-schema owns the .bss integer global rule.
static LogicalResult checkAtomicWidth(Operation *op, Type t, StringRef what) {
  if (!t.isInteger(32) && !t.isInteger(64))
    return op->emitOpError() << what << " is 32 or 64 bits (BPF atomic), got " << t;
  return success();
}
LogicalResult GlobalCmpxchgOp::verify() { return checkAtomicWidth(*this, getOld().getType(), "atomic compare-and-exchange"); }
LogicalResult GlobalAtomicOrOp::verify() { return checkAtomicWidth(*this, getValue().getType(), "atomic or"); }

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
  if (!isa<MaybeRefType, MaybeReservationType, KPtrOrNullType, RcuPtrOrNullType, KRefOrNullType, SockRefOrNullType>(t)) // kptr.check and kref.check.
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
  if (auto m = dyn_cast<RcuPtrOrNullType>(in)) { // present rcu_ptr from kptr.check.
    auto k = dyn_cast<RcuPtrType>(out);
    if (!k || k.getStructName() != m.getStructName())
      return emitOpError() << "a checked " << in << " must become !ebpf.rcu_ptr<\"" << m.getStructName() << "\">, got " << out;
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
        isa<RefLoadOp, RefFieldLoadOp, RefStoreOp, RefFieldStoreOp, RefAtomicAddOp, RefFieldAtomicAddOp, RefFieldCmpxchgOp, RefFieldAtomicOrOp, CallOp>(user))
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
      if (isa<CtxArgOp, CtxRetvalOp, CtxFuncRetOp, CtxFuncIpOp,
              CtxFuncArgOp, CtxFuncArgCntOp, KprobeArgOp, UprobeArgOp>(user))
        return emitOpError() << "context argument #" << i << " is used by '" << user->getName()
                             << "', whose meaning depends on the attach point (the function signature or the tracepoint); "
                                "read it in the program and pass the value as an integer";
      if (isa<XdpAdjustHeadOp, XdpAdjustMetaOp, XdpAdjustTailOp, TailCallOp, TailCallTryOp, LwtSeg6StoreBytesOp, LwtSeg6AdjustSrhOp, LwtSeg6ActionOp,
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
    // struct_ops members such as tcp_congestion_ops.get_info return size_t
    // VerifySchema matches the width against the schema ret.
    bool extRet = !bpfmlir::entryTakesCtx(k->attach) || k->sig == bpfmlir::SigFamily::OpsSig;
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
    CalleeArgSet seen;
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
// the ref.field.atomic_add rules (VerifyRecords owns path / width /
// alignment agreement).
LogicalResult RefFieldCmpxchgOp::verify() {
  if (failed(checkRecordBorrow(*this, getRef().getType())) || failed(checkNotLpmValue(*this, getRef())))
    return failure();
  return checkAtomicWidth(*this, getOld().getType(), "atomic compare-and-exchange");
}
LogicalResult RefFieldAtomicOrOp::verify() {
  if (failed(checkRecordBorrow(*this, getRef().getType())) || failed(checkNotLpmValue(*this, getRef())))
    return failure();
  return checkAtomicWidth(*this, getValue().getType(), "atomic or");
}

// the address of an embedded cpumask field (VerifyRecords matches the
// path to a cpumask field of the result's size). The address is used only as a
// struct argument of a kfunc.call (whose verifier checks the kfunc), within
// the region of the op — never yielded, stored, passed to ebpf.call or carried.
LogicalResult RefFieldAddrOp::verify() {
  if (failed(checkRecordBorrow(*this, getRef().getType())) || failed(checkNotLpmValue(*this, getRef())))
    return failure();
  if (getAddr().getType().getSize() <= 0 || getAddr().getType().getSize() % 8 != 0)
    return emitOpError() << "the cpumask size must be a positive multiple of 8, got " << getAddr().getType();
  for (OpOperand &use : getAddr().getUses()) {
    Operation *u = use.getOwner();
    if (!isa<KfuncCallOp>(u))
      return emitOpError() << "an embedded cpumask address may only be passed to ebpf.kfunc.call, but it is used by '" << u->getName()
                           << "' (it must not escape the borrow)";
    if (!(*this)->getParentRegion()->isAncestor(u->getParentRegion()))
      return emitOpError() << "an embedded cpumask address must be used in the region of its ebpf.ref.field.addr";
  }
  return success();
}

// a record global borrow; the schema (ebpf-verify-schema) owns the
// section, the record shape and the read-only rule of .rodata.
LogicalResult GlobalRefOp::verify() {
  auto b = cast<BorrowedType>(getRef().getType());
  if (!isa<RecordType>(b.getPointee()))
    return emitOpError() << "borrows " << b.getPointee() << "; a global borrow is a record (!ebpf.borrowed<!ebpf.record<…>>) — integer globals use ebpf.global.load / store";
  return success();
}

// a bss kaddr global reads as an untrusted kernel address.
LogicalResult GlobalLoadOp::verify() {
  if (isa<KAddrType>(getResult().getType()))
    return verifyKAddrUses(getResult(), "global value");
  return success();
}

// Loops.
namespace {
// Unrolled IR-copy cost bound.
constexpr uint64_t kMaxUnrolledOps = 4096;
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
  return isa<SkbLoadBytesOp, SkbLoadBytesRelativeOp, SkbAdjustRoomOp, TracePrintkOp,
             SkRedirectRequestOp, MapLookupOp, MapUpdateOp, MapAtomicAddOp,
             RefCheckOp, YieldOp, RefLoadOp, RefStoreOp, RefAtomicAddOp,
             RefFieldLoadOp, RefFieldStoreOp, RefFieldAtomicAddOp, RefFieldCmpxchgOp, RefFieldAtomicOrOp, PacketLoadOp,
             KtimeOp, LoopYieldOp, IfOp, IfYieldOp, BreakOp, ContinueOp, LoopOp,
             CallOp, RecordMakeOp, MapTryUpdateOp, MapTryDeleteOp,
             ByteorderToBeOp, ByteorderFromBeOp, RefIndexOp, ElemLoadOp,
             ElemStoreOp, TaskPidTgidOp, TaskCgroupIdOp, TaskUnderCgroupOp,
             SkbUnderCgroupOp, CtxRetvalOp, CtxFuncRetOp,
             CtxFuncIpOp, CtxFuncArgOp, CtxFuncArgCntOp, CgroupRetvalOp,
             CgroupSetRetvalOp, TaskNsPidTgidOp, TaskSendSignalOp, TaskSendSignalThreadOp,
             GlobalLoadOp, GlobalAtomicAddOp, GlobalCmpxchgOp, GlobalAtomicOrOp, GlobalStoreOp,
             KprobeArgOp, UprobeArgOp,
             // callbacks are rejected by each op's verifier.
             CpuIdOp, RandomU32Op, NumaNodeIdOp, TaskUidGidOp, Jiffies64Op,
             KtimeBootNsOp, KtimeCoarseNsOp, KtimeTaiNsOp,
             TaskAncestorCgroupIdOp, TaskCurrentRawOp, CoreEnumValueOp /* */,
             IterNumOp /* its body is checked by IterNumOp::verify */, IterScxDsqOp /* rejects an enclosing loop by name */,
             GlobalRefOp /* borrowed in each iteration; callback loops (H) and map.for_each reject it by name */>(op);
}

// Capture integers, context and map handles only. References, reservations
// and kernel pointers must remain within each iteration.
bool capturable(Type t) {
  return isa<IntegerType, IndexType, ContextType, MapType>(t);
}
} // namespace

// the first ebpf.global.ref a subprogram reaches
// through its own body and the subprograms it calls (any depth). `path`
// receives the callee chain for the diagnostic; `seen` stops at a revisit.
static GlobalRefOp reachedGlobalRef(SymbolTableCollection &st, SubprogramOp fn,
                                    llvm::SmallPtrSetImpl<Operation *> &seen,
                                    SmallVectorImpl<StringRef> &path) {
  if (!fn || !seen.insert(fn).second)
    return {};
  path.push_back(fn.getSymName());
  GlobalRefOp found;
  fn.walk([&](Operation *op) {
    if (auto g = dyn_cast<GlobalRefOp>(op)) {
      found = g;
      return WalkResult::interrupt();
    }
    if (auto call = dyn_cast<CallOp>(op)) {
      auto t = dyn_cast_or_null<SubprogramOp>(st.lookupNearestSymbolFrom(call, call.getCalleeAttr()));
      if ((found = reachedGlobalRef(st, t, seen, path)))
        return WalkResult::interrupt();
    }
    return WalkResult::advance();
  });
  if (!found)
    path.pop_back();
  return found;
}

LogicalResult LoopOp::verify() {
  int64_t n = getCount();
  int64_t countLimit = LoopBudget::countLimit(getUnroll(), getCallback());
  if (n < 0 || n > countLimit)
    return emitOpError() << "count " << n << " is out of the range this compiler supports (0.."
                         << countLimit << ")";
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
  LoopBudget budget = LoopBudget{}.enter(n, getUnroll(), getCallback());
  // an enclosing ebpf.iter.num adds depth but no count factor.
  // so does an enclosing ebpf.iter.scx_dsq (its body
  // rejects ebpf.loop by name first — counted here for the one depth rule).
  for (Operation *p = (*this)->getParentOp(); p; p = p->getParentOp()) {
    if (auto outer = dyn_cast<LoopOp>(p))
      budget = budget.enter(outer.getCount(), outer.getUnroll(), outer.getCallback());
    else if (isa<IterNumOp, IterScxDsqOp>(p))
      budget = budget.enterIter();
  }
  if (budget.depth > LoopBudget::maxDepth)
    return emitOpError() << "is nested " << budget.depth << " deep; this compiler supports loops nested "
                         << LoopBudget::maxDepth << " deep";
  if (budget.product > budget.productLimit())
    return emitOpError() << "the counts along the nest multiply to " << budget.product
                         << ", over the limit of " << budget.productLimit()
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
    // a bpf_loop callback driven from inside an iterator body is not supported.
    if ((*this)->getParentOfType<IterNumOp>())
      return emitOpError() << "a callback loop (H) inside ebpf.iter.num is not supported (use a loop without callback)";
  }

  Region *self = &getBody();
  WalkResult w = getBody().walk([&](Operation *op) {
    // ops inside a nested ebpf.iter.num follow that iterator's rules (IterNumOp::verify).
    if (auto inner = op->getParentOfType<IterNumOp>(); inner && self->isAncestor(inner->getParentRegion()))
      return WalkResult::advance();
    // likewise the DSQ iterator (it rejects the enclosing loop itself).
    if (auto inner = op->getParentOfType<IterScxDsqOp>(); inner && self->isAncestor(inner->getParentRegion()))
      return WalkResult::advance();
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
    // arena ops follow packet.check's rule (every enclosing loop unroll).
    // In a callback loop (H) the op's own verifier names the placement (the
    // callback body is a separate function) — skip it here.
    bool arenaWalk = isa<ArenaBaseOp, ArenaCheckOp, ArenaLoadOp, ArenaStoreOp>(op);
    if (arenaWalk && cb)
      return WalkResult::advance();
    if (arenaWalk && !getUnroll()) {
      op->emitOpError() << "is only supported inside an unroll ebpf.loop (the unrolled copies have no cycle); "
                           "a loop without unroll (B) cannot hold it yet — use unroll";
      return WalkResult::interrupt();
    }
    // Capture rules also apply to packet operations; windows cannot enter from outside loops.
    if (!packetWalk && !arenaWalk && !allowedInLoop(op)) {
      op->emitOpError() << "is not allowed inside ebpf.loop (arith, scf.if, map "
                           "lookup / update, ref.check and reads / writes of a checked "
                           "reference, packet.load, ktime.ns: ebpf.if, ebpf.break, "
                           "ebpf.continue: ebpf.loop to depth 2: ebpf.call to a subprogram "
                           "that reaches no ring buffer op (the callee's loops are checked on the call path): ebpf.record.make)";
      return WalkResult::interrupt();
    }
    // a record global is borrowed inside a (B) / (U)
    // loop body; a callback loop (H) becomes a separate function and is not
    // opened for it (is out of scope).
    if (cb && isa<GlobalRefOp>(op)) {
      op->emitOpError() << "is not allowed inside a callback loop (H) — borrow the record global in a loop without callback";
      return WalkResult::interrupt();
    }
    // nor through a call from the callback body.
    if (cb)
      if (auto call = dyn_cast<CallOp>(op)) {
        SymbolTableCollection st;
        llvm::SmallPtrSet<Operation *, 8> seen;
        SmallVector<StringRef> path;
        auto t = dyn_cast_or_null<SubprogramOp>(st.lookupNearestSymbolFrom(call, call.getCalleeAttr()));
        if (GlobalRefOp g = reachedGlobalRef(st, t, seen, path)) {
          op->emitOpError() << "reaches ebpf.global.ref @" << g.getName() << " through @"
                                     << llvm::join(path, " -> @")
                                     << " from a callback loop (H) — call it from a loop without callback";
          return WalkResult::interrupt();
        }
      }
    for (Value v : op->getOperands()) {
      Region *def = v.getParentRegion();
      if (self->isAncestor(def))
        continue;
      // Helper callback bodies become separate functions: capture integers into
        // context slots and rebind map handles by symbol, nothing else.
      if (cb ? isa<IntegerType, MapType>(v.getType()) : capturable(v.getType()))
        continue;
      // the arena window base is a scalar; a loop without callback may
      // capture it (a window may not — arena.check names that capture).
      if (!cb && isa<ArenaBaseType>(v.getType()))
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

// ops that may sleep (SleepableOps.def).
bool mlir::ebpf::opMightSleep(Operation *op) {
#define EBPF_SLEEPABLE_OP(OPCLASS, CALLEE) if (isa<OPCLASS>(op)) return true;
#include "bpf-mlir/Support/SleepableOps.def"
#undef EBPF_SLEEPABLE_OP
  return false;
}

namespace {
// the place of ebpf.iter.num / ebpf.rcu.region — an ebpf.program body,
// through ebpf.if / ref.check / kptr.check / kref.check / ebpf.loop without
// callback / ebpf.iter.num / ebpf.rcu.region. Callbacks, map.for_each and
// spin.region are rejected (the iterator's destroy and the section's unlock are
// checked region-locally). an ebpf.func body is a place too — the region
// closes inside the function (never across a call); the kind and the kfunc's
// program type are checked per reaching context by ebpf-verify-call-contexts.
// Returns the enclosing ProgramOp or SubprogramOp.
FailureOr<Operation *> closedRegionOwner(Operation *op, StringRef what) {
  for (Operation *p = op->getParentOp(); p; p = p->getParentOp()) {
    // a sched_ext_ops owner's timer callback body is a place like an
    // ebpf.func body (the region closes in the callback; kind and program type
    // per owner context). Other timer callbacks are rejected below.
    if (isOpsTop(p))
      return p;
    auto loop = dyn_cast<LoopOp>(p);
    if ((loop && loop.getCallback()) || isa<MapForEachOp, SpinRegionOp, TimerCallbackOp, UserRingbufCallbackOp>(p) ||
        p->getName().getStringRef() == "scf.if") {
      op->emitOpError() << "is inside '" << p->getName() << "'; " << what
                        << " is only allowed in an ebpf.program body or an ebpf.func body (callbacks, map.for_each, spin.region "
                           "and scf.if cannot hold it — the compiler checks it region-locally)";
      return failure();
    }
  }
  op->emitOpError() << "is outside an ebpf.program and an ebpf.func; " << what
                    << " is only allowed in an ebpf.program body or an ebpf.func body";
  return failure();
}

LogicalResult closedRegionKfunc(Operation *op, ProgramOp prog, StringRef kfunc) {
  const bpfabi::KfuncABI *k = bpfabi::lookupKfunc(kfunc);
  if (!k)
    return op->emitOpError() << "needs the kfunc \"" << kfunc << "\", which is not in the kfunc table";
  StringRef ptype = programTypeOf(prog.getKind());
  if (!k->allowsProgType(ptype))
    return op->emitOpError() << "lowers to the kfunc \"" << kfunc << "\", which is not registered for program type " << ptype
                             << " (kind \"" << prog.getKind() << "\"); the kfunc table allows " << k->progTypes;
  return success();
}

// the ebpf.iter.num body allowlist — the ebpf.loop allowlist plus
// kfunc.call (acquire / release only inside an rcu.region with no iterator or
// loop in between — checked by the op), kref.check / kptr.xchg (same rule),
// kptr.check, kfield.load, the sched_ext ops and ebpf.rcu.region.
bool allowedInIter(Operation *op) {
  if (allowedInLoop(op))
    return true;
  if (op->getName().getStringRef().starts_with("ebpf.scx."))
    return true;
  return isa<KfuncCallOp, KRefCheckOp, KPtrXchgOp, KPtrLoadRcuOp, GlobalKPtrXchgOp, GlobalKPtrLoadRcuOp, KPtrCheckOp, KFieldLoadOp, RcuRegionOp,
             IterYieldOp>(op); // kptr.load_rcu too; the kptr global ops
}
} // namespace

// acquire / release, kref.check and kptr.xchg are allowed
// in an iterator only when an ebpf.rcu.region lies between the op and every
// enclosing ebpf.iter.num (iter → rcu.region → acquire), so the reference
// closes in that section; directly in an iterator body (and rcu.region →
// iter → acquire) is rejected.
// the one exception — in an ebpf.iter.scx_dsq body (the body runs
// inside the RCU section the iterator needs), acquire / release kfuncs and
// kref.check are allowed directly. limited it to bpf_task_from_pid, its
// kref.check and bpf_task_release; takes any kfunc
// acquire / release and kref.check (LAVD's scx_bpf_get_online_cpumask /
// scx_bpf_put_cpumask in find_cpu_in) — that each reference closes on every
// path of the iteration (release before break / continue / the iteration's
// end) is ebpf-verify-ownership's path check. kptr.xchg stays rejected (the
// body's allowlist rejects it first). The rule is per nearest region: an
// ebpf.iter.num nested in the body applies the rule below.
static bool scxDsqRefOp(Operation *op) { return isa<KfuncCallOp, KRefCheckOp>(op); }

static LogicalResult verifyOwnershipInIter(Operation *op, StringRef what) {
  // an ebpf.func body closes the walk like a program body; the regions of
  // its callers' call sites are checked per context (ebpf-verify-call-contexts).
  for (Operation *p = op->getParentOp(); p && !isOpsTop(p); p = p->getParentOp()) {
    if (isa<RcuRegionOp>(p))
      return success();
    if (isa<IterScxDsqOp>(p)) {
      if (scxDsqRefOp(op))
        return success();
      return op->emitOpError() << what
                               << " directly in an ebpf.iter.scx_dsq body; only kfunc acquire / release and ebpf.kref.check "
                                  "may take and release a reference there, closed in the iteration (the iterator rule's "
                                  "one exception)";
    }
    if (isa<IterNumOp>(p))
      return op->emitOpError() << what
                               << " directly in an ebpf.iter.num body; inside an iterator a kernel reference may only be taken and "
                                  "released in an ebpf.rcu.region with no iterator or loop in between (the reference closes in "
                                  "that section)";
  }
  return success();
}

LogicalResult IterNumOp::verify() {
  for (Type t : getInits().getTypes())
    if (!isLoopScalar(t))
      return emitOpError() << "a carried value must be i8 / i16 / i32 / i64, got " << t;
  if (TypeRange(getInits().getTypes()) != TypeRange(getResults().getTypes()))
    return emitOpError() << "results must have the types of the carried values";
  Block &body = getBody().front();
  if (body.getNumArguments() != getInits().size() + 1 || !body.getArgument(0).getType().isSignlessInteger(32))
    return emitOpError() << "the body must take the index (i32) followed by the carried values";
  for (auto [a, t] : llvm::zip(body.getArguments().drop_front(), getInits().getTypes()))
    if (a.getType() != t)
      return emitOpError() << "body argument type " << a.getType() << " does not match the carried value type " << t;
  auto y = dyn_cast<IterYieldOp>(body.getTerminator());
  if (!y || TypeRange(y.getValues().getTypes()) != TypeRange(getInits().getTypes()))
    return emitOpError() << "the body must end with ebpf.iter.yield of the carried types";
  // H3 (a): ebpf.loop and ebpf.iter.num nest at most 2 deep together.
  // an enclosing ebpf.iter.scx_dsq counts one level
  // too (the DSQ iterator's body holds one ebpf.iter.num; a third level is
  // named with the text and a note on the DSQ iterator).
  LoopBudget budget = LoopBudget{}.enterIter();
  bool underScxDsq = false;
  for (Operation *p = (*this)->getParentOp(); p; p = p->getParentOp()) {
    if (auto outer = dyn_cast<LoopOp>(p))
      budget = budget.enter(outer.getCount(), outer.getUnroll(), outer.getCallback());
    else if (isa<IterNumOp>(p))
      budget = budget.enterIter();
    else if (isa<IterScxDsqOp>(p)) {
      budget = budget.enterIter();
      underScxDsq = true;
    }
  }
  if (budget.depth > LoopBudget::maxDepth) {
    auto d = emitOpError() << "is nested " << budget.depth << " deep (ebpf.loop and ebpf.iter.num count together); this compiler "
                              "supports "
                           << LoopBudget::maxDepth;
    if (underScxDsq)
      d << " (an enclosing ebpf.iter.scx_dsq counts as one level too)";
    return d;
  }
  FailureOr<Operation *> owner = closedRegionOwner(*this, "ebpf.iter.num");
  if (failed(owner))
    return failure();
  if (auto prog = dyn_cast<ProgramOp>(*owner); prog && failed(closedRegionKfunc(*this, prog, "bpf_iter_num_new")))
    return failure(); // In an ebpf.func: per reaching context (ebpf-verify-call-contexts).
  Region *self = &getBody();
  WalkResult w = getBody().walk([&](Operation *op) {
    // Ops of a nested iterator follow that iterator's verifier.
    if (auto inner = op->getParentOfType<IterNumOp>(); inner && inner != *this && self->isAncestor(inner->getParentRegion()))
      return WalkResult::advance();
    if (!allowedInIter(op)) {
      op->emitOpError() << "is not allowed inside ebpf.iter.num (the ebpf.loop body ops, kfunc.call, kptr.check, kfield.load, the "
                           "sched_ext ops and ebpf.rcu.region; packet.check, window_load and ring buffer ops are rejected)";
      return WalkResult::interrupt();
    }
    for (Value v : op->getOperands()) {
      if (self->isAncestor(v.getParentRegion()))
        continue;
      if (capturable(v.getType()))
        continue;
      if (isa<RecordType>(v.getType())) {
        op->emitOpError() << "captures " << v.getType()
                          << " from outside the iterator; a record must be built by ebpf.record.make inside each iteration";
        return WalkResult::interrupt();
      }
      op->emitOpError() << "captures " << v.getType()
                        << " from outside the iterator; a reference, pointer or reservation must be looked up and checked "
                           "inside each iteration";
      return WalkResult::interrupt();
    }
    return WalkResult::advance();
  });
  return failure(w.wasInterrupted());
}

LogicalResult IterNumNextBrOp::verify() {
  Block *body = getBody(), *exit = getExit();
  if (body->getNumArguments() != 1 || !body->getArgument(0).getType().isSignlessInteger(32))
    return emitOpError() << "the body successor must take exactly the index (i32)";
  if (exit->getNumArguments() != 0)
    return emitOpError() << "the exit successor must take no arguments";
  return success();
}

// the DSQ iterator body allowlist — the ebpf.iter.num allowlist
// without ebpf.loop, iterators, ebpf.rcu.region and the kptr reads / xchg; the
// reference ops are allowed directly (verifyOwnershipInIter).
// one nested ebpf.iter.num is allowed (LAVD's
// find_cpu_in bpf_for in the scan's bpf_for_each). The DSQ iterator's walk
// covers the nested body too, so it keeps these exclusions (no ebpf.loop, no
// iterator in it — the depth is 2 — no rcu.region, no kptr read / exchange);
// the nested iter.num's own verifier adds its rules (ownership, captures).
static bool allowedInScxDsq(Operation *op) {
  if (isa<LoopOp, IterScxDsqOp, RcuRegionOp, KPtrXchgOp, KPtrLoadRcuOp, GlobalKPtrXchgOp, GlobalKPtrLoadRcuOp>(op))
    return false;
  if (isa<IterNumOp>(op))
    return true;
  // (e): LAVD's scan reads the referenced task's cpus_ptr in the
  // iterator body (main.bpf.c:1414-1415) — a field read, as kfield.load.
  if (isa<KFieldPtrOp>(op))
    return true;
  return allowedInIter(op);
}

LogicalResult IterScxDsqOp::verify() {
  if (getFlags() != 0)
    return emitOpError() << "flags " << getFlags()
                         << " is not supported; only 0 (SCX_DSQ_ITER_REV and the other bpf_iter_scx_dsq_new flags are out of "
                            "scope)";
  for (Type t : getInits().getTypes())
    if (!isLoopScalar(t))
      return emitOpError() << "a carried value must be i8 / i16 / i32 / i64, got " << t;
  if (TypeRange(getInits().getTypes()) != TypeRange(getResults().getTypes()))
    return emitOpError() << "results must have the types of the carried values";
  Block &body = getBody().front();
  auto taskTy = RcuPtrType::get(getContext(), "task_struct");
  if (body.getNumArguments() != getInits().size() + 1 || body.getArgument(0).getType() != taskTy)
    return emitOpError() << "the body must take the task (" << taskTy << ") followed by the carried values";
  for (auto [a, t] : llvm::zip(body.getArguments().drop_front(), getInits().getTypes()))
    if (a.getType() != t)
      return emitOpError() << "body argument type " << a.getType() << " does not match the carried value type " << t;
  auto y = dyn_cast<IterYieldOp>(body.getTerminator());
  if (!y || TypeRange(y.getValues().getTypes()) != TypeRange(getInits().getTypes()))
    return emitOpError() << "the body must end with ebpf.iter.yield of the carried types";
  // not in a loop or another iterator (the RCU section must not be left
  // per iteration and the compiler does not budget it as a loop factor).
  for (Operation *p = (*this)->getParentOp(); p; p = p->getParentOp())
    if (isa<LoopOp, IterNumOp, IterScxDsqOp, MapForEachOp>(p))
      return emitOpError() << "is inside '" << p->getName()
                           << "'; ebpf.iter.scx_dsq is not supported inside ebpf.loop, ebpf.iter.num, map.for_each or another "
                              "ebpf.iter.scx_dsq";
  FailureOr<Operation *> owner = closedRegionOwner(*this, "ebpf.iter.scx_dsq");
  if (failed(owner))
    return failure();
  // struct_ops only (the schema check names the sched_ext_ops member and
  // its sleepable flag); TRACING / SYSCALL are registered but out of scope.
  // in an ebpf.func, per reaching context (ebpf-verify-call-contexts).
  if (auto prog = dyn_cast<ProgramOp>(*owner)) {
    if (!bpfmlir::kindAllows(prog.getKind(), "scx"))
      return emitOpError() << "is only for " << bpfmlir::kindsAllowing("scx")
                           << " programs implementing a sched_ext_ops member (kind \"" << prog.getKind()
                           << "\" — the iterator in tp_btf / fentry / syscall programs is out of scope)";
    if (failed(closedRegionKfunc(*this, prog, "bpf_iter_scx_dsq_new")))
      return failure();
  }
  // the task reaches only kfield.load (MEM_RCU — verifier.c:5986, :6096).
  for (Operation *user : body.getArgument(0).getUsers()) {
    if (isa<KFieldLoadOp>(user))
      continue;
    if (auto call = dyn_cast<KfuncCallOp>(user)) {
      const bpfabi::KfuncABI *k = bpfabi::lookupKfunc(call.getCallee());
      if (k && !k->hasFlag("rcu"))
        return user->emitOpError() << "passes the ebpf.iter.scx_dsq task to \"" << call.getCallee()
                                   << "\", which is not KF_RCU: the kfunc needs a trusted or referenced pointer and the "
                                      "iterator's task is MEM_RCU (7.3.1 verifier.c:13096-13110 — must be referenced or trusted); "
                                      "take a reference with bpf_task_from_pid of its pid";
    }
    return user->emitOpError() << "uses the ebpf.iter.scx_dsq task; the task reaches only ebpf.kfield.load (take a reference "
                                  "with bpf_task_from_pid of its pid for other uses)";
  }
  Region *self = &getBody();
  WalkResult w = getBody().walk([&](Operation *op) {
    if (!allowedInScxDsq(op)) {
      op->emitOpError() << "is not allowed inside ebpf.iter.scx_dsq (the ebpf.iter.num body ops without ebpf.loop, iterators, "
                           "ebpf.rcu.region and the kptr reads / exchanges): one nested ebpf.iter.num is the exception, "
                           "and its body keeps these exclusions";
      return WalkResult::interrupt();
    }
    for (Value v : op->getOperands()) {
      if (self->isAncestor(v.getParentRegion()))
        continue;
      if (capturable(v.getType()))
        continue;
      op->emitOpError() << "captures " << v.getType()
                        << " from outside the iterator; a reference, pointer, record or reservation must be made inside each "
                           "iteration";
      return WalkResult::interrupt();
    }
    return WalkResult::advance();
  });
  return failure(w.wasInterrupted());
}

LogicalResult IterScxDsqNextBrOp::verify() {
  Block *body = getBody(), *exit = getExit();
  if (body->getNumArguments() != 1 || body->getArgument(0).getType() != RcuPtrType::get(getContext(), "task_struct"))
    return emitOpError() << "the body successor must take exactly the task (!ebpf.rcu_ptr<\"task_struct\">)";
  if (exit->getNumArguments() != 0)
    return emitOpError() << "the exit successor must take no arguments";
  return success();
}

LogicalResult RcuRegionOp::verify() {
  Block &body = getBody().front();
  if (body.empty() || !isa<YieldOp>(body.back()))
    return emitOpError() << "the body must end with ebpf.yield (the section's only exit)";
  // H5 (a): no nesting, also through an iterator or ebpf.if.
  for (Operation *p = (*this)->getParentOp(); p; p = p->getParentOp())
    if (isa<RcuRegionOp>(p))
      return emitOpError() << "is nested in another ebpf.rcu.region; nested RCU sections are rejected (6.6.157 / 6.12.111 reject a "
                              "nested bpf_rcu_read_lock — the compiler takes the strict side)";
  FailureOr<Operation *> owner = closedRegionOwner(*this, "ebpf.rcu.region");
  if (failed(owner))
    return failure();
  if (auto prog = dyn_cast<ProgramOp>(*owner); prog && failed(closedRegionKfunc(*this, prog, "bpf_rcu_read_lock")))
    return failure(); // In an ebpf.func: per reaching context (ebpf-verify-call-contexts).
  Region *self = &getBody();
  auto outside = [&](Value v) { return v && !self->isAncestor(v.getParentRegion()); };
  WalkResult w = getBody().walk([&](Operation *op) {
    // H5 (b): ops that may sleep.
    if (opMightSleep(op)) {
      op->emitOpError() << "may sleep, which is not allowed inside ebpf.rcu.region (the verifier rejects a sleepable helper or "
                           "kfunc in an RCU read section)";
      return WalkResult::interrupt();
    }
    // a reference taken outside must not be consumed inside (a compiler
    // restriction that keeps ownership region-local — the kernel allows it).
    bool outerRef = false;
    if (auto call = dyn_cast<KfuncCallOp>(op)) {
      const bpfabi::KfuncABI *k = bpfabi::lookupKfunc(call.getCallee());
      if (k && k->hasFlag("release"))
        outerRef = llvm::any_of(call.getArgs(), [&](Value a) { return isa<KRefType>(a.getType()) && outside(a); });
    } else if (auto x = dyn_cast<KPtrXchgOp>(op)) {
      outerRef = outside(x.getNewRef());
    } else if (auto x = dyn_cast<GlobalKPtrXchgOp>(op)) {
      outerRef = outside(x.getNewRef());
    } else if (isa<KRefCheckOp, SockRefCheckOp, SockReleaseOp>(op)) {
      outerRef = outside(op->getOperand(0));
    }
    if (outerRef) {
      op->emitOpError() << "consumes a reference taken outside the ebpf.rcu.region; a reference may only be released in the "
                           "section that acquired it (a compiler restriction — ownership is checked region-locally)";
      return WalkResult::interrupt();
    }
    // H5 (c): a reservation may not cross the section.
    if (isa<RingbufSubmitOp, RingbufDiscardOp, RingbufSubmitDynptrOp, RingbufDiscardDynptrOp>(op) && outside(op->getOperand(0))) {
      op->emitOpError() << "consumes a ring buffer reservation taken outside the ebpf.rcu.region; a reservation may not cross the "
                           "section";
      return WalkResult::interrupt();
    }
    return WalkResult::advance();
  });
  return failure(w.wasInterrupted());
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
    if (isa<LoopOp, IterNumOp, CallOp, BreakOp, ContinueOp, MapForEachOp, GlobalRefOp /* not opened for callbacks */>(op) ||
        (!isa<MapForEachYieldOp>(op) && !allowedInLoop(op))) {
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
  // The former ParentOneOf<["IfOp", "RefCheckOp"]> trait's text is kept; adds the kref.check arm.
  if (!isa_and_nonnull<IfOp, RefCheckOp, KRefCheckOp>(p))
    return op->emitOpError() << "expects parent op to be one of 'ebpf.if, ebpf.ref.check' (or an ebpf.kref.check arm inside "
                                "ebpf.iter.scx_dsq)";
  // kref.check / kptr.check arms may lie between a break / continue and
  // an ebpf.iter.scx_dsq (LAVD's `if (!p) continue` and release-then-continue);
  // for the other loops they stay rejected as before.
  Operation *checkArm = nullptr;
  while (p && (isa<IfOp, RefCheckOp, KRefCheckOp, KPtrCheckOp>(p) || p->getName().getStringRef() == "scf.if")) {
    if (isa<KRefCheckOp, KPtrCheckOp>(p) && !checkArm)
      checkArm = p;
    p = p->getParentOp();
  }
  if (auto it = dyn_cast_or_null<IterScxDsqOp>(p)) {
    if (TypeRange(vals.getTypes()) != TypeRange(it.getInits().getTypes()))
      return op->emitOpError() << "must carry the carried values of the nearest ebpf.iter.scx_dsq (" << it.getInits().getTypes()
                               << "), got (" << vals.getTypes() << ")";
    return success();
  }
  if (checkArm)
    return op->emitOpError() << "is inside '" << checkArm->getName()
                             << "'; only ebpf.if / ebpf.ref.check / scf.if may lie between a break / continue and the loop it "
                                "leaves (kref.check / kptr.check arms only for ebpf.iter.scx_dsq)";
  // the rcu.region's one exit is its yield (its unlock has one place);
  // leaving it for an enclosing loop or iterator is rejected by name.
  if (isa_and_nonnull<RcuRegionOp>(p))
    return op->emitOpError() << "leaves the ebpf.rcu.region without its unlock (the section's only exit is its yield); "
                                "yield a flag and break after the region";
  if (auto it = dyn_cast_or_null<IterNumOp>(p)) {
    if (TypeRange(vals.getTypes()) != TypeRange(it.getInits().getTypes()))
      return op->emitOpError() << "must carry the carried values of the nearest ebpf.iter.num (" << it.getInits().getTypes()
                               << "), got (" << vals.getTypes() << ")";
    return success();
  }
  auto loop = dyn_cast_or_null<LoopOp>(p);
  if (!loop)
    return op->emitOpError()
           << "must be inside ebpf.loop or ebpf.iter.num (only ebpf.if / ebpf.ref.check / scf.if may lie "
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
static int64_t callbackLead(LoopCallbackOp cb) { return (cb.getForEach() || cb.getFindVma()) ? 2 : 1; } // key + value, or task + vma

LogicalResult LoopCallbackOp::verify() {
  if (getBody().empty())
    return emitOpError() << "has no body";
  Block &entry = getBody().front();
  int64_t nc = getNumCarried(), ncap = getNumCaptured(), lead = callbackLead(*this);
  size_t nmaps = getMapSymbols().size();
  if (nc < 0 || ncap < 0 || (int64_t)entry.getNumArguments() != lead + nc + ncap + (int64_t)nmaps)
    return emitOpError() << "entry block must take " << (getFindVma() ? "the task and the vma" : getForEach() ? "the key and the value" : "the induction variable") << ", " << nc
                         << " loop-carried value(s), " << ncap << " captured integer(s) and "
                         << nmaps << " map(s)";
  if (getForEach() && getFindVma())
    return emitOpError() << "cannot be both a for_each and a find_vma callback";
  if (getFindVma()) {
    auto task = dyn_cast<KPtrType>(entry.getArgument(0).getType());
    auto vma = dyn_cast<KPtrType>(entry.getArgument(1).getType());
    if (!task || task.getStructName() != "task_struct" || !vma || vma.getStructName() != "vm_area_struct")
      return emitOpError() << "a find_vma callback takes !ebpf.kptr<\"task_struct\"> and !ebpf.kptr<\"vm_area_struct\"> first";
    if (nmaps != 0)
      return emitOpError() << "a find_vma callback takes no map";
  } else if (getForEach()) {
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
  if (cb.getFindVma() && getStop() != 0)
    return emitOpError() << "a find_vma callback returns constant 0 (the kernel ignores the value, so a stop has no meaning)";
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

// bpf_find_vma callback call. The callback is the dedicated find_vma
// kind of ebpf.loop_callback (task, vma, carried, captures).
LogicalResult FindVmaCallOp::verify() {
  if (TypeRange(getInits().getTypes()) != TypeRange(getResults().getTypes()))
    return emitOpError() << "results must be the status followed by the types of the loop-carried values";
  auto cb = SymbolTable::lookupNearestSymbolFrom<LoopCallbackOp>(*this, getCallbackAttr());
  if (!cb || !cb.getFindVma())
    return emitOpError() << "does not name an ebpf.loop_callback with find_vma";
  Block &entry = cb.getBody().front();
  if (entry.getArgument(0).getType() != getTask().getType())
    return emitOpError() << "the callback's task argument does not match " << getTask().getType();
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

// ebpf.task.find_vma. The body is a closed set (arith, kfield.load,
// the yield); the task and the vma reach only kfield.load; integers are the only
// captures; fentry programs only; the task is ebpf.task.current_btf's result.
LogicalResult TaskFindVmaOp::verify() {
  if (getTask().getType().getStructName() != "task_struct")
    return emitOpError("takes !ebpf.kptr<\"task_struct\">");
  if (!isa_and_nonnull<TaskCurrentBtfOp>(getTask().getDefiningOp()))
    return emitOpError("the task must be the result of ebpf.task.current_btf (the only task source this op accepts)");
  auto prog = (*this)->getParentOfType<ProgramOp>();
  if (!prog)
    return emitOpError("requires a program body (not a static function)");
  for (Operation *p = (*this)->getParentOp(); p && p != prog.getOperation(); p = p->getParentOp())
    if (isa<SubprogramOp, LoopCallbackOp, TimerCallbackOp, UserRingbufCallbackOp, LoopOp, MapForEachOp, BpfLoopOp, TaskFindVmaOp>(p))
      return emitOpError("is not supported inside a func, callback, loop or another find_vma");
  if (!bpfmlir::kindAllows(prog.getKind(), "task.find_vma"))
    return emitOpError() << "is only for " << bpfmlir::kindsAllowing("task.find_vma") << " programs (kind \"" << prog.getKind()
                         << "\" is a compiler-unsupported combination — only fentry is measured)";
  for (Type t : getInits().getTypes())
    if (!isLoopScalar(t))
      return emitOpError() << "a loop-carried value must be i8 / i16 / i32 / i64, got " << t;
  if (TypeRange(getInits().getTypes()) != TypeRange(getResults().getTypes()))
    return emitOpError() << "results must be the status (i64) followed by the types of the loop-carried values";
  Block &body = getBody().front();
  if (body.getNumArguments() != getInits().size() + 2)
    return emitOpError() << "the body must take the task, the vma and the loop-carried values";
  auto vma = dyn_cast<KPtrType>(body.getArgument(1).getType());
  if (body.getArgument(0).getType() != getTask().getType() || !vma || vma.getStructName() != "vm_area_struct")
    return emitOpError() << "the body must take " << getTask().getType() << " and !ebpf.kptr<\"vm_area_struct\"> first";
  for (auto [a, t] : llvm::zip(body.getArguments().drop_front(2), getInits().getTypes()))
    if (a.getType() != t)
      return emitOpError() << "body argument type " << a.getType() << " does not match the loop-carried value type " << t;
  auto y = dyn_cast<TaskFindVmaYieldOp>(body.getTerminator());
  if (!y || TypeRange(y.getValues().getTypes()) != TypeRange(getInits().getTypes()))
    return emitOpError() << "the body must end with ebpf.task.find_vma.yield of the loop-carried types";
  // The task and the vma reach only ebpf.kfield.load: no yield, select, store,
  // call, kfunc argument or capture escape.
  for (unsigned i = 0; i < 2; ++i)
    for (Operation *user : body.getArgument(i).getUsers())
      if (!isa<KFieldLoadOp>(user))
        return user->emitOpError() << "uses the ebpf.task.find_vma " << (i == 0 ? "task" : "vma")
                                   << " argument; it reaches only ebpf.kfield.load (a read through the kernel pointer)";
  Region *self = &getBody();
  WalkResult w = getBody().walk([&](Operation *op) {
    bool arith = op->getName().getDialectNamespace() == "arith";
    if (!arith && !isa<KFieldLoadOp, TaskFindVmaYieldOp>(op)) {
      op->emitOpError() << "is not allowed inside ebpf.task.find_vma (the body allows arith ops, ebpf.kfield.load and the yield only)";
      return WalkResult::interrupt();
    }
    for (Value v : op->getOperands()) {
      if (self->isAncestor(v.getParentRegion()))
        continue;
      if (isa<IntegerType>(v.getType()))
        continue;
      op->emitOpError() << "captures " << v.getType() << " into ebpf.task.find_vma; only integers can be passed to the callback";
      return WalkResult::interrupt();
    }
    return WalkResult::advance();
  });
  return failure(w.wasInterrupted());
}

LogicalResult BpfLoopOp::verify() {
  if (TypeRange(getInits().getTypes()) != TypeRange(getResults().getTypes()))
    return emitOpError() << "results must have the types of the loop-carried values";
  auto cb = SymbolTable::lookupNearestSymbolFrom<LoopCallbackOp>(*this, getCallbackAttr());
  if (!cb || cb.getForEach() || cb.getFindVma()) // a find_vma callback has (task, vma, ctx) arguments, not (index, ctx).
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
    // fib_lookup input, copied before the helper writes (input never modified).
    if (auto fl = dyn_cast<FibLookupOp>(user); fl && fl.getInput() == getResult())
      continue;
    // tunnel key get input (helper start content) / set input (copied before the helper reads).
    if (auto tg = dyn_cast<SkbGetTunnelKeyOp>(user); tg && tg.getInput() == getResult())
      continue;
    if (auto ts = dyn_cast<SkbSetTunnelKeyOp>(user); ts && ts.getKey() == getResult())
      continue;
    // sk_lookup tuple, read-only for the helper (passed without a copy).
    if (isa<SockLookupTcpOp, SockLookupUdpOp, SockSkcLookupTcpOp>(user) && user->getOperand(1) == getResult())
      continue;
    return user->emitOpError() << "uses a record built by ebpf.record.make; a record value may only "
                                  "be the value of ebpf.map.update / try_update, ebpf.ringbuf.store_record, ebpf.perf.output, ebpf.seq.write, ebpf.ringbuf.output, "
                                  "ebpf.lwt.seg6_store_bytes, ebpf.lwt.seg6_action, ebpf.sys.bpf or the input of ebpf.fib.lookup / ebpf.skb.get_tunnel_key / ebpf.skb.set_tunnel_key, the tuple of "
                                  "ebpf.sock.lookup_tcp / lookup_udp / skc_lookup_tcp, or "
                                  "the key of ebpf.map.lookup / update / delete / try_update / try_delete";
  }
  return success();
}
