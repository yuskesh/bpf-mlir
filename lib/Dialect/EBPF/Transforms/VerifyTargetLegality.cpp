//===- VerifyTargetLegality.cpp - program-kind and target policy checks ------===//
//
// Separate semantic validity (operation verifiers), compiler support, and
// target support (profile facts). Timer/spin restrictions concern both allowed
// operation kinds and actual use of maps bearing those members, reflecting
// kernel check_map_prog_compatibility.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h"
#include "bpf-mlir/Dialect/EBPF/Transforms/TargetProfile.h"

#include "bpf-mlir/Dialect/BTF/IR/BTFDialect.h"
#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"
#include "bpf-mlir/Support/ProgramKinds.h"

#include "llvm/ADT/StringSet.h"

namespace mlir {
namespace ebpf {
#define GEN_PASS_DEF_EBPFVERIFYTARGETLEGALITY
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h.inc"
} // namespace ebpf
} // namespace mlir

using namespace mlir;
using namespace mlir::ebpf;

namespace {

// Check @records for a btfType member (bpf_timer/bpf_spin_lock). Missing scope
// or declaration is indeterminate (nullopt), never false: callers must reject
// rather than bypass profile restrictions.
std::optional<bool> recordHasMember(btf::ScopeOp records, RecordType rt, StringRef btfType) {
  if (!records)
    return std::nullopt;
  auto st = dyn_cast_or_null<btf::StructOp>(SymbolTable::lookupSymbolIn(records, rt.getSymbol()));
  if (!st)
    return std::nullopt;
  for (Attribute a : st.getMembers())
    if (auto r = dyn_cast<btf::RefAttr>(cast<btf::MemberAttr>(a).getType()); r && r.getTarget().getLeafReference() == btfType)
      return true;
  return false;
}

// Map symbols with btfType members actually used by a program or transitive
// ebpf.call callees, associated with first use. Record maps lacking declarations
// are undecided because member presence cannot be established.
llvm::SmallVector<std::pair<std::string, Operation *>> usedMapsWithMember(ModuleOp module, ProgramOp prog, btf::ScopeOp records, StringRef btfType,
                                                                          llvm::SmallVector<std::pair<std::string, Operation *>> &undecided) {
  llvm::SmallVector<std::pair<std::string, Operation *>> out;
  llvm::StringSet<> seenSym, seenFn;
  auto scan = [&](Operation *owner, ArrayAttr syms, Block &entry, unsigned firstMap) {
    for (unsigned i = firstMap; syms && i < entry.getNumArguments() && i - firstMap < syms.size(); ++i) {
      BlockArgument arg = entry.getArgument(i);
      auto mt = dyn_cast<MapType>(arg.getType());
      auto rt = mt ? dyn_cast<RecordType>(mt.getValueType()) : RecordType();
      if (!rt || arg.use_empty())
        continue;
      std::string sym = cast<FlatSymbolRefAttr>(syms[i - firstMap]).getValue().str();
      std::optional<bool> has = recordHasMember(records, rt, btfType);
      if (!has) {
        undecided.push_back({sym, *arg.getUsers().begin()});
        continue;
      }
      if (*has && seenSym.insert(sym).second)
        out.push_back({sym, *arg.getUsers().begin()});
    }
  };
  SmallVector<Operation *> work{prog};
  scan(prog, prog.getMapSymbolsAttr(), prog.getBody().front(), 1); // Entry map arguments follow ctx.
  while (!work.empty()) {
    Operation *owner = work.pop_back_val();
    owner->walk([&](CallOp call) {
      auto fn = SymbolTable::lookupNearestSymbolFrom<SubprogramOp>(call, call.getCalleeAttr());
      if (!fn || !seenFn.insert(fn.getSymName()).second)
        return;
      Block &e = fn.getBody().front();
      scan(fn, fn.getMapSymbolsAttr(), e, e.getNumArguments() - (fn.getMapSymbolsAttr() ? fn.getMapSymbolsAttr().size() : 0));
      work.push_back(fn);
    });
  }
  return out;
}

struct EBPFVerifyTargetLegalityPass
    : public mlir::ebpf::impl::EBPFVerifyTargetLegalityBase<EBPFVerifyTargetLegalityPass> {
  using Base::Base;
  void runOnOperation() override {
    ModuleOp module = getOperation();
    std::optional<TargetProfile> profile;
    if (!profilePath.empty()) {
      std::string why;
      profile = TargetProfile::load(profilePath, why);
      if (!profile) {
        module.emitError() << why;
        return signalPassFailure();
      }
    }
    const TargetProfile *pp = profile ? &*profile : nullptr;
    btf::ScopeOp records;
    for (auto sc : module.getOps<btf::ScopeOp>())
      if (sc.getSymName() == "records")
        records = sc;
    // Timer/spin_lock policies share compiler support and target-profile axes.
    struct Feature {
      StringRef fact, btfType, holds, opWord, compilerWhy;
      LegalityAnswer (*legality)(StringRef, const TargetProfile *);
      bool (*isOp)(Operation *);
    };
    const Feature features[] = {
        {kFactMapWithTimer, "bpf_timer", "a bpf_timer", "timers",
         "the callback's helper set, a C oracle and runs on the targets are missing", timerLegality,
         [](Operation *op) { return isa<TimerInitOp, TimerSetCallbackOp, TimerStartOp>(op); }},
        {kFactMapWithSpinLock, "bpf_spin_lock", "a bpf_spin_lock", "spin regions",
         "a C oracle and runs on the targets are missing", spinLegality,
         [](Operation *op) { return isa<SpinRegionOp>(op); }},
    };
    bool bad = false;
    for (auto prog : module.getOps<ProgramOp>()) {
      StringRef kind = prog.getKind(), ptype = programTypeOf(kind);
      // Operations must belong to a compiler-supported and verified program kind.
      bool unsupported = false;
      for (const Feature &f : features) {
        Operation *first = nullptr;
        prog.walk([&](Operation *op) {
          if (!first && f.isOp(op))
            first = op;
        });
        if (!first)
          continue;
        LegalityAnswer a = f.legality(kind, pp);
        if (a.compiler != Legality::CompilerUnsupported)
          continue;
        InFlightDiagnostic d = first->emitOpError()
                               << "in a \"" << kind << "\" program is not supported by this compiler (compiler unsupported: " << f.opWord
                               << " are implemented only in " << bpfmlir::kindsAllowing(f.fact == kFactMapWithTimer ? "timer" : "spin")
                               << " programs — " << f.compilerWhy << " for \"" << kind << "\", "
                               << (f.fact == kFactMapWithTimer ? "timer compiler capability" : "spin-lock compiler capability") << ")";
        if (a.target == FactValue::Rejected)
          d.attachNote() << "target unsupported too: profile '" << pp->path << "' records that the target rejects maps holding " << f.holds << " in "
                         << ptype << " programs (fact " << f.fact << " " << ptype << " rejected, evidence " << a.targetEvidence << ")";
        bad = unsupported = true;
      }
      if (unsupported || !pp)
        continue;
      // Enforce rejected profile facts on actually used timer/spin_lock maps,
      // even without their operations. Mere maps[] binding is not a use; inspect
      // block-argument uses in program bodies and transitive ebpf.call callees.
      for (const Feature &f : features) {
        std::string ev;
        if (pp->fact(f.fact, ptype, &ev) != FactValue::Rejected)
          continue;
        llvm::SmallVector<std::pair<std::string, Operation *>> undecided;
        auto used = usedMapsWithMember(module, prog, records, f.btfType, undecided);
        for (auto [sym, use] : undecided) {
          InFlightDiagnostic d = prog.emitOpError()
                                 << "uses map @" << sym << " whose record is not declared in btf.scope @records, so whether it holds " << f.holds << " is unknown; "
                                 << "profile '" << pp->path << "' rejects maps holding " << f.holds << " in " << ptype
                                 << " programs — cannot decide (run ebpf-build-btf-types before ebpf-verify-target-legality)";
          d.attachNote(use->getLoc()) << "the map is used here";
          bad = true;
        }
        for (auto [sym, use] : used) {
          InFlightDiagnostic d = prog.emitOpError()
                                 << "(\"" << kind << "\", program type " << ptype << ") uses map @" << sym << " whose value holds " << f.holds << "; "
                                 << "target unsupported: profile '" << pp->path << "' records that the target rejects this (fact " << f.fact << " "
                                 << ptype << " rejected, evidence " << ev << ")";
          d.attachNote(use->getLoc()) << "the map is used here";
          bad = true;
        }
      }
    }
    if (bad)
      signalPassFailure();
  }
};

} // namespace
