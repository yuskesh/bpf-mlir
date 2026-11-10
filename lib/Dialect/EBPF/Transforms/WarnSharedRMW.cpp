//===- WarnSharedRMW.cpp - warn about non-atomic RMW of shared map values ----===//
//
// a value loaded from a shared (not per-CPU) map value
// or a .bss global that reaches, through arithmetic and region results, a write
// of the same location is a non-atomic read-modify-write: programs running on
// other CPUs at the same time lose updates. Neither the verifier nor the
// compiler rejects it. This pass warns (opt-in: ebpf-compile --warn-shared-rmw)
// and changes no IR.
//
// The rules are rmwprobe's (kernel/cmd/rmwprobe — docs/tools/rmwprobe.md)
// within one function:
//   sources  ref.load / ref.field.load / elem.load (once too) and global.load;
//   carried  every op result from its operands, region results from the
//            terminators of the op's regions (and break for loops), loop and
//            for_each iter_args from the inits and the yields / continues;
//            ebpf.call results carry nothing (functions are not crossed — the
//            interprocedural shapes are rmwprobe's);
//   writes   ref.store / ref.field.store / elem.store of the same borrow
//            location (map, key signature, path — elem: the same elem value),
//            ref.atomic_add / ref.field.atomic_add deltas, map.update /
//            try_update / atomic_add of the same map and key signature (any
//            path), global.store / global.atomic_add of the same @G,
//            ref.field.atomic_or / global.atomic_or operands (like a
//            delta; cmpxchg is not a write: it is the atomic retry form);
//   excluded per-CPU map kinds, and a load and a write inside the same
//            spin.region.
// A key signature is the same SSA value, an arith.constant of the same type and
// value, or a record.make of the same record type, field names and per-field
// signatures. The map kind of a borrow comes from its lookup's map type, a
// for_each's map, a timer.callback's `map @m` binding (the program or function
// entry argument bound to @m), or for a function's borrowed argument from every
// call site's argument (the one non-per-CPU kind among them; every caller
// per-CPU: no warning; otherwise an unknown kind, which warns — not shown to be
// per-CPU).
// Control dependence (a branch on the loaded value choosing what to write) is
// not detected.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h"

#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"

#include "mlir/Dialect/Arith/IR/Arith.h"
#include "mlir/IR/SymbolTable.h"

#include "llvm/Support/raw_ostream.h"

#include <set>

namespace mlir {
namespace ebpf {
#define GEN_PASS_DEF_EBPFWARNSHAREDRMW
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h.inc"
} // namespace ebpf
} // namespace mlir

using namespace mlir;
using namespace mlir::ebpf;

namespace {

// A memory location: root (map value, elem value, timer binding, function
// argument or global), key signature and path. kind is the map kind ("" when
// unknown) or "global".
struct Location {
  std::string root, key, path, kind, global;
};

std::string ptr(Value v) {
  std::string s;
  llvm::raw_string_ostream os(s);
  os << v.getAsOpaquePointer();
  return s;
}

std::string typeStr(Type t) {
  std::string s;
  llvm::raw_string_ostream os(s);
  os << t;
  return s;
}

std::string keySig(Value k, unsigned depth = 0) {
  if (depth < 8) {
    if (auto c = k.getDefiningOp<arith::ConstantOp>()) {
      if (auto ia = dyn_cast<IntegerAttr>(c.getValue())) {
        SmallString<32> v;
        ia.getValue().toStringSigned(v);
        return "c:" + typeStr(k.getType()) + ":" + std::string(v);
      }
    }
    if (auto rm = k.getDefiningOp<RecordMakeOp>()) {
      std::string s = "r:" + typeStr(k.getType()) + "{";
      for (auto [f, v] : llvm::zip(rm.getFields(), rm.getValues()))
        s += cast<StringAttr>(f).getValue().str() + "=" + keySig(v, depth + 1) + ";";
      return s + "}";
    }
  }
  return "v:" + ptr(k);
}

bool perCPU(StringRef kind) { return kind.contains("percpu"); }

class Analysis {
public:
  explicit Analysis(ModuleOp m) : module(m) {
    // Map bindings by symbol (for timer.callback's `map @m`): the entry
    // argument of every program / function that binds the symbol.
    auto bind = [&](ArrayAttr syms, Block &entry, unsigned first) {
      if (!syms)
        return;
      for (auto [i, s] : llvm::enumerate(syms)) {
        unsigned a = first + i;
        if (a >= entry.getNumArguments())
          continue;
        if (auto mt = dyn_cast<MapType>(entry.getArgument(a).getType()))
          bindKinds[cast<FlatSymbolRefAttr>(s).getValue()].insert(mt.getKind().str());
      }
    };
    m.walk([&](Operation *op) {
      if (auto p = dyn_cast<ProgramOp>(op)) {
        if (!p.getBody().empty())
          bind(p.getMapSymbolsAttr(), p.getBody().front(), 1);
      } else if (auto f = dyn_cast<SubprogramOp>(op)) {
        if (!f.getBody().empty()) {
          Block &e = f.getBody().front();
          unsigned n = f.getMapSymbolsAttr() ? f.getMapSymbolsAttr().size() : 0;
          bind(f.getMapSymbolsAttr(), e, e.getNumArguments() >= n ? e.getNumArguments() - n : 0);
        }
      }
    });
  }

  void run() {
    // Sources in pre-order: their index is the "earliest" order of the note.
    module.walk<WalkOrder::PreOrder>([&](Operation *op) {
      if (auto l = sourceLocation(op)) {
        sourceIndex[op] = sources.size();
        sources.push_back({op, *l});
      }
    });
    propagate();
    module.walk<WalkOrder::PreOrder>([&](Operation *op) { checkWrite(op); });
  }

private:
  struct Source {
    Operation *op;
    Location loc;
  };

  ModuleOp module;
  llvm::StringMap<std::set<std::string>> bindKinds;
  std::vector<Source> sources;
  DenseMap<Operation *, unsigned> sourceIndex;
  DenseMap<Value, std::set<unsigned>> taint;

  // The kind of the map behind a function's borrowed argument j, from every
  // call site's argument: the one non-per-CPU kind among them (the warning is
  // about those callers — per-CPU callers are not shared), a per-CPU kind when
  // every caller passes per-CPU maps (no warning), otherwise "" (unknown: no
  // call site, a caller whose kind is not known, or several shared kinds).
  std::string calleeArgKind(SubprogramOp fn, unsigned j, unsigned depth) {
    std::set<std::string> shared, local;
    bool unknown = false, any = false;
    module.walk([&](CallOp call) {
      if (call.getCallee() != fn.getSymName() || j >= call.getArgs().size())
        return;
      any = true;
      std::optional<Location> l = borrowLocation(call.getArgs()[j], "", depth + 1);
      if (!l || l->kind.empty())
        unknown = true;
      else
        (perCPU(l->kind) ? local : shared).insert(l->kind);
    });
    if (!any || unknown || shared.size() > 1)
      return "";
    if (shared.size() == 1)
      return *shared.begin();
    return *local.begin();
  }

  // The location of a borrowed value (and path).
  std::optional<Location> borrowLocation(Value b, StringRef path, unsigned depth = 0) {
    if (depth > 8)
      return std::nullopt;
    auto ba = dyn_cast<BlockArgument>(b);
    if (!ba)
      return Location{"b:" + ptr(b), "", path.str(), "", ""};
    Operation *owner = ba.getOwner()->getParentOp();
    if (auto rc = dyn_cast_or_null<RefCheckOp>(owner)) {
      if (auto lk = rc.getRef().getDefiningOp<MapLookupOp>())
        return Location{"m:" + ptr(lk.getMap()), keySig(lk.getKey()), path.str(),
                        cast<MapType>(lk.getMap().getType()).getKind().str(), ""};
      return Location{"b:" + ptr(b), "", path.str(), "", ""};
    }
    if (auto fe = dyn_cast_or_null<MapForEachOp>(owner)) {
      if (ba.getArgNumber() == 1)
        return Location{"m:" + ptr(fe.getMap()), "v:" + ptr(ba.getOwner()->getArgument(0)), path.str(),
                        cast<MapType>(fe.getMap().getType()).getKind().str(), ""};
      return std::nullopt;
    }
    if (auto tc = dyn_cast_or_null<TimerCallbackOp>(owner)) {
      std::string kind;
      auto it = bindKinds.find(tc.getMap());
      if (it != bindKinds.end() && it->second.size() == 1)
        kind = *it->second.begin();
      return Location{"t:" + tc.getMap().str(), "self", path.str(), kind, ""};
    }
    if (auto fn = dyn_cast_or_null<SubprogramOp>(owner)) {
      if (ba.getOwner() == &fn.getBody().front())
        return Location{"a:" + ptr(b), "", path.str(), calleeArgKind(fn, ba.getArgNumber(), depth), ""};
    }
    return Location{"b:" + ptr(b), "", path.str(), "", ""};
  }

  // The location of an elem value: the elem itself, kind from ref.index's borrow.
  std::optional<Location> elemLocation(Value e) {
    std::string kind;
    if (auto ba = dyn_cast<BlockArgument>(e))
      if (auto ri = dyn_cast_or_null<RefIndexOp>(ba.getOwner()->getParentOp()))
        if (auto l = borrowLocation(ri.getRef(), ri.getField()))
          kind = l->kind;
    return Location{"e:" + ptr(e), "", "", kind, ""};
  }

  std::optional<Location> sourceLocation(Operation *op) {
    if (auto l = dyn_cast<RefLoadOp>(op))
      return borrowLocation(l.getRef(), "");
    if (auto l = dyn_cast<RefFieldLoadOp>(op))
      return borrowLocation(l.getRef(), l.getField());
    if (auto l = dyn_cast<ElemLoadOp>(op))
      return elemLocation(l.getElem());
    if (auto g = dyn_cast<GlobalLoadOp>(op))
      return Location{"g:" + g.getName().str(), "", "", "global", g.getName().str()};
    return std::nullopt;
  }

  bool merge(Value to, const std::set<unsigned> &from) {
    if (from.empty())
      return false;
    std::set<unsigned> &t = taint[to];
    size_t n = t.size();
    t.insert(from.begin(), from.end());
    return t.size() != n;
  }

  std::set<unsigned> of(Value v) {
    auto it = taint.find(v);
    return it == taint.end() ? std::set<unsigned>{} : it->second;
  }

  // The carried values of a region op: for each block directly in its regions,
  // the terminator's values; for a loop, also the break / continue values whose
  // nearest loop is the op.
  static SmallVector<ValueRange> carriers(Operation *op, bool withContinue, bool withBreak) {
    SmallVector<ValueRange> out;
    for (Region &r : op->getRegions())
      for (Block &b : r) {
        if (b.empty())
          continue;
        Operation *t = &b.back();
        if (auto y = dyn_cast<LoopYieldOp>(t))
          out.push_back(y.getValues());
        else if (auto y = dyn_cast<MapForEachYieldOp>(t))
          out.push_back(y.getValues());
        else if (t->hasTrait<OpTrait::IsTerminator>() && !isa<BreakOp, ContinueOp>(t))
          out.push_back(t->getOperands());
      }
    if (withContinue || withBreak)
      op->walk([&](Operation *x) {
        if (!isa<BreakOp, ContinueOp>(x) || x->getParentOfType<LoopOp>() != op)
          return;
        if (isa<BreakOp>(x) ? withBreak : withContinue)
          out.push_back(x->getOperands());
      });
    return out;
  }

  void propagate() {
    for (bool changed = true; changed;) {
      changed = false;
      module.walk<WalkOrder::PreOrder>([&](Operation *op) {
        auto si = sourceIndex.find(op);
        if (si != sourceIndex.end()) {
          changed |= merge(op->getResult(0), {si->second});
          return;
        }
        if (isa<CallOp>(op))
          return; // Functions are not crossed.
        if (auto loop = dyn_cast<LoopOp>(op)) {
          Block &body = loop.getBody().front();
          for (auto [i, init] : llvm::enumerate(loop.getInits())) {
            std::set<unsigned> s = of(init);
            for (ValueRange vs : carriers(op, /*continue*/ true, /*break*/ false))
              if (i < vs.size())
                for (unsigned x : of(vs[i]))
                  s.insert(x);
            if (1 + i < body.getNumArguments())
              changed |= merge(body.getArgument(1 + i), s);
            std::set<unsigned> r = of(init);
            for (ValueRange vs : carriers(op, false, true))
              if (i < vs.size())
                for (unsigned x : of(vs[i]))
                  r.insert(x);
            for (unsigned x : of(body.getArgument(1 + i)))
              r.insert(x);
            if (i < loop.getNumResults())
              changed |= merge(loop.getResult(i), r);
          }
          return;
        }
        if (auto fe = dyn_cast<MapForEachOp>(op)) {
          Block &body = fe.getBody().front();
          for (auto [i, init] : llvm::enumerate(fe.getInits())) {
            std::set<unsigned> s = of(init);
            for (ValueRange vs : carriers(op, false, false))
              if (i < vs.size())
                for (unsigned x : of(vs[i]))
                  s.insert(x);
            if (2 + i < body.getNumArguments())
              changed |= merge(body.getArgument(2 + i), s);
            if (1 + i < fe.getNumResults())
              changed |= merge(fe.getResult(1 + i), s);
          }
          return;
        }
        if (op->getNumRegions() > 0) {
          for (ValueRange vs : carriers(op, false, false))
            for (auto [i, v] : llvm::enumerate(vs))
              if (i < op->getNumResults())
                changed |= merge(op->getResult(i), of(v));
          return;
        }
        std::set<unsigned> s;
        for (Value in : op->getOperands())
          for (unsigned x : of(in))
            s.insert(x);
        for (Value r : op->getResults())
          changed |= merge(r, s);
      });
    }
  }

  static SpinRegionOp spin(Operation *op) { return op->getParentOfType<SpinRegionOp>(); }

  void checkWrite(Operation *op) {
    std::optional<Location> at;
    Value val;
    bool anyPath = false, delta = false;
    // cmpxchg is not a write here — a value computed from a load and
    // written by cmpxchg with that load as expected is the atomic retry form.
    StringRef opName = "add";
    if (auto s = dyn_cast<RefStoreOp>(op)) {
      at = borrowLocation(s.getRef(), "");
      val = s.getValue();
    } else if (auto s = dyn_cast<RefFieldStoreOp>(op)) {
      at = borrowLocation(s.getRef(), s.getField());
      val = s.getValue();
    } else if (auto s = dyn_cast<ElemStoreOp>(op)) {
      at = elemLocation(s.getElem());
      val = s.getValue();
    } else if (auto s = dyn_cast<RefAtomicAddOp>(op)) {
      at = borrowLocation(s.getRef(), "");
      val = s.getDelta();
      delta = true;
    } else if (auto s = dyn_cast<RefFieldAtomicOrOp>(op)) { // an or operand, like a delta.
      at = borrowLocation(s.getRef(), s.getField());
      val = s.getValue();
      delta = true;
      opName = "or";
    } else if (auto s = dyn_cast<GlobalAtomicOrOp>(op)) {
      at = Location{"g:" + s.getName().str(), "", "", "global", s.getName().str()};
      val = s.getValue();
      delta = true;
      opName = "or";
    } else if (auto s = dyn_cast<RefFieldAtomicAddOp>(op)) {
      at = borrowLocation(s.getRef(), s.getField());
      val = s.getDelta();
      delta = true;
    } else if (auto s = dyn_cast<MapUpdateOp>(op)) {
      at = Location{"m:" + ptr(s.getMap()), keySig(s.getKey()), "", cast<MapType>(s.getMap().getType()).getKind().str(), ""};
      val = s.getValue();
      anyPath = true;
    } else if (auto s = dyn_cast<MapTryUpdateOp>(op)) {
      at = Location{"m:" + ptr(s.getMap()), keySig(s.getKey()), "", cast<MapType>(s.getMap().getType()).getKind().str(), ""};
      val = s.getValue();
      anyPath = true;
    } else if (auto s = dyn_cast<MapAtomicAddOp>(op)) {
      at = Location{"m:" + ptr(s.getMap()), keySig(s.getKey()), "", cast<MapType>(s.getMap().getType()).getKind().str(), ""};
      val = s.getDelta();
      anyPath = true;
      delta = true;
    } else if (auto s = dyn_cast<GlobalStoreOp>(op)) {
      at = Location{"g:" + s.getName().str(), "", "", "global", s.getName().str()};
      val = s.getValue();
    } else if (auto s = dyn_cast<GlobalAtomicAddOp>(op)) {
      at = Location{"g:" + s.getName().str(), "", "", "global", s.getName().str()};
      val = s.getDelta();
      delta = true;
    }
    if (!at || perCPU(at->kind)) // An unknown kind ("") warns: not shown to be per-CPU.
      return;
    SpinRegionOp ws = spin(op);
    std::optional<unsigned> first;
    for (unsigned i : of(val)) {
      const Source &src = sources[i];
      const Location &l = src.loc;
      if (l.root != at->root || l.key != at->key || (!anyPath && l.path != at->path))
        continue;
      if (ws && spin(src.op) == ws)
        continue; // Load and write inside the same spin.region.
      if (!first || i < *first)
        first = i;
    }
    if (!first)
      return;
    std::string what = at->kind == "global" ? "the .bss global @" + at->global
                     : at->kind.empty() ? std::string("a map value whose map kind is not known in this function (not shown to be per-CPU)") : "a shared " + at->kind + " map value";
    std::string same = at->kind == "global" ? "the same global" : "the same location";
    InFlightDiagnostic d = mlir::emitWarning(op->getLoc());
    d << "a non-atomic read-modify-write of " << what << ": ";
    if (delta)
      d << (opName == "add" ? "the delta of this atomic add" : "the operand of this atomic or") << " is computed from a load of " << same
        << " — the " << opName << " is atomic but the loaded value is stale; remove the load (--warn-shared-rmw)";
    else if (at->kind == "global")
      d << "the value written here is computed from a load of " << same
        << ", so updates from other CPUs can be lost — use ebpf.global.atomic_add when the update is an addition "
           "(--warn-shared-rmw)";
    else
      d << "the value written here is computed from a load of " << same
        << ", so updates from other CPUs can be lost — use ebpf.ref.atomic_add / ebpf.ref.field.atomic_add when the "
           "update is an addition, otherwise a per-CPU map or ebpf.spin.region around both the load and the store "
           "(--warn-shared-rmw)";
    d.attachNote(sources[*first].op->getLoc()) << "the value is loaded here";
  }
};

struct EBPFWarnSharedRMWPass : public mlir::ebpf::impl::EBPFWarnSharedRMWBase<EBPFWarnSharedRMWPass> {
  void runOnOperation() override {
    Analysis(getOperation()).run();
    markAllAnalysesPreserved();
  }
};

} // namespace
