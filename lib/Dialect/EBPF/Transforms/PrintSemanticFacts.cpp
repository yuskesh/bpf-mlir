//===- PrintSemanticFacts.cpp - read-only semantic fact diagnostics ----------===//
//
// Explicitly requested by ebpf-print-semantic-facts, never in the default
// pipeline. Preserve all analyses and leave operations, values, attributes and
// CFG unchanged. Report only existing facts, without another lattice/framework:
//
// IntegerRangeAnalysis gives SSA-wide ranges, not branch-refined program-point
// ranges. Report simple incoming constant-comparison refinements separately as
// integer-edge, local to that block without propagating them.
// Non-null facts come only from present-region arguments or checked-edge
// assume_present results satisfying VerifyStructured placement rules. Nullable
// references/reservations are not reported non-null.
// Packet windows use PacketNeutral along origin-to-use paths: invalidating
// operations/helpers give valid=false; unproven neutrality gives valid=unknown.
//
// These are compiler facts, not guarantees that the kernel can prove the same
// facts from generated instructions. Keep them separate from TargetProfile.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h"
#include "bpf-mlir/Dialect/EBPF/Transforms/PacketNeutral.h"
#include "bpf-mlir/Dialect/EBPF/Transforms/CheckedEdge.h"
#include "bpf-mlir/Dialect/EBPF/Transforms/WindowPath.h"
#include "bpf-mlir/Dialect/EBPF/Transforms/RecordPath.h"

#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"

#include "mlir/Analysis/DataFlow/IntegerRangeAnalysis.h"
#include "mlir/Analysis/DataFlow/Utils.h"
#include "mlir/Analysis/DataFlowFramework.h"
#include "mlir/Dialect/Arith/IR/Arith.h"
#include "mlir/Dialect/ControlFlow/IR/ControlFlowOps.h"
#include "mlir/IR/AsmState.h"
#include "mlir/IR/Matchers.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Support/raw_ostream.h"

namespace mlir {
namespace ebpf {
#define GEN_PASS_DEF_EBPFPRINTSEMANTICFACTS
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h.inc"
} // namespace ebpf
} // namespace mlir

using namespace mlir;
using namespace mlir::ebpf;

namespace {

// Full domain (no information) is unknown.
std::string rangeStr(const APInt &lo, const APInt &hi, bool isSigned) {
  bool full = isSigned ? (lo.isMinSignedValue() && hi.isMaxSignedValue()) : (lo.isZero() && hi.isAllOnes());
  if (full)
    return "unknown";
  return "[" + llvm::toString(lo, 10, isSigned) + "," + llvm::toString(hi, 10, isSigned) + "]";
}

std::string rangesStr(const ConstantIntRanges &r) {
  return "unsigned=" + rangeStr(r.umin(), r.umax(), false) + " signed=" + rangeStr(r.smin(), r.smax(), true);
}

// Range when cmpi predicate p against a constant is true. nullopt means empty,
// possible for comparisons such as ult zero. ne excludes one point and cannot
// be represented by an interval, so conservatively return the full domain.
std::optional<ConstantIntRanges> rangeFromPredicate(arith::CmpIPredicate p, const APInt &c) {
  unsigned w = c.getBitWidth();
  APInt umin = APInt::getZero(w), umax = APInt::getAllOnes(w);
  APInt smin = APInt::getSignedMinValue(w), smax = APInt::getSignedMaxValue(w);
  using P = arith::CmpIPredicate;
  switch (p) {
  case P::eq:
    return ConstantIntRanges::constant(c);
  case P::ne:
    return ConstantIntRanges::maxRange(w);
  case P::ult:
    if (c.isZero())
      return std::nullopt;
    return ConstantIntRanges::fromUnsigned(umin, c - 1);
  case P::ule:
    return ConstantIntRanges::fromUnsigned(umin, c);
  case P::ugt:
    if (c.isAllOnes())
      return std::nullopt;
    return ConstantIntRanges::fromUnsigned(c + 1, umax);
  case P::uge:
    return ConstantIntRanges::fromUnsigned(c, umax);
  case P::slt:
    if (c.isMinSignedValue())
      return std::nullopt;
    return ConstantIntRanges::fromSigned(smin, c - 1);
  case P::sle:
    return ConstantIntRanges::fromSigned(smin, c);
  case P::sgt:
    if (c.isMaxSignedValue())
      return std::nullopt;
    return ConstantIntRanges::fromSigned(c + 1, smax);
  case P::sge:
    return ConstantIntRanges::fromSigned(c, smax);
  }
  return std::nullopt;
}

// Convert c OP v to v OP' c.
arith::CmpIPredicate swapOperands(arith::CmpIPredicate p) {
  using P = arith::CmpIPredicate;
  switch (p) {
  case P::ult: return P::ugt;
  case P::ule: return P::uge;
  case P::ugt: return P::ult;
  case P::uge: return P::ule;
  case P::slt: return P::sgt;
  case P::sle: return P::sge;
  case P::sgt: return P::slt;
  case P::sge: return P::sle;
  default: return p;
  }
}

// Sole incoming edge's condition and truth value: a unique cf.cond_br
// predecessor (not two edges to this block), or an ebpf.if arm's entry block.
struct EdgeCondition {
  Value cond;
  bool whenTrue;
  StringRef via;
};
std::optional<EdgeCondition> edgeCondition(Block *b) {
  if (b->isEntryBlock()) {
    if (auto ifOp = dyn_cast_or_null<IfOp>(b->getParentOp())) {
      bool isThen = b->getParent() == &ifOp.getThenRegion();
      return EdgeCondition{ifOp.getCond(), isThen, "ebpf.if"};
    }
    return std::nullopt;
  }
  Block *pred = b->getSinglePredecessor();
  auto br = pred ? dyn_cast<cf::CondBranchOp>(pred->getTerminator()) : cf::CondBranchOp();
  if (!br || br.getTrueDest() == br.getFalseDest())
    return std::nullopt;
  return EdgeCondition{br.getCondition(), br.getTrueDest() == b, "cf.cond_br"};
}

// Packet-window path classification.
enum class WindowValidity { Valid, Invalid, Unknown };
struct WindowAnswer {
  WindowValidity v = WindowValidity::Valid;
  Operation *by = nullptr;
};

// Classify an operation and its regions. Invalid is stronger than Unknown neutrality.
void considerOp(Operation *op, WindowAnswer &ans) {
  if (ans.v == WindowValidity::Invalid || isPacketNeutral(op))
    return;
  Operation *firstNonNeutral = nullptr;
  op->walk([&](Operation *o) {
    // Share PacketNeutral invalidation predicates with VerifyStructured.
    if (opInvalidatesPacketPointers(o)) {
      ans = {WindowValidity::Invalid, o};
      return WalkResult::interrupt();
    }
    if (!firstNonNeutral && !isPacketNeutral(o))
      firstNonNeutral = o; // Post-order selects the innermost non-neutral operation.
    return WalkResult::advance();
  });
  if (ans.v != WindowValidity::Invalid && ans.v != WindowValidity::Unknown)
    ans = {WindowValidity::Unknown, firstNonNeutral ? firstNonNeutral : op};
}

// A source window originates at packet.check's in_range argument. Walk
// outward from use, examining preceding operations at each region level.
// Unless the ancestor executes at most once (if/ref.check/if_reserved/
// packet.check/ref.index/spin.region), inspect its whole region: later loop
// operations may precede the next use. Conservatively inspect all operations
// of multi-block regions too.
WindowAnswer windowAtStage1(Value w, Operation *use) {
  WindowAnswer ans;
  Region *defRegion = w.getParentRegion();
  Operation *cur = use;
  while (cur && cur->getParentRegion() != defRegion) {
    Region *r = cur->getParentRegion();
    if (r->hasOneBlock()) {
      for (Operation &op : *cur->getBlock()) {
        if (&op == cur)
          break;
        considerOp(&op, ans);
      }
    } else {
      for (Block &b : *r)
        for (Operation &op : b)
          if (&op != cur)
            considerOp(&op, ans);
    }
    Operation *parent = cur->getParentOp();
    if (!parent)
      break;
    if (!isa<IfOp, RefCheckOp, RingbufIfReservedOp, PacketCheckOp, RefIndexOp, SpinRegionOp>(parent))
      for (Region &pr : parent->getRegions())
        for (Block &b : pr)
          for (Operation &op : b)
            if (!op.isAncestor(use))
              considerOp(&op, ans);
    cur = parent;
  }
  if (!cur)
    return {WindowValidity::Unknown, nullptr};
  if (defRegion->hasOneBlock()) {
    for (Operation &op : *cur->getBlock()) {
      if (&op == cur)
        break;
      considerOp(&op, ans);
    }
  } else {
    for (Block &b : *defRegion)
      for (Operation &op : b)
        if (&op != cur)
          considerOp(&op, ans);
  }
  return ans;
}

// Expanded windows originate at pkt.check_br in_range arguments. Use
// WindowPath DominatedBackward plus operations preceding use: all paths since
// the last entry to in_range. Passing through in_range recreates the window,
// so only cycles avoiding it can affect a use.
// VerifyStructured retains MayExecute for compatibility. Thus handwritten
// expanded input with cyclic in_range may report valid=true yet be rejected.
// Source allowedInLoop prevents that topology in ebpf-compile input.
WindowAnswer windowAtStage2(Block *in, Operation *use) {
  WindowAnswer ans;
  DominanceInfo dom(in->getParentOp());
  WindowPath(in, use, WindowPathKind::DominatedBackward, UseBlockOps::BeforeUse, &dom).forEachOp([&](Operation *op) {
    considerOp(op, ans);
    return true;
  });
  return ans;
}

struct Printer {
  DataFlowSolver &solver;
  AsmState &state;
  raw_ostream &os;
  ModuleOp module;

  std::string name(Value v) {
    std::string s;
    llvm::raw_string_ostream ss(s);
    v.printAsOperand(ss, state);
    if (auto nl = dyn_cast<NameLoc>(v.getLoc()))
      ss << " name=" << nl.getName().getValue();
    return s;
  }
  std::string blockName(Block *b) {
    std::string s;
    llvm::raw_string_ostream ss(s);
    b->printAsOperand(ss, state);
    return s;
  }
  const IntegerValueRange *range(Value v) {
    auto *l = solver.lookupState<dataflow::IntegerValueRangeLattice>(v);
    if (!l || l->getValue().isUninitialized())
      return nullptr;
    return &l->getValue();
  }

  void integerFact(Value v) {
    auto it = dyn_cast<IntegerType>(v.getType());
    if (!it)
      return;
    os << "FACT kind=integer value=" << name(v) << " bitwidth=" << it.getWidth() << " ";
    if (const IntegerValueRange *r = range(v))
      os << rangesStr(r->getValue()) << " origin=IntegerRangeAnalysis\n";
    else
      os << "range=unreached origin=IntegerRangeAnalysis\n"; // DeadCodeAnalysis does not establish this block as live.
  }

  // Intersect upstream ranges with a sole incoming v-versus-constant condition.
  void edgeFacts(Block *b) {
    // Source ref.index in_range entry: one fact per index dimension.
    if (auto ri = dyn_cast_or_null<RefIndexOp>(b->getParentOp());
        ri && b->isEntryBlock() && b->getParent() == &ri.getInRange()) {
      if (std::optional<SmallVector<uint64_t, 2>> counts = elemCounts(ri.getRef(), ri.getField()))
        for (auto [k, idx] : llvm::enumerate(ri.getIndices()))
          if (k < counts->size())
            checkedIndexEdge(b, idx, "ebpf.ref.index", k, (*counts)[k]);
      return;
    }
    std::optional<EdgeCondition> ec = edgeCondition(b);
    if (!ec)
      return;
    // Expanded elem.in_range true edge: the corresponding dimension's index.
    if (auto test = ec->cond.getDefiningOp<ElemInRangeOp>()) {
      uint64_t dim = test.getDim().value_or(0);
      if (ec->whenTrue)
        if (std::optional<SmallVector<uint64_t, 2>> counts = elemCounts(test.getRef(), test.getField()); counts && dim < counts->size())
          checkedIndexEdge(b, test.getIndex(), "ebpf.elem.in_range", dim, (*counts)[dim]);
      return;
    }
    auto cmp = ec->cond.getDefiningOp<arith::CmpIOp>();
    if (!cmp)
      return;
    APInt c;
    Value v;
    arith::CmpIPredicate p = cmp.getPredicate();
    if (matchPattern(cmp.getRhs(), m_ConstantInt(&c)) && !matchPattern(cmp.getLhs(), m_Constant())) {
      v = cmp.getLhs();
    } else if (matchPattern(cmp.getLhs(), m_ConstantInt(&c)) && !matchPattern(cmp.getRhs(), m_Constant())) {
      v = cmp.getRhs();
      p = swapOperands(p);
    } else {
      return;
    }
    if (!isa<IntegerType>(v.getType()))
      return;
    if (!ec->whenTrue)
      p = arith::invertPredicate(p);
    os << "FACT kind=integer-edge block=" << blockName(b) << " value=" << name(v) << " via=" << ec->via << " edge="
       << (ec->whenTrue ? "true" : "false") << " cond=" << arith::stringifyCmpIPredicate(cmp.getPredicate()) << " ";
    std::optional<ConstantIntRanges> edge = rangeFromPredicate(p, c);
    const IntegerValueRange *up = range(v);
    if (!edge) {
      os << "infeasible\n";
      return;
    }
    ConstantIntRanges r = up ? up->getValue().intersection(*edge) : *edge;
    os << rangesStr(r) << " scope=block-only\n";
  }

  void nullFacts(Value v) {
    Type t = v.getType();
    if (isa<MaybeRefType, MaybeReservationType>(t)) {
      os << "FACT kind=nullable value=" << name(v) << " nonnull=false\n";
      return;
    }
    if (!isa<BorrowedType, ReservationType>(t))
      return;
    os << "FACT kind=nonnull value=" << name(v) << " ";
    if (auto arg = dyn_cast<BlockArgument>(v)) {
      Block *b = arg.getOwner();
      Operation *parent = b->getParentOp();
      if (b->isEntryBlock()) {
        if (auto rc = dyn_cast<RefCheckOp>(parent); rc && b->getParent() == &rc.getPresentRegion()) {
          os << "nonnull=true origin=ebpf.ref.check of=" << name(rc.getRef()) << " scope=present-region\n";
          return;
        }
        if (auto ir = dyn_cast<RingbufIfReservedOp>(parent); ir && b->getParent() == &ir.getPresentRegion()) {
          os << "nonnull=true origin=ebpf.ringbuf.if_reserved of=" << name(ir.getReservation()) << " scope=present-region\n";
          return;
        }
        // Borrowed subprogram arguments are caller-checked by op verification,
        // not by a local check in this function.
        if (isa<SubprogramOp>(parent) && isa<BorrowedType>(t)) {
          os << "nonnull=true origin=caller-checked-argument scope=function\n";
          return;
        }
        // Timer callback values come from the kernel contract (map-element
        // pointer), not a compiler check or caller-checked argument.
        if (isa<TimerCallbackOp>(parent) && isa<BorrowedType>(t) && arg.getArgNumber() == 0) {
          os << "nonnull=true origin=kernel-callback-contract scope=callback\n";
          return;
        }
      }
      os << "nonnull=unproven origin=unknown\n";
      return;
    }
    if (auto a = v.getDefiningOp<AssumePresentOp>()) {
      if (assumePresentPlacementHolds(a)) // Same CheckedEdge placement condition as VerifyStructured.
        os << "nonnull=true origin=ebpf.assume_present of=" << name(a.getValue())
           << " guard=ebpf.is_present-true-edge scope=dominated-by-assume\n";
      else
        os << "nonnull=unproven origin=ebpf.assume_present reason=not-only-under-is_present-true-edge\n";
      return;
    }
    os << "nonnull=unproven origin=unknown\n";
  }

  void windowDef(Value w) {
    auto wt = dyn_cast<PktWindowType>(w.getType());
    if (!wt)
      return;
    os << "FACT kind=packet-window value=" << name(w) << " len=" << wt.getLen() << " ";
    Value off;
    StringRef origin;
    if (auto arg = dyn_cast<BlockArgument>(w)) {
      Block *b = arg.getOwner();
      if (auto pc = dyn_cast_or_null<PacketCheckOp>(b->getParentOp());
          pc && b->isEntryBlock() && b->getParent() == &pc.getInRange()) {
        off = pc.getOffset();
        origin = "ebpf.packet.check";
      } else if (Block *pred = b->getSinglePredecessor()) {
        if (auto br = dyn_cast<PktCheckBrOp>(pred->getTerminator()); br && br.getInRange() == b && arg.getArgNumber() == 0) {
          off = br.getOffset();
          origin = "ebpf.pkt.check_br";
        }
      }
    }
    if (!off) {
      os << "origin=unknown\n";
      return;
    }
    os << "offset=" << name(off) << " ";
    const IntegerValueRange *r = range(off);
    std::optional<APInt> k = r ? r->getValue().getConstantValue() : std::nullopt;
    if (k)
      os << "checked=[" << k->getZExtValue() << "," << k->getZExtValue() + wt.getLen() << ")";
    else
      os << "checked=[offset,offset+" << wt.getLen() << ")";
    os << " origin=" << origin << "\n";
  }

  void windowUse(Operation *op) {
    Value w;
    int64_t index;
    if (auto st = dyn_cast<PacketStoreOp>(op)) {
      w = st.getWindow();
      index = st.getIndex();
    } else if (auto ld = dyn_cast<PacketWindowLoadOp>(op)) {
      w = ld.getWindow();
      index = ld.getIndex();
    } else {
      return;
    }
    WindowAnswer ans;
    auto arg = dyn_cast<BlockArgument>(w);
    Block *b = arg ? arg.getOwner() : nullptr;
    if (b && isa_and_nonnull<PacketCheckOp>(b->getParentOp()) && b->isEntryBlock())
      ans = windowAtStage1(w, op);
    else if (b && b->getSinglePredecessor() && isa<PktCheckBrOp>(b->getSinglePredecessor()->getTerminator()))
      ans = windowAtStage2(b, op);
    else
      ans = {WindowValidity::Unknown, nullptr};
    os << "FACT kind=packet-window-use window=" << name(w) << " use=" << op->getName() << "[" << index << "]";
    if (op->getNumResults())
      os << " result=" << name(op->getResult(0));
    switch (ans.v) {
    case WindowValidity::Valid:
      os << " valid=true\n";
      break;
    case WindowValidity::Invalid:
      os << " valid=false invalidated-by=" << ans.by->getName() << "\n";
      break;
    case WindowValidity::Unknown:
      os << " valid=unknown not-neutral=" << (ans.by ? ans.by->getName().getStringRef() : StringRef("<no-origin>")) << "\n";
      break;
    }
  }

  // Resolve dimension counts from @records with resolveRecordTemplate, shared
  // by lowering. Omit the key if resolution fails; do not infer a bound.
  std::optional<SmallVector<uint64_t, 2>> elemCounts(Value ref, StringRef field) {
    auto bt = dyn_cast<BorrowedType>(ref.getType());
    auto rt = bt ? dyn_cast<RecordType>(bt.getPointee()) : RecordType();
    if (!rt)
      return std::nullopt;
    for (auto sc : module.getOps<btf::ScopeOp>()) {
      if (sc.getSymName() != "records")
        continue;
      auto st = dyn_cast_or_null<btf::StructOp>(SymbolTable::lookupSymbolIn(sc, rt.getSymbol()));
      if (!st)
        return std::nullopt;
      std::string err;
      FailureOr<RecordTemplate> t = resolveRecordTemplate(sc, st, indexTemplate(field), err, /*recordLeaf=*/true);
      if (failed(t))
        return std::nullopt;
      SmallVector<uint64_t, 2> counts;
      for (const RecordDim &d : t->dims)
        counts.push_back(d.count);
      return counts;
    }
    return std::nullopt;
  }
  std::string elemBound(Value ref, StringRef field) {
    std::optional<SmallVector<uint64_t, 2>> counts = elemCounts(ref, field);
    if (!counts)
      return "";
    std::string b = " bound=[";
    for (auto [k, c] : llvm::enumerate(*counts))
      b += (k ? ",u<" : "u<") + std::to_string(c);
    return b + "]";
  }

  // Intersect checked index <u count with the upstream range, local to this
  // block without propagation. Omit counts that cannot be resolved from @records.
  void checkedIndexEdge(Block *b, Value idx, StringRef via, uint64_t dim, uint64_t count) {
    auto it = dyn_cast<IntegerType>(idx.getType());
    if (!it)
      return;
    os << "FACT kind=integer-edge block=" << blockName(b) << " value=" << name(idx) << " via=" << via << " dim=" << dim
       << " edge=true cond=ult ";
    unsigned w = it.getWidth();
    if (count == 0 || !llvm::isUIntN(w, count - 1)) {
      os << "infeasible\n";
      return;
    }
    ConstantIntRanges edge = ConstantIntRanges::fromUnsigned(APInt(w, 0), APInt(w, count - 1));
    const IntegerValueRange *up = range(idx);
    ConstantIntRanges r = up ? up->getValue().intersection(edge) : edge;
    os << rangesStr(r) << " scope=block-only\n";
  }

  // Checked array elements are source ref.index in_range arguments or
// expanded elem.at results satisfying CheckedEdge placement.
  void elemFact(Value v) {
    if (!isa<ElemType>(v.getType()))
      return;
    os << "FACT kind=elem value=" << name(v) << " ";
    auto head = [&](Value ref, StringRef field, ValueRange indices) {
      os << "ref=" << name(ref) << " field=" << field << " indices=[";
      llvm::interleave(indices, os, [&](Value i) { os << name(i); }, ",");
      os << "] ";
    };
    if (auto arg = dyn_cast<BlockArgument>(v)) {
      Block *b = arg.getOwner();
      if (auto ri = dyn_cast_or_null<RefIndexOp>(b->getParentOp());
          ri && b->isEntryBlock() && b->getParent() == &ri.getInRange()) {
        head(ri.getRef(), ri.getField(), ri.getIndices());
        os << "checked=true origin=ebpf.ref.index scope=in-range-region" << elemBound(ri.getRef(), ri.getField()) << "\n";
        return;
      }
    }
    if (auto at = v.getDefiningOp<ElemAtOp>()) {
      head(at.getRef(), at.getField(), at.getIndices());
      if (elemAtPlacementHolds(at))
        os << "checked=true origin=ebpf.elem.at guard=ebpf.elem.in_range-true-edge scope=dominated-by-elem.at"
           << elemBound(at.getRef(), at.getField()) << "\n";
      else
        os << "checked=unproven origin=ebpf.elem.at reason=not-only-under-elem.in_range-true-edge\n";
      return;
    }
    os << "checked=unproven origin=unknown\n";
  }

  void value(Value v) {
    integerFact(v);
    nullFacts(v);
    windowDef(v);
    elemFact(v);
  }

  void region(Region &r) {
    for (Block &b : r) {
      for (BlockArgument a : b.getArguments())
        value(a);
      edgeFacts(&b);
      for (Operation &op : b) {
        windowUse(&op);
        for (Value res : op.getResults())
          value(res);
        for (Region &nested : op.getRegions())
          region(nested);
      }
    }
  }
};

// Print semantic for region operations; expanded operations/multi-block
    // bodies identify the structured stage.
StringRef stageOf(Operation *scope) {
  bool s1 = false, s2 = false;
  scope->walk([&](Operation *op) {
    if (isa<RefCheckOp, RingbufIfReservedOp, PacketCheckOp, IfOp, LoopOp, RefIndexOp, SpinRegionOp, TailCallOp, VerdictIfOp,
            MapAtomicAddOp>(op))
      s1 = true;
    if (isa<IsPresentOp, AssumePresentOp, PktCheckBrOp, ElemInRangeOp, ElemAtOp, ElemMaskOp, TailCallTryOp, LoopSpillOp, cf::BranchOp,
            cf::CondBranchOp>(op)) // loop.spill is also a structured-stage operation.
      s2 = true;
  });
  if (s1 && s2)
    return "mixed";
  return s1 ? "semantic" : s2 ? "structured" : "straight-line";
}

struct EBPFPrintSemanticFactsPass : public mlir::ebpf::impl::EBPFPrintSemanticFactsBase<EBPFPrintSemanticFactsPass> {
  using EBPFPrintSemanticFactsBase::EBPFPrintSemanticFactsBase;

  void runOnOperation() override {
    ModuleOp module = getOperation();
    DataFlowSolver solver;
    dataflow::loadBaselineAnalyses(solver);
    solver.load<dataflow::IntegerRangeAnalysis>();
    if (failed(solver.initializeAndRun(module))) {
      module.emitError() << "ebpf-print-semantic-facts: the dataflow solver failed";
      return signalPassFailure();
    }
    AsmState state(module);
    Printer p{solver, state, llvm::errs(), module};
    unsigned scopes = 0;
    for (Operation &op : module.getBody()->getOperations()) {
      StringRef kind;
      if (isa<ProgramOp>(op))
        kind = "ebpf.program";
      else if (isa<SubprogramOp>(op))
        kind = "ebpf.func";
      else if (isa<LoopCallbackOp>(op))
        kind = "ebpf.loop_callback";
      else if (isa<TimerCallbackOp>(op))
        kind = "ebpf.timer.callback";
      else if (isa<LLVM::LLVMFuncOp>(op))
        kind = "llvm.func"; // ABI/LLVM stages retain only integer ranges; checked types became llvm.ptr.
      else
        continue;
      auto sym = op.getAttrOfType<StringAttr>(SymbolTable::getSymbolAttrName());
      if (op.getNumRegions() == 0 || op.getRegion(0).empty())
        continue;
      ++scopes;
      p.os << "SCOPE @" << (sym ? sym.getValue() : StringRef("<anon>")) << " op=" << kind << " stage=" << (isa<LLVM::LLVMFuncOp>(op) ? StringRef("lowered") : stageOf(&op)) << "\n";
      p.region(op.getRegion(0));
    }
    if (!scopes)
      p.os << "SCOPE none\n";
    markAllAnalysesPreserved();
  }
};

} // namespace
