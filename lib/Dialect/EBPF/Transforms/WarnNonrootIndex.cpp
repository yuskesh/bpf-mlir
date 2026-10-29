//===- WarnNonrootIndex.cpp - warn about privilege-sensitive indexing --------===//
//
// Without CAP_PERFMON, 6.12/6.6 reject mixed constant/unknown paths to pointer
// addition with REASON_PATHS, including bounded-loop IVs with varying constants.
// Root and simple 7.1.8 cases can succeed, so this is a warning, not rejection.
//
// Trace source-IR origins: constants retain values through integer casts;
// select unions its arms. Region results collect yield origins tagged by
// operation/arm, excluding break/continue. Bounded-loop IVs/iter_args are
// loop-carried. Other arithmetic propagates loop-carried inputs, recognizes
// untagged constant inputs without computing values, or becomes unknown.
// Loads, helpers, function arguments, other loop arguments/results are unknown.
//
// Prune tagged constants when evaluating an enclosing if condition with that
// arm's values proves the ref.index branch unreachable. This is a conservative
// compiler approximation, not verifier path exploration. It changes no IR and
// performs no kernel-version comparisons.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h"

#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"

#include "mlir/Dialect/Arith/IR/Arith.h"

namespace mlir {
namespace ebpf {
#define GEN_PASS_DEF_EBPFWARNNONROOTINDEX
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h.inc"
} // namespace ebpf
} // namespace mlir

using namespace mlir;
using namespace mlir::ebpf;

namespace {

struct Origin {
  enum Kind { Const, Unknown, Carried } kind;
  std::optional<APInt> value; // Known value for Const origins.
  Location loc;
  SmallVector<std::pair<Operation *, unsigned>, 2> arms; // Traversed region arms, outermost last.
};

constexpr unsigned kMaxDepth = 32;

void collect(Value v, SmallVectorImpl<Origin> &out, unsigned depth);

void unknown(Value v, SmallVectorImpl<Origin> &out) { out.push_back({Origin::Unknown, std::nullopt, v.getLoc(), {}}); }

// Result i collects value i from every arm's terminating yield.
void regionResult(Operation *op, unsigned i, SmallVectorImpl<Origin> &out, unsigned depth) {
  for (auto [a, r] : llvm::enumerate(op->getRegions())) {
    for (Block &b : r) {
      Operation *t = b.getTerminator();
      if (!t || !isa<YieldOp, IfYieldOp>(t) || i >= t->getNumOperands())
        continue; // break/continue does not reach the result.
      SmallVector<Origin> sub;
      collect(t->getOperand(i), sub, depth + 1);
      for (Origin &o : sub) {
        o.arms.push_back({op, unsigned(a)});
        out.push_back(std::move(o));
      }
    }
  }
}

void collect(Value v, SmallVectorImpl<Origin> &out, unsigned depth) {
  if (depth > kMaxDepth)
    return unknown(v, out);
  if (auto ba = dyn_cast<BlockArgument>(v)) {
    auto loop = dyn_cast<LoopOp>(ba.getOwner()->getParentOp());
    if (loop && !loop.getUnroll() && !loop.getCallback())
      out.push_back({Origin::Carried, std::nullopt, v.getLoc(), {}});
    else
      unknown(v, out);
    return;
  }
  Operation *d = v.getDefiningOp();
  if (auto c = dyn_cast<arith::ConstantOp>(d)) {
    if (auto ia = dyn_cast<IntegerAttr>(c.getValue()))
      out.push_back({Origin::Const, ia.getValue(), c.getLoc(), {}});
    else
      unknown(v, out);
    return;
  }
  if (isa<arith::ExtUIOp, arith::ExtSIOp, arith::TruncIOp>(d)) {
    unsigned w = cast<IntegerType>(v.getType()).getWidth();
    SmallVector<Origin> sub;
    collect(d->getOperand(0), sub, depth + 1);
    for (Origin &o : sub) {
      if (o.value)
        o.value = isa<arith::ExtUIOp>(d) ? o.value->zext(w) : isa<arith::ExtSIOp>(d) ? o.value->sext(w) : o.value->trunc(w);
      out.push_back(std::move(o));
    }
    return;
  }
  if (auto sel = dyn_cast<arith::SelectOp>(d)) {
    collect(sel.getTrueValue(), out, depth + 1);
    collect(sel.getFalseValue(), out, depth + 1);
    return;
  }
  if (isa<IfOp, RefCheckOp, RefIndexOp, PacketCheckOp, RingbufIfReservedOp>(d))
    return regionResult(d, cast<OpResult>(v).getResultNumber(), out, depth);
  if (d->getDialect() && d->getDialect()->getNamespace() == "arith") {
    bool carried = false, allPlainConst = true;
    for (Value in : d->getOperands()) {
      SmallVector<Origin> sub;
      collect(in, sub, depth + 1);
      for (Origin &o : sub) {
        carried |= o.kind == Origin::Carried;
        allPlainConst &= o.kind == Origin::Const && o.arms.empty();
      }
    }
    if (carried)
      out.push_back({Origin::Carried, std::nullopt, v.getLoc(), {}});
    else if (allPlainConst)
      out.push_back({Origin::Const, std::nullopt, v.getLoc(), {}});
    else
      unknown(v, out);
    return;
  }
  unknown(v, out); // Loads, helpers, loop results and other unknown origins.
}

// Determine v for arm when all matching origins have the same constant value.
// Untagged constants also apply.
std::optional<APInt> valueUnder(Value v, std::pair<Operation *, unsigned> arm) {
  SmallVector<Origin> os;
  collect(v, os, 0);
  std::optional<APInt> val;
  bool any = false;
  for (const Origin &o : os) {
    // Origins from another arm of this operation cannot reach the selected arm.
    bool otherArm = llvm::any_of(o.arms, [&](auto x) { return x.first == arm.first && x.second != arm.second; });
    if (otherArm)
      continue;
    if (o.kind != Origin::Const || !o.value)
      return std::nullopt;
    if (val && *val != *o.value)
      return std::nullopt;
    val = o.value;
    any = true;
  }
  return any ? val : std::nullopt;
}

std::optional<bool> evalCond(Value cond, std::pair<Operation *, unsigned> arm) {
  if (auto cmp = cond.getDefiningOp<arith::CmpIOp>()) {
    auto l = valueUnder(cmp.getLhs(), arm), r = valueUnder(cmp.getRhs(), arm);
    if (!l || !r || l->getBitWidth() != r->getBitWidth())
      return std::nullopt;
    return arith::applyCmpPredicate(cmp.getPredicate(), *l, *r);
  }
  if (auto c = valueUnder(cond, arm))
    return !c->isZero();
  return std::nullopt;
}

// Does any arm in o contradict the enclosing if condition on the ref.index side?
bool unreachable(const Origin &o, Operation *use) {
  for (auto arm : o.arms)
    for (Operation *p = use->getParentOp(); p; p = p->getParentOp()) {
      if (p == arm.first || p->isAncestor(arm.first))
        break; // Conditions outside the arm's operation cannot observe its yielded value.
      auto ifOp = dyn_cast<IfOp>(p);
      if (!ifOp)
        continue;
      bool inThen = ifOp.getThenRegion().isAncestor(use->getParentRegion());
      if (auto r = evalCond(ifOp.getCond(), arm); r && *r != inThen)
        return true;
    }
  return false;
}

struct EBPFWarnNonrootIndexPass : public mlir::ebpf::impl::EBPFWarnNonrootIndexBase<EBPFWarnNonrootIndexPass> {
  using EBPFWarnNonrootIndexBase::EBPFWarnNonrootIndexBase;

  void runOnOperation() override {
    getOperation().walk([](RefIndexOp ri) {
      for (Value idx : ri.getIndices()) {
        SmallVector<Origin> os;
        collect(idx, os, 0);
        const Origin *konst = nullptr, *unk = nullptr, *carried = nullptr;
        for (const Origin &o : os) {
          if (o.kind == Origin::Carried)
            carried = carried ? carried : &o;
          else if (o.kind == Origin::Unknown)
            unk = unk ? unk : &o;
          else if (!unreachable(o, ri))
            konst = konst ? konst : &o;
        }
        if (carried) {
          mlir::emitWarning(ri.getLoc()) << "the index of ebpf.ref.index is a value carried by an ebpf.loop without unroll (a different constant on "
                              "each iteration reaches the same pointer arithmetic) — loaders without CAP_PERFMON were observed to reject "
                              "this pointer arithmetic on some kernels; use unroll or callback";
        } else if (konst && unk) {
          auto d = mlir::emitWarning(ri.getLoc()) << "the index of ebpf.ref.index can be a constant on one path and a non-constant value on another — "
                                       "loaders without CAP_PERFMON were observed to reject this pointer arithmetic on some kernels; "
                                       "keep the default out of the index (put the ref.index inside the present region) or make the default "
                                       "non-constant";
          d.attachNote(konst->loc) << "the constant index comes from here";
        }
      }
    });
    markAllAnalysesPreserved();
  }
};

} // namespace
