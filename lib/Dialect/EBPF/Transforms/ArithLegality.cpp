//===- ArithLegality.cpp - reject arithmetic UB/poison at compiler entry -----===//
//
// Dialect membership alone does not establish safe arithmetic. For example,
// divui w,w can fold to one under LLVM's division-by-zero UB assumptions.
// Enforce docs/arith_contract.md before lowering.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/ArithLegality.h"

#include "mlir/Analysis/DataFlow/IntegerRangeAnalysis.h"
#include "mlir/Analysis/DataFlow/Utils.h"
#include "mlir/Analysis/DataFlowFramework.h"
#include "mlir/Dialect/Arith/IR/Arith.h"
#include "mlir/IR/Matchers.h"
#include "llvm/ADT/StringExtras.h"

using namespace mlir;

namespace {

std::string rangeText(const ConstantIntRanges &r) {
  return "unsigned [" + llvm::toString(r.umin(), 10, false) + ", " + llvm::toString(r.umax(), 10, false) + "], signed [" +
         llvm::toString(r.smin(), 10, true) + ", " + llvm::toString(r.smax(), 10, true) + "]";
}

struct Checker {
  DataFlowSolver &solver;
  bool bad = false;

  // Exact constants, otherwise IntegerRangeAnalysis or the full domain when absent.
  ConstantIntRanges rangeOf(Value v) {
    unsigned w = cast<IntegerType>(v.getType()).getWidth();
    APInt c;
    if (matchPattern(v, m_ConstantInt(&c)))
      return ConstantIntRanges::constant(c);
    if (auto *l = solver.lookupState<dataflow::IntegerValueRangeLattice>(v))
      if (!l->getValue().isUninitialized())
        return l->getValue().getValue();
    return ConstantIntRanges::maxRange(w);
  }

  void reject(Operation *op, const Twine &why, bool poison = true, StringRef tag = "arithmetic contract") {
    bad = true;
    auto d = op->emitOpError() << why;
    if (poison)
      d << "; ebpf-compile rejects arith ops whose LLVM semantics are undefined or poison for some inputs "
           "(LLVM may fold them assuming the case never happens) (" << tag << ")";
    else
      d << " (" << tag << ")";
  }

  void check(Operation *op) {
    // Non-integer types are rejected by type alone.
    for (Type t : llvm::concat<Type>(op->getOperandTypes(), op->getResultTypes()))
      if (!isa<IntegerType>(t)) {
        reject(op, "has a " + [&] {
          std::string s;
          llvm::raw_string_ostream os(s);
          os << t;
          return s;
        }() + " operand or result; eBPF has no floating-point, index or vector values, and ebpf-compile does not lower them",
               /*poison=*/false);
        return;
      }
    // Poison-producing flags.
    if (auto f = op->getAttrOfType<arith::IntegerOverflowFlagsAttr>("overflowFlags");
        f && f.getValue() != arith::IntegerOverflowFlags::none) {
      reject(op, "has overflow flags (nsw / nuw), which make overflow poison");
      return;
    }
    if (op->hasAttr("isExact")) {
      reject(op, "has the exact flag, which makes a non-exact result poison");
      return;
    }
    // Division and remainder.
    if (isa<arith::DivUIOp, arith::RemUIOp, arith::CeilDivUIOp>(op)) {
      ConstantIntRanges d = rangeOf(op->getOperand(1));
      if (d.umin().isZero())
        reject(op, "divisor may be 0 (range " + rangeText(d) + "); show it is non-zero, e.g. a constant or arith.ori %d, 1");
      return;
    }
    if (isa<arith::DivSIOp, arith::RemSIOp, arith::CeilDivSIOp, arith::FloorDivSIOp>(op)) {
      ConstantIntRanges n = rangeOf(op->getOperand(0)), d = rangeOf(op->getOperand(1));
      if (!(d.smin().isStrictlyPositive() || d.smax().isNegative())) {
        reject(op, "divisor may be 0 (range " + rangeText(d) + "); show it is non-zero");
        return;
      }
      // eBPF CPU v1 has no signed division instruction. LLVM expands nonzero
      // constant divisors for i8..i32 through magic multiplication, but only
      // signed powers of two for i64 through shifts. Reject other cases here
      // explicitly rather than reaching the backend unsupported-division error.
      {
        unsigned dw = d.smin().getBitWidth();
        bool isConst = d.smin() == d.smax();
        if (!isConst || (dw == 64 && !d.smin().abs().isPowerOf2())) {
          reject(op, Twine("needs a constant divisor (") + (isConst ? "an i64 divisor must be +-2^k" : "not a variable") +
                         "; the eBPF CPU v1 has no signed division — LLVM expands a constant divisor: any non-zero constant "
                         "for i8 / i16 / i32, only +-2^k for i64; divisor range " + rangeText(d) +
                         "); for another divisor, divide the magnitudes with arith.divui / arith.remui and correct the sign "
                         "in the frontend (docs/arith_contract.md)",
                 /*poison=*/false, "arithmetic contract");
          return;
        }
      }
      unsigned w = n.smin().getBitWidth();
      bool dMayBeMinusOne = d.smin().sle(APInt::getAllOnes(w)) && d.smax().sge(APInt::getAllOnes(w));
      bool nMayBeMin = n.smin().isMinSignedValue();
      if (dMayBeMinusOne && nMayBeMin)
        reject(op, "may divide the minimum signed value by -1, which overflows (dividend range " + rangeText(n) +
                       ", divisor range " + rangeText(d) + ")");
      return;
    }
    // Shift counts.
    if (isa<arith::ShLIOp, arith::ShRUIOp, arith::ShRSIOp>(op)) {
      ConstantIntRanges c = rangeOf(op->getOperand(1));
      unsigned w = cast<IntegerType>(op->getResult(0).getType()).getWidth();
      if (c.umax().uge(w))
        reject(op, "shift count may be >= the bit width " + Twine(w) + " (range " + rangeText(c) +
                       "); show it is smaller, e.g. arith.andi %c, " + Twine(w - 1) + " (the eBPF masking made explicit)");
      return;
    }
  }
};

} // namespace

LogicalResult mlir::ebpf::verifyArithLegality(ModuleOp module) {
  DataFlowSolver solver;
  dataflow::loadBaselineAnalyses(solver);
  solver.load<dataflow::IntegerRangeAnalysis>();
  if (failed(solver.initializeAndRun(module))) {
    module.emitError() << "arith legality: the dataflow solver failed";
    return failure();
  }
  Checker c{solver};
  module.walk([&](Operation *op) {
    if (op->getDialect() && op->getDialect()->getNamespace() == "arith")
      c.check(op);
  });
  return failure(c.bad);
}
