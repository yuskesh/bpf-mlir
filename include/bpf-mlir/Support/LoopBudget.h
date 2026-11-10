// Conservative compiler loop limits, independent of kernel verifier budgets.
#ifndef BPF_MLIR_SUPPORT_LOOPBUDGET_H
#define BPF_MLIR_SUPPORT_LOOPBUDGET_H
#include <algorithm>
#include <cstdint>
#include <limits>

namespace mlir::ebpf {
struct LoopBudget {
  static constexpr int64_t maxDepth = 2;
  static constexpr int64_t legacyLimit = 64;
  static constexpr int64_t boundedLimit = 4096;
  int64_t depth = 0;
  int64_t product = 1;
  bool bounded = false;
  bool helper = false;

  static int64_t countLimit(bool unroll, bool callback) {
    return unroll || callback ? legacyLimit : boundedLimit;
  }
  int64_t productLimit() const {
    return bounded && !helper ? boundedLimit : legacyLimit;
  }
  LoopBudget enter(int64_t count, bool unroll, bool callback) const {
    LoopBudget next = *this;
    ++next.depth;
    next.bounded |= !unroll && !callback;
    next.helper |= callback;
    int64_t n = std::max<int64_t>(count, 1);
    // Preserve exact diagnostics when representable; never wrap into acceptance.
    constexpr int64_t ceiling = std::numeric_limits<int64_t>::max();
    next.product = n > ceiling / product ? ceiling : product * n;
    return next;
  }
  // an ebpf.iter.num adds one nesting level but no count factor — the
  // verifier checks its body by state convergence, not by unrolling it.
  LoopBudget enterIter() const {
    LoopBudget next = *this;
    ++next.depth;
    return next;
  }
  bool dominates(const LoopBudget &other) const {
    return bounded == other.bounded && helper == other.helper &&
           depth >= other.depth && product >= other.product;
  }
};
} // namespace mlir::ebpf
#endif
