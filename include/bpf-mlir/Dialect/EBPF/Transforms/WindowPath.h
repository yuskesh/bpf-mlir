// One shared stage-2 window-to-use operation-set primitive serves W1 expansion,
// invalidation checks and semantic diagnostics. MayExecute is the reflexive
// forward(in) intersection backward(use-block), including cycles through in.
// DominatedBackward walks predecessors from use through in-dominated blocks
// and stops at in. BeforeUse excludes use and later ops unless the use block
// cycles, when it includes every other op; All includes use as well.
// MayExecute counts cycles through in; DominatedBackward counts only cycles
// avoiding in, since revisiting in recreates the window. W1 uses
// DominatedBackward+All; invalidation uses MayExecute+BeforeUse; diagnostics
// use DominatedBackward+BeforeUse. Replacing invalidation with DominatedBackward
// would broaden acceptance of handwritten stage-2 input and needs review.
#ifndef BPF_MLIR_DIALECT_EBPF_TRANSFORMS_WINDOWPATH_H
#define BPF_MLIR_DIALECT_EBPF_TRANSFORMS_WINDOWPATH_H

#include "mlir/IR/Dominance.h"
#include "mlir/IR/Operation.h"
#include "llvm/ADT/STLFunctionalExtras.h"
#include "llvm/ADT/SmallPtrSet.h"

namespace mlir::ebpf {

enum class WindowPathKind { MayExecute, DominatedBackward };
enum class UseBlockOps { BeforeUse, All };

class WindowPath {
public:
  // DominatedBackward needs DominanceInfo for in's region.
  WindowPath(Block *in, Operation *use, WindowPathKind kind, UseBlockOps useOps, DominanceInfo *dom = nullptr);

  // Test membership, respecting the configured use-block handling.
  bool contains(Operation *op) const;

  // Visit in region/block order, stopping when fn returns false.
  void forEachOp(llvm::function_ref<bool(Operation *)> fn) const;

private:
  Block *in;
  Block *useBlock;
  Operation *use;
  UseBlockOps useOps;
  bool useBlockOnCycle = false;
  llvm::SmallPtrSet<Block *, 16> blocks;
};

} // namespace mlir::ebpf

#endif
