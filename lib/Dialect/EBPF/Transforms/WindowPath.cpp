//===- WindowPath.cpp - expanded window-to-use operation paths ---------------===//
//
// Shared traversal for expansion's neutral-path checks, structured invalidation
// verification and semantic fact diagnostics. Callers select path and use bounds.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/WindowPath.h"

#include "llvm/ADT/SmallVector.h"

using namespace mlir;
using namespace mlir::ebpf;

namespace {
// Reachable successors/predecessors of from. Include from only through a
// cycle. Include stop if reached but do not expand beyond it.
llvm::SmallPtrSet<Block *, 16> strictClosure(Block *from, bool forward, Block *stop = nullptr) {
  llvm::SmallPtrSet<Block *, 16> seen;
  SmallVector<Block *> work;
  auto push = [&](Block *b) {
    if (forward)
      work.append(b->getSuccessors().begin(), b->getSuccessors().end());
    else
      work.append(b->getPredecessors().begin(), b->getPredecessors().end());
  };
  push(from);
  while (!work.empty()) {
    Block *x = work.pop_back_val();
    if (!seen.insert(x).second)
      continue;
    if (x != stop)
      push(x);
  }
  return seen;
}
} // namespace

WindowPath::WindowPath(Block *in, Operation *use, WindowPathKind kind, UseBlockOps useOps, DominanceInfo *dom)
    : in(in), useBlock(use->getBlock()), use(use), useOps(useOps) {
  // DominatedBackward excludes cycles through in: re-entry recreates its
  // block-argument window. MayExecute retains those cycles for compatibility
  // with invalidation acceptance. If ub==in, no cycle can avoid in.
  if (kind == WindowPathKind::DominatedBackward)
    useBlockOnCycle = useBlock != in && strictClosure(useBlock, /*forward=*/true, /*stop=*/in).contains(useBlock);
  else
    useBlockOnCycle = strictClosure(useBlock, /*forward=*/true).contains(useBlock);
  if (kind == WindowPathKind::MayExecute) {
    llvm::SmallPtrSet<Block *, 16> fwd = strictClosure(in, true), bwd = strictClosure(useBlock, false);
    fwd.insert(in);
    bwd.insert(useBlock);
    for (Block *b : fwd)
      if (bwd.contains(b))
        blocks.insert(b);
    return;
  }
  assert(dom && "DominatedBackward needs DominanceInfo");
  SmallVector<Block *> work{useBlock};
  blocks.insert(useBlock);
  while (!work.empty()) {
    Block *b = work.pop_back_val();
    if (b == in)
      continue;
    for (Block *p : b->getPredecessors())
      if (dom->dominates(in, p) && blocks.insert(p).second)
        work.push_back(p);
  }
}

bool WindowPath::contains(Operation *op) const {
  Block *b = op->getBlock();
  if (!blocks.contains(b))
    return false;
  if (b != useBlock || useOps == UseBlockOps::All)
    return true;
  return op != use && (useBlockOnCycle || op->isBeforeInBlock(use));
}

void WindowPath::forEachOp(llvm::function_ref<bool(Operation *)> fn) const {
  for (Block &b : *in->getParent()) {
    if (!blocks.contains(&b))
      continue;
    for (Operation &op : b) {
      if (&b == useBlock && useOps == UseBlockOps::BeforeUse) {
        if (!useBlockOnCycle && &op == use)
          break;
        if (&op == use)
          continue;
      }
      if (!fn(&op))
        return;
    }
  }
}
