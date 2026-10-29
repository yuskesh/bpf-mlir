// Conservatively estimate BPF instruction counts in blocks dominated by each
// ringbuf_reserve result's non-null entry, after LLVM verification and before
// codegen. The same LLVM IR gives the same estimate, used for outlining and
// --report-present-cost diagnostics.

#ifndef BPF_MLIR_TARGET_EBPF_PRESENTCOST_H
#define BPF_MLIR_TARGET_EBPF_PRESENTCOST_H

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Module.h"

namespace ebpf {

// Maximum BPF argument count. Above this combined input/output count,
// CodeExtractor aggregates values in a stack struct passed by one pointer.
// Cost estimation and outline eligibility must use the same boundary.
constexpr unsigned kMaxBPFArgs = 5;

struct PresentCost {
  llvm::Function *fn = nullptr;       // Function containing the reservation.
  unsigned index = 0;                 // Reservation index in function instruction order.
  llvm::BasicBlock *entry = nullptr;  // Non-null entry block.
  llvm::SmallVector<llvm::BasicBlock *> blocks; // Blocks dominated by entry, including entry itself.
  uint64_t estimate = 0;              // Estimated BPF instruction count.
};

// Estimate all reservations in function/reservation order, omitting those
// without a null-check branch.
llvm::SmallVector<PresentCost> estimatePresentCosts(llvm::Module &m);

} // namespace ebpf

#endif
