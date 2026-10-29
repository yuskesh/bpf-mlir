// ebpf pass entry points.
#ifndef BPF_MLIR_DIALECT_EBPF_TRANSFORMS_PASSES_H
#define BPF_MLIR_DIALECT_EBPF_TRANSFORMS_PASSES_H

#include "bpf-mlir/Dialect/BPFABI/IR/BPFABIDialect.h"

#include "mlir/Dialect/ControlFlow/IR/ControlFlow.h"
#include "mlir/Dialect/LLVMIR/LLVMDialect.h"
#include "mlir/IR/BuiltinOps.h"
#include "mlir/Pass/Pass.h"
#include "mlir/Pass/PassManager.h"

#include <memory>

namespace mlir {
namespace ebpf {

#define GEN_PASS_DECL
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h.inc"

#define GEN_PASS_REGISTRATION
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h.inc"

// Compiler and --convert-ebpf-to-llvm share the complete staged pipeline.
// C3 (C1+C2) is enabled by default; disabling it selects the older conversion.
struct TuneOptions {
  bool sinkWindowLoads = true;     // C1
  bool skipFullCoverMemset = true; // C2
  bool storeRecordDirect = false;   // Optional D1 conversion.
  bool storeRecordMerge = true;     // D2 includes D1 and is enabled by default.
  bool shareKeySlot = false;        // Optional K1 conversion.
  bool spillLifetime = true;        // Enabled by default; false selects v0.15.0-style output.
  bool maskCheckedIndex = true;     // M1, enabled by default.
  bool maskSkipConstantIndex = true;  // Omit M1 for constant indices by default.
  bool windowLoadNested = true;     // W1, enabled by default.
  bool threadI1Join = false;        // Optional K2b conversion.
  bool warnIndexMaskFit = true;     // Fit warning only; does not change output.
  bool backedgeSpill = true;        // S, enabled by default: per-iteration volatile stores to dedicated stack
// slots in bounded loops, forming a speculation-path barrier.
  bool alignedPacketLoad = true;    // Enabled by default: one wide packet read when (2 + constant offset) mod width = 0.
  bool backedgeRotate = false;      // R rotates bounded loops: entry has only the bound guard, latch checks
// i+1, then i<n, then i<N.
};
// Empty targetProfile checks compiler legality only and defers target
// decisions to loading; otherwise use the explicit verifier-policy profile.
void buildEBPFToLLVMPipeline(OpPassManager &pm, const TuneOptions &tune = {}, llvm::StringRef targetProfile = "");
void registerEBPFPipelines();

} // namespace ebpf
} // namespace mlir

#endif // BPF_MLIR_DIALECT_EBPF_TRANSFORMS_PASSES_H
