//===- Pipeline.cpp - staged lowering and exit checks -----------------------===//
//
// Target legality precedes source-region expansion. Verify expanded CFG,
// lower to LLVM plus kernel ABI operations, verify ABI/table agreement,
// record per-program requirements, then expand ABI operations to LLVM.
// Callers install source ownership/schema checks before this pipeline.
// Arithmetic conversion and cast reconciliation follow before LLVM IR/ELF.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h"

#include "bpf-mlir/Dialect/BPFABI/Transforms/Passes.h"

#include "mlir/Pass/PassRegistry.h"

using namespace mlir;

void mlir::ebpf::buildEBPFToLLVMPipeline(OpPassManager &pm, const TuneOptions &tune, llvm::StringRef targetProfile) {
  EBPFVerifyTargetLegalityOptions tl;
  tl.profilePath = targetProfile.str();
  pm.addPass(createEBPFVerifyTargetLegality(tl));
  EBPFExpandRegionsOptions er;
  er.sinkWindowLoads = tune.sinkWindowLoads;
  er.windowLoadNested = tune.windowLoadNested;
  er.maskCheckedIndex = tune.maskCheckedIndex;
  er.maskSkipConstantIndex = tune.maskSkipConstantIndex;
  er.threadI1Join = tune.threadI1Join;
  er.backedgeSpill = tune.backedgeSpill;   // Iteration spill barrier.
  er.backedgeRotate = tune.backedgeRotate; // Back-edge rotation.
  pm.addPass(createEBPFExpandRegions(er));
  pm.addPass(createEBPFVerifyStructured());
  ConvertEBPFToBPFABIOptions cv;
  cv.skipFullCoverMemset = tune.skipFullCoverMemset;
  cv.storeRecordDirect = tune.storeRecordDirect;
  cv.storeRecordMerge = tune.storeRecordMerge;
  cv.shareKeySlot = tune.shareKeySlot;
  cv.spillLifetime = tune.spillLifetime;
  cv.warnIndexMaskFit = tune.warnIndexMaskFit;
  cv.alignedPacketLoad = tune.alignedPacketLoad;
  pm.addPass(createConvertEBPFToBPFABI(cv));
  pm.addPass(bpfabi::createBPFABIVerify());
  pm.addPass(bpfabi::createBPFABIRequirements());
  pm.addPass(bpfabi::createConvertBPFABIToLLVM());
}

void mlir::ebpf::registerEBPFPipelines() {
  PassPipelineRegistration<>(
      "convert-ebpf-to-llvm",
      "lower ebpf to LLVM dialect in stages (1 -> 2 -> 3 -> 4, including each stage's exit checks)",
      [](OpPassManager &pm) { buildEBPFToLLVMPipeline(pm); });
}
