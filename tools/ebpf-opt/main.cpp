// mlir-opt with ebpf dialects and passes registered.
#include "bpf-mlir/Dialect/BPFABI/IR/BPFABIDialect.h"
#include "bpf-mlir/Dialect/BPFABI/Transforms/Passes.h"
#include "bpf-mlir/Dialect/BTF/Transforms/Passes.h"
#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h"

#include "mlir/InitAllDialects.h"
#include "mlir/InitAllPasses.h"
#include "mlir/Tools/mlir-opt/MlirOptMain.h"

int main(int argc, char **argv) {
  mlir::DialectRegistry registry;
  mlir::registerAllDialects(registry);
  registry.insert<mlir::ebpf::EBPFDialect, mlir::bpfabi::BPFABIDialect,
                  mlir::btf::BTFDialect>();

  mlir::registerAllPasses();
  mlir::ebpf::registerEBPFPasses();
  mlir::bpfabi::registerBPFABIPasses();
  mlir::btf::registerBTFPasses();
  // --convert-ebpf-to-llvm runs the staged lowering pipeline.
  mlir::ebpf::registerEBPFPipelines();

  return mlir::asMainReturnCode(
      mlir::MlirOptMain(argc, argv, "ebpf optimizer driver\n", registry));
}
