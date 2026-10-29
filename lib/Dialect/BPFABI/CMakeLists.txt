# Keep the UAPI table independent of MLIR for consumers such as ObjectEmitter.
add_library(BpfMLIRKernelABI STATIC
  KernelABI.cpp)
target_link_libraries(BpfMLIRKernelABI PUBLIC LLVMSupport)

# Kernel-ABI dialect.
add_library(MLIRBPFABIDialect STATIC
  IR/BPFABIDialect.cpp)
add_dependencies(MLIRBPFABIDialect MLIRBPFABIOpsIncGen)
target_link_libraries(MLIRBPFABIDialect PUBLIC MLIRIR MLIRSupport MLIRLLVMDialect BpfMLIRKernelABI)
add_subdirectory(Transforms)
