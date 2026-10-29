# ebpf dialect implementation depends on generated MLIREBPFOpsIncGen declarations.
add_library(MLIREBPFDialect STATIC
  IR/EBPFDialect.cpp)
add_dependencies(MLIREBPFDialect MLIREBPFOpsIncGen)
# ebpf.ctx.field verification uses UAPI ctxfield and capability ctxaccess tables.
target_link_libraries(MLIREBPFDialect PUBLIC MLIRIR MLIRSupport BpfMLIRKernelABI)
add_subdirectory(Transforms)
