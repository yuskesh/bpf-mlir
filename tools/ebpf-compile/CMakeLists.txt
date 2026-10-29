add_llvm_executable(ebpf-compile ebpf-compile.cpp)
llvm_update_compile_flags(ebpf-compile)
target_link_libraries(ebpf-compile PRIVATE
  MLIREBPFDialect
  MLIREBPFTransforms
  MLIRBTFTransforms
  BpfMLIREBPFObject
  MLIRParser
  MLIRPass
  MLIRArithToLLVM
  MLIRReconcileUnrealizedCasts
  MLIRFuncDialect
  MLIRSCFDialect
  MLIRControlFlowDialect
  MLIRLLVMDialect)
mlir_check_all_link_libraries(ebpf-compile)

# Generate --version metadata each build; gen-version leaves an identical header untouched.
set(BPF_MLIR_VERSION_HEADER ${CMAKE_BINARY_DIR}/include/bpf-mlir/Version.inc)
set(_bpf_mlir_version_args)
if(BPF_MLIR_DISTRIBUTION)
  list(APPEND _bpf_mlir_version_args "${CMAKE_SOURCE_DIR}" --distribution)
endif()
add_custom_target(bpf-mlir-version ALL
  COMMAND ${CMAKE_SOURCE_DIR}/scripts/gen-version ${BPF_MLIR_VERSION_HEADER} ${_bpf_mlir_version_args}
  BYPRODUCTS ${BPF_MLIR_VERSION_HEADER}
  COMMENT "Write bpf-mlir version (git describe) to header"
  VERBATIM)
add_dependencies(ebpf-compile bpf-mlir-version)
