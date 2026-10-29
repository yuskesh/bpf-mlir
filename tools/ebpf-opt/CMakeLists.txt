add_llvm_executable(ebpf-opt main.cpp)
llvm_update_compile_flags(ebpf-opt)
target_link_libraries(ebpf-opt PRIVATE
  MLIREBPFDialect
  MLIREBPFTransforms
  MLIRBTFTransforms
  MLIROptLib
  MLIRRegisterAllDialects
  MLIRRegisterAllPasses)
mlir_check_all_link_libraries(ebpf-opt)
