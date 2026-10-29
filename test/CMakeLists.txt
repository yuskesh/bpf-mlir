configure_file(lit.cfg.py.in ${CMAKE_CURRENT_BINARY_DIR}/lit.cfg.py @ONLY)
add_custom_target(check-bpf-mlir
  COMMAND "${BPF_MLIR_PYTHON}" "${LLVM_EXTERNAL_LIT}" -sv "${CMAKE_CURRENT_BINARY_DIR}"
  DEPENDS ebpf-compile ebpf-opt ebpf-schema-check FileCheck not
  USES_TERMINAL)
