# Validate schema JSON corpus and frontend output against docs/schema_format.md.
add_llvm_executable(ebpf-schema-check ebpf-schema-check.cpp)
llvm_update_compile_flags(ebpf-schema-check)
target_link_libraries(ebpf-schema-check PRIVATE BpfMLIREBPFSchema)
