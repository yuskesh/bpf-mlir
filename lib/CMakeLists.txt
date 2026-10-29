add_subdirectory(Dialect)
add_subdirectory(Target)

# C ABI for schema parsing/serialization, kept in the developer build.
if(BPF_MLIR_BUILD_CAPI)
add_library(BpfMLIRCAPI STATIC
  CAPI/Support.cpp
  CAPI/EBPF.cpp)
target_include_directories(BpfMLIRCAPI PUBLIC
  ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(BpfMLIRCAPI PUBLIC BpfMLIREBPFSchema)
endif()
