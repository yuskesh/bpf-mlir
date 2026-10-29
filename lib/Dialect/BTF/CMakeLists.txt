# BTF dialect.
add_library(MLIRBTFDialect STATIC
  IR/BTFDialect.cpp)
add_dependencies(MLIRBTFDialect MLIRBTFOpsIncGen)
target_link_libraries(MLIRBTFDialect PUBLIC MLIRIR MLIRSupport)
add_subdirectory(Transforms)
