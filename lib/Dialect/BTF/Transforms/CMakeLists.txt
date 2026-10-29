add_library(MLIRBTFTransforms STATIC
  BuildBTF.cpp
  BTFToLLVMDI.cpp
  VerifyBTF.cpp
  DumpGraph.cpp)
add_dependencies(MLIRBTFTransforms MLIRBTFTransformsIncGen)
target_link_libraries(MLIRBTFTransforms PUBLIC
  MLIRBTFDialect
  MLIREBPFDialect
  BpfMLIREBPFSchema
  BpfMLIRKernelABI
  MLIRPass
  MLIRLLVMDialect)
