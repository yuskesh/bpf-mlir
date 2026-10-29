add_library(MLIRBPFABITransforms STATIC
  VerifyABI.cpp
  Requirements.cpp
  TpBufferLoweringInternal.cpp
  BPFABIToLLVM.cpp)
add_dependencies(MLIRBPFABITransforms MLIRBPFABITransformsIncGen)
target_link_libraries(MLIRBPFABITransforms PUBLIC
  MLIRBPFABIDialect
  MLIRPass
  MLIRLLVMDialect)
