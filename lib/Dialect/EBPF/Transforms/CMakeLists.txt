add_library(MLIREBPFTransforms STATIC
  VerifyOwnership.cpp
  VerifySchema.cpp
  VerifyKPtr.cpp
  VerifyRecords.cpp
  RecordPath.cpp
  PacketNeutral.cpp
  CheckedEdge.cpp
  ArithLegality.cpp
  WindowPath.cpp
  TargetProfile.cpp
  VerifyTargetLegality.cpp
  VerifyCallGraph.cpp
  ExpandRegions.cpp
  VerifyStructured.cpp
  EBPFToBPFABI.cpp
  PrintSemanticFacts.cpp
  WarnNonrootIndex.cpp
  Pipeline.cpp)
add_dependencies(MLIREBPFTransforms MLIREBPFTransformsIncGen)
target_link_libraries(MLIREBPFTransforms PUBLIC
  BpfMLIREBPFSchema
  MLIREBPFDialect
  MLIRBPFABIDialect
  MLIRBPFABITransforms
  MLIRBTFDialect
  MLIRPass
  MLIRTransforms
  MLIRLLVMDialect
  MLIRControlFlowDialect
  MLIRSCFDialect
  MLIRFuncDialect
  MLIRAnalysis
  MLIRArithDialect
  MLIRInferIntRangeInterface)
