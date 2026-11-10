# Canonical schema is upstream of IR and depends only on LLVMSupport JSON, not MLIR.
add_library(BpfMLIREBPFSchema STATIC
  Schema.cpp)
# spin_lock field size comes from MLIR-independent BpfMLIRKernelABI.
target_link_libraries(BpfMLIREBPFSchema PUBLIC LLVMSupport BpfMLIRKernelABI)

# BTF-enabled BPF ELF emission directly uses the BPF backend and MLIR-to-LLVM
# translation. Preserve the root build's direct-link include safeguards.
add_library(BpfMLIREBPFObject STATIC
  ObjectEmitter.cpp
  PresentCost.cpp
  PresentOutline.cpp)
target_link_libraries(BpfMLIREBPFObject PUBLIC
  BpfMLIREBPFSchema
  BpfMLIRKernelABI
  MLIRBTFDialect
  MLIRTargetLLVMIRExport
  MLIRToLLVMIRTranslationRegistration
  LLVMBPFCodeGen
  LLVMBPFDesc
  LLVMBPFInfo
  LLVMBPFAsmParser # scx.exit_info emits textual inline asm (cmpxchg32_32).
  LLVMMCParser
  LLVMCodeGen
  LLVMTarget
  LLVMCore
  LLVMObject
  LLVMObjCopy
  LLVMDebugInfoBTF
  LLVMMC
  LLVMPasses)
