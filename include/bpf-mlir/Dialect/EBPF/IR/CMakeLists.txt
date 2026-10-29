# EBPFOps.td is the root. Generate EBPFOps{,Types,Dialect}.{h,cpp}.inc
# under the MLIREBPFOpsIncGen target.
add_mlir_dialect(EBPFOps ebpf)

# Stage2InternalOp canonically marks internal stage-2 operations.
set(LLVM_TARGET_DEFINITIONS EBPFOps.td)
mlir_tablegen(EBPFOpsInterfaces.h.inc -gen-op-interface-decls)
mlir_tablegen(EBPFOpsInterfaces.cpp.inc -gen-op-interface-defs)
add_public_tablegen_target(MLIREBPFOpsInterfacesIncGen)
add_dependencies(MLIREBPFOpsIncGen MLIREBPFOpsInterfacesIncGen)
