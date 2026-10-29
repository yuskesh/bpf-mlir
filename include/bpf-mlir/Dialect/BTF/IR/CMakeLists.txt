# Generate BTF types/attributes explicitly instead of add_mlir_dialect.
set(LLVM_TARGET_DEFINITIONS BTFOps.td)
mlir_tablegen(BTFOps.h.inc -gen-op-decls)
mlir_tablegen(BTFOps.cpp.inc -gen-op-defs)
mlir_tablegen(BTFOpsDialect.h.inc -gen-dialect-decls -dialect=btf)
mlir_tablegen(BTFOpsDialect.cpp.inc -gen-dialect-defs -dialect=btf)
mlir_tablegen(BTFOpsAttrs.h.inc -gen-attrdef-decls -attrdefs-dialect=btf)
mlir_tablegen(BTFOpsAttrs.cpp.inc -gen-attrdef-defs -attrdefs-dialect=btf)
add_public_tablegen_target(MLIRBTFOpsIncGen)
