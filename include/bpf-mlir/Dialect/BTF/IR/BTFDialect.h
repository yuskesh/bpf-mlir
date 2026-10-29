// Public BTF dialect declarations.
#ifndef BPF_MLIR_DIALECT_BTF_IR_BTFDIALECT_H
#define BPF_MLIR_DIALECT_BTF_IR_BTFDIALECT_H

#include "mlir/Bytecode/BytecodeOpInterface.h"
#include "mlir/IR/Attributes.h"
#include "mlir/IR/BuiltinAttributes.h"
#include "mlir/IR/Dialect.h"
#include "mlir/IR/OpDefinition.h"
#include "mlir/IR/RegionKindInterface.h"
#include "mlir/IR/SymbolTable.h"

#include "bpf-mlir/Dialect/BTF/IR/BTFOpsDialect.h.inc"

#define GET_ATTRDEF_CLASSES
#include "bpf-mlir/Dialect/BTF/IR/BTFOpsAttrs.h.inc"

#define GET_OP_CLASSES
#include "bpf-mlir/Dialect/BTF/IR/BTFOps.h.inc"

namespace mlir {
namespace btf {

// Return type size in bits, resolving named types from the symbol table at
// from, or nullopt when resolution fails.
std::optional<uint64_t> sizeInBits(Attribute type, Operation *from);

// Validate BTF types recursively, including nested anonymous types and references.
LogicalResult verifyType(Attribute type, Operation *from, llvm::StringRef what);

// MLIR DI lacks annotations. Lower PTR -> TYPE_TAG <tag> -> T as a named
// DIDerivedType pointer with this prefix/tag; after LLVM translation,
// ObjectEmitter replaces it with an unnamed pointer annotated btf_type_tag.
inline constexpr llvm::StringLiteral kTypeTagMarkerPrefix = "__ebpf_btf_type_tag.";

} // namespace btf
} // namespace mlir

#endif // BPF_MLIR_DIALECT_BTF_IR_BTFDIALECT_H
