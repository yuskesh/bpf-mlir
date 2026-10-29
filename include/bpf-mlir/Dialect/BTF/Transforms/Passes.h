// BTF pass entry points.
#ifndef BPF_MLIR_DIALECT_BTF_TRANSFORMS_PASSES_H
#define BPF_MLIR_DIALECT_BTF_TRANSFORMS_PASSES_H

#include "bpf-mlir/Dialect/BTF/IR/BTFDialect.h"

#include "mlir/Dialect/LLVMIR/LLVMDialect.h"
#include "mlir/IR/BuiltinOps.h"
#include "mlir/Pass/Pass.h"

#include <memory>

namespace mlir {
namespace btf {

#define GEN_PASS_DECL
#include "bpf-mlir/Dialect/BTF/Transforms/Passes.h.inc"

#define GEN_PASS_REGISTRATION
#include "bpf-mlir/Dialect/BTF/Transforms/Passes.h.inc"

} // namespace btf
} // namespace mlir

#endif // BPF_MLIR_DIALECT_BTF_TRANSFORMS_PASSES_H
