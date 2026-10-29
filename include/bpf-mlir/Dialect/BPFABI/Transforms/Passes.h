// Kernel-ABI pass entry points.
#ifndef BPF_MLIR_DIALECT_BPFABI_TRANSFORMS_PASSES_H
#define BPF_MLIR_DIALECT_BPFABI_TRANSFORMS_PASSES_H

#include "mlir/Dialect/LLVMIR/LLVMDialect.h"
#include "mlir/IR/BuiltinOps.h"
#include "mlir/Pass/Pass.h"

#include <memory>

namespace mlir {
namespace bpfabi {

#define GEN_PASS_DECL
#include "bpf-mlir/Dialect/BPFABI/Transforms/Passes.h.inc"

#define GEN_PASS_REGISTRATION
#include "bpf-mlir/Dialect/BPFABI/Transforms/Passes.h.inc"

} // namespace bpfabi
} // namespace mlir

#endif // BPF_MLIR_DIALECT_BPFABI_TRANSFORMS_PASSES_H
