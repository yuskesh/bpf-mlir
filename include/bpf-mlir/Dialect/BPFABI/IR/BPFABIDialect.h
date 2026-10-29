// Public declarations for the kernel-ABI dialect.
#ifndef BPF_MLIR_DIALECT_BPFABI_IR_BPFABIDIALECT_H
#define BPF_MLIR_DIALECT_BPFABI_IR_BPFABIDIALECT_H

#include "mlir/Bytecode/BytecodeOpInterface.h"
#include "mlir/IR/Dialect.h"
#include "mlir/IR/OpDefinition.h"
#include "mlir/Interfaces/SideEffectInterfaces.h"

#include "bpf-mlir/Dialect/BPFABI/IR/BPFABIOpsDialect.h.inc"

#define GET_OP_CLASSES
#include "bpf-mlir/Dialect/BPFABI/IR/BPFABIOps.h.inc"

#endif // BPF_MLIR_DIALECT_BPFABI_IR_BPFABIDIALECT_H
