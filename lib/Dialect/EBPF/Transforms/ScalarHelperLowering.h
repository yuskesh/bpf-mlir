// Internal output-slot mechanics; helper selection belongs to the caller.
#ifndef BPFMLIR_SCALAR_HELPER_LOWERING_H
#define BPFMLIR_SCALAR_HELPER_LOWERING_H

#include "mlir/IR/Builders.h"

namespace mlir::ebpf::detail {
Value scalarOutputSlot(OpBuilder &b, Block *entry, Location loc, Type type,
                       unsigned alignment);
void clearScalarOutput(OpBuilder &b, Location loc, Value slot, Type type,
                       unsigned alignment);
Value scalarOutputValue(OpBuilder &b, Location loc, Value slot,
                        IntegerType loadType, IntegerType resultType,
                        Value status, unsigned alignment);
} // namespace mlir::ebpf::detail
#endif
