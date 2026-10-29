// Public ebpf dialect declarations.
#ifndef BPF_MLIR_DIALECT_EBPF_IR_EBPFDIALECT_H
#define BPF_MLIR_DIALECT_EBPF_IR_EBPFDIALECT_H

#include "mlir/Bytecode/BytecodeOpInterface.h"
#include "mlir/IR/BuiltinTypes.h"
#include "mlir/IR/Dialect.h"
#include "mlir/IR/OpDefinition.h"
#include "mlir/IR/SymbolTable.h"
#include "mlir/Interfaces/SideEffectInterfaces.h"

#include "bpf-mlir/Dialect/EBPF/IR/EBPFOpsDialect.h.inc"

namespace mlir {
namespace ebpf {
// Declare resources only for packet reads/writes and reservation stores.
// ref/field/elem accesses (normal and once) and helper operations keep unknown
// effects; do not accidentally make them appear pure.
struct PacketResource : public SideEffects::Resource::Base<PacketResource> {
  MLIR_DEFINE_EXPLICIT_INTERNAL_INLINE_TYPE_ID(PacketResource)
  llvm::StringRef getName() const final { return "ebpf.packet"; }
};
struct ReservationResource : public SideEffects::Resource::Base<ReservationResource> {
  MLIR_DEFINE_EXPLICIT_INTERNAL_INLINE_TYPE_ID(ReservationResource)
  llvm::StringRef getName() const final { return "ebpf.reservation"; }
};
} // namespace ebpf
} // namespace mlir

#define GET_TYPEDEF_CLASSES
#include "bpf-mlir/Dialect/EBPF/IR/EBPFOpsTypes.h.inc"

#include "bpf-mlir/Dialect/EBPF/IR/EBPFOpsInterfaces.h.inc"

#define GET_OP_CLASSES
#include "bpf-mlir/Dialect/EBPF/IR/EBPFOps.h.inc"

namespace mlir {
namespace ebpf {

// Enumerate known values in verifier diagnostics so users see valid choices.
bool isKnownProgramKind(llvm::StringRef kind);
bool isKnownMapKind(llvm::StringRef kind);
// Verdicts come from this program's ProgramAttaches.def row; omitted attach is empty.
bool isVerdictAllowedFor(llvm::StringRef programKind, llvm::StringRef attach, llvm::StringRef action);
bool supportsPacketAccess(llvm::StringRef programKind);
std::string knownProgramKinds();
std::string knownMapKinds();
std::string knownVerdicts(llvm::StringRef programKind, llvm::StringRef attach);
// Shared kind-to-UAPI program type mapping for ABI lowering and target legality.
// fentry/fexit/tp_btf use tracing; user probes use kprobe.
llvm::StringRef programTypeOf(llvm::StringRef kind);

// Return a stage-2 callback symbol for bpf_loop/for_each_map_elem, else null.
// Call-graph checks, callback-kind selection and expansion share these edges.
inline FlatSymbolRefAttr callbackOf(Operation *op) {
  if (auto bl = llvm::dyn_cast<BpfLoopOp>(op))
    return bl.getCallbackAttr();
  if (auto fe = llvm::dyn_cast<ForEachMapElemOp>(op))
    return fe.getCallbackAttr();
  return {};
}

} // namespace ebpf
} // namespace mlir

#endif // BPF_MLIR_DIALECT_EBPF_IR_EBPFDIALECT_H
