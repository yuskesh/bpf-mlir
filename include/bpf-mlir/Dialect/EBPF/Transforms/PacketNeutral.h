//===- PacketNeutral.h - packet neutrality and invalidation queries ---------===//
//
// Shared by sink-window-loads and window-load-nested. Packet-neutral means no
// packet writes or pointer invalidation, independent of MemoryEffectOpInterface:
// helper calls can remain unknown MLIR effects (publication/lock boundaries)
// while packet-neutral. Only explicitly classified operations qualify; unknown
// operations/helpers and pktinval helpers never do. Helper contracts follow
// kernel func_proto arguments and pointers supplied by lowering.
//===----------------------------------------------------------------------===//
#ifndef BPF_MLIR_DIALECT_EBPF_TRANSFORMS_PACKETNEUTRAL_H
#define BPF_MLIR_DIALECT_EBPF_TRANSFORMS_PACKETNEUTRAL_H

#include "mlir/IR/Operation.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include <optional>
#include <string>

namespace mlir::ebpf {

// One row: ABI helper names and whether the operation itself writes packets.
struct PacketNeutralClass {
  llvm::ArrayRef<llvm::StringLiteral> helpers;
  bool writesPacket;
};

// Classify this operation only. Unknown is nullopt; arithmetic calls no helpers and writes no packets.
std::optional<PacketNeutralClass> packetNeutralClass(Operation *op);

// Include nested operations. Unknown operations/helpers, invalidators and writes return false.
bool isPacketNeutral(Operation *op);

// Check classified helpers exist in ABI and are not pktinval; return a reason on inconsistency.
std::optional<std::string> checkPacketNeutralTable();

// Check whether this operation or any nested operation calls an ABI pktinval
// helper. packetEffectHelpers covers both neutral and non-neutral helper
// operations. Shared by VerifyStructured and fact diagnostics. ABI lowering
// checks every emitted pktinval helper has this predicate, rejecting omissions.
bool invalidatesPacketPointers(Operation *op);

// Check this operation only; invalidatesPacketPointers recursively applies it to regions.
bool opInvalidatesPacketPointers(Operation *op);

// Helper names for this operation, without visiting regions. nullopt means
// unclassified, neither proven neutral nor proven invalidating.
std::optional<llvm::ArrayRef<llvm::StringLiteral>> packetEffectHelpers(Operation *op);

// Whether any name is pktinval. Unknown names return false; lookupHelper
// separately rejects unknown helpers. Also exposed for unit tests.
bool helpersInvalidatePacketPointers(llvm::ArrayRef<llvm::StringRef> helpers);

} // namespace mlir::ebpf

#endif
