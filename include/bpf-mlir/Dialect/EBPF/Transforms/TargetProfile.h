// Explicit named verifier-policy facts, not kernel version comparisons.
// Accepted/Rejected/Unknown are distinct; missing rows are Unknown, never
// false. Only Rejected establishes target unsupported. These facts are
// separate from load-time requirements capabilities and must not duplicate
// helper/program/map availability as a second authority.
#ifndef BPF_MLIR_DIALECT_EBPF_TRANSFORMS_TARGETPROFILE_H
#define BPF_MLIR_DIALECT_EBPF_TRANSFORMS_TARGETPROFILE_H

#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringRef.h"
#include <optional>
#include <string>

namespace mlir::ebpf {

enum class FactValue { Accepted, Rejected, Unknown };

struct TargetProfile {
  std::string path;
  // Key <fact>\t<program-type> maps to outcome and evidence.
  llvm::StringMap<std::pair<FactValue, std::string>> facts;

  // Strictly parse fact <name> <program-type> <accepted|rejected|unknown>
  // <evidence>. Reject unknown names/values, non-UAPI program types, duplicate
  // facts and wrong field counts with a reason.
  static std::optional<TargetProfile> load(llvm::StringRef path, std::string &why);

  // Missing facts are Unknown.
  FactValue fact(llvm::StringRef name, llvm::StringRef programType, std::string *evidence = nullptr) const;
};

// Known facts are map-with-timer and map-with-spin-lock. map-with-timer
// describes verifier acceptance when instructions actually reference such a
// map, without timer operations. Accepted does not establish support for
// init/set_callback/start or callbacks. timerLegality also requires compiler
// OPS support; a profile alone never makes an operation Native.
inline constexpr llvm::StringLiteral kFactMapWithTimer = "map-with-timer";
// map-with-spin-lock likewise establishes map use without spin.region, not
// helper 93/94 support. spinLegality must combine it with compiler OPS support.
inline constexpr llvm::StringLiteral kFactMapWithSpinLock = "map-with-spin-lock";
// Is this a recognized fact name?
bool isKnownFact(llvm::StringRef name);

// timerLegality combines compiler implementation with explicit map-with-timer
// policy. Rejected justifies target unsupported; Accepted alone does not
// establish Native. The compiler answer is Native or CompilerUnsupported;
// callers diagnose target failure only when LegalityAnswer::target is Rejected.
enum class Legality { Native, CompilerUnsupported };
struct LegalityAnswer {
  Legality compiler;             // Native or CompilerUnsupported.
  FactValue target;              // Profile outcome, Unknown without a profile.
  std::string targetEvidence;    // Evidence for Rejected or Accepted.
};
LegalityAnswer timerLegality(llvm::StringRef programKind, const TargetProfile *profile);
// spinLegality uses the same two axes, with the map-with-spin-lock fact.
LegalityAnswer spinLegality(llvm::StringRef programKind, const TargetProfile *profile);

} // namespace mlir::ebpf

#endif
