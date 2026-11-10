//===- LoweringOnlyKfuncs.h - lookups over LoweringOnlyKfuncs.def --===//
#ifndef BPF_MLIR_SUPPORT_LOWERINGONLYKFUNCS_H
#define BPF_MLIR_SUPPORT_LOWERINGONLYKFUNCS_H

#include "llvm/ADT/StringRef.h"

namespace bpfmlir {
struct LoweringKfuncInfo {
  llvm::StringLiteral kfunc;
  llvm::StringLiteral owner;
};
inline constexpr LoweringKfuncInfo kLoweringOnlyKfuncs[] = {
#define EBPF_LOWERING_KFUNC(KFUNC, OWNER) {KFUNC, OWNER},
#include "bpf-mlir/Support/LoweringOnlyKfuncs.def"
#undef EBPF_LOWERING_KFUNC
};
inline const LoweringKfuncInfo *lookupLoweringOnlyKfunc(llvm::StringRef kfunc) {
  for (const LoweringKfuncInfo &k : kLoweringOnlyKfuncs)
    if (k.kfunc == kfunc)
      return &k;
  return nullptr;
}

// SleepableOps.def: helpers that may sleep (kfuncs use the "sleepable" flag).
inline constexpr llvm::StringLiteral kMightSleepHelpers[] = {
#define EBPF_MIGHT_SLEEP_HELPER(NAME) NAME,
#include "bpf-mlir/Support/SleepableOps.def"
#undef EBPF_MIGHT_SLEEP_HELPER
};
inline bool isMightSleepHelper(llvm::StringRef name) {
  for (llvm::StringRef h : kMightSleepHelpers)
    if (h == name)
      return true;
  return false;
}
} // namespace bpfmlir
#endif
