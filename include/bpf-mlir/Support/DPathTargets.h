//===- DPathTargets.h - fentry targets of ebpf.kernel.d_path ----*- C++ -*-===//
//
// The closed table of fentry targets ebpf.kernel.d_path may attach to.
// It is not the kernel's d_path allowlist: adding a target is a plan decision.
//
//===----------------------------------------------------------------------===//
#ifndef BPF_MLIR_SUPPORT_DPATHTARGETS_H
#define BPF_MLIR_SUPPORT_DPATHTARGETS_H

#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringRef.h"
#include <string>

namespace mlir::ebpf {

inline constexpr llvm::StringLiteral kDPathTargets[] = {"vfs_getattr", "security_inode_getattr"};

inline bool isDPathTarget(llvm::StringRef target) {
  return llvm::is_contained(kDPathTargets, target);
}

// The helper_target row (without the helper columns) of one permitted target.
inline std::string dPathHelperTarget(llvm::StringRef target) {
  return ("trace_fentry\t" + target + "\t0\tpath").str();
}

inline bool isDPathHelperTarget(llvm::StringRef row) {
  return llvm::any_of(kDPathTargets, [&](llvm::StringRef target) { return row == dPathHelperTarget(target); });
}

} // namespace mlir::ebpf

#endif
