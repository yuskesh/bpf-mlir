#ifndef BPF_MLIR_SUPPORT_KERNELFIELDPATH_H
#define BPF_MLIR_SUPPORT_KERNELFIELDPATH_H
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
namespace bpfmlir {
inline bool validKernelFieldPath(llvm::StringRef path) {
  if (path.empty()) return false;
  // Preserve the legacy single-member spelling contract.
  if (!path.contains('.')) return true;
  llvm::SmallVector<llvm::StringRef, 3> parts;
  path.split(parts, '.', -1, true);
  if (parts.size() > 3) return false;
  for (auto p : parts) {
    if (p.empty()) return false;
    for (size_t i = 0; i < p.size(); ++i) {
      char c = p[i];
      if (!(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (i && c >= '0' && c <= '9'))) return false;
    }
  }
  return true;
}
}
#endif
