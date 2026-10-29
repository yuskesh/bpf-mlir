// Shared local-storage map/owner classification for schema checks, storage
// get/delete verifiers and ABI helper selection. Schema requires a 32-bit key,
// max_entries zero and no_prealloc. Owners follow kernel helper BTF prototypes:
// task_struct, inode, cgroup and sock. sk_storage's sock_common family is
// conservatively restricted to sock by this compiler.

#ifndef BPF_MLIR_SUPPORT_LOCALSTORAGE_H
#define BPF_MLIR_SUPPORT_LOCALSTORAGE_H

#include "llvm/ADT/StringRef.h"

#include <optional>

namespace bpfmlir {

// Return the kernel owner struct for local storage, otherwise nullopt.
inline std::optional<llvm::StringRef> localStorageOwner(llvm::StringRef mapKind) {
  if (mapKind == "sk_storage")
    return llvm::StringRef("sock");
  if (mapKind == "task_storage")
    return llvm::StringRef("task_struct");
  if (mapKind == "inode_storage")
    return llvm::StringRef("inode");
  if (mapKind == "cgrp_storage")
    return llvm::StringRef("cgroup");
  return std::nullopt;
}

} // namespace bpfmlir

#endif // BPF_MLIR_SUPPORT_LOCALSTORAGE_H
