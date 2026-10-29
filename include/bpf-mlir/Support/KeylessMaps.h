// Shared classification for keyless queue, stack and bloom_filter maps.
// Schema requires no key and an integer value; map handles use none as key.
// BuildBTF omits the key member, matching kernel key_size == 0.
// Only queue/stack support pop and value-returning peek. Bloom peek instead
// reads the supplied value. Redirect-map targets have a separate classification.

#ifndef BPF_MLIR_SUPPORT_KEYLESSMAPS_H
#define BPF_MLIR_SUPPORT_KEYLESSMAPS_H

#include "llvm/ADT/StringRef.h"

namespace bpfmlir {

// True for queue, stack and bloom_filter.
inline bool isKeylessMapKind(llvm::StringRef mapKind) {
  return mapKind == "queue" || mapKind == "stack" || mapKind == "bloom_filter";
}

// Only queue/stack support pop and value-returning peek. bloom_filter uses
// the separate ebpf.bloom.peek operation, which reads a supplied value.
inline bool isQueueOrStackMapKind(llvm::StringRef mapKind) { return mapKind == "queue" || mapKind == "stack"; }

// devmap, devmap_hash, cpumap and xskmap are redirect_map targets, matching
// check_map_func_compatibility. Other in-program map operations are rejected.
inline bool isRedirectMapKind(llvm::StringRef mapKind) {
  return mapKind == "devmap" || mapKind == "devmap_hash" || mapKind == "cpumap" || mapKind == "xskmap";
}

} // namespace bpfmlir

#endif // BPF_MLIR_SUPPORT_KEYLESSMAPS_H
