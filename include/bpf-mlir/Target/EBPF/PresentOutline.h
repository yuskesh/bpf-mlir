// Outline over-threshold present regions with LLVM CodeExtractor into internal
// noinline __ebpf_present_<function>_<reservation-index> functions. This keeps
// the reservation check jump across a call rather than a large region, avoiding
// the signed 16-bit BPF jump limit. Run after LLVM verification/requirements and
// before codegen; requirements remain unchanged.

#ifndef BPF_MLIR_TARGET_EBPF_PRESENTOUTLINE_H
#define BPF_MLIR_TARGET_EBPF_PRESENTOUTLINE_H

#include "llvm/ADT/Twine.h"
#include "llvm/IR/Module.h"

#include <functional>

namespace ebpf {

// Default: 32767 * 0.75 rounded down to a multiple of 1024.
inline constexpr uint64_t kPresentOutlineThreshold = 23552;

// Outline present regions whose estimate exceeds threshold. Return false with
// error for name collisions or shapes CodeExtractor cannot extract.
bool outlineLargePresents(llvm::Module &m, uint64_t threshold,
                          const std::function<void(const llvm::Twine &)> &error);

} // namespace ebpf

#endif
