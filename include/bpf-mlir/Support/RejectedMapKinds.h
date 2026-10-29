// Shared named rejections for map kinds deliberately unsupported by the
// compiler, used by schema parsing and operation verification.
#ifndef BPF_MLIR_SUPPORT_REJECTEDMAPKINDS_H
#define BPF_MLIR_SUPPORT_REJECTEDMAPKINDS_H

#include "llvm/ADT/StringRef.h"
#include "llvm/Support/ErrorHandling.h"

#include <optional>
#include <string>

namespace bpfmlir {

// Known spellings return the reason and optional replacement; others nullopt.
inline std::optional<std::string> rejectedMapKindMessage(llvm::StringRef kind) {
  struct Row {
    llvm::StringLiteral name, uapi, reason, replacement, note, experiment;
  };
  static constexpr Row kRows[] = {
#define EBPF_REJECTED_MAP_KIND(NAME, UAPI, REASON, REPLACEMENT, NOTE, EXPERIMENT, EVIDENCE) {NAME, UAPI, REASON, REPLACEMENT, NOTE, EXPERIMENT},
#include "bpf-mlir/Support/RejectedMapKinds.def"
  };
  for (const Row &r : kRows) {
    if (r.name != kind)
      continue;
    std::string s = ("map kind \"" + r.name + "\" (" + r.uapi + ") ").str();
    if (r.reason == "deprecated")
      s += "is deprecated by the kernel and not supported";
    else if (r.reason == "loader-generated")
      s += "is loader-generated and not supported as a user-declared map";
    else
      llvm_unreachable("unknown reason in RejectedMapKinds.def");
    if (!r.replacement.empty())
      s += (" — use \"" + r.replacement + "\"").str();
    if (!r.note.empty())
      s += (" (" + r.note + ")").str();
    s += (" (" + r.experiment + ")").str();
    return s;
  }
  return std::nullopt;
}

} // namespace bpfmlir

#endif
