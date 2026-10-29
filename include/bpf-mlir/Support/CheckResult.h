// Stage exit checks distinguish four outcomes:
// Verified: safe on every target; Rejected: illegal on every target and stops
// compilation; Conditional: depends on target capabilities, recorded in ELF
// requirements; Unknown: not established here, requiring explicit verification.
// Unknown must never silently imply acceptance.
#ifndef BPF_MLIR_SUPPORT_CHECKRESULT_H
#define BPF_MLIR_SUPPORT_CHECKRESULT_H

#include "llvm/Support/raw_ostream.h"

#include <string>

namespace bpfmlir {

enum class CheckVerdict { Verified, Rejected, Conditional, Unknown };

// Aggregate pass outcomes, emitted as remarks with the report option.
struct CheckTally {
  unsigned verified = 0, rejected = 0, conditional = 0, unknown = 0;

  void add(CheckVerdict v) {
    switch (v) {
    case CheckVerdict::Verified:
      ++verified;
      break;
    case CheckVerdict::Rejected:
      ++rejected;
      break;
    case CheckVerdict::Conditional:
      ++conditional;
      break;
    case CheckVerdict::Unknown:
      ++unknown;
      break;
    }
  }

  std::string str() const {
    std::string out;
    llvm::raw_string_ostream os(out);
    os << "verified=" << verified << " rejected=" << rejected
       << " conditional=" << conditional << " unknown=" << unknown;
    return out;
  }
};

} // namespace bpfmlir

#endif // BPF_MLIR_SUPPORT_CHECKRESULT_H
