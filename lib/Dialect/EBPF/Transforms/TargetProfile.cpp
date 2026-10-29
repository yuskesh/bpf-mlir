//===- TargetProfile.cpp - explicit target profiles and legality queries -----===//
#include "bpf-mlir/Dialect/EBPF/Transforms/TargetProfile.h"

#include "bpf-mlir/Dialect/BPFABI/KernelABI.h"
#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"
#include "bpf-mlir/Support/ProgramKinds.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/MemoryBuffer.h"

using namespace mlir;
using namespace mlir::ebpf;

bool mlir::ebpf::isKnownFact(llvm::StringRef name) { return name == kFactMapWithTimer || name == kFactMapWithSpinLock; }

std::optional<TargetProfile> TargetProfile::load(llvm::StringRef path, std::string &why) {
  auto buf = llvm::MemoryBuffer::getFile(path);
  if (!buf) {
    why = "cannot read target profile '" + path.str() + "': " + buf.getError().message();
    return std::nullopt;
  }
  TargetProfile p;
  p.path = path.str();
  llvm::SmallVector<llvm::StringRef> lines;
  (*buf)->getBuffer().split(lines, '\n');
  for (auto [i, line] : llvm::enumerate(lines)) {
    llvm::StringRef l = line.rtrim("\r");
    if (l.empty() || l.starts_with("#"))
      continue;
    std::string at = path.str() + ":" + std::to_string(i + 1) + ": ";
    llvm::SmallVector<llvm::StringRef> f;
    l.split(f, '\t');
    if (f.size() != 5 || f[0] != "fact") {
      why = at + "expected `fact <name> <program type> <accepted|rejected|unknown> <evidence>` (5 tab-separated columns)";
      return std::nullopt;
    }
    if (!isKnownFact(f[1])) {
      why = at + "unknown fact '" + f[1].str() + "' (this compiler knows: " + kFactMapWithTimer.str() + ", " + kFactMapWithSpinLock.str() + ")";
      return std::nullopt;
    }
    if (!bpfabi::lookupProgType(f[2])) {
      why = at + "program type '" + f[2].str() + "' is not in the UAPI table";
      return std::nullopt;
    }
    FactValue v;
    if (f[3] == "accepted")
      v = FactValue::Accepted;
    else if (f[3] == "rejected")
      v = FactValue::Rejected;
    else if (f[3] == "unknown")
      v = FactValue::Unknown;
    else {
      why = at + "value '" + f[3].str() + "' is not accepted / rejected / unknown";
      return std::nullopt;
    }
    std::string key = (f[1] + "\t" + f[2]).str();
    if (p.facts.count(key)) {
      why = at + "fact '" + f[1].str() + " " + f[2].str() + "' is listed twice";
      return std::nullopt;
    }
    p.facts[key] = {v, f[4].str()};
  }
  return p;
}

FactValue TargetProfile::fact(llvm::StringRef name, llvm::StringRef programType, std::string *evidence) const {
  auto it = facts.find((name + "\t" + programType).str());
  if (it == facts.end())
    return FactValue::Unknown;
  if (evidence)
    *evidence = it->second.second;
  return it->second.first;
}

// Timer compiler support comes from OPS, independently of profile facts.
// Adding kinds requires callback helper contracts, C oracle and target
// measurements; Unknown/accepted profiles cannot enable unsupported kinds.
// Tracing-kind support and its separate kernel evidence must not be conflated.
LegalityAnswer mlir::ebpf::timerLegality(llvm::StringRef programKind, const TargetProfile *profile) {
  LegalityAnswer a{bpfmlir::kindAllows(programKind, "timer") ? Legality::Native : Legality::CompilerUnsupported, FactValue::Unknown, ""};
  if (profile)
    a.target = profile->fact(kFactMapWithTimer, programTypeOf(programKind), &a.targetEvidence);
  return a;
}

// Spin compiler support likewise comes from OPS. Other kinds stay
// unsupported until C oracle and corresponding target measurements exist;
// target profiles do not expand compiler capabilities.
LegalityAnswer mlir::ebpf::spinLegality(llvm::StringRef programKind, const TargetProfile *profile) {
  LegalityAnswer a{bpfmlir::kindAllows(programKind, "spin") ? Legality::Native : Legality::CompilerUnsupported, FactValue::Unknown, ""};
  if (profile)
    a.target = profile->fact(kFactMapWithSpinLock, programTypeOf(programKind), &a.targetEvidence);
  return a;
}
