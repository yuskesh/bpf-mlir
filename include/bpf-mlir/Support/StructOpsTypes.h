//===- StructOpsTypes.h - struct_ops type table access -----------*- C++ -*-===//
//
// StructOpsTypes.def owns types, registration, data members and promotions with
// source evidence. ABI structopsmember rows own member names/kinds, exposed by
// KernelABI.h lookupStructOpsMember. Shared by schema parsing, BTF and emission.
//===----------------------------------------------------------------------===//
#ifndef BPF_MLIR_SUPPORT_STRUCTOPSTYPES_H
#define BPF_MLIR_SUPPORT_STRUCTOPSTYPES_H

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"

#include <string>

namespace bpfmlir {

struct StructOpsTypeInfo {
  llvm::StringLiteral type, registerMode, evidence;
  bool registers() const { return registerMode == "link"; }
};
struct StructOpsDataInfo {
  llvm::StringLiteral type, member, schemaKey;
  unsigned bytes;
  llvm::StringLiteral kind, rule, evidence;
};
struct StructOpsPromotionInfo {
  llvm::StringLiteral type, btf, promoted, evidence;
};

inline constexpr StructOpsTypeInfo kStructOpsTypes[] = {
#define EBPF_STRUCT_OPS(TYPE, REGISTER, EVIDENCE) {TYPE, REGISTER, EVIDENCE},
#include "bpf-mlir/Support/StructOpsTypes.def"
};
inline constexpr StructOpsDataInfo kStructOpsData[] = {
#define EBPF_STRUCT_OPS_DATA(TYPE, MEMBER, SCHEMAKEY, BYTES, KIND, RULE, EVIDENCE) {TYPE, MEMBER, SCHEMAKEY, BYTES, KIND, RULE, EVIDENCE},
#include "bpf-mlir/Support/StructOpsTypes.def"
};
inline constexpr StructOpsPromotionInfo kStructOpsPromotions[] = {
#define EBPF_STRUCT_OPS_PROMOTION(TYPE, BTF, PROMOTED, EVIDENCE) {TYPE, BTF, PROMOTED, EVIDENCE},
#include "bpf-mlir/Support/StructOpsTypes.def"
};

inline const StructOpsTypeInfo *lookupStructOpsType(llvm::StringRef type) {
  for (const StructOpsTypeInfo &t : kStructOpsTypes)
    if (t.type == type)
      return &t;
  return nullptr;
}

// Listed type names for diagnostics: "a", "b".
inline std::string listStructOpsTypes() {
  std::string out;
  for (const StructOpsTypeInfo &t : kStructOpsTypes)
    out += (out.empty() ? "\"" : ", \"") + t.type.str() + "\"";
  return out;
}

// Data rows in table order, following function pointers in the local struct.
inline llvm::SmallVector<const StructOpsDataInfo *> structOpsDataOf(llvm::StringRef type) {
  llvm::SmallVector<const StructOpsDataInfo *> out;
  for (const StructOpsDataInfo &d : kStructOpsData)
    if (d.type == type)
      out.push_back(&d);
  return out;
}

// Data row for a schema key, or nullptr.
inline const StructOpsDataInfo *structOpsDataByKey(llvm::StringRef type, llvm::StringRef key) {
  for (const StructOpsDataInfo &d : kStructOpsData)
    if (d.type == type && d.schemaKey == key)
      return &d;
  return nullptr;
}

// Map a promoted name back to BTF within this ops type; unlisted names pass through.
inline llvm::StringRef structOpsArgBTFName(llvm::StringRef type, llvm::StringRef name) {
  for (const StructOpsPromotionInfo &p : kStructOpsPromotions)
    if (p.type == type && p.promoted == name)
      return p.btf;
  return name;
}

} // namespace bpfmlir

#endif
