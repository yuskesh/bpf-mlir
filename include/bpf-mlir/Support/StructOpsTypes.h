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

// Integer DATA rows (KIND u32 / u64) are optional schema keys; str rows are required.
inline bool isStructOpsIntData(const StructOpsDataInfo &d) { return d.kind == "u32" || d.kind == "u64"; }

// True when some type has an integer DATA row with this schema key.
inline bool isStructOpsIntDataKey(llvm::StringRef key) {
  for (const StructOpsDataInfo &d : kStructOpsData)
    if (isStructOpsIntData(d) && d.schemaKey == key)
      return true;
  return false;
}

// Empty when v fits the row's width and RULE (any / max:<N> / clear:<hex>);
// otherwise the reason, such as "> 30000" or "sets bits 0xff00000000000000".
inline std::string checkStructOpsDataValue(const StructOpsDataInfo &d, uint64_t v) {
  if (d.kind == "u32" && v > 0xffffffffull)
    return "does not fit u32 (> 4294967295)";
  llvm::StringRef rule = d.rule;
  if (rule == "any")
    return "";
  uint64_t n = 0;
  if (rule.consume_front("max:") && !rule.getAsInteger(10, n))
    return v > n ? "> " + std::to_string(n) : "";
  rule = d.rule;
  if (rule.consume_front("clear:0x") && !rule.getAsInteger(16, n))
    return (v & n) ? "sets bits " + d.rule.substr(6).str() : "";
  return "has an unknown RULE " + d.rule.str() + " in StructOpsTypes.def";
}

} // namespace bpfmlir

#endif
