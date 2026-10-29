// Shared record paths for record verification and ABI lowering. Up to three
// dot-separated names can carry constant [index] or dynamic [] suffixes per
// array dimension. Dynamic [] is only for ref.index templates. Limits: struct
// depth <=3, array dimensions <=2, elements integers or one-dimensional records;
// two-dimensional arrays contain integers. Read offsets/widths from schema-
// derived btf.scope @records, never recompute the canonical schema layout.
#ifndef BPF_MLIR_DIALECT_EBPF_TRANSFORMS_RECORDPATH_H
#define BPF_MLIR_DIALECT_EBPF_TRANSFORMS_RECORDPATH_H

#include "bpf-mlir/Dialect/BTF/IR/BTFDialect.h"

#include "llvm/ADT/SmallVector.h"

#include <string>

namespace mlir::ebpf {

// Compiler shape limits, not kernel ABI limits.
inline constexpr unsigned kMaxRecordDepth = 3;
inline constexpr unsigned kMaxArrayDims = 2;

struct RecordLeaf {
  std::string path;    // Path spelling, e.g. in.port or arr[2].
  int64_t offsetBytes; // Byte offset from record start.
  unsigned bits;       // Integer width.
  Attribute type;      // Leaf type (#btf.int, used in diagnostics).
};

// One dynamic [] dimension.
struct RecordDim {
  uint64_t count;      // Element count.
  int64_t strideBytes; // Element size.
};

// Template path may contain []. Address is offsetBytes + sum(index_k * stride_k).
struct RecordTemplate {
  int64_t offsetBytes;
  unsigned bits;
  Attribute type;
  llvm::SmallVector<RecordDim, 2> dims; // In [] order.
};

// Resolve an integer leaf in st; invalid shapes fail with a reason in err.
FailureOr<RecordTemplate> resolveRecordTemplate(btf::ScopeOp records, btf::StructOp st, llvm::StringRef path,
                                                std::string &err);

// Resolve a constant path in btf.scope @records, rejecting dynamic [] and
// invalid shapes with a reason in err.
FailureOr<RecordLeaf> resolveRecordPath(btf::ScopeOp records, btf::StructOp st, llvm::StringRef path,
                                        std::string &err);

// ref.index template: a field without [] such as arr is equivalent to arr[].
inline std::string indexTemplate(llvm::StringRef field) {
  return field.contains("[]") ? field.str() : (field + "[]").str();
}

// Enumerate constructor leaves in declaration order, failing with err if any
// member exceeds supported shapes.
LogicalResult recordLeaves(btf::ScopeOp records, btf::StructOp st,
                           llvm::SmallVectorImpl<RecordLeaf> &out, std::string &err);

// Check supported member shapes with a reason in err. kptr nesting is limited
// to record_ref chains.
LogicalResult checkRecordShape(btf::ScopeOp records, btf::StructOp st, std::string &err);

// Ordinary referenced-kptr target and constant offset from map-value start.
struct KptrLeaf {
  std::string structName;
  int64_t offsetBytes;
};
FailureOr<KptrLeaf> resolveKptrPath(btf::ScopeOp records, btf::StructOp st,
                                  llvm::StringRef path, std::string &err);
// Closure check prevents record.make from treating a nested kptr as integer-only.
bool recordHasKptr(btf::ScopeOp records, btf::StructOp st);

// Return T only for referenced map-value kptr members:
// #btf.ptr<#btf.type_tag<"kptr", #btf.ref<@kernel::@T>>>; otherwise empty.
inline llvm::StringRef kptrStructOf(Attribute t) {
  auto p = llvm::dyn_cast<btf::PtrAttr>(t);
  auto tt = p ? llvm::dyn_cast<btf::TypeTagAttr>(p.getPointee()) : btf::TypeTagAttr();
  auto r = tt && tt.getTag() == "kptr" ? llvm::dyn_cast<btf::RefAttr>(tt.getBase()) : btf::RefAttr();
  return r ? r.getTarget().getLeafReference().getValue() : llvm::StringRef();
}

} // namespace mlir::ebpf

#endif
