// Emit bpfel/-mcpu=v1 ELF with stable symbols, .maps, program sections, license,
// relocations and .BTF. BTF comes from schema-derived DWARF through LLVM's BPF
// backend; dropping debug information would drop BTF. Do not hand-encode it.
#ifndef BPF_MLIR_TARGET_EBPF_OBJECTEMITTER_H
#define BPF_MLIR_TARGET_EBPF_OBJECTEMITTER_H

#include "bpf-mlir/Target/EBPF/Schema.h"

#include "mlir/IR/BuiltinOps.h"
#include "mlir/Support/LLVM.h"
#include "llvm/Support/raw_ostream.h"

#include <functional>
#include <string>

namespace ebpf {

// Emission diagnostics keep MLIR types out of this boundary.
struct Diagnostics {
  std::function<void(llvm::StringRef message)> sink;
  bool failed = false;

  void error(const llvm::Twine &msg) {
    failed = true;
    if (sink)
      sink(msg.str());
  }
};

// Generic section names. Witness pointers in .ebpf_records retain record types
// in BTF without importing frontend-specific section spellings.
inline constexpr llvm::StringLiteral kMapsSection = ".maps";
inline constexpr llvm::StringLiteral kLicenseSection = "license";
inline constexpr llvm::StringLiteral kRecordsSection = ".ebpf_records";
// Kernel program/helper/map capabilities required at load time.
// See docs/requirements_format.md and emitRequirements in ObjectEmitter.cpp.
inline constexpr llvm::StringLiteral kRequirementsSection = ".ebpf_requirements";

// Emit BTF-enabled BPF ELF from an LLVM-dialect module and canonical schema.
// schemaSHA256 is the hexadecimal SHA-256 of the schema file bytes, recorded in
// .ebpf_requirements for binding generation and load-time checks.
// llvmIROut optionally writes debug-enabled LLVM IR before codegen/CO-RE passes.
// presentCostOut optionally writes cost TSV without changing the ELF.
// Regions above presentOutlineThreshold move into internal functions; the
// default is kPresentOutlineThreshold in PresentOutline.h.
mlir::LogicalResult emitObject(mlir::ModuleOp module, const Schema &schema,
                               llvm::StringRef schemaSHA256,
                               llvm::raw_pwrite_stream &os,
                               Diagnostics &diags,
                               llvm::StringRef license = "GPL",
                               llvm::raw_ostream *llvmIROut = nullptr,
                               llvm::raw_ostream *presentCostOut = nullptr,
                               uint64_t presentOutlineThreshold = 23552);

} // namespace ebpf

#endif // BPF_MLIR_TARGET_EBPF_OBJECTEMITTER_H
