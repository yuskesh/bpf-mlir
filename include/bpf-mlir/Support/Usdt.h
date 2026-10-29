// Shared compiler/loader layout for each USDT program's spec map and record.
// See docs/requirements_format.md section 8. Schema construction, argument
// verification and ABI lowering use this same contract. Each value contains
// 12 argument specs of 16 bytes: kind u8@0 (0 absent, 1 const, 2 reg, 3 deref),
// register u8@1 (UAPI usdtreg), six zero bytes, off i64@8 (constant or deref
// offset). The u32 key is the point index, also used as the uprobe cookie.
#ifndef BPF_MLIR_SUPPORT_USDT_H
#define BPF_MLIR_SUPPORT_USDT_H

#include <cstdint>

namespace ebpf {

inline constexpr int kUsdtMaxArgs = 12;
inline constexpr uint64_t kUsdtMaxPoints = 65536; // Compiler bound on the array map's max_entries.
inline constexpr int kUsdtArgSpecBytes = 16;
inline constexpr int kUsdtSpecBytes = kUsdtMaxArgs * kUsdtArgSpecBytes; // 192
inline constexpr int kUsdtArgKindOffset = 0, kUsdtArgRegOffset = 1, kUsdtArgOffOffset = 8;
inline constexpr int kUsdtKindNone = 0, kUsdtKindConst = 1, kUsdtKindReg = 2, kUsdtKindDeref = 3;
inline constexpr const char *kUsdtSpecMapPrefix = "__ebpf_usdt_spec_";
inline constexpr const char *kUsdtSpecRecord = "ebpf_usdt_spec";

} // namespace ebpf

#endif
