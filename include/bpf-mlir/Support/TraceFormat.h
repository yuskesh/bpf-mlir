#ifndef BPF_MLIR_SUPPORT_TRACEFORMAT_H
#define BPF_MLIR_SUPPORT_TRACEFORMAT_H
#include "llvm/ADT/StringRef.h"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
namespace bpfmlir {
// One conversion of a trace.printk format, in format order (= the helper's
// slot order). An integer conversion takes the next $args value; a %s
// conversion (isString) takes the next literal of the op's strs, passed as
// the address of a compiler-owned .rodata string (bits 64 — a pointer slot).
struct TraceFormatArg {
  unsigned bits;
  bool isSigned;
  bool isString = false;
};
// the compiler's conservative bound on the kernel's bin_args buffer
// (MAX_BPRINTF_BIN_ARGS = 512 in 7.3.1 / 7.1.8 / 6.12.111 / 6.6.157): each %s
// literal counts len + 1 (NUL) + 7 (alignment), each integer 8 bytes.
inline constexpr uint64_t kTraceBinArgsBound = 512;
inline uint64_t traceBinArgsBytes(const std::vector<llvm::StringRef> &strs, unsigned integers) {
  uint64_t n = 8ull * integers;
  for (llvm::StringRef s : strs)
    n += s.size() + 1 + 7;
  return n;
}
// The kernel's -EINVAL rule after %s (bpf_bprintf_prepare): the next character
// is the end, a space or a punctuation character. C isspace / ispunct in the
// "C" locale (ASCII); the kernel's ctype also accepts some Latin-1 bytes,
// which the compiler rejects (the strict side).
inline bool traceStrFollowerOk(char c) {
  unsigned char u = static_cast<unsigned char>(c);
  if (u == ' ' || (u >= '\t' && u <= '\r'))
    return true;
  return (u >= 33 && u <= 47) || (u >= 58 && u <= 64) || (u >= 91 && u <= 96) || (u >= 123 && u <= 126);
}
inline std::optional<std::vector<TraceFormatArg>>
parseTraceFormat(llvm::StringRef format, std::string &error) {
  auto fail = [&](const char *s) -> std::optional<std::vector<TraceFormatArg>> {
    error = s;
    return std::nullopt;
  };
  if (format.contains('\0'))
    return fail("format must not contain an embedded NUL");
  if (format.size() >= UINT32_MAX)
    return fail("format including NUL must fit u32");
  std::vector<TraceFormatArg> result;
  for (size_t i = 0; i < format.size(); ++i) {
    if (format[i] != '%')
      continue;
    if (++i == format.size())
      return fail("incomplete format conversion");
    if (format[i] == '%') // %% consumes no argument (and no literal).
      continue;
    llvm::StringRef rest = format.substr(i);
    // name a flag, width or precision before s (the kernel skips them;
    // the compiler accepts the plain %s only).
    size_t skip = rest.find_first_not_of("-+ #0123456789.");
    if (skip != 0 && skip != llvm::StringRef::npos && rest[skip] == 's')
      return fail("%s takes no flag, width or precision (write the plain %s)");
    unsigned count = 1, bits = 32;
    bool sign = false, str = false;
    if (rest.starts_with("llx")) {
      count = 3;
      bits = 64;
    } else if (rest.starts_with("ld") || rest.starts_with("lu") ||
               rest.starts_with("lx")) {
      count = 2;
      bits = 64;
      sign = rest[1] == 'd';
    } else if (rest[0] == 'd' || rest[0] == 'u' || rest[0] == 'x') {
      sign = rest[0] == 'd';
    } else if (rest[0] == 's') {
      str = true;
      bits = 64;
      if (rest.size() > 1 && !traceStrFollowerOk(rest[1]))
        return fail("%s must be followed by the end of the format, a space or a punctuation character (the kernel's "
                    "bpf_bprintf_prepare returns -EINVAL and prints nothing otherwise)");
    } else
      return fail("only %d/%u/%x/%ld/%lu/%lx/%llx, %s and %% are supported");
    result.push_back({bits, sign, str});
    i += count - 1;
    if (result.size() > 3)
      return fail("at most three arguments (integer conversions and %s together — the helper's three slots) are supported");
  }
  return result;
}
// Exact kernel include/linux/license.h strings, shared by all emission entries.
inline bool isGPLCompatible(llvm::StringRef license) {
  return license == "GPL" || license == "GPL v2" ||
         license == "GPL and additional rights" || license == "Dual BSD/GPL" ||
         license == "Dual MIT/GPL" || license == "Dual MPL/GPL";
}
} // namespace bpfmlir
#endif
