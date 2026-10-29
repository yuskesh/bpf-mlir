# Arithmetic contract (arith operations accepted by ebpf-compile)

- **Purpose**: the normative accepted and rejected forms of input `arith` operations. Frontends such as go-bpf-mlir and mojo-bpf-mlir must follow this contract when emitting arithmetic.
- **Implementation**: `lib/Dialect/EBPF/Transforms/ArithLegality.cpp`, checked at the `ebpf-compile` entry point, not by the development `ebpf-opt` passes. Ranges come from MLIR IntegerRangeAnalysis; constants have singleton ranges. **Branch conditions do not narrow ranges**: division after `if d != 0` is still rejected.
- Development test: `test/Target/EBPF/arith-legality.test`.

## 1. Types

Only integers (`i1` and integers of other widths) are supported. Arithmetic operations with floating-point, index or vector operands/results are rejected; eBPF has no floating-point arithmetic.

## 2. Forms that can produce LLVM undefined behavior or poison

LLVM may fold expressions on the assumption that undefined behavior or poison never occurs. Without the checks below, for example, `divui %w, %w` could become the constant 1. Reject unless range analysis proves the following conditions:

| Form | Acceptance condition | Example proof |
|---|---|---|
| Divisor of division/remainder (divui / remui / ceildivui / divsi / remsi / ceildivsi / floordivsi) | Range excludes 0; signed operations use the signed range | Constant; `arith.ori %d, 1` (unsigned); `(x & 7) \| 1` (signed range [1, 7]) |
| Signed division MinInt / −1 | Dividend excludes MinInt, or divisor excludes −1 | Narrow the dividend with `andi` |
| Shift count (shli / shrui / shrsi) | Range upper bound is less than the bit width | `arith.andi %c, 63` explicitly masks the BPF shift count |
| Overflow flags (nsw / nuw) and exact flags | Must be absent | — |

## 3. Signed division

- **eBPF CPU v1, the ebpf-compile target, has no signed division instruction.** LLVM's BPF backend expands constant divisors: **any nonzero constant for i8 / i16 / i32** (magic multiplication; i8 / i16 are promoted to i32), and **only ±2^k for i64** (shifts). Variable divisors and other i64 constants fail with `unsupported signed division`.
- **Contract: the divisor of `arith.divsi` / `arith.remsi` / `arith.floordivsi` / `arith.ceildivsi` must be constant (a singleton range); at width 64 its magnitude must be a power of two (1, 2, 4, …, 2^63, including negative divisors).** For −1, the MinInt / −1 condition in §2 also applies. Rejected forms receive:
  `needs a constant divisor (not a variable | an i64 divisor must be +-2^k; the eBPF CPU v1 has no signed division — LLVM expands a constant divisor: any non-zero constant for i8 / i16 / i32, only +-2^k for i64 …); for another divisor, divide the magnitudes with arith.divui / arith.remui and correct the sign in the frontend`
- **Compatibility correction**: an earlier check tested only i64 and incorrectly imposed the ±2^k restriction on every width, rejecting non-power-of-two i32 constants accepted by v0.7.0, such as `int32(a)/-3`. The corrected acceptance matrix (4 widths × 12 divisors × 4 operations = 192 combinations) matches the v0.7.0 build, and accepted combinations produce byte-identical ELF. **Accepted inputs have not decreased from v0.7.0**; only error wording changed.
- Semantics match MLIR arith: divsi truncates toward zero; remsi has the dividend's sign; floordivsi rounds toward −∞ (Python / Mojo `//`); ceildivsi rounds toward +∞.
- Differential measurements on 7.1.8 / 6.12.111 / 6.6.157 (development runner `kernel/cmd/sdivcheck`, inputs `kernel/sdiv/`) covered non-power-of-two i8 / i16 / i32 constants (3, −3, 5, 7, −7, 10, 100, MaxInt, −MaxInt, …), powers of two of either sign, i64 powers of two, dividend boundaries (MinInt, MaxInt, 0, ±1, neighbors of d, …), and five operations including floor-remainder expansion. **All 10315 combinations matched math/big**, including MinInt dividends and negative divisors for truncation, floor and ceiling.
- **Frontends expand signed division by general divisors** (variables or non-power-of-two i64 constants): divide magnitudes using `divui` / `remui`, then correct signs. The quotient is negative when operand signs differ; the remainder has the dividend's sign. For floor / ceiling, apply a ±1 correction when the remainder is nonzero. Compiler expansion at the ABI stage remains a candidate, dependent on downstream demand.

### Recommended floor-remainder expansion (Python `%`)

Arith has no floor-remainder operation. For a constant divisor d accepted by §3:

```mlir
%r    = arith.remsi %x, %d : i32                 // remainder has the dividend's sign
%rnz  = arith.cmpi ne, %r, %zero : i32
%rneg = arith.cmpi slt, %r, %zero : i32
%dneg = arith.constant <d < 0> : i1               // constant because d is constant
%sd   = arith.xori %rneg, %dneg : i1
%fix  = arith.andi %rnz, %sd : i1                 // nonzero remainder, sign differs from d
%rd   = arith.addi %r, %d : i32                   // |r| < |d| and opposite signs: no overflow
%m    = arith.select %fix, %rd, %r : i32          // remainder has the divisor's sign
```

The differential runner's `pymod` operation uses this form and matched on all three targets.
