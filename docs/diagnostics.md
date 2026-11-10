# ebpf-compile diagnostic line format (contract)

- **Date**: 2026-09-28. The existing format is fixed as a contract.
- **Development tests**: `test/Target/EBPF/diag-format.test` checks exact warning, note and error prefixes; `test/Target/EBPF/btf-rules.test` checks K9 locations.

## Format

Each ebpf-compile diagnostic is written to stderr as a line:

```
loc("<F>":<L>:<C>): <severity>: <message>
```

- `<severity>` is `error`, `warning` or `note`. Remarks occur only in development pass reports, not in the default ebpf-compile output.
- **A `note:` line continues the preceding `error:` or `warning:`**, for example `note: the constant index comes from here`. `note: see current operation: …` continues an operation-verifier error.
- Any error gives rc 1 and no ELF output. Warnings and notes alone give rc 0; warnings do not change the ELF bytes.
- Lines beginning `ebpf-compile: <message>` report errors outside MLIR operations (schema reading or input/output) and have no location.

## Origin of `<F>:<L>:<C>`

- An operation's FileLineColLoc supplies the location. For handwritten `.mlir`, this is the input file, line and column. If a frontend emits `loc("x.rb":12:10)`, it is **the frontend source location**. NameLoc and FusedLoc use an inner FileLineColLoc.
- A map-definition error (such as btf-verify K9, a btf.var error) uses **the location of the first operation referencing the map**. For a map bound by `maps [@m]`, this is the program operation; for a ring buffer referenced by name, it is the reservation operation. A declared but unused map is absent from the ELF, so its definition errors are not emitted either.
- An operation without a frontend location may use the input file with `:0:0` or `1:1`.

## Downstream dependencies (coordinate format changes)

- spinel-bpf-mlir `cmd/spinelbpf/e013_test.go` checks the `loc("idx.rb":19:11): warning:` prefix and `loc\("[^"]+":\d+:\d+\)`.
- go-bpf-mlir `internal/toolchain/toolchain.go` classifies `loc("F":L:C): warning:` and subsequent `note:` lines as Warning.
- mojo-bpf-mlir `internal/toolchain` fails closed on lines other than the recognized `loc(…): warning:` / `note:` forms.

A change to this format requires a separate plan and synchronized versions of all three downstream parsers; the original contract was fixed before v1.0.

## Cost of adding warning kinds

Separately from the line-format contract, **mojo-bpf-mlir recognizes warning kinds by message-prefix phrases and fails closed on an unknown phrase**. Its `TestCompileWarningKinds` explicitly rejects `a brand-new warning bpf-mlir might add`. go-bpf-mlir accepts any message with the recognized line format as Warning without stopping generation (GB024); spinel-bpf-mlir uses the return code and preserves the original message in generated output.

Therefore **a new warning kind enabled by default stops mojo compilation of programs that trigger it**. Either synchronize the new phrase in mojo at the same version, as with the bml copy, or introduce the warning disabled by default (`--warn-…` opt-in) until downstream enables it. Existing kinds concern a non-root-shaped ref.index index and a mask range exceeding a record's array.

**Opt-in kinds (default off — the default `ebpf-compile` output is unchanged).** `--warn-shared-rmw` adds the kind whose message starts with the phrase `a non-atomic read-modify-write of` (`… a shared <kind> map value` / `… a map value whose map kind is not known in this function …` / `… the .bss global @G`): a value loaded from a shared (not per-CPU) map value or a `.bss` global reaches a write of the same location in the same function, followed by `note: the value is loaded here`. A downstream that passes the flag must recognize the phrase first. The rules and limits are in the pass description (`ebpf-warn-shared-rmw`); shapes that cross functions are reported by `kernel/cmd/rmwprobe` only (`docs/tools/rmwprobe.md`).
