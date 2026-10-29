# Requirements conformance data

These fixed inputs and expected results let a checker in any language test its
implementation of [the requirements contract](../../docs/requirements_format.md).
They do not require a Go toolchain. The reference loader implementations are
not part of this source package.

- `cases/<name>/`: `object.bpf.o` or `requirements.txt`, recorded `caps.json`, and
  `want.json`. Optional `load_as.json` and `reprobe.json` define the loading
  privileges and available reprobe answers. `case.json` contains optional metadata.
- `parse/<name>/`: section text and expected parse acceptance or the first rule,
  row and line that must be rejected.
- `maps/<name>/`: object or section text, caller `maps.json`, and the expected
  map/layout comparison result.
- `json/<name>/`: JSON-reading inputs and expected validity/rule names.
- `bin/`: fixed ELF, DWARF and USDT binary inputs used by recorded file answers.
  Resolve their relative paths from each caps file's directory. Do not execute
  these binaries; they are evidence for file-reading checks.
- `VERSION`: the requirements format ceiling and verdict-policy version.

Read each case's input, apply the normative rules and compare every expected
field in order. Include nonblocking unmet requirements. A checking failure is
not the same as a definite target mismatch. Missing input, missing case or an
unknown answer must not count as success. JSON fixtures include intentionally
invalid bytes and must be read without repair or reformatting.

The development checkout owns data regeneration. Descriptive why/source metadata
is omitted from the source package; test inputs, expected results, names and
relative binary references are retained. See specification sections 10, 12 and
13 for the exact result shapes and comparison obligations.
