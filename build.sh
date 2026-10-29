#!/bin/sh
# Build the three compiler CLIs. Optional tests never bootstrap dependencies.
set -eu
repo=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
case "$(uname -s):$(uname -m)" in Linux:x86_64) ;; *) echo 'source distribution requires Linux x86_64' >&2; exit 1;; esac
prefix=${LLVM_PREFIX:?set LLVM_PREFIX to LLVM/MLIR 23.1.1}
build=${BUILD_DIR:-$repo/build}
tests=${BPF_MLIR_BUILD_TESTS:-OFF}
case "$tests" in ON|OFF) ;; *) echo 'BPF_MLIR_BUILD_TESTS must be ON or OFF' >&2; exit 1;; esac
cmake -G Ninja -S "$repo" -B "$build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="${CC:-$prefix/bin/clang}" \
  -DCMAKE_CXX_COMPILER="${CXX:-$prefix/bin/clang++}" \
  -DLLVM_DIR="$prefix/lib/cmake/llvm" -DMLIR_DIR="$prefix/lib/cmake/mlir" \
  -DBPF_MLIR_DISTRIBUTION=ON -DBPF_MLIR_BUILD_CAPI=OFF \
  -DBPF_MLIR_BUILD_TESTS="$tests" \
  -DLLVM_EXTERNAL_LIT="${LLVM_EXTERNAL_LIT:-}" -DBPF_MLIR_PYTHON="${BPF_MLIR_PYTHON:-}"
ninja -C "$build" ebpf-compile ebpf-opt ebpf-schema-check
if [ "$tests" = ON ]; then ninja -C "$build" check-bpf-mlir; fi
