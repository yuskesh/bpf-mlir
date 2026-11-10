# Building the source distribution

The source distribution is `bpf-mlir-<version>-source.tar.gz`. It supports
**Linux x86_64**, validated on Debian 13. macOS and arm64 are not supported.
It includes the three compiler CLIs, public specifications, conformance data and
a small optional non-root test suite. It contains no Go source, Go modules,
prebuilt binaries, C API/SDK or kernel test runners. Go is not a prerequisite.
Publication requires the project's license and release acceptance; an internal
export made before that step is not a published release.

## Prerequisites

Supply LLVM/MLIR **23.1.1**, including headers, CMake packages, `mlir-tblgen`, Clang
and LLVM tools. Configuration rejects other versions. We do not bundle or
silently download LLVM.

Official archive:
[LLVM-23.1.1-Linux-X64.tar.xz](https://github.com/llvm/llvm-project/releases/download/llvmorg-23.1.1/LLVM-23.1.1-Linux-X64.tar.xz)

SHA256:
`832aeb58d105de1cabc7b982dd2c65de0610f7377df48ae8fc2dd8e97420a15c`

The URL and digest come from the official
[LLVM 23.1.1 release](https://github.com/llvm/llvm-project/releases/tag/llvmorg-23.1.1).
Verify the archive against that digest before unpacking it. The release also
provides signature/attestation files. Supplying LLVM is a separate preparation
step; the build does not fetch this archive.

Other C++ build prerequisites: CMake >=3.20, Ninja, Bash and POSIX shell utilities
(including awk, sed, realpath and coreutils), a working Linux C/C++ development
sysroot, and the runtime/development dependencies required by the chosen LLVM
archive. For the Debian 13 package list, see the declaration below; it includes
libc and the selected archive dependencies. Clang/clang++ are the defaults;
CC/CXX may select compatible C/C++17 compilers. No package installation is
performed by the build.

## Compiler CLIs: no network or Python required

After prerequisites are installed, unpack the source archive and run:

```sh
LLVM_PREFIX=/path/to/llvm-23.1.1 ./build.sh
```

The outputs are `build/bin/ebpf-compile`, `ebpf-opt` and `ebpf-schema-check`.
`BUILD_DIR` chooses another build directory. Tests and the C API are disabled by
default in the source distribution. This C++ build does not run Go, pip, Git
fetches or a package manager. It reads `SOURCE_VERSION` from the unpacked root;
missing or invalid metadata is an error. A parent Git repository cannot supply
its version. The version is displayed by the compiler and is not embedded into
ELF output. The metadata records a source commit; it is not a digital signature. The commit names
the compiler source: the documents in the package can come from a later commit that
changes documents only, so a document may differ from that commit.

## Optional tests

Tests source is included but building/running it is optional. Supply Python 3
and an explicitly selected **lit 23.1.1** executable; this build does not create
a venv or run pip. A pre-provisioned lit environment is suitable.

```sh
LLVM_PREFIX=/path/to/llvm-23.1.1 \
BPF_MLIR_BUILD_TESTS=ON \
LLVM_EXTERNAL_LIT=/path/to/lit \
BPF_MLIR_PYTHON=/path/to/python3 ./build.sh
```

The four distribution tests cover CLI availability, schema-backed compilation
with BTF/requirements, invalid-schema rejection and reservation ownership.
They require neither root nor a running BPF program and do not replace the
full development suite. Matching LLVM FileCheck/count/not utility sources are
included under third_party/llvm-test-utils with their LICENSE.TXT and NOTICE.txt;
no LLVM binaries/libraries or lit/Python runtime are bundled.

## Development checkout

The development repository keeps its tests-on and C API-on defaults, and its
existing build.sh may bootstrap lit. Those defaults differ intentionally from
the unpacked source package. The distribution build and file set are generated
from a fixed commit; changes should be made upstream and exported again.

When lit comes from a virtual environment, BPF_MLIR_PYTHON must select that
environment's Python (with the lit module installed), not an unrelated system
Python. The build does not install lit into a different interpreter.

## Debian 13 package declaration

For the validated Linux x86_64 configuration, install the following Debian 13
packages and their **Depends/Pre-Depends** (Recommends are not required). Python
is needed only for the optional tests; lit 23.1.1 is supplied separately as described above. No Go toolchain is needed. This declaration includes the dependencies of the
selected LLVM archive; libedit is disabled in that archive and is not required.

<!-- source-build-packages -->
```text
dash bash coreutils diffutils findutils grep sed mawk tar gzip xz-utils
cmake ninja-build gcc g++ libc6-dev zlib1g-dev libzstd-dev libxml2-dev python3
```
<!-- /source-build-packages -->

The build never runs apt or installs these packages itself.
