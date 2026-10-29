# Out-of-tree MLIR dialect and BPF object compiler. build.sh owns the configure command.
cmake_minimum_required(VERSION 3.20)
project(bpf-mlir LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BPF_MLIR_DISTRIBUTION "Build the source distribution" ON)
if(BPF_MLIR_DISTRIBUTION)
  set(_bpf_mlir_developer_default OFF)
else()
  set(_bpf_mlir_developer_default ON)
endif()
option(BPF_MLIR_BUILD_TESTS "Build non-root tests" ${_bpf_mlir_developer_default})
option(BPF_MLIR_BUILD_CAPI "Build the developer C API" ${_bpf_mlir_developer_default})
include(cmake/BuildContract.cmake)
if(BPF_MLIR_DISTRIBUTION)
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64)$")
    message(FATAL_ERROR "the source distribution supports Linux x86_64 only")
  endif()
  if(BPF_MLIR_BUILD_CAPI)
    message(FATAL_ERROR "the C API is not included in the source distribution")
  endif()
  bpf_mlir_check_distribution_tests()
  if(BPF_MLIR_BUILD_TESTS)
    set(Python3_EXECUTABLE "${BPF_MLIR_PYTHON}")
  endif()
endif()
find_package(MLIR 23.1.1 EXACT REQUIRED CONFIG)
bpf_mlir_check_toolchain("${LLVM_PACKAGE_VERSION}" "${LLVM_VERSION}")
message(STATUS "bpf-mlir defaults: distribution=${BPF_MLIR_DISTRIBUTION} tests=${BPF_MLIR_BUILD_TESTS} C_API=${BPF_MLIR_BUILD_CAPI}")
message(STATUS "MLIRConfig.cmake: ${MLIR_DIR}")
message(STATUS "LLVMConfig.cmake: ${LLVM_DIR}")
message(STATUS "LLVM version:     ${LLVM_PACKAGE_VERSION}")

# Set the executable output directory explicitly to match lit's <build>/bin.
set(LLVM_RUNTIME_OUTPUT_INTDIR ${CMAKE_BINARY_DIR}/bin)
set(LLVM_LIBRARY_OUTPUT_INTDIR ${CMAKE_BINARY_DIR}/lib)

list(APPEND CMAKE_MODULE_PATH "${MLIR_CMAKE_DIR}")
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(TableGen)
include(AddLLVM)
include(AddMLIR)

# Keep one LLVM instance per process. Exported MLIR targets can pull static LLVM
# components even when the toolchain supplies shared libLLVM. Mixing both splits
# AnalysisManager/cl::opt registries from pass plugins and has caused crashes and
# duplicate registrations. Redirect component targets to the shared library and
# clear their interface chains, including tools that do not load plugins.
if(LLVM_LINK_LLVM_DYLIB AND TARGET LLVM)
  # Imported locations are configuration-specific (e.g. RELEASE/RELWITHDEBINFO).
  # Inspect IMPORTED_CONFIGURATIONS rather than a fixed pair of names, and warn
  # if resolution fails so a toolchain cannot silently retain mixed LLVM copies.
  get_target_property(_bpfmlir_llvm_dylib LLVM IMPORTED_LOCATION)
  if(NOT _bpfmlir_llvm_dylib)
    get_target_property(_bpfmlir_llvm_cfgs LLVM IMPORTED_CONFIGURATIONS)
    foreach(_cfg IN LISTS _bpfmlir_llvm_cfgs)
      get_target_property(_bpfmlir_llvm_dylib LLVM IMPORTED_LOCATION_${_cfg})
      if(_bpfmlir_llvm_dylib)
        break()
      endif()
    endforeach()
  endif()
  if(NOT _bpfmlir_llvm_dylib)
    message(WARNING "bpf-mlir: LLVM_LINK_LLVM_DYLIB is ON but the LLVM dylib location could not be resolved (IMPORTED_CONFIGURATIONS=${_bpfmlir_llvm_cfgs}); static LLVM components stay linked — a pass plugin loaded in-process may crash")
  endif()
  if(_bpfmlir_llvm_dylib)
    foreach(_c IN LISTS LLVM_AVAILABLE_LIBS)
      if(_c MATCHES "^LLVM[A-Za-z0-9]+$" AND NOT _c STREQUAL "LLVM" AND TARGET ${_c})
        get_target_property(_kind ${_c} TYPE)
        if(_kind STREQUAL "STATIC_LIBRARY")
          set_target_properties(${_c} PROPERTIES
            IMPORTED_LOCATION "${_bpfmlir_llvm_dylib}"
            IMPORTED_LOCATION_RELEASE "${_bpfmlir_llvm_dylib}"
            IMPORTED_LOCATION_DEBUG "${_bpfmlir_llvm_dylib}"
            IMPORTED_LOCATION_RELWITHDEBINFO "${_bpfmlir_llvm_dylib}"
            IMPORTED_LOCATION_MINSIZEREL "${_bpfmlir_llvm_dylib}"
            INTERFACE_LINK_LIBRARIES "LLVM")
        endif()
      endif()
    endforeach()
    message(STATUS "bpf-mlir: LLVM components resolve to ${_bpfmlir_llvm_dylib} (single LLVM per process)")
  endif()
endif()
include(HandleLLVMOptions)

# Match toolchain RTTI. Plain add_library does not apply LLVM's compile flags;
# missing -fno-rtti with the official RTTI-off archive causes undefined typeinfo
# references such as mlir::Pass. This code uses no dynamic_cast/typeid/exceptions.
if(NOT LLVM_ENABLE_RTTI)
  add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>)
endif()

include_directories(${LLVM_INCLUDE_DIRS} ${MLIR_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
# ODS .h.inc/.cpp.inc files use matching relative paths in the build tree.
include_directories(${CMAKE_CURRENT_BINARY_DIR}/include)
link_directories(${LLVM_BUILD_LIBRARY_DIR})

# Split whitespace-separated LLVM_DEFINITIONS: passing it as one value can make
# the first definition consume later definitions.
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

# Direct imported LLVMSupport can propagate dependency SDK includes ahead of
# libc++ wrappers, unlike MLIR's LINK_ONLY path. These headers are not used here;
# remove only include requirements, retaining link dependencies.
if(APPLE)
  foreach(_t ZLIB::ZLIB LibEdit::LibEdit zstd::libzstd_shared zstd::libzstd_static)
    if(TARGET ${_t})
      set_target_properties(${_t} PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ""
        INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "")
    endif()
  endforeach()
endif()

if(BPF_MLIR_BUILD_TESTS)
# Resolve explicit LLVM_EXTERNAL_LIT, then prefix/bin/llvm-lit, then prefix/bin/lit.
# LLVM_DEFAULT_EXTERNAL_LIT can point at a nonexistent path; fail at configure
# time rather than deferring a missing executable to the test run.
if(NOT DEFINED LLVM_EXTERNAL_LIT OR LLVM_EXTERNAL_LIT STREQUAL "")
  foreach(cand "${LLVM_TOOLS_BINARY_DIR}/llvm-lit" "${LLVM_TOOLS_BINARY_DIR}/lit")
    if(EXISTS "${cand}")
      set(LLVM_EXTERNAL_LIT "${cand}" CACHE FILEPATH "lit runner" FORCE)
      break()
    endif()
  endforeach()
endif()
if(NOT DEFINED LLVM_EXTERNAL_LIT OR NOT EXISTS "${LLVM_EXTERNAL_LIT}")
  message(FATAL_ERROR
    "no usable lit runner. Pass -DLLVM_EXTERNAL_LIT=<path to lit> "
    "(Homebrew llvm ships neither llvm-lit nor lit — build.sh creates a pinned "
    "third_party/lit-venv; see docs/build.md)")
endif()
message(STATUS "lit:              ${LLVM_EXTERNAL_LIT}")
endif()

# Generate ODS before libraries that depend on its targets.
add_subdirectory(include/bpf-mlir/Dialect/EBPF/IR)
add_subdirectory(include/bpf-mlir/Dialect/EBPF/Transforms)
add_subdirectory(include/bpf-mlir/Dialect/BPFABI/IR)
add_subdirectory(include/bpf-mlir/Dialect/BPFABI/Transforms)
add_subdirectory(include/bpf-mlir/Dialect/BTF/IR)
add_subdirectory(include/bpf-mlir/Dialect/BTF/Transforms)

add_subdirectory(lib)
add_subdirectory(tools)
if(BPF_MLIR_BUILD_TESTS)
  if(NOT BPF_MLIR_DISTRIBUTION)
    add_subdirectory(unittests)
  endif()
  add_subdirectory(third_party/llvm-test-utils)
  add_subdirectory(test)
endif()
