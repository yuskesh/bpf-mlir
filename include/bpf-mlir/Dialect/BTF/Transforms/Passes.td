// BTF pass declarations.
#ifndef BTF_TRANSFORMS_PASSES
#define BTF_TRANSFORMS_PASSES

include "mlir/Pass/PassBase.td"

def EBPFBuildBTF : Pass<"ebpf-build-btf", "mlir::ModuleOp"> {
  let summary = "Build BTF IR from the schema and lowered module";
  let description = [{
    Add btf dialect types to a module lowered to stage 4 (LLVM dialect):
    `btf.scope @records` for schema records, `btf.scope @kernel` for schema
    kernel_types (local CO-RE types), `btf.var` for map definitions used by the
    program (`__uint(type)` / `__uint(max_entries)` / `__type(key)` / `__type(value)`),
    record witnesses and license, and `btf.func` for program functions and argument
    names. The schema is canonical; BTF IR is derived.
  }];
  let options = [
    Option<"schemaPath", "schema", "std::string", /*default=*/"\"\"", "canonical schema path">,
    Option<"license", "license", "std::string", /*default=*/"\"GPL\"", "license string">
  ];
  let dependentDialects = ["::mlir::btf::BTFDialect"];
}

def EBPFBuildBTFTypes : Pass<"ebpf-build-btf-types", "mlir::ModuleOp"> {
  let summary = "Build only BTF type declarations (@records / @kernel) from the schema at stage 1";
  let description = [{
    Build type declarations before lowering, so ebpf-verify-kptr can check stage-1
    ebpf types (!ebpf.kptr) against BTF declarations. After lowering,
    ebpf-build-btf adds variables and functions (@objects), reusing existing types.
  }];
  let options = [
    Option<"schemaPath", "schema", "std::string", /*default=*/"\"\"", "canonical schema path">
  ];
  let dependentDialects = ["::mlir::btf::BTFDialect"];
}

def ConvertBTFToLLVMDI : Pass<"convert-btf-to-llvm-di", "mlir::ModuleOp"> {
  let summary = "Lower BTF IR to LLVM dialect globals and DI attributes";
  let description = [{
    btf.var becomes `llvm.mlir.global` plus `dbg_exprs` (replacing map placeholders,
    creating witnesses and license). btf.func becomes `DISubprogram` in the
    function's fused location (arguments are DILocalVariable retainedNodes).
    Remove `btf.scope @records`, btf.var and btf.func. Keep `btf.scope @kernel`
    (local CO-RE types) for ObjectEmitter's bridge: LLVM dialect cannot represent
    `!llvm.preserve.access.index` metadata.

    Only frontend-explicit op locations (the innermost FileLineColLoc whose file
    differs from the module location file) become
    `fused<#llvm.di_lexical_block_file<...>>` for line_info / DWARF. Remove other
    locations supplied by the parser. Absolute paths or names containing `..`
    are rejected for reproducibility. `line-info=false` removes all locations.
  }];
  let options = [
    Option<"lineInfo", "line-info", "bool", /*default=*/"true", "copy frontend-explicit op locations to line_info / DWARF (false removes all)">
  ];
  let dependentDialects = ["::mlir::LLVM::LLVMDialect"];
}

def BTFVerify : Pass<"btf-verify", "mlir::ModuleOp"> {
  let summary = "Check BTF IR against BTF rules (four verdicts)";
  let description = [{
    Rules have three classes: K, kernel acceptance constraints (kernel/bpf/btf.c);
    L, ELF / loader contracts; and C, compiler limitations. Violations are
    Rejected, identified at their MLIR locations, and fail the pass. Values
    supplied by the loader, such as DATASEC size / offsets, are Conditional.
    report prints verdict counts as remarks.
  }];
  let options = [
    Option<"report", "report", "bool", /*default=*/"false", "print verdict counts as remarks">
  ];
}

def BTFDumpGraph : Pass<"btf-dump-graph", "mlir::ModuleOp"> {
  let summary = "Dump BTF IR in btfgraph format for comparing IR with emitted BTF";
  let description = [{
    Print BTF IR roots in the format of the .BTF part of btfgraph, which reads
    ELF `.BTF` through cilium/ebpf. Mirror LLVM BPF backend conventions (array
    index type `__ARRAY_SIZE_TYPE__`, char as signed INT, etc.). DATASEC does not
    yet have loader-supplied sizes / offsets, so print only variable order;
    the comparison also omits sizes / offsets.
  }];
  let options = [
    Option<"out", "out", "std::string", /*default=*/"\"-\"", "output path (- for stdout)">
  ];
}

#endif // BTF_TRANSFORMS_PASSES
