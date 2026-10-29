// Kernel-ABI pass declarations.
#ifndef BPFABI_TRANSFORMS_PASSES
#define BPFABI_TRANSFORMS_PASSES

include "mlir/Pass/PassBase.td"

def BPFABIVerify : Pass<"bpfabi-verify", "mlir::ModuleOp"> {
  let summary = "Stage 3 kernel-ABI exit check: compare IR numbers with the UAPI table";
  let description = [{
    Check bpfabi.helper_call numbers, argument counts and nullability,
    bpfabi.ctx_packet offsets and widths, and bpfabi.return verdicts against
    KernelABI.h. Each op is Verified or Rejected (only these two of the four
    verdicts occur at this stage). Any Rejected verdict fails the pass.
  }];
  let options = [
    Option<"report", "report", "bool", /*default=*/"false",
           "print verdict counts as remarks">
  ];
}

def BPFABIRequirements : Pass<"bpfabi-requirements", "mlir::ModuleOp"> {
  let summary = "Stage 3 exit: collect kernel capability requirements per program";
  let description = [{
    Compilation does not decide whether the target kernel supports a program
    type or a helper for that program type. Record these requirements per
    program (llvm.func) as `bpfabi.requires = {prog_type = "xdp", helpers = [...]}`.
    ObjectEmitter writes them into the ELF `.ebpf_requirements` section; the
    target check compares them with actual capabilities at load time.
    Each requirement row is Conditional. A program type absent from the UAPI
    table is Rejected.
  }];
  let options = [
    Option<"report", "report", "bool", /*default=*/"false",
           "print verdict counts as remarks">
  ];
}

def ConvertBPFABIToLLVM : Pass<"convert-bpfabi-to-llvm", "mlir::ModuleOp"> {
  let summary = "Stage 3 to 4: expand bpfabi operations into LLVM dialect";
  let description = [{
    helper_call becomes an indirect call through the numbered function pointer,
    as in libbpf. ctx_packet becomes a u32 context read, extension to 64 bits,
    and inttoptr. return becomes a constant verdict and llvm.return.
  }];
  let dependentDialects = ["::mlir::LLVM::LLVMDialect"];
}

#endif // BPFABI_TRANSFORMS_PASSES
