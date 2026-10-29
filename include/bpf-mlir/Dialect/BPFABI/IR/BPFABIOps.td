// Kernel-ABI stage: operations expose UAPI helper IDs, context access widths
// and verdict values. Control/arithmetic use LLVM/arith. Lowering reads the
// KernelABI table and bpfabi-verify checks against that same table, making
// wrong widths, IDs or nullability explicit before LLVM lowering.
#ifndef BPFABI_OPS
#define BPFABI_OPS

include "mlir/IR/OpBase.td"
include "mlir/Interfaces/SideEffectInterfaces.td"

def BPFABI_Dialect : Dialect {
  let name = "bpfabi";
  let cppNamespace = "::mlir::bpfabi";
  let summary = "kernel ABI stage with explicit helper IDs, context layouts and verdict values";
}

class BPFABI_Op<string mnemonic, list<Trait> traits = []>
    : Op<BPFABI_Dialect, mnemonic, traits>;

// helper_call retains both the human/table name and the immediate call ID.
// ret_nullable follows *_OR_NULL bpf_func_proto return types.
def BPFABI_HelperCallOp : BPFABI_Op<"helper_call"> {
  let summary = "call a helper by numeric ID";
  let arguments = (ins StrAttr:$callee, I64Attr:$id, UnitAttr:$ret_nullable,
                       Variadic<AnyType>:$args);
  let results = (outs Variadic<AnyType>:$results);
  let assemblyFormat =
      "$callee `(` $args `)` attr-dict `:` functional-type($args, $results)";
  let hasVerifier = 1;
}

// kfunc_call has no numeric ID: the loader resolves the BTF name. ret_null
// requires result use only on the true null-check edge, as for helper calls.
// LLVM calls the .ksyms extern; loader/verifier check presence/signature at load.
def BPFABI_KfuncCallOp : BPFABI_Op<"kfunc_call"> {
  let summary = "call a kfunc by name";
  let arguments = (ins StrAttr:$callee, UnitAttr:$ret_nullable, Variadic<AnyType>:$args);
  let results = (outs Variadic<AnyType>:$results);
  let assemblyFormat =
      "$callee `(` $args `)` attr-dict `:` functional-type($args, $results)";
  let hasVerifier = 1;
}

// ctx_packet reads xdp_md data/data_end as __u32 (field_bytes 4), which the
// verifier rewrites to real pointers. Eight-byte reads fail context validation
// (invalid bpf_context access off=4 size=8).
def BPFABI_CtxPacketOp : BPFABI_Op<"ctx_packet"> {
  let summary = "read context data/data_end fields at explicit widths as pointers";
  let arguments = (ins AnyType:$ctx, StrAttr:$kind, I64Attr:$data_offset,
                       I64Attr:$data_end_offset, I64Attr:$field_bytes);
  let results = (outs AnyType:$data, AnyType:$data_end);
  let assemblyFormat =
      "$ctx $kind attr-dict `:` type($ctx) `->` type($data) `,` type($data_end)";
  let hasVerifier = 1;
}

// kprobe_arg reads the argument's pt_regs register as eight bytes. Offsets
// and sizes follow architecture UAPI/calling conventions; ctxfield requirements
// check them against target BTF before load, so the exit verdict is Conditional.
def BPFABI_KprobeArgOp : BPFABI_Op<"kprobe_arg"> {
  let summary = "read the nth argument register from kprobe pt_regs";
  let arguments = (ins AnyType:$ctx, StrAttr:$arch, I64Attr:$n, I64Attr:$offset, I64Attr:$field_bytes);
  let results = (outs I64:$result);
  let assemblyFormat = "$ctx $arch `[` $n `]` attr-dict `:` type($ctx)";
}

// ctx_arg reads tp_btf's u64 argument array, like BPF_PROG: eight bytes at 8*index.
def BPFABI_CtxArgOp : BPFABI_Op<"ctx_arg"> {
  let summary = "read one u64 argument slot from a tracing context";
  let arguments = (ins AnyType:$ctx, I64Attr:$index, I64Attr:$offset,
                       I64Attr:$field_bytes);
  let results = (outs AnyType:$result);
  let assemblyFormat = "$ctx `[` $index `]` attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

// Context field loads/stores use UAPI ctxfield offsets and compiler
// abi/ctxaccess.tsv widths/permissions. The verifier rewrites these accesses;
// ABI exit checks compare both tables to catch invalid context access widths.
def BPFABI_TpBufferLoadOp : BPFABI_Op<"tp_buffer_load", [MemoryEffects<[MemRead, MemWrite]>]> {
  let summary = "perform one volatile i32 read from an owned raw_tp_writable private buffer";
  let arguments = (ins AnyType:$ctx, StrAttr:$prog_type, StrAttr:$attach_type,
                       I64Attr:$ctx_offset, I64Attr:$ctx_bytes, I64Attr:$buffer_offset, I64Attr:$buffer_bytes);
  let results = (outs I32:$result);
  let assemblyFormat = "$ctx attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

def BPFABI_TpBufferStoreOp : BPFABI_Op<"tp_buffer_store", [MemoryEffects<[MemRead, MemWrite]>]> {
  let summary = "perform one volatile i32 write to an owned raw_tp_writable private buffer";
  let arguments = (ins AnyType:$ctx, StrAttr:$prog_type, StrAttr:$attach_type,
                       I64Attr:$ctx_offset, I64Attr:$ctx_bytes, I64Attr:$buffer_offset, I64Attr:$buffer_bytes, I32:$value);
  let assemblyFormat = "$ctx `,` $value attr-dict `:` type($ctx) `,` type($value)";
  let hasVerifier = 1;
}

def BPFABI_CtxFieldLoadOp : BPFABI_Op<"ctx_field_load"> {
  let summary = "read a context integer or BTF-struct pointer field at a fixed offset and declared width";
  // Flexible ctx arrays (ctxfield count zero) use field offset + index*width.
  let arguments = (ins AnyType:$ctx, StrAttr:$prog_type, StrAttr:$attach_type, StrAttr:$strct, StrAttr:$field,
                       I64Attr:$offset, I64Attr:$field_bytes, OptionalAttr<I64Attr>:$index);
  let results = (outs AnyType:$result);
  let assemblyFormat = "$ctx $strct $field (`[` $index^ `]`)? attr-dict `:` type($ctx) `->` type($result)";
}

def BPFABI_CtxFieldStoreOp : BPFABI_Op<"ctx_field_store"> {
  let summary = "write a writable context integer field at a fixed offset and declared width";
  let arguments = (ins AnyType:$ctx, StrAttr:$prog_type, StrAttr:$attach_type, StrAttr:$strct, StrAttr:$field,
                       I64Attr:$offset, I64Attr:$field_bytes, AnySignlessInteger:$value);
  let assemblyFormat = "$ctx $strct $field `,` $value attr-dict `:` type($ctx) `,` type($value)";
}

// core_field_load has no fixed target offset: the loader relocates it with
// target BTF. ObjectEmitter obtains local field indices/temporary offsets from
// the schema and checks that same schema. LLVM's __ebpf_core.<struct>.<field>
// marker expands to preserve.struct.access.index and the actual load.
def BPFABI_CoreFieldLoadOp : BPFABI_Op<"core_field_load"> {
  let summary = "read a kernel struct field using a CO-RE relocation";
  let arguments = (ins AnyType:$ptr, StrAttr:$struct_name, StrAttr:$field);
  let results = (outs AnyType:$result); // Integer kfield.load or pointer kfield.ptr.
  let assemblyFormat =
      "$ptr $struct_name `,` $field attr-dict `:` type($ptr) `->` type($result)";
  let hasVerifier = 1;
}

// core_field_addr supports byte-array copies without a load. The LLVM marker
// __ebpf_core_addr.<struct>.<field> expands to preserve.struct.access.index.
def BPFABI_CoreFieldAddrOp : BPFABI_Op<"core_field_addr"> {
  let summary = "obtain a kernel struct field address using a CO-RE relocation";
  let arguments = (ins AnyType:$ptr, StrAttr:$struct_name, StrAttr:$field);
  let results = (outs AnyType:$result);
  let assemblyFormat =
      "$ptr $struct_name `,` $field attr-dict `:` type($ptr) `->` type($result)";
}

// Return the attach-specific verdict and terminate the program.
def BPFABI_ReturnOp : BPFABI_Op<"return", [Terminator]> {
  let summary = "return an attach-kind verdict value such as xdp_action";
  let arguments = (ins StrAttr:$kind, StrAttr:$action, I32Attr:$value);
  let assemblyFormat = "$kind $action attr-dict";
}

#endif // BPFABI_OPS
