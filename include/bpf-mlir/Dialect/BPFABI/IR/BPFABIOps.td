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

// a kernel enum constant read through a CO-RE
// enum value relocation. value is the UAPI table's (the relocation's local
// value); ④ writes the marker __ebpf_core_enum.<enum>.<name>, which
// ObjectEmitter turns into llvm.bpf.preserve.enum.value. Requirements record
// coreenum <prog> <enum> <name> so the loader checks that the target has it.
def BPFABI_CoreEnumValueOp : BPFABI_Op<"core_enum_value", [Pure]> {
  let summary = "a kernel enum constant the loader writes from the target BTF (CO-RE enum value)";
  let arguments = (ins StrAttr:$enum_name, StrAttr:$name, I64Attr:$value);
  let results = (outs I64:$result);
  let assemblyFormat = "$enum_name $name `=` $value attr-dict";
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

// ctx_meta reads xdp_md data_meta and data as __u32 (the verifier rewrites
// them to PTR_TO_PACKET_META / PTR_TO_PACKET). Eight-byte reads fail context validation.
def BPFABI_CtxMetaOp : BPFABI_Op<"ctx_meta"> {
  let summary = "read the XDP context data_meta and data fields at four-byte width as pointers";
  let arguments = (ins AnyType:$ctx, StrAttr:$kind, I64Attr:$meta_offset,
                       I64Attr:$data_offset, I64Attr:$field_bytes);
  let results = (outs AnyType:$meta, AnyType:$data);
  let assemblyFormat =
      "$ctx $kind attr-dict `:` type($ctx) `->` type($meta) `,` type($data)";
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

// CO-RE existence (bpf_core_type_exists / bpf_core_field_exists). The
// loader writes 1 or 0 at load; the compiler does not know which. The
// marker __ebpf_core_exists.<kind>.<struct>[.<field>] expands in ObjectEmitter
// to llvm.bpf.preserve.type.info / preserve.field.info (clang's form).
def BPFABI_CoreExistsOp : BPFABI_Op<"core_exists"> {
  let summary = "CO-RE type or field existence (0 or 1, set by the loader)";
  let arguments = (ins StrAttr:$kind, StrAttr:$struct_name, StrAttr:$field);
  let results = (outs I32:$result);
  let assemblyFormat = "$kind $struct_name `,` $field attr-dict";
}

// CO-RE field byte offset (bpf_core_field_offset) for kaddr.container_of.
// The marker __ebpf_core_offset.<struct>.<field> expands in ObjectEmitter to
// llvm.bpf.preserve.field.info(…, BPF_FIELD_BYTE_OFFSET 0) (clang's form).
def BPFABI_CoreFieldOffsetOp : BPFABI_Op<"core_field_offset"> {
  let summary = "CO-RE field byte offset (relocated by the loader)";
  let arguments = (ins StrAttr:$struct_name, StrAttr:$field);
  let results = (outs I32:$result);
  let assemblyFormat = "$struct_name `,` $field attr-dict";
}

// the address of an arena window — base (bpf_arena.user_vm_start, i64)
// plus the checked offset, as an address-space-1 (__arena) pointer. ③ creates
// it only at the entry of an arena.check_br's in-range block (never before the
// range compare). ④ expands it to add and inttoptr; the BPF backend emits
// addr_space_cast before the first access. No traits: it must not be moved.
def BPFABI_ArenaAddrOp : BPFABI_Op<"arena_addr"> {
  let summary = "arena window address: base + offset in address space 1";
  let arguments = (ins I64:$base, I64:$offset);
  let results = (outs AnyType:$result);
  let assemblyFormat = "$base `,` $offset attr-dict `:` type($result)";
  let hasVerifier = 1;
}

// Return the attach-specific verdict and terminate the program.
def BPFABI_ReturnOp : BPFABI_Op<"return", [Terminator]> {
  let summary = "return an attach-kind verdict value such as xdp_action";
  let arguments = (ins StrAttr:$kind, StrAttr:$action, I32Attr:$value);
  let assemblyFormat = "$kind $action attr-dict";
}

#endif // BPFABI_OPS
