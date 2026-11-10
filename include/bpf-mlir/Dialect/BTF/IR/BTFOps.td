// Schema-derived BTF IR. Named structs are nominal ops in separate @records
// and @kernel scopes, referenced as nested symbols. Anonymous types are
// structurally uniqued attributes; #btf.ref names a struct. FUNC/VAR are symbol
// ops, with VAR sections producing DATASEC through LLVM's BPF backend.
// The schema remains canonical: ebpf-build-btf constructs this IR, which
// convert-btf-to-llvm-di lowers to LLVM debug attributes. Do not hand-encode BTF.
#ifndef BTF_OPS
#define BTF_OPS

include "mlir/IR/AttrTypeBase.td"
include "mlir/IR/OpBase.td"
include "mlir/IR/SymbolInterfaces.td"
include "mlir/IR/RegionKindInterface.td"

def BTF_Dialect : Dialect {
  let name = "btf";
  let cppNamespace = "::mlir::btf";
  let summary = "BTF types: named structs as operations, anonymous types as attributes, locally verified and lowered to DI";
  let useDefaultAttributePrinterParser = 1;
}

class BTF_Attr<string name, string attrMnemonic> : AttrDef<BTF_Dialect, name> {
  let mnemonic = attrMnemonic;
}

// Anonymous type attributes. Void is valid only as a pointer target:
// void* is PTR to BTF type ID zero, not a zero-width INT named void.
def BTF_VoidAttr : BTF_Attr<"Void", "void"> {
  let summary = "void, only as a pointer target";
}

// Integer encodings signed/unsigned/char map to DW_ATE_signed/unsigned/signed_char.
def BTF_IntAttr : BTF_Attr<"Int", "int"> {
  let summary = "an integer type with a name, bit width and signedness";
  let parameters = (ins StringRefParameter<"name">:$name, "uint64_t":$bits,
                        StringRefParameter<"encoding">:$encoding);
  let assemblyFormat = "`<` $name `,` $bits `,` $encoding `>`";
  let genVerifyDecl = 1;
}

// an anonymous enum of 8/16/32/64 bits with no enumerators. Only a
// kernel_types field uses it (the CO-RE local type of a kernel ENUM field —
// cilium matches an anonymous local enum with any target enum of that name).
def BTF_EnumAttr : BTF_Attr<"Enum", "enum"> {
  let summary = "an anonymous enum of a bit width, without enumerators";
  let parameters = (ins "uint64_t":$bits);
  let assemblyFormat = "`<` $bits `>`";
  let genVerifyDecl = 1;
}

// libbpf __ulong(name, value) — an anonymous unsigned ENUM64 (8 bytes)
// with one enumerator whose value is the 64-bit integer. Only the arena map
// definition member map_extra uses it: the __uint form int (*)[N] cannot carry
// a value above U32_MAX bytes (btf-verify K9). libbpf get_map_field_long and
// cilium uintFromBTF read Values[0]; the enumerator name is not read.
def BTF_ULongAttr : BTF_Attr<"ULong", "ulong"> {
  let summary = "a 64-bit unsigned value as a one-enumerator anonymous ENUM64 (libbpf __ulong)";
  let parameters = (ins "uint64_t":$value);
  let assemblyFormat = "`<` $value `>`";
}

def BTF_PtrAttr : BTF_Attr<"Ptr", "ptr"> {
  let summary = "a 64-bit pointer";
  let parameters = (ins "::mlir::Attribute":$pointee);
  let assemblyFormat = "`<` $pointee `>`";
}

def BTF_ConstAttr : BTF_Attr<"Const", "const"> {
  let summary = "a const qualifier";
  let parameters = (ins "::mlir::Attribute":$base);
  let assemblyFormat = "`<` $base `>`";
}

// TYPE_TAG is allowed only as a pointer target: PTR -> TYPE_TAG -> T marks
// referenced map-value kptr fields. ObjectEmitter bridges it to DI pointer
// annotations named btf_type_tag.
def BTF_TypeTagAttr : BTF_Attr<"TypeTag", "type_tag"> {
  let summary = "a TYPE_TAG qualifier on a pointer target, including the kptr annotation";
  let parameters = (ins StringRefParameter<"tag">:$tag, "::mlir::Attribute":$base);
  let assemblyFormat = "`<` $tag `,` $base `>`";
}

def BTF_ArrayAttr : BTF_Attr<"ArrayOf", "array"> {
  let summary = "an array with element type and count; size is element size times count";
  let parameters = (ins "::mlir::Attribute":$element, "uint64_t":$count);
  let assemblyFormat = "`<` $element `,` $count `>`";
  let genVerifyDecl = 1;
}

// Named struct reference via nested symbol, e.g. @records::@event.
def BTF_RefAttr : BTF_Attr<"Ref", "ref"> {
  let summary = "a reference to a named type";
  let parameters = (ins "::mlir::SymbolRefAttr":$target);
  let assemblyFormat = "`<` $target `>`";
}

// Struct member size_bits is its type's DI sizeInBits.
def BTF_MemberAttr : BTF_Attr<"Member", "member"> {
  let summary = "a struct member with a name, bit offset, bit width and type";
  let parameters = (ins StringRefParameter<"name">:$name, "uint64_t":$offsetBits,
                        "uint64_t":$sizeBits, "::mlir::Attribute":$type);
  let assemblyFormat = "`<` $name `,` $offsetBits `,` $sizeBits `,` $type `>`";
}

// Anonymous struct for loader-compatible __uint/__type map definitions.
def BTF_AnonStructAttr : BTF_Attr<"AnonStruct", "anon_struct"> {
  let summary = "an anonymous struct";
  let parameters = (ins "uint64_t":$sizeBits, "uint64_t":$alignBits,
                        ArrayRefParameter<"::mlir::btf::MemberAttr">:$members);
  let assemblyFormat = "`<` $sizeBits `,` $alignBits `,` `[` $members `]` `>`";
}

// Anonymous FUNC_PROTO, used as a struct_ops function-pointer member target.
// result is the return type (#btf.void for void); params are argument types.
def BTF_FuncProtoAttr : BTF_Attr<"FuncProto", "func_proto"> {
  let summary = "a function type with return and argument types, used as a function-pointer target";
  let parameters = (ins "::mlir::Attribute":$result, "::mlir::ArrayAttr":$params);
  let assemblyFormat = "`<` $result `,` $params `>`";
}

def BTF_ParamAttr : BTF_Attr<"Param", "param"> {
  let summary = "a named function argument; global FUNC arguments require names";
  // Optional argument DECL_TAG strings, such as arg:nonnull; component_idx
  // is the argument index. Omission means no tags.
  let parameters = (ins StringRefParameter<"name">:$name, "::mlir::Attribute":$type,
                        OptionalParameter<"::mlir::ArrayAttr">:$tags);
  let builders = [
    AttrBuilder<(ins "::llvm::StringRef":$name, "::mlir::Attribute":$type), [{
      return $_get($_ctxt, name, type, ::mlir::ArrayAttr());
    }]>
  ];
  let assemblyFormat = "`<` $name `,` $type (`,` $tags^)? `>`";
}

// Named declarations (operations).
class BTF_Op<string mnemonic, list<Trait> traits = []> : Op<BTF_Dialect, mnemonic, traits>;

def BTF_ScopeOp : BTF_Op<"scope", [Symbol, SymbolTable, NoTerminator, SingleBlock, NoRegionArguments]> {
  let summary = "a scope: @records for userspace records, @kernel for local CO-RE types, @objects for globals and functions";
  let arguments = (ins SymbolNameAttr:$sym_name);
  let regions = (region SizedRegion<1>:$body);
  let assemblyFormat = "$sym_name attr-dict-with-keyword $body";
  let hasVerifier = 1;
}

def BTF_StructOp : BTF_Op<"struct", [Symbol, HasParent<"ScopeOp">]> {
  let summary = "a named nominal struct";
  let arguments = (ins SymbolNameAttr:$sym_name, I64Attr:$size_bits, I64Attr:$align_bits,
                       TypedArrayAttrBase<BTF_MemberAttr, "members">:$members);
  let assemblyFormat = "$sym_name attr-dict";
  let hasVerifier = 1;
}

def BTF_VarOp : BTF_Op<"var", [Symbol, HasParent<"ScopeOp">]> {
  let summary = "a global variable for maps, record witnesses or a license; its ELF section becomes a DATASEC";
  let arguments = (ins SymbolNameAttr:$sym_name, AnyAttr:$type, StrAttr:$section);
  let assemblyFormat = "$sym_name attr-dict";
  let hasVerifier = 1;
}

def BTF_FuncOp : BTF_Op<"func", [Symbol, HasParent<"ScopeOp">]> {
  let summary = "a program function represented by FUNC and FUNC_PROTO, with named arguments";
  // FUNC linkage is global (default) or static.
  let arguments = (ins SymbolNameAttr:$sym_name, TypedArrayAttrBase<BTF_ParamAttr, "params">:$params,
                       AnyAttr:$result, DefaultValuedStrAttr<StrAttr, "global">:$linkage);
  let assemblyFormat = "$sym_name attr-dict";
  let hasVerifier = 1;
}

#endif // BTF_OPS
