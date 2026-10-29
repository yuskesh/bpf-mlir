//===- BTFDialect.cpp - registration and local BTF verification --------------===//
//
// Check local operation/attribute consistency: symbol resolution, member
// bounds and nonempty names. VerifyBTF separately owns kernel acceptance rules.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/BTF/IR/BTFDialect.h"

#include "mlir/IR/Builders.h"
#include "mlir/IR/BuiltinOps.h"
#include "mlir/IR/DialectImplementation.h"
#include "mlir/IR/OpImplementation.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/ADT/TypeSwitch.h"
#include "llvm/Support/MathExtras.h"

using namespace mlir;
using namespace mlir::btf;

#include "bpf-mlir/Dialect/BTF/IR/BTFOpsDialect.cpp.inc"

#define GET_ATTRDEF_CLASSES
#include "bpf-mlir/Dialect/BTF/IR/BTFOpsAttrs.cpp.inc"

#define GET_OP_CLASSES
#include "bpf-mlir/Dialect/BTF/IR/BTFOps.cpp.inc"

void BTFDialect::initialize() {
  addAttributes<
#define GET_ATTRDEF_LIST
#include "bpf-mlir/Dialect/BTF/IR/BTFOpsAttrs.cpp.inc"
      >();
  addOperations<
#define GET_OP_LIST
#include "bpf-mlir/Dialect/BTF/IR/BTFOps.cpp.inc"
      >();
}

// Type resolution.
namespace {
// Resolve nested symbols from nearest symbol tables outward. Checking only
// the outermost misses explicit modules wrapped by the parser's implicit module.
StructOp resolve(RefAttr ref, Operation *from) {
  for (Operation *op = from; op; op = op->getParentOp())
    if (op->hasTrait<OpTrait::SymbolTable>())
      if (auto st = dyn_cast_or_null<StructOp>(
              SymbolTable::lookupSymbolIn(op, ref.getTarget())))
        return st;
  return nullptr;
}
} // namespace

std::optional<uint64_t> mlir::btf::sizeInBits(Attribute type, Operation *from) {
  if (auto i = dyn_cast<IntAttr>(type))
    return i.getBits();
  if (isa<PtrAttr>(type))
    return 64;
  if (auto c = dyn_cast<ConstAttr>(type))
    return sizeInBits(c.getBase(), from);
  if (auto a = dyn_cast<ArrayOfAttr>(type)) {
    auto e = sizeInBits(a.getElement(), from);
    if (!e)
      return std::nullopt;
    return *e * a.getCount();
  }
  if (auto s = dyn_cast<AnonStructAttr>(type))
    return s.getSizeBits();
  if (auto r = dyn_cast<RefAttr>(type))
    if (StructOp st = resolve(r, from))
      return static_cast<uint64_t>(st.getSizeBits());
  return std::nullopt;
}

LogicalResult mlir::btf::verifyType(Attribute type, Operation *from,
                                    StringRef what) {
  auto err = [&]() { return from->emitOpError() << what << ": "; };
  if (isa<IntAttr>(type))
    return success();
  if (auto p = dyn_cast<PtrAttr>(type)) {
    if (isa<VoidAttr>(p.getPointee()))
      return success(); // void is legal only as a pointer pointee. Function pointers in local
    // struct_ops members permit void/typed returns and typed arguments.
    if (auto fp = dyn_cast<FuncProtoAttr>(p.getPointee())) {
      if (!isa<VoidAttr>(fp.getResult()) && failed(verifyType(fp.getResult(), from, what)))
        return failure();
      for (Attribute a : fp.getParams())
        if (failed(verifyType(a, from, what)))
          return failure();
      return success();
    }
    // TYPE_TAG is permitted only under PTR. The tag must be nonempty and its
    // target a struct reference, as for map-value kptr.
    if (auto tt = dyn_cast<TypeTagAttr>(p.getPointee())) {
      if (tt.getTag().empty())
        return err() << "a type_tag needs a non-empty tag";
      if (!isa<RefAttr>(tt.getBase()))
        return err() << "a type_tag must qualify a reference to a struct (the kptr of a map value), got " << tt.getBase();
      return verifyType(tt.getBase(), from, what);
    }
    return verifyType(p.getPointee(), from, what);
  }
  if (isa<TypeTagAttr>(type))
    return err() << "a type_tag may only be the target of a pointer";
  if (isa<VoidAttr>(type))
    return err() << "void may only be the target of a pointer (rule C4)";
  if (isa<FuncProtoAttr>(type))
    return err() << "a func_proto may only be the target of a pointer (a function pointer member)";
  if (auto c = dyn_cast<ConstAttr>(type))
    return verifyType(c.getBase(), from, what);
  if (auto a = dyn_cast<ArrayOfAttr>(type))
    return verifyType(a.getElement(), from, what);
  if (auto r = dyn_cast<RefAttr>(type)) {
    if (!resolve(r, from))
      return err() << "reference " << r.getTarget()
                   << " does not resolve to a btf.struct";
    return success();
  }
  if (auto s = dyn_cast<AnonStructAttr>(type)) {
    llvm::StringSet<> names;
    for (MemberAttr m : s.getMembers()) {
      if (m.getName().empty() || !names.insert(m.getName()).second)
        return err() << "anonymous struct member names must be non-empty and unique";
      if (m.getOffsetBits() + m.getSizeBits() > s.getSizeBits())
        return err() << "member \"" << m.getName() << "\" ends past the struct";
      if (failed(verifyType(m.getType(), from, what)))
        return failure();
    }
    return success();
  }
  return err() << "not a btf type: " << type;
}

// Attribute verification.
LogicalResult IntAttr::verify(function_ref<InFlightDiagnostic()> emitError,
                              StringRef name, uint64_t bits,
                              StringRef encoding) {
  if (encoding != "signed" && encoding != "unsigned" && encoding != "char")
    return emitError() << "encoding must be signed / unsigned / char, got \""
                       << encoding << "\"";
  if (name.empty())
    return emitError() << "an integer needs a name";
  // Only 8/16/32/64-bit integers; void uses #btf.void, not a zero-bit INT.
  if (bits != 8 && bits != 16 && bits != 32 && bits != 64)
    return emitError() << "integer width must be 8 / 16 / 32 / 64 bits, got "
                       << bits;
  return success();
}

LogicalResult ArrayOfAttr::verify(function_ref<InFlightDiagnostic()> emitError,
                                Attribute element, uint64_t count) {
  if (count == 0)
    return emitError() << "an array needs at least one element";
  return success();
}

// Operation verification.
LogicalResult ScopeOp::verify() {
  // @records/@kernel contain named types; @objects contains vars/functions.
  // Separate scopes avoid collisions with lowered LLVM symbols of the same name.
  StringRef n = getSymName();
  // @struct_ops contains local .struct_ops.link structs; loaders match their
  // members by name against target kernel types.
  if (n == "records" || n == "kernel" || n == "struct_ops") {
    for (Operation &op : getBody().front())
      if (!isa<StructOp>(op))
        return op.emitOpError() << "only btf.struct may live in btf.scope @" << n;
    return success();
  }
  if (n == "objects") {
    for (Operation &op : getBody().front())
      if (!isa<VarOp, FuncOp>(op))
        return op.emitOpError() << "only btf.var / btf.func may live in btf.scope @objects";
    return success();
  }
  return emitOpError() << "scope must be @records (userspace records), @kernel (CO-RE local "
                          "types) or @objects (variables and functions), got @"
                       << n;
}

LogicalResult StructOp::verify() {
  if (getSizeBits() <= 0 || getSizeBits() % 8 != 0)
    return emitOpError() << "size must be a positive whole number of bytes";
  if (getAlignBits() <= 0 || !llvm::isPowerOf2_64(getAlignBits()))
    return emitOpError() << "alignment must be a power of two";
  llvm::StringSet<> names;
  for (Attribute a : getMembers()) {
    auto m = cast<MemberAttr>(a);
    if (m.getName().empty() || !names.insert(m.getName()).second)
      return emitOpError() << "member names must be non-empty and unique (\""
                           << m.getName() << "\")";
    if (m.getOffsetBits() + m.getSizeBits() > (uint64_t)getSizeBits())
      return emitOpError() << "member \"" << m.getName()
                           << "\" ends past the struct";
    if (failed(verifyType(m.getType(), *this,
                          "member \"" + m.getName().str() + "\"")))
      return failure();
    if (auto sz = sizeInBits(m.getType(), *this); sz && *sz != m.getSizeBits())
      return emitOpError() << "member \"" << m.getName() << "\" says "
                           << m.getSizeBits() << " bits but its type has "
                           << *sz;
  }
  return success();
}

LogicalResult VarOp::verify() {
  if (getSection().empty())
    return emitOpError() << "a btf.var needs an ELF section";
  return verifyType(getType(), *this, "type");
}

LogicalResult FuncOp::verify() {
  if (getLinkage() != "global" && getLinkage() != "static")
    return emitOpError() << "unknown linkage \"" << getLinkage()
                         << "\" (known: \"global\", \"static\")";
  for (Attribute a : getParams()) {
    auto p = cast<ParamAttr>(a);
    // Unnamed global FUNC parameters make kernel reject BTF (Invalid arg#1);
    // libbpf may silently discard it, so reject before load.
    if (p.getName().empty())
      return emitOpError() << "function parameters must be named (a global "
                              "FUNC with an unnamed argument is rejected by "
                              "the kernel)";
    if (failed(verifyType(p.getType(), *this, "parameter")))
      return failure();
  }
  return verifyType(getResult(), *this, "result");
}
