//===- Schema.cpp - strict three-layer schema parsing and canonical JSON ----===//
//
// Unknown keys, omissions, versions, duplicates, overlaps, non-power-of-two
// constraints and unresolved references are errors. Only extensions are opaque
// and preserved without core interpretation.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Target/EBPF/Schema.h"
#include "bpf-mlir/Dialect/BPFABI/KernelABI.h"
#include "bpf-mlir/Support/ProgramKinds.h"
#include "bpf-mlir/Support/LocalStorage.h"
#include "bpf-mlir/Support/KeylessMaps.h"
#include "bpf-mlir/Support/StructOpsTypes.h"
#include "bpf-mlir/Support/RejectedMapKinds.h"

#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <functional>
#include <limits>
#include <set>

using namespace llvm;

namespace ebpf {

// Value types.
bool IntType::operator==(const IntType &o) const {
  return bits == o.bits && isSigned == o.isSigned &&
         endianness == o.endianness && alignment == o.alignment;
}

ArrayType::ArrayType(const ArrayType &o) : count(o.count) {
  if (o.element)
    element = std::make_unique<Type>(*o.element);
}
ArrayType &ArrayType::operator=(const ArrayType &o) {
  if (this != &o) {
    count = o.count;
    element = o.element ? std::make_unique<Type>(*o.element) : nullptr;
  }
  return *this;
}
bool ArrayType::operator==(const ArrayType &o) const {
  if (count != o.count)
    return false;
  if (!element || !o.element)
    return element.get() == o.element.get();
  return *element == *o.element;
}

namespace {

Error err(const Twine &msg) {
  return createStringError(inconvertibleErrorCode(), msg);
}

bool isPowerOfTwo(uint64_t v) { return v != 0 && (v & (v - 1)) == 0; }

// Per-object allowed keys from SchemaKeys.inc, checked against schema_format.md.
#define SCHEMA_OBJECT(id, path, ...) const StringRef kKeys##id[] = {__VA_ARGS__};
#include "SchemaKeys.inc"
#undef SCHEMA_OBJECT

Error requireOnlyKeys(const json::Object &obj, ArrayRef<StringRef> allowed,
                      StringRef where) {
  for (const auto &kv : obj) {
    StringRef k = kv.first;
    if (!llvm::is_contained(allowed, k)) {
      std::string known;
      raw_string_ostream os(known);
      llvm::interleaveComma(allowed, os);
      return err(where + ": unknown key \"" + k + "\" (known: " + known + ")");
    }
  }
  return Error::success();
}

Expected<StringRef> getStr(const json::Object &o, StringRef key,
                           StringRef where) {
  if (auto v = o.getString(key))
    return *v;
  return err(where + ": missing or non-string \"" + key + "\"");
}

// Optional strings default to empty only when absent; present non-strings fail.
Error optStrInto(const json::Object &o, StringRef key, StringRef where, std::string &dst) {
  const json::Value *v = o.get(key);
  if (!v) {
    dst.clear();
    return Error::success();
  }
  if (auto str = v->getAsString()) {
    dst = str->str();
    return Error::success();
  }
  return err(where + ": \"" + key + "\" must be a string");
}

// Present optional keys must have the expected value type.
Error requirePresentKind(const json::Object &o, StringRef key, StringRef where, json::Value::Kind kind, StringRef what) {
  const json::Value *v = o.get(key);
  if (!v || v->kind() == kind)
    return Error::success();
  // llvm::json classifies integers as Number; callers use getInteger for integrality.
  return err(where + ": \"" + key + "\" must be " + what);
}

// Validate uint32 before truncation; otherwise 2^32+64 could be accepted as 64.
Error requireU32(uint64_t v, StringRef key, StringRef where) {
  if (v > UINT32_MAX)
    return err(where + ": \"" + key + "\" is out of range (" + Twine(v) + " > 4294967295)");
  return Error::success();
}

Expected<uint64_t> getU64(const json::Object &o, StringRef key,
                          StringRef where) {
  auto v = o.getInteger(key);
  if (!v)
    return err(where + ": missing or non-integer \"" + key + "\"");
  if (*v < 0)
    return err(where + ": \"" + key + "\" must not be negative");
  return static_cast<uint64_t>(*v);
}

Expected<bool> getBool(const json::Object &o, StringRef key, StringRef where) {
  if (auto v = o.getBoolean(key))
    return *v;
  return err(where + ": missing or non-boolean \"" + key + "\"");
}

Expected<const json::Array *> getArr(const json::Object &o, StringRef key,
                                     StringRef where) {
  if (const auto *v = o.getArray(key))
    return v;
  return err(where + ": missing or non-array \"" + key + "\"");
}

Expected<const json::Object *> getObj(const json::Object &o, StringRef key,
                                      StringRef where) {
  if (const auto *v = o.getObject(key))
    return v;
  return err(where + ": missing or non-object \"" + key + "\"");
}

// Types.
Expected<Type> parseType(const json::Value &v, StringRef where);

Expected<IntType> parseIntBody(const json::Object &o, StringRef where) {
  IntType t;
  auto bits = getU64(o, "bits", where);
  if (!bits)
    return bits.takeError();
  if (Error e = requireU32(*bits, "bits", where))
    return std::move(e);
  t.bits = static_cast<uint32_t>(*bits);
  if (t.bits != 8 && t.bits != 16 && t.bits != 32 && t.bits != 64)
    return err(where + ": bits must be 8, 16, 32 or 64, got " + Twine(t.bits));

  auto sign = getBool(o, "signed", where);
  if (!sign)
    return sign.takeError();
  t.isSigned = *sign;

  auto endian = getStr(o, "endianness", where);
  if (!endian)
    return endian.takeError();
  if (*endian == "little")
    t.endianness = Endianness::Little;
  else if (*endian == "big")
    t.endianness = Endianness::Big;
  else
    return err(where + ": endianness must be \"little\" or \"big\", got \"" +
               *endian + "\"");

  auto align = getU64(o, "alignment", where);
  if (!align)
    return align.takeError();
  if (Error e = requireU32(*align, "alignment", where))
    return std::move(e);
  t.alignment = static_cast<uint32_t>(*align);
  if (!isPowerOfTwo(t.alignment))
    return err(where + ": alignment must be a power of two, got " +
               Twine(t.alignment));
  if (t.alignment > t.bits / 8)
    return err(where + ": alignment " + Twine(t.alignment) +
               " exceeds the width of a " + Twine(t.bits) + "-bit integer");
  return t;
}

Expected<Type> parseType(const json::Value &v, StringRef where) {
  const auto *o = v.getAsObject();
  if (!o)
    return err(where + ": type must be an object");
  auto kind = getStr(*o, "kind", where);
  if (!kind)
    return kind.takeError();

  Type t;
  if (*kind == "int") {
    if (Error e = requireOnlyKeys(*o, kKeysTypeInt, where))
      return std::move(e);
    auto it = parseIntBody(*o, where);
    if (!it)
      return it.takeError();
    t.v = *it;
    return t;
  }
  if (*kind == "array") {
    if (Error e = requireOnlyKeys(*o, kKeysTypeArray, where))
      return std::move(e);
    auto count = getU64(*o, "count", where);
    if (!count)
      return count.takeError();
    if (*count == 0)
      return err(where + ": array count must be positive");
    const json::Value *ev = o->get("element");
    if (!ev)
      return err(where + ": array is missing \"element\"");
    auto elem = parseType(*ev, (where + " element").str());
    if (!elem)
      return elem.takeError();
    if (std::holds_alternative<SpinLockType>(elem->v))
      return err(where + ": a spin_lock cannot be an array element (a record has at most one lock, as a direct field)");
    if (std::holds_alternative<TimerType>(elem->v))
      return err(where + ": a timer cannot be an array element (a record has at most one timer, as a direct field)");
    if (std::holds_alternative<KptrType>(elem->v))
      return err(where + ": a kptr cannot be an array element (a compiler restriction — only a direct record field)");
    ArrayType at;
    at.count = *count;
    at.element = std::make_unique<Type>(std::move(*elem));
    t.v = std::move(at);
    return t;
  }
  // Map-value lock field. Record/map validation restricts it to direct record members.
  if (*kind == "spin_lock") {
    if (Error e = requireOnlyKeys(*o, kKeysTypeSpinLock, where))
      return std::move(e);
    t.v = SpinLockType{};
    return t;
  }
  // Build-ID stack element; record/map validation confines it to stack_trace value arrays.
  if (*kind == "stack_build_id") {
    if (Error e = requireOnlyKeys(*o, kKeysTypeStackBuildId, where))
      return std::move(e);
    t.v = StackBuildIdType{};
    return t;
  }
  // Map-value timer field; record/map placement restrictions match locks.
  if (*kind == "timer") {
    if (Error e = requireOnlyKeys(*o, kKeysTypeTimer, where))
      return std::move(e);
    t.v = TimerType{};
    return t;
  }
  // Referenced map-value kptr names core.kernel_types; record/map checks own placement and resolution.
  if (*kind == "kptr") {
    if (Error e = requireOnlyKeys(*o, kKeysTypeKptr, where))
      return std::move(e);
    auto st = getStr(*o, "struct", where);
    if (!st)
      return st.takeError();
    if (st->empty())
      return err(where + ": a kptr type needs a non-empty \"struct\"");
    t.v = KptrType{st->str()};
    return t;
  }
  if (*kind == "record_ref") {
    if (Error e = requireOnlyKeys(*o, kKeysTypeRecordRef, where))
      return std::move(e);
    auto sym = getStr(*o, "symbol", where);
    if (!sym)
      return sym.takeError();
    t.v = RecordRefType{sym->str()};
    return t;
  }
  return err(where + ": type kind must be \"int\", \"array\", "
                     "\"record_ref\", \"spin_lock\" or \"timer\", got \"" +
             *kind + "\"");
}

// Telemetry AST.
const StringRef kPredOps[] = {"always", "never",   "empty", "nonempty",
                              "zero",   "nonzero", "byte_eq", "any",
                              "all",    "not",     "unexpressible"};

Expected<Operand> parseOperand(const json::Object &o, StringRef where) {
  if (Error e = requireOnlyKeys(o, kKeysPredOperand, where))
    return std::move(e);
  auto kind = getStr(o, "kind", where);
  if (!kind)
    return kind.takeError();
  if (*kind != "field" && *kind != "derived" && *kind != "constant")
    return err(where + ": operand kind must be \"field\", \"derived\" or "
                       "\"constant\", got \"" +
               *kind + "\"");
  auto name = getStr(o, "name", where);
  if (!name)
    return name.takeError();
  return Operand{kind->str(), name->str()};
}

Expected<Predicate> parsePredicate(const json::Value &v, StringRef where) {
  const auto *o = v.getAsObject();
  if (!o)
    return err(where + ": predicate must be an object");
  if (Error e = requireOnlyKeys(*o, kKeysPredicate, where))
    return std::move(e);
  Predicate p;
  auto op = getStr(*o, "op", where);
  if (!op)
    return op.takeError();
  p.op = op->str();
  if (!llvm::is_contained(kPredOps, p.op)) {
    std::string known;
    raw_string_ostream os(known);
    llvm::interleaveComma(kPredOps, os);
    return err(where + ": unknown predicate op \"" + p.op + "\" (known: " +
               known + ")");
  }

  if (Error e = requirePresentKind(*o, "operand", where, json::Value::Object, "an object"))
    return std::move(e);
  if (Error e = requirePresentKind(*o, "bytes", where, json::Value::Array, "an array"))
    return std::move(e);
  if (Error e = requirePresentKind(*o, "args", where, json::Value::Array, "an array"))
    return std::move(e);
  if (const json::Value *iv = o->get("index"); iv && !iv->getAsInteger())
    return err(where + ": \"index\" must be an integer");
  if (const auto *oo = o->getObject("operand")) {
    auto operand = parseOperand(*oo, (where + " operand").str());
    if (!operand)
      return operand.takeError();
    p.operand = *operand;
  }
  if (auto idx = o->getInteger("index")) {
    if (*idx < 0)
      return err(where + ": byte index must not be negative");
    p.index = static_cast<uint64_t>(*idx);
  }
  if (Error e = optStrInto(*o, "detail", "predicate", p.detail))
    return std::move(e);
  if (const auto *ba = o->getArray("bytes")) {
    for (const json::Value &bv : *ba) {
      auto b = bv.getAsInteger();
      if (!b || *b < 0 || *b > 255)
        return err(where + ": bytes entries must be 0..255");
      p.bytes.push_back(static_cast<uint8_t>(*b));
    }
  }
  if (const auto *aa = o->getArray("args")) {
    for (const json::Value &av : *aa) {
      auto sub = parsePredicate(av, (where + " arg").str());
      if (!sub)
        return sub.takeError();
      p.args.push_back(std::move(*sub));
    }
  }

  // Each operation has a fixed set of required and forbidden shape fields.
  bool needsOperand = p.op == "empty" || p.op == "nonempty" || p.op == "zero" ||
                      p.op == "nonzero" || p.op == "byte_eq";
  bool needsArgs = p.op == "any" || p.op == "all" || p.op == "not";
  if (needsOperand && !p.operand)
    return err(where + ": predicate \"" + p.op + "\" needs an operand");
  if (!needsOperand && p.operand)
    return err(where + ": predicate \"" + p.op + "\" takes no operand");
  if (needsArgs && p.args.empty())
    return err(where + ": predicate \"" + p.op + "\" needs args");
  if (!needsArgs && !p.args.empty())
    return err(where + ": predicate \"" + p.op + "\" takes no args");
  if (p.op == "not" && p.args.size() != 1)
    return err(where + ": predicate \"not\" takes exactly one arg");
  if (p.op == "byte_eq" && p.bytes.empty())
    return err(where + ": predicate \"byte_eq\" needs bytes");
  if (p.op != "byte_eq" && !p.bytes.empty())
    return err(where + ": predicate \"" + p.op + "\" takes no bytes");
  if (p.op != "byte_eq" && p.index != 0)
    return err(where + ": predicate \"" + p.op + "\" takes no byte index");
  // Require detail rather than silently dropping unrepresentable content.
  if (p.op == "unexpressible" && p.detail.empty())
    return err(where + ": predicate \"unexpressible\" must carry \"detail\" "
                       "(the condition that could not be expressed)");
  if (p.op != "unexpressible" && !p.detail.empty())
    return err(where + ": only \"unexpressible\" takes \"detail\"");
  return p;
}

Expected<Source> parseSource(const json::Object &o, StringRef where) {
  if (Error e = requireOnlyKeys(o, kKeysSource, where))
    return std::move(e);
  Source s;
  auto kind = getStr(o, "kind", where);
  if (!kind)
    return kind.takeError();
  s.kind = kind->str();
  if (s.kind != "field" && s.kind != "derived" && s.kind != "constant" &&
      s.kind != "runtime_extension")
    return err(where + ": source kind must be \"field\", \"derived\", "
                       "\"constant\" or \"runtime_extension\", got \"" +
               s.kind + "\"");
  auto name = getStr(o, "name", where);
  if (!name)
    return name.takeError();
  s.name = name->str();
  if (Error e = optStrInto(o, "from", "source", s.from))
    return std::move(e);
  if (Error e = optStrInto(o, "detail", "source", s.detail))
    return std::move(e);
  // Unrepresentable content must include detail, never disappear silently.
  if (s.kind == "runtime_extension" && s.detail.empty())
    return err(where + ": a runtime_extension source must carry \"detail\" "
                       "(what could not be expressed)");
  return s;
}

// Telemetry body/value/attribute field sources must resolve through
// core.records. Dotted paths such as hdr.timestamp follow record_ref members.
const Record *findRecordBySymbol(const std::vector<Record> &recs,
                                 StringRef sym) {
  for (const Record &r : recs)
    if (r.symbol == sym)
      return &r;
  return nullptr;
}

bool hasFieldPath(const std::vector<Record> &recs, const Record &r,
                  StringRef path) {
  auto [head, rest] = path.split('.');
  for (const Field &f : r.fields) {
    if (f.name != head)
      continue;
    if (rest.empty())
      return true;
    if (const auto *rr = std::get_if<RecordRefType>(&f.type.v)) {
      const Record *inner = findRecordBySymbol(recs, rr->symbol);
      return inner && hasFieldPath(recs, *inner, rest);
    }
    return false;
  }
  return false;
}

// Canonical JSON helpers.
void emitStr(raw_ostream &os, StringRef s) { os << json::Value(s); }

void indent(raw_ostream &os, unsigned n) { os.indent(n); }

// Canonicalize opaque extension payloads by sorting object keys. Core does
// not interpret their contents, and key order is not preserved state.
void emitCanonical(raw_ostream &os, const json::Value &v, unsigned ind) {
  switch (v.kind()) {
  case json::Value::Null:
    os << "null";
    return;
  case json::Value::Boolean:
    os << (*v.getAsBoolean() ? "true" : "false");
    return;
  case json::Value::Number: {
    if (auto i = v.getAsInteger())
      os << *i;
    else
      os << *v.getAsNumber();
    return;
  }
  case json::Value::String:
    emitStr(os, *v.getAsString());
    return;
  case json::Value::Array: {
    const auto *a = v.getAsArray();
    if (a->empty()) {
      os << "[]";
      return;
    }
    os << "[\n";
    for (size_t i = 0; i < a->size(); ++i) {
      indent(os, ind + 2);
      emitCanonical(os, (*a)[i], ind + 2);
      os << (i + 1 < a->size() ? "," : "") << "\n";
    }
    indent(os, ind);
    os << "]";
    return;
  }
  case json::Value::Object: {
    const auto *o = v.getAsObject();
    std::vector<StringRef> keys;
    for (const auto &kv : *o)
      keys.push_back(kv.first);
    llvm::sort(keys);
    if (keys.empty()) {
      os << "{}";
      return;
    }
    os << "{\n";
    for (size_t i = 0; i < keys.size(); ++i) {
      indent(os, ind + 2);
      emitStr(os, keys[i]);
      os << ": ";
      emitCanonical(os, *o->get(keys[i]), ind + 2);
      os << (i + 1 < keys.size() ? "," : "") << "\n";
    }
    indent(os, ind);
    os << "}";
    return;
  }
  }
}

const char *endianName(Endianness e) {
  return e == Endianness::Little ? "little" : "big";
}

void emitType(raw_ostream &os, const Type &t, unsigned ind);

void emitTypeBody(raw_ostream &os, const IntType &t, unsigned ind) {
  os << "{\n";
  indent(os, ind + 2); os << "\"kind\": \"int\",\n";
  indent(os, ind + 2); os << "\"alignment\": " << t.alignment << ",\n";
  indent(os, ind + 2); os << "\"bits\": " << t.bits << ",\n";
  indent(os, ind + 2); os << "\"endianness\": \"" << endianName(t.endianness) << "\",\n";
  indent(os, ind + 2); os << "\"signed\": " << (t.isSigned ? "true" : "false") << "\n";
  indent(os, ind); os << "}";
}

void emitTypeBody(raw_ostream &os, const ArrayType &t, unsigned ind) {
  os << "{\n";
  indent(os, ind + 2); os << "\"kind\": \"array\",\n";
  indent(os, ind + 2); os << "\"count\": " << t.count << ",\n";
  indent(os, ind + 2); os << "\"element\": ";
  emitType(os, *t.element, ind + 2);
  os << "\n";
  indent(os, ind); os << "}";
}

void emitTypeBody(raw_ostream &os, const RecordRefType &t, unsigned ind) {
  os << "{\n";
  indent(os, ind + 2); os << "\"kind\": \"record_ref\",\n";
  indent(os, ind + 2); os << "\"symbol\": "; emitStr(os, t.symbol); os << "\n";
  indent(os, ind); os << "}";
}

void emitTypeBody(raw_ostream &os, const SpinLockType &, unsigned ind) {
  os << "{\n";
  indent(os, ind + 2); os << "\"kind\": \"spin_lock\"\n";
  indent(os, ind); os << "}";
}

void emitTypeBody(raw_ostream &os, const TimerType &, unsigned ind) {
  os << "{\n";
  indent(os, ind + 2); os << "\"kind\": \"timer\"\n";
  indent(os, ind); os << "}";
}

void emitTypeBody(raw_ostream &os, const KptrType &t, unsigned ind) {
  os << "{\n";
  indent(os, ind + 2); os << "\"kind\": \"kptr\",\n";
  indent(os, ind + 2); os << "\"struct\": "; emitStr(os, t.structName); os << "\n";
  indent(os, ind); os << "}";
}

void emitTypeBody(raw_ostream &os, const StackBuildIdType &, unsigned ind) {
  os << "{\n";
  indent(os, ind + 2); os << "\"kind\": \"stack_build_id\"\n";
  indent(os, ind); os << "}";
}

void emitType(raw_ostream &os, const Type &t, unsigned ind) {
  std::visit([&](const auto &x) { emitTypeBody(os, x, ind); }, t.v);
}

void emitOperand(raw_ostream &os, const Operand &o, unsigned ind) {
  os << "{\n";
  indent(os, ind + 2); os << "\"kind\": "; emitStr(os, o.kind); os << ",\n";
  indent(os, ind + 2); os << "\"name\": "; emitStr(os, o.name); os << "\n";
  indent(os, ind); os << "}";
}

void emitPredicate(raw_ostream &os, const Predicate &p, unsigned ind) {
  os << "{\n";
  indent(os, ind + 2); os << "\"op\": "; emitStr(os, p.op);
  if (p.operand) {
    os << ",\n";
    indent(os, ind + 2); os << "\"operand\": ";
    emitOperand(os, *p.operand, ind + 2);
  }
  if (!p.detail.empty()) {
    os << ",\n";
    indent(os, ind + 2); os << "\"detail\": "; emitStr(os, p.detail);
  }
  if (!p.bytes.empty()) {
    os << ",\n";
    indent(os, ind + 2); os << "\"index\": " << p.index << ",\n";
    indent(os, ind + 2); os << "\"bytes\": [";
    for (auto [i, b] : llvm::enumerate(p.bytes))
      os << (i ? ", " : "") << unsigned(b);
    os << "]";
  }
  if (!p.args.empty()) {
    os << ",\n";
    indent(os, ind + 2); os << "\"args\": [\n";
    for (auto [i, a] : llvm::enumerate(p.args)) {
      indent(os, ind + 4);
      emitPredicate(os, a, ind + 4);
      os << (i + 1 < p.args.size() ? "," : "") << "\n";
    }
    indent(os, ind + 2); os << "]";
  }
  os << "\n";
  indent(os, ind); os << "}";
}

void emitSource(raw_ostream &os, const Source &s, unsigned ind) {
  os << "{\n";
  indent(os, ind + 2); os << "\"kind\": "; emitStr(os, s.kind); os << ",\n";
  indent(os, ind + 2); os << "\"name\": "; emitStr(os, s.name); os << ",\n";
  indent(os, ind + 2); os << "\"from\": "; emitStr(os, s.from); os << ",\n";
  indent(os, ind + 2); os << "\"detail\": "; emitStr(os, s.detail); os << "\n";
  indent(os, ind); os << "}";
}

} // namespace

// Shared spelling source outside the anonymous namespace for verify-schema.
const char *mapKindName(MapKind k) { return mapKindSpelling(k); } // Canonical MapKinds.def NAME spellings.

// Byte sizes.
static Expected<uint64_t> sizeOfImpl(const Schema &s, const Type &t,
                                     std::set<std::string> &visiting);

static Expected<uint64_t> recordSize(const Schema &s, StringRef symbol,
                                     std::set<std::string> &visiting) {
  if (!visiting.insert(symbol.str()).second)
    return err("record \"" + symbol + "\" is cyclic");
  for (const Record &r : s.records())
    if (r.symbol == symbol) {
      visiting.erase(symbol.str());
      return r.size;
    }
  visiting.erase(symbol.str());
  return err("record_ref \"" + symbol + "\" is not declared in the schema");
}

static Expected<uint64_t> sizeOfImpl(const Schema &s, const Type &t,
                                     std::set<std::string> &visiting) {
  if (const auto *i = std::get_if<IntType>(&t.v))
    return i->bits / 8;
  if (const auto *a = std::get_if<ArrayType>(&t.v)) {
    auto e = sizeOfImpl(s, *a->element, visiting);
    if (!e)
      return e.takeError();
    return *e * a->count;
  }
  // bpf_spin_lock size comes from ABI, never a duplicated literal.
  if (std::holds_alternative<SpinLockType>(t.v)) {
    std::optional<int64_t> sz = mlir::bpfabi::lookupUapiStructSize("bpf_spin_lock");
    if (!sz)
      return err("struct bpf_spin_lock is not in the UAPI table");
    return static_cast<uint64_t>(*sz);
  }
  // bpf_timer size also comes from ABI.
  if (std::holds_alternative<TimerType>(t.v)) {
    std::optional<int64_t> sz = mlir::bpfabi::lookupUapiStructSize("bpf_timer");
    if (!sz)
      return err("struct bpf_timer is not in the UAPI table");
    return static_cast<uint64_t>(*sz);
  }
  // bpf_stack_build_id size also comes from ABI.
  if (std::holds_alternative<StackBuildIdType>(t.v)) {
    std::optional<int64_t> sz = mlir::bpfabi::lookupUapiStructSize("bpf_stack_build_id");
    if (!sz)
      return err("struct bpf_stack_build_id is not in the UAPI table");
    return static_cast<uint64_t>(*sz);
  }
  // kptr is a 64-bit pointer.
  if (std::holds_alternative<KptrType>(t.v))
    return uint64_t(8);
  const auto &r = std::get<RecordRefType>(t.v);
  return recordSize(s, r.symbol, visiting);
}

Expected<uint64_t> Schema::sizeOf(const Type &t) const {
  std::set<std::string> visiting;
  return sizeOfImpl(*this, t, visiting);
}

bool Schema::operator==(const Schema &o) const {
  if (!(coverage_ == o.coverage_ &&
        programs_ == o.programs_ && maps_ == o.maps_ && records_ == o.records_ &&
        kernelTypes_ == o.kernelTypes_ && globals_ == o.globals_ &&
        signals_ == o.signals_ && clocks_ == o.clocks_ &&
        valueMaps_ == o.valueMaps_ && boundsSets_ == o.boundsSets_))
    return false;
  if (extensions_.size() != o.extensions_.size())
    return false;
  for (const auto &kv : extensions_) {
    auto it = o.extensions_.find(kv.first);
    if (it == o.extensions_.end() || it->second != kv.second)
      return false;
  }
  return true;
}

// Parsing.
// Reject duplicate keys before llvm::json::parse, which retains the last value.
// Track object/array delimiters outside strings and compare decoded keys.
// Leave syntax errors to the JSON parser.
static Error checkDuplicateKeys(StringRef text) {
  struct Frame {
    bool object;
    StringSet<> keys;
    bool expectKey;
  };
  SmallVector<Frame, 16> stack;
  for (size_t i = 0; i < text.size(); ++i) {
    char c = text[i];
    if (c == '"') {
      size_t j = i + 1;
      while (j < text.size() && text[j] != '"')
        j += (text[j] == '\\') ? 2 : 1;
      if (j >= text.size())
        return Error::success(); // The JSON parser reports unterminated strings.
      if (!stack.empty() && stack.back().object && stack.back().expectKey) {
        auto key = json::parse(text.slice(i, j + 1));
        if (!key) {
          consumeError(key.takeError());
          return Error::success();
        }
        std::string k = key->getAsString() ? key->getAsString()->str() : std::string();
        if (!stack.back().keys.insert(k).second)
          return err("schema: duplicate key \"" + k + "\" in one JSON object (the JSON parser would keep only the last value)");
        stack.back().expectKey = false;
      }
      i = j;
      continue;
    }
    if (c == '{')
      stack.push_back({true, {}, true});
    else if (c == '[')
      stack.push_back({false, {}, false});
    else if ((c == '}' || c == ']') && !stack.empty())
      stack.pop_back();
    else if (c == ',' && !stack.empty() && stack.back().object)
      stack.back().expectKey = true;
  }
  return Error::success();
}

Expected<Schema> Schema::parseJSON(StringRef jsonText) {
  if (Error e = checkDuplicateKeys(jsonText))
    return std::move(e);
  auto parsed = json::parse(jsonText);
  if (!parsed)
    return parsed.takeError();
  const auto *root = parsed->getAsObject();
  if (!root)
    return err("schema: root must be an object");

  // Unknown top-level keys fail; only extensions permits opaque additions.
  if (Error e = requireOnlyKeys(*root, kKeysRoot,
          "schema"))
    return std::move(e);

  auto version = getU64(*root, "version", "schema");
  if (!version)
    return version.takeError();
  if (*version != kSchemaVersion)
    return err("schema: version must be " + Twine(kSchemaVersion) + ", got " +
               Twine(*version));

  Schema s;

  // Coverage is required, without implicit defaults.
  {
    auto covObj = getObj(*root, "coverage", "schema");
    if (!covObj)
      return err("schema: \"coverage\" is required — it says what this schema "
                 "makes canonical. Omitting it would let a missing declaration "
                 "silently disable checking.");
    if (Error e = requireOnlyKeys(**covObj, kKeysCoverage, "coverage"))
      return std::move(e);
    auto one = [&](StringRef key, Coverage &out) -> Error {
      auto v = getStr(**covObj, key, "coverage");
      if (!v)
        return v.takeError();
      if (*v == "complete")
        out = Coverage::Complete;
      else if (*v == "omitted")
        out = Coverage::Omitted;
      else
        return err("coverage." + key +
                   " must be \"complete\" or \"omitted\", got \"" + *v +
                   "\" (there is no \"partial\": its scope would be ambiguous)");
      return Error::success();
    };
    if (Error e = one("programs", s.coverage_.programs))
      return std::move(e);
    if (Error e = one("maps", s.coverage_.maps))
      return std::move(e);
    if (Error e = one("records", s.coverage_.records))
      return std::move(e);
    if (Error e = one("telemetry", s.coverage_.telemetry))
      return std::move(e);
  }

  //===------------------------------------------------------------------===//
  // core
  //===------------------------------------------------------------------===//
  auto coreObj = getObj(*root, "core", "schema");
  if (!coreObj)
    return coreObj.takeError();
  if (Error e =
          requireOnlyKeys(**coreObj, kKeysCore,
                          "core"))
    return std::move(e);

  // ---- records ----
  auto recArr = getArr(**coreObj, "records", "core");
  if (!recArr)
    return recArr.takeError();
  StringSet<> recSymbols;
  DenseSet<uint32_t> recIds;
  for (const json::Value &v : **recArr) {
    const auto *o = v.getAsObject();
    if (!o)
      return err("core.records: entry must be an object");
    if (Error e = requireOnlyKeys(*o, kKeysRecord,
                                  "core.records"))
      return std::move(e);
    Record r;
    auto sym = getStr(*o, "symbol", "core.records");
    if (!sym)
      return sym.takeError();
    r.symbol = sym->str();
    if (!recSymbols.insert(r.symbol).second)
      return err("core.records: duplicate record symbol \"" + r.symbol + "\"");
    std::string where = "record \"" + r.symbol + "\"";

    auto id = getU64(*o, "id", where);
    if (!id)
      return id.takeError();
    if (Error e = requireU32(*id, "id", where))
      return std::move(e);
    r.id = static_cast<uint32_t>(*id);
    if (r.id != 0 && !recIds.insert(r.id).second)
      return err(where + ": duplicate record id " + Twine(r.id));

    auto size = getU64(*o, "size", where);
    if (!size)
      return size.takeError();
    r.size = *size;
    auto minSize = getU64(*o, "min_size", where);
    if (!minSize)
      return minSize.takeError();
    r.minSize = *minSize;
    if (r.minSize > r.size)
      return err(where + ": min_size " + Twine(r.minSize) +
                 " exceeds size " + Twine(r.size));

    auto align = getU64(*o, "alignment", where);
    if (!align)
      return align.takeError();
    if (Error e = requireU32(*align, "alignment", where))
      return std::move(e);
    r.alignment = static_cast<uint32_t>(*align);
    if (!isPowerOfTwo(r.alignment))
      return err(where + ": alignment must be a power of two, got " +
                 Twine(r.alignment));
    if (r.size % r.alignment != 0)
      return err(where + ": size " + Twine(r.size) +
                 " is not a multiple of alignment " + Twine(r.alignment));

    auto reqThrough = getStr(*o, "required_through", where);
    if (!reqThrough)
      return reqThrough.takeError();
    r.requiredThrough = reqThrough->str();
    if (Error e = optStrInto(*o, "note", "core.records", r.note))
      return std::move(e);

    auto fieldsArr = getArr(*o, "fields", where);
    if (!fieldsArr)
      return fieldsArr.takeError();
    StringSet<> fieldNames;
    for (const json::Value &fv : **fieldsArr) {
      const auto *fo = fv.getAsObject();
      if (!fo)
        return err(where + ": field must be an object");
      if (Error e = requireOnlyKeys(*fo, kKeysRecordField,
              where + " field"))
        return std::move(e);
      Field f;
      auto fname = getStr(*fo, "name", where + " field");
      if (!fname)
        return fname.takeError();
      f.name = fname->str();
      if (!fieldNames.insert(f.name).second)
        return err(where + ": duplicate field name \"" + f.name + "\"");
      std::string fwhere = where + " field \"" + f.name + "\"";

      const json::Value *tv = fo->get("type");
      if (!tv)
        return err(fwhere + ": missing \"type\"");
      auto ft = parseType(*tv, fwhere);
      if (!ft)
        return ft.takeError();
      f.type = std::move(*ft);

      auto off = getU64(*fo, "offset", fwhere);
      if (!off)
        return off.takeError();
      f.offset = *off;
      if (Error e = optStrInto(*fo, "expose", "core.records field", f.expose))
        return std::move(e);
      if (Error e = optStrInto(*fo, "note", "core.records field", f.note))
        return std::move(e);
      r.fields.push_back(std::move(f));
    }
    if (!r.requiredThrough.empty() && !fieldNames.contains(r.requiredThrough))
      return err(where + ": required_through \"" + r.requiredThrough +
                 "\" is not a field of this record");
    // At most one lock, four-byte aligned. Reserve bpf_spin_lock for its BTF type.
    if (r.symbol == "bpf_spin_lock")
      return err(where + ": the record name \"bpf_spin_lock\" is reserved (the BTF type of a spin_lock field)");
    if (r.symbol == kUsdtSpecRecord) // Compiler-generated USDT spec record.
      return err(where + ": the record name \"" + kUsdtSpecRecord + "\" is reserved (the value of the compiler's USDT spec map)");
    unsigned locks = 0;
    for (const Field &f : r.fields)
      if (std::holds_alternative<SpinLockType>(f.type.v)) {
        ++locks;
        if (f.offset % 4 != 0)
          return err(where + ": spin_lock field \"" + f.name + "\" must be at an offset that is a multiple of 4");
      }
    if (locks > 1)
      return err(where + ": a record has at most one spin_lock field (the kernel allows one lock per map value)");
    // At most one timer, eight-byte aligned per UAPI. Coexistence with a lock is
  // unsupported. Reserve bpf_timer for its BTF type.
    if (r.symbol == "bpf_timer")
      return err(where + ": the record name \"bpf_timer\" is reserved (the BTF type of a timer field)");
    unsigned timers = 0;
    for (const Field &f : r.fields)
      if (std::holds_alternative<TimerType>(f.type.v)) {
        ++timers;
        if (f.offset % mlir::bpfabi::kTimerAlignment != 0)
          return err(where + ": timer field \"" + f.name + "\" must be at an offset that is a multiple of " +
                     std::to_string(mlir::bpfabi::kTimerAlignment));
      }
    if (timers > 1)
      return err(where + ": a record has at most one timer field (the kernel allows one timer per map value)");
    if (timers && locks)
      return err(where + ": a record with both a timer and a spin_lock field is not supported");
    // Build-ID entries belong only in stack_trace value arrays, never record fields.
    {
      std::function<bool(const Type &)> hasBid = [&](const Type &t) -> bool {
        if (std::holds_alternative<StackBuildIdType>(t.v))
          return true;
        if (const auto *a = std::get_if<ArrayType>(&t.v))
          return hasBid(*a->element);
        return false;
      };
      for (const Field &f : r.fields)
        if (hasBid(f.type))
          return err(where + ": field \"" + f.name + "\": a stack_build_id is only the element of a stack_trace map value");
    }
    s.records_.push_back(std::move(r));
  }

  // Lock-bearing records can only be array-map values, not record_ref fields or arrays thereof.
  std::set<std::string> lockRecords;
  for (const Record &r : s.records_)
    for (const Field &f : r.fields)
      if (std::holds_alternative<SpinLockType>(f.type.v))
        lockRecords.insert(r.symbol);
  // Timer-bearing records share the same array-map-only placement restriction.
  std::set<std::string> timerRecords;
  for (const Record &r : s.records_)
    for (const Field &f : r.fields)
      if (std::holds_alternative<TimerType>(f.type.v))
        timerRecords.insert(r.symbol);
  {
    std::function<bool(const Type &)> refsLock = [&](const Type &t) -> bool {
      if (const auto *a = std::get_if<ArrayType>(&t.v))
        return refsLock(*a->element);
      if (const auto *rr = std::get_if<RecordRefType>(&t.v))
        return lockRecords.count(rr->symbol) != 0;
      return false;
    };
    for (const Record &r : s.records_)
      for (const Field &f : r.fields)
        if (refsLock(f.type))
          return err("record \"" + r.symbol + "\" field \"" + f.name +
                     "\": a record with a spin_lock field cannot be nested in another record (it is only an array map value)");
    std::function<bool(const Type &)> refsTimer = [&](const Type &t) -> bool {
      if (const auto *a = std::get_if<ArrayType>(&t.v))
        return refsTimer(*a->element);
      if (const auto *rr = std::get_if<RecordRefType>(&t.v))
        return timerRecords.count(rr->symbol) != 0;
      return false;
    };
    for (const Record &r : s.records_)
      for (const Field &f : r.fields)
        if (refsTimer(f.type))
          return err("record \"" + r.symbol + "\" field \"" + f.name +
                     "\": a record with a timer field cannot be nested in another record (it is only an array map value)");
  }
  // Referenced kptrs may reach map values through record_ref chains. Compute
  // containment closure to a fixed point so key/payload checks include parents.
  std::set<std::string> kptrRecords;
  for (const Record &r : s.records_)
    for (const Field &f : r.fields)
      if (std::holds_alternative<KptrType>(f.type.v)) {
        if (f.offset % 8 != 0)
          return err("record \"" + r.symbol + "\" field \"" + f.name + "\": a kptr field must be at an offset that is a multiple of 8");
        kptrRecords.insert(r.symbol);
      }
  bool addedKptr;
  do {
    addedKptr = false;
    for (const Record &r : s.records_)
      for (const Field &f : r.fields)
        if (const auto *rr = std::get_if<RecordRefType>(&f.type.v);
            rr && kptrRecords.count(rr->symbol))
          addedKptr |= kptrRecords.insert(r.symbol).second;
  } while (addedKptr);
  std::function<bool(const Type &)> refsKptr = [&](const Type &t) -> bool {
    if (const auto *a = std::get_if<ArrayType>(&t.v))
      return refsKptr(*a->element);
    if (const auto *rr = std::get_if<RecordRefType>(&t.v))
      return kptrRecords.count(rr->symbol) != 0;
    return std::holds_alternative<KptrType>(t.v);
  };
  for (const Record &r : s.records_)
    for (const Field &f : r.fields) {
      if (const auto *a = std::get_if<ArrayType>(&f.type.v); a && refsKptr(*a->element))
        return err("record \"" + r.symbol + "\" field \"" + f.name +
                   "\": a record with a kptr field cannot be an array element");
      if (const auto *rr = std::get_if<RecordRefType>(&f.type.v);
          rr && kptrRecords.count(rr->symbol) && f.offset % 8)
        return err("record \"" + r.symbol + "\" field \"" + f.name +
                   "\": a nested record with a kptr field must be at an offset that is a multiple of 8");
    }

  // Reject record_ref cycles first: sizeOf returns declared sizes and would
  // otherwise allow impossible self-containing structs.
  {
    llvm::StringMap<std::vector<std::string>> refs;
    std::function<void(const Type &, std::vector<std::string> &)> collect =
        [&](const Type &t, std::vector<std::string> &out) {
          if (const auto *a = std::get_if<ArrayType>(&t.v))
            collect(*a->element, out);
          else if (const auto *r = std::get_if<RecordRefType>(&t.v))
            out.push_back(r->symbol);
        };
    for (const Record &r : s.records_) {
      auto &out = refs[r.symbol];
      for (const Field &f : r.fields)
        collect(f.type, out);
    }
    std::set<std::string> onStack, done;
    std::function<Error(StringRef)> visit = [&](StringRef sym) -> Error {
      if (done.count(sym.str()))
        return Error::success();
      if (!onStack.insert(sym.str()).second)
        return err("record \"" + sym + "\" is cyclic (a record cannot contain "
                                       "itself, directly or through another "
                                       "record)");
      auto it = refs.find(sym);
      if (it != refs.end())
        for (const std::string &next : it->second) {
          if (!recSymbols.contains(next))
            return err("record_ref \"" + next +
                       "\" is not declared in the schema");
          if (Error e = visit(next))
            return e;
        }
      onStack.erase(sym.str());
      done.insert(sym.str());
      return Error::success();
    };
    for (const Record &r : s.records_)
      if (Error e = visit(r.symbol))
        return std::move(e);
  }

  // Validate layout after collecting all records needed for reference resolution.
  for (const Record &r : s.records_) {
    std::string where = "record \"" + r.symbol + "\"";
    struct Span { uint64_t begin, end; const Field *f; };
    std::vector<Span> spans;
    for (const Field &f : r.fields) {
      auto sz = s.sizeOf(f.type);
      if (!sz)
        return err(where + " field \"" + f.name +
                   "\": " + toString(sz.takeError()));
      if (*sz == 0)
        return err(where + " field \"" + f.name + "\": zero-sized field");
      // Offset must satisfy the type's alignment.
      uint64_t need = 1;
      if (const auto *i = std::get_if<IntType>(&f.type.v))
        need = i->alignment;
      else if (const auto *rr = std::get_if<RecordRefType>(&f.type.v)) {
        for (const Record &o : s.records_)
          if (o.symbol == rr->symbol)
            need = o.alignment;
      }
      if (f.offset % need != 0)
        return err(where + " field \"" + f.name + "\": offset " +
                   Twine(f.offset) + " is not aligned to " + Twine(need));
      if (f.offset + *sz > r.size)
        return err(where + " field \"" + f.name + "\": ends at " +
                   Twine(f.offset + *sz) + " which is past the record size " +
                   Twine(r.size));
      spans.push_back({f.offset, f.offset + *sz, &f});
    }
    llvm::sort(spans, [](const Span &a, const Span &b) {
      return a.begin < b.begin;
    });
    for (size_t i = 1; i < spans.size(); ++i)
      if (spans[i].begin < spans[i - 1].end)
        return err(where + ": fields \"" + spans[i - 1].f->name + "\" and \"" +
                   spans[i].f->name + "\" overlap (" +
                   Twine(spans[i - 1].begin) + ".." + Twine(spans[i - 1].end) +
                   " vs " + Twine(spans[i].begin) + ")");
  }

  // Optional local kernel types. Provisional offsets follow declaration order
  // with natural alignment; schema cannot supply them lest they be mistaken
  // for live kernel offsets. Load-time matching resolves target layout.
  StringSet<> kernelTypeNames;
  if (const json::Value *ktv = (*coreObj)->get("kernel_types")) {
    const auto *ktArr = ktv->getAsArray();
    if (!ktArr)
      return err("core.kernel_types must be an array");
    for (const json::Value &v : *ktArr) {
      const auto *o = v.getAsObject();
      if (!o)
        return err("core.kernel_types: entry must be an object");
      if (Error e = requireOnlyKeys(*o, kKeysKernelType,
                                    "core.kernel_types"))
        return std::move(e);
      KernelType k;
      auto name = getStr(*o, "name", "core.kernel_types");
      if (!name)
        return name.takeError();
      k.name = name->str();
      if (k.name.empty())
        return err("core.kernel_types: name must not be empty");
      if (!kernelTypeNames.insert(k.name).second)
        return err("core.kernel_types: duplicate kernel type \"" + k.name +
                   "\"");
      // Reserve integer argument spellings and unread '-' rather than accepting
      // them as kernel type names; internal and requirement spellings coincide.
      if (isTPArgScalarSpelling(k.name))
        return err("core.kernel_types: \"" + k.name + "\" is reserved (an integer or unread tp_btf argument spelling)");
      std::string where = "kernel type \"" + k.name + "\"";
      if (Error e = optStrInto(*o, "note", "core.kernel_types", k.note))
        return std::move(e);
      auto fieldsArr = getArr(*o, "fields", where);
      if (!fieldsArr)
        return fieldsArr.takeError();
      if ((*fieldsArr)->empty())
        return err(where + ": needs at least one field");
      StringSet<> fieldNames;
      uint64_t off = 0, maxAlign = 4;
      for (const json::Value &fv : **fieldsArr) {
        const auto *fo = fv.getAsObject();
        if (!fo)
          return err(where + ": field must be an object");
        if (Error e = requireOnlyKeys(*fo, kKeysKernelField,
                                      where + " field"))
          return std::move(e);
        KernelField f;
        auto fname = getStr(*fo, "name", where + " field");
        if (!fname)
          return fname.takeError();
        f.name = fname->str();
        if (!fieldNames.insert(f.name).second)
          return err(where + ": duplicate field name \"" + f.name + "\"");
        std::string fwhere = where + " field \"" + f.name + "\"";
        const json::Value *tv = fo->get("type");
        if (!tv)
          return err(fwhere + ": missing \"type\"");
        if (const auto *to = tv->getAsObject(); to && to->getString("kind") == "struct") {
          if (Error e = requireOnlyKeys(*to, kKeysKernelStruct, fwhere)) return std::move(e);
          auto st = to->getString("struct");
          if (!st || st->empty()) return err(fwhere + ": embedded struct needs a nonempty struct name");
          if (!(st->front() == '_' || llvm::isAlpha(st->front())) ||
              !llvm::all_of(*st, [](char c) { return c == '_' || llvm::isAlnum(c); }))
            return err(fwhere + ": embedded struct name must be an identifier");
          f.embedded = st->str();
          if (Error e = optStrInto(*fo, "note", "core.kernel_types field", f.note)) return std::move(e);
          k.fields.push_back(std::move(f));
          continue;
        }
        // kptr fields name kernel_types, resolved later to allow forward/self references.
        if (const auto *to = tv->getAsObject(); to && to->getString("kind") == "kptr") {
          for (const auto &kv : *to)
            if (kv.first != "kind" && kv.first != "struct")
              return err(fwhere + ": a kptr field type takes only \"kind\" and \"struct\", got \"" + kv.first.str() + "\"");
          auto st = to->getString("struct");
          if (!st || st->empty())
            return err(fwhere + ": a kptr field type needs a string \"struct\"");
          f.ptrTo = st->str();
          if (Error e = optStrInto(*fo, "note", "core.kernel_types field", f.note))
            return std::move(e);
          off = (off + 7) / 8 * 8;
          maxAlign = std::max<uint64_t>(maxAlign, 8);
          f.offset = off;
          off += 8;
          k.fields.push_back(std::move(f));
          continue;
        }
        // strptr is an eight-byte char* to a one-byte integer, read only by kernel.read_str.
        if (const auto *to = tv->getAsObject(); to && to->getString("kind") == "strptr") {
          for (const auto &kv : *to)
            if (kv.first != "kind")
              return err(fwhere + ": a strptr field type takes only \"kind\", got \"" + kv.first.str() + "\"");
          f.strPtr = true;
          if (Error e = optStrInto(*fo, "note", "core.kernel_types field", f.note))
            return std::move(e);
          off = (off + 7) / 8 * 8;
          maxAlign = std::max<uint64_t>(maxAlign, 8);
          f.offset = off;
          off += 8;
          k.fields.push_back(std::move(f));
          continue;
        }
        auto ft = parseType(*tv, fwhere);
        if (!ft)
          return ft.takeError();
        // One to 64 eight-bit elements: compiler bound for fixed-byte kfield.copy.
        if (const auto *at = std::get_if<ArrayType>(&ft->v)) {
          const auto *et = at->element ? std::get_if<IntType>(&at->element->v) : nullptr;
          if (!et || et->bits != 8 || et->endianness != Endianness::Little || at->count < 1 || at->count > 64)
            return err(fwhere + ": an array field in kernel_types must have 1 to 64 elements of an 8-bit little-endian integer");
          f.type = *et;
          f.arrayCount = at->count;
          if (Error e = optStrInto(*fo, "note", "core.kernel_types field", f.note))
            return std::move(e);
          f.offset = off;
          off += at->count;
          k.fields.push_back(std::move(f));
          continue;
        }
        const auto *it = std::get_if<IntType>(&ft->v);
        if (!it || (it->bits != 8 && it->bits != 16 && it->bits != 32 && it->bits != 64) ||
            it->endianness != Endianness::Little)
          return err(fwhere + ": only plain 8 / 16 / 32 / 64-bit little-endian integer "
                              "fields are supported in kernel_types; "
                              "bitfields, arrays, unions and pointers are not");
        f.type = *it;
        if (Error e = optStrInto(*fo, "note", "core.kernel_types field", f.note))
          return std::move(e);
        // Provisional offsets follow declaration order with natural alignment.
        uint64_t w = it->bits / 8;
        off = (off + w - 1) / w * w;
        maxAlign = std::max(maxAlign, w);
        f.offset = off;
        off += w;
        k.fields.push_back(std::move(f));
      }
      k.size = (off + maxAlign - 1) / maxAlign * maxAlign;
      s.kernelTypes_.push_back(std::move(k));
    }
    // resolve embedded value dependencies. Pointer edges do not participate in cycles.
    StringMap<unsigned> layoutState;
    std::function<Error(KernelType &)> layout = [&](KernelType &k) -> Error {
      if (layoutState[k.name] == 2) return Error::success();
      if (layoutState[k.name] == 1) return err("embedded kernel struct cycle at " + k.name);
      layoutState[k.name] = 1;
      uint64_t off = 0, align = 4;
      for (KernelField &f : k.fields) {
        uint64_t sz, a;
        if (!f.embedded.empty()) {
          auto it = llvm::find_if(s.kernelTypes_, [&](const KernelType &t) { return t.name == f.embedded; });
          if (it == s.kernelTypes_.end()) return err("embedded kernel struct is not declared: " + f.embedded);
          if (Error e = layout(*it)) return e;
          sz = it->size; a = it->alignment;
        } else if (!f.ptrTo.empty() || f.strPtr) { sz = a = 8; }
        else if (f.arrayCount) { sz = f.arrayCount; a = 1; }
        else { sz = a = f.type.bits / 8; }
        const uint64_t max = std::numeric_limits<uint64_t>::max() / 8;
        if (off > max - (a - 1)) return err("embedded kernel layout overflow");
        off = (off + a - 1) / a * a;
        if (sz > max - off) return err("embedded kernel layout overflow");
        f.offset = off; off += sz; align = std::max(align, a);
      }
      if (off > std::numeric_limits<uint64_t>::max() / 8 - (align - 1)) return err("embedded kernel layout overflow");
      k.size = (off + align - 1) / align * align; k.alignment = align;
      layoutState[k.name] = 2;
      return Error::success();
    };
    for (KernelType &k : s.kernelTypes_) if (Error e = layout(k)) return std::move(e);
    // Pointer pointees must name declared kernel_types.
    for (const KernelType &k : s.kernelTypes_)
      for (const KernelField &f : k.fields)
        if (!f.ptrTo.empty() && !kernelTypeNames.contains(f.ptrTo))
          return err("kernel type \"" + k.name + "\" field \"" + f.name + "\": kptr to \"" + f.ptrTo +
                     "\", which is not declared in core.kernel_types");
  }
  // Referenced kptr structs must name kernel_types. Their local TYPE_TAG
  // targets let the kernel resolve vmlinux structs by name.
  for (const Record &r : s.records_)
    for (const Field &f : r.fields)
      if (const auto *kp = std::get_if<KptrType>(&f.type.v); kp && !kernelTypeNames.contains(kp->structName))
        return err("record \"" + r.symbol + "\" field \"" + f.name + "\": kptr to \"" + kp->structName +
                   "\", which is not declared in core.kernel_types");

  // ---- maps ----
  auto mapsArr = getArr(**coreObj, "maps", "core");
  if (!mapsArr)
    return mapsArr.takeError();
  StringSet<> mapSymbols;
  for (const json::Value &v : **mapsArr) {
    const auto *o = v.getAsObject();
    if (!o)
      return err("core.maps: entry must be an object");
    if (Error e = requireOnlyKeys(*o, kKeysMap,
                                  "core.maps"))
      return std::move(e);
    Map m;
    auto sym = getStr(*o, "symbol", "core.maps");
    if (!sym)
      return sym.takeError();
    m.symbol = sym->str();
    if (!mapSymbols.insert(m.symbol).second)
      return err("core.maps: duplicate map symbol \"" + m.symbol + "\"");
    // Reserve the compiler-generated per-program USDT spec-map prefix.
    if (StringRef(m.symbol).starts_with(kUsdtSpecMapPrefix))
      return err("core.maps: map symbol \"" + m.symbol + "\" is reserved by the compiler (the prefix " + kUsdtSpecMapPrefix +
                 " names the USDT spec map of a usdt program)");
    std::string where = "map \"" + m.symbol + "\"";

    auto kind = getStr(*o, "kind", where);
    if (!kind)
      return kind.takeError();
    // MapKinds.def owns spellings and diagnostic list order.
    static constexpr std::pair<llvm::StringLiteral, MapKind> kKinds[] = {
#define EBPF_MAP_KIND(ENUM, NAME, MAPTYPE) {NAME, MapKind::ENUM},
#include "bpf-mlir/Support/MapKinds.def"
    };
    auto known = llvm::find_if(kKinds, [&](const auto &e) { return e.first == *kind; });
    if (known == std::end(kKinds)) {
      // RejectedMapKinds.def names intentionally unsupported kinds and their replacements.
      if (std::optional<std::string> msg = bpfmlir::rejectedMapKindMessage(*kind))
        return err("map \"" + m.symbol + "\": " + *msg);
      std::string list;
      for (size_t i = 0; i < std::size(kKinds); ++i)
        list += (i == 0 ? "" : i + 1 == std::size(kKinds) ? " or " : ", ") + ("\"" + kKinds[i].first + "\"").str();
      return err(where + ": kind must be " + list + ", got \"" + *kind + "\"");
    }
    m.kind = known->second;

    if (const json::Value *kv = o->get("key")) {
      auto kt = parseType(*kv, where + " key");
      if (!kt)
        return kt.takeError();
      m.key = std::move(*kt);
    }
    if (const json::Value *vv = o->get("value")) {
      auto vt = parseType(*vv, where + " value");
      if (!vt)
        return vt.takeError();
      m.value = std::move(*vt);
    }
    // Resolve key/value record_ref declarations too, including array elements.
    {
      std::function<const RecordRefType *(const Type &)> refOf = [&](const Type &t) -> const RecordRefType * {
        if (const auto *rr = std::get_if<RecordRefType>(&t.v))
          return rr;
        if (const auto *a = std::get_if<ArrayType>(&t.v))
          return a->element ? refOf(*a->element) : nullptr;
        return nullptr;
      };
      for (const auto &[name, t] : {std::pair<const char *, const std::optional<Type> *>{"key", &m.key}, {"value", &m.value}})
        if (*t)
          if (const RecordRefType *rr = refOf(**t); rr && !recSymbols.contains(rr->symbol))
            return err(where + " " + name + ": record_ref \"" + rr->symbol + "\" is not declared in core.records");
    }
    // Ring buffers have no ordinary key/value. Enforce requirements per kind
    // instead of imposing them on every map.
    if (m.kind == MapKind::RingBuf) {
      if (m.key || m.value)
        return err(where + ": a ringbuf map has no key/value");
    } else if (m.kind == MapKind::UserRingBuf) {
      // User ring buffers share no-key/value, power-of-two size and nominal sample-record rules.
      if (m.key || m.value)
        return err(where + ": a user_ringbuf map has no key/value");
    } else if (m.kind == MapKind::StructOps) {
      // struct_ops uses its operation table; loader maps the kernel value type.
    // Key is u32, kernel key_size four, with only key zero.
      const auto *ki = m.key ? std::get_if<IntType>(&m.key->v) : nullptr;
      if (!ki || ki->bits != 32 || ki->isSigned || m.value)
        return err(where + ": a struct_ops map needs a u32 key and no value (its value is the ops table — struct_ops)");
    } else if (bpfmlir::isKeylessMapKind(*kind)) {
      // queue/stack/bloom_filter have key_size zero. Values are integers only:
      // record-valued pop/peek results are outside compiler support.
      if (m.key)
        return err(where + ": a " + *kind + " map has no key (the kernel's key_size is 0)");
      if (!m.value || !std::holds_alternative<IntType>(m.value->v))
        return err(where + ": a " + *kind + " map needs an integer value (8 / 16 / 32 / 64 bits — a record value is outside the compiler's range)");
    } else if (!m.key || !m.value) {
      return err(where + ": a \"" + *kind + "\" map needs both key and value");
    }
    // devmap legacy ifindex keys/values are u32.
    if (m.kind == MapKind::Devmap) {
      auto u32 = [](const Type &t) {
        const auto *i = std::get_if<IntType>(&t.v);
        return i && i->bits == 32 && !i->isSigned;
      };
      if (!u32(*m.key) || !u32(*m.value))
        return err(where + ": a devmap map needs a u32 key and a u32 value (the ifindex)");
    }
    // Redirect targets use u32/u32: cpumap CPU/qsize, xskmap RX queue/socket FD,
    // devmap_hash key/ifindex. Eight-byte program-bearing variants are outside
    // scope. Require flags zero and no payload record.
    if (m.kind == MapKind::Cpumap || m.kind == MapKind::Xskmap || m.kind == MapKind::DevmapHash) {
      auto u32 = [](const Type &t) {
        const auto *i = std::get_if<IntType>(&t.v);
        return i && i->bits == 32 && !i->isSigned;
      };
      const char *what = m.kind == MapKind::Cpumap ? "a u32 key (the CPU) and a u32 value (the qsize)"
                         : m.kind == MapKind::Xskmap ? "a u32 key (the rx queue) and a u32 value (the AF_XDP socket fd)"
                                                     : "a u32 key and a u32 value (the ifindex)";
      if (!u32(*m.key) || !u32(*m.value))
        return err(where + ": a " + *kind + " map needs " + what + "");
    }

    auto maxE = getU64(*o, "max_entries", where);
    if (!maxE)
      return maxE.takeError();
    m.maxEntries = *maxE;
    // perf_event_array requires max_entries zero; loader supplies possible CPUs,
    // an environmental value not embedded in ELF. Local storage also requires
    // zero: cardinality follows owners, and kernel rejects positive limits.
    const bool localStorage = bpfmlir::localStorageOwner(mapKindSpelling(m.kind)).has_value();
    if (m.kind == MapKind::PerfEventArray) {
      if (m.maxEntries != 0)
        return err(where + ": a perf_event_array map takes max_entries 0 (the loader sets it to the possible CPU count — an environment value), got " + Twine(m.maxEntries));
    } else if (localStorage) {
      if (m.maxEntries != 0)
        return err(where + ": a " + *kind + " map takes max_entries 0 (one value per owner object — the kernel refuses a positive max_entries), got " +
                   Twine(m.maxEntries));
    } else if (m.maxEntries == 0)
      return err(where + ": max_entries must be positive");
    if (m.kind == MapKind::RingBuf && !isPowerOfTwo(m.maxEntries))
      return err(where + ": a ringbuf size must be a power of two, got " +
                 Twine(m.maxEntries));
    if (m.kind == MapKind::UserRingBuf && !isPowerOfTwo(m.maxEntries))
      return err(where + ": a user_ringbuf size must be a power of two, got " + Twine(m.maxEntries));

    auto flags = getU64(*o, "flags", where);
    if (!flags)
      return flags.takeError();
    m.flags = *flags;
    // FD-array support is u32/u32, flags zero, without payload records.
    if (m.kind == MapKind::CgroupArray) {
      auto u32 = [](const Type &t) {
        const auto *i = std::get_if<IntType>(&t.v);
        return i && i->bits == 32 && !i->isSigned;
      };
      if (!u32(*m.key) || !u32(*m.value))
        return err(where + ": a cgroup_array map needs a u32 key (the index) and a u32 value (the cgroup fd)");
      if (m.flags != 0)
        return err(where + ": a cgroup_array map takes no flags");
    }
    // IPv4 lpm_trie keys are eight-byte records: prefixlen:u32 at zero, addr:u8[4]
    // at four. Require BPF_F_NO_PREALLOC; kernel rejects its absence and
    // non-STRUCT key BTF. Values are integers.
    if (m.kind == MapKind::LpmTrie) {
      const auto *rr = std::get_if<RecordRefType>(&m.key->v);
      const Record *kr = nullptr;
      for (const Record &r : s.records_)
        if (rr && r.symbol == rr->symbol)
          kr = &r;
      auto isU = [](const Type &t, unsigned bits) {
        const auto *i = std::get_if<IntType>(&t.v);
        return i && i->bits == bits && !i->isSigned;
      };
      bool ok = kr && kr->size == 8 && kr->fields.size() == 2 && kr->fields[0].name == "prefixlen" && kr->fields[0].offset == 0 &&
                isU(kr->fields[0].type, 32) && kr->fields[1].name == "addr" && kr->fields[1].offset == 4;
      if (ok) {
        const auto *at = std::get_if<ArrayType>(&kr->fields[1].type.v);
        ok = at && at->count == 4 && at->element && isU(*at->element, 8);
      }
      if (!ok)
        return err(where + ": a lpm_trie key must be a record { prefixlen: u32 @0, addr: u8[4] @4 } of 8 bytes (the compiler's IPv4 key convention)");
      if (!(m.flags & 1))
        return err(where + ": a lpm_trie map needs BPF_F_NO_PREALLOC (flags bit 0) — the kernel refuses it otherwise");
      if (!std::get_if<IntType>(&m.value->v))
        return err(where + ": a lpm_trie value must be an integer");
    }
    // prog_array has u32 slot/FD types and flags zero. Unique slots must be below
    // max_entries; emission matches program presence/kind in this ELF.
    // Only prog_array may declare slots.
    if (const json::Value *sv = o->get("slots")) {
      if (m.kind != MapKind::ProgArray)
        return err(where + ": only a prog_array map has slots");
      const json::Array *sa = sv->getAsArray();
      if (!sa)
        return err(where + ": slots must be an array");
      for (const json::Value &e : *sa) {
        const auto *so = e.getAsObject();
        if (!so)
          return err(where + ": a slot must be an object {index, program}");
        if (Error er = requireOnlyKeys(*so, kKeysMapSlot, where + " slot"))
          return std::move(er);
        auto idx = getU64(*so, "index", where + " slot");
        if (!idx)
          return idx.takeError();
        auto prog = getStr(*so, "program", where + " slot");
        if (!prog)
          return prog.takeError();
        if (*idx >= m.maxEntries)
          return err(where + ": slot " + Twine(*idx) + " is outside max_entries " + Twine(m.maxEntries));
        for (const Map::Slot &q : m.slots)
          if (q.index == *idx)
            return err(where + ": slot " + Twine(*idx) + " is declared twice");
        if (prog->empty())
          return err(where + ": slot " + Twine(*idx) + " needs a program name");
        m.slots.push_back({*idx, prog->str()});
      }
    }
    if (m.kind == MapKind::ProgArray) {
      auto u32 = [](const Type &t) {
        const auto *i = std::get_if<IntType>(&t.v);
        return i && i->bits == 32 && !i->isSigned;
      };
      if (!u32(*m.key) || !u32(*m.value))
        return err(where + ": a prog_array map needs a u32 key (the slot) and a u32 value (the program)");
      if (m.flags != 0)
        return err(where + ": a prog_array map takes no flags");
    }
    // sockmap/sockhash values are u32/u64 socket FDs. sockmap keys are u32;
    // sockhash accepts integer keys, not records. Require flags zero despite
    // wider kernel support. Userspace populates entries; program operations
    // are restricted separately by checkMapKind.
    if (m.kind == MapKind::Sockmap || m.kind == MapKind::Sockhash) {
      const char *kn = m.kind == MapKind::Sockmap ? "sockmap" : "sockhash";
      auto uint = [](const Type &t, unsigned bits) {
        const auto *i = std::get_if<IntType>(&t.v);
        return i && i->bits == bits && !i->isSigned;
      };
      bool keyOk = m.kind == MapKind::Sockmap ? uint(*m.key, 32) : std::holds_alternative<IntType>(m.key->v);
      if (!keyOk)
        return err(where + ": a " + kn + " map needs " +
                   (m.kind == MapKind::Sockmap ? "a u32 key (the slot)" : "an integer key") + "");
      if (!uint(*m.value, 32) && !uint(*m.value, 64))
        return err(where + ": a " + kn + " map needs a u32 or u64 value (the socket fd userspace puts in)");
      if (m.flags != 0)
        return err(where + ": a " + kn + " map takes no flags");
    }
    // Local storage uses a four-byte owner-FD key (kernel ignores its sign) and
    // typed integer/record values. Require BPF_F_NO_PREALLOC; compiler does
    // not expose BPF_F_CLONE. These maps do not carry payload records.
    if (localStorage) {
      const auto *ki = std::get_if<IntType>(&m.key->v);
      if (!ki || ki->bits != 32)
        return err(where + ": a " + *kind + " map needs a 32-bit integer key (the owner's fd in userspace — the kernel's key_size is sizeof(int))");
      if (!std::holds_alternative<IntType>(m.value->v) && !std::holds_alternative<RecordRefType>(m.value->v))
        return err(where + ": a " + *kind + " map needs an integer or record value");
      std::optional<int64_t> noPrealloc = mlir::bpfabi::lookupMapFlag("no_prealloc");
      if (!noPrealloc)
        return err(where + ": BPF_F_NO_PREALLOC is not in the UAPI table");
      if (m.flags != static_cast<uint64_t>(*noPrealloc))
        return err(where + ": a " + *kind + " map needs flags " + std::to_string(*noPrealloc) +
                   " (BPF_F_NO_PREALLOC) and no other flag — the kernel refuses it otherwise, got " + std::to_string(m.flags));
    }
    // queue/stack require flags zero despite wider kernel flags. bloom_filter
    // additionally permits BPF_F_ZERO_SEED.
    if (bpfmlir::isKeylessMapKind(*kind)) {
      std::optional<int64_t> zeroSeed = mlir::bpfabi::lookupMapFlag("zero_seed");
      if (!zeroSeed)
        return err(where + ": BPF_F_ZERO_SEED is not in the UAPI table");
      if (m.kind == MapKind::BloomFilter) {
        if (m.flags != 0 && m.flags != static_cast<uint64_t>(*zeroSeed))
          return err(where + ": a bloom_filter map takes flags 0 or " + std::to_string(*zeroSeed) + " (BPF_F_ZERO_SEED), got " +
                     std::to_string(m.flags));
      } else if (m.flags != 0) {
        return err(where + ": a " + *kind + " map takes no flags");
      }
    }
    // stack_trace uses u32 IDs and nonempty u64 IP arrays with flags zero.
    // Environmental perf_event_max_stack limits are checked at map creation,
    // not compile time. Build-ID arrays instead require both stack_build_id
    // elements and BPF_F_STACK_BUILD_ID; reject either without the other.
    if (m.kind == MapKind::StackTrace) {
      const auto *ki = std::get_if<IntType>(&m.key->v);
      const auto *va = std::get_if<ArrayType>(&m.value->v);
      const IntType *ve = va && va->element ? std::get_if<IntType>(&va->element->v) : nullptr;
      bool bid = va && va->element && std::holds_alternative<StackBuildIdType>(va->element->v);
      std::optional<int64_t> bidFlag = mlir::bpfabi::lookupMapFlag("stack_build_id");
      if (!bidFlag)
        return err(where + ": BPF_F_STACK_BUILD_ID is not in the UAPI table");
      if (!ki || ki->bits != 32 || ki->isSigned || va == nullptr || va->count < 1 || (!bid && (!ve || ve->bits != 64 || ve->isSigned)))
        return err(where + ": a stack_trace map needs a u32 key (the id) and an array value (depth >= 1) of u64 (the IPs) or of stack_build_id");
      if (bid && m.flags != static_cast<uint64_t>(*bidFlag))
        return err(where + ": a stack_trace map of stack_build_id elements needs flags " + std::to_string(*bidFlag) +
                   " (BPF_F_STACK_BUILD_ID) — the kernel fills the build id only on such a map");
      if (!bid && m.flags == static_cast<uint64_t>(*bidFlag))
        return err(where + ": flags " + std::to_string(*bidFlag) + " (BPF_F_STACK_BUILD_ID) needs a value of stack_build_id elements, not u64 (each entry is a 32-byte struct bpf_stack_build_id)");
      if (!bid && m.flags != 0)
        return err(where + ": a stack_trace map of u64 IPs takes no flags");
    } else {
      // stack_build_id is allowed only as a stack_trace value-array element.
      std::function<bool(const Type &)> hasBid = [&](const Type &t) -> bool {
        if (std::holds_alternative<StackBuildIdType>(t.v))
          return true;
        if (const auto *a = std::get_if<ArrayType>(&t.v))
          return hasBid(*a->element);
        return false;
      };
      if ((m.key && hasBid(*m.key)) || (m.value && hasBid(*m.value)))
        return err(where + ": a stack_build_id is only the element of a stack_trace map value");
    }
    if (Error e = optStrInto(*o, "record", "core.maps", m.record))
      return std::move(e);
    if (Error e = optStrInto(*o, "note", "core.maps", m.note))
      return std::move(e);
    if (m.kind == MapKind::CgroupArray && !m.record.empty())
      return err(where + ": a cgroup_array map has no payload record");
    if (!m.record.empty() && !recSymbols.contains(m.record))
      return err(where + ": record \"" + m.record +
                 "\" is not declared in the schema");
    if (m.kind == MapKind::RingBuf && m.record.empty())
      return err(where + ": a ringbuf map must name the record it carries");
    if (localStorage && !m.record.empty()) // Values are key/value types, not payload records.
      return err(where + ": a " + *kind + " map carries no record (its value type is the map's value)");
    if (bpfmlir::isKeylessMapKind(*kind) && !m.record.empty())
      return err(where + ": a " + *kind + " map carries no record");
    // Redirect maps require flags zero and no record; devmap_hash max_entries <= 2^31.
    if (m.kind == MapKind::Cpumap || m.kind == MapKind::Xskmap || m.kind == MapKind::DevmapHash) {
      if (m.flags != 0)
        return err(where + ": a " + *kind + " map takes no flags");
      if (!m.record.empty())
        return err(where + ": a " + *kind + " map carries no record");
      if (m.kind == MapKind::DevmapHash && m.maxEntries > (uint64_t(1) << 31))
        return err(where + ": a devmap_hash map takes max_entries up to 2147483648 (the kernel refuses more), got " + Twine(m.maxEntries));
    }
    // Only map-in-map requires inner template symbols. array_of_maps keys are
    // u32; hash_of_maps keys are integers. Values are u32 inner FDs. Require
    // flags zero/no record; BPF_F_INNER_MAP is outside scope. Resolve templates
    // after reading all maps to permit forward declarations.
    if (Error e = optStrInto(*o, "inner", "core.maps", m.inner))
      return std::move(e);
    {
      const bool mapInMap = m.kind == MapKind::ArrayOfMaps || m.kind == MapKind::HashOfMaps;
      if (!mapInMap && o->get("inner"))
        return err(where + ": only an array_of_maps / hash_of_maps map has inner");
      if (mapInMap) {
        if (m.inner.empty())
          return err(where + ": a " + *kind + " map needs inner (the symbol of the inner map template in core.maps)");
        const auto *ki = std::get_if<IntType>(&m.key->v);
        if (!ki || (m.kind == MapKind::ArrayOfMaps && (ki->bits != 32 || ki->isSigned)))
          return err(where + ": a " + *kind + " map needs " + (m.kind == MapKind::ArrayOfMaps ? "a u32 key (the slot)" : "an integer key") + "");
        const auto *vi = std::get_if<IntType>(&m.value->v);
        if (!vi || vi->bits != 32 || vi->isSigned)
          return err(where + ": a " + *kind + " map needs a u32 value (the inner map's fd — the kernel's value_size is 4)");
        if (m.flags != 0)
          return err(where + ": a " + *kind + " map takes no flags");
        if (!m.record.empty())
          return err(where + ": a " + *kind + " map carries no record");
      }
    }
    if (m.kind == MapKind::UserRingBuf && m.record.empty())
      return err(where + ": a user_ringbuf map must name the record it carries (the sample userspace writes)");
    // Locks belong only within array-map value records, never keys, direct
    // values, payload records or other map kinds.
    {
      auto isLockRef = [&](const std::optional<Type> &t) {
        const auto *rr = t ? std::get_if<RecordRefType>(&t->v) : nullptr;
        return rr && lockRecords.count(rr->symbol);
      };
      if ((m.key && std::holds_alternative<SpinLockType>(m.key->v)) || (m.value && std::holds_alternative<SpinLockType>(m.value->v)))
        return err(where + ": a spin_lock is only a field of a record, not a map key or value by itself");
      if (isLockRef(m.key))
        return err(where + ": a record with a spin_lock field cannot be a map key");
      if (isLockRef(m.value) && m.kind != MapKind::Array)
        return err(where + ": a record with a spin_lock field is only supported as the value of an array map, not \"" +
                   std::string(mapKindName(m.kind)) + "\"");
      if (!m.record.empty() && lockRecords.count(m.record))
        return err(where + ": a record with a spin_lock field cannot be carried by a ring buffer / perf event map");
    }
    // Timer placement likewise permits only array-map value records.
    {
      auto isTimerRef = [&](const std::optional<Type> &t) {
        const auto *rr = t ? std::get_if<RecordRefType>(&t->v) : nullptr;
        return rr && timerRecords.count(rr->symbol);
      };
      if ((m.key && std::holds_alternative<TimerType>(m.key->v)) || (m.value && std::holds_alternative<TimerType>(m.value->v)))
        return err(where + ": a timer is only a field of a record, not a map key or value by itself");
      if (isTimerRef(m.key))
        return err(where + ": a record with a timer field cannot be a map key");
      if (isTimerRef(m.value) && m.kind != MapKind::Array)
        return err(where + ": a record with a timer field is only supported as the value of an array map, not \"" +
                   std::string(mapKindName(m.kind)) + "\"");
      if (!m.record.empty() && timerRecords.count(m.record))
        return err(where + ": a record with a timer field cannot be carried by a ring buffer / perf event map");
    }
    // These ten map kinds permit ordinary referenced kptr under map_check_btf.
    // Keys and ring/perf payload records reject even nested kptr containment.
    {
      auto isKptrRef = [&](const std::optional<Type> &t) {
        const auto *rr = t ? std::get_if<RecordRefType>(&t->v) : nullptr;
        return rr && kptrRecords.count(rr->symbol);
      };
      if ((m.key && std::holds_alternative<KptrType>(m.key->v)) || (m.value && std::holds_alternative<KptrType>(m.value->v)))
        return err(where + ": a kptr is only a field of a record, not a map key or value by itself");
      if (isKptrRef(m.key))
        return err(where + ": a record with a kptr field cannot be a map key");
      bool permitsKptr = m.kind == MapKind::Array || m.kind == MapKind::Hash ||
                         m.kind == MapKind::PerCpuArray || m.kind == MapKind::PerCpuHash ||
                         m.kind == MapKind::LruHash || m.kind == MapKind::LruPerCpuHash ||
                         m.kind == MapKind::SkStorage || m.kind == MapKind::InodeStorage ||
                         m.kind == MapKind::TaskStorage || m.kind == MapKind::CgrpStorage;
      if (isKptrRef(m.value) && !permitsKptr)
        return err(where + ": a record with a kptr field is only supported as the value of a hash, array, per-CPU, LRU or local storage map, not \"" +
                   std::string(mapKindName(m.kind)) + "\"");
      if (!m.record.empty() && kptrRecords.count(m.record))
        return err(where + ": a record with a kptr field cannot be carried by a ring buffer / perf event map");
    }
    // perf_event_array uses u32 key/FD value, flags zero, and a required nominal
    // payload record, distinct from the FD map value.
    if (m.kind == MapKind::PerfEventArray) {
      auto u32 = [](const Type &t) {
        const auto *i = std::get_if<IntType>(&t.v);
        return i && i->bits == 32 && !i->isSigned;
      };
      if (!u32(*m.key) || !u32(*m.value))
        return err(where + ": a perf_event_array map needs a u32 key and a u32 value (the perf event fd — not the payload)");
      if (m.flags != 0)
        return err(where + ": a perf_event_array map takes no flags");
      if (m.record.empty())
        return err(where + ": a perf_event_array map must name the record it carries (the payload — separate from the u32 value)");
    }
    // reuseport_sockarray uses u32 indices and u32/u64 values. Userspace update
    // supplies socket FDs; lookup returns cookies only with eight-byte values.
    // Require flags zero and no payload record.
    if (m.kind == MapKind::ReuseportSockarray) {
      auto uint = [](const Type &t, unsigned bits) {
        const auto *i = std::get_if<IntType>(&t.v);
        return i && i->bits == bits && !i->isSigned;
      };
      if (!uint(*m.key, 32) || !(uint(*m.value, 32) || uint(*m.value, 64)))
        return err(where + ": a reuseport_sockarray map needs a u32 key and a u32 or u64 value (userspace stores the socket fd)");
      if (m.flags != 0)
        return err(where + ": a reuseport_sockarray map takes no flags");
      if (!m.record.empty())
        return err(where + ": a reuseport_sockarray map carries no record (its values are sockets)");
    }
    // struct_ops requires {type,name,ops:[{member,program}]}. Type must be listed
    // in StructOpsTypes.def. Name exists only when the type's DATA row requires
    // it, with objname length/character rules. Unique fptr member names come
    // from ABI; nonempty programs are resolved after parsing all programs.
    // Require max_entries one, flags zero and no record.
    if (const json::Value *sv = o->get("struct_ops")) {
      if (m.kind != MapKind::StructOps)
        return err(where + ": only a struct_ops map has struct_ops");
      const auto *so = sv->getAsObject();
      if (!so)
        return err(where + ": struct_ops must be an object {type, name, ops}");
      if (Error er = requireOnlyKeys(*so, kKeysMapStructOps, where + " struct_ops"))
        return std::move(er);
      Map::StructOps st;
      auto ty = getStr(*so, "type", where + " struct_ops");
      if (!ty)
        return ty.takeError();
      st.type = ty->str();
      // Types are compiler capabilities in StructOpsTypes.def; members are target
      // BTF facts recorded by ABI structopsmember rows.
      if (!bpfmlir::lookupStructOpsType(st.type))
        return err(where + ": struct_ops type must be one of " + bpfmlir::listStructOpsTypes() +
                   " (the struct_ops types the compiler supports — StructOpsTypes.def), got \"" + st.type + "\"");
      if (!mlir::bpfabi::hasStructOpsType(st.type))
        return err(where + ": struct_ops type \"" + st.type + "\" has no structopsmember rows in the UAPI table (re-extract abi/uapi.tsv)");
      // DATA SCHEMAKEY (currently name) is required with its rule/size only when
      // listed for this type; reject it otherwise.
      const bpfmlir::StructOpsDataInfo *nameRow = bpfmlir::structOpsDataByKey(st.type, "name");
      if (nameRow) {
        auto nm = getStr(*so, "name", where + " struct_ops");
        if (!nm)
          return nm.takeError();
        st.name = nm->str();
        auto nameChar = [](char c) { return isAlnum(c) || c == '_' || c == '.'; };
        if (st.name.empty() || st.name.size() > nameRow->bytes - 1 || !llvm::all_of(st.name, nameChar))
          return err(where + ": struct_ops name must be 1 to " + Twine(nameRow->bytes - 1) + " characters of letters, digits, '_' or '.' (" +
                     st.type + "." + nameRow->member + " is char[" + Twine(nameRow->bytes) + "] with the NUL — the kernel's bpf_obj_name_cpy), got \"" +
                     st.name + "\"");
      } else if (so->get("name")) {
        return err(where + ": struct_ops type \"" + st.type + "\" has no name member (StructOpsTypes.def); leave out \"name\"");
      }
      auto opsArr = getArr(*so, "ops", where + " struct_ops");
      if (!opsArr)
        return opsArr.takeError();
      if ((*opsArr)->empty())
        return err(where + ": struct_ops ops must not be empty");
      for (const json::Value &e : **opsArr) {
        const auto *oo = e.getAsObject();
        if (!oo)
          return err(where + ": a struct_ops op must be an object {member, program}");
        if (Error er = requireOnlyKeys(*oo, kKeysMapStructOpsOp, where + " struct_ops op"))
          return std::move(er);
        auto mem = getStr(*oo, "member", where + " struct_ops op");
        if (!mem)
          return mem.takeError();
        auto prog = getStr(*oo, "program", where + " struct_ops op");
        if (!prog)
          return prog.takeError();
        // Require ABI fptr members, rejecting misspellings/data fields at compile
        // time. Pre-load structop matching owns signature validation.
        const mlir::bpfabi::StructOpsMemberABI *mrow = mlir::bpfabi::lookupStructOpsMember(st.type, *mem);
        if (!mrow || mrow->kind != "fptr")
          return err(where + ": struct_ops op member \"" + *mem + "\" is not a function pointer member of " + st.type +
                     (mrow ? " (it is a data member)" : "") + " in the UAPI table (structopsmember)");
        if (prog->empty())
          return err(where + ": struct_ops op \"" + *mem + "\" needs a program name");
        for (const Map::StructOps::Op &q : st.ops) {
          if (q.member == *mem)
            return err(where + ": struct_ops member \"" + *mem + "\" is declared twice");
          if (q.program == *prog)
            return err(where + ": struct_ops program \"" + *prog + "\" implements two members (a program implements one member)");
        }
        st.ops.push_back({mem->str(), prog->str()});
      }
      m.structOps = std::move(st);
    }
    if (m.kind == MapKind::StructOps) {
      if (!m.structOps)
        return err(where + ": a struct_ops map needs struct_ops {type, name, ops}");
      if (m.maxEntries != 1)
        return err(where + ": a struct_ops map takes max_entries 1 (one ops table), got " + Twine(m.maxEntries));
      if (m.flags != 0)
        return err(where + ": a struct_ops map takes no flags (the loader sets BPF_F_LINK for .struct_ops.link)");
      if (!m.record.empty())
        return err(where + ": a struct_ops map carries no record");
    }
    s.maps_.push_back(std::move(m));
  }

  // ---- programs ----
  auto progArr = getArr(**coreObj, "programs", "core");
  if (!progArr)
    return progArr.takeError();
  StringSet<> progNames;
  for (const json::Value &v : **progArr) {
    const auto *o = v.getAsObject();
    if (!o)
      return err("core.programs: entry must be an object");
    if (Error e = requireOnlyKeys(*o, kKeysProgram,
            "core.programs"))
      return std::move(e);
    Program p;
    auto name = getStr(*o, "name", "core.programs");
    if (!name)
      return name.takeError();
    p.name = name->str();
    if (!progNames.insert(p.name).second)
      return err("core.programs: duplicate program name \"" + p.name + "\"");
    std::string where = "program \"" + p.name + "\"";

    auto kind = getStr(*o, "kind", where);
    if (!kind)
      return kind.takeError();
    p.kind = kind->str();
    // ProgramKinds.def owns kinds, attachment shapes and architecture requirements.
    const bpfmlir::ProgramKindInfo *info = bpfmlir::lookupProgramKind(p.kind);
    if (!info)
      return err(where + ": kind must be " + bpfmlir::joinProgramKinds([](auto &) { return true; }, "\"", ", ", " or ") + ", got \"" +
                 p.kind + "\"");

    // Multi-probe attach_target is a JSON name array in program attachment order.
    // Reject empty arrays/names, duplicates and globs. Other kinds use strings.
    if (bpfmlir::isAttachList(info->attach)) {
      const json::Value *tv = o->get("attach_target");
      const json::Array *ta = tv ? tv->getAsArray() : nullptr;
      if (!ta)
        return err(where + ": a " + p.kind + " program needs attach_target as an array of names (the functions / symbols it is attached to)");
      if (ta->empty())
        return err(where + ": attach_target of a " + p.kind + " program must name at least one function / symbol");
      StringSet<> seenTargets;
      for (const json::Value &e : *ta) {
        auto s = e.getAsString();
        if (!s || s->empty())
          return err(where + ": attach_target entries must be non-empty strings");
        if (s->find_first_of("*?[") != StringRef::npos)
          return err(where + ": attach_target entry \"" + *s + "\" has a glob character ('*', '?' or '['); list each name");
        if (!seenTargets.insert(*s).second)
          return err(where + ": attach_target names \"" + *s + "\" twice");
        p.attachTargets.push_back(s->str());
      }
    } else {
      auto target = getStr(*o, "attach_target", where);
      if (!target)
        return target.takeError();
      p.attachTarget = target->str();
    }
    if (Error e = optStrInto(*o, "note", "core.programs", p.note))
      return std::move(e);

    // tp_btf declares target tracepoint and local argument types; xdp does not.
    if (const json::Value *av = o->get("args")) {
      const auto *aa = av->getAsArray();
      if (!aa)
        return err(where + ": args must be an array");
      for (const json::Value &a : *aa) {
        // Null means unread; integer objects retain i8..u64 requirement spellings.
        if (a.kind() == json::Value::Null) {
          p.args.push_back("-");
          continue;
        }
        // Nullable struct-pointer args are stored internally as S?, yielding
        // kptr_or_null<S> and requirement S. False/omitted nullable matches
        // the plain string form.
        if (const auto *ao = a.getAsObject(); ao && ao->getString("kind") == "struct") {
          for (const auto &kv : *ao)
            if (kv.first != "kind" && kv.first != "name" && kv.first != "nullable")
              return err(where + ": struct args entries take only \"kind\", \"name\" and \"nullable\", got \"" + kv.first.str() + "\"");
          auto nm = ao->getString("name");
          if (!nm)
            return err(where + ": struct args entries need a string \"name\"");
          if (!kernelTypeNames.contains(*nm))
            return err(where + ": arg type \"" + *nm + "\" is not declared in core.kernel_types");
          bool nullable = false;
          if (const json::Value *nv = ao->get("nullable")) {
            auto b = nv->getAsBoolean();
            if (!b)
              return err(where + ": struct args entry \"nullable\" must be a boolean");
            nullable = *b;
          }
          p.args.push_back(nm->str() + (nullable ? "?" : ""));
          continue;
        }
        if (a.getAsObject()) {
          auto t = parseType(a, where + " args");
          if (!t)
            return t.takeError();
          const auto *it = std::get_if<IntType>(&t->v);
          if (!it || it->endianness != Endianness::Little || it->alignment != it->bits / 8)
            return err(where + ": integer args entries must be little-endian integers of 8 / 16 / 32 / 64 bits with the natural alignment");
          p.args.push_back(std::string(it->isSigned ? "i" : "u") + std::to_string(it->bits));
          continue;
        }
        auto as = a.getAsString();
        if (!as)
          return err(where + ": args entries must be kernel type names, integer types or null");
        if (!kernelTypeNames.contains(*as))
          return err(where + ": arg type \"" + *as +
                     "\" is not declared in core.kernel_types");
        p.args.push_back(as->str());
      }
    }
    // Attachment shape comes from the shared program-kind table. Kinds with
    // no attachment shape, such as xdp, do not inspect attach_target.
    switch (info->attach) {
    case bpfmlir::AttachForm::None:
    case bpfmlir::AttachForm::KernelFuncList: // Name lists were validated above.
    case bpfmlir::AttachForm::UserSymbolList:
      break;
    case bpfmlir::AttachForm::Tracepoint:
      if (p.attachTarget.empty())
        return err(where + ": a " + p.kind + " program needs attach_target (the tracepoint name)");
      break;
    case bpfmlir::AttachForm::KernelFunc:
      if (p.attachTarget.empty())
        return err(where + ": a " + p.kind + " program needs attach_target (the kernel function name)");
      break;
    case bpfmlir::AttachForm::UserSymbol:
      if (p.attachTarget.empty())
        return err(where + ": a " + p.kind + " program needs attach_target (the function symbol in the user binary)");
      break;
    case bpfmlir::AttachForm::SyscallName: // ksyscall names an unprefixed syscall C identifier.
      if (!bpfmlir::isSyscallName(p.attachTarget))
        return err(where + ": a " + p.kind + " program needs attach_target (the syscall name without the arch prefix, e.g. getppid — not sys_… or __…), got \"" +
                   p.attachTarget + "\"");
      break;
    case bpfmlir::AttachForm::UsdtProbe: // USDT provider:name matches program and requirement target spellings.
      if (!bpfmlir::isUsdtProbeName(p.attachTarget))
        return err(where + ": a " + p.kind + " program needs attach_target \"<provider>:<name>\" (two C identifiers — the USDT probe), got \"" +
                   p.attachTarget + "\"");
      break;
    case bpfmlir::AttachForm::IterTarget:
      if (p.attachTarget.empty())
        return err(where + ": a " + p.kind + " program needs attach_target (the iter target name, e.g. bpf_map_elem)");
      break;
    case bpfmlir::AttachForm::ProgFunc: // ext names the global BPF function being replaced.
      if (p.attachTarget.empty())
        return err(where + ": a " + p.kind + " program needs attach_target (the global function of the BPF program it replaces)");
      break;
    case bpfmlir::AttachForm::LsmHook:
      if (p.attachTarget.empty())
        return err(where + ": a " + p.kind + " program needs attach_target (the LSM hook name, e.g. socket_create)");
      break;
    case bpfmlir::AttachForm::TracefsEvent:
      if (!bpfmlir::isTracefsEventName(p.attachTarget))
        return err(where + ": a " + p.kind + " program needs attach_target \"<category>/<event>\" (the tracefs event, e.g. syscalls/sys_enter_getppid), got \"" +
                   p.attachTarget + "\"");
      break;
    case bpfmlir::AttachForm::StructOpsMap: { // struct_ops must appear in the target map's ops member list.
      const Map *am = nullptr;
      for (const Map &mm : s.maps_)
        if (mm.symbol == p.attachTarget)
          am = &mm;
      if (!am || am->kind != MapKind::StructOps)
        return err(where + ": a " + p.kind + " program needs attach_target naming a struct_ops map in core.maps, got \"" + p.attachTarget + "\"");
      if (llvm::none_of(am->structOps->ops, [&](const Map::StructOps::Op &q) { return q.program == p.name; }))
        return err(where + ": the struct_ops map \"" + am->symbol + "\" has no op implemented by this program (struct_ops.ops[].program)");
      break;
    }
    case bpfmlir::AttachForm::MapSymbol: { // sk_skb/sk_msg targets are schema sockmap/sockhash symbols. Strip hook
      // prefixes such as stream_parser: before resolving the map.
      llvm::StringRef sym = bpfmlir::mapSymbolOfAttach(*info, p.attachTarget);
      const Map *am = nullptr;
      for (const Map &mm : s.maps_)
        if (mm.symbol == sym)
          am = &mm;
      if (!am || (am->kind != MapKind::Sockmap && am->kind != MapKind::Sockhash))
        return err(where + ": a " + p.kind + " program needs attach_target naming a sockmap or sockhash map in core.maps, got \"" +
                   p.attachTarget + "\"");
      break;
    }
    // Fixed attachment values are exactly the ProgramAttaches.def rows.
    case bpfmlir::AttachForm::TcxDirection:
    case bpfmlir::AttachForm::SockoptHook:    // cgroup_sockopt hook.
    case bpfmlir::AttachForm::CgroupDirection: // cgroup_skb direction.
    case bpfmlir::AttachForm::ReuseportHook:  // sk_reuseport: empty defaults to select; migrate is explicit.
    case bpfmlir::AttachForm::CgroupHook: {   // Cgroup socket hooks retain an empty default row. A kind whose only
      // row is empty ignores attach_target, like None, for compatibility.
      if (!bpfmlir::kindTakesAttach(*info))
        break;
      if (bpfmlir::lookupProgramAttach(*info, p.attachTarget))
        break;
      llvm::SmallVector<llvm::StringRef, 4> vals = bpfmlir::attachValuesOf(*info);
      std::string list;
      for (size_t i = 0; i < vals.size(); ++i)
        list += (i ? (i + 1 == vals.size() ? " or " : ", ") : "") + ("\"" + vals[i] + "\"").str();
      llvm::StringRef what = info->attach == bpfmlir::AttachForm::TcxDirection      ? "the tcx direction"
                             : info->attach == bpfmlir::AttachForm::SockoptHook     ? "the sockopt hook"
                             : info->attach == bpfmlir::AttachForm::CgroupDirection ? "the cgroup attach direction"
                             : info->attach == bpfmlir::AttachForm::ReuseportHook   ? "the reuseport hook"
                                                                                     : "the cgroup socket hook";
      bool dflt = bpfmlir::lookupProgramAttach(*info, "") != nullptr;
      return err(where + ": a " + p.kind + " program needs attach_target " + list + (dflt ? " or \"\"" : "") + " (" + what + "), got \"" +
                 p.attachTarget + "\"");
    }
    }
    if (info->sig == bpfmlir::SigFamily::TpArgs) { // Signature family from SIG.
      if (p.args.empty())
        return err(where + ": a " + p.kind + " program needs args (the kernel types "
                           "of the tracepoint arguments it reads)");
    } else if (info->sig == bpfmlir::SigFamily::FuncArgs && o->get("args")) {
      // fentry args accept scalar/struct/skip, retaining nullable pointer discipline.
      if (p.args.empty())
        return err(where + ": args of a " + p.kind + " program must not be empty (omit it instead)");
    } else if (info->sig == bpfmlir::SigFamily::IntArgs && o->get("args")) {
      // Optional fmod_ret args are integers or unread null. Struct pointers lack
      // the required matching contract here and could silently read wrong types.
      if (p.args.empty())
        return err(where + ": args of a " + p.kind + " program must not be empty (omit it instead)");
      for (const std::string &a : p.args)
        if (a != "-" && !isTPArgScalarSpelling(a))
          return err(where + ": " + p.kind + " args entries must be integer types or null (struct arguments are not supported)");
    } else if ((info->sig == bpfmlir::SigFamily::HookArgs || info->sig == bpfmlir::SigFamily::OpsSig) && o->get("args")) {
      // struct_ops allows promoted verifier struct types, integers and null; farg
      // records the unpromoted BTF name. LSM args similarly allow nullable
      // struct pointers, integers and null, matched before load against
      // bpf_lsm_<hook> FUNC_PROTO through trace_lsm farg.
      if (p.args.empty())
        return err(where + ": args of a " + p.kind + " program must not be empty (omit it instead)");
    } else if (info->sig == bpfmlir::SigFamily::ExtSig && o->get("args")) {
      // ext declares all replacement arguments as integer types, never null.
      // BTF FUNC_PROTO must match target widths; validate length against nargs
      // after reading it below.
      if (p.args.empty())
        return err(where + ": args of a " + p.kind + " program must not be empty (omit it when nargs is 0)");
      for (const std::string &a : p.args)
        if (!isTPArgScalarSpelling(a) || a == "-")
          return err(where + ": " + p.kind + " args entries must be integer types (every argument of the replaced function, also the ones it does not "
                                             "read — the BTF of the ext program carries their sizes)");
    } else if (o->get("args")) {
      // Reject even empty arrays for unsupported argument declarations.
      return err(where + ": args is only for " +
                 bpfmlir::joinProgramKinds([](auto &k) { return k.sig == bpfmlir::SigFamily::TpArgs || k.sig == bpfmlir::SigFamily::FuncArgs ||
                                                                k.sig == bpfmlir::SigFamily::IntArgs || k.sig == bpfmlir::SigFamily::HookArgs ||
                                                                k.sig == bpfmlir::SigFamily::ExtSig || k.sig == bpfmlir::SigFamily::OpsSig; },
                                           "", ", ", " and ") + " programs");
    }
    // fexit requires nargs/ret; other signature families are handled explicitly.
    const json::Value *nv = o->get("nargs");
    const json::Value *rv = o->get("ret");
    bool extSig = info->sig == bpfmlir::SigFamily::ExtSig; // ext replacement signature feeds extret/extarg and BTF FUNC_PROTO.
    bool opsSig = info->sig == bpfmlir::SigFamily::OpsSig; // struct_ops member signature feeds structop retsig/farg.
    if (info->sig == bpfmlir::SigFamily::FuncRet || info->sig == bpfmlir::SigFamily::IntArgs || extSig || opsSig) { // fmod_ret also supplies retsig for return-value replacement.
      if (!nv || !rv)
        return err(where + ": a " + p.kind + " program needs nargs and ret (" +
                   (extSig   ? "the signature of the BPF function it replaces"
                    : opsSig ? "the signature of the struct_ops member it implements"
                             : "the signature of the kernel function — its return value sits after nargs arguments") +
                   ")");
      std::optional<int64_t> n = nv->getAsInteger();
      if (!n || *n < 0 || *n > (extSig ? 5 : 12))
        return err(where + (extSig ? ": nargs must be an integer in 0..5 (a BPF function takes at most 5 arguments)" : ": nargs must be an integer in 0..12"));
      p.nargs = *n;
      if (opsSig && p.args.size() > static_cast<size_t>(p.nargs))
        return err(where + ": args of a " + p.kind + " program declare " + std::to_string(p.args.size()) + " arguments, more than nargs " +
                   std::to_string(p.nargs) + "");
      // Void struct_ops members explicitly declare ret:void and return no value.
      if (opsSig && rv->getAsString() && *rv->getAsString() == "void") {
        p.retVoid = true; // Leave the unused p.ret default unchanged.
      } else {
        if (rv->getAsString())
          return err(where + ": ret must be an int type" + (opsSig ? std::string(" or \"void\"") : std::string()));
        auto rt = parseType(*rv, where + " ret");
        if (!rt)
          return rt.takeError();
        const auto *ri = std::get_if<IntType>(&rt->v);
        if (!ri)
          return err(where + ": ret must be an int type");
        if (extSig && ri->bits != 32 && ri->bits != 64)
          return err(where + ": ret of a " + p.kind + " program must be a 32- or 64-bit integer (ebpf.return returns i32 or i64)");
        p.ret = *ri;
      }
      if (extSig && p.args.size() != static_cast<size_t>(p.nargs))
        return err(where + ": args of a " + p.kind + " program must declare all " + std::to_string(p.nargs) + " arguments (got " +
                   std::to_string(p.args.size()) + ")");
    } else if (nv || rv) {
      return err(where + ": nargs and ret are only for " + bpfmlir::joinProgramKinds([](auto &k) { return k.sig == bpfmlir::SigFamily::FuncRet || k.sig == bpfmlir::SigFamily::IntArgs ||
                                                                                                    k.sig == bpfmlir::SigFamily::ExtSig || k.sig == bpfmlir::SigFamily::OpsSig; }, "", ", ", " and ") + " programs");
    }
    // Probe families require target/arch and optionally declare read parameter types.
    const json::Value *archV = o->get("arch");
    const json::Value *paramsV = o->get("params");
    if (info->arch) { // Architecture requirement from the program-kind table.
      auto arch = getStr(*o, "arch", where);
      if (!arch)
        return arch.takeError();
      p.arch = arch->str();
      if (p.arch != "x86_64")
        return err(where + ": arch must be \"x86_64\" (the compiler has the calling convention and pt_regs of x86_64 only), got \"" + p.arch + "\"");
      // Return probes cannot read entry argument registers, which are clobbered.
      // ksyscall shares ProbeRet shape to avoid wrapper-register declarations,
      // but its params describe syscall arguments through sysarg indices 1..6.
      bool sysParams = info->attach == bpfmlir::AttachForm::SyscallName;
      if (paramsV && info->sig == bpfmlir::SigFamily::ProbeRet && !sysParams)
        return err(where + ": a " + p.kind + " program has no params (it runs at the function's return — read the return value with ebpf.probe.retval)");
      // Params belong to probe families. perf_event architecture instead establishes
      // fixed bpf_perf_event_data offsets and declares no arguments.
      if (paramsV && info->sig != bpfmlir::SigFamily::Probe && !sysParams)
        return err(where + ": a " + p.kind + " program has no params (its arch is the premise of the fixed ctx offsets — read the ctx with ebpf.ctx.field)");
      // Share parameter parsing for common params and multi-target target_params.
      auto parseParams = [&](const json::Value &v, const std::string &w, const std::string &kc, std::vector<Program::Param> &out) -> Error {
        // w prefixes parameter diagnostics; kc preserves key/type diagnostic context.
        const auto *pa = v.getAsArray();
        if (!pa)
          return err(w + " must be an array");
        auto declared = [&](int64_t n) { return llvm::any_of(out, [&](const Program::Param &q) { return q.n == n; }); };
        for (const json::Value &qv : *pa) {
          const auto *qo = qv.getAsObject();
          if (!qo)
            return err(w + " entries must be objects");
          if (Error e = requireOnlyKeys(*qo, kKeysProgramParam, kc))
            return e;
          const json::Value *nn = qo->get("n");
          std::optional<int64_t> n = nn ? nn->getAsInteger() : std::nullopt;
          if (!n || *n < 1)
            return err(w + " n must be an integer >= 1 (the argument number, 1-based)");
          if (declared(*n))
            return err(w + " n " + std::to_string(*n) + " is declared twice");
          const json::Value *tv = qo->get("type");
          if (!tv)
            return err(w + " entry needs a type");
          // a buffer address is a distinct typed source, only in user probes.
          if (const auto *to = tv->getAsObject(); to && to->getString("kind") == std::optional<StringRef>("user_buf")) {
            if (!bpfmlir::kindAllows(*info, "uprobe.arg"))
              return err(where + ": a user_buf param is only for uprobe and uprobe_multi programs");
            if (Error e = requireOnlyKeys(*to, kKeysProgramParamUserBuf, kc + " type"))
              return e;
            Program::Param bp{*n, IntType{}};
            bp.type.bits = 64;
            bp.userBuf = true;
            out.push_back(bp);
            continue;
          }
          // user_str is a pointer parameter with no other keys; reject it for kprobes.
          if (const auto *to = tv->getAsObject(); to && to->getString("kind") == std::optional<StringRef>("user_str_array")) {
            if (!sysParams)
              return err(where + ": a user_str_array param is only for ksyscall programs");
            if (Error e = requireOnlyKeys(*to, kKeysProgramParamUserStrArray, kc + " type"))
              return e;
            Program::Param up{*n, IntType{}, false, false, true};
            up.type.bits = 64;
            out.push_back(up);
            continue;
          }
          if (const auto *to = tv->getAsObject(); to && to->getString("kind") == std::optional<StringRef>("user_str")) {
            if (!bpfmlir::kindAllows(*info, "uprobe.arg") && !sysParams) // syscall string pointers are a typed source too.
              return err(where + ": a user_str param is only for " + bpfmlir::kindsAllowing("uprobe.arg") + " programs, or ksyscall programs");
            if (Error e = requireOnlyKeys(*to, kKeysProgramParamUserStr, kc + " type"))
              return e;
            Program::Param up{*n, IntType{}, true};
            up.type.bits = 64;
            out.push_back(up);
            continue;
          }
          // Raw eight-byte pointer identity; never dereference this integer.
          if (const auto *to = tv->getAsObject(); to && to->getString("kind") == std::optional<StringRef>("ptr")) {
            if (!bpfmlir::kindAllows(*info, "kprobe.arg") && !bpfmlir::kindAllows(*info, "uprobe.arg") && !sysParams)
              return err(where + ": a ptr param is only for kprobe, kprobe_multi, uprobe, uprobe_multi and ksyscall programs");
            if (Error e = requireOnlyKeys(*to, kKeysProgramParamPtr, kc + " type"))
              return e;
            Program::Param pp{*n, IntType{}, false, true};
            pp.type.bits = 64;
            out.push_back(pp);
            continue;
          }
          auto t = parseType(*tv, kc + " type");
          if (!t)
            return t.takeError();
          const auto *ti = std::get_if<IntType>(&t->v);
          if (!ti)
            return err(w + " type must be an int");
          out.push_back({*n, *ti});
        }
        return Error::success();
      };
      if (paramsV)
        if (Error e = parseParams(*paramsV, where + ": params", where + " params", p.params))
          return std::move(e);
      // Syscalls have at most six arguments, matching sysarg indices 1..6.
      if (sysParams)
        for (const Program::Param &q : p.params)
          if (q.n > 6)
            return err(where + ": params n " + std::to_string(q.n) + " is not a syscall argument (a syscall takes at most 6 arguments)");
      // target_params requires multi-entry probe.target_arg support, matches
    // attach_target length and is exclusive with shared params.
      if (const json::Value *tpV = o->get("target_params")) {
        if (!bpfmlir::kindAllows(*info, "probe.target_arg"))
          return err(where + ": target_params is only for " + bpfmlir::kindsAllowing("probe.target_arg") + " programs");
        if (paramsV)
          return err(where + ": target_params and params are exclusive (declare every argument per attach target)");
        const auto *ta = tpV->getAsArray();
        if (!ta)
          return err(where + ": target_params must be an array of params arrays, one per attach target");
        if (ta->size() != p.attachTargets.size())
          return err(where + ": target_params has " + std::to_string(ta->size()) + " entries, but attach_target lists " +
                     std::to_string(p.attachTargets.size()) + " targets");
        for (auto [i, tv] : llvm::enumerate(*ta)) {
          p.targetParams.emplace_back();
          if (Error e = parseParams(tv, where + ": target_params[" + std::to_string(i) + "]", where + " target_params[" + std::to_string(i) + "]", p.targetParams.back()))
            return std::move(e);
        }
      }
    } else if (o->get("target_params")) { // Kinds without architecture declarations cannot have target_params.
      return err(where + ": target_params is only for " + bpfmlir::kindsAllowing("probe.target_arg") + " programs");
    } else if (archV || paramsV) {
      return err(where + ": arch and params are only for " + bpfmlir::joinProgramKinds([](auto &k) { return k.arch; }, "", ", ", " and ") + " programs");
    }
    // USDT permits at most twelve arguments, matching spec-map slots and usdtarg.
    if (info->attach == bpfmlir::AttachForm::UsdtProbe)
      for (const Program::Param &q : p.params)
        if (q.n > kUsdtMaxArgs)
          return err(where + ": params n " + std::to_string(q.n) + " of a " + p.kind + " program must be 1.." + std::to_string(kUsdtMaxArgs) +
                     " (a USDT probe has at most " + std::to_string(kUsdtMaxArgs) + " arguments)");
    // Uprobe families and USDT require binary content SHA-256; other kinds cannot declare it.
    if (bpfmlir::attachesUserBinary(info->attach)) { // User-binary attachment shapes include uprobe, multi-uprobe and USDT.
      auto sha = getStr(*o, "binary_sha256", where);
      if (!sha)
        return sha.takeError();
      p.binarySHA256 = sha->str();
      if (p.binarySHA256.size() != 64 ||
          !llvm::all_of(p.binarySHA256, [](char c) { return llvm::isDigit(c) || (c >= 'a' && c <= 'f'); }))
        return err(where + ": binary_sha256 must be 64 lowercase hex digits (the SHA-256 of the user binary's content)");
    } else if (o->get("binary_sha256")) {
      return err(where + ": binary_sha256 is only for " + bpfmlir::joinProgramKinds([](auto &k) { return bpfmlir::attachesUserBinary(k.attach); }, "", ", ", " and ") + " programs");
    }
    // USDT requires semaphore required/none and max_points. Loader usdt_attach
    // declares semaphore handling; compiler sets spec-map max_entries, and
    // usdt_probe matching rejects more note points than available slots.
    if (info->attach == bpfmlir::AttachForm::UsdtProbe) {
      auto sem = getStr(*o, "semaphore", where);
      if (!sem)
        return sem.takeError();
      if (*sem != "required" && *sem != "none")
        return err(where + ": semaphore must be \"required\" or \"none\" (whether the USDT probe's points are guarded by a semaphore), got \"" +
                   *sem + "\"");
      p.usdtSemaphore = sem->str();
      auto mp = getU64(*o, "max_points", where);
      if (!mp)
        return mp.takeError();
      if (*mp < 1 || *mp > kUsdtMaxPoints)
        return err(where + ": max_points must be 1.." + std::to_string(kUsdtMaxPoints) +
                   " (the entries of the compiler's USDT spec map — one per probe point)");
      p.usdtMaxPoints = *mp;
    } else if (o->get("semaphore") || o->get("max_points")) {
      return err(where + ": semaphore and max_points are only for " +
                 bpfmlir::joinProgramKinds([](auto &k) { return k.attach == bpfmlir::AttachForm::UsdtProbe; }, "", ", ", " and ") + " programs");
    }
    // Only tracepoint declares optional event fields. Require offset >= 8 because
    // the first eight bytes become pt_regs*, natural width alignment, and
    // offset+width <= 8192 (tp_prog_is_valid_access). Names and byte ranges
    // cannot overlap; tpfield requirements use strictly increasing offsets.
    if (const json::Value *fv = o->get("fields")) {
      if (info->attach != bpfmlir::AttachForm::TracefsEvent)
        return err(where + ": fields is only for " +
                   bpfmlir::joinProgramKinds([](auto &k) { return k.attach == bpfmlir::AttachForm::TracefsEvent; }, "", ", ", " and ") +
                   " programs (the fields of the tracefs event record it reads)");
      const auto *fa = fv->getAsArray();
      if (!fa)
        return err(where + ": fields must be an array");
      if (fa->empty())
        return err(where + ": fields must not be empty (omit it instead)");
      StringSet<> fNames;
      std::set<uint64_t> fOffsets;
      for (const json::Value &e : *fa) {
        const auto *fo = e.getAsObject();
        if (!fo)
          return err(where + ": fields entries must be objects");
        if (Error er = requireOnlyKeys(*fo, kKeysProgramField, where + " fields"))
          return std::move(er);
        auto fname = getStr(*fo, "name", where + " fields");
        if (!fname)
          return fname.takeError();
        if (fname->empty() || !(llvm::isAlpha((*fname)[0]) || (*fname)[0] == '_') ||
            !llvm::all_of(*fname, [](char c) { return llvm::isAlnum(c) || c == '_'; }))
          return err(where + ": fields name \"" + *fname + "\" must be a C identifier (the field name in the tracefs format)");
        if (!fNames.insert(*fname).second)
          return err(where + ": fields name \"" + *fname + "\" is declared twice");
        const json::Value *ov = fo->get("offset");
        std::optional<int64_t> off = ov ? ov->getAsInteger() : std::nullopt;
        if (!off || *off < 0)
          return err(where + ": fields \"" + *fname + "\" needs an integer offset >= 0 (bytes from the start of the record, as in the tracefs format)");
        const json::Value *tv = fo->get("type");
        if (!tv)
          return err(where + ": fields \"" + *fname + "\" needs a type");
        const auto *typeObject = tv->getAsObject();
        bool userStr = typeObject && typeObject->getString("kind") == std::optional<StringRef>("user_str");
        bool userStrArray = typeObject && typeObject->getString("kind") == std::optional<StringRef>("user_str_array");
        bool byteArray = typeObject && typeObject->getString("kind") == std::optional<StringRef>("array");
        uint64_t arrayCount = 0;
        Type fieldType{IntType{}};
        if (byteArray) {
          if (Error e = requireOnlyKeys(*typeObject, kKeysProgramFieldArray, where + " fields type"))
            return std::move(e);
          auto elem = typeObject->getString("elem");
          auto n = typeObject->getInteger("n");
          if (!elem || (*elem != "u8" && *elem != "i8") || !n || *n < 1 || *n > 64)
            return err(where + ": fields array type needs elem u8 / i8 and integer n from 1 to 64");
          arrayCount = static_cast<uint64_t>(*n);
          fieldType = Type{IntType{8, *elem == "i8", Endianness::Little, 1}};
        } else if (userStr || userStrArray) {
          if (Error e = userStrArray ? requireOnlyKeys(*typeObject, kKeysProgramFieldUserStrArray, where + " fields type")
                                    : requireOnlyKeys(*typeObject, kKeysProgramFieldUserStr, where + " fields type"))
            return std::move(e);
          fieldType = Type{IntType{64, false, Endianness::Little, 8}};
        } else {
          auto t = parseType(*tv, where + " fields type");
          if (!t)
            return t.takeError();
          fieldType = std::move(*t);
        }
        const auto *it = std::get_if<IntType>(&fieldType.v);
        if (!it || it->endianness != Endianness::Little || it->alignment != it->bits / 8)
          return err(where + ": fields \"" + *fname + "\" type must be a little-endian integer of 8 / 16 / 32 / 64 bits with the natural alignment");
        int64_t bytes = arrayCount ? arrayCount : it->bits / 8;
        if (*off < mlir::bpfabi::kTracepointFirstField)
          return err(where + ": fields \"" + *fname + "\" offset " + std::to_string(*off) +
                     " is in the first 8 bytes of the record (the common header — the kernel replaces it with a pt_regs pointer)");
        if (!arrayCount && *off % bytes != 0)
          return err(where + ": fields \"" + *fname + "\" offset " + std::to_string(*off) + " must be a multiple of its width " + std::to_string(bytes));
        if (*off + bytes > mlir::bpfabi::kTracepointMaxCtx)
          return err(where + ": fields \"" + *fname + "\" offset " + std::to_string(*off) + " + " + std::to_string(bytes) + " bytes is beyond the " +
                     std::to_string(mlir::bpfabi::kTracepointMaxCtx) + "-byte record a tracepoint program reads");
        // Syscall BPF contexts differ from tracefs records: enter has nr at eight
        // and args[6] at 16+8k; exit has nr at eight and ret at sixteen. Other
        // tracefs fields such as __data_loc __buf_val would read different data.
        // Keep agreement with requirements.SyscallsCtxProblem.
        if (auto [cat, ev] = StringRef(p.attachTarget).split('/'); cat == "syscalls") {
          if (arrayCount)
            return err(where + ": inline array fields are not part of the BPF context of syscalls events");
          bool inCtx = (*off == 8 && bytes == 4) ||
                       (ev.starts_with("sys_enter_") && *off >= 16 && *off < 64 && (*off - 16) % 8 == 0 && bytes == 8) ||
                       (ev.starts_with("sys_exit_") && *off == 16 && bytes == 8);
          if (!inCtx)
            return err(where + ": fields \"" + *fname + "\" (offset " + std::to_string(*off) + ", " + std::to_string(bytes) +
                       " bytes) is not part of the BPF context of syscalls events (struct syscall_trace_enter: nr at 8 (4 bytes), "
                       "args[6] at 16 + 8k (8 bytes); struct syscall_trace_exit: nr at 8, ret at 16 (8 bytes)) — the tracefs format of a "
                       "syscalls event is not what a BPF program reads");
        }
        if (!fOffsets.insert(static_cast<uint64_t>(*off)).second)
          return err(where + ": fields \"" + *fname + "\" offset " + std::to_string(*off) + " is declared twice");
        p.fields.push_back({fname->str(), static_cast<uint64_t>(*off), *it, userStr, userStrArray, arrayCount});
      }
    }

    auto pMaps = getArr(*o, "maps", where);
    if (!pMaps)
      return pMaps.takeError();
    StringSet<> bound;
    for (const json::Value &mv : **pMaps) {
      auto ms = mv.getAsString();
      if (!ms)
        return err(where + ": maps entries must be strings");
      if (!mapSymbols.contains(*ms))
        return err(where + ": map symbol \"" + *ms +
                   "\" is not declared in the schema");
      if (!bound.insert(*ms).second)
        return err(where + ": map symbol \"" + *ms + "\" is bound twice");
      p.maps.push_back(ms->str());
    }
    s.programs_.push_back(std::move(p));
  }
  // Synthesize one USDT array-map per program: u32 cookie key, max_points
  // entries, 192-byte ebpf_usdt_spec value with twelve 16-byte argument slots
  // (kind at +0, reg at +1, off i64 at +8). Loaders populate specs from notes;
  // usdt.arg looks them up by cookie. Omit synthesized maps/records from
  // canonical JSON so reparsing synthesizes them once, not twice.
  for (const Program &p : s.programs_) {
    const bpfmlir::ProgramKindInfo *pk = bpfmlir::lookupProgramKind(p.kind);
    if (!pk || pk->attach != bpfmlir::AttachForm::UsdtProbe)
      continue;
    if (!llvm::any_of(s.records_, [](const Record &r) { return r.symbol == kUsdtSpecRecord; })) {
      Record r;
      r.symbol = kUsdtSpecRecord;
      r.size = r.minSize = kUsdtSpecBytes;
      r.alignment = 8;
      r.synthesized = true;
      r.note = "the compiler's USDT spec (requirements_format.md §8)";
      for (int i = 1; i <= kUsdtMaxArgs; ++i) {
        uint64_t base = static_cast<uint64_t>(kUsdtArgSpecBytes) * (i - 1);
        auto intField = [&](std::string name, uint32_t bits, bool sgn, uint64_t off) {
          Field f;
          f.name = std::move(name);
          IntType t;
          t.bits = bits;
          t.isSigned = sgn;
          t.alignment = bits / 8;
          f.type = Type{t};
          f.offset = off;
          f.expose = "int";
          r.fields.push_back(std::move(f));
        };
        intField("kind" + std::to_string(i), 8, false, base + kUsdtArgKindOffset);
        intField("reg" + std::to_string(i), 8, false, base + kUsdtArgRegOffset);
        intField("off" + std::to_string(i), 64, true, base + kUsdtArgOffOffset);
      }
      s.records_.push_back(std::move(r));
    }
    Map m;
    m.symbol = kUsdtSpecMapPrefix + p.name;
    if (s.program(m.symbol) || llvm::any_of(s.maps_, [&](const Map &o) { return o.symbol == m.symbol; }))
      return err("program \"" + p.name + "\": the USDT spec map \"" + m.symbol + "\" collides with another symbol");
    m.kind = MapKind::Array;
    IntType k;
    k.bits = 32;
    k.alignment = 4;
    m.key = Type{k};
    m.value = Type{RecordRefType{kUsdtSpecRecord}};
    m.maxEntries = p.usdtMaxPoints;
    m.synthesized = true;
    m.note = "the compiler's USDT spec map of program " + p.name;
    s.maps_.push_back(std::move(m));
  }
  // Inner templates must name schema hash/array-family maps with program map
  // operations, no lock/timer and no binding in any program maps list.
  // Exclude lpm_trie, ring buffers, storage and nested map-in-map; only one
  // level is supported. Templates are not emitted as standalone .maps objects.
  for (const Map &m : s.maps_) {
    if (m.inner.empty())
      continue;
    std::string where = "map \"" + m.symbol + "\"";
    const Map *t = nullptr;
    for (const Map &o : s.maps_)
      if (o.symbol == m.inner)
        t = &o;
    if (!t || t == &m)
      return err(where + ": inner \"" + m.inner + "\" must name another map in core.maps (the inner map template)");
    if (t->kind != MapKind::Hash && t->kind != MapKind::Array && t->kind != MapKind::PerCpuArray && t->kind != MapKind::PerCpuHash &&
        t->kind != MapKind::LruHash && t->kind != MapKind::LruPerCpuHash)
      return err(where + ": the inner map template \"" + t->symbol + "\" is a \"" + mapKindName(t->kind) +
                 "\" map; it must be hash, array, percpu_array, percpu_hash, lru_hash or lru_percpu_hash");
    if (lockRecords.count(t->value && std::holds_alternative<RecordRefType>(t->value->v) ? std::get<RecordRefType>(t->value->v).symbol : "") ||
        timerRecords.count(t->value && std::holds_alternative<RecordRefType>(t->value->v) ? std::get<RecordRefType>(t->value->v).symbol : ""))
      return err(where + ": the inner map template \"" + t->symbol + "\" holds a spin_lock / timer (out of scope)");
    for (const Program &p : s.programs_)
      if (llvm::is_contained(p.maps, t->symbol))
        return err("program \"" + p.name + "\": the inner map template \"" + t->symbol + "\" of \"" + m.symbol +
                   "\" is not a program map (it is only the type of the inner maps; leave it out of maps)");
  }
  // Each ops program must be this schema's struct_ops program targeting that
  // map (reverse validation). Programs cannot bind operation tables as maps:
  // loaders populate them rather than exposing !ebpf.map handles.
  for (const Map &m : s.maps_) {
    for (const Program &p : s.programs_)
      if (m.kind == MapKind::StructOps && llvm::is_contained(p.maps, m.symbol))
        return err("program \"" + p.name + "\": the struct_ops map \"" + m.symbol + "\" is not a program map (leave it out of maps)");
    if (!m.structOps)
      continue;
    // Only one local ELF BTF struct per kernel type is supported; reject a second ops table of that type.
    for (const Map &o : s.maps_)
      if (&o != &m && o.structOps && o.structOps->type == m.structOps->type)
        return err("map \"" + o.symbol + "\": a second struct_ops map of type \"" + m.structOps->type +
                   "\" (the compiler emits one local struct per type)");
    for (const Map::StructOps::Op &q : m.structOps->ops) {
      const Program *p = s.program(q.program);
      if (!p || p->kind != "struct_ops" || p->attachTarget != m.symbol)
        return err("map \"" + m.symbol + "\": struct_ops op \"" + q.member + "\" names program \"" + q.program +
                   "\", which is not a struct_ops program of core.programs with attach_target \"" + m.symbol + "\"");
    }
  }

  // Optional globals use C identifiers because they become ELF symbols.
  auto isCIdentifier = [](StringRef n) {
    if (n.empty() || !(llvm::isAlpha(n[0]) || n[0] == '_'))
      return false;
    return llvm::all_of(n, [](char c) { return llvm::isAlnum(c) || c == '_'; });
  };
  if (const json::Value *gv = (*coreObj)->get("globals")) {
    const auto *ga = gv->getAsArray();
    if (!ga)
      return err("core.globals must be an array");
    StringSet<> gNames;
    for (const json::Value &v : *ga) {
      const auto *o = v.getAsObject();
      if (!o)
        return err("core.globals: entry must be an object");
      if (Error e = requireOnlyKeys(*o, kKeysGlobal, "core.globals"))
        return std::move(e);
      Global g;
      auto name = getStr(*o, "name", "core.globals");
      if (!name)
        return name.takeError();
      g.name = name->str();
      if (!gNames.insert(g.name).second)
        return err("core.globals: duplicate global \"" + g.name + "\"");
      // Globals share the ELF symbol namespace with maps, programs and compiler
      // reservations. A collision could otherwise resolve a map global as data
      // and silently compile an incorrect program.
      if (!isCIdentifier(g.name))
        return err("core.globals: global name \"" + g.name + "\" must be a C identifier (it is an ELF symbol)");
      for (const Map &m : s.maps_)
        if (m.symbol == g.name)
          return err("core.globals: global \"" + g.name + "\" has the same name as a map (ELF symbols share one namespace)");
      for (const Program &p : s.programs_)
        if (p.name == g.name)
          return err("core.globals: global \"" + g.name + "\" has the same name as a program (ELF symbols share one namespace)");
      if (g.name == "_license" || StringRef(g.name).starts_with("__ebpf"))
        return err("core.globals: global name \"" + g.name + "\" is reserved by the compiler");
      std::string where = "global \"" + g.name + "\"";
      auto sec = getStr(*o, "section", where);
      if (!sec)
        return sec.takeError();
      g.section = sec->str();
      if (g.section != "rodata" && g.section != "bss")
        return err(where + ": section must be \"rodata\" or \"bss\", got \"" + g.section + "\"");
      const json::Value *tv = o->get("type");
      if (!tv)
        return err(where + ": needs a type");
      auto t = parseType(*tv, where + " type");
      if (!t)
        return t.takeError();
      const auto *it = std::get_if<IntType>(&t->v);
      if (!it)
        return err(where + ": type must be an int (integer globals only)");
      g.type = *it;
      if (Error e = optStrInto(*o, "note", "core.globals", g.note))
        return std::move(e);
      s.globals_.push_back(std::move(g));
    }
  }

  //===------------------------------------------------------------------===//
  // telemetry
  //===------------------------------------------------------------------===//
  auto telObj = getObj(*root, "telemetry", "schema");
  if (!telObj)
    return telObj.takeError();
  if (Error e = requireOnlyKeys(**telObj, kKeysTelemetry,
          "telemetry"))
    return std::move(e);

  // ---- clocks ----
  auto clockArr = getArr(**telObj, "clocks", "telemetry");
  if (!clockArr)
    return clockArr.takeError();
  StringSet<> clockIds;
  for (const json::Value &v : **clockArr) {
    const auto *o = v.getAsObject();
    if (!o)
      return err("telemetry.clocks: entry must be an object");
    if (Error e = requireOnlyKeys(*o, kKeysClock,
            "telemetry.clocks"))
      return std::move(e);
    Clock c;
    auto id = getStr(*o, "id", "telemetry.clocks");
    if (!id)
      return id.takeError();
    c.id = id->str();
    if (!clockIds.insert(c.id).second)
      return err("telemetry.clocks: duplicate clock id \"" + c.id + "\"");
    std::string where = "clock \"" + c.id + "\"";
    auto ks = getStr(*o, "kernel_source", where);
    if (!ks)
      return ks.takeError();
    c.kernelSource = ks->str();
    auto pc = getStr(*o, "posix_clock", where);
    if (!pc)
      return pc.takeError();
    c.posixClock = pc->str();
    auto tw = getStr(*o, "to_wall", where);
    if (!tw)
      return tw.takeError();
    c.toWall = tw->str();
    if (Error e = optStrInto(*o, "note", "telemetry.clocks", c.note))
      return std::move(e);
    s.clocks_.push_back(std::move(c));
  }

  // ---- value_maps ----
  auto vmArr = getArr(**telObj, "value_maps", "telemetry");
  if (!vmArr)
    return vmArr.takeError();
  StringSet<> vmIds;
  for (const json::Value &v : **vmArr) {
    const auto *o = v.getAsObject();
    if (!o)
      return err("telemetry.value_maps: entry must be an object");
    if (Error e = requireOnlyKeys(*o, kKeysValueMap,
                                  "telemetry.value_maps"))
      return std::move(e);
    ValueMap vm;
    auto id = getStr(*o, "id", "telemetry.value_maps");
    if (!id)
      return id.takeError();
    vm.id = id->str();
    if (!vmIds.insert(vm.id).second)
      return err("telemetry.value_maps: duplicate id \"" + vm.id + "\"");
    std::string where = "value_map \"" + vm.id + "\"";
    if (Error e = optStrInto(*o, "unknown", "telemetry.value_maps", vm.unknown))
      return std::move(e);
    if (Error e = requirePresentKind(*o, "arch_invariant", "telemetry.value_maps", json::Value::Boolean, "a boolean"))
      return std::move(e);
    if (auto ai = o->getBoolean("arch_invariant"))
      vm.archInvariant = *ai;
    if (Error e = optStrInto(*o, "btf_mode", "telemetry.value_maps", vm.btfMode))
      return std::move(e);
    if (Error e = optStrInto(*o, "btf_anchor", "telemetry.value_maps", vm.btfAnchor))
      return std::move(e);
    if (Error e = optStrInto(*o, "btf_prefix", "telemetry.value_maps", vm.btfPrefix))
      return std::move(e);
    if (Error e = optStrInto(*o, "btf_omit", "telemetry.value_maps", vm.btfOmit))
      return std::move(e);
    if (Error e = optStrInto(*o, "authority", "telemetry.value_maps", vm.authority))
      return std::move(e);
    if (Error e = optStrInto(*o, "note", "telemetry.value_maps", vm.note))
      return std::move(e);
    if (!vm.btfMode.empty() && vm.btfAnchor.empty())
      return err(where + ": btf_mode needs a btf_anchor to check against");
    auto entries = getArr(*o, "entries", where);
    if (!entries)
      return entries.takeError();
    std::set<int64_t> seen;
    for (const json::Value &ev : **entries) {
      const auto *eo = ev.getAsObject();
      if (!eo)
        return err(where + ": entry must be an object");
      if (Error e = requireOnlyKeys(*eo, kKeysValueMapEntry, where + " entry"))
        return std::move(e);
      auto val = eo->getInteger("value");
      if (!val)
        return err(where + ": entry missing integer \"value\"");
      if (!seen.insert(*val).second)
        return err(where + ": duplicate value " + Twine(*val));
      auto nm = getStr(*eo, "name", where + " entry");
      if (!nm)
        return nm.takeError();
      vm.entries.push_back({*val, nm->str()});
    }
    s.valueMaps_.push_back(std::move(vm));
  }

  // ---- bounds_sets ----
  auto bsArr = getArr(**telObj, "bounds_sets", "telemetry");
  if (!bsArr)
    return bsArr.takeError();
  StringSet<> bsIds;
  for (const json::Value &v : **bsArr) {
    const auto *o = v.getAsObject();
    if (!o)
      return err("telemetry.bounds_sets: entry must be an object");
    if (Error e = requireOnlyKeys(*o, kKeysBoundsSet,
            "telemetry.bounds_sets"))
      return std::move(e);
    BoundsSet b;
    auto id = getStr(*o, "id", "telemetry.bounds_sets");
    if (!id)
      return id.takeError();
    b.id = id->str();
    if (!bsIds.insert(b.id).second)
      return err("telemetry.bounds_sets: duplicate id \"" + b.id + "\"");
    std::string where = "bounds_set \"" + b.id + "\"";
    auto unit = getStr(*o, "unit", where);
    if (!unit)
      return unit.takeError();
    b.unit = unit->str();
    if (Error e = optStrInto(*o, "authority", "telemetry.bounds_sets", b.authority))
      return std::move(e);
    if (Error e = optStrInto(*o, "note", "telemetry.bounds_sets", b.note))
      return std::move(e);
    auto bounds = getArr(*o, "bounds", where);
    if (!bounds)
      return bounds.takeError();
    double prev = -std::numeric_limits<double>::infinity();
    for (const json::Value &bv : **bounds) {
      auto d = bv.getAsNumber();
      if (!d)
        return err(where + ": bounds entries must be numbers");
      if (*d <= prev)
        return err(where + ": bounds must be strictly increasing");
      prev = *d;
      b.bounds.push_back(*d);
    }
    if (b.bounds.empty())
      return err(where + ": bounds must not be empty");
    s.boundsSets_.push_back(std::move(b));
  }

  // ---- signals ----
  auto sigArr = getArr(**telObj, "signals", "telemetry");
  if (!sigArr)
    return sigArr.takeError();
  StringSet<> sigNames;
  for (const json::Value &v : **sigArr) {
    const auto *o = v.getAsObject();
    if (!o)
      return err("telemetry.signals: entry must be an object");
    if (Error e = requireOnlyKeys(*o, kKeysSignal,
                                  "telemetry.signals"))
      return std::move(e);
    Signal sig;
    auto name = getStr(*o, "name", "telemetry.signals");
    if (!name)
      return name.takeError();
    sig.name = name->str();
    if (!sigNames.insert(sig.name).second)
      return err("telemetry.signals: duplicate signal name \"" + sig.name +
                 "\"");
    std::string where = "signal \"" + sig.name + "\"";

    auto kind = getStr(*o, "signal", where);
    if (!kind)
      return kind.takeError();
    sig.signal = kind->str();
    if (sig.signal != "traces" && sig.signal != "metrics" &&
        sig.signal != "logs")
      return err(where + ": signal must be \"traces\", \"metrics\" or "
                         "\"logs\", got \"" +
                 sig.signal + "\"");

    auto rec = getStr(*o, "record", where);
    if (!rec)
      return rec.takeError();
    sig.record = rec->str();
    if (!recSymbols.contains(sig.record))
      return err(where + ": record \"" + sig.record +
                 "\" is not declared in core.records");

    if (Error e = optStrInto(*o, "span_name", "telemetry.signals", sig.spanName))
      return std::move(e);
    if (Error e = optStrInto(*o, "span_kind", "telemetry.signals", sig.spanKind))
      return std::move(e);
    if (Error e = optStrInto(*o, "note", "telemetry.signals", sig.note))
      return std::move(e);

    auto timing = getObj(*o, "timing", where);
    if (!timing)
      return timing.takeError();
    if (Error e = requireOnlyKeys(**timing, kKeysSignalTiming,
                                  where + " timing"))
      return std::move(e);
    auto st = getStr(**timing, "start", where + " timing");
    if (!st)
      return st.takeError();
    sig.timing.start = st->str();
    auto ck = getStr(**timing, "clock", where + " timing");
    if (!ck)
      return ck.takeError();
    sig.timing.clock = ck->str();
    // Empty clock means direct wall-clock construction without a kernel clock.
    // Permit empty, but require any explicit clock name to exist.
    if (!sig.timing.clock.empty() && !clockIds.contains(sig.timing.clock))
      return err(where + ": clock \"" + sig.timing.clock +
                 "\" is not declared in telemetry.clocks");
    auto en = getStr(**timing, "end", where + " timing");
    if (!en)
      return en.takeError();
    sig.timing.end = en->str();

    const json::Value *dw = o->get("drop_when");
    if (!dw)
      return err(where + ": missing \"drop_when\" (a signal must say when it "
                         "produces nothing)");
    auto pred = parsePredicate(*dw, where + " drop_when");
    if (!pred)
      return pred.takeError();
    sig.dropWhen = std::move(*pred);

    if (Error e = requirePresentKind(*o, "metric", where, json::Value::Object, "an object"))
      return std::move(e);
    if (const auto *mo = o->getObject("metric")) {
      if (Error e = requireOnlyKeys(*mo, kKeysMetric,
                                    where + " metric"))
        return std::move(e);
      Metric m;
      auto mk = getStr(*mo, "kind", where + " metric");
      if (!mk)
        return mk.takeError();
      m.kind = mk->str();
      // Closed kind set: accepting unknown declarations would claim unsupported
      // content was representable even though no consumer reads it.
      if (m.kind != "sum" && m.kind != "exponential_histogram")
        return err(where + ": metric kind must be \"sum\" or "
                           "\"exponential_histogram\", got \"" +
                   m.kind + "\"");
      auto mu = getStr(*mo, "unit", where + " metric");
      if (!mu)
        return mu.takeError();
      m.unit = mu->str();
      auto mt = getStr(*mo, "temporality", where + " metric");
      if (!mt)
        return mt.takeError();
      m.temporality = mt->str();
      if (m.temporality != "delta" && m.temporality != "cumulative")
        return err(where + ": metric temporality must be \"delta\" or "
                           "\"cumulative\", got \"" +
                   m.temporality + "\"");
      // Required/forbidden fields per kind.
      if (m.kind == "sum") {
        auto mono = getBool(*mo, "monotonic", where + " metric (sum)");
        if (!mono)
          return mono.takeError();
        m.monotonic = *mono;
        if (mo->get("scale") || mo->get("zero_threshold") ||
            mo->get("bucket_rule"))
          return err(where + ": a sum metric takes no scale / zero_threshold "
                             "/ bucket_rule");
      } else { // exponential_histogram
        if (mo->get("monotonic"))
          return err(where +
                     ": an exponential_histogram metric takes no monotonic");
        auto sc = mo->getInteger("scale");
        if (!sc)
          return err(where + " metric (exponential_histogram): missing or "
                             "non-integer \"scale\"");
        m.scale = *sc;
        auto zt = mo->getNumber("zero_threshold");
        if (!zt)
          return err(where + " metric (exponential_histogram): missing or "
                             "non-numeric \"zero_threshold\"");
        if (*zt < 0)
          return err(where + ": zero_threshold must not be negative");
        m.zeroThreshold = *zt;
        auto br = getStr(*mo, "bucket_rule",
                         where + " metric (exponential_histogram)");
        if (!br)
          return br.takeError();
        m.bucketRule = br->str();
        // Scalar-observation to bucket-index mappings form a closed set too,
        // preventing frontend/MLIR/Go disagreement over open/closed boundaries.
        if (m.bucketRule != "otlp_lower_exclusive")
          return err(where + ": bucket_rule must be \"otlp_lower_exclusive\" "
                             "(v > zero_threshold goes to index i with "
                             "base^i < v <= base^(i+1)), got \"" +
                     m.bucketRule + "\"");
      }
      sig.metric = m;
    }
    if (sig.signal == "metrics" && !sig.metric)
      return err(where + ": a metrics signal needs a \"metric\" block");
    if (sig.signal != "metrics" && sig.metric)
      return err(where + ": \"metric\" only applies to metrics signals");
    if (sig.signal == "traces" && sig.spanName.empty())
      return err(where + ": a traces signal needs a span_name");

    auto attrs = getArr(*o, "attributes", where);
    if (!attrs)
      return attrs.takeError();
    StringSet<> attrKeys;
    for (const json::Value &av : **attrs) {
      const auto *ao = av.getAsObject();
      if (!ao)
        return err(where + ": attribute must be an object");
      if (Error e = requireOnlyKeys(*ao, kKeysAttribute,
              where + " attribute"))
        return std::move(e);
      Attribute a;
      auto key = getStr(*ao, "key", where + " attribute");
      if (!key)
        return key.takeError();
      a.key = key->str();
      if (!attrKeys.insert(a.key).second)
        return err(where + ": duplicate attribute key \"" + a.key + "\"");
      std::string awhere = where + " attribute \"" + a.key + "\"";
      auto stab = getStr(*ao, "stability", awhere);
      if (!stab)
        return stab.takeError();
      a.stability = stab->str();
      if (Error e = optStrInto(*ao, "note", "telemetry.signals attribute", a.note))
        return std::move(e);

      auto srcObj = getObj(*ao, "source", awhere);
      if (!srcObj)
        return srcObj.takeError();
      auto src = parseSource(**srcObj, awhere + " source");
      if (!src)
        return src.takeError();
      a.source = std::move(*src);

      const json::Value *pv = ao->get("presence");
      if (!pv)
        return err(awhere + ": missing \"presence\"");
      auto pp = parsePredicate(*pv, awhere + " presence");
      if (!pp)
        return pp.takeError();
      a.presence = std::move(*pp);
      sig.attributes.push_back(std::move(a));
    }

    // Reuse Source for body/value rather than embedding language-specific
    // expressions or exporter function names in this generic layer.
    if (const auto *bo = o->getObject("body")) {
      auto src = parseSource(*bo, where + " body");
      if (!src)
        return src.takeError();
      sig.body = std::move(*src);
    } else if (o->get("body")) {
      return err(where + ": \"body\" must be an object");
    }
    if (const auto *vo = o->getObject("value")) {
      auto src = parseSource(*vo, where + " value");
      if (!src)
        return src.takeError();
      sig.value = std::move(*src);
    } else if (o->get("value")) {
      return err(where + ": \"value\" must be an object");
    }

    // Required/forbidden fields per signal kind.
    if (sig.signal == "logs") {
      if (!sig.body)
        return err(where + ": a logs signal needs a \"body\" (the source of "
                           "the LogRecord body)");
      if (sig.value)
        return err(where + ": \"value\" only applies to metrics signals");
      if (!sig.spanName.empty() || !sig.spanKind.empty())
        return err(where +
                   ": span_name/span_kind only apply to traces signals");
    } else if (sig.signal == "metrics") {
      if (!sig.value)
        return err(where + ": a metrics signal needs a \"value\" (the source "
                           "of the observation)");
      if (sig.body)
        return err(where + ": \"body\" only applies to logs signals");
      if (!sig.spanName.empty() || !sig.spanKind.empty())
        return err(where +
                   ": span_name/span_kind only apply to traces signals");
    } else { // traces
      if (sig.spanKind.empty())
        return err(where + ": a traces signal needs a span_kind");
      if (sig.body || sig.value)
        return err(where + ": body/value do not apply to traces signals");
    }

    // Field-reference consistency.
    const Record *sigRec = findRecordBySymbol(s.records_, sig.record);
    auto checkFieldRef = [&](const Source &src,
                             const std::string &what) -> Error {
      if (src.kind == "field" && !hasFieldPath(s.records_, *sigRec, src.name))
        return err(where + " " + what + ": source field \"" + src.name +
                   "\" is not declared in record \"" + sig.record + "\"");
      if (src.kind == "derived" && !src.from.empty() &&
          !hasFieldPath(s.records_, *sigRec, src.from))
        return err(where + " " + what + ": derived source's \"from\" field \"" +
                   src.from + "\" is not declared in record \"" + sig.record +
                   "\"");
      return Error::success();
    };
    if (sig.body)
      if (Error e = checkFieldRef(*sig.body, "body"))
        return std::move(e);
    if (sig.value) {
      if (Error e = checkFieldRef(*sig.value, "value"))
        return std::move(e);
      // Constant observations must be integers for aggregation; never silently use zero.
      if (sig.value->kind == "constant") {
        int64_t n;
        if (StringRef(sig.value->name).getAsInteger(10, n))
          return err(where + ": a constant metrics value must be an integer "
                             "literal, got \"" +
                     sig.value->name + "\"");
      }
    }
    for (const Attribute &a : sig.attributes)
      if (Error e = checkFieldRef(a.source,
                                  "attribute \"" + a.key + "\""))
        return std::move(e);

    s.signals_.push_back(std::move(sig));
  }

  // Extensions are opaque to core; validate only namespace shape.
  if (const auto *extObj = root->getObject("extensions")) {
    for (const auto &kv : *extObj) {
      StringRef ns = kv.first;
      if (!ns.contains('.'))
        return err("extensions: namespace \"" + ns +
                   "\" must be a reverse-DNS style stable name (containing "
                   "'.')");
      if (ns.starts_with(".") || ns.ends_with(".") || ns.contains(".."))
        return err("extensions: malformed namespace \"" + ns + "\"");
      s.extensions_.emplace(ns.str(), kv.second);
    }
  } else if (root->get("extensions")) {
    return err("schema: \"extensions\" must be an object");
  }

  // Sort every collection by name for canonical output.
  auto bySymbol = [](const auto &a, const auto &b) { return a.symbol < b.symbol; };
  auto byName = [](const auto &a, const auto &b) { return a.name < b.name; };
  auto byId = [](const auto &a, const auto &b) { return a.id < b.id; };
  llvm::sort(s.records_, bySymbol);
  llvm::sort(s.kernelTypes_, byName);
  llvm::sort(s.maps_, bySymbol);
  llvm::sort(s.programs_, byName);
  llvm::sort(s.signals_, byName);
  llvm::sort(s.clocks_, byId);
  llvm::sort(s.valueMaps_, byId);
  llvm::sort(s.boundsSets_, byId);
  return s;
}

// Canonical serialization.
std::string Schema::serializeJSON() const {
  std::string out;
  raw_string_ostream os(out);
  os << "{\n";
  os << "  \"version\": " << kSchemaVersion << ",\n";

  auto cov = [](Coverage c) { return c == Coverage::Complete ? "complete" : "omitted"; };
  os << "  \"coverage\": {\n";
  os << "    \"programs\": \"" << cov(coverage_.programs) << "\",\n";
  os << "    \"maps\": \"" << cov(coverage_.maps) << "\",\n";
  os << "    \"records\": \"" << cov(coverage_.records) << "\",\n";
  os << "    \"telemetry\": \"" << cov(coverage_.telemetry) << "\"\n";
  os << "  },\n";

  // ---- core ----
  os << "  \"core\": {\n";
  // Omit synthesized USDT maps/records: canonical JSON reflects input schema,
  // and parsing regenerates them.
  std::vector<Record> userRecords;
  for (const Record &r : records_)
    if (!r.synthesized)
      userRecords.push_back(r);
  std::vector<Map> userMaps;
  for (const Map &m : maps_)
    if (!m.synthesized)
      userMaps.push_back(m);

  os << "    \"records\": [\n";
  for (auto [i, r] : llvm::enumerate(userRecords)) {
    os << "      {\n";
    os << "        \"symbol\": "; emitStr(os, r.symbol); os << ",\n";
    os << "        \"id\": " << r.id << ",\n";
    os << "        \"size\": " << r.size << ",\n";
    os << "        \"min_size\": " << r.minSize << ",\n";
    os << "        \"alignment\": " << r.alignment << ",\n";
    os << "        \"required_through\": "; emitStr(os, r.requiredThrough); os << ",\n";
    os << "        \"note\": "; emitStr(os, r.note); os << ",\n";
    os << "        \"fields\": [\n";
    for (auto [j, f] : llvm::enumerate(r.fields)) {
      os << "          {\n";
      os << "            \"name\": "; emitStr(os, f.name); os << ",\n";
      os << "            \"offset\": " << f.offset << ",\n";
      os << "            \"expose\": "; emitStr(os, f.expose); os << ",\n";
      os << "            \"note\": "; emitStr(os, f.note); os << ",\n";
      os << "            \"type\": ";
      emitType(os, f.type, 12);
      os << "\n          }" << (j + 1 < r.fields.size() ? "," : "") << "\n";
    }
    os << "        ]\n";
    os << "      }" << (i + 1 < userRecords.size() ? "," : "") << "\n";
  }
  os << "    ],\n";

  // Omit empty kernel_types to preserve canonical output for existing schemas.
  if (!kernelTypes_.empty()) {
    os << "    \"kernel_types\": [\n";
    for (auto [i, k] : llvm::enumerate(kernelTypes_)) {
      os << "      {\n";
      os << "        \"name\": "; emitStr(os, k.name); os << ",\n";
      os << "        \"note\": "; emitStr(os, k.note); os << ",\n";
      os << "        \"fields\": [\n";
      for (auto [j, f] : llvm::enumerate(k.fields)) {
        os << "          {\n";
        os << "            \"name\": "; emitStr(os, f.name); os << ",\n";
        os << "            \"note\": "; emitStr(os, f.note); os << ",\n";
        os << "            \"type\": ";
        // Round-trip pointer/array fields in their parsed form, preserving pointee
        // and element counts rather than serializing them as integer placeholders.
        if (!f.embedded.empty()) {
          os << "{\"kind\": \"struct\", \"struct\": "; emitStr(os, f.embedded); os << "}";
        } else if (!f.ptrTo.empty()) {
          os << "{\"kind\": \"kptr\", \"struct\": ";
          emitStr(os, f.ptrTo);
          os << "}";
        } else if (f.strPtr) {
          os << "{\"kind\": \"strptr\"}";
        } else if (f.arrayCount) {
          ArrayType at;
          at.element = std::make_unique<Type>(Type{f.type});
          at.count = f.arrayCount;
          emitType(os, Type{std::move(at)}, 12);
        } else {
          emitType(os, Type{f.type}, 12);
        }
        os << "\n          }" << (j + 1 < k.fields.size() ? "," : "") << "\n";
      }
      os << "        ]\n";
      os << "      }" << (i + 1 < kernelTypes_.size() ? "," : "") << "\n";
    }
    os << "    ],\n";
  }

  os << "    \"maps\": [\n";
  for (auto [i, m] : llvm::enumerate(userMaps)) {
    os << "      {\n";
    os << "        \"symbol\": "; emitStr(os, m.symbol); os << ",\n";
    os << "        \"kind\": \"" << mapKindName(m.kind) << "\",\n";
    if (m.key) {
      os << "        \"key\": ";
      emitType(os, *m.key, 8);
      os << ",\n";
    }
    if (m.value) {
      os << "        \"value\": ";
      emitType(os, *m.value, 8);
      os << ",\n";
    }
    os << "        \"max_entries\": " << m.maxEntries << ",\n";
    os << "        \"flags\": " << m.flags << ",\n";
    os << "        \"record\": "; emitStr(os, m.record); os << ",\n";
    if (!m.slots.empty()) { // Emit prog_array slots only when present, preserving other map output.
      os << "        \"slots\": [";
      for (auto [j, q] : llvm::enumerate(m.slots)) {
        os << (j ? ", " : "") << "{\"index\": " << q.index << ", \"program\": ";
        emitStr(os, q.program);
        os << "}";
      }
      os << "],\n";
    }
    if (m.structOps) { // Emit operation tables only for struct_ops maps.
      os << "        \"struct_ops\": {\"type\": "; emitStr(os, m.structOps->type);
      if (bpfmlir::structOpsDataByKey(m.structOps->type, "name")) { // Types without a name DATA row, such as bpf_dummy_ops, omit name.
        os << ", \"name\": "; emitStr(os, m.structOps->name);
      }
      os << ", \"ops\": [";
      for (auto [j, q] : llvm::enumerate(m.structOps->ops)) {
        os << (j ? ", " : "") << "{\"member\": "; emitStr(os, q.member);
        os << ", \"program\": "; emitStr(os, q.program); os << "}";
      }
      os << "]},\n";
    }
    if (!m.inner.empty()) { // Emit inner templates only when present.
      os << "        \"inner\": "; emitStr(os, m.inner); os << ",\n";
    }
    os << "        \"note\": "; emitStr(os, m.note); os << "\n";
    os << "      }" << (i + 1 < userMaps.size() ? "," : "") << "\n";
  }
  os << "    ],\n";

  os << "    \"programs\": [\n";
  for (auto [i, p] : llvm::enumerate(programs_)) {
    os << "      {\n";
    os << "        \"name\": "; emitStr(os, p.name); os << ",\n";
    os << "        \"kind\": "; emitStr(os, p.kind); os << ",\n";
    os << "        \"attach_target\": ";
    if (const bpfmlir::ProgramKindInfo *ak = bpfmlir::lookupProgramKind(p.kind); ak && bpfmlir::isAttachList(ak->attach)) {
      os << "["; // Multi-probe name lists; other kind output is unchanged.
      for (auto [j, t] : llvm::enumerate(p.attachTargets)) {
        if (j)
          os << ", ";
        emitStr(os, t);
      }
      os << "]";
    } else {
      emitStr(os, p.attachTarget);
    }
    os << ",\n";
    os << "        \"maps\": [";
    for (auto [j, mm] : llvm::enumerate(p.maps)) {
      if (j)
        os << ", ";
      emitStr(os, mm);
    }
    os << "],\n";
    if (!p.args.empty()) { // Omit absent arguments to preserve canonical output.
      os << "        \"args\": [";
      for (auto [j, aa] : llvm::enumerate(p.args)) {
        if (j)
          os << ", ";
        if (aa == "-") { // Unread argument.
          os << "null";
        } else if (!aa.empty() && aa.back() == '?') { // Nullable struct-pointer argument.
          os << "{\"kind\": \"struct\", \"name\": ";
          emitStr(os, StringRef(aa).drop_back());
          os << ", \"nullable\": true}";
        } else if (isTPArgScalarSpelling(aa)) { // Naturally aligned little-endian integer argument.
          IntType it;
          it.bits = std::stoi(aa.substr(1));
          it.isSigned = aa[0] == 'i';
          it.endianness = Endianness::Little;
          it.alignment = it.bits / 8;
          emitTypeBody(os, it, 8);
        } else {
          emitStr(os, aa);
        }
      }
      os << "],\n";
    }
    if (p.nargs >= 0) { // Omit absent return signatures to preserve canonical output.
      os << "        \"nargs\": " << p.nargs << ",\n";
      os << "        \"ret\": ";
      if (p.retVoid) // Void struct_ops member.
        os << "\"void\"";
      else
        emitType(os, Type{p.ret}, 8);
      os << ",\n";
    }
    if (!p.binarySHA256.empty()) { // Omit absent binary hash to preserve canonical output.
      os << "        \"binary_sha256\": "; emitStr(os, p.binarySHA256); os << ",\n";
    }
    if (!p.arch.empty()) { // Omit absent architecture to preserve canonical output.
      os << "        \"arch\": "; emitStr(os, p.arch); os << ",\n";
      // Emit params only for entry probe families. Return probes and perf_event
      // have no params; writing them would fail round-trip parsing.
      const bpfmlir::ProgramKindInfo *pk = bpfmlir::lookupProgramKind(p.kind);
      auto emitParams = [&](const std::vector<Program::Param> &ps) {
        os << "[";
        for (auto [j, q] : llvm::enumerate(ps)) {
          os << (j ? ", " : "") << "{\"n\": " << q.n << ", \"type\": ";
          if (q.userBuf)
            os << "{\"kind\": \"user_buf\"}";
          else if (q.userStrArray)
            os << "{\"kind\": \"user_str_array\"}";
          else if (q.userStr)
            os << "{\"kind\": \"user_str\"}";
          else if (q.ptr)
            os << "{\"kind\": \"ptr\"}";
          else
            emitType(os, Type{q.type}, 8);
          os << "}";
        }
        os << "]";
      };
      // Emit ksyscall argument params only when present.
      if (pk && ((pk->sig == bpfmlir::SigFamily::Probe && p.targetParams.empty()) ||
                 (pk->attach == bpfmlir::AttachForm::SyscallName && !p.params.empty()))) {
        os << "        \"params\": ";
        emitParams(p.params);
        os << ",\n";
      }
      // Per-target parameters exclude shared params; omit when absent.
      if (!p.targetParams.empty()) {
        os << "        \"target_params\": [";
        for (auto [i, ps] : llvm::enumerate(p.targetParams)) {
          os << (i ? ", " : "");
          emitParams(ps);
        }
        os << "],\n";
      }
    }
    if (!p.usdtSemaphore.empty()) { // USDT only; omit when absent.
      os << "        \"semaphore\": "; emitStr(os, p.usdtSemaphore); os << ",\n";
      os << "        \"max_points\": " << p.usdtMaxPoints << ",\n";
    }
    if (!p.fields.empty()) { // Tracepoint only; omit when absent.
      os << "        \"fields\": [";
      for (auto [j, f] : llvm::enumerate(p.fields)) {
        os << (j ? ", " : "") << "{\"name\": ";
        emitStr(os, f.name);
        os << ", \"offset\": " << f.offset << ", \"type\": ";
        if (f.arrayCount)
          os << "{\"kind\": \"array\", \"elem\": \"" << (f.type.isSigned ? "i8" : "u8") << "\", \"n\": " << f.arrayCount << "}";
        else if (f.userStrArray)
          os << "{\"kind\": \"user_str_array\"}";
        else if (f.userStr)
          os << "{\"kind\": \"user_str\"}";
        else
          emitType(os, Type{f.type}, 8);
        os << "}";
      }
      os << "],\n";
    }
    os << "        \"note\": "; emitStr(os, p.note); os << "\n";
    os << "      }" << (i + 1 < programs_.size() ? "," : "") << "\n";
  }
  if (globals_.empty()) { // Omit absent globals to preserve canonical output.
    os << "    ]\n";
  } else {
    os << "    ],\n";
    os << "    \"globals\": [\n";
    for (auto [i, g] : llvm::enumerate(globals_)) {
      os << "      {\n";
      os << "        \"name\": "; emitStr(os, g.name); os << ",\n";
      os << "        \"section\": "; emitStr(os, g.section); os << ",\n";
      os << "        \"type\": "; emitType(os, Type{g.type}, 8); os << ",\n";
      os << "        \"note\": "; emitStr(os, g.note); os << "\n";
      os << "      }" << (i + 1 < globals_.size() ? "," : "") << "\n";
    }
    os << "    ]\n";
  }
  os << "  },\n";

  // ---- telemetry ----
  os << "  \"telemetry\": {\n";

  os << "    \"clocks\": [\n";
  for (auto [i, c] : llvm::enumerate(clocks_)) {
    os << "      {\n";
    os << "        \"id\": "; emitStr(os, c.id); os << ",\n";
    os << "        \"kernel_source\": "; emitStr(os, c.kernelSource); os << ",\n";
    os << "        \"posix_clock\": "; emitStr(os, c.posixClock); os << ",\n";
    os << "        \"to_wall\": "; emitStr(os, c.toWall); os << ",\n";
    os << "        \"note\": "; emitStr(os, c.note); os << "\n";
    os << "      }" << (i + 1 < clocks_.size() ? "," : "") << "\n";
  }
  os << "    ],\n";

  os << "    \"value_maps\": [\n";
  for (auto [i, v] : llvm::enumerate(valueMaps_)) {
    os << "      {\n";
    os << "        \"id\": "; emitStr(os, v.id); os << ",\n";
    os << "        \"unknown\": "; emitStr(os, v.unknown); os << ",\n";
    os << "        \"arch_invariant\": " << (v.archInvariant ? "true" : "false") << ",\n";
    os << "        \"btf_mode\": "; emitStr(os, v.btfMode); os << ",\n";
    os << "        \"btf_anchor\": "; emitStr(os, v.btfAnchor); os << ",\n";
    os << "        \"btf_prefix\": "; emitStr(os, v.btfPrefix); os << ",\n";
    os << "        \"btf_omit\": "; emitStr(os, v.btfOmit); os << ",\n";
    os << "        \"authority\": "; emitStr(os, v.authority); os << ",\n";
    os << "        \"note\": "; emitStr(os, v.note); os << ",\n";
    os << "        \"entries\": [\n";
    for (auto [j, e] : llvm::enumerate(v.entries)) {
      os << "          {\"value\": " << e.value << ", \"name\": ";
      emitStr(os, e.name);
      os << "}" << (j + 1 < v.entries.size() ? "," : "") << "\n";
    }
    os << "        ]\n";
    os << "      }" << (i + 1 < valueMaps_.size() ? "," : "") << "\n";
  }
  os << "    ],\n";

  os << "    \"bounds_sets\": [\n";
  for (auto [i, b] : llvm::enumerate(boundsSets_)) {
    os << "      {\n";
    os << "        \"id\": "; emitStr(os, b.id); os << ",\n";
    os << "        \"unit\": "; emitStr(os, b.unit); os << ",\n";
    os << "        \"authority\": "; emitStr(os, b.authority); os << ",\n";
    os << "        \"note\": "; emitStr(os, b.note); os << ",\n";
    os << "        \"bounds\": [";
    for (auto [j, d] : llvm::enumerate(b.bounds)) {
      if (j)
        os << ", ";
      os << json::Value(d);
    }
    os << "]\n";
    os << "      }" << (i + 1 < boundsSets_.size() ? "," : "") << "\n";
  }
  os << "    ],\n";

  os << "    \"signals\": [\n";
  for (auto [i, sg] : llvm::enumerate(signals_)) {
    os << "      {\n";
    os << "        \"name\": "; emitStr(os, sg.name); os << ",\n";
    os << "        \"signal\": "; emitStr(os, sg.signal); os << ",\n";
    os << "        \"record\": "; emitStr(os, sg.record); os << ",\n";
    os << "        \"span_name\": "; emitStr(os, sg.spanName); os << ",\n";
    os << "        \"span_kind\": "; emitStr(os, sg.spanKind); os << ",\n";
    os << "        \"note\": "; emitStr(os, sg.note); os << ",\n";
    os << "        \"timing\": {\n";
    os << "          \"start\": "; emitStr(os, sg.timing.start); os << ",\n";
    os << "          \"clock\": "; emitStr(os, sg.timing.clock); os << ",\n";
    os << "          \"end\": "; emitStr(os, sg.timing.end); os << "\n";
    os << "        },\n";
    if (sg.body) {
      os << "        \"body\": ";
      emitSource(os, *sg.body, 8);
      os << ",\n";
    }
    if (sg.value) {
      os << "        \"value\": ";
      emitSource(os, *sg.value, 8);
      os << ",\n";
    }
    if (sg.metric) {
      os << "        \"metric\": {\n";
      os << "          \"kind\": "; emitStr(os, sg.metric->kind); os << ",\n";
      os << "          \"unit\": "; emitStr(os, sg.metric->unit); os << ",\n";
      os << "          \"temporality\": "; emitStr(os, sg.metric->temporality);
      if (sg.metric->monotonic) {
        os << ",\n          \"monotonic\": "
           << (*sg.metric->monotonic ? "true" : "false");
      }
      if (sg.metric->scale)
        os << ",\n          \"scale\": " << *sg.metric->scale;
      if (sg.metric->zeroThreshold)
        os << ",\n          \"zero_threshold\": "
           << json::Value(*sg.metric->zeroThreshold);
      if (!sg.metric->bucketRule.empty()) {
        os << ",\n          \"bucket_rule\": ";
        emitStr(os, sg.metric->bucketRule);
      }
      os << "\n        },\n";
    }
    os << "        \"drop_when\": ";
    emitPredicate(os, sg.dropWhen, 8);
    os << ",\n";
    os << "        \"attributes\": [\n";
    for (auto [j, a] : llvm::enumerate(sg.attributes)) {
      os << "          {\n";
      os << "            \"key\": "; emitStr(os, a.key); os << ",\n";
      os << "            \"stability\": "; emitStr(os, a.stability); os << ",\n";
      os << "            \"note\": "; emitStr(os, a.note); os << ",\n";
      os << "            \"source\": ";
      emitSource(os, a.source, 12);
      os << ",\n";
      os << "            \"presence\": ";
      emitPredicate(os, a.presence, 12);
      os << "\n          }" << (j + 1 < sg.attributes.size() ? "," : "") << "\n";
    }
    os << "        ]\n";
    os << "      }" << (i + 1 < signals_.size() ? "," : "") << "\n";
  }
  os << "    ]\n";
  os << "  },\n";

  // ---- extensions ----
  os << "  \"extensions\": ";
  if (extensions_.empty()) {
    os << "{}\n";
  } else {
    os << "{\n";
    size_t i = 0;
    for (const auto &kv : extensions_) {
      os << "    ";
      emitStr(os, kv.first);
      os << ": ";
      emitCanonical(os, kv.second, 4);
      os << (++i < extensions_.size() ? "," : "") << "\n";
    }
    os << "  }\n";
  }
  os << "}\n";
  return out;
}

} // namespace ebpf
