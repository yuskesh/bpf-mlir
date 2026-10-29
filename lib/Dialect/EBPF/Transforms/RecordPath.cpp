//===- RecordPath.cpp - record field paths ---------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/RecordPath.h"

#include "mlir/IR/SymbolTable.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/DenseSet.h"

using namespace mlir;
using namespace mlir::ebpf;

namespace {

btf::StructOp refTarget(btf::ScopeOp records, btf::RefAttr ref) {
  return dyn_cast_or_null<btf::StructOp>(
      SymbolTable::lookupSymbolIn(records, ref.getTarget().getLeafReference()));
}

btf::MemberAttr findMember(btf::StructOp st, StringRef name) {
  for (Attribute a : st.getMembers())
    if (cast<btf::MemberAttr>(a).getName() == name)
      return cast<btf::MemberAttr>(a);
  return {};
}

// Byte size: declared record size or array count times element size.
std::optional<int64_t> sizeBytes(btf::ScopeOp records, Attribute t) {
  if (auto it = dyn_cast<btf::IntAttr>(t))
    return static_cast<int64_t>(it.getBits() / 8);
  if (auto ref = dyn_cast<btf::RefAttr>(t)) {
    btf::StructOp s = refTarget(records, ref);
    if (!s)
      return std::nullopt;
    return static_cast<int64_t>(s.getSizeBits() / 8);
  }
  if (auto arr = dyn_cast<btf::ArrayOfAttr>(t)) {
    std::optional<int64_t> e = sizeBytes(records, arr.getElement());
    if (!e)
      return std::nullopt;
    return static_cast<int64_t>(arr.getCount()) * *e;
  }
  return std::nullopt;
}

// Recursive shape validation. depth starts at one; via names the path to st.
LogicalResult checkShape(btf::ScopeOp records, btf::StructOp st, unsigned depth, StringRef via, std::string &err) {
  auto name = [&](StringRef m) { return via.empty() ? m.str() : (via + "." + m).str(); };
  for (Attribute a : st.getMembers()) {
    auto m = cast<btf::MemberAttr>(a);
    Attribute t = m.getType();
    std::string p = name(m.getName());
    auto nested = [&](btf::RefAttr ref, StringRef at) -> LogicalResult {
      btf::StructOp inner = refTarget(records, ref);
      if (!inner) {
        err = ("field \"" + at + "\" refers to a record that has no declaration").str();
        return failure();
      }
      if (depth + 1 > kMaxRecordDepth) {
        err = ("field \"" + at + "\" nests records " + std::to_string(depth + 1) + " deep; this compiler supports " +
               std::to_string(kMaxRecordDepth) + "")
                  .str();
        return failure();
      }
      return checkShape(records, inner, depth + 1, at, err);
    };
    if (isa<btf::IntAttr>(t))
      continue;
    // Extend kptr placement only along constant record_ref paths.
    if (!kptrStructOf(t).empty())
      continue;
    if (auto ref = dyn_cast<btf::RefAttr>(t)) {
      if (failed(nested(ref, p)))
        return failure();
      continue;
    }
    if (auto arr = dyn_cast<btf::ArrayOfAttr>(t)) {
      Attribute e = arr.getElement();
      if (isa<btf::IntAttr>(e))
        continue;
      if (auto ref = dyn_cast<btf::RefAttr>(e)) {
        if (auto inner = refTarget(records, ref); inner && recordHasKptr(records, inner)) {
          err = "field \"" + p + "\" is an array of records with a kptr field";
          return failure();
        }
        if (failed(nested(ref, p + "[]")))
          return failure();
        continue;
      }
      if (auto inner = dyn_cast<btf::ArrayOfAttr>(e)) {
        if (isa<btf::IntAttr>(inner.getElement()))
          continue;
        err = ("field \"" + p + "\" is a " +
               (isa<btf::ArrayOfAttr>(inner.getElement()) ? std::string("3-or-more-dimensional array")
                                                          : std::string("2-dimensional array of non-integers")) +
               "; this compiler supports arrays of " + std::to_string(kMaxArrayDims) +
               " dimensions of integers, or 1 dimension of records");
        return failure();
      }
      err = ("field \"" + p + "\" is an array of a type this compiler does not support in a record");
      return failure();
    }
    err = ("field \"" + p + "\" has a type this compiler does not support in a record");
    return failure();
  }
  return success();
}

} // namespace

LogicalResult mlir::ebpf::checkRecordShape(btf::ScopeOp records, btf::StructOp st, std::string &err) {
  return checkShape(records, st, 1, "", err);
}

bool mlir::ebpf::recordHasKptr(btf::ScopeOp records, btf::StructOp st) {
  llvm::DenseSet<Operation *> seen;
  SmallVector<btf::StructOp> pending{st};
  while (!pending.empty()) {
    btf::StructOp cur = pending.pop_back_val();
    if (!cur || !seen.insert(cur.getOperation()).second)
      continue;
    for (Attribute a : cur.getMembers()) {
      Attribute t = cast<btf::MemberAttr>(a).getType();
      if (!kptrStructOf(t).empty())
        return true;
      while (auto arr = dyn_cast<btf::ArrayOfAttr>(t))
        t = arr.getElement();
      if (auto ref = dyn_cast<btf::RefAttr>(t))
        pending.push_back(refTarget(records, ref));
    }
  }
  return false;
}

FailureOr<KptrLeaf> mlir::ebpf::resolveKptrPath(btf::ScopeOp records, btf::StructOp st,
                                             StringRef path, std::string &err) {
  SmallVector<StringRef> comps;
  path.split(comps, '.', -1, true);
  if (comps.size() > kMaxRecordDepth || path.contains('[') || path.contains(']') ||
      llvm::any_of(comps, [](StringRef c) { return c.empty(); })) {
    err = "field \"" + path.str() + "\" must be a non-empty dotted path of at most 3 record fields, without array indices";
    return failure();
  }
  int64_t offset = 0;
  btf::StructOp cur = st;
  for (size_t i = 0; i < comps.size(); ++i) {
    auto m = findMember(cur, comps[i]);
    if (!m) {
      err = ("btf.struct @records::@" + cur.getSymName() + " has no field \"" + comps[i] + "\" (schema core.records)").str();
      return failure();
    }
    if (m.getOffsetBits() % 64) {
      err = "field \"" + path.str() + "\" has a component at an offset that is not a multiple of 8";
      return failure();
    }
    offset += static_cast<int64_t>(m.getOffsetBits() / 8);
    if (StringRef target = kptrStructOf(m.getType()); !target.empty()) {
      if (i + 1 != comps.size()) {
        err = "field \"" + path.str() + "\" goes past a kptr field";
        return failure();
      }
      if (offset % 8) {
        err = "field \"" + path.str() + "\" is a kptr at an offset that is not a multiple of 8";
        return failure();
      }
      return KptrLeaf{target.str(), offset};
    }
    if (i + 1 == comps.size()) {
      err = ("field \"" + path + "\" of record \"" + st.getSymName() +
             "\" is not a kptr field (schema {\"kind\": \"kptr\", \"struct\": …})").str();
      return failure();
    }
    auto ref = dyn_cast<btf::RefAttr>(m.getType());
    auto inner = ref ? refTarget(records, ref) : btf::StructOp();
    if (!inner) {
      err = "field \"" + path.str() + "\" traverses a field that is not a record";
      return failure();
    }
    cur = inner;
  }
  llvm_unreachable("a kptr path always returns at its final field");
}

FailureOr<RecordTemplate> mlir::ebpf::resolveRecordTemplate(btf::ScopeOp records, btf::StructOp st, StringRef path,
                                                            std::string &err) {
  SmallVector<StringRef> comps;
  path.split(comps, '.');
  if (comps.size() > kMaxRecordDepth) {
    err = ("\"" + path + "\" is nested deeper than " + std::to_string(kMaxRecordDepth) + "").str();
    return failure();
  }
  RecordTemplate out{0, 0, {}, {}};
  btf::StructOp cur = st;
  std::string via; // Diagnostic path to cur.
  for (size_t ci = 0; ci < comps.size(); ++ci) {
    StringRef comp = comps[ci];
    bool last = ci + 1 == comps.size();
    StringRef name = comp.take_until([](char c) { return c == '['; });
    StringRef idx = comp.drop_front(name.size());
    btf::MemberAttr m = findMember(cur, name);
    if (!m) {
      if (via.empty())
        err = ("btf.struct @records::@" + st.getSymName() + " has no field \"" + name + "\" (schema core.records)").str();
      else
        err = ("nested record \"" + cur.getSymName() + "\" (field \"" + via + "\") has no field \"" + name + "\"").str();
      return failure();
    }
    std::string here = via.empty() ? name.str() : via + "." + name.str();
    out.offsetBytes += static_cast<int64_t>(m.getOffsetBits() / 8);
    Attribute t = m.getType();
    // Resolve one index at a time.
    while (!idx.empty()) {
      if (!idx.starts_with("[")) {
        err = ("\"" + path + "\" is malformed after field \"" + name + "\"").str();
        return failure();
      }
      size_t rb = idx.find(']');
      if (rb == StringRef::npos) {
        err = ("\"" + path + "\" has an unclosed index").str();
        return failure();
      }
      StringRef tok = idx.substr(1, rb - 1);
      idx = idx.drop_front(rb + 1);
      auto arr = dyn_cast<btf::ArrayOfAttr>(t);
      if (!arr) {
        if (isa<btf::IntAttr>(t))
          err = ("field \"" + here + "\" is an integer; \"" + path + "\" goes past it").str();
        else
          err = ("field \"" + here + "\" is a record, not an array");
        return failure();
      }
      std::optional<int64_t> es = sizeBytes(records, arr.getElement());
      if (!es) {
        err = ("field \"" + here + "\" has elements of an unknown size");
        return failure();
      }
      if (tok.empty()) {
        out.dims.push_back(RecordDim{static_cast<uint64_t>(arr.getCount()), *es});
      } else {
        uint64_t i;
        if (tok.getAsInteger(10, i)) {
          err = ("index in \"" + path + "\" must be a constant decimal integer (a variable index is not supported)").str();
          return failure();
        }
        if (i >= arr.getCount()) {
          err = ("index " + std::to_string(i) + " is out of range for field \"" + here + "\" (" +
                 std::to_string(arr.getCount()) + " elements)");
          return failure();
        }
        out.offsetBytes += static_cast<int64_t>(i) * *es;
      }
      t = arr.getElement();
    }
    if (auto it = dyn_cast<btf::IntAttr>(t)) {
      if (!last) {
        err = ("field \"" + here + "\" is an integer; \"" + path + "\" goes past it").str();
        return failure();
      }
      out.bits = static_cast<unsigned>(it.getBits());
      out.type = it;
      return out;
    }
    if (isa<btf::ArrayOfAttr>(t)) {
      err = ("field \"" + here + "\" is an array; give an element (\"" + here + "[i]\")");
      return failure();
    }
    if (!kptrStructOf(t).empty()) {
      err = ("field \"" + here + "\" is a kptr; only ebpf.kptr.xchg takes it");
      return failure();
    }
    auto ref = dyn_cast<btf::RefAttr>(t);
    btf::StructOp inner = ref ? refTarget(records, ref) : btf::StructOp();
    if (!inner) {
      err = ("field \"" + here + "\" has a type this compiler does not support in a record");
      return failure();
    }
    if (last) {
      err = ("field \"" + here + "\" is a record \"" + inner.getSymName() + "\"; give a field of it (\"" + here +
             ".<field>\")").str();
      return failure();
    }
    cur = inner;
    via = here;
  }
  llvm_unreachable("the loop returns at the last component");
}

FailureOr<RecordLeaf> mlir::ebpf::resolveRecordPath(btf::ScopeOp records, btf::StructOp st, StringRef path,
                                                    std::string &err) {
  if (path.contains("[]")) {
    err = ("index in \"" + path + "\" must be a constant decimal integer (a variable index is not supported; "
           "use ebpf.ref.index)").str();
    return failure();
  }
  FailureOr<RecordTemplate> t = resolveRecordTemplate(records, st, path, err);
  if (failed(t))
    return failure();
  return RecordLeaf{path.str(), t->offsetBytes, t->bits, t->type};
}

namespace {
// All leaf paths of type t beneath prefix.
void leafPaths(btf::ScopeOp records, Attribute t, const std::string &prefix, SmallVectorImpl<std::string> &out) {
  if (isa<btf::IntAttr>(t)) {
    out.push_back(prefix);
    return;
  }
  if (auto arr = dyn_cast<btf::ArrayOfAttr>(t)) {
    for (uint64_t i = 0; i < arr.getCount(); ++i)
      leafPaths(records, arr.getElement(), prefix + "[" + std::to_string(i) + "]", out);
    return;
  }
  if (auto ref = dyn_cast<btf::RefAttr>(t))
    for (Attribute ia : refTarget(records, ref).getMembers()) {
      auto m = cast<btf::MemberAttr>(ia);
      leafPaths(records, m.getType(), prefix + "." + m.getName().str(), out);
    }
}
} // namespace

LogicalResult mlir::ebpf::recordLeaves(btf::ScopeOp records, btf::StructOp st,
                                       SmallVectorImpl<RecordLeaf> &out, std::string &err) {
  if (failed(checkRecordShape(records, st, err)))
    return failure();
  for (Attribute a : st.getMembers()) {
    auto m = cast<btf::MemberAttr>(a);
    SmallVector<std::string> paths;
    leafPaths(records, m.getType(), m.getName().str(), paths);
    for (const std::string &p : paths) {
      FailureOr<RecordLeaf> l = resolveRecordPath(records, st, p, err);
      if (failed(l))
        return failure();
      out.push_back(*l);
    }
  }
  return success();
}
