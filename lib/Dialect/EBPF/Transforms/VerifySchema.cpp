//===- VerifySchema.cpp - match IR bindings against canonical schema --------===//
//
// Keep schema matching in a pass, not the dialect: operations define eBPF
// vocabulary while callers select the schema for validation. Check existence
// and kind/key/value agreement in addition to binding structure/uniqueness.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h"

#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"
#include "bpf-mlir/Dialect/EBPF/Transforms/CallContexts.h"
#include "bpf-mlir/Dialect/BPFABI/KernelABI.h"
#include "bpf-mlir/Support/ProgramKinds.h"
#include "bpf-mlir/Support/KeylessMaps.h"
#include "bpf-mlir/Support/ScxContract.h"
#include "bpf-mlir/Target/EBPF/Schema.h"

#include "mlir/IR/Matchers.h"
#include "llvm/Support/MemoryBuffer.h"

#include <map>

namespace mlir {
namespace ebpf {
#define GEN_PASS_DEF_EBPFVERIFYSCHEMA
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h.inc"
} // namespace ebpf
} // namespace mlir

using namespace mlir;
using namespace mlir::ebpf;

namespace {

// Match schema types against dialect types.
bool sameInt(const ::ebpf::Type &st, Type mt) {
  const auto *i = std::get_if<::ebpf::IntType>(&st.v);
  if (!i)
    return false;
  auto it = dyn_cast<IntegerType>(mt);
  return it && it.getWidth() == i->bits;
}

std::string describe(const ::ebpf::Type &st) {
  if (const auto *i = std::get_if<::ebpf::IntType>(&st.v))
    return (i->isSigned ? "i" : "u") + std::to_string(i->bits);
  if (const auto *a = std::get_if<::ebpf::ArrayType>(&st.v)) {
    if (a->element && std::holds_alternative<::ebpf::StackBuildIdType>(a->element->v))
      return "an array of stack_build_id";
    return "an array";
  }
  if (const auto *r = std::get_if<::ebpf::RecordRefType>(&st.v))
    return "record " + r->symbol;
  return "a special type (spin_lock / timer / stack_build_id)";
}

// Flatten integer record fields to byte-offset/bit-width pairs. Recurse
// through record_ref with accumulated offsets. Arrays are raw payload, not
// scalar stores; store_field into them fails the integer-field lookup.
void flattenIntFields(const ::ebpf::Schema &schema,
                      const ::ebpf::Record &rec, uint64_t base,
                      llvm::SmallVectorImpl<std::pair<uint64_t, unsigned>> &out) {
  for (const ::ebpf::Field &f : rec.fields) {
    if (const auto *i = std::get_if<::ebpf::IntType>(&f.type.v)) {
      out.push_back({base + f.offset, i->bits});
    } else if (const auto *r =
                   std::get_if<::ebpf::RecordRefType>(&f.type.v)) {
      for (const ::ebpf::Record &sub : schema.records())
        if (sub.symbol == r->symbol)
          flattenIntFields(schema, sub, base + f.offset, out);
    }
  }
}

const ::ebpf::Record *findRecord(const ::ebpf::Schema &schema,
                                  llvm::StringRef symbol) {
  for (const ::ebpf::Record &r : schema.records())
    if (r.symbol == symbol)
      return &r;
  return nullptr;
}

// the first use that may write through a read-only (.rodata) record
// borrow v, or nullptr. An allow-list (fail closed): field / value reads,
// ref.index whose checked integer elements are only loaded and whose record
// element borrows pass the same walk, and calls whose callee argument passes
// it — visited by (callee, argument position), so a second argument of the
// same callee is not dropped.
Operation *readOnlyBorrowWrite(SymbolTableCollection &st, Value v,
                               llvm::DenseSet<std::pair<Operation *, unsigned>> &seen) {
  for (OpOperand &use : v.getUses()) {
    Operation *u = use.getOwner();
    if (isa<RefLoadOp, RefFieldLoadOp>(u))
      continue;
    if (auto ix = dyn_cast<RefIndexOp>(u)) {
      if (use.getOperandNumber() != 0)
        return u;
      BlockArgument e = ix.getInRange().front().getArgument(0);
      if (isa<BorrowedType>(e.getType())) { // a record element borrow.
        if (Operation *w = readOnlyBorrowWrite(st, e, seen))
          return w;
        continue;
      }
      for (Operation *eu : e.getUsers())
        if (!isa<ElemLoadOp>(eu))
          return eu;
      continue;
    }
    if (auto call = dyn_cast<CallOp>(u)) {
      auto fn = dyn_cast_or_null<SubprogramOp>(st.lookupNearestSymbolFrom(call, call.getCalleeAttr()));
      unsigned i = use.getOperandNumber();
      if (!fn || fn.getBody().empty() || i >= fn.getBody().front().getNumArguments())
        return u;
      if (!seen.insert({fn.getOperation(), i}).second)
        continue;
      if (Operation *w = readOnlyBorrowWrite(st, fn.getBody().front().getArgument(i), seen))
        return w;
      continue;
    }
    return u;
  }
  return nullptr;
}

// the nullable operand that v is the checked form of — the kptr.check
// present argument (①) or its ② expansion, assume_present. A copy of
// EBPFDialect.cpp's scxCheckedFrom (static there).
Value scxCheckedFromKPtr(Value v) {
  if (auto ap = v.getDefiningOp<AssumePresentOp>())
    return ap.getValue();
  auto ba = dyn_cast<BlockArgument>(v);
  if (!ba)
    return {};
  auto kc = dyn_cast_or_null<KPtrCheckOp>(ba.getOwner()->getParentOp());
  if (!kc || ba.getOwner() != &kc.getPresentRegion().front())
    return {};
  return kc.getPtr();
}

// trace.printk in a struct_ops program is only for a sched_ext_ops
// member — sched_ext's get_func_proto is bpf_base_func_proto (7.3.1
// ext.c:8160); the other struct_ops types' get_func_proto is not read, so the
// compiler rejects them by name. The program body and every reaching context
// of an ebpf.func share the text (who: "@p" / "the owner").
std::string structOpsPrintkRule(StringRef who, StringRef impl) {
  return ("is only for programs implementing a " + bpfmlir::kScxOpsType +
          " member among the struct_ops programs (the compiler has not read the get_func_proto of the other struct_ops "
          "types), but " +
          who + " implements " + impl)
      .str();
}

struct EBPFVerifySchemaPass
    : public mlir::ebpf::impl::EBPFVerifySchemaBase<EBPFVerifySchemaPass> {
  using Base::Base;

  void runOnOperation() override {
    if (schemaPath.empty()) {
      getOperation().emitError()
          << "ebpf-verify-schema needs --schema=<path to the canonical schema>";
      return signalPassFailure();
    }
    auto buf = llvm::MemoryBuffer::getFile(schemaPath);
    if (!buf) {
      getOperation().emitError()
          << "cannot read schema " << schemaPath << ": "
          << buf.getError().message();
      return signalPassFailure();
    }
    auto schema = ::ebpf::Schema::parseJSON((*buf)->getBuffer());
    if (!schema) {
      getOperation().emitError()
          << "schema " << schemaPath << " is invalid: "
          << llvm::toString(schema.takeError());
      return signalPassFailure();
    }

    bool bad = false;
    // the new address type has only these two defining operations.
    getOperation().walk([&](Operation *op) {
      for (Value result : op->getResults())
        if (isa<UserBufType>(result.getType()) && !isa<UprobeArgOp, ProbeTargetArgOp>(op)) {
          bad = true;
          op->emitOpError("user_buf can only be defined by uprobe.arg or probe.target_arg");
        }
      for (Region &region : op->getRegions())
        for (Block &block : region)
          for (BlockArgument arg : block.getArguments())
            if (isa<UserBufType>(arg.getType())) {
              bad = true;
              op->emitOpError("user_buf cannot be a block or function argument");
            }
    });
    // Share map/reservation/record matching across program and subprogram bodies.
    auto checkMaps = [&](Operation *owner, ArrayAttr syms, Block::BlockArgListType mapArgs) {
      for (auto [i, arg] : llvm::enumerate(mapArgs)) {
        auto flat = cast<FlatSymbolRefAttr>(syms[i]);
        StringRef sym = flat.getValue();

        const ::ebpf::Map *decl = nullptr;
        for (const ::ebpf::Map &m : schema->maps())
          if (m.symbol == sym)
            decl = &m;
        if (!decl) {
          bad = true;
          owner->emitOpError() << "map symbol @" << sym
                             << " is not declared in the schema";
          continue;
        }

        auto mt = cast<MapType>(arg.getType());
        const char *declKind = ::ebpf::mapKindName(decl->kind);
        if (mt.getKind() != declKind) {
          bad = true;
          owner->emitOpError() << "map @" << sym << " is declared \"" << declKind
                             << "\" in the schema but bound as \""
                             << mt.getKind() << "\"";
          continue;
        }
        // arena has no key/value; its handle is !ebpf.map<"arena", none, none>.
        if (decl->kind == ::ebpf::MapKind::Arena) {
          if (!isa<NoneType>(mt.getKeyType()) || !isa<NoneType>(mt.getValueType())) {
            bad = true;
            owner->emitOpError() << "map @" << sym << " is an arena map (no key/value) — bind it as !ebpf.map<\"arena\", none, none>, got "
                                 << mt;
          }
          continue;
        }
        // Keyless queue/stack/bloom handles use none keys and schema integer values.
        if (bpfmlir::isKeylessMapKind(declKind)) {
          if (!isa<NoneType>(mt.getKeyType())) {
            bad = true;
            owner->emitOpError() << "map @" << sym << " is a " << declKind << " map (no key) — bind it as !ebpf.map<\"" << declKind
                                 << "\", none, V>, got key type " << mt.getKeyType() << "";
          } else if (!decl->value || !sameInt(*decl->value, mt.getValueType())) {
            bad = true;
            owner->emitOpError() << "map @" << sym << " value type " << mt.getValueType() << " does not match the schema ("
                                 << (decl->value ? describe(*decl->value) : std::string("no value")) << ")";
          }
          continue;
        }
        if (!decl->key || !decl->value) {
          bad = true;
          owner->emitOpError() << "map @" << sym
                             << " has no key/value in the schema and cannot be "
                                "bound as a lookup map";
          continue;
        }
        // Record keys require the same nominal record_ref, like record values.
        if (auto rt = dyn_cast<RecordType>(mt.getKeyType())) {
          const auto *rr = std::get_if<::ebpf::RecordRefType>(&decl->key->v);
          const ::ebpf::Record *rec = rr ? findRecord(*schema, rr->symbol) : nullptr;
          if (!rr || rr->symbol != rt.getSymbol() || !rec || rec->size != (uint64_t)rt.getSize()) {
            bad = true;
            owner->emitOpError() << "map @" << sym << " key type " << mt.getKeyType()
                                 << " does not match the schema (" << describe(*decl->key) << ")";
          }
        } else if (!sameInt(*decl->key, mt.getKeyType())) {
          bad = true;
          owner->emitOpError() << "map @" << sym << " key type " << mt.getKeyType()
                             << " does not match the schema (" 
                             << describe(*decl->key) << ")";
        }
        // Outer map-in-map values are inner handles matched against schema template
        // kind/key/value. Schema outer values remain u32 FDs, checked by parsing.
        if (auto im = dyn_cast<MapType>(mt.getValueType())) {
          const ::ebpf::Map *tpl = nullptr;
          for (const ::ebpf::Map &m : schema->maps())
            if (!decl->inner.empty() && m.symbol == decl->inner)
              tpl = &m;
          auto sameIntOrRecord = [&](const ::ebpf::Type &st, Type t) {
            if (auto rt = dyn_cast<RecordType>(t)) {
              const auto *rr = std::get_if<::ebpf::RecordRefType>(&st.v);
              const ::ebpf::Record *rec = rr ? findRecord(*schema, rr->symbol) : nullptr;
              return rr && rr->symbol == rt.getSymbol() && rec && rec->size == (uint64_t)rt.getSize();
            }
            return sameInt(st, t);
          };
          if (!tpl || im.getKind() != ::ebpf::mapKindName(tpl->kind) || !tpl->key || !tpl->value || !sameIntOrRecord(*tpl->key, im.getKeyType()) ||
              !sameIntOrRecord(*tpl->value, im.getValueType())) {
            bad = true;
            auto d = owner->emitOpError() << "map @" << sym << " value type " << mt.getValueType()
                                          << " does not match the inner map template in the schema";
            if (tpl && tpl->key && tpl->value)
              d << " — \"" << decl->inner << "\" is " << ::ebpf::mapKindName(tpl->kind) << " with key " << describe(*tpl->key) << " and value "
                << describe(*tpl->value);
            else
              d << " — \"" << decl->symbol << "\" has no inner map template";
          }
          continue;
        }
        // stack<D> matches schema u64[D]; stack_build_id<D> matches stack_build_id[D].
        if (isa<StackType, StackBuildIdType>(mt.getValueType())) {
          const auto *at = std::get_if<::ebpf::ArrayType>(&decl->value->v);
          bool isBid = isa<StackBuildIdType>(mt.getValueType());
          int64_t depth = isBid ? cast<StackBuildIdType>(mt.getValueType()).getDepth() : cast<StackType>(mt.getValueType()).getDepth();
          bool elemBid = at && at->element && std::holds_alternative<::ebpf::StackBuildIdType>(at->element->v);
          if (!at || at->count != (uint64_t)depth || elemBid != isBid) {
            bad = true;
            owner->emitOpError() << "map @" << sym << " value type " << mt.getValueType()
                                 << " does not match the schema (" << describe(*decl->value) << ")";
          }
        } else if (auto rt = dyn_cast<RecordType>(mt.getValueType())) {
          const auto *rr = std::get_if<::ebpf::RecordRefType>(&decl->value->v);
          const ::ebpf::Record *rec = rr ? findRecord(*schema, rr->symbol) : nullptr;
          if (!rr || rr->symbol != rt.getSymbol() || !rec || rec->size != (uint64_t)rt.getSize()) {
            bad = true;
            owner->emitOpError() << "map @" << sym << " value type " << mt.getValueType()
                                 << " does not match the schema (" << describe(*decl->value) << ")";
          }
        } else if (!sameInt(*decl->value, mt.getValueType())) {
          bad = true;
          owner->emitOpError() << "map @" << sym << " value type "
                             << mt.getValueType()
                             << " does not match the schema ("
                             << describe(*decl->value) << ")";
        }
      }

    };
    auto checkReserves = [&](Operation *owner) {
      // Resolve ringbuf.reserve string names to schema ringbuf symbols.
      owner->walk([&](RingbufReserveOp reserve) {
        StringRef name = reserve.getRingbuf();
        const ::ebpf::Map *decl = nullptr;
        for (const ::ebpf::Map &m : schema->maps())
          if (m.symbol == name)
            decl = &m;
        if (!decl) {
          bad = true;
          reserve.emitOpError() << "ring buffer \"" << name
                                << "\" is not declared in the schema";
          return;
        }
        if (decl->kind != ::ebpf::MapKind::RingBuf) {
          bad = true;
          reserve.emitOpError() << "\"" << name
                                << "\" is declared in the schema but is not a "
                                   "ringbuf map";
          return;
        }
        // Reject reservations that fail even in an empty ring: kernel requires
        // round_up(size+BPF_RINGBUF_HDR_SZ,8) <= max_entries-1. Load can succeed
        // while every reservation is absent. Header size comes from ABI.
        {
          auto resTy0 =
              cast<MaybeReservationType>(reserve.getResult().getType());
          uint64_t size = 0;
          if (auto rt = dyn_cast<RecordType>(resTy0.getRecordType()))
            size = rt.getSize();
          else if (auto it = dyn_cast<IntegerType>(resTy0.getRecordType()))
            size = it.getWidth() / 8;
          std::optional<int64_t> hdr = mlir::bpfabi::lookupRingbufConst("hdr_sz");
          if (!hdr) {
            bad = true;
            reserve.emitOpError()
                << "the UAPI table has no ringbufconst hdr_sz (regenerate abi/uapi.tsv)";
            return;
          }
          uint64_t len = (size + (uint64_t)*hdr + 7) / 8 * 8;
          if (size > 0 && decl->maxEntries > 0 && len > decl->maxEntries - 1) {
            bad = true;
            uint64_t maxSize =
                decl->maxEntries >= 8 + 2 * (uint64_t)*hdr
                    ? (decl->maxEntries - 1) / 8 * 8 - (uint64_t)*hdr
                    : 0;
            reserve.emitOpError()
                << "a " << size << "-byte reservation from ring buffer \"" << name
                << "\" (max_entries " << decl->maxEntries
                << ") always fails: the kernel needs round_up(size + " << *hdr
                << ", 8) <= max_entries - 1, so at most " << maxSize
                << " bytes can be reserved (the program would load and every "
                   "reservation would be absent)";
            return;
          }
        }
        // Match reserved record type to schema; do not silently allow scalar
        // reservations where the map declares a record.
        auto resTy =
            cast<MaybeReservationType>(reserve.getResult().getType());
        if (auto rt = dyn_cast<RecordType>(resTy.getRecordType())) {
          if (decl->record.empty()) {
            bad = true;
            reserve.emitOpError()
                << "reserves record \"" << rt.getSymbol() << "\" but the "
                << "schema ringbuf \"" << name << "\" declares no record";
            return;
          }
          if (decl->record != rt.getSymbol()) {
            bad = true;
            reserve.emitOpError()
                << "reserves record \"" << rt.getSymbol()
                << "\" but the schema ringbuf \"" << name
                << "\" carries record \"" << decl->record << "\"";
            return;
          }
          const ::ebpf::Record *rec = findRecord(*schema, rt.getSymbol());
          if (!rec) {
            bad = true;
            reserve.emitOpError() << "record \"" << rt.getSymbol()
                                  << "\" is not declared in the schema";
            return;
          }
          if (rec->size != (uint64_t)rt.getSize()) {
            bad = true;
            reserve.emitOpError()
                << "record \"" << rt.getSymbol() << "\" is " << rec->size
                << " bytes in the schema but the reservation type says "
                << rt.getSize();
          }
        } else if (!decl->record.empty()) {
          bad = true;
          reserve.emitOpError()
              << "the schema ringbuf \"" << name << "\" carries record \""
              << decl->record << "\" but the reservation type is "
              << resTy.getRecordType()
              << " — reserve it as !ebpf.record<...> so the layout is checked";
        }
      });

      // ringbuf.output must match map name and nominal record size/name. Apply the
      // same empty-ring size bound: oversize output loads but always returns -EAGAIN.
      owner->walk([&](RingbufOutputOp out) {
        StringRef name = out.getRingbuf();
        const ::ebpf::Map *decl = nullptr;
        for (const ::ebpf::Map &m : schema->maps())
          if (m.symbol == name)
            decl = &m;
        if (!decl) {
          bad = true;
          out.emitOpError() << "ring buffer \"" << name << "\" is not declared in the schema";
          return;
        }
        if (decl->kind != ::ebpf::MapKind::RingBuf) {
          bad = true;
          out.emitOpError() << "\"" << name << "\" is declared in the schema but is not a ringbuf map";
          return;
        }
        auto rt = cast<RecordType>(out.getRecord().getType());
        uint64_t size = rt.getSize();
        std::optional<int64_t> hdr = mlir::bpfabi::lookupRingbufConst("hdr_sz");
        if (!hdr) {
          bad = true;
          out.emitOpError() << "the UAPI table has no ringbufconst hdr_sz (regenerate abi/uapi.tsv)";
          return;
        }
        uint64_t len = (size + (uint64_t)*hdr + 7) / 8 * 8;
        if (size > 0 && decl->maxEntries > 0 && len > decl->maxEntries - 1) {
          bad = true;
          uint64_t maxSize =
              decl->maxEntries >= 8 + 2 * (uint64_t)*hdr ? (decl->maxEntries - 1) / 8 * 8 - (uint64_t)*hdr : 0;
          out.emitOpError() << "a " << size << "-byte output to ring buffer \"" << name << "\" (max_entries "
                            << decl->maxEntries << ") always fails: the kernel needs round_up(size + " << *hdr
                            << ", 8) <= max_entries - 1, so at most " << maxSize
                            << " bytes can be output (the program would load and every output would return -EAGAIN)";
          return;
        }
        if (decl->record != rt.getSymbol()) {
          bad = true;
          out.emitOpError() << "outputs record \"" << rt.getSymbol() << "\" but the schema ringbuf \"" << name
                            << "\" carries record \"" << decl->record << "\"";
          return;
        }
        const ::ebpf::Record *rec = findRecord(*schema, rt.getSymbol());
        if (!rec) {
          bad = true;
          out.emitOpError() << "record \"" << rt.getSymbol() << "\" is not declared in the schema";
          return;
        }
        if (rec->size != size) {
          bad = true;
          out.emitOpError() << "record \"" << rt.getSymbol() << "\" is " << rec->size
                            << " bytes in the schema but the output type says " << size;
        }
      });

      // user_ringbuf.drain must name a schema user_ringbuf.
      owner->walk([&](UserRingbufDrainOp dr) {
        StringRef name = dr.getRingbuf();
        const ::ebpf::Map *decl = nullptr;
        for (const ::ebpf::Map &m : schema->maps())
          if (m.symbol == name)
            decl = &m;
        if (!decl) {
          bad = true;
          dr.emitOpError() << "user ring buffer \"" << name << "\" is not declared in the schema";
          return;
        }
        if (decl->kind != ::ebpf::MapKind::UserRingBuf) {
          bad = true;
          dr.emitOpError() << "\"" << name << "\" is declared in the schema but is not a user_ringbuf map";
        }
      });

      // reserve_dynptr names a schema ringbuf but need not match its nominal
      // record because event size varies. Direct constants use the same ring
      // size bound; oversize always returns -EINVAL. Dynamic sizes use kernel status.
      owner->walk([&](RingbufReserveDynptrOp rd) {
        StringRef name = rd.getRingbuf();
        const ::ebpf::Map *decl = nullptr;
        for (const ::ebpf::Map &m : schema->maps())
          if (m.symbol == name)
            decl = &m;
        if (!decl) {
          bad = true;
          rd.emitOpError() << "ring buffer \"" << name << "\" is not declared in the schema";
          return;
        }
        if (decl->kind != ::ebpf::MapKind::RingBuf) {
          bad = true;
          rd.emitOpError() << "\"" << name << "\" is declared in the schema but is not a ringbuf map";
          return;
        }
        APInt cv;
        if (!matchPattern(rd.getSize(), m_ConstantInt(&cv)))
          return;
        uint64_t size = cv.getZExtValue();
        std::optional<int64_t> hdr = mlir::bpfabi::lookupRingbufConst("hdr_sz");
        if (!hdr) {
          bad = true;
          rd.emitOpError() << "the UAPI table has no ringbufconst hdr_sz (regenerate abi/uapi.tsv)";
          return;
        }
        uint64_t len = (size + (uint64_t)*hdr + 7) / 8 * 8;
        if (decl->maxEntries > 0 && len > decl->maxEntries - 1) {
          bad = true;
          uint64_t maxSize =
              decl->maxEntries >= 8 + 2 * (uint64_t)*hdr ? (decl->maxEntries - 1) / 8 * 8 - (uint64_t)*hdr : 0;
          rd.emitOpError() << "a " << size << "-byte dynptr reservation from ring buffer \"" << name << "\" (max_entries "
                           << decl->maxEntries << ") always fails: the kernel needs round_up(size + " << *hdr
                           << ", 8) <= max_entries - 1, so at most " << maxSize
                           << " bytes can be reserved (the program would load and every reservation would return -EINVAL)";
        }
      });
    };
    // Validate globals inside both programs and funcs; a subprogram must not
    // bypass name/width/section checks.
    auto checkGlobals = [&](Operation *owner) {
      // a bss kaddr global is read / stored only as !ebpf.kaddr<"S"> of
      // its struct, and a !ebpf.kaddr only names a kaddr global. True when the
      // op's type or the global is a kaddr (checked here).
      auto checkKaddrGlobal = [&](Operation *op, const ::ebpf::Global *g, Type t, StringRef verb) -> bool {
        auto kt = dyn_cast<KAddrType>(t);
        if (!g->isKaddr() && !kt)
          return false;
        if (!g->isKaddr()) {
          bad = true;
          op->emitOpError() << verb << " global @" << g->name << " as " << t << ", but it is not a kaddr global (the schema's \"type\" is not "
                            << "{\"kind\": \"kaddr\", …})";
        } else if (!kt || kt.getStructName() != g->kaddr) {
          bad = true;
          op->emitOpError() << verb << " global @" << g->name << " as " << t << ", but it is a bss kaddr global of struct " << g->kaddr
                            << " (use !ebpf.kaddr<\"" << g->kaddr << "\">)";
        }
        return true;
      };
      // Match global read names and widths against core.globals.
      owner->walk([&](GlobalLoadOp gl) {
        const ::ebpf::Global *g = schema->global(gl.getName());
        if (!g) {
          bad = true;
          gl.emitOpError() << "global @" << gl.getName() << " is not declared in the schema (core.globals)";
          return;
        }
        if (g->isRecord()) { // .data globals are records, written only by ebpf.scx.exit_info; rodata / bss records are borrowed with ebpf.global.ref.
          bad = true;
          gl.emitOpError() << "global @" << gl.getName() << " is a ." << g->section << " record (" << g->record << "), not an integer";
          return;
        }
        if (g->isKptr()) { // data:<name> globals are kptrs.
          bad = true;
          gl.emitOpError() << "global @" << gl.getName() << " is a kptr (" << g->section << "), not an integer; read it with ebpf.global.kptr_load_rcu";
          return;
        }
        if (checkKaddrGlobal(gl, g, gl.getResult().getType(), "reads"))
          return;
        unsigned w = gl.getResult().getType().getIntOrFloatBitWidth();
        if (w != g->type.bits) {
          bad = true;
          gl.emitOpError() << "reads global @" << gl.getName() << " as " << w << " bits, but the schema declares " << g->type.bits;
        }
      });
      // Atomic global addition is .bss-only: .rodata is frozen after load.
      // cmpxchg / or follow the same rules (verb names the access).
      auto checkAtomicGlobal = [&](Operation *op, StringRef name, Type t, StringRef verb) {
        const ::ebpf::Global *g = schema->global(name);
        if (!g) {
          bad = true;
          op->emitOpError() << "global @" << name << " is not declared in the schema (core.globals)";
          return;
        }
        if (g->isRecord()) { // record globals are not integers.
          bad = true;
          op->emitOpError() << "global @" << name << " is a ." << g->section << " record (" << g->record << "), not an integer";
          return;
        }
        if (g->isKptr()) {
          bad = true;
          op->emitOpError() << "global @" << name << " is a kptr (" << g->section << "), not an integer; exchange it with ebpf.global.kptr_xchg";
          return;
        }
        if (g->isKaddr()) { // a kernel address is not a counter.
          bad = true;
          op->emitOpError() << "global @" << name << " is a bss kaddr global (" << g->kaddr
                            << "), not an integer; store a !ebpf.kaddr to it with ebpf.global.store";
          return;
        }
        unsigned w = t.getIntOrFloatBitWidth();
        if (w != g->type.bits) {
          bad = true;
          op->emitOpError() << verb << " global @" << name << " as " << w << " bits, but the schema declares " << g->type.bits;
        }
        if (g->section != "bss") {
          bad = true;
          op->emitOpError() << "global @" << name << " is in ." << g->section
                            << "; only .bss globals are writable (.rodata is frozen after load)";
        }
      };
      owner->walk([&](GlobalAtomicAddOp ga) { checkAtomicGlobal(ga, ga.getName(), ga.getDelta().getType(), "adds to"); });
      owner->walk([&](GlobalCmpxchgOp cx) { checkAtomicGlobal(cx, cx.getName(), cx.getOld().getType(), "compares and exchanges"); });
      owner->walk([&](GlobalAtomicOrOp o) { checkAtomicGlobal(o, o.getName(), o.getValue().getType(), "ors into"); });
      // a plain store is .bss-only and of the declared width.
      owner->walk([&](GlobalStoreOp gs) {
        const ::ebpf::Global *g = schema->global(gs.getName());
        if (!g) {
          bad = true;
          gs.emitOpError() << "global @" << gs.getName() << " is not declared in the schema (core.globals)";
          return;
        }
        if (g->isRecord()) {
          bad = true;
          gs.emitOpError() << "global @" << gs.getName() << " is a ." << g->section << " record (" << g->record << "), not an integer";
          return;
        }
        if (g->isKptr()) { // the kernel forbids direct stores to a kptr.
          bad = true;
          gs.emitOpError() << "global @" << gs.getName() << " is a kptr (" << g->section << "), not an integer; exchange it with ebpf.global.kptr_xchg";
          return;
        }
        if (g->section != "bss") {
          bad = true;
          gs.emitOpError() << "global @" << gs.getName() << " is in ." << g->section
                           << "; only .bss globals are writable (.rodata is frozen after load)";
          return;
        }
        if (checkKaddrGlobal(gs, g, gs.getValue().getType(), "stores to"))
          return;
        unsigned w = gs.getValue().getType().getIntOrFloatBitWidth();
        if (w != g->type.bits) {
          bad = true;
          gs.emitOpError() << "stores to global @" << gs.getName() << " as " << w << " bits, but the schema declares " << g->type.bits;
        }
      });
      // the kptr global ops name a data:<name> kptr global of the result's struct.
      auto checkKptrGlobal = [&](Operation *op, StringRef name, StringRef st) {
        const ::ebpf::Global *g = schema->global(name);
        if (!g) {
          bad = true;
          op->emitOpError() << "global @" << name << " is not declared in the schema (core.globals)";
          return;
        }
        if (!g->isKptr()) {
          bad = true;
          op->emitOpError() << "global @" << name << " is in ." << g->section
                            << ", not a kptr global (\"section\": \"data:<name>\", \"type\": {\"kind\": \"kptr\", …})";
          return;
        }
        if (g->kptr != st) {
          bad = true;
          op->emitOpError() << "global @" << name << " is a kptr to struct " << g->kptr << ", used as struct " << st;
        }
      };
      owner->walk([&](GlobalKPtrXchgOp x) {
        checkKptrGlobal(x, x.getName(), cast<KRefOrNullType>(x.getOld().getType()).getStructName());
      });
      owner->walk([&](GlobalKPtrLoadRcuOp lr) { checkKptrGlobal(lr, lr.getName(), lr.getPtr().getType().getStructName()); });
      // global.ref borrows a rodata / bss record global of the same record
      // and size; a .rodata borrow is read-only (frozen after load).
      owner->walk([&](GlobalRefOp gr) {
        const ::ebpf::Global *g = schema->global(gr.getName());
        if (!g) {
          bad = true;
          gr.emitOpError() << "global @" << gr.getName() << " is not declared in the schema (core.globals)";
          return;
        }
        if (!g->isRecord() || g->section == "data") {
          bad = true;
          if (g->section == "data")
            gr.emitOpError() << "global @" << gr.getName()
                             << " is a .data record; it is written only by ebpf.scx.exit_info, not borrowed";
          else
            gr.emitOpError() << "global @" << gr.getName() << " is " << (g->isKptr() ? "a kptr" : g->isKaddr() ? "a kaddr" : "an integer") << " global in ."
                             << g->section << "; ebpf.global.ref borrows a rodata / bss record global (\"record\": …)";
          return;
        }
        auto rt = cast<RecordType>(cast<BorrowedType>(gr.getRef().getType()).getPointee());
        const ::ebpf::Record *rec = findRecord(*schema, g->record);
        if (g->record != rt.getSymbol() || !rec || rec->size != (uint64_t)rt.getSize()) {
          bad = true;
          gr.emitOpError() << "borrows global @" << gr.getName() << " as record \"" << rt.getSymbol() << "\" of " << rt.getSize()
                           << " bytes, but the schema declares record \"" << g->record << "\""
                           << (rec ? " of " + std::to_string(rec->size) + " bytes" : std::string());
          return;
        }
        if (g->section != "rodata")
          return;
        SymbolTableCollection st;
        llvm::DenseSet<std::pair<Operation *, unsigned>> seen;
        if (Operation *w = readOnlyBorrowWrite(st, gr.getRef(), seen)) {
          bad = true;
          InFlightDiagnostic d = w->emitOpError();
          d << "may write the .rodata record global @" << gr.getName()
                                    << "; a .rodata global is read-only (frozen after load) — only field reads, element loads and "
                                       "calls to functions that only read it are allowed";
          d.attachNote(gr.getLoc()) << "borrowed here";
        }
      });
      // scx.exit_info writes a .data record of exactly the C struct
      // user_exit_info shape (user_exit_info.bpf.h), so one decoder reads both arms.
      owner->walk([&](ScxExitInfoOp ex) {
        const ::ebpf::Global *g = schema->global(ex.getUei());
        if (!g) {
          bad = true;
          ex.emitOpError() << "global @" << ex.getUei() << " is not declared in the schema (core.globals)";
          return;
        }
        if (g->section != "data") {
          bad = true;
          ex.emitOpError() << "global @" << ex.getUei() << " is in ." << g->section
                           << "; scx.exit_info writes a .data record global (\"section\": \"data\", \"record\": ...)";
          return;
        }
        const ::ebpf::Record *rec = findRecord(*schema, g->record);
        struct Want {
          const char *name;
          uint64_t offset;
          unsigned bits;  // Integer width, or element width of an array.
          uint64_t count; // 0 for a scalar.
        };
        static const Want want[] = {{"kind", 0, 32, 0},     {"exit_cpu", 4, 32, 0}, {"exit_code", 8, 64, 0},
                                    {"reason", 16, 8, 128}, {"msg", 144, 8, 1024}};
        constexpr uint64_t wantSize = 1168;
        std::string why;
        if (!rec)
          why = "record \"" + g->record + "\" is not declared";
        else if (rec->size != wantSize)
          why = "size is " + std::to_string(rec->size) + ", not " + std::to_string(wantSize);
        else if (rec->fields.size() != std::size(want))
          why = "it has " + std::to_string(rec->fields.size()) + " fields, not " + std::to_string(std::size(want));
        else
          for (auto [f, w] : llvm::zip(rec->fields, want)) {
            const ::ebpf::IntType *it = std::get_if<::ebpf::IntType>(&f.type.v);
            if (const auto *at = std::get_if<::ebpf::ArrayType>(&f.type.v); at && w.count)
              it = (at->count == w.count && at->element) ? std::get_if<::ebpf::IntType>(&at->element->v) : nullptr;
            else if (w.count)
              it = nullptr;
            if (f.name != w.name || f.offset != w.offset || !it || it->bits != w.bits) {
              why = "field \"" + f.name + "\" @" + std::to_string(f.offset) + " differs from \"" + w.name + "\" @" +
                    std::to_string(w.offset) + " " + (w.count ? "[" + std::to_string(w.count) + "]" : std::string()) +
                    "i" + std::to_string(w.bits);
              break;
            }
          }
        if (!why.empty()) {
          bad = true;
          ex.emitOpError() << "global @" << ex.getUei() << " must be the struct user_exit_info record "
                           << "{kind i32 @0, exit_cpu i32 @4, exit_code i64 @8, reason [128]i8 @16, msg [1024]i8 @144; 1168 bytes}: "
                           << why;
        }
      });
    };
    auto checkStoreFields = [&](Operation *owner) {
      // store_field offset/width must identify a schema integer field.
      owner->walk([&](RingbufStoreFieldOp sf) {
        auto res = cast<ReservationType>(sf.getReservation().getType());
        auto rt = dyn_cast<RecordType>(res.getRecordType());
        if (!rt)
          return; // Already rejected by the dialect verifier.
        const ::ebpf::Record *rec = findRecord(*schema, rt.getSymbol());
        if (!rec) {
          bad = true;
          sf.emitOpError() << "record \"" << rt.getSymbol()
                           << "\" is not declared in the schema";
          return;
        }
        unsigned bits = cast<IntegerType>(sf.getValue().getType()).getWidth();
        llvm::SmallVector<std::pair<uint64_t, unsigned>, 16> fields;
        flattenIntFields(*schema, *rec, 0, fields);
        for (auto [off, w] : fields)
          if (off == (uint64_t)sf.getOffset() && w == bits)
            return;
        bad = true;
        auto d = sf.emitOpError()
                 << "no integer field of record \"" << rt.getSymbol()
                 << "\" sits at offset " << sf.getOffset() << " with width "
                 << bits << " bits";
        std::string have;
        for (auto [off, w] : fields) {
          if (!have.empty())
            have += ", ";
          have += "i" + std::to_string(w) + "@" + std::to_string(off);
        }
        d.attachNote() << "schema fields (after expanding record_ref): " << have;
      });
    };
    // the scx_bpf_task_cgroup calls the member check below
    // examined; any other is rejected after the walk (fail closed).
    llvm::DenseSet<Operation *> taskCgroupChecked;
    getOperation().walk([&](ProgramOp prog) {
      // Match the program declaration itself when coverage requires it. Do not
      // infer disabled checking from an empty programs list: that could hide
      // omitted declarations. Only explicit coverage controls validation.
      const bool checkPrograms =
          schema->coverage().programs == ::ebpf::Coverage::Complete;
      const ::ebpf::Program *pdecl = nullptr;
      // ProgramKinds.def owns signature/attachment/architecture rules. Unknown
      // kinds have already failed operation verification.
      const bpfmlir::ProgramKindInfo *kinfo = bpfmlir::lookupProgramKind(prog.getKind());
      if (!kinfo)
        return;
      for (const ::ebpf::Program &p : schema->programs())
        if (p.name == prog.getSymName())
          pdecl = &p;
      if (checkPrograms && !pdecl) {
        bad = true;
        prog.emitOpError() << "program @" << prog.getSymName()
                           << " is not declared in the schema "
                           << "(coverage.programs = complete)";
        return;
      }
      if (pdecl && pdecl->kind != prog.getKind()) {
        bad = true;
        prog.emitOpError() << "program @" << prog.getSymName()
                           << " is declared \"" << pdecl->kind
                           << "\" in the schema but written as \""
                           << prog.getKind() << "\"";
        return;
      }

      {
        Block &entry = prog.getBody().front();
        checkMaps(prog, prog.getMapSymbolsAttr(), entry.getArguments().drop_front());
      }
      checkReserves(prog);

      // a sleepable fentry is declared twice (program keyword, schema flag)
      // and the two must agree — the keyword picks section fentry.s/<fn>, the
      // flag is what the schema consumers (bindgen, loaders) read. The program
      // must be declared even under partial coverage (like fentry attach_target).
      if (bpfmlir::kindHasFlagRow(*kinfo, "sleepable")) {
        if (prog.getSleepable() && !pdecl) {
          bad = true;
          prog.emitOpError() << "a sleepable " << prog.getKind() << " program @" << prog.getSymName()
                             << " must be declared in the schema with \"sleepable\": true";
          return;
        }
        if (pdecl && pdecl->sleepable != static_cast<bool>(prog.getSleepable())) {
          bad = true;
          prog.emitOpError() << "program @" << prog.getSymName() << (prog.getSleepable() ? " is written `sleepable` but the schema does not set"
                                                                                            : " is not written `sleepable` but the schema sets")
                             << " \"sleepable\": true";
          return;
        }
      }

      // Tracepoint targets, local argument types and kernel fields require
      // schema declarations regardless of coverage: schema is their type source.
      if (kinfo->sig == bpfmlir::SigFamily::TpArgs) {
        if (!pdecl) {
          bad = true;
          prog.emitOpError() << prog.getKind() << " program @" << prog.getSymName()
                             << " must be declared in the schema (its argument "
                                "types come from core.programs[].args)";
          return;
        }
        if (prog.getAttach() && *prog.getAttach() != pdecl->attachTarget) {
          bad = true;
          prog.emitOpError() << "attach \"" << *prog.getAttach()
                             << "\" does not match the schema attach_target \""
                             << pdecl->attachTarget << "\"";
        }
      }
      // perf.output uses the perf_event_array's nominal payload record, distinct
      // from its u32 FD map value.
      prog.walk([&](PerfOutputOp po) {
        auto arg = dyn_cast<BlockArgument>(po.getMap());
        ArrayAttr syms = prog.getMapSymbolsAttr();
        if (!arg || !syms || arg.getArgNumber() < 1 || arg.getArgNumber() > syms.size())
          return;
        StringRef sym = cast<FlatSymbolRefAttr>(syms[arg.getArgNumber() - 1]).getValue();
        const ::ebpf::Map *decl = nullptr;
        for (const ::ebpf::Map &m : schema->maps())
          if (m.symbol == sym)
            decl = &m;
        auto rt = cast<RecordType>(po.getRecord().getType());
        const ::ebpf::Record *rec = decl ? findRecord(*schema, decl->record) : nullptr;
        if (!decl || decl->record != rt.getSymbol() || !rec || rec->size != (uint64_t)rt.getSize()) {
          bad = true;
          po.emitOpError() << "sends record " << po.getRecord().getType() << " but the schema map @" << sym << " carries record \""
                           << (decl ? decl->record : std::string("?")) << "\"";
        }
      });
      checkGlobals(prog);
      // arena windows against the schema size (pages × 4096): len ≤ size
      // and a constant offset c ≤ size − len (subtraction form). The op
      // verifier does not know the size.
      prog.walk([&](ArenaAllocOp allocation) {
        auto arg = dyn_cast<BlockArgument>(allocation.getMap());
        ArrayAttr syms = prog.getMapSymbolsAttr();
        if (!arg || !syms || arg.getArgNumber() < 1 || arg.getArgNumber() > syms.size()) {
          bad = true;
          allocation.emitOpError("allocation map lacks its program/schema binding");
          return;
        }
        StringRef sym = cast<FlatSymbolRefAttr>(syms[arg.getArgNumber() - 1]).getValue();
        const ::ebpf::Map *decl = nullptr;
        for (const ::ebpf::Map &m : schema->maps())
          if (m.symbol == sym)
            decl = &m;
        uint64_t count = allocation.getPageCount(), off = allocation.getPageOffset();
        if (!decl || decl->kind != ::ebpf::MapKind::Arena || count > decl->maxEntries || off > decl->maxEntries - count) {
          bad = true;
          allocation.emitOpError("allocation page range exceeds its bound schema arena");
        }
      });
      prog.walk([&](ArenaCheckOp ac) {
        auto ab = ac.getBase().getDefiningOp<ArenaBaseOp>();
        auto arg = ab ? dyn_cast<BlockArgument>(ab.getMap()) : BlockArgument();
        ArrayAttr syms = prog.getMapSymbolsAttr();
        if (!arg || !syms || arg.getArgNumber() < 1 || arg.getArgNumber() > syms.size())
          return;
        StringRef sym = cast<FlatSymbolRefAttr>(syms[arg.getArgNumber() - 1]).getValue();
        const ::ebpf::Map *decl = nullptr;
        for (const ::ebpf::Map &m : schema->maps())
          if (m.symbol == sym)
            decl = &m;
        if (!decl || decl->kind != ::ebpf::MapKind::Arena)
          return; // checkMaps names the binding mismatch.
        auto segv = bpfabi::lookupMapFlag("segv_on_fault");
        if (segv && (decl->flags & static_cast<uint64_t>(*segv))) {
          auto allocation = ac->getParentOfType<ArenaAllocOp>();
          if (!allocation || !allocation.getAllocated().isAncestor(ac->getParentRegion())) {
            bad = true;
            ac.emitOpError("BPF_F_SEGV_ON_FAULT requires a live allocation success proof; bounds alone do not prove allocation");
            return;
          }
        }
        uint64_t size = decl->maxEntries * ::ebpf::kArenaPageSize, len = ac.getLen();
        if (len > size) {
          bad = true;
          ac.emitOpError() << "the window of " << len << " bytes is larger than the arena @" << sym << " (" << decl->maxEntries
                           << " pages = " << size << " bytes in the schema)";
          return;
        }
        APInt c;
        if (matchPattern(ac.getOffset(), m_ConstantInt(&c)) && (c.getActiveBits() > 64 || c.getZExtValue() > size - len)) {
          bad = true;
          ac.emitOpError() << "the window at constant offset " << c.getZExtValue() << " with " << len << " bytes exceeds the arena @"
                           << sym << " (" << size << " bytes in the schema); the offset must be at most " << (size - len);
        }
      });
      // Resolve tracepoint field names and compare offsets/widths with schema.
      // Operation offsets are copies, not authority; tpfield requirements
      // separately match target tracefs before load.
      prog.walk([&](TpFieldOp tf) {
        const ::ebpf::Program::TpField *f = pdecl ? pdecl->field(tf.getField()) : nullptr;
        if (!f) {
          bad = true;
          tf.emitOpError() << "reads field \"" << tf.getField() << "\", which is not declared in the schema fields of @" << prog.getSymName()
                           << " (its offset and type are checked against the tracefs format at load)";
          return;
        }
        if (f->arrayCount) {
          bad = true;
          tf.emitOpError("an array field must be read with ebpf.tp.field.copy");
          return;
        }
        if (tf.getOffset() != f->offset) {
          bad = true;
          tf.emitOpError() << "reads field \"" << tf.getField() << "\" at offset " << tf.getOffset() << ", but the schema fields declare offset "
                           << f->offset;
        }
        bool isUserStr = isa<UserStrType>(tf.getResult().getType());
        bool isUserArray = isa<UserStrArrayType>(tf.getResult().getType());
        if (isUserStr != f->userStr || isUserArray != f->userStrArray) {
          bad = true;
          tf.emitOpError() << "reads field \"" << tf.getField() << "\" as " << tf.getResult().getType()
                          << ", but the schema fields declare " << (f->userStrArray ? "user_str_array" : f->userStr ? "user_str" : "an integer");
          return;
        }
        unsigned w = isUserStr || isUserArray ? 64 : tf.getResult().getType().getIntOrFloatBitWidth();
        if (w != f->type.bits) {
          bad = true;
          tf.emitOpError() << "reads field \"" << tf.getField() << "\" as " << w << " bits, but the schema fields declare " << f->type.bits;
        }
      });
      prog.walk([&](TpFieldCopyOp tc) {
        const auto *f = pdecl ? pdecl->field(tc.getField()) : nullptr;
        if (!f || !f->arrayCount || f->offset != tc.getOffset()) {
          bad = true;
          tc.emitOpError("needs a schema byte-array field with the same name and offset");
          return;
        }
        // Pass the schema's checked count to VerifyRecords, which runs after BuildBTFTypes.
        // Always overwrite input metadata: a caller-supplied count is not evidence.
        tc->setAttr("ebpf.tp_array_count", IntegerAttr::get(IntegerType::get(tc.getContext(), 64), f->arrayCount));
      });
      // fexit ctx.retval argument count/width must match schema nargs/ret.
      prog.walk([&](CtxRetvalOp rv) {
        if (pdecl && pdecl->nargs < 0 && pdecl->hasRet) { // ret without nargs — no N to read after.
          bad = true;
          rv.emitOpError() << "reads the return value after " << rv.getNargs() << " arguments, but the schema of @" << prog.getSymName()
                           << " declares no nargs (use ebpf.ctx.func_ret, or declare nargs)";
          return;
        }
        if (!pdecl || pdecl->nargs < 0) {
          bad = true;
          rv.emitOpError() << "reads the return value but the schema declares no signature (nargs / ret) for @" << prog.getSymName();
          return;
        }
        if (rv.getNargs() != pdecl->nargs) {
          bad = true;
          rv.emitOpError() << "reads the return value after " << rv.getNargs() << " arguments, but the schema signature has nargs "
                           << pdecl->nargs;
        }
        unsigned w = rv.getResult().getType().getIntOrFloatBitWidth();
        if (w != pdecl->ret.bits) {
          bad = true;
          rv.emitOpError() << "reads a " << w << "-bit return value, but the schema signature returns " << pdecl->ret.bits << " bits";
        }
      });
      // ctx.func_ret checks the width only (iW has no sign); the schema's
      // i / u goes to the funcret / retsig row and is checked against the target.
      prog.walk([&](CtxFuncRetOp fr) {
        if (!pdecl || !pdecl->hasRet) {
          bad = true;
          fr.emitOpError() << "reads the return value but the schema declares no ret for @" << prog.getSymName();
          return;
        }
        unsigned w = fr.getResult().getType().getIntOrFloatBitWidth();
        if (w != pdecl->ret.bits) {
          bad = true;
          fr.emitOpError() << "reads a " << w << "-bit return value, but the schema signature returns " << pdecl->ret.bits << " bits";
        }
      });
      // ext.arg index must be below nargs with args[index] width; return width
      // must match ret. Schema feeds extret/extarg requirements and FUNC_PROTO.
      if (kinfo->sig == bpfmlir::SigFamily::ExtSig && pdecl) {
        prog.walk([&](ExtArgOp ea) {
          if (ea.getIndex() >= pdecl->nargs) {
            bad = true;
            ea.emitOpError() << "reads argument " << ea.getIndex() << ", but the schema signature of @" << prog.getSymName() << " has nargs "
                             << pdecl->nargs;
            return;
          }
          unsigned w = ea.getResult().getType().getIntOrFloatBitWidth();
          const std::string &want = pdecl->args[ea.getIndex()];
          if (want.substr(1) != std::to_string(w)) {
            bad = true;
            ea.emitOpError() << "reads argument " << ea.getIndex() << " as " << w << " bits, but the schema args declares \"" << want << "\"";
          }
        });
        prog.walk([&](ReturnOp r) {
          unsigned w = r.getValue().getType().getIntOrFloatBitWidth();
          if (w != pdecl->ret.bits) {
            bad = true;
            r.emitOpError() << "returns a " << w << "-bit value, but the schema signature returns " << pdecl->ret.bits << " bits";
          }
        });
      }
      // Void struct_ops members permit only done, not integer returns (which can
      // pass kernel verification). Integer member returns require matching width.
      if (kinfo->sig == bpfmlir::SigFamily::OpsSig && pdecl && pdecl->nargs >= 0) {
        prog.walk([&](ReturnOp r) {
          unsigned w = r.getValue().getType().getIntOrFloatBitWidth();
          if (pdecl->retVoid) {
            bad = true;
            r.emitOpError() << "returns a value, but the schema signature of @" << prog.getSymName()
                            << " returns void (end it with ebpf.verdict \"done\")";
          } else if (w != pdecl->ret.bits) {
            bad = true;
            r.emitOpError() << "returns a " << w << "-bit value, but the schema signature returns " << pdecl->ret.bits << " bits";
          }
        });
      }
      // trace.printk in a struct_ops program body — only a sched_ext_ops
      // member (also without a schema declaration: no member is no evidence).
      if (kinfo->sig == bpfmlir::SigFamily::OpsSig)
        prog.walk([&](TracePrintkOp tp) {
          std::string opsType, member;
          if (pdecl)
            for (const ::ebpf::Map &m : schema->maps())
              if (m.structOps && m.symbol == pdecl->attachTarget)
                for (const auto &o : m.structOps->ops)
                  if (o.program == pdecl->name) {
                    opsType = m.structOps->type;
                    member = o.member;
                  }
          if (opsType == bpfmlir::kScxOpsType)
            return;
          bad = true;
          tp.emitOpError() << structOpsPrintkRule(("@" + prog.getSymName()).str(),
                                                  opsType.empty() ? std::string("no struct_ops member") : opsType + "." + member);
        });
      // the sched_ext kfunc contract needs the member the program
      // implements (schema struct_ops map type and ops[].member). The table
      // ScxContract.def is keyed by (ops type, member).
      if (kinfo->sig == bpfmlir::SigFamily::OpsSig && pdecl) {
        std::string opsType, member;
        const ::ebpf::Map *opsMap = nullptr;
        for (const ::ebpf::Map &m : schema->maps())
          if (m.structOps && m.symbol == pdecl->attachTarget)
            for (const auto &o : m.structOps->ops)
              if (o.program == pdecl->name) {
                opsType = m.structOps->type;
                member = o.member;
                opsMap = &m;
              }
        // task->cpus_ptr is MEM_RCU only in the RCU read section; a
        // sleepable sched_ext program would read it PTR_UNTRUSTED.
        if (opsType == bpfmlir::kScxOpsType && pdecl->sleepable)
          prog.walk([&](KFieldPtrOp fp) {
            if (fp.getField() == "cpus_ptr" && fp.getBaseStructName() == "task_struct" && !fp->getParentOfType<RcuRegionOp>()) { // an explicit RCU section is the read section
              bad = true;
              fp.emitOpError() << "reads task_struct.cpus_ptr in @" << prog.getSymName() << ", a sleepable " << opsType << "." << member
                               << " program — outside the RCU read section the verifier marks it untrusted (only non-sleepable members)";
            }
          });
        // sched_ext kfuncs of the generic kfunc.call. The
        // kernel filter rejects them from a non-SCX struct_ops program (7.1.8 /
        // 7.3.1; 6.12.111 has no filter) — the compiler takes the strict side.
        if (opsType != bpfmlir::kScxOpsType)
          prog.walk([&](KfuncCallOp call) {
            if (!bpfmlir::isScxGenericKfunc(call.getCallee()))
              return;
            taskCgroupChecked.insert(call);
            bad = true;
            call.emitOpError() << "calls " << call.getCallee() << ", a sched_ext kfunc, in @" << prog.getSymName() << ", which implements "
                               << (opsType.empty() ? std::string("no struct_ops member") : opsType + "." + member)
                               << " — in a struct_ops program the kernel's scx_kfunc_context_filter allows it only for " << bpfmlir::kScxOpsType;
          });
        // scx_bpf_task_cgroup(p) is scx_error at run time
        // unless p is in current->scx.kf_tasks[] (7.3.1 ext/internal.h:2382-2392;
        // 6.12.111 / 7.1.8 the same) — the verifier accepts any trusted task. The
        // compiler takes only a task argument of the member at a kf_tasks position
        // (ScxContract.def EBPF_SCX_TASKARGS): ctx.arg, then kptr.check.
        if (opsType == bpfmlir::kScxOpsType)
          prog.walk([&](KfuncCallOp call) {
            if (call.getCallee() != bpfmlir::kScxTaskCgroupKfunc || call.getArgs().empty())
              return;
            taskCgroupChecked.insert(call);
            uint32_t mask = bpfmlir::scxTaskArgMask(opsType, member);
            Value nullable = scxCheckedFromKPtr(call.getArgs().front());
            auto arg = nullable ? nullable.getDefiningOp<CtxArgOp>() : CtxArgOp();
            if (arg && arg.getIndex() < 32 && (mask & (1u << arg.getIndex())))
              return;
            bad = true;
            auto d = call.emitOpError() << "calls " << call.getCallee() << " in @" << prog.getSymName() << " (" << opsType << "." << member << ") on ";
            if (!arg)
              d << "a task that is not a checked task argument of the member (ctx.arg, then ebpf.kptr.check)";
            else
              d << "argument " << arg.getIndex() << ", which the kernel does not put in current->scx.kf_tasks";
            d << " — the kernel fails the scheduler with scx_error on a task it is not operating on (task arguments only of: "
              << bpfmlir::scxTaskArgMembers() << ")";
          });
        // a kptr field read is MEM_RCU only in the RCU read section — the
        // whole program when not sleepable, an ebpf.rcu.region when sleepable.
        if (pdecl->sleepable)
          prog.walk([&](KPtrLoadRcuOp lr) {
            if (lr->getParentOfType<RcuRegionOp>())
              return;
            bad = true;
            lr.emitOpError() << "reads a kptr field in @" << prog.getSymName() << ", a sleepable " << opsType << "." << member
                             << " program, outside ebpf.rcu.region — the verifier marks it untrusted there (only inside the section)";
          });
        if (pdecl->sleepable) // a kptr global read follows the same section rule.
          prog.walk([&](GlobalKPtrLoadRcuOp lr) {
            if (lr->getParentOfType<RcuRegionOp>())
              return;
            bad = true;
            lr.emitOpError() << "reads a kptr global in @" << prog.getSymName() << ", a sleepable " << opsType << "." << member
                             << " program, outside ebpf.rcu.region — the verifier marks it untrusted there (only inside the section)";
          });
        if (pdecl->sleepable && !bpfmlir::scxSleepableMember(opsType, member)) {
          bad = true;
          prog.emitOpError() << "program @" << prog.getSymName() << " is declared sleepable, but " << opsType << "." << member
                             << " is not a member the compiler loads sleepable (ScxContract.def: " << bpfmlir::scxSleepableMembers() << ")";
        }
        // the DSQ iterator is scx_kfunc_ids_any (every sched_ext_ops
        // member — ext.c:11084-11085); its _new is KF_RCU_PROTECTED, so a
        // sleepable member needs ebpf.rcu.region (verifier.c:13993-13994).
        prog.walk([&](IterScxDsqOp it) {
          if (opsType != bpfmlir::kScxOpsType) {
            bad = true;
            it.emitOpError() << "is only for programs implementing a " << bpfmlir::kScxOpsType << " member, but @" << prog.getSymName()
                             << " implements " << (opsType.empty() ? std::string("no struct_ops member") : opsType + "." + member);
            return;
          }
          if (pdecl->sleepable && !it->getParentOfType<RcuRegionOp>()) {
            bad = true;
            it.emitOpError() << "starts bpf_iter_scx_dsq_new (KF_RCU_PROTECTED) outside the RCU read section: @" << prog.getSymName()
                             << " is a sleepable " << opsType << "." << member
                             << " program — put the iterator inside ebpf.rcu.region (the verifier rejects it outside a section)";
          }
        });
        // struct_ops timers (the kind's OPS tag "timer") only in a
        // sleepable sched_ext_ops member (LAVD's init — decision 4); others are
        // out of the decided scope.
        prog.walk([&](Operation *op) {
          // ebpf.timer.cancel's closed kind set is xdp / fentry / fexit / tp_btf (the timer.start sets without struct_ops) — not in struct_ops.
          if (isa<TimerCancelOp>(op)) {
            bad = true;
            op->emitOpError() << "is not available in a struct_ops program (@" << prog.getSymName()
                              << "): the first step of timer cancel covers xdp / fentry / fexit / tp_btf only";
            return;
          }
          if (!isa<TimerInitOp, TimerSetCallbackOp, TimerStartOp>(op))
            return;
          if (opsType != bpfmlir::kScxOpsType || !pdecl->sleepable) {
            bad = true;
            op->emitOpError() << "in a struct_ops program is only for a sleepable " << bpfmlir::kScxOpsType << " member ("
                              << bpfmlir::scxSleepableMembers() << " declared \"sleepable\": true), but @" << prog.getSymName()
                              << " implements "
                              << (opsType.empty() ? std::string("no struct_ops member") : opsType + "." + member)
                              << (pdecl->sleepable ? "" : " and is not sleepable") << " (other members are out of scope)";
          }
        });
        // (d): the string buffers exist only for scx.dump's %s, so
        // only in the dump members (scxDumpMember — as scx.dump below).
        prog.walk([&](Operation *op) {
          if (!isa<StrBufLiteralOp, KernelReadStrBufOp>(op))
            return;
          if (opsType != bpfmlir::kScxOpsType || !bpfmlir::scxDumpMember(opsType, member)) {
            bad = true;
            op->emitOpError() << "is only in the dump, dump_cpu and dump_task members of " << bpfmlir::kScxOpsType << ", but @"
                              << prog.getSymName() << " implements "
                              << (opsType.empty() ? std::string("no struct_ops member") : opsType + "." + member) << "";
          }
        });
        prog.walk([&](Operation *op) {
          StringRef name = op->getName().getStringRef();
          if (!name.consume_front("ebpf.scx."))
            return;
          // scx.const calls no kfunc but is still sched_ext_ops only (H2 —
          // it skipped this check before).
          const bpfmlir::ScxKfuncInfo *info = bpfmlir::lookupScxOp(name);
          if (!info && name != "const" && name != "exit_info") // exit_info calls no kfunc either.
            return; // The op verifier names ops without a row.
          if (opsType != bpfmlir::kScxOpsType) {
            bad = true;
            op->emitOpError() << "is only for programs implementing a " << bpfmlir::kScxOpsType << " member, but @" << prog.getSymName()
                              << " implements " << (opsType.empty() ? std::string("no struct_ops member") : opsType + "." + member);
            return;
          }
          if (!info)
            return; // scx.const / scx.exit_info: no kfunc group or sleepable flag to check.
          if (!bpfmlir::scxMemberAllows(*info, opsType, member)) {
            bad = true;
            op->emitOpError() << "calls " << info->kfunc << ", which " << opsType << "." << member
                              << " may not call (scx_kf_allow_flags — allowed in: " << bpfmlir::scxMembersAllowing(*info) << ")";
            return;
          }
          const bpfabi::KfuncABI *k = bpfabi::lookupKfunc(info->kfunc);
          if (k && k->hasFlag("sleepable") && !pdecl->sleepable) {
            bad = true;
            op->emitOpError() << "calls " << info->kfunc << " (KF_SLEEPABLE), but @" << prog.getSymName()
                              << " is not sleepable (declare \"sleepable\": true in the schema program)";
          }
          // the RCU read section is the whole non-sleepable program
          // (!in_sleepable(env) in 6.12.111 / 7.1.8 / 7.3.1); no explicit lock in B1.
          if (bpfmlir::scxNeedsRcuSection(name) && pdecl->sleepable && !op->getParentOfType<RcuRegionOp>()) { // inside ebpf.rcu.region the section is explicit
            bad = true;
            op->emitOpError() << "calls " << info->kfunc << ", which needs the RCU read section, but @" << prog.getSymName()
                              << " is a sleepable " << opsType << "." << member << " program (only non-sleepable members)";
          }
          if (name == "dump" && !bpfmlir::scxDumpMember(opsType, member)) {
            bad = true;
            op->emitOpError() << "calls " << info->kfunc << " in " << opsType << "." << member
                              << "; the compiler allows it only in the dump, dump_cpu and dump_task members";
          }
          // with update_idle, the built-in idle tracking (and so
          // pick_idle_cpu) needs SCX_OPS_KEEP_BUILTIN_IDLE in the ops flags.
          if (name == "pick_idle_cpu" && opsMap &&
              llvm::any_of(opsMap->structOps->ops, [](const auto &o) { return o.member == "update_idle"; })) {
            const bpfabi::ScxEnumABI *keep = bpfabi::lookupScxEnum("SCX_OPS_KEEP_BUILTIN_IDLE");
            uint64_t flags = 0;
            for (const auto &d : opsMap->structOps->data)
              if (d.member == "flags")
                flags = d.value;
            if (!keep) {
              bad = true;
              op->emitOpError() << "needs the scxenum row SCX_OPS_KEEP_BUILTIN_IDLE in the UAPI table to check the ops flags";
            } else if (!(flags & keep->value)) {
              bad = true;
              op->emitOpError() << "calls " << info->kfunc << ", but struct_ops map \"" << opsMap->symbol
                                << "\" implements update_idle without SCX_OPS_KEEP_BUILTIN_IDLE (0x" << llvm::utohexstr(keep->value)
                                << ") in its flags (0x" << llvm::utohexstr(flags) << ") — the kernel then stops built-in idle tracking";
            }
          }
        });
      }
      // Match attachment-bearing kinds outside tracepoint/probe families.
      // A kind with only an empty default attachment row behaves like None;
      // explicit attachment shapes require a declaration.
      if (bpfmlir::kindTakesAttach(*kinfo) && kinfo->sig != bpfmlir::SigFamily::TpArgs && !kinfo->arch) {
        if (!pdecl) {
          bad = true;
          prog.emitOpError() << prog.getKind() << " program @" << prog.getSymName()
                             << " must be declared in the schema (its attach target is core.programs[].attach_target)";
          return;
        }
        if (prog.getAttach() && *prog.getAttach() != pdecl->attachTarget) {
          bad = true;
          prog.emitOpError() << "attach \"" << *prog.getAttach()
                             << "\" does not match the schema attach_target \"" << pdecl->attachTarget << "\"";
        }
      }
      // Probe targets and architecture must match schema; argument indices fit
      // architecture ABI bounds and parameter types match declarations.
      if (kinfo->arch) { // Probe families identified by ARCH.
        if (!pdecl) {
          bad = true;
          prog.emitOpError() << prog.getKind() << " program @" << prog.getSymName()
                             << " must be declared in the schema (attach_target, arch and params)";
          return;
        }
        if (prog.getAttach() && *prog.getAttach() != pdecl->attachTarget) {
          bad = true;
          prog.emitOpError() << "attach \"" << *prog.getAttach()
                             << "\" does not match the schema attach_target \"" << pdecl->attachTarget << "\"";
        }
        // Multi-probe target names must match schema order, which determines
      // mtarget indices and loader cookies.
        if (ArrayAttr list = prog.getAttachListAttr()) {
          std::vector<std::string> names;
          for (Attribute a : list)
            names.push_back(cast<StringAttr>(a).getValue().str());
          if (names != pdecl->attachTargets) {
            bad = true;
            auto join = [](const std::vector<std::string> &v) {
              std::string s = "[";
              for (size_t i = 0; i < v.size(); ++i)
                s += (i ? ", \"" : "\"") + v[i] + "\"";
              return s + "]";
            };
            prog.emitOpError() << "attach " << join(names) << " does not match the schema attach_target " << join(pdecl->attachTargets)
                               << " (same names in the same order — the index is the attach cookie)";
          }
        }
        if (prog.getArch() && *prog.getArch() != pdecl->arch) {
          bad = true;
          prog.emitOpError() << "arch \"" << *prog.getArch() << "\" does not match the schema arch \"" << pdecl->arch << "\"";
        }
        int maxN = mlir::bpfabi::kprobeArgCount(pdecl->arch);
        auto checkArg = [&](Operation *op, int64_t n, Type rt) {
          if (n > maxN) {
            bad = true;
            op->emitOpError() << "argument " << n << " is not in a register on " << pdecl->arch << " (the calling convention passes "
                              << maxN << " arguments in pt_regs)";
            return;
          }
          const ::ebpf::Program::Param *q = pdecl->param(n);
          if (!q) {
            bad = true;
            op->emitOpError() << "argument " << n << " is not declared in the schema params of @" << prog.getSymName()
                              << (!bpfmlir::attachesUserSymbol(kinfo->attach) ? " (its type is checked against the kernel function at load)"
                                                             : " (its type is checked against the binary's DWARF at load)");
            return;
          }
          // User-string pointers must pair with user_str, never integer declarations.
          if (isa<UserBufType>(rt) != q->userBuf) {
            bad = true;
            op->emitOpError() << "reads argument " << n << " as " << rt
                             << ", but the schema params declares " << (q->userBuf ? "a user_buf" : "a non-buffer argument");
            return;
          }
          if (q->userBuf)
            return;
          if (isa<UserStrType>(rt) != q->userStr) {
            bad = true;
            op->emitOpError() << "reads argument " << n << " as " << rt << ", but the schema params declares "
                              << (q->userStr ? "a user_str" : "an integer");
            return;
          }
          if (q->userStr)
            return;
          unsigned w = rt.getIntOrFloatBitWidth();
          // Raw pointer identity is i64 only: truncating addresses loses usable identity.
          if (q->ptr && w != 64) {
            bad = true;
            op->emitOpError() << "reads argument " << n << " as " << w << " bits, but the schema params declares a ptr (read it as i64 — the raw 8-byte value)";
            return;
          }
          if (w != q->type.bits) {
            bad = true;
            op->emitOpError() << "reads argument " << n << " as " << w << " bits, but the schema params declares " << q->type.bits;
          }
        };
        prog.walk([&](KprobeArgOp ka) { checkArg(ka, ka.getN(), ka.getResult().getType()); });
        prog.walk([&](KernelReadScalarOp read) {
          auto arg = read.getAddr().getDefiningOp<KprobeArgOp>();
          const ::ebpf::Program::Param *q = arg ? pdecl->param(arg.getN()) : nullptr;
          if (!q || !q->ptr) {
            bad = true;
            read.emitOpError("address kprobe.arg must be declared ptr in the schema params");
          }
        });
        prog.walk([&](UprobeArgOp ua) { checkArg(ua, ua.getN(), ua.getResult().getType()); });
        // ksyscall indices fit architecture ksyscallarg bounds and match schema
        // syscall-parameter widths; ptr requires i64.
        prog.walk([&](KsyscallArgOp sa) {
          int maxS = mlir::bpfabi::ksyscallArgCount(pdecl->arch);
          if (sa.getN() > maxS) {
            bad = true;
            sa.emitOpError() << "syscall argument " << sa.getN() << " is not in the UAPI table of " << pdecl->arch << " (" << maxS
                             << " ksyscallarg rows)";
            return;
          }
          const ::ebpf::Program::Param *q = pdecl->param(sa.getN());
          if (!q) {
            bad = true;
            sa.emitOpError() << "syscall argument " << sa.getN() << " is not declared in the schema params of @" << prog.getSymName()
                             << " (its type is checked against the target's syscall at load)";
            return;
          }
          bool userStr = isa<UserStrType>(sa.getResult().getType());
          bool userArray = isa<UserStrArrayType>(sa.getResult().getType());
          if (userStr != q->userStr || userArray != q->userStrArray) {
            bad = true;
            sa.emitOpError("user_str result must match a user_str schema param (ptr and integers are not interchangeable)");
            return;
          }
          unsigned w = userStr || userArray ? 64 : sa.getResult().getType().getIntOrFloatBitWidth();
          unsigned want = q->ptr ? 64 : q->type.bits;
          if (w != want) {
            bad = true;
            sa.emitOpError() << "reads syscall argument " << sa.getN() << " as " << w << " bits, but the schema params declares "
                             << (q->ptr ? "a ptr (read it as i64 — the raw 8-byte value)" : std::to_string(want)) << "";
          }
        });
        // Target-specific argument n must exist at target_params[i] with matching
        // width; ptr requires i64.
        prog.walk([&](ProbeTargetArgOp ta) {
          size_t i = static_cast<size_t>(ta.getTarget());
          if (pdecl->targetParams.empty()) {
            bad = true;
            ta.emitOpError() << "reads per-target arguments, but the schema program @" << prog.getSymName() << " has no target_params";
            return;
          }
          if (ta.getN() > maxN) {
            bad = true;
            ta.emitOpError() << "argument " << ta.getN() << " is not in a register on " << pdecl->arch << " (the calling convention passes " << maxN
                             << " arguments in pt_regs)";
            return;
          }
          const ::ebpf::Program::Param *q = pdecl->targetParam(i, ta.getN());
          if (isa<UserBufType>(ta.getValue().getType()) || (q && q->userBuf)) {
            if (!q || !q->userBuf || !isa<UserBufType>(ta.getValue().getType())) {
              bad = true;
              ta.emitOpError("user_buf result must match a user_buf schema target param");
            }
            return;
          }
          if (q && isa<UserStrType>(ta.getValue().getType())) {
            if (!q->userStr) {
              bad = true;
              ta.emitOpError() << "reads argument " << ta.getN() << " of target " << i
                               << " as user_str, but the schema target_params[" << i << "] declares an integer";
            }
            return;
          }
          if (!q || q->userStr) {
            bad = true;
            ta.emitOpError() << "argument " << ta.getN() << " of target " << i << " is not declared as an integer in the schema target_params["
                             << i << "] of @" << prog.getSymName() << "";
            return;
          }
          unsigned w = ta.getValue().getType().getIntOrFloatBitWidth();
          unsigned want = q->ptr ? 64 : q->type.bits;
          if (w != want) {
            bad = true;
            ta.emitOpError() << "reads argument " << ta.getN() << " of target " << i << " as " << w << " bits, but the schema target_params["
                             << i << "] declares " << (q->ptr ? "a ptr (read it as i64)" : std::to_string(want)) << "";
          }
        });
        // USDT locations come from loader note specs, not register conventions.
        // Match n and width to schema params; pre-load usdtarg matching checks
        // note size/sign spellings.
        prog.walk([&](UsdtArgOp ua) {
          const ::ebpf::Program::Param *q = pdecl->param(ua.getN());
          if (!q) {
            bad = true;
            ua.emitOpError() << "argument " << ua.getN() << " is not declared in the schema params of @" << prog.getSymName()
                             << " (its size and sign are checked against the USDT note at load)";
            return;
          }
          unsigned w = ua.getValue().getType().getIntOrFloatBitWidth();
          if (w != q->type.bits) {
            bad = true;
            ua.emitOpError() << "reads argument " << ua.getN() << " as " << w << " bits, but the schema params declares " << q->type.bits
                             << "";
          }
        });
      }
      prog.walk([&](CtxArgOp arg) {
        // iter ctx.arg is only index-zero bpf_iter_meta, enforced by op verification;
      // iterator schema has no args.
        if (const bpfmlir::ProgramKindInfo *ak = bpfmlir::lookupProgramKind(cast<ContextType>(arg.getCtx().getType()).getKind());
            ak && ak->sig == bpfmlir::SigFamily::Iter)
          return;
        if (!pdecl || arg.getIndex() >= (int64_t)pdecl->args.size()) {
          bad = true;
          arg.emitOpError() << "argument " << arg.getIndex()
                            << " is not declared in the schema args of @"
                            << prog.getSymName();
          return;
        }
        const std::string &want = pdecl->args[arg.getIndex()];
        // Unread '-' is not accessible; integers require equal width. Signedness
        // belongs to schema because IR read types are signless.
        std::string got;
        if (auto kp = dyn_cast<KPtrType>(arg.getResult().getType()))
          got = kp.getStructName().str();
        else if (auto kn = dyn_cast<KPtrOrNullType>(arg.getResult().getType()))
          got = kn.getStructName().str() + "?"; // Nullable struct-pointer argument declared by schema.
        else
          got = "i" + std::to_string(cast<IntegerType>(arg.getResult().getType()).getWidth());
        if (want == "-") {
          bad = true;
          arg.emitOpError() << "argument " << arg.getIndex() << " is declared as not read (null) in the schema args";
        } else if (isa<KPtrOrNullType>(arg.getResult().getType()) && bpfmlir::lookupProgramKind(cast<ContextType>(arg.getCtx().getType()).getKind()) &&
                   (bpfmlir::lookupProgramKind(cast<ContextType>(arg.getCtx().getType()).getKind())->sig == bpfmlir::SigFamily::FuncArgs ||
                    bpfmlir::lookupProgramKind(cast<ContextType>(arg.getCtx().getType()).getKind())->sig == bpfmlir::SigFamily::HookArgs || // Include LSM.
                    bpfmlir::lookupProgramKind(cast<ContextType>(arg.getCtx().getType()).getKind())->sig == bpfmlir::SigFamily::OpsSig) && // Include struct_ops.
                   (want == got || want + "?" == got)) {
          // fentry always returns nullable kernel pointers; schema may declare S or S?.
        } else if (isa<KPtrType>(arg.getResult().getType()) && want == got + "?") {
          bad = true;
          arg.emitOpError() << "argument " << arg.getIndex() << " is declared nullable in the schema; read it as !ebpf.kptr_or_null<\""
                            << got << "\"> and check it with ebpf.kptr.check";
        } else if (::ebpf::isEnumArgSpelling(want)) {
          // struct_ops enum: raw iN bits of the declared BTF enum width.
          if (!isa<IntegerType>(arg.getResult().getType()) || StringRef(want).drop_front(5) != StringRef(got).drop_front(1)) {
            bad = true;
            arg.emitOpError() << "argument " << arg.getIndex() << " is declared as \"" << want << "\" in the schema but read as \"" << got
                              << "\" (an enum argument is read as an integer of its width)";
          }
        } else if (::ebpf::isTPArgScalarSpelling(want) != isa<IntegerType>(arg.getResult().getType()) ||
                   (isa<IntegerType>(arg.getResult().getType()) ? want.substr(1) != got.substr(1) : want != got)) {
          bad = true;
          arg.emitOpError() << "argument " << arg.getIndex() << " is declared as \""
                            << want << "\" in the schema but read as \"" << got << "\"";
        }
      });
      // VerifyKPtr owns kernel field/type matching against @kernel declarations.

      checkStoreFields(prog);
    });

    for (auto fn : getOperation().getOps<SubprogramOp>()) {
      Block &entry = fn.getBody().front();
      checkMaps(fn, fn.getMapSymbolsAttr(),
                entry.getArguments().drop_front(fn.getFunctionType().getNumInputs()));
      checkReserves(fn);
      checkStoreFields(fn);
      checkGlobals(fn);
    }
    // Module-level user_ringbuf callbacks are outside program/func walks, so
    // check their globals separately.
    for (auto cb : getOperation().getOps<UserRingbufCallbackOp>())
      checkGlobals(cb);
    // a sched_ext_ops owner's timer callback body may use the global ops.
    for (auto cb : getOperation().getOps<TimerCallbackOp>())
      checkGlobals(cb);

    // the member and sleepable rules above, for the
    // context-dependent ops of an ebpf.func, in every context that reaches it
    // (CallContexts.h). sleepable is in_sleepable_context: the program body of
    // a program loaded sleepable (OPS tag or schema) with no ebpf.rcu.region on
    // the call path or around the op. ebpf-verify-call-contexts checked the
    // kind-level rules and rejects these ops in helper callback contexts; :
    // the timer callback bodies are walked too, with the timer context's rules
    // (not sleepable, RCU only inside a held ebpf.rcu.region). One failing
    // context is named per op.
    {
      struct OwnerFacts {
        const ::ebpf::Program *pdecl = nullptr;
        const bpfmlir::ProgramKindInfo *kinfo = nullptr;
        std::string opsType, member;
        const ::ebpf::Map *opsMap = nullptr;
      };
      std::map<Operation *, OwnerFacts> facts; // Stable references.
      auto factsOf = [&](ProgramOp prog) -> const OwnerFacts & {
        auto [it, inserted] = facts.try_emplace(prog.getOperation());
        OwnerFacts &f = it->second;
        if (!inserted)
          return f;
        f.kinfo = bpfmlir::lookupProgramKind(prog.getKind());
        for (const ::ebpf::Program &p : schema->programs())
          if (p.name == prog.getSymName())
            f.pdecl = &p;
        if (f.pdecl)
          for (const ::ebpf::Map &m : schema->maps())
            if (m.structOps && m.symbol == f.pdecl->attachTarget)
              for (const auto &o : m.structOps->ops)
                if (o.program == f.pdecl->name) {
                  f.opsType = m.structOps->type;
                  f.member = o.member;
                  f.opsMap = &m;
                }
        return f;
      };
      // sl: the context may sleep (the constraint — an ebpf.rcu.region on the
      // path ends it, also across a global callee). rcuOk: an RCU-dependent op
      // has its read section (the guarantee; a global callee does not
      // inherit the caller's section). Without a global callee on the way
      // !rcuOk is sl in a program body context.
      auto ruleFor = [&](Operation *op, const CallContext &c, const OwnerFacts &f, bool sl, bool rcuOk) -> std::string {
        StringRef name = op->getName().getStringRef();
        bool ops = f.kinfo && f.kinfo->sig == bpfmlir::SigFamily::OpsSig && f.pdecl;
        std::string impl = f.opsType.empty() ? std::string("no struct_ops member") : f.opsType + "." + f.member;
        // why a caller's ebpf.rcu.region does not count here.
        std::string rcuNote = c.inRcu && !c.rcuHeld
                                  ? std::string("; the caller's ebpf.rcu.region does not reach into a global function (7.1.8 / "
                                                "6.12.111 / 6.6.157 verify a global function once with the program's sleepable "
                                                "flag — put the section in the global function's body)")
                                  : std::string();
        // The context the RCU rules name: sleepable, or a global
        // function verified with the program's sleepable flag.
        std::string slCtx = rcuNote.empty() ? std::string("in a sleepable context")
                                            : std::string("in a program loaded sleepable, past a global function on the call path");
        // a timer callback context is not sleepable and has
        // no RCU read section unless an ebpf.rcu.region is held. The sched_ext
        // op set (kScxTimerCallbackOps) and the kind-level rules are in
        // ebpf-verify-call-contexts; here the schema-level ones.
        if (c.entryKind == CallEntry::TimerCallback) {
          if (name.starts_with("ebpf.scx.")) {
            if (const bpfmlir::ScxKfuncInfo *info = bpfmlir::lookupScxOp(name.drop_front(StringRef("ebpf.scx.").size())))
              if (const bpfabi::KfuncABI *k = bpfabi::lookupKfunc(info->kfunc); k && k->hasFlag("sleepable"))
                return "calls " + info->kfunc.str() + " (KF_SLEEPABLE) in an ebpf.timer.callback context, which is not sleepable";
          }
          if (auto call = dyn_cast<KfuncCallOp>(op); call && f.opsType != bpfmlir::kScxOpsType && bpfmlir::isScxGenericKfunc(call.getCallee()))
            return "calls " + call.getCallee().str() + ", a sched_ext kfunc, in an ebpf.timer.callback context whose owner implements " +
                   impl + " — the kernel's scx_kfunc_context_filter allows it only for " + bpfmlir::kScxOpsType.str();
          if (auto fp = dyn_cast<KFieldPtrOp>(op); fp && !rcuOk && fp.getField() == "cpus_ptr" && fp.getBaseStructName() == "task_struct")
            return "reads task_struct.cpus_ptr outside ebpf.rcu.region in an ebpf.timer.callback context, which assumes no RCU read "
                   "section — the verifier marks it untrusted there (put it inside an ebpf.rcu.region)" +
                   rcuNote;
        }
        if (c.entryKind == CallEntry::ProgramBody) {
          // as the program body — a struct_ops owner must implement a
          // sched_ext_ops member (the timer and helper callback contexts are
          // rejected by ebpf-verify-call-contexts before this pass).
          if (isa<TracePrintkOp>(op) && f.kinfo && f.kinfo->sig == bpfmlir::SigFamily::OpsSig &&
              f.opsType != bpfmlir::kScxOpsType)
            return structOpsPrintkRule("the owner", impl);
          if (ops && name.consume_front("ebpf.scx.")) {
            const bpfmlir::ScxKfuncInfo *info = bpfmlir::lookupScxOp(name);
            if (!info && name != "const" && name != "exit_info")
              return {}; // The op verifier names ops without a row.
            if (f.opsType != bpfmlir::kScxOpsType)
              return "is only for programs implementing a " + bpfmlir::kScxOpsType.str() + " member, but the owner implements " + impl;
            if (!info)
              return {}; // scx.const / scx.exit_info: no kfunc group or sleepable flag to check.
            if (!bpfmlir::scxMemberAllows(*info, f.opsType, f.member))
              return "calls " + info->kfunc.str() + ", which " + impl + " may not call (scx_kf_allow_flags — allowed in: " +
                     bpfmlir::scxMembersAllowing(*info) + ")";
            const bpfabi::KfuncABI *k = bpfabi::lookupKfunc(info->kfunc);
            if (k && k->hasFlag("sleepable") && !sl)
              return "calls " + info->kfunc.str() + " (KF_SLEEPABLE) in a context that is not sleepable";
            if (bpfmlir::scxNeedsRcuSection(name) && !rcuOk)
              return "calls " + info->kfunc.str() + ", which needs the RCU read section, " + slCtx + " outside ebpf.rcu.region" +
                     rcuNote;
            if (name == "dump" && !bpfmlir::scxDumpMember(f.opsType, f.member))
              return "calls " + info->kfunc.str() + " in " + impl + "; the compiler allows it only in the dump, dump_cpu and dump_task members";
            if (name == "pick_idle_cpu" && f.opsMap &&
                llvm::any_of(f.opsMap->structOps->ops, [](const auto &o) { return o.member == "update_idle"; })) {
              const bpfabi::ScxEnumABI *keep = bpfabi::lookupScxEnum("SCX_OPS_KEEP_BUILTIN_IDLE");
              uint64_t flags = 0;
              for (const auto &d : f.opsMap->structOps->data)
                if (d.member == "flags")
                  flags = d.value;
              if (!keep)
                return "needs the scxenum row SCX_OPS_KEEP_BUILTIN_IDLE in the UAPI table to check the ops flags";
              if (!(flags & keep->value))
                return "calls " + info->kfunc.str() + ", but struct_ops map \"" + f.opsMap->symbol +
                       "\" implements update_idle without SCX_OPS_KEEP_BUILTIN_IDLE (0x" + llvm::utohexstr(keep->value) +
                       ") in its flags (0x" + llvm::utohexstr(flags) + ") — the kernel then stops built-in idle tracking";
            }
            return {};
          }
          if (auto call = dyn_cast<KfuncCallOp>(op);
              call && ops && f.opsType != bpfmlir::kScxOpsType && bpfmlir::isScxGenericKfunc(call.getCallee()))
            return "calls " + call.getCallee().str() + ", a sched_ext kfunc, in a function whose owner implements " + impl +
                   " — in a struct_ops program the kernel's scx_kfunc_context_filter allows it only for " + bpfmlir::kScxOpsType.str();
          if (isa<KPtrLoadRcuOp, GlobalKPtrLoadRcuOp>(op) && !rcuOk)
            return std::string("reads a ") + (isa<KPtrLoadRcuOp>(op) ? "kptr field" : "kptr global") +
                   " outside ebpf.rcu.region " + slCtx + " — the verifier marks it untrusted there (only inside the section)" +
                   rcuNote;
          if (isa<IterScxDsqOp>(op) && ops) {
            if (f.opsType != bpfmlir::kScxOpsType)
              return "is only for programs implementing a " + bpfmlir::kScxOpsType.str() + " member, but the owner implements " + impl;
            if (!rcuOk)
              return "starts bpf_iter_scx_dsq_new (KF_RCU_PROTECTED) outside the RCU read section " + slCtx + " — put the "
                     "iterator inside ebpf.rcu.region (the verifier rejects it outside a section)" +
                     rcuNote;
          }
          if (auto fp = dyn_cast<KFieldPtrOp>(op); fp && ops && f.opsType == bpfmlir::kScxOpsType && !rcuOk &&
                                                     fp.getField() == "cpus_ptr" && fp.getBaseStructName() == "task_struct")
            return "reads task_struct.cpus_ptr " + slCtx + " outside the RCU read section — the verifier marks it untrusted "
                   "there" +
                   rcuNote;
        }
        if (opMightSleep(op) && !sl)
          return "may sleep (SleepableOps.def), but the context is not sleepable";
        return {};
      };
      CallContexts contexts(getOperation());
      // the timer callback bodies are tops too (one context per owner).
      SmallVector<Operation *> tops;
      for (auto fn : getOperation().getOps<SubprogramOp>())
        tops.push_back(fn);
      for (auto cb : getOperation().getOps<TimerCallbackOp>())
        tops.push_back(cb);
      for (Operation *fn : tops) {
        ArrayRef<CallContext> cs = contexts.of(fn);
        fn->walk([&](Operation *op) {
          if (!isContextDependentOp(op) && !isa<KFieldPtrOp>(op) && !opMightSleep(op))
            return;
          for (const CallContext &c0 : cs) {
            CallContext c = callContextAt(c0, op, fn);
            const OwnerFacts &f = factsOf(c.owner);
            bool ownerSleepable = bpfmlir::kindAllows(c.kind(), "sleepable") || (f.pdecl && f.pdecl->sleepable);
            std::string why = ruleFor(op, c, f, c.sleepable(ownerSleepable), c.rcuGuaranteed(ownerSleepable));
            if (why.empty())
              continue;
            bad = true;
            std::string member = f.opsType.empty() ? std::string() : f.opsType + "." + f.member;
            op->emitOpError() << why << " — " << describeCallContext(c, member, ownerSleepable);
            break; // One context per op.
          }
        });
      }
    }

    // a scx_bpf_task_cgroup call the member check did not
    // examine (a program kind or ops type the op verifier and the check let
    // through, a struct_ops program without a schema member) has no proven kf_tasks
    // position — rejected by name, never passed through.
    getOperation().walk([&](KfuncCallOp call) {
      if (call.getCallee() != bpfmlir::kScxTaskCgroupKfunc || taskCgroupChecked.contains(call))
        return;
      bad = true;
      auto prog = call->getParentOfType<ProgramOp>();
      call.emitOpError() << "calls " << call.getCallee() << " in @" << (prog ? prog.getSymName() : StringRef("?"))
                         << ", which the compiler could not tie to a " << bpfmlir::kScxOpsType
                         << " member of the schema; scx_bpf_task_cgroup is only for a task argument at a current->scx.kf_tasks position";
    });

    // typed ksym VARs, kconfig and the guards (requirements_format.md
    // §9 guarded). Guards get provisional ids, one per (kind, target) in walk
    // order — two exists ops on the same target are one fact and share the id,
    // so the intersections over read sites (here for ksymvar, in ObjectEmitter
    // for kfield) are over targets. ObjectEmitter writes
    // only the used ones, renumbered. A read site's guards are the guard ifs
    // whose then region encloses it in the same function (not across a
    // bpf_loop callback or map.for_each body, which become other functions).
    {
      Builder bld(&getContext());
      // The attributes below are this pass's output only: drop any the input
      // carries, so a stale ebpf.guards / ebpf.weak never reaches the rows
      //.
      getOperation()->removeAttr("ebpf.guard_table");
      getOperation()->removeAttr("ebpf.ksym_guards");
      getOperation().walk([&](Operation *op) {
        op->removeAttr("ebpf.guards");
        if (isa<KsymExistsOp, KsymPerCpuLoadOp, KsymPerCpuBrOp, KconfigLoadOp>(op)) {
          op->removeAttr("ebpf.weak");
          op->removeAttr("ebpf.extern_type");
        }
      });
      SmallVector<Attribute> table; // "<kind>\t<target>" per provisional id.
      llvm::StringMap<int32_t> rowId;
      DenseMap<Operation *, int32_t> guardId;
      getOperation().walk([&](Operation *op) {
        std::string row;
        if (auto e = dyn_cast<KsymExistsOp>(op)) {
          const ::ebpf::KsymVar *k = schema->ksym(e.getName());
          if (!k) {
            bad = true;
            e.emitOpError() << "ksym @" << e.getName() << " is not declared in the schema (core.ksyms)";
            return;
          }
          if (!k->weak) {
            bad = true;
            e.emitOpError() << "ksym @" << e.getName()
                            << " is strong (the load fails when it is absent), so it needs no guard; declare it \"weak\": true to guard it";
            return;
          }
          row = "ksym\t" + e.getName().str();
          // ③ creates the extern_weak .ksyms global with the slot's type.
          e->setAttr("ebpf.weak", bld.getUnitAttr());
          e->setAttr("ebpf.extern_type",
                     TypeAttr::get(!k->slotStruct.empty() ? Type(KAddrType::get(&getContext(), k->slotStruct))
                                                          : Type(IntegerType::get(&getContext(), k->slotBits()))));
        } else if (auto t = dyn_cast<CoreTypeExistsOp>(op)) {
          if (!schema->kernelType(t.getStructName())) {
            bad = true;
            t.emitOpError() << "struct \"" << t.getStructName() << "\" is not declared in the schema (core.kernel_types)";
            return;
          }
          row = "type\t" + t.getStructName().str();
        } else if (auto f = dyn_cast<CoreFieldExistsOp>(op)) {
          if (!schema->kernelType(f.getStructName())) {
            bad = true;
            f.emitOpError() << "struct \"" << f.getStructName() << "\" is not declared in the schema (core.kernel_types)";
            return;
          }
          row = "field\t" + f.getStructName().str() + "." + f.getField().str();
        } else {
          return;
        }
        auto [it, fresh] = rowId.try_emplace(row, static_cast<int32_t>(table.size()));
        if (fresh)
          table.push_back(bld.getStringAttr(row));
        guardId[op] = it->second;
      });
      auto enclosingGuards = [&](Operation *site) {
        SmallVector<int32_t> ids;
        Operation *child = site;
        for (Operation *p = site->getParentOp(); p && !p->hasTrait<OpTrait::IsIsolatedFromAbove>(); child = p, p = p->getParentOp()) {
          if (auto lp = dyn_cast<LoopOp>(p); (lp && lp.getCallback()) || isa<MapForEachOp>(p))
            break; // Another function after stage ②.
          auto ifo = dyn_cast<IfOp>(p);
          if (!ifo || child->getParentRegion() != &ifo.getThenRegion())
            continue;
          if (Operation *d = ifo.getCond().getDefiningOp(); d && guardId.count(d))
            ids.push_back(guardId[d]);
        }
        llvm::sort(ids);
        ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
        return ids;
      };
      // ksymvar rows are ELF-wide: guards = intersection over the read sites;
      // a VAR only tested by ksym.exists keeps all its exists guards.
      llvm::StringMap<SmallVector<int32_t>> ksymGuards;
      llvm::StringMap<bool> ksymRead;
      getOperation().walk([&](KsymPerCpuLoadOp pl) {
        const ::ebpf::KsymVar *k = schema->ksym(pl.getName());
        if (!k) {
          bad = true;
          pl.emitOpError() << "ksym @" << pl.getName() << " is not declared in the schema (core.ksyms)";
          return;
        }
        Type got = pl.getPresentRegion().front().getArgument(0).getType();
        Type want = !k->slotStruct.empty() ? Type(KAddrType::get(&getContext(), k->slotStruct))
                                           : Type(IntegerType::get(&getContext(), k->slotBits()));
        if (got != want) {
          bad = true;
          pl.emitOpError() << "reads the slot of ksym @" << pl.getName() << " as " << got << ", but the schema declares "
                           << k->slotSpelling() << " (" << want << ")";
          return;
        }
        if (k->weak)
          pl->setAttr("ebpf.weak", bld.getUnitAttr());
        pl->setAttr("ebpf.extern_type", TypeAttr::get(want));
        SmallVector<int32_t> ids = enclosingGuards(pl);
        SmallVector<int32_t> own;
        for (int32_t g : ids)
          if (cast<StringAttr>(table[g]).getValue() == "ksym\t" + pl.getName().str())
            own.push_back(g);
        if (k->weak && own.empty()) {
          bad = true;
          pl.emitOpError() << "reads weak ksym @" << pl.getName()
                           << " outside the then region of an ebpf.if on ebpf.ksym.exists @" << pl.getName()
                           << " (in the same function); an unresolved weak VAR is address 0 and the verifier rejects the read"
                           << " unless that compare prunes it — another VAR's guard does not count";
          return;
        }
        if (!k->weak)
          return; // Strong rows carry no guards (guard_strong).
        if (!ksymRead.try_emplace(pl.getName(), true).second) {
          SmallVector<int32_t> &cur = ksymGuards[pl.getName()];
          SmallVector<int32_t> keep;
          for (int32_t g : cur)
            if (llvm::is_contained(own, g))
              keep.push_back(g);
          cur = keep;
        } else {
          ksymGuards[pl.getName()] = own;
        }
      });
      for (auto [op, id] : guardId)
        if (auto e = dyn_cast<KsymExistsOp>(op); e && !ksymRead.contains(e.getName()))
          if (!llvm::is_contained(ksymGuards[e.getName()], id))
            ksymGuards[e.getName()].push_back(id);
      // kfield sites carry all their enclosing guards; ObjectEmitter keeps the
      // ones whose target matches each row and intersects over the sites.
      getOperation().walk([&](Operation *op) {
        if (!isa<KFieldLoadOp, KFieldPtrOp, KFieldCopyOp, KFieldStoreOp, KAddrReadOp, KAddrStrncmpOp, KFieldStrncmpOp, KAddrContainerOfOp>(op)) // the kaddr reads too
          return;
        SmallVector<int32_t> ids = enclosingGuards(op);
        if (!ids.empty())
          op->setAttr("ebpf.guards", bld.getDenseI32ArrayAttr(ids));
      });
      getOperation().walk([&](KconfigLoadOp kl) {
        const ::ebpf::KconfigDecl *k = schema->kconfig(kl.getName());
        if (!k) {
          bad = true;
          kl.emitOpError() << "kconfig @" << kl.getName() << " is not declared in the schema (core.kconfig)";
          return;
        }
        if (k->weak)
          kl->setAttr("ebpf.weak", bld.getUnitAttr());
        unsigned w = kl.getResult().getType().getIntOrFloatBitWidth();
        if (w != k->bits()) {
          bad = true;
          kl.emitOpError() << "reads kconfig @" << kl.getName() << " as " << w << " bits, but the schema declares " << k->type
                           << " (" << k->bits() << " bits)";
        }
      });
      if (!table.empty()) {
        getOperation()->setAttr("ebpf.guard_table", bld.getArrayAttr(table));
        SmallVector<NamedAttribute> kg;
        for (auto &e : ksymGuards) {
          llvm::sort(e.second);
          kg.push_back(bld.getNamedAttr(e.getKey(), bld.getDenseI32ArrayAttr(e.second)));
        }
        getOperation()->setAttr("ebpf.ksym_guards", bld.getDictionaryAttr(kg));
      }
    }

    // complete coverage requires every schema program in IR too: bidirectional matching.
    if (schema->coverage().programs == ::ebpf::Coverage::Complete) {
      for (const ::ebpf::Program &decl : schema->programs()) {
        bool found = false;
        getOperation().walk([&](ProgramOp p) {
          if (p.getSymName() == decl.name)
            found = true;
        });
        if (!found) {
          bad = true;
          getOperation().emitError()
              << "the schema declares program @" << decl.name
              << " (coverage.programs = complete) but this module does not "
                 "define it";
        }
      }
    }

    if (bad)
      signalPassFailure();
  }
};

} // namespace
