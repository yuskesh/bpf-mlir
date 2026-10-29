//===- VerifySchema.cpp - match IR bindings against canonical schema --------===//
//
// Keep schema matching in a pass, not the dialect: operations define eBPF
// vocabulary while callers select the schema for validation. Check existence
// and kind/key/value agreement in addition to binding structure/uniqueness.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h"

#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"
#include "bpf-mlir/Dialect/BPFABI/KernelABI.h"
#include "bpf-mlir/Support/ProgramKinds.h"
#include "bpf-mlir/Support/KeylessMaps.h"
#include "bpf-mlir/Target/EBPF/Schema.h"

#include "mlir/IR/Matchers.h"
#include "llvm/Support/MemoryBuffer.h"

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
      // Match global read names and widths against core.globals.
      owner->walk([&](GlobalLoadOp gl) {
        const ::ebpf::Global *g = schema->global(gl.getName());
        if (!g) {
          bad = true;
          gl.emitOpError() << "global @" << gl.getName() << " is not declared in the schema (core.globals)";
          return;
        }
        unsigned w = gl.getResult().getType().getIntOrFloatBitWidth();
        if (w != g->type.bits) {
          bad = true;
          gl.emitOpError() << "reads global @" << gl.getName() << " as " << w << " bits, but the schema declares " << g->type.bits;
        }
      });
      // Atomic global addition is .bss-only: .rodata is frozen after load.
      owner->walk([&](GlobalAtomicAddOp ga) {
        const ::ebpf::Global *g = schema->global(ga.getName());
        if (!g) {
          bad = true;
          ga.emitOpError() << "global @" << ga.getName() << " is not declared in the schema (core.globals)";
          return;
        }
        unsigned w = ga.getDelta().getType().getIntOrFloatBitWidth();
        if (w != g->type.bits) {
          bad = true;
          ga.emitOpError() << "adds to global @" << ga.getName() << " as " << w << " bits, but the schema declares " << g->type.bits;
        }
        if (g->section != "bss") {
          bad = true;
          ga.emitOpError() << "global @" << ga.getName() << " is in ." << g->section
                           << "; only .bss globals are writable (.rodata is frozen after load)";
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
