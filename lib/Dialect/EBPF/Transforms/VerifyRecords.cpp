//===- VerifyRecords.cpp - match record types with @records declarations -----===//
//
// record<S,N> names @records::S with matching byte size. Field loads/stores
// require matching integer member widths. checkRecordShape validates map values
// and subprogram argument records with nesting and one-dimensional integer arrays.
// Schema owns offsets; the compiler does not recompute layout. MLIR integers
// are signless, so this pass does not check signedness.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h"

#include "bpf-mlir/Dialect/BTF/IR/BTFDialect.h"
#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"

#include "bpf-mlir/Dialect/EBPF/Transforms/RecordPath.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/StringMap.h"

namespace mlir {
namespace ebpf {
#define GEN_PASS_DEF_EBPFVERIFYRECORDS
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h.inc"
} // namespace ebpf
} // namespace mlir

using namespace mlir;
using namespace mlir::ebpf;

namespace {

// Extract record types from map values, references and reservations.
RecordType recordIn(Type t) {
  if (auto r = dyn_cast<RecordType>(t))
    return r;
  if (auto m = dyn_cast<MapType>(t))
    return recordIn(m.getValueType());
  if (auto m = dyn_cast<MaybeRefType>(t))
    return recordIn(m.getPointee());
  if (auto b = dyn_cast<BorrowedType>(t))
    return recordIn(b.getPointee());
  if (auto r = dyn_cast<ReservationType>(t))
    return recordIn(r.getRecordType());
  if (auto r = dyn_cast<MaybeReservationType>(t))
    return recordIn(r.getRecordType());
  return nullptr;
}

struct EBPFVerifyRecordsPass
    : public mlir::ebpf::impl::EBPFVerifyRecordsBase<EBPFVerifyRecordsPass> {
  void runOnOperation() override {
    ModuleOp module = getOperation();
    btf::ScopeOp records;
    for (auto sc : module.getOps<btf::ScopeOp>())
      if (sc.getSymName() == "records")
        records = sc;
    bool bad = false;
    llvm::DenseSet<Type> checked;

    auto resolve = [&](Operation *op, RecordType rt) -> btf::StructOp {
      auto st = records ? dyn_cast_or_null<btf::StructOp>(
                              SymbolTable::lookupSymbolIn(records, rt.getSymbol()))
                        : btf::StructOp();
      if (!checked.insert(rt).second)
        return st;
      if (!st) {
        bad = true;
        op->emitOpError() << "record \"" << rt.getSymbol()
                          << "\" has no declaration btf.struct @records::@" << rt.getSymbol()
                          << " (schema core.records)";
        return st;
      }
      if (st.getSizeBits() != rt.getSize() * 8) {
        bad = true;
        op->emitOpError() << "record type " << rt << " is " << rt.getSize()
                          << " bytes but btf.struct @records::@" << rt.getSymbol() << " is "
                          << st.getSizeBits() / 8 << " bytes";
      }
      return st;
    };
    auto checkType = [&](Operation *op, Type t) {
      RecordType rt = recordIn(t);
      if (!rt)
        return;
      btf::StructOp st = resolve(op, rt);
      // Validate map-value and subprogram-reference record shapes.
      auto mt = dyn_cast<MapType>(t);
      bool shapeNeeded = (mt && isa<RecordType>(mt.getValueType())) ||
                        (isa<SubprogramOp>(op) && isa<MaybeRefType, BorrowedType>(t));
      if (!st || !shapeNeeded)
        return;
      // Map values allow nested integer-only records and one-dimensional integer
      // arrays. Subprogram argument records share these shape rules; callees
      // retain their read-only restriction.
      std::string err;
      if (failed(checkRecordShape(records, st, err))) {
        bad = true;
        op->emitOpError() << (mt ? "map value record \"" : "argument record \"") << rt.getSymbol()
                          << "\": " << err;
      }
    };

    module.walk([&](Operation *op) {
      if (auto tc = dyn_cast<TpFieldCopyOp>(op)) {
        auto st = resolve(op, tc.getDstRecord());
        if (!st)
          return;
        std::string err;
        auto t = resolveRecordTemplate(records, st, indexTemplate(tc.getPath()), err);
        auto n = tc->getAttrOfType<IntegerAttr>("ebpf.tp_array_count");
        if (!n || n.getInt() < 1 || n.getInt() > 64 || failed(t) || t->dims.size() != 1 || t->bits != 8 ||
            t->dims[0].count != static_cast<uint64_t>(n.getInt())) {
          bad = true;
          tc.emitOpError() << "destination must be a one-dimensional 8-bit array with the schema field's length"
                           << (n ? " " + std::to_string(n.getInt()) : " (run ebpf-verify-schema first)")
                           << (err.empty() ? "" : " — " + err);
        }
        return;
      }
      if (isa<btf::BTFDialect>(op->getDialect()))
        return;
      for (Type t : op->getOperandTypes())
        checkType(op, t);
      for (Type t : op->getResultTypes())
        checkType(op, t);
      for (Region &r : op->getRegions())
        for (Block &b : r)
          for (BlockArgument a : b.getArguments())
            checkType(op, a.getType());

      // record.make names every declared field exactly once, with matching widths.
      // The nominal record name selects the declaration.
      if (auto mk = dyn_cast<RecordMakeOp>(op)) {
        auto rt = cast<RecordType>(mk.getResult().getType());
        btf::StructOp st = resolve(op, rt);
        if (!st)
          return;
        for (Attribute a : st.getMembers()) {
          auto m = cast<btf::MemberAttr>(a);
          if (auto r = dyn_cast<btf::RefAttr>(m.getType()); r && r.getTarget().getLeafReference() == "bpf_spin_lock") {
            bad = true;
            op->emitOpError() << "record \"" << st.getSymName() << "\" has a spin_lock field; ebpf.record.make cannot build it";
            return;
          }
          if (auto r = dyn_cast<btf::RefAttr>(m.getType()); r && r.getTarget().getLeafReference() == "bpf_timer") {
            bad = true;
            op->emitOpError() << "record \"" << st.getSymName() << "\" has a timer field; ebpf.record.make cannot build it";
            return;
          }
          if (!kptrStructOf(m.getType()).empty()) {
            bad = true;
            op->emitOpError() << "record \"" << st.getSymName() << "\" has a kptr field (\"" << m.getName()
                              << "\"); ebpf.record.make cannot build it (only ebpf.kptr.xchg writes a kptr field)";
            return;
          }
        }
        if (recordHasKptr(records, st)) {
          bad = true;
          op->emitOpError() << "record \"" << st.getSymName()
                            << "\" has a nested kptr field; ebpf.record.make cannot build it (only ebpf.kptr.xchg writes a kptr field)";
          return;
        }
        llvm::StringMap<Type> given;
        for (auto [a, v] : llvm::zip(mk.getFields(), mk.getValues()))
          given[cast<StringAttr>(a).getValue()] = v.getType();
        // Name each leaf exactly once, including nested x.y and array x[i] fields.
        SmallVector<RecordLeaf> leaves;
        std::string err;
        if (failed(recordLeaves(records, st, leaves, err))) {
          bad = true;
          op->emitOpError() << "record \"" << st.getSymName() << "\": " << err;
          return;
        }
        for (const RecordLeaf &l : leaves) {
          auto it = given.find(l.path);
          if (it == given.end()) {
            bad = true;
            op->emitOpError() << "does not give field \"" << l.path << "\" of btf.struct @records::@"
                              << st.getSymName() << " (every field is required)";
            return;
          }
          if (l.bits != cast<IntegerType>(it->second).getWidth()) {
            bad = true;
            op->emitOpError() << "gives field \"" << st.getSymName() << "." << l.path << "\" as "
                              << it->second << " but it is " << l.type << " in btf.struct @records::@"
                              << st.getSymName();
            return;
          }
          given.erase(it);
        }
        if (!given.empty()) {
          bad = true;
          op->emitOpError() << "gives field \"" << given.begin()->getKey() << "\" that btf.struct @records::@"
                            << st.getSymName() << " does not have";
        }
        return;
      }

      // task.comm requires a one-dimensional eight-bit array; do not implicitly
      // reinterpret wider elements as a byte count.
      if (auto tc = dyn_cast<TaskCommOp>(op)) {
        RecordType rt = recordIn(tc.getReservation().getType());
        btf::StructOp st = rt ? resolve(op, rt) : btf::StructOp();
        if (!st)
          return;
        std::string err;
        FailureOr<RecordTemplate> t = resolveRecordTemplate(records, st, (tc.getField() + "[]").str(), err);
        if (failed(t) || t->dims.size() != 1 || t->bits != 8) {
          bad = true;
          op->emitOpError() << "field \"" << tc.getField() << "\" of record \"" << st.getSymName()
                            << "\" must be a 1-dimensional array of 8-bit integers (a byte array) for ebpf.task.comm"
                            << (failed(t) ? " — " + err : std::string());
        }
        return;
      }

      // Buffer destinations are direct byte arrays with an initialization bound
      // that avoids allocating a large stack buffer.
      if (auto rd = dyn_cast<UserReadOp>(op)) {
        RecordType rt = recordIn(rd.getReservation().getType());
        btf::StructOp st = rt ? resolve(op, rt) : btf::StructOp();
        if (!st)
          return;
        std::string err;
        FailureOr<RecordTemplate> t = resolveRecordTemplate(records, st, (rd.getField() + "[]").str(), err);
        if (failed(t) || t->dims.size() != 1 || t->bits != 8 || t->dims[0].count < 1 || t->dims[0].count > 8192) {
          bad = true;
          op->emitOpError("needs a direct 1-dimensional byte array field with 1..8192 elements")
              << (failed(t) ? " — " + err : std::string());
        }
        return;
      }

      // user.read_str requires a nonempty one-dimensional eight-bit array, like task.comm.
      if (auto rs = dyn_cast<UserReadStrOp>(op)) {
        RecordType rt = recordIn(rs.getReservation().getType());
        btf::StructOp st = rt ? resolve(op, rt) : btf::StructOp();
        if (!st)
          return;
        std::string err;
        FailureOr<RecordTemplate> t = resolveRecordTemplate(records, st, (rs.getField() + "[]").str(), err);
        if (failed(t) || t->dims.size() != 1 || t->bits != 8 || t->dims[0].count < 1) {
          bad = true;
          op->emitOpError() << "field \"" << rs.getField() << "\" of record \"" << st.getSymName()
                            << "\" must be a 1-dimensional array of 8-bit integers with at least 1 element for ebpf.user.read_str"
                            << (failed(t) ? " — " + err : std::string());
        }
        return;
      }

      // kernel.read_str requires a one-dimensional eight-bit array of 1..64
      // elements, matching the kfield.copy bound.
      if (auto ks = dyn_cast<KernelReadStrOp>(op)) {
        RecordType rt = recordIn(ks.getReservation().getType());
        btf::StructOp st = rt ? resolve(op, rt) : btf::StructOp();
        if (!st)
          return;
        std::string err;
        FailureOr<RecordTemplate> t = resolveRecordTemplate(records, st, (ks.getPath() + "[]").str(), err);
        if (failed(t) || t->dims.size() != 1 || t->bits != 8 || t->dims[0].count < 1 || t->dims[0].count > 64) {
          bad = true;
          op->emitOpError() << "destination \"" << ks.getPath() << "\" of record \"" << st.getSymName()
                            << "\" must be a 1-dimensional array of 1 to 64 8-bit integers for ebpf.kernel.read_str"
                            << (failed(t) ? " — " + err : std::string());
        }
        return;
      }

      // Variable-index fields are direct one-dimensional integer arrays whose
      // element width matches elem<iN>.
      if (auto ri = dyn_cast<RefIndexOp>(op)) {
        RecordType rt = recordIn(ri.getRef().getType());
        btf::StructOp st = rt ? resolve(op, rt) : btf::StructOp();
        if (!st)
          return;
        // Each variable-index [] in the field template requires one index.
        std::string err, tmpl = indexTemplate(ri.getField());
        FailureOr<RecordTemplate> t = resolveRecordTemplate(records, st, tmpl, err);
        if (failed(t)) {
          bad = true;
          op->emitOpError() << err;
          return;
        }
        if (t->dims.size() != ri.getIndices().size()) {
          bad = true;
          op->emitOpError() << "\"" << tmpl << "\" has " << t->dims.size() << " variable index(es) but "
                            << ri.getIndices().size() << " index value(s) are given";
          return;
        }
        auto et = cast<ElemType>(ri.getInRange().front().getArgument(0).getType());
        unsigned w = cast<IntegerType>(et.getElement()).getWidth();
        if (t->bits != w) {
          bad = true;
          op->emitOpError() << "field \"" << st.getSymName() << "." << tmpl << "\" is " << t->bits
                            << "-bit in btf.struct @records::@" << st.getSymName() << " but the element is " << et;
        }
        return;
      }

      // Only spin.region accesses bpf_spin_lock members. record.make cannot build
      // lock-bearing records; ref.field operations cannot access lock or lock.val.
      // bpf_timer members are similarly restricted to timer operations.
      auto memberOfType = [&](btf::StructOp st, StringRef type) -> std::string {
        for (Attribute a : st.getMembers()) {
          auto m = cast<btf::MemberAttr>(a);
          if (auto r = dyn_cast<btf::RefAttr>(m.getType()); r && r.getTarget().getLeafReference() == type)
            return m.getName().str();
        }
        return "";
      };
      auto lockMember = [&](btf::StructOp st) { return memberOfType(st, "bpf_spin_lock"); };
      auto timerMember = [&](btf::StructOp st) { return memberOfType(st, "bpf_timer"); };
      if (isa<TimerInitOp, TimerSetCallbackOp, TimerStartOp>(op)) {
        Value r = op->getOperand(0);
        StringRef tf = op->getAttrOfType<StringAttr>("field").getValue();
        RecordType rt = recordIn(r.getType());
        btf::StructOp st = rt ? resolve(op, rt) : btf::StructOp();
        if (!st)
          return;
        std::string tm = timerMember(st);
        if (tm.empty() || tm != tf) {
          bad = true;
          op->emitOpError() << "field \"" << tf << "\" of record \"" << st.getSymName() << "\" is not its timer field"
                            << (tm.empty() ? std::string(" (the record has none)") : " (it is \"" + tm + "\")");
        }
        return;
      }
      // Source and ABI stages share the constant-path resolver for kptr targets/offsets.
      if (auto x = dyn_cast<KPtrXchgOp>(op)) {
        RecordType rt = recordIn(x.getRef().getType());
        btf::StructOp st = rt ? resolve(op, rt) : btf::StructOp();
        if (!st)
          return;
        StringRef want = cast<KRefOrNullType>(x.getOld().getType()).getStructName();
        std::string err;
        auto leaf = resolveKptrPath(records, st, x.getField(), err);
        if (failed(leaf)) {
          bad = true;
          op->emitOpError() << err;
        } else if (leaf->structName != want) {
          bad = true;
          op->emitOpError() << "field \"" << x.getField() << "\" of record \"" << st.getSymName()
                            << "\" is a kptr to struct " << leaf->structName
                            << ", but the exchange is typed for struct " << want << "";
        }
        return;
      }
      if (auto sr = dyn_cast<SpinRegionOp>(op)) {
        RecordType rt = recordIn(sr.getRef().getType());
        btf::StructOp st = rt ? resolve(op, rt) : btf::StructOp();
        if (!st)
          return;
        std::string lm = lockMember(st);
        if (lm.empty() || lm != sr.getLock()) {
          bad = true;
          op->emitOpError() << "field \"" << sr.getLock() << "\" of record \"" << st.getSymName() << "\" is not its spin_lock field"
                            << (lm.empty() ? std::string(" (the record has none)") : " (it is \"" + lm + "\")");
        }
        return;
      }
      StringRef field;
      Type ref, width;
      if (auto ld = dyn_cast<RefFieldLoadOp>(op)) {
        field = ld.getField();
        ref = ld.getRef().getType();
        width = ld.getResult().getType();
      } else if (auto stOp = dyn_cast<RefFieldStoreOp>(op)) {
        field = stOp.getField();
        ref = stOp.getRef().getType();
        width = stOp.getValue().getType();
      } else if (auto addOp = dyn_cast<RefFieldAtomicAddOp>(op)) {
        field = addOp.getField();
        ref = addOp.getRef().getType();
        width = addOp.getDelta().getType();
      } else {
        return;
      }
      RecordType rt = recordIn(ref);
      btf::StructOp st = rt ? resolve(op, rt) : btf::StructOp();
      if (!st)
        return;
      if (std::string lm = lockMember(st); !lm.empty()) {
        StringRef head = field.take_until([](char c) { return c == '.' || c == '['; });
        if (head == lm) {
          bad = true;
          op->emitOpError() << "field \"" << field << "\" is the spin_lock of record \"" << st.getSymName()
                            << "\"; it cannot be read or written directly (only ebpf.spin.region takes it)";
          return;
        }
      }
      if (std::string tm = timerMember(st); !tm.empty()) {
        StringRef head = field.take_until([](char c) { return c == '.' || c == '['; });
        if (head == tm) {
          bad = true;
          op->emitOpError() << "field \"" << field << "\" is the timer of record \"" << st.getSymName()
                            << "\"; it cannot be read or written directly (only ebpf.timer.{init,set_callback,start} take it)";
          return;
        }
      }
      // Only kptr.xchg accesses kptr fields; kernel rejects direct stores.
      for (Attribute a : st.getMembers()) {
        auto m = cast<btf::MemberAttr>(a);
        StringRef head = field.take_until([](char c) { return c == '.' || c == '['; });
        if (m.getName() == head && !kptrStructOf(m.getType()).empty()) {
          bad = true;
          op->emitOpError() << "field \"" << field << "\" is a kptr of record \"" << st.getSymName()
                            << "\"; it cannot be read or written directly (only ebpf.kptr.xchg takes it)";
          return;
        }
      }
      // RecordPath resolves x, x.y and x[i] against @records declarations.
      std::string err;
      FailureOr<RecordLeaf> leaf = resolveRecordPath(records, st, field, err);
      if (failed(leaf)) {
        bad = true;
        op->emitOpError() << err;
        return;
      }
      unsigned w = cast<IntegerType>(width).getWidth();
      if (leaf->bits != w) {
        bad = true;
        op->emitOpError() << "field \"" << st.getSymName() << "." << field << "\" is " << leaf->type
                          << " in btf.struct @records::@" << st.getSymName() << " but accessed as " << width;
      }
      // Atomic addition requires natural alignment. Map values start eight-byte
      // aligned, so offset divisible by the value's byte width proves alignment.
      if (isa<RefFieldAtomicAddOp>(op) && leaf->bits == w && leaf->offsetBytes % (w / 8) != 0) {
        bad = true;
        op->emitOpError() << "field \"" << st.getSymName() << "." << field << "\" is at byte offset " << leaf->offsetBytes
                          << ", not a multiple of " << w / 8 << "; a BPF atomic add needs a naturally aligned " << width << "";
      }
    });
    if (bad)
      signalPassFailure();
  }
};

} // namespace
