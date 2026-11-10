//===- VerifyKPtr.cpp - match kernel pointers/fields with BTF declarations ---===//
//
// kptr<S> names btf.struct S in btf.scope @kernel, generated from schema
// kernel_types. kfield.load members must exist with matching integer widths.
// Signless MLIR integers cannot express signedness: kfield requirements and
// load-time CheckKFields own that check.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h"

#include "bpf-mlir/Dialect/BTF/IR/BTFDialect.h"
#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"
#include "bpf-mlir/Dialect/EBPF/Transforms/RecordPath.h"
#include "bpf-mlir/Support/KernelFieldPath.h"

#include "llvm/ADT/SetVector.h"

namespace mlir {
namespace ebpf {
#define GEN_PASS_DEF_EBPFVERIFYKPTR
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h.inc"
} // namespace ebpf
} // namespace mlir

using namespace mlir;
using namespace mlir::ebpf;

namespace {

struct EBPFVerifyKPtrPass : public mlir::ebpf::impl::EBPFVerifyKPtrBase<EBPFVerifyKPtrPass> {
  void runOnOperation() override {
    ModuleOp module = getOperation();
    btf::ScopeOp kernel, records;
    for (auto sc : module.getOps<btf::ScopeOp>()) {
      if (sc.getSymName() == "kernel")
        kernel = sc;
      if (sc.getSymName() == "records")
        records = sc;
    }
    auto lookup = [&](StringRef name) -> btf::StructOp {
      if (!kernel)
        return nullptr;
      return dyn_cast_or_null<btf::StructOp>(SymbolTable::lookupSymbolIn(kernel, name));
    };
    bool bad = false;
    auto pathMember = [&](Operation *op, btf::StructOp st, StringRef path) -> btf::MemberAttr {
      if (!bpfmlir::validKernelFieldPath(path)) {
        bad = true; op->emitOpError("kernel field path must have 1 to 3 identifier segments"); return {};
      }
      SmallVector<StringRef> parts;
      path.split(parts, '.', -1, true);
      btf::MemberAttr member;
      for (auto [i, part] : llvm::enumerate(parts)) {
        member = {};
        for (Attribute a : st.getMembers())
          if (cast<btf::MemberAttr>(a).getName() == part) member = cast<btf::MemberAttr>(a);
        if (!member) return {};
        if (i + 1 < parts.size()) {
          auto ref = dyn_cast<btf::RefAttr>(member.getType());
          st = ref ? lookup(ref.getTarget().getLeafReference()) : btf::StructOp();
          if (!st) {
            bad = true; op->emitOpError() << "intermediate kernel field \"" << part << "\" must be an embedded kernel struct"; return {};
          }
        }
      }
      return member;
    };
    auto checkKPtr = [&](Operation *op, KPtrType kp) -> btf::StructOp {
      btf::StructOp st = lookup(kp.getStructName());
      if (!st) {
        bad = true;
        op->emitOpError() << "kernel type \"" << kp.getStructName()
                          << "\" has no declaration btf.struct @kernel::@" << kp.getStructName()
                          << " (schema core.kernel_types)";
      }
      return st;
    };
    module.walk([&](Operation *op) {
      if (auto addr = dyn_cast<KPtrAddrOp>(op)) {
        Type t = addr.getPtr().getType();
        StringRef name = isa<KRefType>(t) ? cast<KRefType>(t).getStructName() : cast<KPtrType>(t).getStructName();
        checkKPtr(op, KPtrType::get(op->getContext(), name));
        return;
      }
      if (auto arg = dyn_cast<CtxArgOp>(op)) {
        if (auto kp = dyn_cast<KPtrType>(arg.getResult().getType())) // Integer arguments are not kernel pointers.
          checkKPtr(op, kp);
        else if (auto kn = dyn_cast<KPtrOrNullType>(arg.getResult().getType()))
          checkKPtr(op, KPtrType::get(op->getContext(), kn.getStructName()));
        return;
      }
      // the RCU task results need task_struct in @kernel (the kfunc's *task_struct BTF).
      // the DSQ iterator's task needs task_struct in @kernel (the next kfunc's *task_struct BTF).
      if (isa<IterScxDsqOp>(op)) {
        checkKPtr(op, KPtrType::get(op->getContext(), "task_struct"));
        return;
      }
      if (isa<ScxDsqPeekOp, ScxCpuCurrOp, KPtrLoadRcuOp, GlobalKPtrLoadRcuOp>(op)) { // the RCU kptr reads need their struct in @kernel too.
        checkKPtr(op, KPtrType::get(op->getContext(), cast<RcuPtrOrNullType>(op->getResult(0).getType()).getStructName()));
        return;
      }
      // the typed current task requires task_struct in @kernel.
      if (auto cur = dyn_cast<TaskCurrentBtfOp>(op)) {
        checkKPtr(op, cur.getResult().getType());
        return;
      }
      // task.pt_regs requires task_struct and pt_regs in @kernel.
      if (auto regs = dyn_cast<TaskPtRegsOp>(op)) {
        checkKPtr(op, regs.getTask().getType());
        checkKPtr(op, regs.getResult().getType());
        return;
      }
      // Context struct-pointer fields (netfilter state/skb) require S in @kernel.
      if (auto cf = dyn_cast<CtxFieldOp>(op)) {
        if (auto kp = dyn_cast<KPtrType>(cf.getResult().getType()))
          checkKPtr(op, kp);
        return;
      }
      // kfield.copy requires N eight-bit integer elements on both the kernel
      // member and the destination record path's one-dimensional array.
      if (auto kc = dyn_cast<KFieldCopyOp>(op)) {
        btf::StructOp st = checkKPtr(op, kc.getPtr().getType());
        if (!st)
          return;
        btf::MemberAttr member = pathMember(op, st, kc.getField());
        auto arr = member ? dyn_cast<btf::ArrayOfAttr>(member.getType()) : btf::ArrayOfAttr();
        auto el = arr ? dyn_cast<btf::IntAttr>(arr.getElement()) : btf::IntAttr();
        if (!el || el.getBits() != 8) {
          bad = true;
          kc.emitOpError() << "field \"" << st.getSymName() << "." << kc.getField()
                           << "\" is not an array of 8-bit integers in btf.struct @kernel::@" << st.getSymName()
                           << " (schema core.kernel_types — {\"kind\": \"array\", \"count\": N, \"element\": {int 8}})";
          return;
        }
        RecordType rt = kc.getDstRecord(); // Borrowed or reserved record; the op verifier guarantees record type.
        auto rst = records ? dyn_cast_or_null<btf::StructOp>(SymbolTable::lookupSymbolIn(records, rt.getSymbol())) : btf::StructOp();
        std::string err;
        FailureOr<RecordTemplate> t = rst ? resolveRecordTemplate(records, rst, indexTemplate(kc.getPath()), err)
                                          : FailureOr<RecordTemplate>(failure());
        if (failed(t) || t->dims.size() != 1 || t->bits != 8 || t->dims[0].count != arr.getCount()) {
          bad = true;
          kc.emitOpError() << "destination \"" << kc.getPath() << "\" of record \"" << rt.getSymbol()
                           << "\" must be a one-dimensional array of " << arr.getCount()
                           << " 8-bit integers (the length of the kernel field \"" << kc.getField() << "\")"
                           << (err.empty() ? "" : " — " + err);
        }
        return;
      }
      // kernel.read_str (and kernel.read_str_buf) requires char*: BTF PTR -> eight-bit INT.
      if (isa<KernelReadStrOp, KernelReadStrBufOp>(op)) {
        auto kp = cast<KPtrType>(op->getOperand(isa<KernelReadStrOp>(op) ? 1 : 0).getType());
        StringRef field = op->getAttrOfType<StringAttr>("field").getValue();
        btf::StructOp st = checkKPtr(op, kp);
        if (!st)
          return;
        btf::MemberAttr member = pathMember(op, st, field);
        auto pt = member ? dyn_cast<btf::PtrAttr>(member.getType()) : btf::PtrAttr();
        auto ci = pt ? dyn_cast<btf::IntAttr>(pt.getPointee()) : btf::IntAttr();
        if (!ci || ci.getBits() != 8) {
          bad = true;
          op->emitOpError() << "field \"" << st.getSymName() << "." << field
                           << "\" is not a char * (strptr) field in btf.struct @kernel::@" << st.getSymName()
                           << " (schema core.kernel_types — {\"kind\": \"strptr\"})";
        }
        return;
      }
      // scx.exit_info reads kind (enum 32), exit_code (64-bit int) and
      // reason / msg (char *) of scx_exit_info.
      if (auto ex = dyn_cast<ScxExitInfoOp>(op)) {
        btf::StructOp st = checkKPtr(op, ex.getInfo().getType());
        if (!st)
          return;
        auto memberOf = [&](StringRef name) -> btf::MemberAttr {
          for (Attribute a : st.getMembers())
            if (cast<btf::MemberAttr>(a).getName() == name)
              return cast<btf::MemberAttr>(a);
          return {};
        };
        auto isStr = [](Attribute t) {
          auto pt = dyn_cast<btf::PtrAttr>(t);
          auto ci = pt ? dyn_cast<btf::IntAttr>(pt.getPointee()) : btf::IntAttr();
          return ci && ci.getBits() == 8;
        };
        struct Want {
          StringRef name, schema;
          bool (*ok)(Attribute);
        };
        Want want[] = {
            {"kind", "{\"kind\": \"enum\", \"bits\": 32}",
             [](Attribute t) { auto e = dyn_cast<btf::EnumAttr>(t); return e && e.getBits() == 32; }},
            {"exit_code", "a 64-bit int", [](Attribute t) { auto i = dyn_cast<btf::IntAttr>(t); return i && i.getBits() == 64; }},
            {"reason", "{\"kind\": \"strptr\"}", isStr},
            {"msg", "{\"kind\": \"strptr\"}", isStr},
        };
        for (const Want &w : want) {
          btf::MemberAttr m = memberOf(w.name);
          if (!m || !w.ok(m.getType())) {
            bad = true;
            ex.emitOpError() << "needs field \"scx_exit_info." << w.name << "\" as " << w.schema
                             << " in btf.struct @kernel::@scx_exit_info (schema core.kernel_types), got "
                             << (m ? m.getType() : Attribute());
          }
        }
        return;
      }
      // kfield.ptr requires S's member to point to @kernel::T and returns kptr_or_null<T>.
      if (auto kf = dyn_cast<KFieldPtrOp>(op)) {
        btf::StructOp st = checkKPtr(op, KPtrType::get(op->getContext(), kf.getBaseStructName()));
        if (!st)
          return;
        btf::MemberAttr member = pathMember(op, st, kf.getField());
        auto want = cast<KPtrOrNullType>(kf.getResult().getType()).getStructName();
        auto pt = member ? dyn_cast<btf::PtrAttr>(member.getType()) : btf::PtrAttr();
        auto ref = pt ? dyn_cast<btf::RefAttr>(pt.getPointee()) : btf::RefAttr();
        if (!ref || ref.getTarget().getLeafReference() != want) {
          bad = true;
          kf.emitOpError() << "field \"" << st.getSymName() << "." << kf.getField()
                           << "\" is not a pointer to kernel type \"" << want
                           << "\" in btf.struct @kernel::@" << st.getSymName() << " (schema core.kernel_types — {\"kind\": \"kptr\", \"struct\": \"" << want << "\"})";
        }
        return;
      }
      // kfield.store matches an integer member's width with the stored value.
      if (auto ks = dyn_cast<KFieldStoreOp>(op)) {
        if (ks.getField().contains('.')) { bad = true; ks.emitOpError("nested kernel stores are not supported"); return; }
        btf::StructOp st = checkKPtr(op, cast<KPtrType>(ks.getPtr().getType()));
        if (!st)
          return;
        btf::MemberAttr member;
        for (Attribute a : st.getMembers())
          if (cast<btf::MemberAttr>(a).getName() == ks.getField())
            member = cast<btf::MemberAttr>(a);
        if (!member) {
          bad = true;
          ks.emitOpError() << "btf.struct @kernel::@" << st.getSymName() << " has no field \"" << ks.getField() << "\" (schema core.kernel_types)";
          return;
        }
        auto it = dyn_cast<btf::IntAttr>(member.getType());
        unsigned w = cast<IntegerType>(ks.getValue().getType()).getWidth();
        if (!it || it.getBits() != w) {
          bad = true;
          ks.emitOpError() << "field \"" << st.getSymName() << "." << member.getName() << "\" is " << member.getType()
                           << " in btf.struct @kernel::@" << st.getSymName() << " but written as " << ks.getValue().getType();
        }
        return;
      }
      // kfunc kref/kref_or_null argument and result structs must be declared in
      // @kernel: ObjectEmitter represents FUNC_PROTO struct pointers with
      // local CO-RE types. kptr arguments were checked at ctx.arg or their origin.
      if (isa<KfuncCallOp, KPtrXchgOp, GlobalKPtrXchgOp>(op)) { // Include the new reference and result type of kptr.xchg (and global.kptr_xchg).
        auto structOf = [](Type t) -> StringRef {
          if (auto r = dyn_cast<KRefType>(t))
            return r.getStructName();
          if (auto r = dyn_cast<KRefOrNullType>(t))
            return r.getStructName();
          return {};
        };
        SmallVector<Type> tys(op->getOperandTypes());
        tys.append(op->getResultTypes().begin(), op->getResultTypes().end());
        llvm::SmallSetVector<StringRef, 2> names; // Diagnose each struct once; acquire may share its argument and result type.
        for (Type t : tys)
          if (StringRef s = structOf(t); !s.empty())
            names.insert(s);
        for (StringRef s : names)
          checkKPtr(op, KPtrType::get(op->getContext(), s));
        return;
      }
      // the kaddr reads, the strncmp ops and container_of match their
      // field with @kernel like the kfield ops (paths of 1 to 3 components).
      auto is8BitArray = [](btf::MemberAttr m, uint64_t &count) {
        auto arr = m ? dyn_cast<btf::ArrayOfAttr>(m.getType()) : btf::ArrayOfAttr();
        auto el = arr ? dyn_cast<btf::IntAttr>(arr.getElement()) : btf::IntAttr();
        if (!el || el.getBits() != 8)
          return false;
        count = arr.getCount();
        return true;
      };
      if (auto rd = dyn_cast<KAddrReadOp>(op)) {
        btf::StructOp st = checkKPtr(op, KPtrType::get(op->getContext(), rd.getAddr().getType().getStructName()));
        if (!st)
          return;
        btf::MemberAttr member = pathMember(op, st, rd.getField());
        if (!member) {
          bad = true;
          rd.emitOpError() << "btf.struct @kernel::@" << st.getSymName() << " has no field \"" << rd.getField() << "\" (schema core.kernel_types)";
          return;
        }
        Type t = rd.getValue().getType();
        bool ok = false;
        std::string want;
        if (auto ka = dyn_cast<KAddrType>(t)) {
          auto pt = dyn_cast<btf::PtrAttr>(member.getType());
          if (ka.getStructName().empty()) {
            ok = pt && isa<btf::VoidAttr>(pt.getPointee());
            want = "{\"kind\": \"ptr\"} (void *)";
          } else {
            auto ref = pt ? dyn_cast<btf::RefAttr>(pt.getPointee()) : btf::RefAttr();
            ok = ref && ref.getTarget().getLeafReference() == ka.getStructName();
            want = "{\"kind\": \"kptr\", \"struct\": \"" + ka.getStructName().str() + "\"}";
          }
        } else {
          auto it = dyn_cast<btf::IntAttr>(member.getType()); // Enum fields are read by kfield.load only.
          ok = it && it.getBits() == cast<IntegerType>(t).getWidth();
          want = "an integer of " + std::to_string(cast<IntegerType>(t).getWidth()) + " bits";
        }
        if (!ok) {
          bad = true;
          rd.emitOpError() << "field \"" << st.getSymName() << "." << rd.getField() << "\" is " << member.getType()
                           << " in btf.struct @kernel::@" << st.getSymName() << " but read as " << t << " (schema core.kernel_types — " << want << ")";
        }
        return;
      }
      if (isa<KAddrStrncmpOp, KFieldStrncmpOp>(op)) {
        auto ks = dyn_cast<KFieldStrncmpOp>(op);
        auto as = dyn_cast<KAddrStrncmpOp>(op);
        StringRef sname = ks ? ks.getPtr().getType().getStructName() : as.getAddr().getType().getStructName();
        StringRef field = ks ? ks.getField() : as.getField();
        btf::StructOp st = checkKPtr(op, KPtrType::get(op->getContext(), sname));
        if (!st)
          return;
        btf::MemberAttr member = pathMember(op, st, field);
        uint64_t count = 0;
        if (!is8BitArray(member, count)) {
          bad = true;
          op->emitOpError() << "field \"" << st.getSymName() << "." << field << "\" is not an array of 8-bit integers in btf.struct @kernel::@"
                            << st.getSymName() << " (schema core.kernel_types — {\"kind\": \"array\", \"count\": N, \"element\": {int 8}})";
          return;
        }
        if (ks && static_cast<uint64_t>(ks.getLen()) > count) {
          bad = true;
          ks.emitOpError() << "len " << ks.getLen() << " exceeds the " << count << " elements of \"" << st.getSymName() << "." << field << "\"";
        }
        return;
      }
      if (auto co = dyn_cast<KAddrContainerOfOp>(op)) {
        btf::StructOp st = checkKPtr(op, KPtrType::get(op->getContext(), co.getStructName()));
        if (!st || !checkKPtr(op, KPtrType::get(op->getContext(), co.getAddr().getType().getStructName())))
          return;
        btf::MemberAttr member = pathMember(op, st, co.getField());
        auto ref = member ? dyn_cast<btf::RefAttr>(member.getType()) : btf::RefAttr();
        StringRef t = co.getAddr().getType().getStructName();
        if (!ref || ref.getTarget().getLeafReference() != t) {
          bad = true;
          co.emitOpError() << "field \"" << st.getSymName() << "." << co.getField() << "\" is not the embedded struct \"" << t
                           << "\" in btf.struct @kernel::@" << st.getSymName() << " (schema core.kernel_types — {\"kind\": \"struct\", \"struct\": \"" << t
                           << "\"}), got " << (member ? member.getType() : Attribute());
        }
        return;
      }
      auto ld = dyn_cast<KFieldLoadOp>(op);
      if (!ld)
        return;
      // Reads from acquired kref values use the same matching rules.
      Type pt = ld.getPtr().getType();
      btf::StructOp st = checkKPtr(op, isa<KRefType>(pt)     ? KPtrType::get(op->getContext(), cast<KRefType>(pt).getStructName())
                                       : isa<RcuPtrType>(pt) ? KPtrType::get(op->getContext(), cast<RcuPtrType>(pt).getStructName())
                                                             : cast<KPtrType>(pt));
      if (!st)
        return;
      btf::MemberAttr member = pathMember(op, st, ld.getField());
      if (!member) {
        bad = true;
        ld.emitOpError() << "btf.struct @kernel::@" << st.getSymName() << " has no field \""
                         << ld.getField() << "\" (schema core.kernel_types)";
        return;
      }
      auto it = dyn_cast<btf::IntAttr>(member.getType());
      auto en = dyn_cast<btf::EnumAttr>(member.getType()); // an enum field reads as iN of its width.
      unsigned w = cast<IntegerType>(ld.getResult().getType()).getWidth();
      if (!(it && it.getBits() == w) && !(en && en.getBits() == w)) {
        bad = true;
        ld.emitOpError() << "field \"" << st.getSymName() << "." << member.getName() << "\" is "
                         << member.getType() << " in btf.struct @kernel::@" << st.getSymName()
                         << " but read as " << ld.getResult().getType();
      }
    });
    if (bad)
      signalPassFailure();
  }
};

} // namespace
