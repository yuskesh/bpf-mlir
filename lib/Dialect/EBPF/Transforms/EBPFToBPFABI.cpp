//===- EBPFToBPFABI.cpp - lower explicit CFG to LLVM plus kernel ABI ---------===//
//
// Lower expanded programs into llvm.func. Kernel-facing helpers/context reads/
// verdicts become bpfabi operations using KernelABI.h numbers/nullability/layout.
// Other branches, memory accesses, globals and spills become LLVM operations.
// Helper numbers remain absent from frontend IR/schema. Map placeholders live
// in .maps and addressof creates loader FD relocations; BTF construction follows
// separately. convert-bpfabi-to-llvm handles the next stage.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/PacketNeutral.h"
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h"
#include "ArenaPageLowering.h"
#include "ScalarHelperLowering.h"
#include "mlir/Interfaces/DataLayoutInterfaces.h"
#include "bpf-mlir/Support/DPathTargets.h"
#include "bpf-mlir/Support/LoweringOnlyKfuncs.h"
#include "bpf-mlir/Support/ProgramKinds.h"
#include "bpf-mlir/Support/TraceFormat.h"
#include "bpf-mlir/Support/Usdt.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/SHA256.h"

#include "bpf-mlir/Dialect/BPFABI/IR/BPFABIDialect.h"
#include "bpf-mlir/Dialect/BPFABI/KernelABI.h"
#include "bpf-mlir/Dialect/BTF/IR/BTFDialect.h"
#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"
#include "bpf-mlir/Dialect/EBPF/Transforms/RecordPath.h"

#include "mlir/Dialect/Arith/IR/Arith.h"
#include "mlir/Dialect/ControlFlow/IR/ControlFlowOps.h"
#include "mlir/Dialect/LLVMIR/LLVMDialect.h"
#include "mlir/IR/Builders.h"
#include "mlir/IR/IRMapping.h"
#include "mlir/IR/Matchers.h"
#include "llvm/ADT/StringMap.h"

#include <functional>
#include <set>

namespace mlir {
namespace ebpf {
#define GEN_PASS_DEF_CONVERTEBPFTOBPFABI
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h.inc"
} // namespace ebpf
} // namespace mlir

using namespace mlir;
using namespace mlir::ebpf;

namespace {

// a kfield site's enclosing guard ids (ebpf-verify-schema) ride on the
// CO-RE op to the ④ marker name, where ObjectEmitter keeps the matching ones.
void copyGuards(mlir::Operation *from, mlir::Operation *to) {
  if (mlir::Attribute a = from->getAttr("ebpf.guards"))
    to->setAttr("ebpf.guards", a);
}

// Compiler support is exactly the ProgramKinds.def rows. Kernel helper
// availability is recorded as a requirement, never decided during compilation.
bool helperLoweringSupportedFor(StringRef programKind) { return bpfmlir::lookupProgramKind(programKind) != nullptr; }

// Attachment-table SECTION owns loader-recognized section spellings and
// expected attachment types. User binary paths/offsets remain loader inputs.
StringRef attachOf(ProgramOp prog) { return prog.getAttachValue(); } // Multi rows carry no name value in sections/types; use the first name for lookup.
const bpfmlir::ProgramAttachInfo *attachRowFor(ProgramOp prog) { return bpfmlir::lookupProgramAttach(prog.getKind(), attachOf(prog), prog.getAttachFlags()); }
std::string sectionFor(ProgramOp prog) {
  const bpfmlir::ProgramAttachInfo *a = attachRowFor(prog);
  if (!a) // Unknown kinds/missing attachment rows should already fail op verification.
    return prog.getKind().str();
  return bpfmlir::sectionOf(*a, attachOf(prog));
}
StringRef progTypeFor(StringRef kind) { return programTypeOf(kind); } // Share dialect programTypeOf with target-legality checks.

// Strict-alignment verifiers (check_pkt_ptr_alignment) model NET_IP_ALIGN = 2
// and accept a W-byte packet read at constant offset off only if
// (2 + off) mod W = 0; width 1 is never checked. The rule is the same on every
// kernel the compiler targets, so it does not consult the kernel version.
bool strictAlignedPacketRead(uint64_t off, unsigned width) { return width > 1 && (2 + off) % width == 0; }

// Stage 2 widens a packet.check's offset with arith.extui; look through it.
std::optional<uint64_t> constantPacketOffset(Value off) {
  if (auto ext = off.getDefiningOp<arith::ExtUIOp>())
    off = ext.getIn();
  APInt c;
  if (!matchPattern(off, m_ConstantInt(&c)) || c.getActiveBits() > 64)
    return std::nullopt;
  return c.getZExtValue();
}

// The constant packet offset of a window: every predecessor of its block must
// be a pkt.check_br entering it through in_range with the same constant offset.
// Windows passed as static-function arguments have no such origin.
std::optional<uint64_t> constantWindowOffset(Value window) {
  auto arg = dyn_cast<BlockArgument>(window);
  if (!arg)
    return std::nullopt;
  Block *blk = arg.getOwner();
  std::optional<uint64_t> off;
  for (auto it = blk->pred_begin(), e = blk->pred_end(); it != e; ++it) {
    auto pk = dyn_cast<PktCheckBrOp>((*it)->getTerminator());
    if (!pk || pk.getInRange() != blk || pk.getOutOfRange() == blk)
      return std::nullopt;
    std::optional<uint64_t> c = constantPacketOffset(pk.getOffset());
    if (!c || (off && *off != *c))
      return std::nullopt;
    off = c;
  }
  return off;
}

// the constant arena offset of a window — its block is entered only
// through an arena.check_br's in_range with a constant (extui-looked-through)
// offset. Anything else is not provably aligned.
std::optional<uint64_t> constantArenaWindowOffset(Value window) {
  auto arg = dyn_cast<BlockArgument>(window);
  if (!arg)
    return std::nullopt;
  Block *blk = arg.getOwner();
  Block *pred = blk->getSinglePredecessor();
  auto br = pred ? dyn_cast<ArenaCheckBrOp>(pred->getTerminator()) : ArenaCheckBrOp();
  if (!br || br.getInRange() != blk || br.getOutOfRange() == blk)
    return std::nullopt;
  return constantPacketOffset(br.getOffset());
}

// Module-wide state.
struct Lowering {
  ModuleOp module;
  OpBuilder builder;
  // All program kinds reaching the current function. Helpers in shared
  // subprograms must lower for every reaching kind, not just one caller.
  SmallVector<StringRef> programKinds;
  llvm::StringMap<LLVM::GlobalOp> mapGlobals;
  bool failed = false;
  Operation *currentOp = nullptr; // Current operation for helper invalidation-table consistency checks.
  bool skipFullCoverMemset = false; // Elide memset when stores cover every reservation byte.
  bool storeRecordDirect = false;   // Direct record stores tuning.
  bool storeRecordMerge = false;    // Constant direct-record tuning includes direct stores.
  bool warnIndexMaskFit = true;     // Checked-index fit warning.
  bool shareKeySlot = false;        // Key-slot reuse tuning.
  bool spillLifetime = false;       // Spill-slot lifetime markers, enabled by default.
  bool alignedPacketLoad = false;   // One wide read for strict-alignment-provable constant packet offsets.

  explicit Lowering(ModuleOp m) : module(m), builder(m.getContext()) {}

  Type ptrTy() { return LLVM::LLVMPointerType::get(module.getContext()); }
  // arena memory is address space 1 (__arena); the BPF backend casts
  // before the first access (addr_space_cast).
  Type arenaPtrTy() { return LLVM::LLVMPointerType::get(module.getContext(), 1); }

  // the arena size in bytes (schema pages × 4096) of map symbol `sym`,
  // recorded by ebpf-build-btf-types as the module attribute ebpf.arena_bytes.
  std::optional<uint64_t> arenaBytes(StringRef sym) {
    auto d = module->getAttrOfType<DictionaryAttr>(kArenaBytesAttr);
    auto v = d ? d.getAs<IntegerAttr>(sym) : IntegerAttr();
    if (!v || v.getInt() <= 0)
      return std::nullopt;
    return static_cast<uint64_t>(v.getInt());
  }
  static constexpr StringLiteral kArenaBytesAttr = "ebpf.arena_bytes";

  // Establish .maps symbols and addressof targets. BTF lowering later
  // replaces placeholders with actual map-definition structs.
  LLVM::GlobalOp mapGlobal(StringRef symbol, Location loc) {
    auto it = mapGlobals.find(symbol);
    if (it != mapGlobals.end())
      return it->second;
    // ELF has one symbol namespace: never reuse a data/function symbol as a map.
    if (Operation *other = module.lookupSymbol(symbol)) {
      emitError(loc) << "map @" << symbol << " collides with another symbol of the same name ("
                     << other->getName() << ")";
      return nullptr;
    }
    OpBuilder::InsertionGuard g(builder);
    builder.setInsertionPointToStart(module.getBody());
    auto ty = LLVM::LLVMArrayType::get(builder.getI8Type(), 1);
    auto global = LLVM::GlobalOp::create(
        builder, loc, ty, /*isConstant=*/false, LLVM::Linkage::External,
        symbol, /*value=*/Attribute());
    global.setSection(".maps");
    mapGlobals[symbol] = global;
    return global;
  }

  // Global placeholders receive sections/typed definitions from schema BTF lowering.
  LLVM::GlobalOp globalVar(StringRef name, Type t, Location loc) {
    // Never reinterpret a same-named map placeholder or function as a data global.
    if (Operation *other = module.lookupSymbol(name)) {
      auto g = dyn_cast<LLVM::GlobalOp>(other);
      if (!g || !g->hasAttr("ebpf.global")) {
        emitError(loc) << "global @" << name << " collides with another symbol of the same name (" << other->getName()
                       << (g && g.getSection() ? (" in " + *g.getSection()) : std::string()) << ")";
        return nullptr;
      }
      if (g.getGlobalType() != t) {
        emitError(loc) << "global @" << name << " is used as " << t << " and as " << g.getGlobalType();
        return nullptr;
      }
      return g;
    }
    OpBuilder::InsertionGuard g(builder);
    builder.setInsertionPointToStart(module.getBody());
    auto global = LLVM::GlobalOp::create(builder, loc, t, /*isConstant=*/false, LLVM::Linkage::External, name,
                                         /*value=*/Attribute());
    global->setAttr("ebpf.global", builder.getUnitAttr());
    return global;
  }

  // C's extern T v __ksym [__weak] / extern T CONFIG_X __kconfig [__weak].
  // Linkage, section and type come from the schema (stamped by
  // ebpf-verify-schema); ObjectEmitter adds the VAR debug type.
  LLVM::GlobalOp externVar(StringRef name, Type t, StringRef section, bool weak, Location loc) {
    if (Operation *other = module.lookupSymbol(name)) {
      auto g = dyn_cast<LLVM::GlobalOp>(other);
      if (!g || !g->hasAttr("ebpf.extern") || g.getSection() != section) {
        emitError(loc) << "extern @" << name << " in " << section << " collides with another symbol of the same name ("
                       << other->getName() << ")";
        return nullptr;
      }
      if (g.getGlobalType() != t || (g.getLinkage() == LLVM::Linkage::ExternWeak) != weak) {
        emitError(loc) << "extern @" << name << " is used as " << t << (weak ? " (weak)" : "") << " and as " << g.getGlobalType();
        return nullptr;
      }
      return g;
    }
    OpBuilder::InsertionGuard g(builder);
    builder.setInsertionPointToStart(module.getBody());
    auto global = LLVM::GlobalOp::create(builder, loc, t, /*isConstant=*/false,
                                         weak ? LLVM::Linkage::ExternWeak : LLVM::Linkage::External, name,
                                         /*value=*/Attribute(), /*alignment=*/t.isInteger() ? std::max(1u, t.getIntOrFloatBitWidth() / 8) : 8);
    global.setSection(section);
    global->setAttr("ebpf.extern", builder.getStringAttr(section == ".ksyms" ? "ksym" : "kconfig"));
    return global;
  }

  // Compiler-owned format strings. trace.printk's helper takes read-only memory
  // (ARG_PTR_TO_MEM | MEM_RDONLY), so its format stays in .rodata as C's
  // bpf_printk. the sched_ext bstr kfuncs' `char *fmt` is a fixed-size
  // kfunc memory argument the verifier checks for read and write
  // (verifier.c:13171), which a BPF_F_RDONLY_PROG .rodata map value fails, so
  // their format is in writable .data as C's scx_bpf_bstr_preamble.
  LLVM::GlobalOp traceFormat(StringRef format, Location loc) {
    return formatGlobal(format, "__ebpf_trace_", ".rodata", loc);
  }
  // a trace.printk %s literal — read through the u64 slot by
  // bpf_bprintf_prepare (strncpy_from_kernel_nofault), so .rodata as C's
  // bpf_printk("%s", "lit"). The prefix keeps it apart from a format of the
  // same content (the hash is hex, so no __ebpf_trace_<hash> equals it).
  LLVM::GlobalOp traceStrLiteral(StringRef lit, Location loc) {
    return formatGlobal(lit, "__ebpf_trace_str_", ".rodata", loc);
  }
  LLVM::GlobalOp scxFormat(StringRef format, Location loc) {
    return formatGlobal(format, "__ebpf_scx_fmt_", ".data", loc);
  }
  // bpf_strncmp's s2 is ARG_PTR_TO_CONST_STR — a NUL-terminated value of
  // a frozen BPF_F_RDONLY_PROG map, so the literal is in .rodata (as C's).
  LLVM::GlobalOp strncmpLiteral(StringRef lit, Location loc) {
    return formatGlobal(lit, "__ebpf_strncmp_", ".rodata", loc);
  }
  LLVM::GlobalOp formatGlobal(StringRef format, StringRef prefix, StringRef section, Location loc) {
    std::string symbol =
        prefix.str() +
        llvm::toHex(llvm::SHA256::hash(llvm::arrayRefFromStringRef(format)),
                    true);
    if (Operation *other = module.lookupSymbol(symbol)) {
      auto g = dyn_cast<LLVM::GlobalOp>(other);
      if (!g || g->getAttrOfType<StringAttr>("ebpf.trace_format") !=
                    builder.getStringAttr(format)) {
        emitError(loc) << "format symbol collision: " << symbol;
        return nullptr;
      }
      return g;
    }
    OpBuilder::InsertionGuard guard(builder);
    builder.setInsertionPointToStart(module.getBody());
    auto ty = LLVM::LLVMArrayType::get(builder.getI8Type(), format.size() + 1);
    auto global = LLVM::GlobalOp::create(
        builder, loc, ty, false, LLVM::Linkage::Internal, symbol, Attribute());
    global.setSection(section);
    global->setAttr("ebpf.trace_format", builder.getStringAttr(format));
    return global;
  }

  // Resolve record field offsets from @records after VerifyRecords; missing evidence fails.
  // cpumaskLeaf: the field is an embedded cpumask (ebpf.ref.field.addr).
  FailureOr<int64_t> recordFieldOffset(Operation *op, StringRef record, StringRef field, bool cpumaskLeaf = false) {
    for (auto sc : module.getOps<btf::ScopeOp>()) {
      if (sc.getSymName() != "records")
        continue;
      auto st = dyn_cast_or_null<btf::StructOp>(SymbolTable::lookupSymbolIn(sc, record));
      if (!st)
        break;
      // Field paths include x, x.y and x[i].
      std::string err;
      if (cpumaskLeaf) {
        FailureOr<RecordTemplate> t = resolveRecordTemplate(sc, st, field, err, /*recordLeaf=*/false, true);
        if (succeeded(t) && t->cpumaskBytes > 0 && t->dims.empty())
          return t->offsetBytes;
        break;
      }
      FailureOr<RecordLeaf> leaf = resolveRecordPath(sc, st, field, err);
      if (succeeded(leaf))
        return leaf->offsetBytes;
      break;
    }
    failed = true;
    op->emitOpError() << "cannot resolve field \"" << field << "\" of record \"" << record
                      << "\" in btf.scope @records (run ebpf-build-btf-types and ebpf-verify-records first)";
    return failure();
  }

  // Resolve variable-index templates through @records.
  FailureOr<RecordTemplate> recordTemplate(Operation *op, StringRef record, StringRef field) {
    for (auto sc : module.getOps<btf::ScopeOp>()) {
      if (sc.getSymName() != "records")
        continue;
      auto st = dyn_cast_or_null<btf::StructOp>(SymbolTable::lookupSymbolIn(sc, record));
      if (!st)
        break;
      std::string err;
      FailureOr<RecordTemplate> t = resolveRecordTemplate(sc, st, indexTemplate(field), err, /*recordLeaf=*/true);
      if (succeeded(t))
        return *t;
      break;
    }
    failed = true;
    op->emitOpError() << "cannot resolve array field \"" << field << "\" of record \"" << record
                      << "\" in btf.scope @records (run ebpf-build-btf-types and ebpf-verify-records first)";
    return failure();
  }

  // Resolve direct opaque lock/timer member offsets from @records, sharing
  // logic with type-specific diagnostic vocabulary.
  FailureOr<int64_t> specialOffset(Operation *op, StringRef record, StringRef field, StringRef type, StringRef word) {
    for (auto sc : module.getOps<btf::ScopeOp>()) {
      if (sc.getSymName() != "records")
        continue;
      if (auto st = dyn_cast_or_null<btf::StructOp>(SymbolTable::lookupSymbolIn(sc, record)))
        for (Attribute a : st.getMembers()) {
          auto m = cast<btf::MemberAttr>(a);
          auto r = dyn_cast<btf::RefAttr>(m.getType());
          if (m.getName() == field && r && r.getTarget().getLeafReference() == type)
            return static_cast<int64_t>(m.getOffsetBits() / 8);
        }
      break;
    }
    failed = true;
    op->emitOpError() << "field \"" << field << "\" of record \"" << record << "\" is not a " << word << " field in btf.scope @records";
    return failure();
  }
  // Share the constant-path byte-offset resolver with source verification.
  FailureOr<int64_t> kptrOffset(Operation *op, StringRef record, StringRef field) {
    for (auto sc : module.getOps<btf::ScopeOp>()) {
      if (sc.getSymName() != "records")
        continue;
      if (auto st = dyn_cast_or_null<btf::StructOp>(SymbolTable::lookupSymbolIn(sc, record))) {
        std::string err;
        auto leaf = resolveKptrPath(sc, st, field, err);
        if (succeeded(leaf))
          return leaf->offsetBytes;
        failed = true;
        op->emitOpError() << err;
        return failure();
      }
      break;
    }
    failed = true;
    op->emitOpError() << "field \"" << field << "\" of record \"" << record << "\" is not a kptr field in btf.scope @records";
    return failure();
  }
  FailureOr<int64_t> lockOffset(Operation *op, StringRef record, StringRef field) {
    return specialOffset(op, record, field, "bpf_spin_lock", "spin_lock");
  }

  // leak check: a helper that may sleep (SleepableOps.def) or a kfunc row
  // with the flag "sleepable" is emitted only for an op of the sleepable-op
  // table; otherwise ebpf.rcu.region would miss it. Internal error, loud.
  LogicalResult checkSleepLeak(StringRef callee, bool kfunc) {
    bool sleeps = false;
    if (kfunc) {
      const bpfabi::KfuncABI *k = bpfabi::lookupKfunc(callee);
      sleeps = k && k->hasFlag("sleepable");
    } else {
      sleeps = bpfmlir::isMightSleepHelper(callee);
    }
    if (!sleeps || (currentOp && opMightSleep(currentOp)))
      return success();
    failed = true;
    (currentOp ? currentOp->emitOpError() : module.emitError())
        << "calls " << (kfunc ? "kfunc " : "helper ") << callee
        << ", which may sleep, but the op is not in the sleepable-op table (SleepableOps.def) — internal error: add the op to "
           "the table so ebpf.rcu.region rejects it";
    return failure();
  }

  // ABI table owns helper numbers, return types and nullability. Use the
  // caller's builder: this lowering object's builder has no insertion point
  // and would create unlinked operations. Void helpers return a null Value;
  // errors return failure.
  FailureOr<Value> helperCall(OpBuilder &b, Location loc, StringRef name,
                              ValueRange args) {
    for (StringRef programKind : programKinds)
      if (!helperLoweringSupportedFor(programKind)) {
        failed = true;
        module.emitError() << "helper " << name
                           << " is not available for program kind \""
                           << programKind << "\"";
        return failure();
      }
    const bpfabi::HelperABI *h = bpfabi::lookupHelper(name);
    if (!h) {
      failed = true;
      module.emitError() << "helper " << name << " is not in the UAPI table";
      return failure();
    }
    // Every emitted pktinval helper requires a true PacketNeutral invalidation
    // predicate for its source operation. Reject table omissions here, keeping
    // VerifyStructured and fact diagnostics consistent with actual lowering.
    if (bpfabi::isPacketInvalidatingHelper(name) && (!currentOp || !opInvalidatesPacketPointers(currentOp))) {
      failed = true;
      (currentOp ? currentOp->emitOpError() : module.emitError())
          << "calls helper " << name << ", which invalidates packet pointers, but the op is not in the packet-effect table "
             "(PacketNeutral invalidatesPacketPointers) — internal error: add the op to the table";
      return failure();
    }
    // likewise every emitted helper that may sleep needs its op in the
    // sleepable-op table (SleepableOps.def), which ebpf.rcu.region rejects.
    if (mlir::failed(checkSleepLeak(name, /*kfunc=*/false)))
      return failure();
    SmallVector<Type> resTys;
    switch (h->retKind) {
    case bpfabi::RetKind::Void:
      break;
    case bpfabi::RetKind::Int:
      resTys.push_back(b.getI64Type());
      break;
    case bpfabi::RetKind::Ptr:
      resTys.push_back(ptrTy());
      break;
    }
    bool nullable = h->retKind == bpfabi::RetKind::Ptr && h->markNullable();
    auto call = bpfabi::HelperCallOp::create(
        b, loc, resTys, b.getStringAttr(h->name), b.getI64IntegerAttr(h->id),
        nullable ? b.getUnitAttr() : UnitAttr(), args);
    return resTys.empty() ? Value() : call.getResult(0);
  }
};

struct ConvertEBPFToBPFABIPass
    : public mlir::ebpf::impl::ConvertEBPFToBPFABIBase<
          ConvertEBPFToBPFABIPass> {
  using Base::Base; // Constructor accepting tuning options.
  void runOnOperation() override;
};

// every bpfabi.kfunc_call the per-function builder inserts goes through
// the sleep leak check (the call sites are many; the listener is one place).
struct SleepLeakListener : public OpBuilder::Listener {
  Lowering *ctx = nullptr;
  void notifyOperationInserted(Operation *op, OpBuilder::InsertPoint) override {
    if (auto k = dyn_cast<bpfabi::KfuncCallOp>(op))
      (void)ctx->checkSleepLeak(k.getCallee(), /*kfunc=*/true);
  }
};

// Per-function conversion.
class ProgramLowering {
public:
  // Owner is a program or func.
  ProgramLowering(Operation *owner, Lowering &ctx)
      : owner_(owner), prog_(dyn_cast<ProgramOp>(owner)),
        sub_(dyn_cast<SubprogramOp>(owner)), cb_(dyn_cast<LoopCallbackOp>(owner)),
        tcb_(dyn_cast<TimerCallbackOp>(owner)), ucb_(dyn_cast<UserRingbufCallbackOp>(owner)), ctx_(ctx),
        b_(owner->getContext()) {
    sleepListener_.ctx = &ctx_;
    b_.setListener(&sleepListener_);
  }

  LogicalResult run();

private:
  Value remap(Value v) {
    auto it = map_.find(v);
    return it == map_.end() ? Value() : it->second;
  }
  void bind(Value from, Value to) { map_[from] = to; }
  SmallVector<Value> remapAll(ValueRange vs) {
    SmallVector<Value> out;
    for (Value v : vs)
      out.push_back(remap(v));
    return out;
  }

  Type convertType(Type t) {
    // the arena base is the i64 user_vm_start; a window is an
    // address-space-1 pointer (in practice never a block argument — ③ creates
    // it with bpfabi.arena_addr in the in-range block).
    if (isa<ArenaBaseType>(t))
      return IntegerType::get(t.getContext(), 64);
    if (isa<ArenaWindowType>(t))
      return ctx_.arenaPtrTy();
    return isa<EBPFDialect>(t.getDialect()) ? ctx_.ptrTy() : t;
  }

  LogicalResult convertOp(Operation &op);
  LogicalResult runSubprogram();
  LogicalResult runCallback();
  LogicalResult runTimerCallback();
  LogicalResult runUserRingbufCallback();
  Value ctxSlot(Value base, int64_t k, Location loc);
  LogicalResult bindMaps(ArrayAttr syms, Block::BlockArgListType args, Location loc);
  LogicalResult convertBody(Region &body);

  Value allocaFor(Type t, Location loc);
  Value literalBuffer(StringRef literal, int64_t n, Location loc);
  static unsigned provableAlignment(unsigned baseAlign, int64_t offset,
                                    Type t);
  static LogicalResult checkOnce(Operation *op, bool once, unsigned align, Type t);
  Value spillInt(Value v, Location loc);
  Value spillKey(Value v, Location loc);
  void endSpills(Location loc);
  DenseMap<Type, Value> keySlots_; // Key slots per function and integer type.

  Operation *owner_;
  ProgramOp prog_;     // Program case.
  SubprogramOp sub_;   // Subprogram case.
  LoopCallbackOp cb_;  // bpf_loop callback case.
  TimerCallbackOp tcb_; // Timer callback case.
  UserRingbufCallbackOp ucb_; // User-ringbuf drain callback case.
  Lowering &ctx_;
  SleepLeakListener sleepListener_; // Declared before b_, which points at it.
  OpBuilder b_;
  DenseMap<Value, Value> map_;
  DenseMap<Block *, Block *> blocks_;
  // alignment of a borrowed record element (elem.at of a record leaf);
  // other borrows (map values, globals) are kMapValueAlignment.
  DenseMap<Value, unsigned> borrowAlign_;
  unsigned borrowAlign(Value lowered) const {
    auto it = borrowAlign_.find(lowered);
    return it == borrowAlign_.end() ? bpfabi::kMapValueAlignment : it->second;
  }
  // i64 uses LLVM's native atomics (CPU v1 has them); i32 is inline asm
  // — LLVM rejects 32-bit cmpxchg / atomicrmw or below CPU v3 and ObjectEmitter
  // targets v1. The asm pins the kernel's implicit r0 (cmpxchg compares with
  // and returns in r0) and the source r2; ~{memory} is a compiler barrier.
  Value atomicCmpxchg(Value at, Value expected, Value desired, Location loc) {
    if (expected.getType().isInteger(64)) {
      auto cx = LLVM::AtomicCmpXchgOp::create(b_, loc, at, expected, desired, LLVM::AtomicOrdering::seq_cst, LLVM::AtomicOrdering::seq_cst);
      return LLVM::ExtractValueOp::create(b_, loc, cx.getRes(), ArrayRef<int64_t>{0});
    }
    auto asmOp = LLVM::InlineAsmOp::create(b_, loc, TypeRange{b_.getI32Type()}, ValueRange{at, expected, desired},
                                           "w0 = cmpxchg32_32($1 + 0, w0, w2)", "={r0},r,{r0},{r2},~{memory}",
                                           /*has_side_effects=*/true, /*is_align_stack=*/false, LLVM::tailcallkind::TailCallKind::None,
                                           /*asm_dialect=*/LLVM::AsmDialectAttr(), /*operand_attrs=*/ArrayAttr());
    return asmOp.getResult(0);
  }
  void atomicOr(Value at, Value v, Location loc) {
    if (v.getType().isInteger(64)) {
      LLVM::AtomicRMWOp::create(b_, loc, LLVM::AtomicBinOp::_or, at, v, LLVM::AtomicOrdering::monotonic);
      return;
    }
    LLVM::InlineAsmOp::create(b_, loc, TypeRange{}, ValueRange{at, v}, "lock *(u32 *)($0 + 0) |= w2", "r,{r2},~{memory}",
                              /*has_side_effects=*/true, /*is_align_stack=*/false, LLVM::tailcallkind::TailCallKind::None,
                              /*asm_dialect=*/LLVM::AsmDialectAttr(), /*operand_attrs=*/ArrayAttr());
  }
  DenseMap<Value, unsigned> elemAlign_; // elem.at pointer alignments and direct record fields (offset/lowered
  // value), stored into reservations at store_record.
  DenseMap<Value, SmallVector<std::pair<int64_t, Value>>> directRecords_;
  // Constant field bit patterns/widths, or nullopt for nonconstant values.
  DenseMap<Value, SmallVector<std::optional<std::pair<APInt, unsigned>>>> directConsts_;
  // Current spill slots with lifetime.start, closed by endSpills after helper calls.
  SmallVector<Value> liveSpills_;
  // Selects feeding integer returns in negative-range kinds, recursively
  // through select arms; constant arms require barriers.
  llvm::SmallPtrSet<Operation *, 4> retSelects_;
  LLVM::LLVMFuncOp func_;
  Block *entry_ = nullptr;
};

// Explicit record.make alloca alignment anchors provable field-store alignment.
constexpr unsigned kRecordStackAlignment = 8;

// An n-byte stack buffer holding the literal, then zeros; every byte is written.
Value ProgramLowering::literalBuffer(StringRef literal, int64_t n, Location loc) {
  Value buf = allocaFor(LLVM::LLVMArrayType::get(b_.getI8Type(), n), loc);
  cast<LLVM::AllocaOp>(buf.getDefiningOp()).setAlignment(8);
  std::string bytes = literal.str();
  bytes.resize(n, '\0');
  for (int64_t off = 0; off < n;) {
    unsigned w = off + 8 <= n ? 8 : 1;
    uint64_t v = 0;
    for (unsigned k = 0; k < w; ++k)
      v |= static_cast<uint64_t>(static_cast<unsigned char>(bytes[off + k])) << (8 * k); // bpfel
    Type it = b_.getIntegerType(8 * w);
    Value c = LLVM::ConstantOp::create(b_, loc, it, b_.getIntegerAttr(it, APInt(8 * w, v)));
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), buf, ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(off)});
    LLVM::StoreOp::create(b_, loc, c, at, w);
    off += w;
  }
  return buf;
}

Value ProgramLowering::allocaFor(Type t, Location loc) {
  OpBuilder::InsertionGuard g(b_);
  b_.setInsertionPointToStart(entry_);
  Value one = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(),
                                       b_.getI64IntegerAttr(1));
  return LLVM::AllocaOp::create(b_, loc, ctx_.ptrTy(), t, one);
}

// Proven alignment is bounded by base alignment, offset divisibility and
// value width; never assume i64 implies alignment eight. A single instruction
// does not make shared-map accesses atomic. once requires natural alignment:
// BPF splits insufficiently aligned volatile accesses, breaking its one-access
// contract. Reject unproven alignment or non-integer once as unsupported.
LogicalResult ProgramLowering::checkOnce(Operation *op, bool once, unsigned align, Type t) {
  if (!once)
    return success();
  auto it = dyn_cast<IntegerType>(t);
  if (!it)
    return op->emitOpError() << "'once' is supported only for integer accesses (got " << t << ")";
  // Enforce 8/16/32/64-bit once widths here too. Rounding i1/i24 to bytes
  // could falsely pass alignment checks, and handwritten IR can bypass schema.
  unsigned bits = it.getWidth();
  if (bits != 8 && bits != 16 && bits != 32 && bits != 64)
    return op->emitOpError() << "'once' is supported only for 8/16/32/64-bit accesses (got i" << bits
                             << ") — a single BPF load / store of the declared width must exist";
  unsigned width = bits / 8;
  if (align < width)
    return op->emitOpError() << "'once' needs the natural alignment of the access (" << width
                             << " byte(s)), but only " << align
                             << " byte(s) can be proven from the declared layout — a volatile access would be split";
  return success();
}

unsigned ProgramLowering::provableAlignment(unsigned baseAlign, int64_t offset,
                                            Type t) {
  auto it = dyn_cast<IntegerType>(t);
  if (!it)
    return 0; // Leave non-integer alignment unspecified, preserving translation defaults.
  unsigned a = baseAlign;
  while (a > 1 && offset % a != 0)
    a /= 2;
  unsigned width = std::max(1u, it.getWidth() / 8);
  return std::min(a, width);
}

// Optional share-key-slot uses one scalar-key slot per function/integer
// type; helpers read only during calls. Otherwise use per-op spillInt. Never
// reuse it for values, which must not alias update keys.
Value ProgramLowering::spillKey(Value v, Location loc) {
  if (!ctx_.shareKeySlot)
    return spillInt(v, loc);
  Value &slot = keySlots_[v.getType()];
  if (!slot)
    slot = allocaFor(v.getType(), loc);
  LLVM::StoreOp::create(b_, loc, v, slot);
  return slot;
}

// Lifetime markers bound spill slots from store to helper return. Since
// helpers retain no key/value pointers, LLVM StackColoring can overlap slots
// instead of accumulating stack usage per operation.
Value ProgramLowering::spillInt(Value v, Location loc) {
  Value slot = allocaFor(v.getType(), loc);
  if (ctx_.spillLifetime) {
    LLVM::LifetimeStartOp::create(b_, loc, slot);
    liveSpills_.push_back(slot);
  }
  LLVM::StoreOp::create(b_, loc, v, slot);
  return slot;
}

void ProgramLowering::endSpills(Location loc) {
  for (Value slot : liveSpills_)
    LLVM::LifetimeEndOp::create(b_, loc, slot);
  liveSpills_.clear();
}

LogicalResult ProgramLowering::run() {
  Location loc = owner_->getLoc();
  if (sub_)
    return runSubprogram();
  if (cb_)
    return runCallback();
  if (tcb_)
    return runTimerCallback();
  if (ucb_)
    return runUserRingbufCallback();
  ctx_.programKinds = {prog_.getKind()};

  // Ordinary programs lower to ptr-context functions returning i32 with an
  // attachment section. ext instead takes i64 argument registers through its
  // maximum used index, truncating in ext.arg, and returns the verified i32/i64
  // type. BTF independently uses the full schema signature, including unused args.
  const bpfmlir::ProgramKindInfo *kinfo = bpfmlir::lookupProgramKind(prog_.getKind());
  bool takesCtx = !kinfo || bpfmlir::entryTakesCtx(kinfo->attach);
  LLVM::LLVMFunctionType fnTy;
  if (takesCtx) {
    // struct_ops may return i64 (size_t members); every other context
    // program, and every i32 struct_ops program, keeps the i32 return.
    Type retTy = b_.getI32Type();
    if (kinfo && kinfo->sig == bpfmlir::SigFamily::OpsSig)
      prog_.walk([&](ReturnOp r) { retTy = r.getValue().getType(); });
    // A named verdict lowers to an i32 return; do not mix it into an i64 entry.
    if (retTy.isInteger(64)) {
      bool verdict = false;
      prog_.walk([&](VerdictOp) { verdict = true; });
      if (verdict)
        return prog_.emitOpError() << "returns an i64 value and also ends a path with ebpf.verdict, which returns i32; "
                                      "end every path of an i64 struct_ops program with ebpf.return";
    }
    fnTy = LLVM::LLVMFunctionType::get(retTy, {ctx_.ptrTy()});
  } else {
    int64_t nparams = 0;
    prog_.walk([&](ExtArgOp a) { nparams = std::max<int64_t>(nparams, a.getIndex() + 1); });
    Type retTy = b_.getI32Type();
    prog_.walk([&](ReturnOp r) { retTy = r.getValue().getType(); });
    fnTy = LLVM::LLVMFunctionType::get(retTy, SmallVector<Type>(nparams, b_.getI64Type()));
  }
  {
    OpBuilder::InsertionGuard g(b_);
    b_.setInsertionPoint(prog_);
    func_ = LLVM::LLVMFuncOp::create(b_, loc, prog_.getSymName(), fnTy);
    func_.setSection(sectionFor(prog_));
    // Program type comes from the compiler's kind table and feeds requirements.
    func_->setAttr("bpfabi.prog_type",
                   b_.getStringAttr(progTypeFor(prog_.getKind())));
  }
  entry_ = func_.addEntryBlock(b_);

  // Barrier constant arms of selects feeding negative-range returns. BPF
  // SelectionDAG can fold select c,-1,0 into sext i1 and BPF_NEG; 6.12 loses
  // its range and rejects LSM [-4095,0]. Barriers retain branches with constant
  // R0 per path instead.
  if (StringRef range; attachRowFor(prog_) && bpfmlir::intReturnOf(*attachRowFor(prog_), range)) { // Integer-return ranges belong to attachment rows.
    auto [loS, hiS] = range.split("..");
    int64_t lo = 0;
    if (!hiS.empty() && !loS.getAsInteger(10, lo) && lo < 0) {
      std::function<void(Value)> chase = [&](Value v) {
        Operation *d = v.getDefiningOp();
        if (!d || d->getName().getStringRef() != "arith.select" || !retSelects_.insert(d).second)
          return;
        chase(d->getOperand(1));
        chase(d->getOperand(2));
      };
      prog_.walk([&](ReturnOp r) { chase(r.getValue()); });
    }
  }

  Block &srcEntry = prog_.getBody().front();
  if (takesCtx)
    bind(srcEntry.getArgument(0), entry_->getArgument(0));
  if (failed(bindMaps(prog_.getMapSymbolsAttr(), srcEntry.getArguments().drop_front(), loc)))
    return failure();
  return convertBody(prog_.getBody());
}

// Funcs become .text llvm.func: static/internal or global/external. Keep
// no_inline to preserve actual callees. Requirements uses bpfabi.subprogram
// for reachability; ObjectEmitter later removes the marker.
LogicalResult ProgramLowering::runSubprogram() {
  Location loc = sub_.getLoc();
  FunctionType ft = sub_.getFunctionType();
  // Nullable/borrowed arguments lower to opaque pointers. Preserve source
  // pointee width and tag decisions in bpfabi.arg_types for BTF construction.
  SmallVector<Type> params;
  for (Type t : ft.getInputs())
    params.push_back(convertType(t));
  auto fnTy = LLVM::LLVMFunctionType::get(ft.getResult(0), params);
  {
    OpBuilder::InsertionGuard g(b_);
    b_.setInsertionPoint(sub_);
    func_ = LLVM::LLVMFuncOp::create(
        b_, loc, sub_.getSymName(), fnTy,
        sub_.getLinkage() == "static" ? LLVM::Linkage::Internal
                                      : LLVM::Linkage::External);
    func_.setNoInline(true);
    func_->setAttr("bpfabi.subprogram", b_.getStringAttr(sub_.getLinkage()));
    func_->setAttr("bpfabi.arg_types", b_.getTypeArrayAttr(ft.getInputs()));
    // ABI verification may accept null only for maybe_ref arguments checked by callees.
    SmallVector<bool> nullable;
    for (Type t : ft.getInputs())
      nullable.push_back(isa<MaybeRefType>(t));
    func_->setAttr("bpfabi.nullable_args", b_.getDenseBoolArrayAttr(nullable));
    // Global borrowed args receive arg:nonnull. BTF DECL_TAG and semantic
    // argtag requirements share this decision. Static tags are omitted because
    // kernel ignores them.
    SmallVector<bool> nonnull;
    for (Type t : ft.getInputs())
      nonnull.push_back(isa<BorrowedType>(t) && sub_.getLinkage() == "global");
    func_->setAttr("bpfabi.nonnull_args", b_.getDenseBoolArrayAttr(nonnull));
  }
  entry_ = func_.addEntryBlock(b_);
  Block &srcEntry = sub_.getBody().front();
  unsigned nIn = ft.getNumInputs();
  for (unsigned i = 0; i < nIn; ++i)
    bind(srcEntry.getArgument(i), entry_->getArgument(i));
  if (failed(bindMaps(sub_.getMapSymbolsAttr(), srcEntry.getArguments().drop_front(nIn), loc)))
    return failure();
  return convertBody(sub_.getBody());
}

// Helper-loop callbacks are internal (i64 index,ptr ctx)->i64. Caller stack
// context contains eight-byte carried-value slots then captured integers.
// Read/truncate at entry, write back at return, and return a constant.
// Static-subprogram/callback markers carry reachability and BTF signature intent.
LogicalResult ProgramLowering::runCallback() {
  Location loc = cb_.getLoc();
  Type i64 = b_.getI64Type();
  // for_each callback uses map/key/value/ctx pointers in r1..r4; bpf_loop
  // uses index/ctx. Both share carried-then-captured context slot order.
  bool forEach = cb_.getForEach();
  bool findVma = cb_.getFindVma(); // (task, vma, ctx) in r1..r3.
  auto fnTy = findVma ? LLVM::LLVMFunctionType::get(i64, {ctx_.ptrTy(), ctx_.ptrTy(), ctx_.ptrTy()}) : forEach ? LLVM::LLVMFunctionType::get(i64, {ctx_.ptrTy(), ctx_.ptrTy(), ctx_.ptrTy(), ctx_.ptrTy()})
                      : LLVM::LLVMFunctionType::get(i64, {i64, ctx_.ptrTy()});
  {
    OpBuilder::InsertionGuard g(b_);
    b_.setInsertionPoint(cb_);
    func_ = LLVM::LLVMFuncOp::create(b_, loc, cb_.getSymName(), fnTy, LLVM::Linkage::Internal);
    func_.setNoInline(true);
    func_->setAttr("bpfabi.subprogram", b_.getStringAttr("static"));
    func_->setAttr(findVma ? "bpfabi.find_vma_callback" : forEach ? "bpfabi.foreach_callback" : "bpfabi.callback", b_.getUnitAttr());
  }
  entry_ = func_.addEntryBlock(b_);
  Block &srcEntry = cb_.getBody().front();
  b_.setInsertionPointToStart(entry_);
  int64_t lead = (forEach || findVma) ? 2 : 1;
  Value ctxBase = entry_->getArgument(findVma ? 2 : forEach ? 3 : 1);
  if (findVma) {
    // The kernel passes the task (r1) and the vma (r2) as BTF pointers; the body reads them only through kfield.load.
    bind(srcEntry.getArgument(0), entry_->getArgument(0));
    bind(srcEntry.getArgument(1), entry_->getArgument(1));
  } else if (forEach) {
    // Read keys at declared width from read-only PTR_TO_MAP_KEY; values remain borrowed PTR_TO_MAP_VALUE.
    Type kt = srcEntry.getArgument(0).getType();
    unsigned kw = cast<IntegerType>(kt).getWidth() / 8;
    bind(srcEntry.getArgument(0), LLVM::LoadOp::create(b_, loc, kt, entry_->getArgument(1), kw));
    bind(srcEntry.getArgument(1), entry_->getArgument(2));
  } else {
    bind(srcEntry.getArgument(0),
         LLVM::TruncOp::create(b_, loc, b_.getI32Type(), entry_->getArgument(0)));
  }
  int64_t slots = cb_.getNumCarried() + cb_.getNumCaptured();
  for (int64_t k = 0; k < slots; ++k) {
    BlockArgument a = srcEntry.getArgument(lead + k);
    Value v = LLVM::LoadOp::create(b_, loc, i64, ctxSlot(ctxBase, k, loc), 8);
    if (a.getType() != i64)
      v = LLVM::TruncOp::create(b_, loc, a.getType(), v);
    bind(a, v);
  }
  if (failed(bindMaps(cb_.getMapSymbols(), srcEntry.getArguments().drop_front(lead + slots), loc)))
    return failure();
  return convertBody(cb_.getBody());
}

// Timer callbacks are internal (ptr map,key,value)->i32, matching
// set_timer_callback_state r1/r2/r3 and C int return. timer.done returns zero.
// The static marker supplies reachability via set_callback addressof; the
// timer marker carries map/record BTF signature information.
LogicalResult ProgramLowering::runTimerCallback() {
  Location loc = tcb_.getLoc();
  auto fnTy = LLVM::LLVMFunctionType::get(b_.getI32Type(), {ctx_.ptrTy(), ctx_.ptrTy(), ctx_.ptrTy()});
  {
    OpBuilder::InsertionGuard g(b_);
    b_.setInsertionPoint(tcb_);
    func_ = LLVM::LLVMFuncOp::create(b_, loc, tcb_.getSymName(), fnTy, LLVM::Linkage::Internal);
    func_.setNoInline(true);
    func_->setAttr("bpfabi.subprogram", b_.getStringAttr("static"));
    func_->setAttr("bpfabi.timer_callback", b_.getArrayAttr({tcb_.getMapAttr(), tcb_.getRecordAttr()}));
  }
  entry_ = func_.addEntryBlock(b_);
  bind(tcb_.getBody().front().getArgument(0), entry_->getArgument(2));
  return convertBody(tcb_.getBody());
}

// User-ring drain callbacks are internal (ptr dynptr,ptr ctx)->i64 with
// r1 CONST_PTR_TO_DYNPTR, r2 null drain context and return range 0..1. Static
// and user-ring callback markers carry reachability and BTF argument shape.
LogicalResult ProgramLowering::runUserRingbufCallback() {
  Location loc = ucb_.getLoc();
  auto fnTy = LLVM::LLVMFunctionType::get(b_.getI64Type(), {ctx_.ptrTy(), ctx_.ptrTy()});
  {
    OpBuilder::InsertionGuard g(b_);
    b_.setInsertionPoint(ucb_);
    func_ = LLVM::LLVMFuncOp::create(b_, loc, ucb_.getSymName(), fnTy, LLVM::Linkage::Internal);
    func_.setNoInline(true);
    func_->setAttr("bpfabi.subprogram", b_.getStringAttr("static"));
    func_->setAttr("bpfabi.user_ringbuf_callback", b_.getUnitAttr());
  }
  entry_ = func_.addEntryBlock(b_);
  bind(ucb_.getBody().front().getArgument(0), entry_->getArgument(0));
  return convertBody(ucb_.getBody());
}

Value ProgramLowering::ctxSlot(Value base, int64_t k, Location loc) {
  if (k == 0)
    return base;
  return LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI64Type(), base,
                             ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(k)});
}

// Replace map arguments with global addressof relocations.
LogicalResult ProgramLowering::bindMaps(ArrayAttr syms, Block::BlockArgListType args,
                                        Location loc) {
  b_.setInsertionPointToStart(entry_);
  for (auto [i, arg] : llvm::enumerate(args)) {
    auto flat = cast<FlatSymbolRefAttr>(syms[i]);
    auto global = ctx_.mapGlobal(flat.getValue(), loc);
    if (!global)
      return failure();
    Value addr = LLVM::AddressOfOp::create(b_, loc, global);
    bind(arg, addr);
  }
  return success();
}

LogicalResult ProgramLowering::convertBody(Region &body) {
  Block &srcEntry = body.front();
  // Create blocks in original order before converting forward branches.
  // Packet-load checks split immediately after the current block, retaining
  // the established single-stage lowering order.
  blocks_[&srcEntry] = entry_;
  for (Block &src : llvm::drop_begin(body)) {
    auto *dst = new Block();
    func_.getBody().push_back(dst);
    for (BlockArgument a : src.getArguments()) {
      // the in-range block's window has no LLVM block argument — the
      // arena.check_br lowering binds it to bpfabi.arena_addr at the block's
      // entry (the address is made only on the true edge).
      if (isa<ArenaWindowType>(a.getType()))
        continue;
      bind(a, dst->addArgument(convertType(a.getType()), a.getLoc()));
    }
    blocks_[&src] = dst;
  }

  for (Block &src : body) {
    b_.setInsertionPointToEnd(blocks_[&src]);
    for (Operation &op : src)
      if ((ctx_.currentOp = &op), failed(convertOp(op)))
        return failure();
  }
  owner_->erase();
  return success();
}

LogicalResult ProgramLowering::convertOp(Operation &op) {
  Location loc = op.getLoc();

  if (isa<SockRefCheckOp, RefCheckOp, RingbufIfReservedOp, MapAtomicAddOp, YieldOp, LoopOp, LoopYieldOp, IfOp,
              IfYieldOp, BreakOp, ContinueOp, PacketCheckOp, MetaCheckOp, ArenaCheckOp, VerdictIfOp, TaskFindVmaOp, TaskFindVmaYieldOp>(op))
    return op.emitOpError() << "is a stage ① op; run ebpf-expand-regions "
                               "before convert-ebpf-to-bpfabi";

  if (auto verdict = dyn_cast<VerdictOp>(op)) {
    auto v = bpfabi::lookupVerdictValue(prog_.getKind(), attachRowFor(prog_), verdict.getAction()); // Verdict family comes from the attachment row.
    if (!v)
      return verdict.emitOpError() << "verdict \"" << verdict.getAction()
                                   << "\" is not in the UAPI table";
    bpfabi::ReturnOp::create(b_, loc, b_.getStringAttr(prog_.getKind()),
                             verdict.getActionAttr(),
                             b_.getI32IntegerAttr(*v));
    return success();
  }

  // Direct BPF-to-BPF calls use llvm.call, distinct from ABI helper calls.
  if (auto call = dyn_cast<CallOp>(op)) {
    auto c = LLVM::CallOp::create(b_, loc, call.getResultTypes(),
                                  call.getCalleeAttr(), remapAll(call.getArgs()));
    for (auto [r, n] : llvm::zip(call.getResults(), c.getResults()))
      bind(r, n);
    return success();
  }
  // Callback returns write carried values as eight-byte slots and return constant zero/one.
  if (auto cr = dyn_cast<CallbackReturnOp>(op)) {
    Value base = func_.getArgument(cb_ && cb_.getFindVma() ? 2 : cb_ && cb_.getForEach() ? 3 : 1); // for_each context is argument four; find_vma's is argument three.
    for (auto [k, v] : llvm::enumerate(cr.getValues())) {
      Value w = remap(v);
      if (w.getType() != b_.getI64Type())
        w = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), w);
      LLVM::StoreOp::create(b_, loc, w, ctxSlot(base, k, loc), 8);
    }
    Value r = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(cr.getStop()));
    LLVM::ReturnOp::create(b_, loc, r);
    return success();
  }
  // bpf_loop(count,&callback,&context,0) uses fully initialized caller-stack
  // i64 slots. Ignore helper return (including possible negative status);
  // read resulting state only from context, never reinterpret errors as counts.
  if (auto bl = dyn_cast<BpfLoopOp>(op)) {
    Type i64 = b_.getI64Type();
    int64_t slots = bl.getInits().size() + bl.getCaptures().size();
    Value base = allocaFor(LLVM::LLVMArrayType::get(i64, std::max<int64_t>(slots, 1)), loc);
    int64_t k = 0;
    for (ValueRange vs : {ValueRange(bl.getInits()), ValueRange(bl.getCaptures())})
      for (Value v : vs) {
        Value w = remap(v);
        if (w.getType() != i64)
          w = LLVM::ZExtOp::create(b_, loc, i64, w);
        LLVM::StoreOp::create(b_, loc, w, ctxSlot(base, k++, loc), 8);
      }
    if (slots == 0)
      LLVM::StoreOp::create(b_, loc, LLVM::ConstantOp::create(b_, loc, i64, b_.getI64IntegerAttr(0)),
                            base, 8);
    Value count = LLVM::ZExtOp::create(b_, loc, i64, remap(bl.getCount()));
    Value fn = LLVM::AddressOfOp::create(b_, loc, ctx_.ptrTy(), bl.getCallback());
    Value flags = LLVM::ConstantOp::create(b_, loc, i64, b_.getI64IntegerAttr(0));
    if (failed(ctx_.helperCall(b_, loc, "loop", {count, fn, base, flags})))
      return failure();
    for (auto [k, r] : llvm::enumerate(bl.getResults())) {
      Value v = LLVM::LoadOp::create(b_, loc, i64, ctxSlot(base, k, loc), 8);
      if (r.getType() != i64)
        v = LLVM::TruncOp::create(b_, loc, r.getType(), v);
      bind(r, v);
    }
    return success();
  }

  // for_each_map_elem uses the same stack context and returns visited element
  // count plus carried values read back from that context.
  if (auto fe = dyn_cast<ForEachMapElemOp>(op)) {
    Type i64 = b_.getI64Type();
    int64_t slots = fe.getInits().size() + fe.getCaptures().size();
    Value base = allocaFor(LLVM::LLVMArrayType::get(i64, std::max<int64_t>(slots, 1)), loc);
    int64_t k = 0;
    for (ValueRange vs : {ValueRange(fe.getInits()), ValueRange(fe.getCaptures())})
      for (Value v : vs) {
        Value w = remap(v);
        if (w.getType() != i64)
          w = LLVM::ZExtOp::create(b_, loc, i64, w);
        LLVM::StoreOp::create(b_, loc, w, ctxSlot(base, k++, loc), 8);
      }
    if (slots == 0)
      LLVM::StoreOp::create(b_, loc, LLVM::ConstantOp::create(b_, loc, i64, b_.getI64IntegerAttr(0)), base, 8);
    Value fn = LLVM::AddressOfOp::create(b_, loc, ctx_.ptrTy(), fe.getCallback());
    Value flags = LLVM::ConstantOp::create(b_, loc, i64, b_.getI64IntegerAttr(0));
    FailureOr<Value> n = ctx_.helperCall(b_, loc, "for_each_map_elem", {remap(fe.getMap()), fn, base, flags});
    if (failed(n))
      return failure();
    bind(fe.getCount(), *n);
    for (auto [k, r] : llvm::enumerate(fe.getResults())) {
      Value v = LLVM::LoadOp::create(b_, loc, i64, ctxSlot(base, k, loc), 8);
      if (r.getType() != i64)
        v = LLVM::TruncOp::create(b_, loc, r.getType(), v);
      bind(r, v);
    }
    return success();
  }

  // bpf_find_vma(task, addr, &callback, &context, 0). The same
  // caller-stack context as bpf_loop; the status is the raw helper result and
  // the carried values are read back from the context (unchanged when the
  // callback did not run).
  if (auto fv = dyn_cast<FindVmaCallOp>(op)) {
    Type i64 = b_.getI64Type();
    int64_t slots = fv.getInits().size() + fv.getCaptures().size();
    Value base = allocaFor(LLVM::LLVMArrayType::get(i64, std::max<int64_t>(slots, 1)), loc);
    int64_t k = 0;
    for (ValueRange vs : {ValueRange(fv.getInits()), ValueRange(fv.getCaptures())})
      for (Value v : vs) {
        Value w = remap(v);
        if (w.getType() != i64)
          w = LLVM::ZExtOp::create(b_, loc, i64, w);
        LLVM::StoreOp::create(b_, loc, w, ctxSlot(base, k++, loc), 8);
      }
    if (slots == 0)
      LLVM::StoreOp::create(b_, loc, LLVM::ConstantOp::create(b_, loc, i64, b_.getI64IntegerAttr(0)), base, 8);
    Value fn = LLVM::AddressOfOp::create(b_, loc, ctx_.ptrTy(), fv.getCallback());
    Value flags = LLVM::ConstantOp::create(b_, loc, i64, b_.getI64IntegerAttr(0));
    FailureOr<Value> st = ctx_.helperCall(b_, loc, "find_vma", {remap(fv.getTask()), remap(fv.getAddr()), fn, base, flags});
    if (failed(st))
      return failure();
    bind(fv.getStatus(), *st);
    for (auto [k, r] : llvm::enumerate(fv.getResults())) {
      Value v = LLVM::LoadOp::create(b_, loc, i64, ctxSlot(base, k, loc), 8);
      if (r.getType() != i64)
        v = LLVM::TruncOp::create(b_, loc, r.getType(), v);
      bind(r, v);
    }
    return success();
  }

  // Return verified func or attachment-enabled program integers unchanged.
  if (auto ret = dyn_cast<ReturnOp>(op)) {
    LLVM::ReturnOp::create(b_, loc, remap(ret.getValue()));
    return success();
  }

  if (auto br = dyn_cast<cf::BranchOp>(op)) {
    LLVM::BrOp::create(b_, loc, remapAll(br.getDestOperands()),
                       blocks_[br.getDest()]);
    return success();
  }

  // Return raw adjust_head status. Later checks/loads reload data/data_end
  // from ctx rather than reuse invalidated packet pointers.
  if (auto ah = dyn_cast<XdpAdjustHeadOp>(op)) {
    Value delta = LLVM::SExtOp::create(b_, loc, b_.getI64Type(), remap(ah.getDelta()));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "xdp_adjust_head", {remap(ah.getCtx()), delta});
    if (failed(r))
      return failure();
    bind(ah.getStatus(), *r);
    return success();
  }

  // adjust_meta returns raw status; it only moves data_meta and invalidates packet pointers.
  if (auto am = dyn_cast<XdpAdjustMetaOp>(op)) {
    Value delta = LLVM::SExtOp::create(b_, loc, b_.getI64Type(), remap(am.getDelta()));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "xdp_adjust_meta", {remap(am.getCtx()), delta});
    if (failed(r))
      return failure();
    bind(am.getStatus(), *r);
    return success();
  }

  // adjust_tail likewise returns raw status and requires fresh packet bounds afterward.
  if (auto at = dyn_cast<XdpAdjustTailOp>(op)) {
    Value delta = LLVM::SExtOp::create(b_, loc, b_.getI64Type(), remap(at.getDelta()));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "xdp_adjust_tail", {remap(at.getCtx()), delta});
    if (failed(r))
      return failure();
    bind(at.getStatus(), *r);
    return success();
  }

  // seg6 helpers return raw status with stack-record data/param and record
  // length. All invalidate packet pointers; later accesses reload from ctx.
  if (auto sb = dyn_cast<LwtSeg6StoreBytesOp>(op)) {
    Value off = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(sb.getOffset()));
    Value len = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(cast<RecordType>(sb.getRecord().getType()).getSize()));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "lwt_seg6_store_bytes", {remap(sb.getCtx()), off, remap(sb.getRecord()), len});
    if (failed(r))
      return failure();
    bind(sb.getStatus(), *r);
    return success();
  }
  if (auto as = dyn_cast<LwtSeg6AdjustSrhOp>(op)) {
    Value off = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(as.getOffset()));
    Value delta = LLVM::SExtOp::create(b_, loc, b_.getI64Type(), remap(as.getDelta()));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "lwt_seg6_adjust_srh", {remap(as.getCtx()), off, delta});
    if (failed(r))
      return failure();
    bind(as.getStatus(), *r);
    return success();
  }
  // sk_msg helper arguments zero-extend u32. pull/pop flags are zero
  // (kernel rejects others with -EINVAL); return raw status.
  if (isa<MsgApplyBytesOp, MsgCorkBytesOp>(op)) {
    bool apply = isa<MsgApplyBytesOp>(op);
    Value ctxV = apply ? cast<MsgApplyBytesOp>(op).getCtx() : cast<MsgCorkBytesOp>(op).getCtx();
    Value n = apply ? cast<MsgApplyBytesOp>(op).getBytes() : cast<MsgCorkBytesOp>(op).getBytes();
    Value n64 = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(n));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, apply ? "msg_apply_bytes" : "msg_cork_bytes", {remap(ctxV), n64});
    if (failed(r))
      return failure();
    bind(op.getResult(0), *r);
    return success();
  }
  if (isa<MsgPullDataOp, MsgPopDataOp>(op)) {
    bool pull = isa<MsgPullDataOp>(op);
    Value ctxV = pull ? cast<MsgPullDataOp>(op).getCtx() : cast<MsgPopDataOp>(op).getCtx();
    Value a = pull ? cast<MsgPullDataOp>(op).getStart() : cast<MsgPopDataOp>(op).getStart();
    Value bv = pull ? cast<MsgPullDataOp>(op).getEnd() : cast<MsgPopDataOp>(op).getLen();
    Value a64 = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(a));
    Value b64 = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(bv));
    Value zero = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(0));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, pull ? "msg_pull_data" : "msg_pop_data", {remap(ctxV), a64, b64, zero});
    if (failed(r))
      return failure();
    bind(op.getResult(0), *r);
    return success();
  }
  if (auto sa = dyn_cast<LwtSeg6ActionOp>(op)) {
    std::optional<int64_t> act = bpfabi::lookupSeg6Action(sa.getAction());
    if (!act)
      return sa.emitOpError() << "seg6local action \"" << sa.getAction() << "\" is not in the UAPI table (seg6action)";
    Value a = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(*act));
    Value len = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(cast<RecordType>(sa.getParam().getType()).getSize()));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "lwt_seg6_action", {remap(sa.getCtx()), a, remap(sa.getParam()), len});
    if (failed(r))
      return failure();
    bind(sa.getStatus(), *r);
    return success();
  }

  if (auto cr = dyn_cast<CloneRedirectOp>(op)) {
    auto ingress = bpfabi::lookupRedirFlag("ingress");
    if (!ingress)
      return cr.emitOpError("ingress flag missing from UAPI table");
    Value ifx = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(cr.getIfindex()));
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(),
                                         b_.getI64IntegerAttr(cr.getFlags() == "ingress" ? *ingress : 0));
    auto r = ctx_.helperCall(b_, loc, "clone_redirect", {remap(cr.getCtx()), ifx, flags});
    if (failed(r))
      return failure();
    bind(cr.getStatus(), *r);
    return success();
  }
  if (isa<SkbLoadBytesOp, XdpLoadBytesOp, SkbLoadBytesRelativeOp>(op)) {
    // xdp.load_bytes shares skb.load_bytes' shape (helper 189).
    struct {
      Value ctx, offset, value, status;
      int64_t len;
      StringRef helper;
    } load;
    if (auto l = dyn_cast<SkbLoadBytesOp>(op))
      load = {l.getCtx(), l.getOffset(), l.getValue(), l.getStatus(), static_cast<int64_t>(l.getLen()), "skb_load_bytes"};
    else if (auto l = dyn_cast<SkbLoadBytesRelativeOp>(op))
      load = {l.getCtx(), l.getOffset(), l.getValue(), l.getStatus(), static_cast<int64_t>(l.getLen()), "skb_load_bytes_relative"};
    else {
      auto x = cast<XdpLoadBytesOp>(op);
      load = {x.getCtx(), x.getOffset(), x.getValue(), x.getStatus(), static_cast<int64_t>(x.getLen()), "xdp_load_bytes"};
    }
    auto i8 = b_.getI8Type();
    auto i64 = b_.getI64Type();
    Value slot = allocaFor(LLVM::LLVMArrayType::get(i8, 8), loc);
    Value zero8 = LLVM::ConstantOp::create(b_, loc, i8, b_.getI8IntegerAttr(0));
    for (int32_t i = 0; i < 8; ++i) {
      Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), i8, slot,
                                     ArrayRef<LLVM::GEPArg>{i});
      LLVM::StoreOp::create(b_, loc, zero8, at, 1);
    }
    Value off = LLVM::ZExtOp::create(b_, loc, i64, remap(load.offset));
    Value len = LLVM::ConstantOp::create(b_, loc, i64,
                                         b_.getI64IntegerAttr(load.len));
    SmallVector<Value> args{remap(load.ctx), off, slot, len};
    if (auto relative = dyn_cast<SkbLoadBytesRelativeOp>(op)) {
      auto start = bpfabi::lookupHeaderStart(relative.getStart());
      if (!start) return relative.emitOpError("header selector missing from UAPI");
      args.push_back(LLVM::ConstantOp::create(b_, loc, i64, b_.getI64IntegerAttr(*start)));
    }
    auto status = ctx_.helperCall(b_, loc, load.helper, args);
    if (failed(status))
      return failure();
    Value value =
        LLVM::ConstantOp::create(b_, loc, i64, b_.getI64IntegerAttr(0));
    for (int32_t i = 0; i < load.len; ++i) {
      Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), i8, slot,
                                     ArrayRef<LLVM::GEPArg>{i});
      Value byte = LLVM::LoadOp::create(b_, loc, i8, at, 1);
      byte = LLVM::ZExtOp::create(b_, loc, i64, byte);
      if (i) {
        Value shift =
            LLVM::ConstantOp::create(b_, loc, i64, b_.getI64IntegerAttr(8 * i));
        byte = LLVM::ShlOp::create(b_, loc, byte, shift);
      }
      value = LLVM::OrOp::create(b_, loc, value, byte);
    }
    bind(load.value, value);
    bind(load.status, *status);
    return success();
  }
  if (auto adjust = dyn_cast<SkbAdjustRoomOp>(op)) {
    Value delta = LLVM::SExtOp::create(b_, loc, b_.getI64Type(),
                                       remap(adjust.getDelta()));
    Value zero = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(),
                                          b_.getI64IntegerAttr(0));
    Value mode = zero;
    if (cast<ContextType>(adjust.getCtx().getType()).getKind() == "sched_cls") {
      // sched_cls mode word (default net) from the UAPI adjroommode rows.
      auto m = bpfabi::lookupAdjRoomMode(adjust.getRoomMode().value_or("net"));
      if (!m)
        return adjust.emitOpError("room mode missing from UAPI table");
      mode = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(*m));
    }
    auto status = ctx_.helperCall(b_, loc, "skb_adjust_room",
                                  {remap(adjust.getCtx()), delta, mode, zero});
    if (failed(status))
      return failure();
    bind(adjust.getStatus(), *status);
    return success();
  }
  if (auto trace = dyn_cast<TracePrintkOp>(op)) {
    auto global = ctx_.traceFormat(trace.getFormat(), loc);
    if (!global)
      return failure();
    Value addr =
        LLVM::AddressOfOp::create(b_, loc, ctx_.ptrTy(), global.getSymName());
    Value size = LLVM::ConstantOp::create(
        b_, loc, b_.getI64Type(),
        b_.getI64IntegerAttr(trace.getFormat().size() + 1));
    SmallVector<Value> args{addr, size};
    std::string error;
    auto spec = bpfmlir::parseTraceFormat(trace.getFormat(), error);
    if (!spec)
      return trace.emitOpError(error);
    // the slots follow the format's conversion order — a %s takes the
    // next strs literal (a .rodata string's address as i64), an integer the
    // next $args value.
    ArrayAttr strs = trace.getStrsAttr();
    unsigned nextStr = 0;
    auto nextArg = trace.getArgs().begin();
    for (const bpfmlir::TraceFormatArg &fmt : *spec) {
      if (fmt.isString) {
        if (!strs || nextStr >= strs.size())
          return trace.emitOpError("has fewer strs than %s conversions (the op verifier checks it)");
        auto lit = ctx_.traceStrLiteral(cast<StringAttr>(strs[nextStr++]).getValue(), loc);
        if (!lit)
          return failure();
        Value p = LLVM::AddressOfOp::create(b_, loc, ctx_.ptrTy(), lit.getSymName());
        args.push_back(LLVM::PtrToIntOp::create(b_, loc, b_.getI64Type(), p));
        continue;
      }
      if (nextArg == trace.getArgs().end())
        return trace.emitOpError("has fewer arguments than integer conversions (the op verifier checks it)");
      Value v = remap(*nextArg++);
      if (fmt.bits == 32) {
        if (fmt.isSigned)
          v = LLVM::SExtOp::create(b_, loc, b_.getI64Type(), v);
        else
          v = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), v);
      }
      args.push_back(v);
    }
    while (args.size() < 5)
      args.push_back(LLVM::ConstantOp::create(b_, loc, b_.getI64Type(),
                                              b_.getI64IntegerAttr(0)));
    auto status = ctx_.helperCall(b_, loc, "trace_printk", args);
    if (failed(status))
      return failure();
    bind(trace.getStatus(), *status);
    return success();
  }
  if (isa<SkbStoreBytesOp, XdpStoreBytesOp>(op)) {
    // xdp.store_bytes shares the stack shape; helper 190 has no flags.
    auto skbStore = dyn_cast<SkbStoreBytesOp>(op);
    auto xdpStore = dyn_cast<XdpStoreBytesOp>(op);
    struct {
      Value ctx, offset, value, status;
      int64_t len;
    } sb = skbStore ? decltype(sb){skbStore.getCtx(), skbStore.getOffset(), skbStore.getValue(), skbStore.getStatus(),
                                   static_cast<int64_t>(skbStore.getLen())}
                    : decltype(sb){xdpStore.getCtx(), xdpStore.getOffset(), xdpStore.getValue(), xdpStore.getStatus(),
                                   static_cast<int64_t>(xdpStore.getLen())};
    auto i8 = b_.getI8Type();
    Value slot = allocaFor(LLVM::LLVMArrayType::get(i8, sb.len), loc);
    Value v = remap(sb.value);
    for (int64_t i = 0; i < sb.len; ++i) {
      Value byte = v;
      if (i) {
        Value shift = LLVM::ConstantOp::create(b_, loc, v.getType(), b_.getIntegerAttr(v.getType(), i * 8));
        byte = LLVM::LShrOp::create(b_, loc, v, shift);
      }
      if (byte.getType() != i8)
        byte = LLVM::TruncOp::create(b_, loc, i8, byte);
      Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), i8, slot,
                                     ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(i)});
      LLVM::StoreOp::create(b_, loc, byte, at, 1);
    }
    Value off = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(sb.offset));
    Value len = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(sb.len));
    FailureOr<Value> r;
    if (xdpStore)
      r = ctx_.helperCall(b_, loc, "xdp_store_bytes", {remap(sb.ctx), off, slot, len});
    else {
      Value zero = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(0));
      r = ctx_.helperCall(b_, loc, "skb_store_bytes", {remap(sb.ctx), off, slot, len, zero});
    }
    if (failed(r))
      return failure();
    bind(sb.status, *r);
    return success();
  }
  if (auto cs = dyn_cast<L3CsumReplaceOp>(op)) {
    Value off = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(cs.getOffset()));
    Value zero = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(0));
    auto r = ctx_.helperCall(b_, loc, "l3_csum_replace", {remap(cs.getCtx()), off, zero, remap(cs.getDiff()), zero});
    if (failed(r))
      return failure();
    bind(cs.getStatus(), *r);
    return success();
  }
  // difference mode (from 0, field size 0); flags OR the UAPI csumflag rows.
  if (auto cs = dyn_cast<L4CsumReplaceOp>(op)) {
    int64_t flag = 0;
    for (auto [on, name] : {std::pair<bool, StringRef>{cs.getPseudoHdr(), "pseudo_hdr"},
                            std::pair<bool, StringRef>{cs.getMarkMangled_0(), "mark_mangled_0"}}) {
      if (!on)
        continue;
      auto v = bpfabi::lookupCsumFlag(name);
      if (!v)
        return cs.emitOpError() << "csum flag " << name << " missing from UAPI table";
      flag |= *v;
    }
    Value off = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(cs.getOffset()));
    Value zero = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(0));
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(flag));
    auto r = ctx_.helperCall(b_, loc, "l4_csum_replace", {remap(cs.getCtx()), off, zero, remap(cs.getDiff()), flags});
    if (failed(r))
      return failure();
    bind(cs.getStatus(), *r);
    return success();
  }
  if (auto vlan = dyn_cast<SkbVlanPushOp>(op)) {
    Value proto = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(vlan.getProto()));
    Value tci = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(vlan.getTci()));
    auto status = ctx_.helperCall(b_, loc, "skb_vlan_push", {remap(vlan.getCtx()), proto, tci});
    if (failed(status)) return failure();
    bind(vlan.getStatus(), *status);
    return success();
  }
  if (auto mtu = dyn_cast<SkbCheckMtuOp>(op)) {
    Value slot;
    {
      OpBuilder::InsertionGuard guard(b_);
      b_.setInsertionPointToStart(entry_);
      Value one = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(1));
      slot = LLVM::AllocaOp::create(b_, loc, ctx_.ptrTy(), b_.getI32Type(), one, /*alignment=*/4);
    }
    LLVM::StoreOp::create(b_, loc, remap(mtu.getMtuIn()), slot, 4);
    Value index = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(mtu.getIfindex()));
    Value delta = LLVM::SExtOp::create(b_, loc, b_.getI64Type(), remap(mtu.getLenDiff()));
    Value zero = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(0));
    auto status = ctx_.helperCall(b_, loc, "check_mtu", {remap(mtu.getCtx()), index, slot, delta, zero});
    if (failed(status)) return failure();
    bind(mtu.getMtuOut(), LLVM::LoadOp::create(b_, loc, b_.getI32Type(), slot, 4));
    bind(mtu.getStatus(), *status);
    return success();
  }
  if (auto level = dyn_cast<SkbCsumLevelOp>(op)) {
    auto mode = bpfabi::lookupCsumLevel(level.getMode());
    if (!mode) return level.emitOpError("checksum selector missing from UAPI");
    Value selector = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(*mode));
    auto status = ctx_.helperCall(b_, loc, "csum_level", {remap(level.getCtx()), selector});
    if (failed(status)) return failure();
    bind(level.getStatus(), *status);
    return success();
  }
  // (ctx, zext integer[, 0]) helpers and (ctx) helpers.
  {
    StringRef helper;
    Value arg;
    bool zeroFlags = false;
    if (auto x = dyn_cast<SkbPullDataOp>(op))
      helper = "skb_pull_data", arg = x.getLen();
    else if (auto x = dyn_cast<SkbChangeTailOp>(op))
      helper = "skb_change_tail", arg = x.getLen(), zeroFlags = true;
    else if (auto x = dyn_cast<SkbChangeHeadOp>(op))
      helper = "skb_change_head", arg = x.getLen(), zeroFlags = true;
    else if (auto x = dyn_cast<SkbChangeProtoOp>(op))
      helper = "skb_change_proto", arg = x.getProto(), zeroFlags = true;
    else if (auto x = dyn_cast<SkbChangeTypeOp>(op))
      helper = "skb_change_type", arg = x.getPktType();
    else if (auto x = dyn_cast<CsumUpdateOp>(op))
      helper = "csum_update", arg = x.getCsum();
    else if (isa<SkbHashRecalcOp>(op))
      helper = "get_hash_recalc";
    else if (isa<SkbCgroupClassidOp>(op))
      helper = "get_cgroup_classid";
    else if (isa<SkbNetnsCookieOp>(op))
      helper = "get_netns_cookie";
    else if (isa<XdpBuffLenOp>(op))
      helper = "xdp_get_buff_len";
    else if (auto x = dyn_cast<SkbSetHashOp>(op))
      helper = "set_hash", arg = x.getHash();
    else if (isa<SkbSetHashInvalidOp>(op))
      helper = "set_hash_invalid";
    else if (isa<SkbVlanPopOp>(op))
      helper = "skb_vlan_pop";
    else if (isa<SkbEcnSetCeOp>(op))
      helper = "skb_ecn_set_ce";
    if (!helper.empty()) {
      SmallVector<Value> args{remap(op.getOperand(0))};
      if (arg)
        args.push_back(LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(arg)));
      if (zeroFlags)
        args.push_back(LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(0)));
      auto r = ctx_.helperCall(b_, loc, helper, args);
      if (failed(r))
        return failure();
      if (op.getNumResults())
        bind(op.getResult(0), *r);
      return success();
    }
  }
  // the kernel argument is a signed int, so level and flags are
  // sign-extended (not the zext of the block above).
  if (isa<SkbSocketUidOp>(op)) {
    auto r = ctx_.helperCall(b_, loc, "get_socket_uid", {remap(op.getOperand(0))});
    if (failed(r))
      return failure();
    bind(op.getResult(0), LLVM::TruncOp::create(b_, loc, b_.getI32Type(), *r));
    return success();
  }
  {
    StringRef helper;
    Value arg;
    if (isa<SkbCgroupIdOp>(op))
      helper = "skb_cgroup_id";
    else if (auto x = dyn_cast<SkbAncestorCgroupIdOp>(op))
      helper = "skb_ancestor_cgroup_id", arg = x.getLevel();
    else if (auto x = dyn_cast<SockOpsCbFlagsSetOp>(op))
      helper = "sock_ops_cb_flags_set", arg = x.getFlags();
    if (!helper.empty()) {
      SmallVector<Value> args{remap(op.getOperand(0))};
      if (arg)
        args.push_back(LLVM::SExtOp::create(b_, loc, b_.getI64Type(), remap(arg)));
      auto r = ctx_.helperCall(b_, loc, helper, args);
      if (failed(r))
        return failure();
      bind(op.getResult(0), *r);
      return success();
    }
  }
  // each present value gets its own fully written 4 / 8-byte stack slot
  // before the call; an absent side is NULL with size 0.
  if (auto cd = dyn_cast<CsumDiffOp>(op)) {
    SmallVector<Value> args;
    for (Value v : {cd.getFrom(), cd.getTo()}) {
      if (!v) {
        args.push_back(LLVM::ZeroOp::create(b_, loc, ctx_.ptrTy()));
        args.push_back(LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(0)));
        continue;
      }
      unsigned bytes = cast<IntegerType>(v.getType()).getWidth() / 8;
      Value slot = allocaFor(v.getType(), loc);
      LLVM::StoreOp::create(b_, loc, remap(v), slot, 4);
      args.push_back(slot);
      args.push_back(LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(bytes)));
    }
    args.push_back(LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(cd.getSeed())));
    auto r = ctx_.helperCall(b_, loc, "csum_diff", args);
    if (failed(r))
      return failure();
    bind(cd.getResult(), *r);
    return success();
  }
  // fib_lookup(ctx, params, plen, flags) on a separate 64-byte,
  // 8-aligned stack copy of the record.make input — the helper writes the
  // params in place, so the input record stays unchanged for any other use.
  // plen is the UAPI struct size; flags is 0 or the UAPI fibflag row. The call
  // carries bpfabi.fib_flags for the requirements pass.
  if (auto fl = dyn_cast<FibLookupOp>(op)) {
    std::optional<int64_t> plen = bpfabi::lookupUapiStructSize("bpf_fib_lookup");
    std::optional<int64_t> flag = bpfabi::lookupFibFlag(fl.getFlags());
    if (!plen || !flag)
      return fl.emitOpError() << "bpf_fib_lookup size or fib flag \"" << fl.getFlags()
                              << "\" missing from UAPI table";
    auto rt = cast<RecordType>(fl.getInput().getType());
    if (static_cast<int64_t>(rt.getSize()) != *plen)
      return fl.emitOpError() << "record is " << rt.getSize() << " bytes, struct bpf_fib_lookup is " << *plen;
    Value buf = allocaFor(LLVM::LLVMArrayType::get(b_.getI8Type(), *plen), loc);
    cast<LLVM::AllocaOp>(buf.getDefiningOp()).setAlignment(kRecordStackAlignment);
    Value len = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(*plen));
    auto mc = LLVM::MemcpyOp::create(b_, loc, buf, remap(fl.getInput()), len, /*isVolatile=*/false);
    auto align = [&](unsigned a) {
      return b_.getDictionaryAttr(b_.getNamedAttr(LLVM::LLVMDialect::getAlignAttrName(), b_.getI64IntegerAttr(a)));
    };
    mc.setArgAttrsAttr(b_.getArrayAttr(
        {align(kRecordStackAlignment), align(kRecordStackAlignment), b_.getDictionaryAttr({})}));
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(*flag));
    auto r = ctx_.helperCall(b_, loc, "fib_lookup", {remap(fl.getCtx()), buf, len, flags});
    if (failed(r))
      return failure();
    r->getDefiningOp()->setAttr("bpfabi.fib_flags", b_.getStringAttr(fl.getFlags()));
    bind(fl.getOutput(), buf);
    bind(fl.getStatus(), *r);
    return success();
  }
  // skb_{get,set}_tunnel_key(ctx, buf, size, flags) on a separate
  // 44-byte, 8-aligned stack copy of the record.make input. size is the UAPI
  // struct size (the kernel's compat sizes are not used); flags come from the
  // UAPI tunnelflag rows. get binds the buffer as its output record; set only
  // returns the raw status. No memory attributes (the helper writes / reads the
  // buffer behind the call), and the call stays when the status is unused.
  if (isa<SkbGetTunnelKeyOp, SkbSetTunnelKeyOp>(op)) {
    bool isGet = isa<SkbGetTunnelKeyOp>(op);
    Value ctxV = isGet ? cast<SkbGetTunnelKeyOp>(op).getCtx() : cast<SkbSetTunnelKeyOp>(op).getCtx();
    Value inV = isGet ? cast<SkbGetTunnelKeyOp>(op).getInput() : cast<SkbSetTunnelKeyOp>(op).getKey();
    StringRef flagSpec = isGet ? cast<SkbGetTunnelKeyOp>(op).getFlags() : cast<SkbSetTunnelKeyOp>(op).getFlags();
    std::optional<int64_t> size = bpfabi::lookupUapiStructSize("bpf_tunnel_key");
    std::optional<int64_t> flag = bpfabi::tunnelFlagsValue(flagSpec, !isGet);
    if (!size || !flag)
      return op.emitOpError() << "bpf_tunnel_key size or tunnel flags \"" << flagSpec << "\" missing from UAPI table";
    auto rt = cast<RecordType>(inV.getType());
    if (static_cast<int64_t>(rt.getSize()) != *size)
      return op.emitOpError() << "record is " << rt.getSize() << " bytes, struct bpf_tunnel_key is " << *size;
    Value buf = allocaFor(LLVM::LLVMArrayType::get(b_.getI8Type(), *size), loc);
    cast<LLVM::AllocaOp>(buf.getDefiningOp()).setAlignment(kRecordStackAlignment);
    Value len = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(*size));
    auto mc = LLVM::MemcpyOp::create(b_, loc, buf, remap(inV), len, /*isVolatile=*/false);
    auto align = [&](unsigned a) {
      return b_.getDictionaryAttr(b_.getNamedAttr(LLVM::LLVMDialect::getAlignAttrName(), b_.getI64IntegerAttr(a)));
    };
    mc.setArgAttrsAttr(b_.getArrayAttr(
        {align(kRecordStackAlignment), align(kRecordStackAlignment), b_.getDictionaryAttr({})}));
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(*flag));
    auto r = ctx_.helperCall(b_, loc, isGet ? "skb_get_tunnel_key" : "skb_set_tunnel_key",
                             {remap(ctxV), buf, len, flags});
    if (failed(r))
      return failure();
    if (isGet) {
      bind(cast<SkbGetTunnelKeyOp>(op).getOutput(), buf);
      bind(cast<SkbGetTunnelKeyOp>(op).getStatus(), *r);
    } else {
      bind(cast<SkbSetTunnelKeyOp>(op).getStatus(), *r);
    }
    return success();
  }
  // one leaf of the fib output buffer, read after the call at its
  // @records offset with the declared width.
  if (auto rf = dyn_cast<RecordFieldOp>(op)) {
    auto rt = cast<RecordType>(rf.getRecord().getType());
    FailureOr<int64_t> off = ctx_.recordFieldOffset(&op, rt.getSymbol(), rf.getPath());
    if (failed(off))
      return failure();
    Type t = rf.getValue().getType();
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(rf.getRecord()),
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(*off)});
    Value v = LLVM::LoadOp::create(b_, loc, t, at, provableAlignment(kRecordStackAlignment, *off, t));
    bind(rf.getValue(), v);
    return success();
  }

  // Return the requested action, not delivery success.
  if (auto rd = dyn_cast<RedirectOp>(op)) {
    if (rd.getCond() || !rd.getFallback().empty())
      return rd.emitOpError() << "the `when` form is a stage ① op; run ebpf-expand-regions first";
    Value ifx = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(rd.getIfindex()));
    int64_t flag = 0;
    if (rd.getFlags() && *rd.getFlags() == "ingress") {
      auto ingress = bpfabi::lookupRedirFlag("ingress");
      if (!ingress)
        return rd.emitOpError("ingress flag missing from UAPI table");
      flag = *ingress;
    }
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(flag));
    FailureOr<Value> r;
    // redirect_neigh(ifx, NULL, 0, 0) / redirect_peer(ifx, 0).
    if (rd.getVia() && *rd.getVia() == "neigh")
      r = ctx_.helperCall(b_, loc, "redirect_neigh", {ifx, LLVM::ZeroOp::create(b_, loc, ctx_.ptrTy()), flags, flags});
    else if (rd.getVia() && *rd.getVia() == "peer")
      r = ctx_.helperCall(b_, loc, "redirect_peer", {ifx, flags});
    else
      r = ctx_.helperCall(b_, loc, "redirect", {ifx, flags});
    if (failed(r))
      return failure();
    Value ret = LLVM::TruncOp::create(b_, loc, b_.getI32Type(), *r);
    LLVM::ReturnOp::create(b_, loc, ret);
    return success();
  }

  // Timer helper arg1 is value+@records timer offset. init receives map and
  // ABI monotonic clock; set_callback uses a relocation; start flags are zero.
  // Return raw status.
  if (isa<TimerInitOp, TimerSetCallbackOp, TimerStartOp, TimerCancelOp>(op)) {
    Value ref = op.getOperand(0);
    StringRef field = op.getAttrOfType<StringAttr>("field").getValue();
    auto rt = cast<RecordType>(cast<BorrowedType>(ref.getType()).getPointee());
    FailureOr<int64_t> off = ctx_.specialOffset(&op, rt.getSymbol(), field, "bpf_timer", "timer");
    if (failed(off))
      return failure();
    Type i64 = b_.getI64Type();
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(ref),
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(*off)});
    FailureOr<Value> st;
    if (auto ti = dyn_cast<TimerInitOp>(op)) {
      std::optional<int64_t> clock = bpfabi::lookupClockId(ti.getClock());
      if (!clock)
        return op.emitOpError() << "clock \"" << ti.getClock() << "\" is not in the UAPI table";
      Value c = LLVM::ConstantOp::create(b_, loc, i64, b_.getI64IntegerAttr(*clock));
      st = ctx_.helperCall(b_, loc, "timer_init", {at, remap(ti.getMap()), c});
    } else if (auto sc = dyn_cast<TimerSetCallbackOp>(op)) {
      Value fn = LLVM::AddressOfOp::create(b_, loc, ctx_.ptrTy(), sc.getCallback());
      st = ctx_.helperCall(b_, loc, "timer_set_callback", {at, fn});
    } else if (isa<TimerCancelOp>(op)) {
      st = ctx_.helperCall(b_, loc, "timer_cancel", {at});
    } else {
      Value zero = LLVM::ConstantOp::create(b_, loc, i64, b_.getI64IntegerAttr(0));
      st = ctx_.helperCall(b_, loc, "timer_start", {at, remap(cast<TimerStartOp>(op).getNsecs()), zero});
    }
    if (failed(st))
      return failure();
    bind(op.getResult(0), *st);
    return success();
  }
  // Timer callback completion returns zero by verifier contract.
  if (isa<TimerDoneOp>(op)) {
    Value z = LLVM::ConstantOp::create(b_, loc, b_.getI32Type(), b_.getI32IntegerAttr(0));
    LLVM::ReturnOp::create(b_, loc, z);
    return success();
  }

  // Spin lock/unlock use value plus @records lock-member offset.
  if (isa<SpinRegionOp>(op))
    return op.emitOpError() << "is a stage ① op; run ebpf-expand-regions first";
  if (isa<SpinLockOp, SpinUnlockOp>(op)) {
    Value ref = op.getOperand(0);
    StringRef lock = isa<SpinLockOp>(op) ? cast<SpinLockOp>(op).getLock() : cast<SpinUnlockOp>(op).getLock();
    auto rt = cast<RecordType>(cast<BorrowedType>(ref.getType()).getPointee());
    FailureOr<int64_t> off = ctx_.lockOffset(&op, rt.getSymbol(), lock);
    if (failed(off))
      return failure();
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(ref),
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(*off)});
    if (failed(ctx_.helperCall(b_, loc, isa<SpinLockOp>(op) ? "spin_lock" : "spin_unlock", {at})))
      return failure();
    return success();
  }

  // perf_event_output uses current_cpu ABI flags, full stack-record bytes
  // and declared size; return raw status.
  if (auto po = dyn_cast<PerfOutputOp>(op)) {
    auto cur = bpfabi::lookupPerfFlag("current_cpu");
    if (!cur)
      return po.emitOpError() << "BPF_F_CURRENT_CPU is not in the UAPI table";
    auto rt = cast<RecordType>(po.getRecord().getType());
    Value fl = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(*cur));
    Value len = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(rt.getSize()));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "perf_event_output", {remap(po.getCtx()), remap(po.getMap()), fl, remap(po.getRecord()), len});
    if (failed(r))
      return failure();
    bind(po.getStatus(), *r);
    return success();
  }

  // setsockopt / getsockopt pass a 4-byte stack slot. getsockopt zeroes
  // the slot first because the kernel leaves optval unwritten on some paths
  // (the sock_ops lock gate), so the value is defined on every status.
  if (isa<SockOpsSetsockoptOp, SockOpsGetsockoptOp, SockAddrSetsockoptOp, SockAddrGetsockoptOp>(op)) {
    bool set = isa<SockOpsSetsockoptOp, SockAddrSetsockoptOp>(op); // same operands and results.
    StringRef name = op.getAttrOfType<StringAttr>("option").getValue();
    const bpfabi::SockOptABI *row = bpfabi::lookupSockOption(name);
    if (!row)
      return op.emitOpError() << "socket option '" << name << "' is not in the UAPI table";
    auto word = [&](int64_t v) {
      return LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(v)).getResult();
    };
    Value input = set ? remap(op.getOperand(1))
                      : LLVM::ConstantOp::create(b_, loc, b_.getI32Type(), b_.getI32IntegerAttr(0)).getResult();
    Value slot = spillInt(input, loc);
    FailureOr<Value> r = ctx_.helperCall(b_, loc, set ? "setsockopt" : "getsockopt",
                                         {remap(op.getOperand(0)), word(row->Level), word(row->Optname), slot, word(4)});
    if (failed(r))
      return failure();
    if (!set)
      bind(op.getResult(1), LLVM::LoadOp::create(b_, loc, b_.getI32Type(), slot));
    bind(op.getResult(0), *r);
    endSpills(loc);
    return success();
  }
  // the constant name and its NUL in a stack buffer; optlen counts the
  // NUL, so a one-byte name still has optlen 2.
  if (auto sn = dyn_cast<SockOpsSetsockoptNameOp>(op)) {
    const bpfabi::SockOptNameABI *row = bpfabi::lookupSockOptionName(sn.getOption());
    if (!row)
      return op.emitOpError() << "string socket option '" << sn.getOption() << "' is not in the UAPI table";
    auto word = [&](int64_t v) {
      return LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(v)).getResult();
    };
    int64_t n = sn.getLiteral().size() + 1;
    Value buf = literalBuffer(sn.getLiteral(), n, loc);
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "setsockopt", {remap(sn.getCtx()), word(row->Level), word(row->Optname), buf, word(n)});
    if (failed(r))
      return failure();
    bind(sn.getStatus(), *r);
    return success();
  }
  // sk_select_reuseport(ctx,map,&key,0) spills the key like other map ops
  // and returns raw status.
  if (auto sr = dyn_cast<SkSelectReuseportOp>(op)) {
    Value keyPtr = spillKey(remap(sr.getKey()), loc);
    Value fl = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(0));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "sk_select_reuseport", {remap(sr.getCtx()), remap(sr.getMap()), keyPtr, fl});
    if (failed(r))
      return failure();
    endSpills(loc);
    bind(sr.getStatus(), *r);
    return success();
  }

  // Load context socket pointer once with eight-byte volatile ABI ctxfield
  // access, then pass it to get_socket_cookie.
  if (auto rc = dyn_cast<SkReuseportCookieOp>(op)) {
    const bpfabi::StructFieldABI *f = bpfabi::lookupStructField("sk_reuseport_md", rc.getField());
    if (!f || f->bytes != 8)
      return rc.emitOpError() << "has no 8-byte sk_reuseport_md." << rc.getField() << " row in the UAPI table";
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(rc.getCtx()),
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(f->offset)});
    Value sk = LLVM::LoadOp::create(b_, loc, ctx_.ptrTy(), at, /*alignment=*/8, /*isVolatile=*/true);
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "get_socket_cookie", {sk});
    if (failed(r))
      return failure();
    bind(rc.getCookie(), *r);
    return success();
  }

  // Return socket/message redirect SK_PASS/SK_DROP directly. sockmap takes a
  // zero-extended key value; sockhash takes its stack address. Ingress uses
  // ABI redirflag, otherwise flags zero.
  if (isa<SkRedirectOp, MsgRedirectOp>(op)) {
    bool isSk = isa<SkRedirectOp>(op);
    Value cond = isSk ? cast<SkRedirectOp>(op).getCond() : cast<MsgRedirectOp>(op).getCond();
    if (cond)
      return op.emitOpError() << "the `when` form is a stage ① op; run ebpf-expand-regions first";
    Value ctxV = op.getOperand(0), mapV = op.getOperand(1), keyV = op.getOperand(2);
    bool ingress = isSk ? cast<SkRedirectOp>(op).getIngress() : cast<MsgRedirectOp>(op).getIngress();
    int64_t fv = 0;
    if (ingress) {
      std::optional<int64_t> in = bpfabi::lookupRedirFlag("ingress");
      if (!in)
        return op.emitOpError() << "BPF_F_INGRESS is not in the UAPI table";
      fv = *in;
    }
    bool hash = cast<MapType>(mapV.getType()).getKind() == "sockhash";
    Value key = hash ? spillKey(remap(keyV), loc) : LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(keyV)).getResult();
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(fv));
    std::string helper = std::string(isSk ? "sk_redirect_" : "msg_redirect_") + (hash ? "hash" : "map");
    FailureOr<Value> r = ctx_.helperCall(b_, loc, helper, {remap(ctxV), remap(mapV), key, flags});
    if (failed(r))
      return failure();
    if (hash)
      endSpills(loc);
    LLVM::ReturnOp::create(b_, loc, LLVM::TruncOp::create(b_, loc, b_.getI32Type(), *r).getResult());
    return success();
  }

  if (auto rd = dyn_cast<SkRedirectRequestOp>(op)) {
    bool hash = cast<MapType>(rd.getMap().getType()).getKind() == "sockhash";
    Value key = hash ? spillKey(remap(rd.getKey()), loc) :
        LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(rd.getKey())).getResult();
    int64_t fv = 0;
    if (rd.getIngress()) {
      auto in = bpfabi::lookupRedirFlag("ingress");
      if (!in) return op.emitOpError("BPF_F_INGRESS is not in the UAPI table");
      fv = *in;
    }
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(fv));
    auto r = ctx_.helperCall(b_, loc, hash ? "sk_redirect_hash" : "sk_redirect_map",
                             {remap(rd.getCtx()), remap(rd.getMap()), key, flags});
    if (failed(r)) return failure();
    if (hash) endSpills(loc);
    bind(rd.getStatus(), *r);
    return success();
  }

  // Socket-map updates spill keys, resolve ABI update flags and return raw status.
  if (auto su = dyn_cast<SockMapUpdateOp>(op)) {
    std::optional<int64_t> fv = bpfabi::lookupUpdateFlag(su.getFlags());
    if (!fv)
      return su.emitOpError() << "update flags \"" << su.getFlags() << "\" are not in the UAPI table";
    bool hash = cast<MapType>(su.getMap().getType()).getKind() == "sockhash";
    Value keyPtr = spillKey(remap(su.getKey()), loc);
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(*fv));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, hash ? "sock_hash_update" : "sock_map_update", {remap(su.getCtx()), remap(su.getMap()), keyPtr, flags});
    if (failed(r))
      return failure();
    endSpills(loc);
    bind(su.getStatus(), *r);
    return success();
  }

  // seq_write passes full stack-record bytes/size and returns raw status.
  if (auto sw = dyn_cast<SeqWriteOp>(op)) {
    auto rt = cast<RecordType>(sw.getRecord().getType());
    Value len = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(rt.getSize()));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "seq_write", {remap(sw.getSeq()), remap(sw.getRecord()), len});
    if (failed(r))
      return failure();
    bind(sw.getStatus(), *r);
    return success();
  }

  // ringbuf_output passes stack-record data/size and ABI ring flags; return raw status.
  if (auto ro = dyn_cast<RingbufOutputOp>(op)) {
    int64_t flags = 0;
    if (auto f = ro.getFlags()) {
      auto v = bpfabi::lookupRingbufConst(*f);
      if (!v)
        return ro.emitOpError() << "BPF_RB_" << f->upper() << " is not in the UAPI table (ringbufconst " << *f << ")";
      flags = *v;
    }
    LLVM::GlobalOp rbGlobal = ctx_.mapGlobal(ro.getRingbuf(), loc);
    if (!rbGlobal)
      return failure();
    Value rb = LLVM::AddressOfOp::create(b_, loc, rbGlobal);
    auto rt = cast<RecordType>(ro.getRecord().getType());
    Value len = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(rt.getSize()));
    Value fl = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(flags));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "ringbuf_output", {rb, remap(ro.getRecord()), len, fl});
    if (failed(r))
      return failure();
    bind(ro.getStatus(), *r);
    return success();
  }

  // Drain callbacks return i64 zero to continue or one to stop, matching verifier range.
  if (auto dn = dyn_cast<UserRingbufDoneOp>(op)) {
    Value zero = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(0));
    Value r = zero;
    if (dn.getStop()) {
      Value one = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(1));
      r = LLVM::SelectOp::create(b_, loc, remap(dn.getStop()), one, zero);
    }
    LLVM::ReturnOp::create(b_, loc, r);
    return success();
  }
  // user_ringbuf_drain(map,callback,NULL,0) returns raw status. Callback
  // addressof is also a requirement-reachability edge.
  if (auto dr = dyn_cast<UserRingbufDrainOp>(op)) {
    LLVM::GlobalOp g = ctx_.mapGlobal(dr.getRingbuf(), loc);
    if (!g)
      return failure();
    Value m = LLVM::AddressOfOp::create(b_, loc, g);
    Value fn = LLVM::AddressOfOp::create(b_, loc, ctx_.ptrTy(), dr.getCallback());
    Value nul = LLVM::ZeroOp::create(b_, loc, ctx_.ptrTy());
    Value fl = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(0));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "user_ringbuf_drain", {m, fn, nul, fl});
    if (failed(r))
      return failure();
    bind(dr.getStatus(), *r);
    return success();
  }

  // Dynptr uses a 16-byte, eight-aligned entry alloca consumed only by helpers.
  // Kernel tracks its stack slots; other stores would corrupt it. Omit lifetime
  // markers so StackColoring cannot overlap its storage.
  if (auto rd = dyn_cast<RingbufReserveDynptrOp>(op)) {
    LLVM::GlobalOp rbGlobal = ctx_.mapGlobal(rd.getRingbuf(), loc);
    if (!rbGlobal)
      return failure();
    Value rb = LLVM::AddressOfOp::create(b_, loc, rbGlobal);
    Value slot = allocaFor(LLVM::LLVMArrayType::get(b_.getI64Type(), 2), loc);
    Value size = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(rd.getSize()));
    Value fl = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(0));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "ringbuf_reserve_dynptr", {rb, size, fl, slot});
    if (failed(r))
      return failure();
    bind(rd.getDynptr(), slot);
    bind(rd.getStatus(), *r);
    return success();
  }
  if (auto dw = dyn_cast<DynptrWriteOp>(op)) {
    Type vt = dw.getValue().getType();
    Value src = spillInt(remap(dw.getValue()), loc);
    Value off = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(dw.getOffset()));
    Value len = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(vt.getIntOrFloatBitWidth() / 8));
    Value fl = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(0));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "dynptr_write", {remap(dw.getDynptr()), off, src, len, fl});
    if (failed(r))
      return failure();
    endSpills(loc);
    bind(dw.getStatus(), *r);
    return success();
  }
  // Failed reads do not write destinations; zero first to define failure as zero.
  if (auto dr = dyn_cast<DynptrReadOp>(op)) {
    Type vt = dr.getValue().getType();
    Value zero = LLVM::ConstantOp::create(b_, loc, vt, b_.getIntegerAttr(vt, 0));
    Value dst = allocaFor(vt, loc);
    LLVM::StoreOp::create(b_, loc, zero, dst);
    Value len = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(vt.getIntOrFloatBitWidth() / 8));
    Value off = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(dr.getOffset()));
    Value fl = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(0));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "dynptr_read", {dst, len, remap(dr.getDynptr()), off, fl});
    if (failed(r))
      return failure();
    Value v = LLVM::LoadOp::create(b_, loc, vt, dst);
    bind(dr.getValue(), v);
    bind(dr.getStatus(), *r);
    return success();
  }
  if (isa<RingbufSubmitDynptrOp, RingbufDiscardDynptrOp>(op)) {
    Value fl = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(0));
    if (failed(ctx_.helperCall(b_, loc, isa<RingbufSubmitDynptrOp>(op) ? "ringbuf_submit_dynptr" : "ringbuf_discard_dynptr",
                               {remap(op.getOperand(0)), fl})))
      return failure();
    return success();
  }

  // get_stackid returns raw status; skip bounds and reuse flags come from ABI stackflag.
  if (auto sk = dyn_cast<StackKernelIdOp>(op)) {
    auto mask = bpfabi::lookupStackFlag("skip_field_mask");
    auto reuse = bpfabi::lookupStackFlag("reuse_stackid");
    if (!mask || !reuse)
      return sk.emitOpError() << "the stack flags are not in the UAPI table";
    if (static_cast<uint64_t>(sk.getSkip()) > static_cast<uint64_t>(*mask))
      return sk.emitOpError() << "skip " << sk.getSkip() << " exceeds the skip field (" << *mask << " — BPF_F_SKIP_FIELD_MASK)";
    int64_t flags = sk.getSkip() | (sk.getReuse() ? *reuse : 0);
    Value fl = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(flags));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "get_stackid", {remap(sk.getCtx()), remap(sk.getMap()), fl});
    if (failed(r))
      return failure();
    bind(sk.getStatus(), *r);
    return success();
  }

  // User-stack flags combine skip/user_stack/reuse_stackid from ABI.
  if (auto su = dyn_cast<StackUserIdOp>(op)) {
    auto mask = bpfabi::lookupStackFlag("skip_field_mask");
    auto reuse = bpfabi::lookupStackFlag("reuse_stackid");
    auto user = bpfabi::lookupStackFlag("user_stack");
    if (!mask || !reuse || !user)
      return su.emitOpError() << "the stack flags are not in the UAPI table";
    if (static_cast<uint64_t>(su.getSkip()) > static_cast<uint64_t>(*mask))
      return su.emitOpError() << "skip " << su.getSkip() << " exceeds the skip field (" << *mask << " — BPF_F_SKIP_FIELD_MASK)";
    int64_t flags = su.getSkip() | *user | (su.getReuse() ? *reuse : 0);
    Value fl = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(flags));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "get_stackid", {remap(su.getCtx()), remap(su.getMap()), fl});
    if (failed(r))
      return failure();
    bind(su.getStatus(), *r);
    return success();
  }

  // tail_call(ctx,map,zext(index)) has no readable result. Success never
  // returns, so subsequent fallback executes only after failure.
  if (isa<TailCallOp>(op))
    return op.emitOpError() << "is a stage ① op; run ebpf-expand-regions first";
  if (auto tc = dyn_cast<TailCallTryOp>(op)) {
    Value idx = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(tc.getIndex()));
    if (failed(ctx_.helperCall(b_, loc, "tail_call", {remap(tc.getCtx()), remap(tc.getMap()), idx})))
      return failure();
    return success();
  }

  // Return redirect_map's action directly, using ABI XDP verdict as fallback flags.
  if (auto rm = dyn_cast<RedirectMapOp>(op)) {
    if (rm.getCond())
      return rm.emitOpError() << "the `when` form is a stage ① op; run ebpf-expand-regions first";
    auto fb = bpfabi::lookupVerdictValue("xdp", rm.getFallback());
    if (!fb)
      return rm.emitOpError() << "fallback \"" << rm.getFallback() << "\" is not in the UAPI table";
    uint64_t bits = *fb;
    if (auto redir = rm.getRedirectFlags()) {
      auto broadcast = bpfabi::lookupRedirFlag("broadcast");
      if (!broadcast)
        return rm.emitOpError() << "BPF_F_BROADCAST is not in the UAPI table";
      bits |= *broadcast;
      if (*redir == "broadcast_exclude_ingress") {
        auto exclude = bpfabi::lookupRedirFlag("exclude_ingress");
        if (!exclude)
          return rm.emitOpError() << "BPF_F_EXCLUDE_INGRESS is not in the UAPI table";
        bits |= *exclude;
      }
    }
    Value key = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(rm.getKey()));
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(bits));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "redirect_map", {remap(rm.getMap()), key, flags});
    if (failed(r))
      return failure();
    LLVM::ReturnOp::create(b_, loc, LLVM::TruncOp::create(b_, loc, b_.getI32Type(), *r).getResult());
    return success();
  }

  // Load data/data_end once. Check off64<=MAX_PACKET_OFF-len, then compare
  // at+len<=data_end. Pass the exact compared at register into in_range as
  // its window; recomputing data+offset loses verifier range evidence.
  // the XDP metadata window. data_meta and data are read at their UAPI
  // offsets (four-byte fields); the branch compares the advanced meta pointer
  // against data. The window is the meta pointer itself (the same register
  // that was compared, so the verifier keeps its range). Accesses are always
  // byte by byte at align 1 — the strict alignment of PTR_TO_PACKET_META is
  // relative to NET_IP_ALIGN, and a 4-multiple data - data_meta does not make
  // the start aligned.
  if (auto mk = dyn_cast<MetaCheckBrOp>(op)) {
    auto kind = cast<ContextType>(mk.getCtx().getType()).getKind();
    auto layout = bpfabi::lookupMetaCtx(kind);
    if (!layout)
      return mk.emitOpError() << "program kind \"" << kind << "\" has no data_meta in the UAPI table";
    int64_t len = static_cast<int64_t>(mk.getLen());
    auto range = bpfabi::CtxMetaOp::create(b_, loc, TypeRange{ctx_.ptrTy(), ctx_.ptrTy()}, remap(mk.getCtx()),
                                           b_.getStringAttr(kind), b_.getI64IntegerAttr(layout->metaOffset),
                                           b_.getI64IntegerAttr(layout->dataOffset), b_.getI64IntegerAttr(layout->fieldBytes));
    Block *inDst = blocks_[mk.getInRange()];
    Block *outDst = blocks_[mk.getOutOfRange()];
    Value past = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), range.getMeta(),
                                     ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(len)});
    Value ok = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ule, past, range.getData());
    LLVM::CondBrOp::create(b_, loc, ok, inDst, ValueRange{range.getMeta()}, outDst, ValueRange{});
    return success();
  }

  if (auto ml = dyn_cast<MetaLoadOp>(op)) {
    Value w = remap(ml.getWindow());
    Type resTy = ml.getResult().getType();
    unsigned width = resTy.getIntOrFloatBitWidth() / 8;
    Value v;
    for (unsigned i = 0; i < width; ++i) {
      Value p = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), w,
                                    ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(ml.getIndex() + i)});
      Value byte = LLVM::LoadOp::create(b_, loc, b_.getI8Type(), p, /*alignment=*/1);
      Value wide = width == 1 ? byte : LLVM::ZExtOp::create(b_, loc, resTy, byte).getResult();
      if (i != 0) {
        Value sh = LLVM::ConstantOp::create(b_, loc, resTy, b_.getIntegerAttr(resTy, 8 * i));
        wide = LLVM::ShlOp::create(b_, loc, wide, sh);
        wide = LLVM::OrOp::create(b_, loc, v, wide);
      }
      v = wide;
    }
    bind(ml.getResult(), v);
    return success();
  }

  if (auto ms = dyn_cast<MetaStoreOp>(op)) {
    Value w = remap(ms.getWindow());
    Value v = remap(ms.getValue());
    unsigned bytes = v.getType().getIntOrFloatBitWidth() / 8;
    for (unsigned k = 0; k < bytes; ++k) {
      Value byte = v;
      if (k > 0) {
        Value sh = LLVM::ConstantOp::create(b_, loc, v.getType(), b_.getIntegerAttr(v.getType(), 8 * k));
        byte = LLVM::LShrOp::create(b_, loc, v, sh);
      }
      if (bytes > 1)
        byte = LLVM::TruncOp::create(b_, loc, b_.getI8Type(), byte);
      Value p = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), w,
                                    ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(ms.getIndex() + k)});
      LLVM::StoreOp::create(b_, loc, byte, p, /*alignment=*/1);
    }
    return success();
  }

  if (auto pk = dyn_cast<PktCheckBrOp>(op)) {
    auto kind = cast<ContextType>(pk.getCtx().getType()).getKind();
    auto layout = bpfabi::lookupPacketCtx(kind);
    if (!layout)
      return pk.emitOpError() << "program kind \"" << kind << "\" has no packet in the UAPI table";
    int64_t len = static_cast<int64_t>(pk.getLen());
    auto range = bpfabi::CtxPacketOp::create(b_, loc, TypeRange{ctx_.ptrTy(), ctx_.ptrTy()}, remap(pk.getCtx()),
                                             b_.getStringAttr(kind), b_.getI64IntegerAttr(layout->dataOffset),
                                             b_.getI64IntegerAttr(layout->dataEndOffset),
                                             b_.getI64IntegerAttr(layout->fieldBytes));
    Value off64 = remap(pk.getOffset());
    Block *inDst = blocks_[pk.getInRange()];
    Block *outDst = blocks_[pk.getOutOfRange()];
    APInt constOff;
    if (!matchPattern(pk.getOffset(), m_ConstantInt(&constOff))) {
      Value lim = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(bpfabi::kMaxPacketOffset - len));
      Value tooFar = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ugt, off64, lim);
      Block *cur = b_.getInsertionBlock();
      auto *next = new Block();
      func_.getBody().getBlocks().insert(std::next(cur->getIterator()), next);
      LLVM::CondBrOp::create(b_, loc, tooFar, outDst, ValueRange{}, next, ValueRange{});
      b_.setInsertionPointToEnd(next);
    } else if (constOff.getActiveBits() > 64 ||
               constOff.getZExtValue() > static_cast<uint64_t>(bpfabi::kMaxPacketOffset - len)) { // Subtraction avoids overflow.
      return pk.emitOpError() << "the window exceeds MAX_PACKET_OFF (" << bpfabi::kMaxPacketOffset << ")";
    }
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), range.getData(), ArrayRef<LLVM::GEPArg>{off64});
    Value past = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), at, ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(len)});
    Value ok = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ule, past, range.getDataEnd());
    LLVM::CondBrOp::create(b_, loc, ok, inDst, ValueRange{at}, outDst, ValueRange{});
    return success();
  }

  // Read/write windows bytewise in little-endian order for strict-alignment
  // targets. Use the already-compared window pointer plus index without
  // rechecking or reloading data.
  if (auto wl = dyn_cast<PacketWindowLoadOp>(op)) {
    Value w = remap(wl.getWindow());
    Type resTy = wl.getResult().getType();
    unsigned width = resTy.getIntOrFloatBitWidth() / 8;
    if (ctx_.alignedPacketLoad) {
      std::optional<uint64_t> base = constantWindowOffset(wl.getWindow());
      if (base && strictAlignedPacketRead(*base + wl.getIndex(), width)) {
        Value p = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), w,
                                      ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(wl.getIndex())});
        bind(wl.getResult(), LLVM::LoadOp::create(b_, loc, resTy, p, /*alignment=*/width).getResult());
        return success();
      }
    }
    Value v;
    for (unsigned i = 0; i < width; ++i) {
      Value p = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), w,
                                    ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(wl.getIndex() + i)});
      Value byte = LLVM::LoadOp::create(b_, loc, b_.getI8Type(), p, /*alignment=*/1);
      Value wide = width == 1 ? byte : LLVM::ZExtOp::create(b_, loc, resTy, byte).getResult();
      if (i != 0) {
        Value sh = LLVM::ConstantOp::create(b_, loc, resTy, b_.getIntegerAttr(resTy, 8 * i));
        wide = LLVM::ShlOp::create(b_, loc, wide, sh);
        wide = LLVM::OrOp::create(b_, loc, v, wide);
      }
      v = wide;
    }
    bind(wl.getResult(), v);
    return success();
  }

  if (auto st = dyn_cast<PacketStoreOp>(op)) {
    // Static function window writes remain XDP-only, independently of entry
  // kind capabilities that also allow cgroup_sockopt stores.
    if (sub_)
      for (StringRef k : ctx_.programKinds)
        if (k != "xdp")
          return st.emitOpError() << "writes a packet window in @" << sub_.getSymName() << ", which is reached from a \"" << k
                                  << "\" program; static packet-window stores are only for xdp programs (cgroup_sockopt stores are entry-only)";
    Value w = remap(st.getWindow());
    Value v = remap(st.getValue());
    unsigned bytes = v.getType().getIntOrFloatBitWidth() / 8;
    for (unsigned k = 0; k < bytes; ++k) {
      Value byte = v;
      if (k > 0) {
        Value sh = LLVM::ConstantOp::create(b_, loc, v.getType(), b_.getIntegerAttr(v.getType(), 8 * k));
        byte = LLVM::LShrOp::create(b_, loc, v, sh);
      }
      if (bytes > 1)
        byte = LLVM::TruncOp::create(b_, loc, b_.getI8Type(), byte);
      Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), w,
                                     ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(st.getIndex() + k)});
      LLVM::StoreOp::create(b_, loc, byte, at, /*alignment=*/1);
    }
    return success();
  }

  // the arena window base is a CO-RE read of bpf_arena.user_vm_start
  // from the map's .maps placeholder address (the kfield.load form).
  if (isa<ArenaAllocBrOp, ArenaFreePagesOp>(op)) {
    auto allocation = dyn_cast<ArenaAllocBrOp>(op);
    auto release = dyn_cast<ArenaFreePagesOp>(op);
    Value map = remap(allocation ? allocation.getMap() : release.getMap());
    if (!map)
      return op.emitOpError("arena lifecycle map has no address at stage ③");
    uint64_t offset = allocation ? allocation.getPageOffset() : release.getPageOffset();
    uint64_t count = allocation ? allocation.getPageCount() : release.getPageCount();
    Value base = bpfabi::CoreFieldLoadOp::create(b_, loc, b_.getI64Type(), map, b_.getStringAttr("bpf_arena"),
                                               b_.getStringAttr("user_vm_start"));
    auto constant = [&](Type ty, uint64_t value) -> Value {
      return LLVM::ConstantOp::create(b_, loc, ty, b_.getIntegerAttr(ty, value));
    };
    Value delta = constant(b_.getI64Type(), offset * 4096);
    Value requested = LLVM::AddOp::create(b_, loc, base, delta);
    Value pointer = LLVM::IntToPtrOp::create(b_, loc, ctx_.ptrTy(), requested);
    Value pages = constant(b_.getI32Type(), count);
    if (release) {
      bpfabi::KfuncCallOp::create(b_, loc, TypeRange{}, b_.getStringAttr("bpf_arena_free_pages"), UnitAttr(),
                                ValueRange{map, pointer, pages});
      return success();
    }
    Value node = constant(b_.getI32Type(), uint32_t(-1));
    Value flags = constant(b_.getI64Type(), 0);
    auto call = bpfabi::KfuncCallOp::create(b_, loc, TypeRange{ctx_.ptrTy()}, b_.getStringAttr("bpf_arena_alloc_pages"), UnitAttr(),
                                          ValueRange{map, pointer, pages, node, flags});
    Value actual = LLVM::PtrToIntOp::create(b_, loc, b_.getI64Type(), call.getResult(0));
    Value ok = mlir::ebpf::detail::arenaAllocationMatches(b_, loc, actual, requested);
    LLVM::CondBrOp::create(b_, loc, ok, blocks_[allocation.getAllocated()], ValueRange{}, blocks_[allocation.getFailed()], ValueRange{});
    return success();
  }

  if (auto ab = dyn_cast<ArenaBaseOp>(op)) {
    Value m = remap(ab.getMap());
    if (!m)
      return ab.emitOpError() << "the arena map has no address at stage ③";
    auto r = bpfabi::CoreFieldLoadOp::create(b_, loc, b_.getI64Type(), m, b_.getStringAttr("bpf_arena"),
                                             b_.getStringAttr("user_vm_start"));
    bind(ab.getBase(), r.getResult());
    return success();
  }

  // one unsigned scalar compare off64 ule size − len and a branch — no
  // address before the compare. The window address (base + off64 in address
  // space 1) is made at the entry of the in-range block only.
  if (auto ck = dyn_cast<ArenaCheckBrOp>(op)) {
    auto ab = ck.getBase().getDefiningOp<ArenaBaseOp>();
    Value mapAddr = ab ? remap(ab.getMap()) : Value();
    auto addr = mapAddr ? mapAddr.getDefiningOp<LLVM::AddressOfOp>() : LLVM::AddressOfOp();
    if (!addr)
      return ck.emitOpError() << "the base is not an ebpf.arena.base of a map at stage ③";
    std::optional<uint64_t> bytes = ctx_.arenaBytes(addr.getGlobalName());
    if (!bytes)
      return ck.emitOpError() << "the size of arena map @" << addr.getGlobalName() << " is not recorded in the module ("
                              << Lowering::kArenaBytesAttr << " — ebpf-build-btf-types sets it from the schema pages)";
    uint64_t len = ck.getLen();
    if (len > *bytes)
      return ck.emitOpError() << "the window of " << len << " bytes is larger than the arena (" << *bytes << " bytes)";
    APInt constOff;
    if (matchPattern(ck.getOffset(), m_ConstantInt(&constOff)) &&
        (constOff.getActiveBits() > 64 || constOff.getZExtValue() > *bytes - len)) // Subtraction avoids overflow.
      return ck.emitOpError() << "the window at constant offset " << constOff.getZExtValue() << " exceeds the arena (" << *bytes
                              << " bytes)";
    Value base = remap(ck.getBase());
    Value off64 = remap(ck.getOffset());
    Block *inDst = blocks_[ck.getInRange()];
    Block *outDst = blocks_[ck.getOutOfRange()];
    Value lim = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(static_cast<int64_t>(*bytes - len)));
    Value ok = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ule, off64, lim);
    LLVM::CondBrOp::create(b_, loc, ok, inDst, ValueRange{}, outDst, ValueRange{});
    {
      OpBuilder::InsertionGuard g(b_);
      b_.setInsertionPointToStart(inDst);
      auto at = bpfabi::ArenaAddrOp::create(b_, loc, ctx_.arenaPtrTy(), base, off64);
      bind(ck.getInRange()->getArgument(0), at.getResult());
    }
    return success();
  }

  // arena accesses are always volatile (shared with user space). One
  // width-aligned access when the window's constant offset c gives
  // (c + index) mod width = 0, otherwise one access per byte.
  if (isa<ArenaLoadOp, ArenaStoreOp>(op)) {
    auto ld = dyn_cast<ArenaLoadOp>(op);
    auto st = dyn_cast<ArenaStoreOp>(op);
    Value window = ld ? ld.getWindow() : st.getWindow();
    uint64_t index = ld ? ld.getIndex() : st.getIndex();
    Value w = remap(window);
    if (!w)
      return op.emitOpError() << "the arena window has no address at stage ③ (its arena.check_br was not lowered first)";
    Type valTy = ld ? ld.getResult().getType() : st.getValue().getType();
    unsigned width = valTy.getIntOrFloatBitWidth() / 8;
    auto addrAt = [&](uint64_t i) {
      return LLVM::GEPOp::create(b_, loc, ctx_.arenaPtrTy(), b_.getI8Type(), w,
                                 ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(i)}).getResult();
    };
    std::optional<uint64_t> c = constantArenaWindowOffset(window);
    bool wide = width == 1 || (c && (*c + index) % width == 0);
    if (ld) {
      if (wide) {
        bind(ld.getResult(), LLVM::LoadOp::create(b_, loc, valTy, addrAt(index), /*alignment=*/width, /*isVolatile=*/true).getResult());
        return success();
      }
      Value v;
      for (unsigned i = 0; i < width; ++i) {
        Value byte = LLVM::LoadOp::create(b_, loc, b_.getI8Type(), addrAt(index + i), /*alignment=*/1, /*isVolatile=*/true);
        Value part = LLVM::ZExtOp::create(b_, loc, valTy, byte);
        if (i != 0) {
          Value sh = LLVM::ConstantOp::create(b_, loc, valTy, b_.getIntegerAttr(valTy, 8 * i));
          part = LLVM::ShlOp::create(b_, loc, part, sh);
          part = LLVM::OrOp::create(b_, loc, v, part);
        }
        v = part;
      }
      bind(ld.getResult(), v);
      return success();
    }
    Value v = remap(st.getValue());
    if (wide) {
      LLVM::StoreOp::create(b_, loc, v, addrAt(index), /*alignment=*/width, /*isVolatile=*/true);
      return success();
    }
    for (unsigned k = 0; k < width; ++k) {
      Value byte = v;
      if (k > 0) {
        Value sh = LLVM::ConstantOp::create(b_, loc, valTy, b_.getIntegerAttr(valTy, 8 * k));
        byte = LLVM::LShrOp::create(b_, loc, v, sh);
      }
      byte = LLVM::TruncOp::create(b_, loc, b_.getI8Type(), byte);
      LLVM::StoreOp::create(b_, loc, byte, addrAt(index + k), /*alignment=*/1, /*isVolatile=*/true);
    }
    return success();
  }

  if (auto br = dyn_cast<cf::CondBranchOp>(op)) {
    LLVM::CondBrOp::create(b_, loc, remap(br.getCondition()),
                           blocks_[br.getTrueDest()],
                           remapAll(br.getTrueDestOperands()),
                           blocks_[br.getFalseDest()],
                           remapAll(br.getFalseDestOperands()));
    return success();
  }

  // is_present becomes a real pointer comparison. assume_present emits
  // nothing: the checked reference is the same raw pointer.
  if (auto test = dyn_cast<IsPresentOp>(op)) {
    Value null = LLVM::ZeroOp::create(b_, loc, ctx_.ptrTy());
    Value ne = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ne,
                                    remap(test.getValue()), null);
    bind(test.getResult(), ne);
    return success();
  }
  if (auto a = dyn_cast<AssumePresentOp>(op)) {
    bind(a.getResult(), remap(a.getValue()));
    return success();
  }

  // both borrowed pointers remain local to this lowering.
  if (auto set = dyn_cast<SockAddrSetSunPathOp>(op)) {
    StringRef literal = set.getLiteral();
    Value buffer = allocaFor(LLVM::LLVMArrayType::get(b_.getI8Type(), literal.size()), loc);
    for (auto [i, byte] : llvm::enumerate(literal.bytes())) {
      Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), buffer,
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(i)});
      Value value = LLVM::ConstantOp::create(b_, loc, b_.getI8Type(), b_.getI8IntegerAttr(byte));
      LLVM::StoreOp::create(b_, loc, value, at, 1);
    }
    auto kernel = bpfabi::KfuncCallOp::create(b_, loc, TypeRange{ctx_.ptrTy()},
        b_.getStringAttr("bpf_cast_to_kern_ctx"), UnitAttr(), ValueRange{remap(set.getCtx())});
    Value size = LLVM::ConstantOp::create(b_, loc, b_.getI32Type(), b_.getI32IntegerAttr(literal.size()));
    auto call = bpfabi::KfuncCallOp::create(b_, loc, TypeRange{b_.getI32Type()},
        b_.getStringAttr("bpf_sock_addr_set_sun_path"), UnitAttr(), ValueRange{kernel.getResult(0), buffer, size});
    bind(set.getStatus(), call.getResult(0));
    return success();
  }

  // initialized private literal; no terminator is added to the helper size.
  if (auto set = dyn_cast<SysctlSetNewValueOp>(op)) {
    StringRef literal = set.getLiteral();
    Value buffer = allocaFor(LLVM::LLVMArrayType::get(b_.getI8Type(), literal.size()), loc);
    for (auto [i, byte] : llvm::enumerate(literal.bytes())) {
      Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), buffer,
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(i)});
      Value value = LLVM::ConstantOp::create(b_, loc, b_.getI8Type(), b_.getI8IntegerAttr(byte));
      LLVM::StoreOp::create(b_, loc, value, at, 1);
    }
    Value size = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(literal.size()));
    FailureOr<Value> status = ctx_.helperCall(b_, loc, "sysctl_set_new_value", {remap(set.getCtx()), buffer, size});
    if (failed(status))
      return failure();
    bind(set.getStatus(), *status);
    return success();
  }

  // ext arguments select i64 entry registers and truncate to result width.
  if (auto ea = dyn_cast<ExtArgOp>(op)) {
    Value v = func_.getArgument(static_cast<unsigned>(ea.getIndex()));
    if (ea.getResult().getType() != v.getType())
      v = LLVM::TruncOp::create(b_, loc, ea.getResult().getType(), v);
    bind(ea.getResult(), v);
    return success();
  }
  // Tracing arguments and CO-RE field reads.
  if (auto arg = dyn_cast<CtxArgOp>(op)) {
    int64_t idx = arg.getIndex();
    // Integer tracing arguments read u64 slots and truncate to result width.
    bool isInt = isa<IntegerType>(arg.getResult().getType());
    auto a = bpfabi::CtxArgOp::create(
        b_, loc, isInt ? Type(b_.getI64Type()) : ctx_.ptrTy(), remap(arg.getCtx()), b_.getI64IntegerAttr(idx),
        b_.getI64IntegerAttr(bpfabi::kTracingArgBytes * idx),
        b_.getI64IntegerAttr(bpfabi::kTracingArgBytes));
    Value v = a.getResult();
    if (isInt && arg.getResult().getType() != v.getType())
      v = LLVM::TruncOp::create(b_, loc, arg.getResult().getType(), v);
    bind(arg.getResult(), v);
    return success();
  }
  // fexit return reads slot N at 8*N and truncates.
  // Private tracepoint-buffer access remains explicit through ABI lowering.
  if (isa<TpBufferLoadOp, TpBufferStoreOp>(op)) {
    auto prog = op.getParentOfType<ProgramOp>();
    auto *info = prog ? bpfmlir::lookupProgramKind(prog.getKind()) : nullptr;
    auto *row = prog ? attachRowFor(prog) : nullptr;
    auto *field = info ? bpfabi::lookupStructField(info->ctxStruct, "args") : nullptr;
    std::string atype = row ? bpfmlir::attachTypeOf(*row, attachOf(prog)) : "";
    auto *access = info ? bpfabi::lookupCtxAccess(info->progType, atype, info->ctxStruct, "args", "r") : nullptr;
    if (!info || !row || !field || !access || field->bytes != access->bytes)
      return op.emitOpError("tp.buffer: ABI shape mismatch");
    if (auto ld = dyn_cast<TpBufferLoadOp>(op)) {
      auto lowered = bpfabi::TpBufferLoadOp::create(b_, loc, ld.getResult().getType(), remap(ld.getCtx()), info->progType,
                                                  atype, field->offset, access->bytes, ld.getOffset(),
                                                  ld.getResult().getType().getIntOrFloatBitWidth() / 8);
      bind(ld.getResult(), lowered.getResult());
    } else {
      auto st = cast<TpBufferStoreOp>(op);
      bpfabi::TpBufferStoreOp::create(b_, loc, remap(st.getCtx()), info->progType, atype, field->offset, access->bytes,
                                     st.getOffset(), st.getValue().getType().getIntOrFloatBitWidth() / 8, remap(st.getValue()));
    }
    return success();
  }
  // Context integer offsets come from ABI ctxfield, widths from capabilities;
  // operation verification checked them and ABI exit verification checks again.
  if (isa<CtxFieldOp, CtxFieldStoreOp>(op)) {
    auto prog = op.getParentOfType<ProgramOp>();
    const bpfmlir::ProgramKindInfo *info = prog ? bpfmlir::lookupProgramKind(prog.getKind()) : nullptr;
    StringRef field = isa<CtxFieldOp>(op) ? cast<CtxFieldOp>(op).getField() : cast<CtxFieldStoreOp>(op).getField();
    const bpfabi::StructFieldABI *f = info ? bpfabi::lookupStructField(info->ctxStruct, field) : nullptr;
    if (!f)
      return op.emitOpError() << "has no ctxfield in the UAPI table";
    const bpfmlir::ProgramAttachInfo *arow = attachRowFor(prog); // expected_attach_type belongs to the attachment row.
    if (!arow)
      return op.emitOpError() << "has no attach row for its program (kind table)";
    std::string atype = bpfmlir::attachTypeOf(*arow, attachOf(prog));
    if (auto ld = dyn_cast<CtxFieldOp>(op)) {
      // BTF-backed pointer fields read eight bytes. Flexible-array offsets add
      // constant index*element width; op/ABI verification check index bounds.
      bool kptr = isa<KPtrType>(ld.getResult().getType());
      int64_t idx = ld.getIndex() ? static_cast<int64_t>(*ld.getIndex()) : 0;
      auto a = bpfabi::CtxFieldLoadOp::create(b_, loc, kptr ? Type(ctx_.ptrTy()) : ld.getResult().getType(), remap(ld.getCtx()), info->progType,
                                              atype, info->ctxStruct, field, f->offset + idx * f->bytes,
                                              kptr ? int64_t(8) : int64_t(ld.getResult().getType().getIntOrFloatBitWidth() / 8),
                                              ld.getIndexAttr());
      bind(ld.getResult(), a.getResult());
      return success();
    }
    auto st = cast<CtxFieldStoreOp>(op);
    bpfabi::CtxFieldStoreOp::create(b_, loc, remap(st.getCtx()), info->progType, atype, info->ctxStruct, field, f->offset,
                                    st.getValue().getType().getIntOrFloatBitWidth() / 8, remap(st.getValue()));
    return success();
  }
  // Return probes read eight bytes at architecture kproberet offset using
  // kprobe_arg n=0, then truncate to iW.
  if (auto pr = dyn_cast<ProbeRetvalOp>(op)) {
    auto prog = pr->getParentOfType<ProgramOp>();
    if (!prog || !prog.getArch())
      return pr.emitOpError() << "must be inside a kretprobe / uretprobe program with `arch`";
    const bpfabi::KprobeArgABI *k = bpfabi::lookupKprobeRet(*prog.getArch());
    if (!k)
      return pr.emitOpError() << "the return value register of arch \"" << *prog.getArch() << "\" is not in the UAPI table (kproberet)";
    auto a = bpfabi::KprobeArgOp::create(b_, loc, b_.getI64Type(), remap(pr.getCtx()), b_.getStringAttr(*prog.getArch()),
                                         b_.getI64IntegerAttr(0), b_.getI64IntegerAttr(k->offset), b_.getI64IntegerAttr(k->bytes));
    Value v = a.getResult();
    if (pr.getResult().getType() != v.getType())
      v = LLVM::TruncOp::create(b_, loc, pr.getResult().getType(), v);
    bind(pr.getResult(), v);
    return success();
  }
  // Syscall context reads use one declared-width volatile load at ctx+offset.
  if (auto cl = dyn_cast<CtxLoadOp>(op)) {
    unsigned bytes = cl.getResult().getType().getIntOrFloatBitWidth() / 8;
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(cl.getCtx()),
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(cl.getOffset())});
    Value v = LLVM::LoadOp::create(b_, loc, cl.getResult().getType(), at, /*alignment=*/bytes, /*isVolatile=*/true);
    bind(cl.getResult(), v);
    return success();
  }
  // Load PTR_TO_FLOW_KEYS once through volatile eight-byte ctx access.
  // Then read/write the field at ABI offset plus index*width with a single
  // declared-width volatile access. Re-resolve the already-verified ABI facts.
  if (isa<FlowKeysLoadOp, FlowKeysStoreOp>(op)) {
    auto ld = dyn_cast<FlowKeysLoadOp>(op);
    auto st = dyn_cast<FlowKeysStoreOp>(op);
    StringRef field = ld ? ld.getField() : st.getField();
    std::optional<uint64_t> index = ld ? ld.getIndex() : st.getIndex();
    const bpfabi::StructFieldABI *fk = bpfabi::lookupStructField("__sk_buff", "flow_keys");
    const bpfabi::StructFieldABI *f = bpfabi::lookupStructField("bpf_flow_keys", field);
    if (!fk || fk->bytes != 8 || !f)
      return op.emitOpError() << "has no __sk_buff.flow_keys / bpf_flow_keys." << field << " row in the UAPI table";
    int64_t idx = index ? static_cast<int64_t>(*index) : 0;
    Value ctxv = remap(ld ? ld.getCtx() : st.getCtx());
    Value pat = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), ctxv, ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(fk->offset)});
    Value keys = LLVM::LoadOp::create(b_, loc, ctx_.ptrTy(), pat, /*alignment=*/8, /*isVolatile=*/true);
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), keys,
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(f->offset + idx * f->bytes)});
    unsigned bytes = static_cast<unsigned>(f->bytes);
    if (ld) {
      Value v = LLVM::LoadOp::create(b_, loc, ld.getResult().getType(), at, /*alignment=*/bytes, /*isVolatile=*/true);
      bind(ld.getResult(), v);
    } else {
      LLVM::StoreOp::create(b_, loc, remap(st.getValue()), at, /*alignment=*/bytes, /*isVolatile=*/true);
    }
    return success();
  }
  // lirc accepts only one volatile four-byte u32 load at context offset zero.
  if (auto ls = dyn_cast<LircSampleOp>(op)) {
    Value v = LLVM::LoadOp::create(b_, loc, b_.getI32Type(), remap(ls.getCtx()), /*alignment=*/4, /*isVolatile=*/true);
    bind(ls.getResult(), v);
    return success();
  }
  // Tracepoint fields use one volatile declared-width load at the schema
  // offset matched by VerifySchema. Target tracefs correctness remains a
  // pre-load tpfield requirement.
  if (auto tf = dyn_cast<TpFieldOp>(op)) {
    Type loadedType = isa<UserStrType, UserStrArrayType>(tf.getResult().getType()) ? b_.getI64Type() : tf.getResult().getType();
    unsigned bytes = loadedType.getIntOrFloatBitWidth() / 8;
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(tf.getCtx()),
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(tf.getOffset())});
    Value v = LLVM::LoadOp::create(b_, loc, loadedType, at, /*alignment=*/bytes, /*isVolatile=*/true);
    bind(tf.getResult(), v);
    return success();
  }
  if (auto rv = dyn_cast<CtxRetvalOp>(op)) {
    int64_t idx = rv.getNargs();
    auto a = bpfabi::CtxArgOp::create(b_, loc, b_.getI64Type(), remap(rv.getCtx()), b_.getI64IntegerAttr(idx),
                                      b_.getI64IntegerAttr(bpfabi::kTracingArgBytes * idx),
                                      b_.getI64IntegerAttr(bpfabi::kTracingArgBytes));
    Value v = a.getResult();
    if (rv.getResult().getType() != v.getType())
      v = LLVM::TruncOp::create(b_, loc, rv.getResult().getType(), v);
    bind(rv.getResult(), v);
    return success();
  }
  if (isa<CtxFuncIpOp, CtxFuncArgCntOp>(op)) {
    StringRef helper = isa<CtxFuncIpOp>(op) ? "get_func_ip" : "get_func_arg_cnt";
    auto value = ctx_.helperCall(b_, loc, helper, {remap(op.getOperand(0))});
    if (failed(value))
      return failure();
    bind(op.getResult(0), *value);
    return success();
  }
  if (auto arg = dyn_cast<CtxFuncArgOp>(op)) {
    Value slot = mlir::ebpf::detail::scalarOutputSlot(b_, entry_, loc, b_.getI64Type(), 8);
    mlir::ebpf::detail::clearScalarOutput(b_, loc, slot, b_.getI64Type(), 8);
    Value index = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(arg.getN()));
    auto status = ctx_.helperCall(b_, loc, "get_func_arg", {remap(arg.getCtx()), index, slot});
    if (failed(status))
      return failure();
    bind(arg.getStatus(), *status);
    bind(arg.getValue(), mlir::ebpf::detail::scalarOutputValue(b_, loc, slot, b_.getI64Type(),
         cast<IntegerType>(arg.getValue().getType()), *status, 8));
    return success();
  }
  // ctx.func_ret — bpf_get_func_ret(ctx, &slot) with an entry-block
  // 8-byte slot; the status (always 0 for fexit) is discarded.
  if (auto fr = dyn_cast<CtxFuncRetOp>(op)) {
    Value slot;
    {
      OpBuilder::InsertionGuard g(b_);
      b_.setInsertionPointToStart(entry_);
      Value one = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(1));
      slot = LLVM::AllocaOp::create(b_, loc, ctx_.ptrTy(), b_.getI64Type(), one, /*alignment=*/8);
    }
    if (failed(ctx_.helperCall(b_, loc, "get_func_ret", {remap(fr.getCtx()), slot})))
      return failure();
    Value v = LLVM::LoadOp::create(b_, loc, b_.getI64Type(), slot, /*alignment=*/8);
    if (fr.getResult().getType() != v.getType())
      v = LLVM::TruncOp::create(b_, loc, fr.getResult().getType(), v);
    bind(fr.getResult(), v);
    return success();
  }
  // kprobe/uprobe arguments read raw eight-byte ABI registers and truncate.
  // Uprobe type correctness is separately matched against binary DWARF.
  if (auto ua = dyn_cast<UprobeArgOp>(op)) {
    auto prog = ua->getParentOfType<ProgramOp>();
    if (!prog || !prog.getArch())
      return ua.emitOpError() << "must be inside a uprobe program with `arch`";
    const bpfabi::KprobeArgABI *k = bpfabi::lookupKprobeArg(*prog.getArch(), static_cast<int>(ua.getN()));
    if (!k)
      return ua.emitOpError() << "argument " << ua.getN() << " has no register on arch \"" << *prog.getArch()
                              << "\" (the UAPI table has " << bpfabi::kprobeArgCount(*prog.getArch()) << ")";
    auto a = bpfabi::KprobeArgOp::create(b_, loc, b_.getI64Type(), remap(ua.getCtx()), b_.getStringAttr(*prog.getArch()),
                                         b_.getI64IntegerAttr(ua.getN()), b_.getI64IntegerAttr(k->offset),
                                         b_.getI64IntegerAttr(k->bytes));
    Value v = a.getResult();
    // user_str carries raw 64-bit register bits only for helper ARG_ANYTHING.
    if (!isa<UserStrType, UserBufType>(ua.getResult().getType()) && ua.getResult().getType() != v.getType())
      v = LLVM::TruncOp::create(b_, loc, ua.getResult().getType(), v);
    bind(ua.getResult(), v);
    return success();
  }
  if (auto ka = dyn_cast<KprobeArgOp>(op)) {
    auto prog = ka->getParentOfType<ProgramOp>();
    if (!prog || !prog.getArch())
      return ka.emitOpError() << "must be inside a kprobe program with `arch`";
    const bpfabi::KprobeArgABI *k = bpfabi::lookupKprobeArg(*prog.getArch(), static_cast<int>(ka.getN()));
    if (!k)
      return ka.emitOpError() << "argument " << ka.getN() << " has no register on arch \"" << *prog.getArch()
                              << "\" (the UAPI table has " << bpfabi::kprobeArgCount(*prog.getArch()) << ")";
    auto a = bpfabi::KprobeArgOp::create(b_, loc, b_.getI64Type(), remap(ka.getCtx()), b_.getStringAttr(*prog.getArch()),
                                         b_.getI64IntegerAttr(ka.getN()), b_.getI64IntegerAttr(k->offset),
                                         b_.getI64IntegerAttr(k->bytes));
    Value v = a.getResult();
    if (ka.getResult().getType() != v.getType())
      v = LLVM::TruncOp::create(b_, loc, ka.getResult().getType(), v);
    bind(ka.getResult(), v);
    return success();
  }
  // Each bounded loop has a dedicated unread i64 stack slot. Store the
  // zero-extended IV there volatile at each iteration. On 7.1.8 without
  // CAP_PERFMON, nospec_result ends the speculative path at this store.
  if (auto sp = dyn_cast<LoopSpillOp>(op)) {
    Type i64 = b_.getI64Type();
    Value slot = allocaFor(i64, loc);
    Value v = LLVM::ZExtOp::create(b_, loc, i64, remap(sp.getIv()));
    LLVM::StoreOp::create(b_, loc, v, slot, /*alignment=*/8, /*isVolatile=*/true);
    return success();
  }
  // one dedicated entry-block slot per expanded iterator — the size
  // of struct bpf_iter_num from the UAPI table, align 8, and no lifetime
  // markers, so stack coloring cannot share it with a spill slot (the
  // verifier tracks the iterator state in these stack slots). new's status is
  // discarded: a failed iterator's next returns NULL.
  if (auto ib = dyn_cast<IterNumBeginOp>(op)) {
    std::optional<int64_t> size = bpfabi::lookupUapiStructSize("bpf_iter_num");
    if (!size || *size <= 0 || *size % 8 != 0)
      return ib.emitOpError() << "struct bpf_iter_num has no usable size in the UAPI table (uapistruct row)";
    Value slot;
    {
      OpBuilder::InsertionGuard g(b_);
      b_.setInsertionPointToStart(entry_);
      Value one = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(1));
      slot = LLVM::AllocaOp::create(b_, loc, ctx_.ptrTy(), LLVM::LLVMArrayType::get(b_.getI64Type(), *size / 8), one,
                                    /*alignment=*/8);
    }
    bpfabi::KfuncCallOp::create(b_, loc, TypeRange{b_.getI32Type()}, b_.getStringAttr("bpf_iter_num_new"), UnitAttr(),
                                ValueRange{slot, remap(ib.getLo()), remap(ib.getHi())});
    bind(ib.getSlot(), slot);
    return success();
  }
  // next (KF_RET_NULL) → NULL test; the present edge loads the i32 index.
  if (auto nb = dyn_cast<IterNumNextBrOp>(op)) {
    auto p = bpfabi::KfuncCallOp::create(b_, loc, TypeRange{ctx_.ptrTy()}, b_.getStringAttr("bpf_iter_num_next"), b_.getUnitAttr(),
                                         ValueRange{remap(nb.getSlot())});
    Value null = LLVM::ZeroOp::create(b_, loc, ctx_.ptrTy());
    Value present = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ne, p.getResult(0), null);
    Block *cur = b_.getInsertionBlock();
    auto *load = new Block();
    func_.getBody().getBlocks().insert(std::next(cur->getIterator()), load);
    LLVM::CondBrOp::create(b_, loc, present, load, ValueRange{}, blocks_[nb.getExit()], ValueRange{});
    b_.setInsertionPointToEnd(load);
    Value idx = LLVM::LoadOp::create(b_, loc, b_.getI32Type(), p.getResult(0), /*alignment=*/4);
    LLVM::BrOp::create(b_, loc, ValueRange{idx}, blocks_[nb.getBody()]);
    return success();
  }
  if (auto ie = dyn_cast<IterNumEndOp>(op)) {
    bpfabi::KfuncCallOp::create(b_, loc, TypeRange{}, b_.getStringAttr("bpf_iter_num_destroy"), UnitAttr(),
                                ValueRange{remap(ie.getSlot())});
    return success();
  }
  // the DSQ iterator — the same dedicated slot rule (struct
  // bpf_iter_scx_dsq from the UAPI table), flags 0, and next's task passed to
  // the body on the present edge.
  if (auto ib = dyn_cast<IterScxDsqBeginOp>(op)) {
    std::optional<int64_t> size = bpfabi::lookupUapiStructSize("bpf_iter_scx_dsq");
    if (!size || *size <= 0 || *size % 8 != 0)
      return ib.emitOpError() << "struct bpf_iter_scx_dsq has no usable size in the UAPI table (uapistruct row)";
    Value slot;
    {
      OpBuilder::InsertionGuard g(b_);
      b_.setInsertionPointToStart(entry_);
      Value one = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(1));
      slot = LLVM::AllocaOp::create(b_, loc, ctx_.ptrTy(), LLVM::LLVMArrayType::get(b_.getI64Type(), *size / 8), one,
                                    /*alignment=*/8);
    }
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(0));
    bpfabi::KfuncCallOp::create(b_, loc, TypeRange{b_.getI32Type()}, b_.getStringAttr("bpf_iter_scx_dsq_new"), UnitAttr(),
                                ValueRange{slot, remap(ib.getDsqId()), flags});
    bind(ib.getSlot(), slot);
    return success();
  }
  if (auto nb = dyn_cast<IterScxDsqNextBrOp>(op)) {
    auto p = bpfabi::KfuncCallOp::create(b_, loc, TypeRange{ctx_.ptrTy()}, b_.getStringAttr("bpf_iter_scx_dsq_next"), b_.getUnitAttr(),
                                         ValueRange{remap(nb.getSlot())});
    Value null = LLVM::ZeroOp::create(b_, loc, ctx_.ptrTy());
    Value present = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ne, p.getResult(0), null);
    // The task crosses into the body only below the non-null edge (③ exit check: a use dominated by that edge).
    Block *cur = b_.getInsertionBlock();
    auto *edge = new Block();
    func_.getBody().getBlocks().insert(std::next(cur->getIterator()), edge);
    LLVM::CondBrOp::create(b_, loc, present, edge, ValueRange{}, blocks_[nb.getExit()], ValueRange{});
    b_.setInsertionPointToEnd(edge);
    LLVM::BrOp::create(b_, loc, ValueRange{p.getResult(0)}, blocks_[nb.getBody()]);
    return success();
  }
  if (auto ie = dyn_cast<IterScxDsqEndOp>(op)) {
    bpfabi::KfuncCallOp::create(b_, loc, TypeRange{}, b_.getStringAttr("bpf_iter_scx_dsq_destroy"), UnitAttr(),
                                ValueRange{remap(ie.getSlot())});
    return success();
  }
  // the RCU section's lock / unlock.
  if (isa<RcuLockOp, RcuUnlockOp>(op)) {
    bpfabi::KfuncCallOp::create(b_, loc, TypeRange{}, b_.getStringAttr(isa<RcuLockOp>(op) ? "bpf_rcu_read_lock" : "bpf_rcu_read_unlock"),
                                UnitAttr(), ValueRange{});
    return success();
  }
  // fixed byte copy from the direct tracepoint context; no helper or CO-RE.
  if (auto tc = dyn_cast<TpFieldCopyOp>(op)) {
    auto t = ctx_.recordTemplate(&op, tc.getDstRecord().getSymbol(), tc.getPath());
    auto n = tc->getAttrOfType<IntegerAttr>("ebpf.tp_array_count");
    if (failed(t))
      return failure();
    if (!n || n.getInt() < 1 || n.getInt() > 64 || t->dims.size() != 1 || t->bits != 8 ||
        t->dims[0].count != static_cast<uint64_t>(n.getInt()) || tc.getOffset() + n.getInt() > bpfabi::kTracepointMaxCtx)
      return tc.emitOpError("needs matching schema-checked source and destination byte arrays");
    for (int64_t i = 0; i < n.getInt(); ++i) {
      Value s = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(tc.getCtx()),
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(tc.getOffset() + i)});
      Value v = LLVM::LoadOp::create(b_, loc, b_.getI8Type(), s, 1, /*isVolatile=*/true);
      Value d = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(tc.getDst()),
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(t->offsetBytes + i)});
      LLVM::StoreOp::create(b_, loc, v, d, 1);
    }
    return success();
  }
  // Copy N bytes from CO-RE field address through N volatile byte loads/stores.
  if (auto kc = dyn_cast<KFieldCopyOp>(op)) {
    auto base = cast<KPtrType>(kc.getPtr().getType());
    RecordType rt = kc.getDstRecord(); // Borrowed and reserved record destinations both lower to pointers.
    FailureOr<RecordTemplate> t = ctx_.recordTemplate(&op, rt.getSymbol(), kc.getPath());
    if (failed(t))
      return failure();
    if (t->dims.size() != 1 || t->bits != 8)
      return kc.emitOpError() << "destination \"" << kc.getPath() << "\" is not a one-dimensional array of 8-bit integers";
    int64_t n = static_cast<int64_t>(t->dims[0].count);
    auto src = bpfabi::CoreFieldAddrOp::create(b_, loc, ctx_.ptrTy(), remap(kc.getPtr()),
                                               b_.getStringAttr(base.getStructName()), kc.getFieldAttr());
    copyGuards(&op, src);
    for (int64_t i = 0; i < n; ++i) {
      Value s = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), src.getResult(),
                                    ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(i)});
      Value v = LLVM::LoadOp::create(b_, loc, b_.getI8Type(), s, 1, /*isVolatile=*/true);
      Value d = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(kc.getDst()),
                                    ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(t->offsetBytes + i)});
      LLVM::StoreOp::create(b_, loc, v, d, 1);
    }
    return success();
  }
  // Store one declared-width volatile integer at the CO-RE field-address marker.
  if (auto ks = dyn_cast<KFieldStoreOp>(op)) {
    if (ks.getField().contains('.')) return ks.emitOpError("nested kernel stores are not supported");
    auto base = cast<KPtrType>(ks.getPtr().getType());
    auto addr = bpfabi::CoreFieldAddrOp::create(b_, loc, ctx_.ptrTy(), remap(ks.getPtr()),
                                                b_.getStringAttr(base.getStructName()), ks.getFieldAttr());
    copyGuards(&op, addr);
    unsigned bytes = cast<IntegerType>(ks.getValue().getType()).getWidth() / 8;
    LLVM::StoreOp::create(b_, loc, remap(ks.getValue()), addr.getResult(), bytes, /*isVolatile=*/true);
    return success();
  }
  if (auto addr = dyn_cast<KPtrAddrOp>(op)) {
    Value value = LLVM::PtrToIntOp::create(b_, loc, b_.getI64Type(), remap(addr.getPtr()));
    bind(addr.getResult(), value);
    return success();
  }
  if (auto kp = dyn_cast<KFieldPtrOp>(op)) { // Nullable pointer result was guarded by expanded kptr.check.
    auto r = bpfabi::CoreFieldLoadOp::create(b_, loc, ctx_.ptrTy(), remap(kp.getPtr()),
                                             b_.getStringAttr(kp.getBaseStructName()), kp.getFieldAttr()); // kptr or kref base.
    copyGuards(&op, r);
    bind(kp.getResult(), r.getResult());
    return success();
  }
  // kfunc_call carries name/arguments. Owned-reference results become pointers;
  // integer results remain integers. ABI ret_null sets ret_nullable.
  if (auto kc = dyn_cast<KfuncCallOp>(op)) {
    const bpfabi::KfuncABI *k = bpfabi::lookupKfunc(kc.getCallee());
    if (!k)
      return kc.emitOpError() << "kfunc \"" << kc.getCallee() << "\" is not in the UAPI table";
    // a bool result is the kernel's one-byte value (mark_reg_unknown —
    // only r0's low byte is defined): call as i8, then compare with 0.
    bool boolRet = StringRef(k->ret) == "bool";
    SmallVector<Type> resTys;
    for (Type t : kc.getResultTypes())
      resTys.push_back(boolRet ? Type(b_.getI8Type()) : convertType(t));
    bool nullable = StringRef(k->ret).starts_with("*") && k->hasFlag("ret_null");
    auto call = bpfabi::KfuncCallOp::create(b_, loc, resTys, kc.getCalleeAttr(), nullable ? b_.getUnitAttr() : UnitAttr(),
                                            remapAll(kc.getArgs()));
    for (auto [from, to] : llvm::zip(kc.getResults(), call.getResults())) {
      if (boolRet) {
        Value zero = LLVM::ConstantOp::create(b_, loc, b_.getI8Type(), b_.getI8IntegerAttr(0));
        bind(from, LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ne, to, zero));
        continue;
      }
      bind(from, to);
    }
    return success();
  }
  // kptr.load_rcu is one volatile 8-byte load of the field (MEM_RCU in the section).
  if (auto lr = dyn_cast<KPtrLoadRcuOp>(op)) {
    auto rt = cast<RecordType>(cast<BorrowedType>(lr.getRef().getType()).getPointee());
    FailureOr<int64_t> off = ctx_.kptrOffset(&op, rt.getSymbol(), lr.getField());
    if (failed(off))
      return failure();
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(lr.getRef()),
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(*off)});
    Value p = LLVM::LoadOp::create(b_, loc, ctx_.ptrTy(), at, /*alignment=*/8, /*isVolatile=*/true);
    bind(lr.getPtr(), p);
    return success();
  }
  // kptr_xchg takes borrowed-record address+field offset and a new ref/null;
  // return is the previous nullable owned reference.
  if (auto x = dyn_cast<KPtrXchgOp>(op)) {
    auto rt = cast<RecordType>(cast<BorrowedType>(x.getRef().getType()).getPointee());
    FailureOr<int64_t> off = ctx_.kptrOffset(&op, rt.getSymbol(), x.getField());
    if (failed(off))
      return failure();
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(x.getRef()),
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(*off)});
    Value nv = x.getNewRef() ? remap(x.getNewRef()) : Value(LLVM::ZeroOp::create(b_, loc, ctx_.ptrTy()));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "kptr_xchg", {at, nv});
    if (failed(r))
      return failure();
    bind(x.getOld(), *r);
    return success();
  }
  // the kptr global ops use the global's address (BPF_PSEUDO_MAP_VALUE —
  // the verifier's PTR_TO_MAP_VALUE) as the kptr field ops use a field address.
  if (auto x = dyn_cast<GlobalKPtrXchgOp>(op)) {
    LLVM::GlobalOp g = ctx_.globalVar(x.getName(), ctx_.ptrTy(), loc);
    if (!g)
      return failure();
    Value at = LLVM::AddressOfOp::create(b_, loc, g);
    Value nv = x.getNewRef() ? remap(x.getNewRef()) : Value(LLVM::ZeroOp::create(b_, loc, ctx_.ptrTy()));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "kptr_xchg", {at, nv});
    if (failed(r))
      return failure();
    bind(x.getOld(), *r);
    return success();
  }
  if (auto lr = dyn_cast<GlobalKPtrLoadRcuOp>(op)) {
    LLVM::GlobalOp g = ctx_.globalVar(lr.getName(), ctx_.ptrTy(), loc);
    if (!g)
      return failure();
    Value at = LLVM::AddressOfOp::create(b_, loc, g);
    bind(lr.getPtr(), LLVM::LoadOp::create(b_, loc, ctx_.ptrTy(), at, /*alignment=*/8, /*isVolatile=*/true));
    return success();
  }
  if (auto ld = dyn_cast<KFieldLoadOp>(op)) {
    Type pt = ld.getPtr().getType(); // Acquired kref reads share the same lowering.
    StringRef sname = isa<KRefType>(pt) ? cast<KRefType>(pt).getStructName() : isa<RcuPtrType>(pt) ? cast<RcuPtrType>(pt).getStructName() : cast<KPtrType>(pt).getStructName(); // rcu_ptr reads too.
    auto r = bpfabi::CoreFieldLoadOp::create(
        b_, loc, ld.getResult().getType(), remap(ld.getPtr()),
        b_.getStringAttr(sname), ld.getFieldAttr());
    copyGuards(&op, r); // guards of the kfield row (marker suffix at ④).
    bind(ld.getResult(), r.getResult());
    return success();
  }

  // u32 index and raw i64 status, including negative errno; values come from ABI.
  if (auto cg = dyn_cast<TaskUnderCgroupOp>(op)) {
    Value index = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(cg.getIndex()));
    FailureOr<Value> st = ctx_.helperCall(b_, loc, "current_task_under_cgroup", {remap(cg.getMap()), index});
    if (failed(st))
      return failure();
    bind(cg.getStatus(), *st);
    return success();
  }
  if (auto cg = dyn_cast<SkbUnderCgroupOp>(op)) {
    Value index = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(cg.getIndex()));
    FailureOr<Value> st = ctx_.helperCall(b_, loc, "skb_under_cgroup", {remap(cg.getCtx()), remap(cg.getMap()), index});
    if (failed(st))
      return failure();
    bind(cg.getStatus(), *st);
    return success();
  }

  if (auto s = dyn_cast<SockMapLookupOp>(op)) {
    Value key = spillKey(remap(s.getKey()), loc);
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "map_lookup_elem", {remap(s.getMap()), key});
    if (failed(r)) return failure();
    endSpills(loc);
    bind(s.getResult(), *r);
    return success();
  }
  // sk_lookup_tcp / _udp(ctx, tuple, size, netns, 0). The helper only
  // reads the tuple, so the record.make stack slot is passed without a copy.
  // size is the declared record size (ebpf-verify-records proved the view).
  if (isa<SockLookupTcpOp, SockLookupUdpOp, SockSkcLookupTcpOp>(op)) {
    std::optional<int64_t> netns = bpfabi::lookupSkLookupNetns("current_netns");
    if (!netns)
      return op.emitOpError() << "sklookupnetns current_netns missing from UAPI table";
    Value tuple = op.getOperand(1);
    int64_t size = cast<RecordType>(tuple.getType()).getSize();
    Value len = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(size));
    Value ns = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(*netns));
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(0));
    StringRef helper = isa<SockLookupTcpOp>(op) ? "sk_lookup_tcp" : isa<SockSkcLookupTcpOp>(op) ? "skc_lookup_tcp" : "sk_lookup_udp";
    FailureOr<Value> r = ctx_.helperCall(b_, loc, helper, {remap(op.getOperand(0)), remap(tuple), len, ns, flags});
    if (failed(r))
      return failure();
    bind(op.getResult(0), *r);
    return success();
  }
  if (auto s = dyn_cast<SockReleaseOp>(op))
    return failed(ctx_.helperCall(b_, loc, "sk_release", {remap(s.getPtr())})) ? failure() : success();
  // sk_assign returns raw status; flags combine ABI replace/no_reuseport bits.
  if (auto sa = dyn_cast<SkAssignOp>(op)) {
    int64_t fl = 0;
    for (auto [set, name] : {std::pair<bool, StringRef>{sa.getReplace(), "replace"}, {sa.getNoReuseport(), "no_reuseport"}}) {
      if (!set)
        continue;
      std::optional<int64_t> c = bpfabi::lookupSkLookupFlag(name);
      if (!c)
        return sa.emitOpError() << "sk_lookup flag \"" << name << "\" is not in the UAPI table";
      fl |= *c;
    }
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(fl));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "sk_assign", {remap(sa.getCtx()), remap(sa.getSock()), flags});
    if (failed(r))
      return failure();
    bind(sa.getStatus(), *r);
    return success();
  }
  // sys.bpf uses ABI command, stack-record address/size; sys.close takes FD.
  // Both return raw status.
  if (auto sb = dyn_cast<SysBpfOp>(op)) {
    std::optional<int64_t> cmd = bpfabi::lookupBpfCmd(sb.getCmd());
    if (!cmd)
      return sb.emitOpError() << "bpf cmd \"" << sb.getCmd() << "\" is not in the UAPI table";
    auto rt = cast<RecordType>(sb.getAttr().getType());
    Value c = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(*cmd));
    Value len = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(rt.getSize()));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "sys_bpf", {c, remap(sb.getAttr()), len});
    if (failed(r))
      return failure();
    bind(sb.getStatus(), *r);
    return success();
  }
  if (auto sc = dyn_cast<SysCloseOp>(op)) {
    Value fd = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(sc.getFd()));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "sys_close", {fd});
    if (failed(r))
      return failure();
    bind(sc.getStatus(), *r);
    return success();
  }
  if (isa<DevmapLookupOp, XskLookupOp>(op)) {
    Value key = spillKey(remap(op.getOperand(1)), loc);
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "map_lookup_elem", {remap(op.getOperand(0)), key});
    if (failed(r)) return failure();
    endSpills(loc);
    Value null = LLVM::ZeroOp::create(b_, loc, ctx_.ptrTy());
    Value present = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ne, *r, null);
    if (auto x = dyn_cast<XskLookupOp>(op)) {
      bind(x.getPresent(), present);
    } else {
      auto d = cast<DevmapLookupOp>(op);
      auto *have = new Block();
      auto *cont = new Block();
      func_.getBody().push_back(have);
      func_.getBody().push_back(cont);
      Value val = cont->addArgument(b_.getI32Type(), loc);
      Value zero = LLVM::ConstantOp::create(b_, loc, b_.getI32Type(), b_.getI32IntegerAttr(0));
      LLVM::CondBrOp::create(b_, loc, present, have, ValueRange{}, cont, ValueRange{zero});
      b_.setInsertionPointToStart(have);
      Value ifindex = LLVM::LoadOp::create(b_, loc, b_.getI32Type(), *r, 4);
      LLVM::BrOp::create(b_, loc, ValueRange{ifindex}, cont);
      b_.setInsertionPointToStart(cont);
      bind(d.getIfindex(), val);
      bind(d.getPresent(), present);
    }
    return success();
  }

  if (auto lookup = dyn_cast<MapLookupOp>(op)) {
    Value m = remap(lookup.getMap());
    // Record keys use record.make storage directly, without another spill.
    Value keyPtr = isa<RecordType>(lookup.getKey().getType()) ? remap(lookup.getKey())
                                                               : spillKey(remap(lookup.getKey()), loc);
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "map_lookup_elem", {m, keyPtr});
    if (failed(r))
      return failure();
    endSpills(loc);
    bind(lookup.getResult(), *r);
    return success();
  }

  // Storage get uses map/owner/NULL initial value/ABI create flags; creation
  // zero-fills values. Delete uses map/owner. Helper names follow kind_get/delete.
  if (auto sg = dyn_cast<StorageGetOp>(op)) {
    StringRef kind = cast<MapType>(sg.getMap().getType()).getKind();
    int64_t fl = 0;
    if (sg.getCreateIfMissing()) {
      std::optional<int64_t> c = bpfabi::lookupStorageFlag("create");
      if (!c)
        return sg.emitOpError() << "storage flag \"create\" (BPF_LOCAL_STORAGE_GET_F_CREATE) is not in the UAPI table";
      fl = *c;
    }
    Value null = LLVM::ZeroOp::create(b_, loc, ctx_.ptrTy());
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(fl));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, (kind + "_get").str(), {remap(sg.getMap()), remap(sg.getOwner()), null, flags});
    if (failed(r))
      return failure();
    bind(sg.getResult(), *r);
    return success();
  }
  // Per-CPU lookup shares ordinary key rules and zero-extends CPU index.
  // Record keys use their record.make storage directly.
  if (auto lp = dyn_cast<MapLookupPercpuOp>(op)) {
    Value keyPtr = isa<RecordType>(lp.getKey().getType()) ? remap(lp.getKey()) : spillKey(remap(lp.getKey()), loc);
    Value cpu = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(lp.getCpu()));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "map_lookup_percpu_elem", {remap(lp.getMap()), keyPtr, cpu});
    if (failed(r))
      return failure();
    endSpills(loc);
    bind(lp.getResult(), *r);
    return success();
  }
  // Keyless push/bloom.peek spill values into helper argument slots.
  if (auto push = dyn_cast<MapPushOp>(op)) {
    std::optional<int64_t> fv = bpfabi::lookupUpdateFlag(push.getFlags());
    if (!fv)
      return push.emitOpError() << "update flags \"" << push.getFlags() << "\" are not in the UAPI table";
    Value valPtr = spillInt(remap(push.getValue()), loc);
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(*fv));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "map_push_elem", {remap(push.getMap()), valPtr, flags});
    if (failed(r))
      return failure();
    endSpills(loc);
    bind(push.getStatus(), *r);
    return success();
  }
  if (auto bp = dyn_cast<BloomPeekOp>(op)) {
    Value valPtr = spillInt(remap(bp.getValue()), loc);
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "map_peek_elem", {remap(bp.getMap()), valPtr});
    if (failed(r))
      return failure();
    endSpills(loc);
    bind(bp.getStatus(), *r);
    return success();
  }
  // Zero pop/peek destinations first: kernel may return -EBUSY without
  // writing them, and failure values are defined as zero. Load afterward at
  // declared width; lifetime.end must follow that load, not just helper return.
  if (isa<MapPopOp, MapPeekOp>(op)) {
    bool pop = isa<MapPopOp>(op);
    Value mapV = pop ? cast<MapPopOp>(op).getMap() : cast<MapPeekOp>(op).getMap();
    Value status = pop ? cast<MapPopOp>(op).getStatus() : cast<MapPeekOp>(op).getStatus();
    Value value = pop ? cast<MapPopOp>(op).getValue() : cast<MapPeekOp>(op).getValue();
    Value zero = LLVM::ConstantOp::create(b_, loc, value.getType(), b_.getIntegerAttr(value.getType(), 0));
    Value slot = spillInt(zero, loc);
    FailureOr<Value> r = ctx_.helperCall(b_, loc, pop ? "map_pop_elem" : "map_peek_elem", {remap(mapV), slot});
    if (failed(r))
      return failure();
    Value v = LLVM::LoadOp::create(b_, loc, value.getType(), slot);
    endSpills(loc);
    bind(status, *r);
    bind(value, v);
    return success();
  }
  // Checked outer lookup pointers already represent CONST_PTR_TO_MAP inner handles.
  if (auto mi = dyn_cast<MapInnerOp>(op)) {
    bind(mi.getInner(), remap(mi.getRef()));
    return success();
  }
  if (auto sd = dyn_cast<StorageDeleteOp>(op)) {
    StringRef kind = cast<MapType>(sd.getMap().getType()).getKind();
    FailureOr<Value> r = ctx_.helperCall(b_, loc, (kind + "_delete").str(), {remap(sd.getMap()), remap(sd.getOwner())});
    if (failed(r))
      return failure();
    bind(sd.getStatus(), *r);
    return success();
  }

  // Allocate declared record size, zero every byte, then store fields at
  // declared offsets. The record value is its storage pointer.
  if (auto mk = dyn_cast<RecordMakeOp>(op)) {
    auto rt = cast<RecordType>(mk.getResult().getType());
    Value base = allocaFor(LLVM::LLVMArrayType::get(b_.getI8Type(), rt.getSize()), loc);
    cast<LLVM::AllocaOp>(base.getDefiningOp()).setAlignment(kRecordStackAlignment);
    // Elide memset only if field-store byte intervals cover all [0,size).
    // Even a one-byte gap retains full zeroing; partial-hole optimization is separate.
    SmallVector<int64_t> offs;
    for (Attribute a : mk.getFields()) {
      FailureOr<int64_t> off = ctx_.recordFieldOffset(&op, rt.getSymbol(), cast<StringAttr>(a).getValue());
      if (failed(off))
        return failure();
      offs.push_back(*off);
    }
    bool covered = false;
    if (ctx_.skipFullCoverMemset || ctx_.storeRecordDirect) {
      SmallVector<bool> byteSet(rt.getSize(), false);
      bool inRange = true;
      for (auto [off, v] : llvm::zip(offs, mk.getValues())) {
        int64_t w = v.getType().getIntOrFloatBitWidth() / 8;
        if (off < 0 || off + w > static_cast<int64_t>(rt.getSize())) {
          inRange = false;
          break;
        }
        for (int64_t i = 0; i < w; ++i)
          byteSet[off + i] = true;
      }
      covered = inRange && llvm::all_of(byteSet, [](bool b) { return b; });
    }
    // Direct-store tuning omits stack only for full-byte coverage and a sole
    // store_record use. Remember already-computed field values and emit their
    // stores at the reservation consumer instead.
    if (ctx_.storeRecordDirect && covered && mk.getResult().hasOneUse()) {
      auto sr = dyn_cast<RingbufStoreRecordOp>(*mk.getResult().getUsers().begin());
      if (sr && sr.getValue() == mk.getResult()) {
        cast<LLVM::AllocaOp>(base.getDefiningOp()).erase();
        auto &fs = directRecords_[mk.getResult()];
        auto &cs = directConsts_[mk.getResult()];
        for (auto [off, v] : llvm::zip(offs, mk.getValues())) {
          fs.push_back({off, remap(v)});
          APInt c;
          if (matchPattern(v, m_ConstantInt(&c)))
            cs.push_back(std::make_pair(c, v.getType().getIntOrFloatBitWidth() / 8));
          else
            cs.push_back(std::nullopt);
        }
        return success();
      }
    }
    if (!ctx_.skipFullCoverMemset)
      covered = false;
    if (!covered) {
      Value zero = LLVM::ConstantOp::create(b_, loc, b_.getI8Type(), b_.getI8IntegerAttr(0));
      Value len = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(rt.getSize()));
      LLVM::MemsetOp::create(b_, loc, base, zero, len, /*isVolatile=*/false);
    }
    for (auto [off, v] : llvm::zip(offs, mk.getValues())) {
      Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), base,
                                     ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(off)});
      LLVM::StoreOp::create(b_, loc, remap(v), at,
                            provableAlignment(kRecordStackAlignment, off, v.getType()));
    }
    bind(mk.getResult(), base);
    return success();
  }

  // Discard map_delete_elem status for resultless delete.
  if (auto del = dyn_cast<MapDeleteOp>(op)) {
    Value m = remap(del.getMap());
    Value keyPtr = isa<RecordType>(del.getKey().getType()) ? remap(del.getKey())
                                                            : spillKey(remap(del.getKey()), loc);
    if (failed(ctx_.helperCall(b_, loc, "map_delete_elem", {m, keyPtr})))
      return failure();
    endSpills(loc);
    return success();
  }

  // Result-bearing delete/update return helper i64 status; update flags come from ABI.
  if (auto del = dyn_cast<MapTryDeleteOp>(op)) {
    Value m = remap(del.getMap());
    Value keyPtr = isa<RecordType>(del.getKey().getType()) ? remap(del.getKey())
                                                            : spillKey(remap(del.getKey()), loc);
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "map_delete_elem", {m, keyPtr});
    if (failed(r))
      return failure();
    endSpills(loc);
    bind(del.getStatus(), *r);
    return success();
  }

  if (auto upd = dyn_cast<MapTryUpdateOp>(op)) {
    std::optional<int64_t> fv = bpfabi::lookupUpdateFlag(upd.getFlags());
    if (!fv)
      return upd.emitOpError() << "update flags \"" << upd.getFlags() << "\" are not in the UAPI table";
    Value m = remap(upd.getMap());
    Value keyPtr = isa<RecordType>(upd.getKey().getType()) ? remap(upd.getKey())
                                                            : spillKey(remap(upd.getKey()), loc);
    Value valPtr = isa<RecordType>(upd.getValue().getType()) ? remap(upd.getValue())
                                                              : spillInt(remap(upd.getValue()), loc);
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(*fv));
    FailureOr<Value> r = ctx_.helperCall(b_, loc, "map_update_elem", {m, keyPtr, valPtr, flags});
    if (failed(r))
      return failure();
    endSpills(loc);
    bind(upd.getStatus(), *r);
    return success();
  }

  if (auto update = dyn_cast<MapUpdateOp>(op)) {
    Value m = remap(update.getMap());
    Value keyPtr = isa<RecordType>(update.getKey().getType()) ? remap(update.getKey())
                                                               : spillKey(remap(update.getKey()), loc);
    // Record values use record.make storage directly, without spilling again.
    Value valPtr = isa<RecordType>(update.getValue().getType()) ? remap(update.getValue())
                                                                 : spillInt(remap(update.getValue()), loc);
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(),
                                           b_.getI64IntegerAttr(0));
    if (failed(ctx_.helperCall(b_, loc, "map_update_elem",
                               {m, keyPtr, valPtr, flags})))
      return failure();
    endSpills(loc);
    return success();
  }

  if (auto load = dyn_cast<RefLoadOp>(op)) {
    Type t = load.getResult().getType();
    unsigned align = provableAlignment(bpfabi::kMapValueAlignment, 0, t);
    if (failed(checkOnce(&op, load.getOnce(), align, t)))
      return failure();
    Value v = LLVM::LoadOp::create(b_, loc, t, remap(load.getRef()), align, /*isVolatile=*/load.getOnce());
    bind(load.getResult(), v);
    return success();
  }

  // @records owns field offsets/widths; never recompute schema layout.
  // Variable indices share the same zero-extended value for bounds and
  // base+offset+index*stride addresses.
  if (isa<ElemInRangeOp, ElemAtOp, ElemMaskOp>(op)) {
    bool isTest = isa<ElemInRangeOp>(op);
    Value ref = op.getOperand(0);
    StringRef field = isTest ? cast<ElemInRangeOp>(op).getField()
                      : isa<ElemMaskOp>(op) ? cast<ElemMaskOp>(op).getField()
                                            : cast<ElemAtOp>(op).getField();
    auto rt = cast<RecordType>(cast<BorrowedType>(ref.getType()).getPointee());
    FailureOr<RecordTemplate> t = ctx_.recordTemplate(&op, rt.getSymbol(), field);
    if (failed(t))
      return failure();
    if (auto test = dyn_cast<ElemInRangeOp>(op)) {
      uint64_t k = test.getDim().value_or(0);
      Value n = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(t->dims[k].count));
      bind(op.getResult(0), LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ult, remap(test.getIndex()), n));
      return success();
    }
    // elem.mask uses instruction-free inline-asm barrier '=r,0' followed by
    // and with the smallest 2^k-1 covering count. Prevent LLVM known-bits
    // elimination without changing checked-edge values; expansion rechecks it.
    if (auto mk = dyn_cast<ElemMaskOp>(op)) {
      uint64_t c = t->dims[mk.getDim().value_or(0)].count, p = 1;
      while (p < c)
        p <<= 1;
      auto i64 = b_.getI64Type();
      Value v = LLVM::InlineAsmOp::create(b_, loc, i64, ValueRange{remap(mk.getIndex())}, "", "=r,0", /*has_side_effects=*/true,
                                          /*is_align_stack=*/false, LLVM::tailcallkind::TailCallKind::None,
                                          /*asm_dialect=*/LLVM::AsmDialectAttr(), /*operand_attrs=*/ArrayAttr())
                    .getResult(0);
      bind(mk.getResult(), LLVM::AndOp::create(b_, loc, v, LLVM::ConstantOp::create(b_, loc, i64, b_.getI64IntegerAttr(p - 1))));
      return success();
    }
    auto atOp = cast<ElemAtOp>(op);
    // Mask guarantees hold only when its full range fits the map value. If
    // recheck narrowing is lost through spills, 6.6 may reject larger ranges.
    // Warn factually when it does not fit; do not reject compilation.
    if (ctx_.warnIndexMaskFit && !atOp.getIndices().empty() && atOp.getIndices()[0].getDefiningOp<ElemMaskOp>()) {
      uint64_t reach = t->offsetBytes + (t->elemRecord.empty() ? t->bits / 8 : t->elemBytes);
      for (auto [k, d] : llvm::enumerate(t->dims)) {
        uint64_t p = 1;
        while (p < d.count)
          p <<= 1;
        reach += (p - 1) * d.strideBytes;
      }
      if (reach > static_cast<uint64_t>(rt.getSize()))
        mlir::emitWarning(loc) << "the mask range of this ebpf.ref.index (\"" << field << "\", up to byte " << reach
                               << ") reaches past the " << rt.getSize()
                               << "-byte record, so avoiding the non-root speculative-path rejection depends on register "
                                  "allocation; leaving room after the array up to the next power of two in the schema "
                                  "record puts it in the guaranteed range";
    }
    // a borrowed base's alignment (8 for a map value or a global; an
    // element borrow records its own in borrowAlign_).
    unsigned baseAlign = borrowAlign(remap(ref));
    Value cur = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(ref),
                                    ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(t->offsetBytes)});
    // a record-array element is borrowed at offset + index × stride
    // (@records); its alignment is what the base, the offset and the stride prove.
    if (!t->elemRecord.empty()) {
      unsigned a = baseAlign;
      while (a > 1 && t->offsetBytes % a != 0)
        a /= 2;
      for (auto [k, izv] : llvm::enumerate(atOp.getIndices())) {
        int64_t stride = t->dims[k].strideBytes;
        Value s = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(stride));
        Value off = LLVM::MulOp::create(b_, loc, remap(izv), s);
        cur = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), cur, ArrayRef<LLVM::GEPArg>{off});
        while (a > 1 && stride % a != 0)
          a /= 2;
      }
      borrowAlign_[cur] = a;
      bind(op.getResult(0), cur);
      return success();
    }
    Type et = b_.getIntegerType(t->bits);
    // Constant offset proves alignment up to width. Index offsets preserve it
    // only when each stride is a multiple of that alignment.
    unsigned align = provableAlignment(baseAlign, t->offsetBytes, et);
    for (auto [k, izv] : llvm::enumerate(atOp.getIndices())) {
      int64_t stride = t->dims[k].strideBytes;
      Value iz = remap(izv);
      // Simple one-dimensional integer arrays use typed GEP; others use byte GEP
    // with index*stride.
      if (stride * 8 == static_cast<int64_t>(t->bits)) {
        cur = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), et, cur, ArrayRef<LLVM::GEPArg>{iz});
      } else {
        Value s = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(stride));
        Value off = LLVM::MulOp::create(b_, loc, iz, s);
        cur = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), cur, ArrayRef<LLVM::GEPArg>{off});
      }
      while (align > 1 && stride % align != 0)
        align /= 2;
    }
    elemAlign_[cur] = align;
    bind(op.getResult(0), cur);
    return success();
  }

  if (auto el = dyn_cast<ElemLoadOp>(op)) {
    Value at = remap(el.getElem());
    if (failed(checkOnce(&op, el.getOnce(), elemAlign_.lookup(at), el.getResult().getType())))
      return failure();
    bind(el.getResult(), LLVM::LoadOp::create(b_, loc, el.getResult().getType(), at, elemAlign_.lookup(at), el.getOnce()));
    return success();
  }

  if (auto es = dyn_cast<ElemStoreOp>(op)) {
    Value at = remap(es.getElem());
    if (failed(checkOnce(&op, es.getOnce(), elemAlign_.lookup(at), es.getValue().getType())))
      return failure();
    LLVM::StoreOp::create(b_, loc, remap(es.getValue()), at, elemAlign_.lookup(at), es.getOnce());
    return success();
  }

  if (isa<RefFieldLoadOp, RefFieldStoreOp>(op)) {
    bool isLoad = isa<RefFieldLoadOp>(op);
    Value ref = isLoad ? cast<RefFieldLoadOp>(op).getRef() : cast<RefFieldStoreOp>(op).getRef();
    StringRef field = isLoad ? cast<RefFieldLoadOp>(op).getField() : cast<RefFieldStoreOp>(op).getField();
    auto rt = cast<RecordType>(cast<BorrowedType>(ref.getType()).getPointee());
    FailureOr<int64_t> off = ctx_.recordFieldOffset(&op, rt.getSymbol(), field);
    if (failed(off))
      return failure();
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(ref),
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(*off)});
    if (isLoad) {
      auto ld = cast<RefFieldLoadOp>(op);
      Type t = ld.getResult().getType();
      unsigned align = provableAlignment(borrowAlign(remap(ref)), *off, t);
      if (failed(checkOnce(&op, ld.getOnce(), align, t)))
        return failure();
      Value v = LLVM::LoadOp::create(b_, loc, t, at, align, /*isVolatile=*/ld.getOnce());
      bind(ld.getResult(), v);
    } else {
      auto st = cast<RefFieldStoreOp>(op);
      Type t = st.getValue().getType();
      unsigned align = provableAlignment(borrowAlign(remap(ref)), *off, t);
      if (failed(checkOnce(&op, st.getOnce(), align, t)))
        return failure();
      LLVM::StoreOp::create(b_, loc, remap(st.getValue()), at, align, /*isVolatile=*/st.getOnce());
    }
    return success();
  }

  // the address of an embedded cpumask — the borrow plus the @records offset.
  if (auto fa = dyn_cast<RefFieldAddrOp>(op)) {
    auto rt = cast<RecordType>(cast<BorrowedType>(fa.getRef().getType()).getPointee());
    FailureOr<int64_t> off = ctx_.recordFieldOffset(&op, rt.getSymbol(), fa.getField(), /*cpumaskLeaf=*/true);
    if (failed(off))
      return failure();
    bind(fa.getAddr(), LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(fa.getRef()),
                                           ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(*off)}));
    return success();
  }

  // Field atomic addition uses non-FETCH monotonic atomicrmw; result is unused.
  if (auto fa = dyn_cast<RefFieldAtomicAddOp>(op)) {
    Type t = fa.getDelta().getType();
    if (!t.isInteger(32) && !t.isInteger(64))
      return fa.emitOpError() << "cannot lower a " << t << " atomic add";
    auto rt = cast<RecordType>(cast<BorrowedType>(fa.getRef().getType()).getPointee());
    FailureOr<int64_t> off = ctx_.recordFieldOffset(&op, rt.getSymbol(), fa.getField());
    if (failed(off))
      return failure();
    unsigned align = provableAlignment(borrowAlign(remap(fa.getRef())), *off, t);
    if (align < t.getIntOrFloatBitWidth() / 8)
      return fa.emitOpError() << "field \"" << fa.getField() << "\" at byte offset " << *off << " is not provably aligned to "
                              << t.getIntOrFloatBitWidth() / 8 << " bytes; cannot lower an atomic add";
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(fa.getRef()),
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(*off)});
    // atomicrmw defaults to natural alignment, already established above.
    LLVM::AtomicRMWOp::create(b_, loc, LLVM::AtomicBinOp::add, at, remap(fa.getDelta()), LLVM::AtomicOrdering::monotonic);
    return success();
  }

  // field cmpxchg / or — the atomic_add address and alignment rules.
  if (isa<RefFieldCmpxchgOp, RefFieldAtomicOrOp>(op)) {
    auto cx = dyn_cast<RefFieldCmpxchgOp>(op);
    auto fo = dyn_cast<RefFieldAtomicOrOp>(op);
    Value ref = cx ? cx.getRef() : fo.getRef();
    StringRef field = cx ? cx.getField() : fo.getField();
    Type t = cx ? cx.getOld().getType() : fo.getValue().getType();
    StringRef what = cx ? "an atomic compare-and-exchange" : "an atomic or";
    if (!t.isInteger(32) && !t.isInteger(64))
      return op.emitOpError() << "cannot lower " << what << " of " << t;
    auto rt = cast<RecordType>(cast<BorrowedType>(ref.getType()).getPointee());
    FailureOr<int64_t> off = ctx_.recordFieldOffset(&op, rt.getSymbol(), field);
    if (failed(off))
      return failure();
    unsigned align = provableAlignment(borrowAlign(remap(ref)), *off, t);
    if (align < t.getIntOrFloatBitWidth() / 8)
      return op.emitOpError() << "field \"" << field << "\" at byte offset " << *off << " is not provably aligned to "
                              << t.getIntOrFloatBitWidth() / 8 << " bytes; cannot lower " << what;
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(ref), ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(*off)});
    if (cx)
      bind(cx.getOld(), atomicCmpxchg(at, remap(cx.getExpected()), remap(cx.getDesired()), loc));
    else
      atomicOr(at, remap(fo.getValue()), loc);
    return success();
  }

  if (auto rs = dyn_cast<RefStoreOp>(op)) {
    Type t = rs.getValue().getType();
    unsigned align = provableAlignment(bpfabi::kMapValueAlignment, 0, t);
    if (failed(checkOnce(&op, rs.getOnce(), align, t)))
      return failure();
    LLVM::StoreOp::create(b_, loc, remap(rs.getValue()), remap(rs.getRef()), align, /*isVolatile=*/rs.getOnce());
    return success();
  }

  if (auto add = dyn_cast<RefAtomicAddOp>(op)) {
    // Defensively enforce 32/64-bit atomic widths before unsupported backend aborts.
    if (!add.getDelta().getType().isInteger(32) && !add.getDelta().getType().isInteger(64))
      return add.emitOpError() << "cannot lower a " << add.getDelta().getType() << " atomic add";
    LLVM::AtomicRMWOp::create(b_, loc, LLVM::AtomicBinOp::add,
                              remap(add.getRef()), remap(add.getDelta()),
                              LLVM::AtomicOrdering::monotonic);
    return success();
  }

  if (auto reserve = dyn_cast<RingbufReserveOp>(op)) {
    auto resTy = cast<MaybeReservationType>(reserve.getResult().getType());
    // Reservation size is carried by integer width or nominal record size.
    // VerifySchema separately checks declarations. No silent eight-byte default.
    int64_t bytes = 0;
    if (auto it = dyn_cast<IntegerType>(resTy.getRecordType()))
      bytes = it.getWidth() / 8;
    else if (auto rt = dyn_cast<RecordType>(resTy.getRecordType()))
      bytes = rt.getSize();
    if (bytes <= 0)
      return op.emitError() << "cannot size a reservation of "
                            << resTy.getRecordType();
    LLVM::GlobalOp rbGlobal = ctx_.mapGlobal(reserve.getRingbuf(), loc);
    if (!rbGlobal)
      return failure();
    Value rb = LLVM::AddressOfOp::create(b_, loc, rbGlobal);
    Value size = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(),
                                          b_.getI64IntegerAttr(bytes));
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(),
                                           b_.getI64IntegerAttr(0));
    FailureOr<Value> r =
        ctx_.helperCall(b_, loc, "ringbuf_reserve", {rb, size, flags});
    if (failed(r))
      return failure();
    bind(reserve.getResult(), *r);
    return success();
  }

  if (auto sf = dyn_cast<RingbufStoreFieldOp>(op)) {
    Value base = remap(sf.getReservation());
    Value at = LLVM::GEPOp::create(
        b_, loc, ctx_.ptrTy(), b_.getI8Type(), base,
        ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(sf.getOffset())});
    LLVM::StoreOp::create(
        b_, loc, remap(sf.getValue()), at,
        provableAlignment(bpfabi::kRingbufSampleAlignment, sf.getOffset(),
                          sf.getValue().getType()));
    return success();
  }

  // Copy all record bytes from eight-aligned record.make storage to sample-aligned reservation.
  if (auto sr = dyn_cast<RingbufStoreRecordOp>(op)) {
    // Direct records store fields at reservation+offset with proven alignment,
    // without intermediate stack storage.
    if (auto it = directRecords_.find(sr.getValue()); it != directRecords_.end()) {
      Value res = remap(sr.getReservation());
      auto storeAt = [&](int64_t off, Value v) {
        Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), res, ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(off)});
        LLVM::StoreOp::create(b_, loc, v, at, provableAlignment(bpfabi::kRingbufSampleAlignment, off, v.getType()));
      };
      auto &fs = it->second;
      auto &cs = directConsts_[sr.getValue()];
      if (!ctx_.storeRecordMerge) {
        for (auto [off, v] : fs)
          storeAt(off, v);
        return success();
      }
      // Merge adjacent constant fields into little-endian bytes, then emit the
      // widest proven-aligned 8/4/2/1-byte stores. Keep nonconstant field order/
      // widths. Place merged stores at the first field of each constant run.
      size_t i = 0;
      while (i < fs.size()) {
        if (!cs[i]) {
          storeAt(fs[i].first, fs[i].second);
          ++i;
          continue;
        }
        int64_t start = fs[i].first, end = start;
        SmallVector<uint8_t> bytes;
        size_t j = i;
        while (j < fs.size() && cs[j] && fs[j].first == end) {
          auto [c, w] = *cs[j];
          for (unsigned k = 0; k < w; ++k)
            bytes.push_back(static_cast<uint8_t>(c.extractBitsAsZExtValue(8, 8 * k)));
          end += w;
          ++j;
        }
        int64_t off = start;
        while (off < end) {
          unsigned w = 8;
          while (w > 1 && (off % w != 0 || off + w > end || bpfabi::kRingbufSampleAlignment % w != 0))
            w /= 2;
          uint64_t val = 0;
          for (unsigned k = 0; k < w; ++k)
            val |= static_cast<uint64_t>(bytes[off - start + k]) << (8 * k);
          Type t = b_.getIntegerType(8 * w);
          storeAt(off, LLVM::ConstantOp::create(b_, loc, t, b_.getIntegerAttr(t, val)));
          off += w;
        }
        i = j;
      }
      return success();
    }
    auto rt = cast<RecordType>(sr.getValue().getType());
    Value len = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(rt.getSize()));
    auto mc = LLVM::MemcpyOp::create(b_, loc, remap(sr.getReservation()), remap(sr.getValue()), len,
                                     /*isVolatile=*/false);
    // Specify both alignments or codegen assumes one and copies bytewise.
    auto align = [&](unsigned a) {
      return b_.getDictionaryAttr(b_.getNamedAttr(LLVM::LLVMDialect::getAlignAttrName(),
                                                  b_.getI64IntegerAttr(a)));
    };
    mc.setArgAttrsAttr(b_.getArrayAttr({align(bpfabi::kRingbufSampleAlignment),
                                        align(kRecordStackAlignment), b_.getDictionaryAttr({})}));
    return success();
  }

  // bpfel uses byte swaps for both to_be/from_be, lowered to BPF_END.
  if (isa<ByteorderToBeOp, ByteorderFromBeOp>(op)) {
    Value v = remap(op.getOperand(0));
    bind(op.getResult(0), LLVM::ByteSwapOp::create(b_, loc, v.getType(), v));
    return success();
  }

  // Global loads are volatile, preventing initial-value assumptions like C const volatile.
  if (auto gl = dyn_cast<GlobalLoadOp>(op)) {
    Type t = gl.getResult().getType();
    // a bss kaddr global is an 8-byte pointer (the address as a value).
    bool kaddr = isa<KAddrType>(t);
    if (kaddr)
      t = ctx_.ptrTy();
    LLVM::GlobalOp g = ctx_.globalVar(gl.getName(), t, loc);
    if (!g)
      return failure();
    Value addr = LLVM::AddressOfOp::create(b_, loc, g);
    unsigned align = kaddr ? 8 : t.getIntOrFloatBitWidth() / 8;
    bind(gl.getResult(), LLVM::LoadOp::create(b_, loc, t, addr, align, /*isVolatile=*/true));
    return success();
  }

  // typed ksym / kconfig externs and the CO-RE existence guards, in
  // clang's shapes: `if (&v)` is ld_imm64 v and a compare with 0;
  // bpf_per_cpu_ptr(&v, cpu), NULL test, then the slot load on the true edge;
  // the kconfig value is a plain load (the .kconfig map is frozen).
  auto externOf = [&](Operation *o, StringRef name, StringRef section) -> LLVM::GlobalOp {
    auto ta = o->getAttrOfType<TypeAttr>("ebpf.extern_type");
    Type t = ta ? convertType(ta.getValue()) : Type();
    if (section == ".kconfig")
      t = o->getResult(0).getType();
    if (!t) {
      o->emitOpError() << "has no ebpf.extern_type (ebpf-verify-schema did not run)";
      return nullptr;
    }
    return ctx_.externVar(name, t, section, o->hasAttr("ebpf.weak"), loc);
  };
  if (auto ex = dyn_cast<KsymExistsOp>(op)) {
    LLVM::GlobalOp g = externOf(&op, ex.getName(), ".ksyms");
    if (!g)
      return failure();
    Value addr = LLVM::AddressOfOp::create(b_, loc, g);
    Value null = LLVM::ZeroOp::create(b_, loc, ctx_.ptrTy());
    bind(ex.getResult(), LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ne, addr, null));
    return success();
  }
  if (auto br = dyn_cast<KsymPerCpuBrOp>(op)) {
    LLVM::GlobalOp g = externOf(&op, br.getName(), ".ksyms");
    if (!g)
      return failure();
    Value addr = LLVM::AddressOfOp::create(b_, loc, g);
    FailureOr<Value> p = ctx_.helperCall(b_, loc, "per_cpu_ptr", {addr, remap(br.getCpu())});
    if (failed(p))
      return failure();
    Value null = LLVM::ZeroOp::create(b_, loc, ctx_.ptrTy());
    Value ok = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ne, *p, null);
    Block *cur = b_.getInsertionBlock();
    auto *mid = new Block();
    func_.getBody().getBlocks().insert(std::next(cur->getIterator()), mid);
    LLVM::CondBrOp::create(b_, loc, ok, mid, ValueRange{}, blocks_[br.getAbsent()], ValueRange{});
    b_.setInsertionPointToEnd(mid);
    Type st = g.getGlobalType();
    unsigned align = st.isInteger() ? st.getIntOrFloatBitWidth() / 8 : 8;
    Value v = LLVM::LoadOp::create(b_, loc, st, *p, align);
    LLVM::BrOp::create(b_, loc, ValueRange{v}, blocks_[br.getPresent()]);
    return success();
  }
  if (auto nn = dyn_cast<KAddrNonNullOp>(op)) {
    Value null = LLVM::ZeroOp::create(b_, loc, ctx_.ptrTy());
    bind(nn.getResult(), LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ne, remap(nn.getAddr()), null));
    return success();
  }
  // the untrusted kernel-address ops (clang's BPF_CORE_READ /
  // bpf_core_read_str / bpf_strncmp / container_of shapes).
  if (auto eq = dyn_cast<KAddrEqOp>(op)) {
    bind(eq.getResult(), LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::eq, remap(eq.getLhs()), remap(eq.getRhs())));
    return success();
  }
  if (isa<KAddrReadOp, KAddrStrncmpOp, KFieldStrncmpOp, KAddrContainerOfOp>(op)) {
    Type i64 = b_.getI64Type();
    auto c64 = [&](int64_t v) -> Value { return LLVM::ConstantOp::create(b_, loc, i64, b_.getI64IntegerAttr(v)); };
    auto fieldAddr = [&](Value base, StringRef sname, StringAttr field) -> Value {
      auto a = bpfabi::CoreFieldAddrOp::create(b_, loc, ctx_.ptrTy(), base, b_.getStringAttr(sname), field);
      copyGuards(&op, a);
      return a.getResult();
    };
    auto literal = [&](StringRef lit) -> FailureOr<Value> {
      LLVM::GlobalOp g = ctx_.strncmpLiteral(lit, loc);
      if (!g)
        return failure();
      return Value(LLVM::AddressOfOp::create(b_, loc, ctx_.ptrTy(), g.getSymName()));
    };
    if (auto rd = dyn_cast<KAddrReadOp>(op)) {
      Type vt = rd.getValue().getType();
      bool ptr = isa<KAddrType>(vt);
      Type lt = ptr ? Type(ctx_.ptrTy()) : vt;
      unsigned bytes = ptr ? 8 : vt.getIntOrFloatBitWidth() / 8;
      Value tmp = allocaFor(i64, loc); // Zeroed: a failed read leaves 0 (the kernel also zeroes it).
      cast<LLVM::AllocaOp>(tmp.getDefiningOp()).setAlignment(8);
      LLVM::StoreOp::create(b_, loc, c64(0), tmp, 8);
      Value src = fieldAddr(remap(rd.getAddr()), rd.getAddr().getType().getStructName(), rd.getFieldAttr());
      FailureOr<Value> st = ctx_.helperCall(b_, loc, "probe_read_kernel", {tmp, c64(bytes), src});
      if (failed(st))
        return failure();
      bind(rd.getStatus(), *st);
      bind(rd.getValue(), LLVM::LoadOp::create(b_, loc, lt, tmp, bytes));
      return success();
    }
    if (auto sc = dyn_cast<KAddrStrncmpOp>(op)) {
      int64_t n = static_cast<int64_t>(sc.getLiteral().size()) + 1; // C's char buf[sizeof(lit)].
      Value buf = allocaFor(LLVM::LLVMArrayType::get(b_.getI8Type(), n), loc);
      cast<LLVM::AllocaOp>(buf.getDefiningOp()).setAlignment(8);
      Value src = fieldAddr(remap(sc.getAddr()), sc.getAddr().getType().getStructName(), sc.getFieldAttr());
      FailureOr<Value> rd = ctx_.helperCall(b_, loc, "probe_read_kernel_str", {buf, c64(n), src});
      if (failed(rd))
        return failure();
      FailureOr<Value> s2 = literal(sc.getLiteral());
      if (failed(s2))
        return failure();
      FailureOr<Value> c = ctx_.helperCall(b_, loc, "strncmp", {buf, c64(n), *s2});
      if (failed(c))
        return failure();
      bind(sc.getStatus(), *rd);
      bind(sc.getCmp(), *c);
      return success();
    }
    if (auto kc = dyn_cast<KFieldStrncmpOp>(op)) {
      Value src = fieldAddr(remap(kc.getPtr()), kc.getPtr().getType().getStructName(), kc.getFieldAttr());
      FailureOr<Value> s2 = literal(kc.getLiteral());
      if (failed(s2))
        return failure();
      FailureOr<Value> c = ctx_.helperCall(b_, loc, "strncmp", {src, c64(kc.getLen()), *s2});
      if (failed(c))
        return failure();
      bind(kc.getCmp(), *c);
      return success();
    }
    auto co = cast<KAddrContainerOfOp>(op);
    auto off = bpfabi::CoreFieldOffsetOp::create(b_, loc, b_.getI32Type(), co.getStructNameAttr(), co.getFieldAttr());
    copyGuards(&op, off);
    Value off64 = LLVM::ZExtOp::create(b_, loc, i64, off.getResult());
    Value neg = LLVM::SubOp::create(b_, loc, c64(0), off64);
    bind(co.getResult(), LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(co.getAddr()), ArrayRef<LLVM::GEPArg>{neg}));
    return success();
  }
  if (auto kl = dyn_cast<KconfigLoadOp>(op)) {
    LLVM::GlobalOp g = externOf(&op, kl.getName(), ".kconfig");
    if (!g)
      return failure();
    Type t = kl.getResult().getType();
    Value addr = LLVM::AddressOfOp::create(b_, loc, g);
    bind(kl.getResult(), LLVM::LoadOp::create(b_, loc, t, addr, t.getIntOrFloatBitWidth() / 8));
    return success();
  }
  // the kind-independent CO-RE enum read (scx.const shares it below).
  if (auto ce = dyn_cast<CoreEnumValueOp>(op)) {
    const bpfabi::ScxEnumABI *e = bpfabi::lookupScxEnum(ce.getName());
    if (!e || e->enumName != ce.getEnumName())
      return ce.emitOpError() << "enum constant \"" << ce.getEnumName() << "." << ce.getName() << "\" is not in the UAPI table";
    bind(ce.getValue(), bpfabi::CoreEnumValueOp::create(b_, loc, b_.getI64Type(), b_.getStringAttr(e->enumName), b_.getStringAttr(e->name),
                                                        b_.getI64IntegerAttr(static_cast<int64_t>(e->value))));
    return success();
  }
  if (isa<CoreTypeExistsOp, CoreFieldExistsOp>(op)) {
    auto te = dyn_cast<CoreTypeExistsOp>(op);
    auto fe = dyn_cast<CoreFieldExistsOp>(op);
    auto r = bpfabi::CoreExistsOp::create(b_, loc, b_.getI32Type(), b_.getStringAttr(te ? "type" : "field"),
                                          te ? te.getStructNameAttr() : fe.getStructNameAttr(),
                                          b_.getStringAttr(te ? StringRef() : fe.getField()));
    Value zero = LLVM::ConstantOp::create(b_, loc, b_.getI32Type(), b_.getI32IntegerAttr(0));
    bind(op.getResult(0), LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ne, r.getResult(), zero));
    return success();
  }

  // a record global borrow is the address of the placeholder (a byte
  // array of the record size — the same placeholder as .data record);
  // BTF-to-DI types it from the schema. The ref ops lower against @records.
  if (auto gr = dyn_cast<GlobalRefOp>(op)) {
    auto rt = cast<RecordType>(cast<BorrowedType>(gr.getRef().getType()).getPointee());
    LLVM::GlobalOp g = ctx_.globalVar(gr.getName(), LLVM::LLVMArrayType::get(b_.getI8Type(), rt.getSize()), loc);
    if (!g)
      return failure();
    bind(gr.getRef(), LLVM::AddressOfOp::create(b_, loc, g));
    return success();
  }

  // .bss stores are volatile like global.load (one access per occurrence).
  if (auto gs = dyn_cast<GlobalStoreOp>(op)) {
    Value v = remap(gs.getValue());
    LLVM::GlobalOp g = ctx_.globalVar(gs.getName(), v.getType(), loc);
    if (!g)
      return failure();
    Value addr = LLVM::AddressOfOp::create(b_, loc, g);
    // a !ebpf.kaddr value is an 8-byte pointer.
    unsigned align = isa<LLVM::LLVMPointerType>(v.getType()) ? 8 : v.getType().getIntOrFloatBitWidth() / 8;
    LLVM::StoreOp::create(b_, loc, v, addr, align, /*isVolatile=*/true);
    return success();
  }

  // UEI_RECORD into the .data struct user_exit_info record (offsets are
  // fixed by ebpf-verify-schema's shape check). The cmpxchg32 is inline asm:
  // LLVM rejects 32-bit cmpxchg below CPU v3, and ObjectEmitter targets v1.
  if (auto ex = dyn_cast<ScxExitInfoOp>(op)) {
    constexpr uint64_t kUeiBytes = 1168, kReasonOff = 16, kReasonLen = 128, kMsgOff = 144, kMsgLen = 1024;
    LLVM::GlobalOp g = ctx_.globalVar(ex.getUei(), LLVM::LLVMArrayType::get(b_.getI8Type(), kUeiBytes), loc);
    if (!g)
      return failure();
    Value ei = remap(ex.getInfo());
    StringAttr sname = b_.getStringAttr("scx_exit_info");
    Value uei = LLVM::AddressOfOp::create(b_, loc, g);
    auto at = [&](uint64_t off) -> Value {
      return LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), uei, ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(off)});
    };
    auto readStr = [&](StringRef field, uint64_t off, uint64_t len) -> LogicalResult {
      auto src = bpfabi::CoreFieldLoadOp::create(b_, loc, ctx_.ptrTy(), ei, sname, b_.getStringAttr(field));
      Value n = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(len));
      return ctx_.helperCall(b_, loc, "probe_read_kernel_str", {at(off), n, src.getResult()});
    };
    if (failed(readStr("reason", kReasonOff, kReasonLen)) || failed(readStr("msg", kMsgOff, kMsgLen)))
      return failure();
    auto code = bpfabi::CoreFieldLoadOp::create(b_, loc, b_.getI64Type(), ei, sname, b_.getStringAttr("exit_code"));
    LLVM::StoreOp::create(b_, loc, code.getResult(), at(8), /*align=*/8);
    Value minus1 = LLVM::ConstantOp::create(b_, loc, b_.getI32Type(), b_.getI32IntegerAttr(-1));
    LLVM::StoreOp::create(b_, loc, minus1, at(4), /*align=*/4);
    Value old = LLVM::LoadOp::create(b_, loc, b_.getI32Type(), uei, /*align=*/4, /*isVolatile=*/true);
    auto kind = bpfabi::CoreFieldLoadOp::create(b_, loc, b_.getI32Type(), ei, sname, b_.getStringAttr("kind"));
    LLVM::InlineAsmOp::create(b_, loc, TypeRange{b_.getI32Type()}, ValueRange{uei, old, kind.getResult()},
                              "w0 = cmpxchg32_32($1 + 0, w0, w2)", "={r0},r,{r0},{r2},~{memory}",
                              /*has_side_effects=*/true, /*is_align_stack=*/false, LLVM::tailcallkind::TailCallKind::None,
                              /*asm_dialect=*/LLVM::AsmDialectAttr(), /*operand_attrs=*/ArrayAttr());
    return success();
  }

  // .bss additions use monotonic atomicrmw, like ref.atomic_add.
  if (auto ga = dyn_cast<GlobalAtomicAddOp>(op)) {
    Value delta = remap(ga.getDelta());
    LLVM::GlobalOp g = ctx_.globalVar(ga.getName(), delta.getType(), loc);
    if (!g)
      return failure();
    Value addr = LLVM::AddressOfOp::create(b_, loc, g);
    LLVM::AtomicRMWOp::create(b_, loc, LLVM::AtomicBinOp::add, addr, delta, LLVM::AtomicOrdering::monotonic);
    return success();
  }

  // .bss cmpxchg / or (ebpf-verify-schema proved an integer .bss global).
  if (auto cx = dyn_cast<GlobalCmpxchgOp>(op)) {
    LLVM::GlobalOp g = ctx_.globalVar(cx.getName(), cx.getOld().getType(), loc);
    if (!g)
      return failure();
    Value addr = LLVM::AddressOfOp::create(b_, loc, g);
    bind(cx.getOld(), atomicCmpxchg(addr, remap(cx.getExpected()), remap(cx.getDesired()), loc));
    return success();
  }
  if (auto go = dyn_cast<GlobalAtomicOrOp>(op)) {
    Value v = remap(go.getValue());
    LLVM::GlobalOp g = ctx_.globalVar(go.getName(), v.getType(), loc);
    if (!g)
      return failure();
    atomicOr(LLVM::AddressOfOp::create(b_, loc, g), v, loc);
    return success();
  }

  // Multi target indices use get_attach_cookie under the loader mtarget-index
  // contract. Session is_return returns i8 bool, compared with zero for i1;
  // session_cookie returns a non-null u64 pointer accessed through eight bytes.
  // sched_ext kfuncs of the family "insert". Each op calls its
  // ScxContract.def kfunc with the UAPI row's BPF-visible prototype (bool
  // returns are i8 compared with zero). select_cpu_dfl's bool out parameter is
  // a zeroed one-byte stack slot; error's format is compiler-owned writable
  // .data (not .rodata as trace.printk) and its arguments a stack u64
  // array.
  // the B1 ops call their kfunc the same way; exit / dump share
  // error's format and argument array.
  if (isa<ScxDsqInsertOp, ScxDsqInsertVtimeOp, ScxDsqMoveToLocalOp, ScxCreateDsqOp, ScxSelectCpuDflOp, ScxTaskSetDsqVtimeOp, ScxErrorOp,
          ScxConstOp, ScxTaskCpuOp, ScxKickCpuOp, ScxDsqNrQueuedOp, ScxDsqPeekOp, ScxTaskSetSliceOp, ScxNowOp, ScxPickIdleCpuOp,
          ScxCpuCurrOp, ScxCpuperfCapOp, ScxCpuperfSetOp, ScxDsqReenqOp, ScxExitOp, ScxDumpOp>(op)) {
    if (auto c = dyn_cast<ScxConstOp>(op)) {
      const bpfabi::ScxEnumABI *e = bpfabi::lookupScxEnum(c.getName());
      if (!e)
        return c.emitOpError() << "enum constant \"" << c.getName() << "\" is not in the UAPI table";
      bind(c.getValue(), bpfabi::CoreEnumValueOp::create(b_, loc, b_.getI64Type(), b_.getStringAttr(e->enumName), b_.getStringAttr(e->name),
                                                         b_.getI64IntegerAttr(static_cast<int64_t>(e->value))));
      return success();
    }
    auto call = [&](StringRef kfunc, TypeRange res, ValueRange args) {
      return bpfabi::KfuncCallOp::create(b_, loc, res, b_.getStringAttr(kfunc), UnitAttr(), args);
    };
    auto nonzero = [&](Value v) {
      Value zero = LLVM::ConstantOp::create(b_, loc, b_.getI8Type(), b_.getI8IntegerAttr(0));
      return LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ne, v, zero);
    };
    if (auto o = dyn_cast<ScxDsqInsertOp>(op)) {
      call("scx_bpf_dsq_insert", {}, {remap(o.getTask()), remap(o.getDsq()), remap(o.getSlice()), remap(o.getFlags())});
      return success();
    }
    if (auto o = dyn_cast<ScxDsqInsertVtimeOp>(op)) {
      call("scx_bpf_dsq_insert_vtime", {},
           {remap(o.getTask()), remap(o.getDsq()), remap(o.getSlice()), remap(o.getVtime()), remap(o.getFlags())});
      return success();
    }
    if (auto o = dyn_cast<ScxDsqMoveToLocalOp>(op)) {
      auto c = call("scx_bpf_dsq_move_to_local", {b_.getI8Type()}, {remap(o.getDsq())});
      bind(o.getMoved(), nonzero(c.getResult(0)));
      return success();
    }
    if (auto o = dyn_cast<ScxCreateDsqOp>(op)) {
      auto c = call("scx_bpf_create_dsq", {b_.getI32Type()}, {remap(o.getDsq()), remap(o.getNode())});
      bind(o.getStatus(), c.getResult(0));
      return success();
    }
    if (auto o = dyn_cast<ScxSelectCpuDflOp>(op)) {
      Value slot = allocaFor(b_.getI8Type(), loc);
      LLVM::StoreOp::create(b_, loc, LLVM::ConstantOp::create(b_, loc, b_.getI8Type(), b_.getI8IntegerAttr(0)), slot, 1);
      auto c = call("scx_bpf_select_cpu_dfl", {b_.getI32Type()}, {remap(o.getTask()), remap(o.getPrev()), remap(o.getWake()), slot});
      bind(o.getCpu(), c.getResult(0));
      bind(o.getIdle(), nonzero(LLVM::LoadOp::create(b_, loc, b_.getI8Type(), slot, 1)));
      return success();
    }
    if (auto o = dyn_cast<ScxTaskSetDsqVtimeOp>(op)) {
      call("scx_bpf_task_set_dsq_vtime", {b_.getI8Type()}, {remap(o.getTask()), remap(o.getVtime())});
      return success();
    }
    // The RCU task results (rcu_ptr_or_null) are KF_RET_NULL: ret_nullable.
    auto one = [&](Value result, StringRef kfunc, ValueRange args) {
      bool ptr = isa<RcuPtrOrNullType>(result.getType());
      auto c = bpfabi::KfuncCallOp::create(b_, loc, TypeRange{ptr ? Type(ctx_.ptrTy()) : result.getType()}, b_.getStringAttr(kfunc),
                                           ptr ? b_.getUnitAttr() : UnitAttr(), args);
      bind(result, c.getResult(0));
      return success();
    };
    if (auto o = dyn_cast<ScxTaskCpuOp>(op))
      return one(o.getCpu(), "scx_bpf_task_cpu", {remap(o.getTask())});
    if (auto o = dyn_cast<ScxDsqNrQueuedOp>(op))
      return one(o.getCount(), "scx_bpf_dsq_nr_queued", {remap(o.getDsq())});
    if (auto o = dyn_cast<ScxDsqPeekOp>(op))
      return one(o.getTask(), "scx_bpf_dsq_peek", {remap(o.getDsq())});
    if (auto o = dyn_cast<ScxNowOp>(op))
      return one(o.getNs(), "scx_bpf_now", {});
    if (auto o = dyn_cast<ScxPickIdleCpuOp>(op))
      return one(o.getCpu(), "scx_bpf_pick_idle_cpu", {remap(o.getCpus()), remap(o.getFlags())});
    if (auto o = dyn_cast<ScxCpuCurrOp>(op))
      return one(o.getTask(), "scx_bpf_cpu_curr", {remap(o.getCpu())});
    if (auto o = dyn_cast<ScxCpuperfCapOp>(op))
      return one(o.getCap(), "scx_bpf_cpuperf_cap", {remap(o.getCpu())});
    if (auto o = dyn_cast<ScxKickCpuOp>(op)) {
      call("scx_bpf_kick_cpu", {}, {remap(o.getCpu()), remap(o.getFlags())});
      return success();
    }
    if (auto o = dyn_cast<ScxTaskSetSliceOp>(op)) {
      call("scx_bpf_task_set_slice", {b_.getI8Type()}, {remap(o.getTask()), remap(o.getSlice())});
      return success();
    }
    if (auto o = dyn_cast<ScxCpuperfSetOp>(op)) {
      call("scx_bpf_cpuperf_set", {}, {remap(o.getCpu()), remap(o.getPerf())});
      return success();
    }
    if (auto o = dyn_cast<ScxDsqReenqOp>(op)) {
      call("scx_bpf_dsq_reenq", {}, {remap(o.getDsq()), remap(o.getFlags())});
      return success();
    }
    // error / exit / dump: format in compiler-owned writable .data (the
    // kfunc's char *fmt needs write access), arguments in a stack u64 array.
    StringRef format, kfunc;
    ValueRange fargs;
    SmallVector<Value, 1> lead;
    if (auto o = dyn_cast<ScxExitOp>(op)) {
      format = o.getFormat(), fargs = o.getArgs(), kfunc = "scx_bpf_exit_bstr";
      lead.push_back(remap(o.getCode()));
    } else if (auto o = dyn_cast<ScxDumpOp>(op)) {
      format = o.getFormat(), fargs = o.getArgs(), kfunc = "scx_bpf_dump_bstr";
    } else {
      auto e = cast<ScxErrorOp>(op);
      format = e.getFormat(), fargs = e.getArgs(), kfunc = "scx_bpf_error_bstr";
    }
    auto global = ctx_.scxFormat(format, loc);
    if (!global)
      return failure();
    Value fmt =LLVM::AddressOfOp::create(b_, loc, ctx_.ptrTy(), global.getSymName());
    // data is never NULL: the kfunc's unsigned long long *data is not a
    // nullable argument, and the 7.3.1 verifier rejects NULL before the
    // mem / size pair's NULL exemption. With no arguments it
    // is a zeroed one-element array with data__sz = 8, as C's
    // scx_bpf_bstr_preamble (___param[narg ?: 1] = {}, common.bpf.h).
    size_t n = fargs.size();
    auto i64 = b_.getI64Type();
    Value data = allocaFor(LLVM::LLVMArrayType::get(i64, n ? n : 1), loc);
    if (n) {
      for (auto [i, a] : llvm::enumerate(fargs)) {
        Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), i64, data, ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(i)});
        Value val = remap(a);
        if (isa<StrBufType>(a.getType())) // a %s argument is the buffer's stack address.
          val = LLVM::PtrToIntOp::create(b_, loc, i64, val);
        LLVM::StoreOp::create(b_, loc, val, at, 8);
      }
    } else {
      Value zero = LLVM::ConstantOp::create(b_, loc, i64, b_.getI64IntegerAttr(0));
      LLVM::StoreOp::create(b_, loc, zero, data, 8);
    }
    Value size = LLVM::ConstantOp::create(b_, loc, b_.getI32Type(), b_.getI32IntegerAttr(static_cast<int32_t>(8 * (n ? n : 1))));
    lead.append({fmt, data, size});
    call(kfunc, {}, lead);
    return success();
  }
  if (isa<SessionIsReturnOp, SessionCookieLoadOp, SessionCookieStoreOp>(op)) {
    Value ctxV = remap(op.getOperand(0));
    if (auto ir = dyn_cast<SessionIsReturnOp>(op)) {
      auto call = bpfabi::KfuncCallOp::create(b_, loc, TypeRange{b_.getI8Type()}, b_.getStringAttr("bpf_session_is_return"), UnitAttr(),
                                              ValueRange{ctxV});
      Value zero = LLVM::ConstantOp::create(b_, loc, b_.getI8Type(), b_.getI8IntegerAttr(0));
      bind(ir.getResult(), LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ne, call.getResult(0), zero));
      return success();
    }
    auto call = bpfabi::KfuncCallOp::create(b_, loc, TypeRange{ctx_.ptrTy()}, b_.getStringAttr("bpf_session_cookie"), UnitAttr(),
                                            ValueRange{ctxV});
    if (auto ld = dyn_cast<SessionCookieLoadOp>(op)) {
      bind(ld.getResult(), LLVM::LoadOp::create(b_, loc, b_.getI64Type(), call.getResult(0), 8));
      return success();
    }
    auto st = cast<SessionCookieStoreOp>(op);
    LLVM::StoreOp::create(b_, loc, remap(st.getValue()), call.getResult(0), 8);
    return success();
  }
  // Target-specific args compare cookie with i, read/truncate the fixed
  // pt_regs register and select hit ? value : zero.
  if (auto ta = dyn_cast<ProbeTargetArgOp>(op)) {
    auto prog = ta->getParentOfType<ProgramOp>();
    if (!prog || !prog.getArch())
      return ta.emitOpError() << "must be inside a multi probe program with `arch`";
    const bpfabi::KprobeArgABI *k = bpfabi::lookupKprobeArg(*prog.getArch(), static_cast<int>(ta.getN()));
    if (!k)
      return ta.emitOpError() << "argument " << ta.getN() << " has no register on arch \"" << *prog.getArch() << "\" (the UAPI table has "
                              << bpfabi::kprobeArgCount(*prog.getArch()) << ")";
    Value ctxV = remap(ta.getCtx());
    FailureOr<Value> cookie = ctx_.helperCall(b_, loc, "get_attach_cookie", {ctxV});
    if (failed(cookie))
      return failure();
    Value want = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(ta.getTarget()));
    Value hit = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::eq, *cookie, want);
    auto a = bpfabi::KprobeArgOp::create(b_, loc, b_.getI64Type(), ctxV, b_.getStringAttr(*prog.getArch()), b_.getI64IntegerAttr(ta.getN()),
                                         b_.getI64IntegerAttr(k->offset), b_.getI64IntegerAttr(k->bytes));
    Value v = a.getResult();
    // user_str is represented by the raw register's i64, as for uprobe.arg.
    Type rt = isa<UserStrType, UserBufType>(ta.getValue().getType()) ? b_.getI64Type() : ta.getValue().getType();
    if (rt != v.getType())
      v = LLVM::TruncOp::create(b_, loc, rt, v);
    Value zero = LLVM::ConstantOp::create(b_, loc, rt, b_.getIntegerAttr(rt, 0));
    bind(ta.getValue(), LLVM::SelectOp::create(b_, loc, hit, v, zero));
    bind(ta.getHit(), hit);
    return success();
  }
  // ksyscall follows wrapper arg1 to user pt_regs, then ABI ksyscallarg offset.
  // probe_read_kernel copies eight bytes into a zeroed slot, then truncate to
  // result width, matching BPF_KSYSCALL's two-level fixed-offset read.
  if (auto sa = dyn_cast<KsyscallArgOp>(op)) {
    auto prog = sa->getParentOfType<ProgramOp>();
    if (!prog || !prog.getArch())
      return sa.emitOpError() << "must be inside a ksyscall program with `arch`";
    const bpfabi::KprobeArgABI *outer = bpfabi::lookupKprobeArg(*prog.getArch(), 1);
    const bpfabi::KprobeArgABI *inner = bpfabi::lookupKsyscallArg(*prog.getArch(), static_cast<int>(sa.getN()));
    if (!outer || !inner)
      return sa.emitOpError() << "syscall argument " << sa.getN() << " has no register on arch \"" << *prog.getArch()
                              << "\" (the UAPI table has " << bpfabi::ksyscallArgCount(*prog.getArch()) << " ksyscallarg rows)";
    auto regs = bpfabi::KprobeArgOp::create(b_, loc, b_.getI64Type(), remap(sa.getCtx()), b_.getStringAttr(*prog.getArch()),
                                            b_.getI64IntegerAttr(1), b_.getI64IntegerAttr(outer->offset), b_.getI64IntegerAttr(outer->bytes));
    Value off = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(inner->offset));
    Value src = LLVM::AddOp::create(b_, loc, regs.getResult(), off);
    Value zero = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(0));
    Value slot = spillInt(zero, loc);
    Value size = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(inner->bytes));
    if (failed(ctx_.helperCall(b_, loc, "probe_read_kernel", {slot, size, src})))
      return failure();
    Value v = LLVM::LoadOp::create(b_, loc, b_.getI64Type(), slot, 8);
    endSpills(loc);
    if (!isa<UserStrType, UserStrArrayType>(sa.getResult().getType()) && sa.getResult().getType() != v.getType())
      v = LLVM::TruncOp::create(b_, loc, sa.getResult().getType(), v);
    bind(sa.getResult(), v);
    return success();
  }
  if (auto ti = dyn_cast<ProbeTargetIndexOp>(op)) {
    FailureOr<Value> v = ctx_.helperCall(b_, loc, "get_attach_cookie", {remap(ti.getCtx())});
    if (failed(v))
      return failure();
    bind(ti.getResult(), *v);
    return success();
  }
  // USDT uses cookie as u32 key into loader-written __ebpf_usdt_spec_<program>.
  // Missing specs return (0,-ENOENT). Argument slots contain kind/reg/off.
  // Const returns truncated off. Other kinds load every ABI register once at
  // fixed offsets and select register values, never select context pointers
  // into variable-offset reads. Invalid reg/kind returns (0,-EINVAL).
  // Register kind returns the truncated register; deref probe_read_user reads
  // W/8 bytes from reg+off into zeroed storage, defining failure value zero.
  if (auto ua = dyn_cast<UsdtArgOp>(op)) {
    auto prog = ua->getParentOfType<ProgramOp>();
    if (!prog || !prog.getArch())
      return ua.emitOpError() << "must be inside a usdt program with `arch`";
    SmallVector<const bpfabi::UsdtRegABI *> regs;
    for (const bpfabi::UsdtRegABI &r : bpfabi::usdtRegs())
      if (r.arch == *prog.getArch())
        regs.push_back(&r);
    if (regs.empty())
      return ua.emitOpError() << "arch \"" << *prog.getArch() << "\" has no USDT register rows in the UAPI table (usdtreg)";
    std::string mapName = std::string(::ebpf::kUsdtSpecMapPrefix) + prog.getSymName().str();
    LLVM::GlobalOp g = ctx_.mapGlobal(mapName, loc);
    if (!g)
      return failure();
    Type i8 = b_.getI8Type(), i64 = b_.getI64Type();
    Type vt = ua.getValue().getType();
    unsigned bytes = vt.getIntOrFloatBitWidth() / 8;
    auto c64 = [&](int64_t v) { return LLVM::ConstantOp::create(b_, loc, i64, b_.getI64IntegerAttr(v)).getResult(); };
    auto c8 = [&](int64_t v) { return LLVM::ConstantOp::create(b_, loc, i8, b_.getIntegerAttr(i8, v)).getResult(); };
    auto zeroV = [&] { return LLVM::ConstantOp::create(b_, loc, vt, b_.getIntegerAttr(vt, 0)).getResult(); };
    auto truncV = [&](Value v64) { return vt == i64 ? v64 : LLVM::TruncOp::create(b_, loc, vt, v64).getResult(); };
    Value ctxv = remap(ua.getCtx());
    FailureOr<Value> cookie = ctx_.helperCall(b_, loc, "get_attach_cookie", {ctxv});
    if (failed(cookie))
      return failure();
    Value key = LLVM::TruncOp::create(b_, loc, b_.getI32Type(), *cookie);
    Value keyPtr = spillKey(key, loc);
    Value mapAddr = LLVM::AddressOfOp::create(b_, loc, g);
    FailureOr<Value> spec = ctx_.helperCall(b_, loc, "map_lookup_elem", {mapAddr, keyPtr});
    if (failed(spec))
      return failure();
    endSpills(loc);
    Block *cur = b_.getInsertionBlock();
    Block *have = cur->splitBlock(b_.getInsertionPoint());
    Block *cont = have->splitBlock(have->begin());
    Value resV = cont->addArgument(vt, loc);
    Value resS = cont->addArgument(i64, loc);
    Block *notConst = new Block();
    Block *notReg = new Block();
    Block *derefBlk = new Block();
    Region *region = cur->getParent();
    region->getBlocks().insertAfter(Region::iterator(have), notConst);
    region->getBlocks().insertAfter(Region::iterator(notConst), notReg);
    region->getBlocks().insertAfter(Region::iterator(notReg), derefBlk);
    // Loader did not populate the point's spec.
    b_.setInsertionPointToEnd(cur);
    Value isNull = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::eq, *spec, LLVM::ZeroOp::create(b_, loc, ctx_.ptrTy()));
    LLVM::CondBrOp::create(b_, loc, isNull, cont, ValueRange{zeroV(), c64(bpfabi::kUsdtNoSpecStatus)}, have, ValueRange{});
    // Argument n in the spec.
    b_.setInsertionPointToEnd(have);
    int32_t base = static_cast<int32_t>(::ebpf::kUsdtArgSpecBytes * (ua.getN() - 1));
    auto field = [&](int32_t off, Type t, unsigned align) {
      Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), i8, *spec, ArrayRef<LLVM::GEPArg>{base + off});
      return LLVM::LoadOp::create(b_, loc, t, at, align).getResult();
    };
    Value kind = field(::ebpf::kUsdtArgKindOffset, i8, 1);
    Value reg = field(::ebpf::kUsdtArgRegOffset, i8, 1);
    Value off = field(::ebpf::kUsdtArgOffOffset, i64, 8);
    Value isConst = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::eq, kind, c8(::ebpf::kUsdtKindConst));
    LLVM::CondBrOp::create(b_, loc, isConst, cont, ValueRange{truncV(off), c64(0)}, notConst, ValueRange{});
    // Load all registers at fixed offsets and select by index for reg/deref base.
    b_.setInsertionPointToEnd(notConst);
    Value regval = c64(0);
    for (const bpfabi::UsdtRegABI *r : regs) {
      Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), i8, ctxv, ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(r->offset)});
      Value v = LLVM::LoadOp::create(b_, loc, i64, at, /*alignment=*/8, /*isVolatile=*/true);
      Value eq = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::eq, reg, c8(r->index));
      regval = LLVM::SelectOp::create(b_, loc, eq, v, regval);
    }
    Value regOk = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ult, reg, c8(static_cast<int64_t>(regs.size())));
    Value isReg = LLVM::AndOp::create(b_, loc, LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::eq, kind, c8(::ebpf::kUsdtKindReg)), regOk);
    LLVM::CondBrOp::create(b_, loc, isReg, cont, ValueRange{truncV(regval), c64(0)}, notReg, ValueRange{});
    b_.setInsertionPointToEnd(notReg);
    Value isDeref = LLVM::AndOp::create(b_, loc, LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::eq, kind, c8(::ebpf::kUsdtKindDeref)), regOk);
    LLVM::CondBrOp::create(b_, loc, isDeref, derefBlk, ValueRange{}, cont, ValueRange{zeroV(), c64(bpfabi::kUsdtBadSpecStatus)});
    // Dereference W/8 user bytes and retain raw helper status.
    b_.setInsertionPointToEnd(derefBlk);
    Value tmp = allocaFor(i64, loc);
    LLVM::StoreOp::create(b_, loc, c64(0), tmp);
    Value addr = LLVM::AddOp::create(b_, loc, regval, off);
    FailureOr<Value> st = ctx_.helperCall(b_, loc, "probe_read_user", {tmp, c64(bytes), addr});
    if (failed(st))
      return failure();
    Value dv = LLVM::LoadOp::create(b_, loc, vt, tmp, bytes);
    LLVM::BrOp::create(b_, loc, ValueRange{dv, *st}, cont);
    b_.setInsertionPointToStart(cont);
    bind(ua.getValue(), resV);
    bind(ua.getStatus(), resS);
    return success();
  }
  if (isa<CgroupRetvalOp, CgroupSetRetvalOp, TaskSendSignalOp, TaskSendSignalThreadOp>(op)) {
    StringRef helper = isa<CgroupRetvalOp>(op) ? "get_retval" :
                       isa<CgroupSetRetvalOp>(op) ? "set_retval" :
                       isa<TaskSendSignalThreadOp>(op) ? "send_signal_thread" : "send_signal";
    SmallVector<Value> args;
    if (op.getNumOperands())
      args.push_back(LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(op.getOperand(0))));
    auto value = ctx_.helperCall(b_, loc, helper, args);
    if (failed(value))
      return failure();
    Value result = *value;
    if (isa<CgroupRetvalOp>(op))
      result = LLVM::TruncOp::create(b_, loc, b_.getI32Type(), result);
    bind(op.getResult(0), result);
    return success();
  }
  if (auto ns = dyn_cast<TaskNsPidTgidOp>(op)) {
    auto *pid = bpfabi::lookupStructField("bpf_pidns_info", "pid");
    auto *tgid = bpfabi::lookupStructField("bpf_pidns_info", "tgid");
    auto type = LLVM::LLVMStructType::getLiteral(b_.getContext(), {b_.getI32Type(), b_.getI32Type()});
    DataLayout layout(ctx_.module);
    uint64_t bytes = layout.getTypeSize(type).getFixedValue();
    unsigned align = layout.getTypeABIAlignment(type);
    // The internal LLVM representation must match the generated UAPI fields.
    if (!pid || !tgid || pid->kind != "int" || tgid->kind != "int" || pid->offset != 0 ||
        pid->bytes != static_cast<int64_t>(layout.getTypeSize(b_.getI32Type()).getFixedValue()) ||
        tgid->offset != pid->bytes || tgid->bytes != pid->bytes ||
        pid->count != 1 || tgid->count != 1 || bytes != static_cast<uint64_t>(tgid->offset + tgid->bytes))
      return ns.emitOpError("internal bpf_pidns_info layout disagrees with UAPI");
    Value slot = mlir::ebpf::detail::scalarOutputSlot(b_, entry_, loc, type, align);
    mlir::ebpf::detail::clearScalarOutput(b_, loc, slot, type, align);
    Value size = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(bytes));
    auto status = ctx_.helperCall(b_, loc, "get_ns_current_pid_tgid",
                                 {remap(ns.getDev()), remap(ns.getIno()), slot, size});
    if (failed(status))
      return failure();
    auto field = [&](const bpfabi::StructFieldABI *f) {
      Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), slot,
          ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(f->offset)});
      return mlir::ebpf::detail::scalarOutputValue(b_, loc, at, b_.getI32Type(), b_.getI32Type(), *status, align);
    };
    bind(ns.getStatus(), *status);
    bind(ns.getPid(), field(pid));
    bind(ns.getTgid(), field(tgid));
    return success();
  }
  // get_current_pid_tgid uses ABI helper ID/return type.
  if (auto pt = dyn_cast<TaskPidTgidOp>(op)) {
    FailureOr<Value> v = ctx_.helperCall(b_, loc, "get_current_pid_tgid", {});
    if (failed(v))
      return failure();
    bind(pt.getResult(), *v);
    return success();
  }
  // get_current_cgroup_id uses ABI helper ID/return type.
  if (auto cg = dyn_cast<TaskCgroupIdOp>(op)) {
    FailureOr<Value> v = ctx_.helperCall(b_, loc, "get_current_cgroup_id", {});
    if (failed(v))
      return failure();
    bind(cg.getResult(), *v);
    return success();
  }

  if (isa<CtxStackOp, KernelDPathOp, StrSnprintfOp>(op)) {
    auto rt = cast<RecordType>(cast<ReservationType>(op.getOperand(0).getType()).getRecordType());
    StringRef field = op.getAttrOfType<StringAttr>("field").getValue();
    auto t = ctx_.recordTemplate(&op, rt.getSymbol(), (field + "[]").str());
    if (failed(t))
      return failure();
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(op.getOperand(0)),
                                  ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(t->offsetBytes)});
    auto c64 = [&](int64_t v) -> Value {
      return LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(v));
    };
    StringRef helper;
    SmallVector<Value> args;
    if (auto stack = dyn_cast<CtxStackOp>(op)) {
      helper = "get_stack";
      args = {remap(stack.getCtx()), at, c64(8 * t->dims[0].count), c64(0)};
    } else if (auto path = dyn_cast<KernelDPathOp>(op)) {
      helper = "d_path";
      args = {remap(path.getPtr()), at, c64(t->dims[0].count)};
    } else {
      auto fmt = cast<StrSnprintfOp>(op);
      auto global = ctx_.formatGlobal(fmt.getFormat(), "__ebpf_snprintf_", ".rodata", loc);
      if (!global)
        return failure();
      Value format = LLVM::AddressOfOp::create(b_, loc, ctx_.ptrTy(), global.getSymName());
      Value data = LLVM::ZeroOp::create(b_, loc, ctx_.ptrTy());
      if (!fmt.getArgs().empty()) {
        data = allocaFor(LLVM::LLVMArrayType::get(b_.getI64Type(), fmt.getArgs().size()), loc);
        cast<LLVM::AllocaOp>(data.getDefiningOp()).setAlignment(8);
        for (auto [i, arg] : llvm::enumerate(fmt.getArgs())) {
          Value slot = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI64Type(), data,
                                          ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(i)});
          LLVM::StoreOp::create(b_, loc, remap(arg), slot, /*alignment=*/8);
        }
      }
      helper = "snprintf";
      args = {at, c64(t->dims[0].count), format, data, c64(8 * fmt.getArgs().size())};
    }
    auto value = ctx_.helperCall(b_, loc, helper, args);
    if (failed(value))
      return failure();
    if (isa<KernelDPathOp>(op))
      value->getDefiningOp()->setAttr(
          "bpfabi.helper_target",
          b_.getStringAttr(dPathHelperTarget(op.getParentOfType<ProgramOp>().getAttach().value_or(""))));
    bind(op.getResult(0), *value);
    return success();
  }

  // get_current_comm writes at base+field offset with constant element count.
  if (auto tc = dyn_cast<TaskCommOp>(op)) {
    auto rt = cast<RecordType>(cast<ReservationType>(tc.getReservation().getType()).getRecordType());
    FailureOr<RecordTemplate> t = ctx_.recordTemplate(&op, rt.getSymbol(), (tc.getField() + "[]").str());
    if (failed(t))
      return failure();
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(tc.getReservation()),
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(t->offsetBytes)});
    Value n = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(t->dims[0].count));
    FailureOr<Value> v = ctx_.helperCall(b_, loc, "get_current_comm", {at, n});
    if (failed(v))
      return failure();
    bind(tc.getStatus(), *v);
    return success();
  }

  // probe_read_user_str writes at destination field offset with constant
  // count and raw 64-bit user pointer (ARG_CONST_SIZE_OR_ZERO).
  if (auto read = dyn_cast<KernelReadScalarOp>(op)) {
    Type i64 = b_.getI64Type();
    Type vt = read.getValue().getType();
    unsigned bytes = vt.getIntOrFloatBitWidth() / 8;
    auto c64 = [&](int64_t v) -> Value {
      return LLVM::ConstantOp::create(b_, loc, i64, b_.getI64IntegerAttr(v));
    };
    Value tmp = allocaFor(i64, loc);
    cast<LLVM::AllocaOp>(tmp.getDefiningOp()).setAlignment(8);
    LLVM::StoreOp::create(b_, loc, c64(0), tmp);
    Value addr = LLVM::AddOp::create(b_, loc, remap(read.getAddr()), c64(read.getOffset()));
    FailureOr<Value> st = ctx_.helperCall(b_, loc, "probe_read_kernel", {tmp, c64(bytes), addr});
    if (failed(st))
      return failure();
    Value value = LLVM::LoadOp::create(b_, loc, vt, tmp, bytes);
    Value failedRead = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::slt, *st, c64(0));
    Value zero = LLVM::ConstantOp::create(b_, loc, vt, b_.getIntegerAttr(vt, 0));
    bind(read.getValue(), LLVM::SelectOp::create(b_, loc, failedRead, zero, value));
    bind(read.getStatus(), *st);
    return success();
  }

  if (auto at = dyn_cast<UserStrAtOp>(op)) {
    auto c64 = [&](int64_t value) -> Value {
      return LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(value));
    };
    Value zero = c64(0);
    Value slot = spillInt(zero, loc);
    Value src = LLVM::AddOp::create(b_, loc, remap(at.getArray()), c64(8 * at.getIndex()));
    FailureOr<Value> status = ctx_.helperCall(b_, loc, "probe_read_user", {slot, c64(8), src});
    if (failed(status))
      return failure();
    Value loaded = LLVM::LoadOp::create(b_, loc, b_.getI64Type(), slot, 8);
    Value ok = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::eq, *status, zero);
    Value ptr = LLVM::SelectOp::create(b_, loc, ok, loaded, zero);
    Value nonnull = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ne, ptr, zero);
    Value present = LLVM::AndOp::create(b_, loc, ok, nonnull);
    endSpills(loc);
    bind(at.getPtr(), ptr);
    bind(at.getStatus(), *status);
    bind(at.getPresent(), present);
    return success();
  }
  if (auto rd = dyn_cast<UserReadOp>(op)) {
    auto rt = cast<RecordType>(cast<ReservationType>(rd.getReservation().getType()).getRecordType());
    FailureOr<RecordTemplate> t = ctx_.recordTemplate(&op, rt.getSymbol(), (rd.getField() + "[]").str());
    if (failed(t))
      return failure();
    // Also fail closed when this pass is invoked without verify-records.
    if (t->dims.size() != 1 || t->bits != 8 || t->dims[0].count < 1 || t->dims[0].count > 8192 ||
        t->offsetBytes < 0 || t->offsetBytes + t->dims[0].count > INT32_MAX)
      return rd.emitOpError("cannot lower without a direct byte array of 1..8192 elements at a representable offset");
    auto i64 = b_.getI64Type();
    Value len = remap(rd.getLen());
    if (cast<IntegerType>(len.getType()).getWidth() < 64)
      len = LLVM::SExtOp::create(b_, loc, i64, len);
    // preserve the verifier-visible comparisons against an opaque register.
    len = LLVM::InlineAsmOp::create(b_, loc, i64, ValueRange{len}, "", "=r,0", true, false,
                                    LLVM::tailcallkind::TailCallKind::None, LLVM::AsmDialectAttr(), ArrayAttr()).getResult(0);
    Value zero = LLVM::ConstantOp::create(b_, loc, i64, b_.getI64IntegerAttr(0));
    Value limit = LLVM::ConstantOp::create(b_, loc, i64, b_.getI64IntegerAttr(t->dims[0].count));
    Value negative = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::slt, len, zero);
    Value nonnegative = LLVM::SelectOp::create(b_, loc, negative, zero, len);
    Value tooLarge = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ugt, nonnegative, limit);
    Value count = LLVM::SelectOp::create(b_, loc, tooLarge, limit, nonnegative);
    Value res = remap(rd.getReservation());
    int64_t begin = t->offsetBytes, end = begin + t->dims[0].count;
    for (int64_t off = begin; off < end;) {
      unsigned width = 8;
      while (width > 1 && (off % width != 0 || off + width > end || bpfabi::kRingbufSampleAlignment % width != 0))
        width /= 2;
      Type ty = b_.getIntegerType(width * 8);
      Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), res,
                                    ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(off)});
      Value z = LLVM::ConstantOp::create(b_, loc, ty, b_.getIntegerAttr(ty, 0));
      auto store = LLVM::StoreOp::create(b_, loc, z, at, provableAlignment(bpfabi::kRingbufSampleAlignment, off, ty));
      store.setVolatile_(true);
      off += width;
    }
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), res,
                                  ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(begin)});
    FailureOr<Value> status = ctx_.helperCall(b_, loc, "probe_read_user", {at, count, remap(rd.getPtr())});
    if (failed(status))
      return failure();
    bind(rd.getStatus(), *status);
    bind(rd.getCount(), LLVM::TruncOp::create(b_, loc, b_.getI32Type(), count));
    return success();
  }
  if (auto rs = dyn_cast<UserReadStrOp>(op)) {
    auto rt = cast<RecordType>(cast<ReservationType>(rs.getReservation().getType()).getRecordType());
    FailureOr<RecordTemplate> t = ctx_.recordTemplate(&op, rt.getSymbol(), (rs.getField() + "[]").str());
    if (failed(t))
      return failure();
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(rs.getReservation()),
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(t->offsetBytes)});
    Value n = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(t->dims[0].count));
    FailureOr<Value> v = ctx_.helperCall(b_, loc, "probe_read_user_str", {at, n, remap(rs.getPtr())});
    if (failed(v))
      return failure();
    bind(rs.getStatus(), *v);
    return success();
  }

  // a sleepable fentry's address is the raw i64 itself (no helper).
  if (auto ua = dyn_cast<UserAddrOp>(op)) {
    bind(ua.getResult(), remap(ua.getValue()));
    return success();
  }
  // bpf_copy_from_user(reservation + field offset, field length, address); raw status.
  if (auto uc = dyn_cast<UserCopyOp>(op)) {
    auto rt = cast<RecordType>(cast<ReservationType>(uc.getReservation().getType()).getRecordType());
    FailureOr<RecordTemplate> t = ctx_.recordTemplate(&op, rt.getSymbol(), (uc.getField() + "[]").str());
    if (failed(t))
      return failure();
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(uc.getReservation()),
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(t->offsetBytes)});
    Value n = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(t->dims[0].count));
    FailureOr<Value> v = ctx_.helperCall(b_, loc, "copy_from_user", {at, n, remap(uc.getAddr())});
    if (failed(v))
      return failure();
    bind(uc.getStatus(), *v);
    return success();
  }

  // bpf_copy_from_user_task(reservation + field offset, field length, address, task, 0); raw status.
  if (auto uc = dyn_cast<UserCopyTaskOp>(op)) {
    auto rt = cast<RecordType>(cast<ReservationType>(uc.getReservation().getType()).getRecordType());
    FailureOr<RecordTemplate> t = ctx_.recordTemplate(&op, rt.getSymbol(), (uc.getField() + "[]").str());
    if (failed(t))
      return failure();
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(uc.getReservation()),
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(t->offsetBytes)});
    Value n = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(t->dims[0].count));
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(0));
    FailureOr<Value> v = ctx_.helperCall(b_, loc, "copy_from_user_task", {at, n, remap(uc.getAddr()), remap(uc.getTask()), flags});
    if (failed(v))
      return failure();
    bind(uc.getStatus(), *v);
    return success();
  }

  // Read char* through an eight-byte CO-RE load, then probe_read_kernel_str
  // into reservation+path offset with constant count. Return raw status.
  if (auto ks = dyn_cast<KernelReadStrOp>(op)) {
    auto rt = cast<RecordType>(cast<ReservationType>(ks.getReservation().getType()).getRecordType());
    FailureOr<RecordTemplate> t = ctx_.recordTemplate(&op, rt.getSymbol(), (ks.getPath() + "[]").str());
    if (failed(t))
      return failure();
    auto base = cast<KPtrType>(ks.getPtr().getType());
    auto src = bpfabi::CoreFieldLoadOp::create(b_, loc, ctx_.ptrTy(), remap(ks.getPtr()), b_.getStringAttr(base.getStructName()),
                                               ks.getFieldAttr());
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), remap(ks.getReservation()),
                                   ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(t->offsetBytes)});
    Value n = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(t->dims[0].count));
    FailureOr<Value> v = ctx_.helperCall(b_, loc, "probe_read_kernel_str", {at, n, src.getResult()});
    if (failed(v))
      return failure();
    bind(ks.getStatus(), *v);
    return success();
  }

  // string buffers — one dedicated entry-block alloca per op (never
  // shared by size or content, no lifetime markers, so stack colouring keeps
  // it apart from every other slot).
  if (isa<StrBufLiteralOp, KernelReadStrBufOp>(op)) {
    auto st = cast<StrBufType>(op.getResult(0).getType());
    int64_t n = st.getSize();
    if (auto lit = dyn_cast<StrBufLiteralOp>(op)) { // All N bytes: the literal, then zeros.
      bind(lit.getBuf(), literalBuffer(lit.getLiteral(), n, loc));
      return success();
    }
    Value buf = allocaFor(LLVM::LLVMArrayType::get(b_.getI8Type(), n), loc);
    cast<LLVM::AllocaOp>(buf.getDefiningOp()).setAlignment(8);
    auto rb = cast<KernelReadStrBufOp>(op); // Not prefilled: the helper writes to the NUL, or zeroes all N bytes.
    auto src = bpfabi::CoreFieldLoadOp::create(b_, loc, ctx_.ptrTy(), remap(rb.getPtr()),
                                               b_.getStringAttr(rb.getPtr().getType().getStructName()), rb.getFieldAttr());
    Value size = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(), b_.getI64IntegerAttr(n));
    FailureOr<Value> v = ctx_.helperCall(b_, loc, "probe_read_kernel_str", {buf, size, src.getResult()});
    if (failed(v))
      return failure();
    bind(rb.getBuf(), buf);
    bind(rb.getStatus(), *v);
    return success();
  }

  if (auto kt = dyn_cast<KtimeOp>(op)) {
    FailureOr<Value> v = ctx_.helperCall(b_, loc, "ktime_get_ns", {});
    if (failed(v))
      return failure();
    bind(kt.getResult(), *v);
    return success();
  }

  // ctx-free scalar helpers. u32 helpers truncate the i64 return; the
  // others keep raw i64 bits. get_current_task stays an integer (no inttoptr).
  {
    StringRef helper;
    bool truncate32 = false;
    if (isa<CpuIdOp>(op))
      helper = "get_smp_processor_id", truncate32 = true;
    else if (isa<RandomU32Op>(op))
      helper = "get_prandom_u32", truncate32 = true;
    else if (isa<NumaNodeIdOp>(op))
      helper = "get_numa_node_id";
    else if (isa<TaskUidGidOp>(op))
      helper = "get_current_uid_gid";
    else if (isa<Jiffies64Op>(op))
      helper = "jiffies64";
    else if (isa<KtimeBootNsOp>(op))
      helper = "ktime_get_boot_ns";
    else if (isa<KtimeCoarseNsOp>(op))
      helper = "ktime_get_coarse_ns";
    else if (isa<KtimeTaiNsOp>(op))
      helper = "ktime_get_tai_ns";
    else if (isa<TaskCurrentRawOp>(op))
      helper = "get_current_task";
    if (!helper.empty()) {
      FailureOr<Value> v = ctx_.helperCall(b_, loc, helper, {});
      if (failed(v))
        return failure();
      Value r = *v;
      if (truncate32)
        r = LLVM::TruncOp::create(b_, loc, b_.getI32Type(), r);
      bind(op.getResult(0), r);
      return success();
    }
  }
  // the int level is passed as clang does (32-bit move, upper zero).
  if (auto anc = dyn_cast<TaskAncestorCgroupIdOp>(op)) {
    Value lvl = LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), remap(anc.getLevel()));
    FailureOr<Value> v = ctx_.helperCall(b_, loc, "get_current_ancestor_cgroup_id", {lvl});
    if (failed(v))
      return failure();
    bind(anc.getResult(), *v);
    return success();
  }
  // RET_PTR_TO_BTF_ID_TRUSTED is never NULL; the pointer becomes the
  // kptr directly, without a NULL branch or ownership.
  // the UAPI signature returns long; the kernel returns a BTF pointer, never NULL.
  if (auto regs = dyn_cast<TaskPtRegsOp>(op)) {
    FailureOr<Value> v = ctx_.helperCall(b_, loc, "task_pt_regs", {remap(regs.getTask())});
    if (failed(v))
      return failure();
    bind(regs.getResult(), LLVM::IntToPtrOp::create(b_, loc, ctx_.ptrTy(), *v));
    return success();
  }
  if (auto cur = dyn_cast<TaskCurrentBtfOp>(op)) {
    FailureOr<Value> v = ctx_.helperCall(b_, loc, "get_current_task_btf", {});
    if (failed(v))
      return failure();
    bind(cur.getResult(), *v);
    return success();
  }

  // ringbuf submit/discard helpers return void, as specified by ABI.
  if (auto submit = dyn_cast<RingbufSubmitOp>(op)) {
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(),
                                           b_.getI64IntegerAttr(0));
    if (failed(ctx_.helperCall(b_, loc, "ringbuf_submit",
                               {remap(submit.getReservation()), flags})))
      return failure();
    return success();
  }

  if (auto discard = dyn_cast<RingbufDiscardOp>(op)) {
    Value flags = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(),
                                           b_.getI64IntegerAttr(0));
    if (failed(ctx_.helperCall(b_, loc, "ringbuf_discard",
                               {remap(discard.getReservation()), flags})))
      return failure();
    return success();
  }

  if (auto packet = dyn_cast<PacketLoadOp>(op)) {
    // Variable offsets need an explicit off<=MAX_PACKET_OFF-width guard before
    // pointer addition or verifier cannot establish a bounded range. Failure
    // follows the out-of-bounds zero-result path. Constants need no such
    // branch. Defensively reject unsupported widths before constructing IR.
    unsigned bits0 = cast<IntegerType>(packet.getResult().getType()).getWidth();
    if (bits0 != 8 && bits0 != 16 && bits0 != 32 && bits0 != 64)
      return packet.emitOpError() << "cannot lower a " << bits0 << "-bit packet read";
    int64_t width0 = bits0 / 8;
    int64_t limit = bpfabi::kMaxPacketOffset - width0;
    APInt constOff;
    bool isConst = matchPattern(packet.getOffset(), m_ConstantInt(&constOff));
    if (isConst && constOff.getZExtValue() > static_cast<uint64_t>(limit))
      return packet.emitOpError()
             << "packet offset " << constOff.getZExtValue() << " + "
             << width0 << " bytes exceeds MAX_PACKET_OFF ("
             << bpfabi::kMaxPacketOffset
             << "); the kernel verifier cannot prove it in bounds";
    // Read context data/data_end at ABI width: xdp_md uses u32, and an
    // eight-byte read would be invalid. Construct bounds branches here.
    auto kind = cast<ContextType>(packet.getCtx().getType()).getKind();
    auto layout = bpfabi::lookupPacketCtx(kind);
    if (!layout)
      return packet.emitOpError() << "program kind \"" << kind
                                  << "\" has no packet in the UAPI table";
    auto range = bpfabi::CtxPacketOp::create(
        b_, loc, TypeRange{ctx_.ptrTy(), ctx_.ptrTy()}, remap(packet.getCtx()),
        b_.getStringAttr(kind), b_.getI64IntegerAttr(layout->dataOffset),
        b_.getI64IntegerAttr(layout->dataEndOffset),
        b_.getI64IntegerAttr(layout->fieldBytes));
    Value data = range.getData();
    Value end = range.getDataEnd();
    Value off = remap(packet.getOffset());
    // Leave i64 offsets unchanged; zero-extension is valid only from narrower widths.
    Value off64 = off.getType() == b_.getI64Type() ? off : LLVM::ZExtOp::create(b_, loc, b_.getI64Type(), off).getResult();
    Type resTy = packet.getResult().getType();
    unsigned width = cast<IntegerType>(resTy).getWidth() / 8;
    // Dynamic-offset upper guard; out-of-range produces zero. Constants skip it.
    Block *limitBlk = nullptr;
    Value tooFar;
    if (!isConst) {
      Value lim = LLVM::ConstantOp::create(b_, loc, b_.getI64Type(),
                                           b_.getI64IntegerAttr(limit));
      tooFar = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ugt, off64,
                                    lim);
      limitBlk = b_.getInsertionBlock();
      Block *inRange = limitBlk->splitBlock(b_.getInsertionPoint());
      b_.setInsertionPointToEnd(inRange);
    }
    Value at = LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), data,
                                   ArrayRef<LLVM::GEPArg>{off64});
    Value past = LLVM::GEPOp::create(
        b_, loc, ctx_.ptrTy(), b_.getI8Type(), at,
        ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(width)});
    Value inBounds = LLVM::ICmpOp::create(b_, loc, LLVM::ICmpPredicate::ule,
                                          past, end);
    Block *cur = b_.getInsertionBlock();
    Block *loadBlk = cur->splitBlock(b_.getInsertionPoint());
    Block *cont = loadBlk->splitBlock(loadBlk->begin());
    Value phi = cont->addArgument(resTy, loc);
    b_.setInsertionPointToEnd(cur);
    Value zero = LLVM::ConstantOp::create(b_, loc, resTy,
                                          b_.getIntegerAttr(resTy, 0));
    LLVM::CondBrOp::create(b_, loc, inBounds, loadBlk, ValueRange{}, cont,
                           ValueRange{zero});
    b_.setInsertionPointToEnd(loadBlk);
    // Assemble wide reads from individual bytes for strict-alignment targets.
    // Keep the full-width bounds check, then shift byte i by 8*i for bpfel.
    // Do not assume NET_IP_ALIGN=2: byte accesses work independently of packet
    // base alignment and CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS.
    // With alignedPacketLoad, a constant offset the strict-alignment rule
    // accepts is one wide load (bpfel, the same little-endian value).
    Value v;
    if (width == 1) {
      v = LLVM::LoadOp::create(b_, loc, resTy, at);
    } else if (ctx_.alignedPacketLoad && isConst && strictAlignedPacketRead(constOff.getZExtValue(), width)) {
      v = LLVM::LoadOp::create(b_, loc, resTy, at, /*alignment=*/width);
    } else {
      for (unsigned i = 0; i < width; ++i) {
        Value p = i == 0 ? at
                         : LLVM::GEPOp::create(b_, loc, ctx_.ptrTy(), b_.getI8Type(), at,
                                               ArrayRef<LLVM::GEPArg>{static_cast<int32_t>(i)})
                               .getResult();
        Value byte = LLVM::LoadOp::create(b_, loc, b_.getI8Type(), p, /*alignment=*/1);
        Value wide = LLVM::ZExtOp::create(b_, loc, resTy, byte);
        if (i != 0) {
          Value sh = LLVM::ConstantOp::create(b_, loc, resTy, b_.getIntegerAttr(resTy, 8 * i));
          wide = LLVM::ShlOp::create(b_, loc, wide, sh);
          wide = LLVM::OrOp::create(b_, loc, v, wide);
        }
        v = wide;
      }
    }
    LLVM::BrOp::create(b_, loc, ValueRange{v}, cont);
    if (limitBlk) {
      b_.setInsertionPointToEnd(limitBlk);
      Value zero2 = LLVM::ConstantOp::create(b_, loc, resTy,
                                             b_.getIntegerAttr(resTy, 0));
      LLVM::CondBrOp::create(b_, loc, tooFar, cont, ValueRange{zero2}, cur,
                             ValueRange{});
    }
    b_.setInsertionPointToEnd(cont);
    bind(packet.getResult(), phi);
    return success();
  }

  // Clone only arithmetic. CFG branches were lowered explicitly; never
  // generically clone unsupported operations, even with this pass used alone.
  if (op.getName().getDialectNamespace() != "arith")
    return op.emitOpError() << "is not supported by convert-ebpf-to-bpfabi";
  IRMapping m;
  for (Value v : op.getOperands())
    if (Value r = remap(v))
      m.map(v, r);
  // Barrier constant return-select arms with instruction-free '=r,0' asm,
    // preserving values while preventing unsafe range-losing folds.
  if (retSelects_.contains(&op))
    for (unsigned i : {1u, 2u}) {
      Value arm = op.getOperand(i);
      if (!matchPattern(arm, m_Constant()) || !remap(arm))
        continue;
      Value r = remap(arm);
      m.map(arm, LLVM::InlineAsmOp::create(b_, loc, r.getType(), ValueRange{r}, "", "=r,0", /*has_side_effects=*/true,
                                           /*is_align_stack=*/false, LLVM::tailcallkind::TailCallKind::None,
                                           /*asm_dialect=*/LLVM::AsmDialectAttr(), /*operand_attrs=*/ArrayAttr())
                     .getResult(0));
    }
  Operation *cloned = b_.clone(op, m);
  for (auto [i, res] : llvm::enumerate(op.getResults()))
    bind(res, cloned->getResult(i));
  return success();
}

void ConvertEBPFToBPFABIPass::runOnOperation() {
  ModuleOp module = getOperation();
  Lowering ctx(module);
  ctx.skipFullCoverMemset = skipFullCoverMemset;
  ctx.storeRecordDirect = storeRecordDirect || storeRecordMerge;
  ctx.storeRecordMerge = storeRecordMerge;
  ctx.warnIndexMaskFit = warnIndexMaskFit;
  ctx.shareKeySlot = shareKeySlot;
  ctx.spillLifetime = spillLifetime;
  ctx.alignedPacketLoad = alignedPacketLoad;

  // Collect every reaching program kind per subprogram. Source graph checks
  // already rejected cycles/unreachable funcs; fail if one still appears here.
  llvm::StringMap<SubprogramOp> funcs;
  for (auto fn : module.getOps<SubprogramOp>())
    funcs[fn.getSymName()] = fn;
  llvm::StringMap<std::set<std::string>> kindsOf;
  std::function<void(Operation *, StringRef)> reach = [&](Operation *owner,
                                                          StringRef kind) {
    owner->walk([&](CallOp call) {
      auto it = funcs.find(call.getCallee());
      if (it == funcs.end())
        return;
      if (kindsOf[call.getCallee()].insert(kind.str()).second)
        reach(it->second, kind);
    });
    // Include calls inside outlined helper callbacks.
    owner->walk([&](Operation *op) { // callbackOf also includes for_each_map_elem.
      if (FlatSymbolRefAttr ref = callbackOf(op))
        if (auto cb = SymbolTable::lookupNearestSymbolFrom<LoopCallbackOp>(op, ref))
          reach(cb, kind);
    });
    // a timer callback's calls (sched_ext_ops owners) reach with the owner's kind.
    owner->walk([&](TimerSetCallbackOp sc) {
      if (auto cb = SymbolTable::lookupNearestSymbolFrom<TimerCallbackOp>(sc, sc.getCallbackAttr()))
        reach(cb, kind);
    });
  };
  for (auto p : module.getOps<ProgramOp>())
    reach(p, p.getKind());

  // Callbacks inherit every using program kind, recursively through nested
  // helper loops and through functions with multiple reaching programs.
  llvm::StringMap<std::set<std::string>> callbackKind;
  std::function<void(Operation *, StringRef)> kindOfCallbacks = [&](Operation *owner, StringRef kind) {
    owner->walk([&](Operation *op) { // callbackOf also includes for_each_map_elem.
      FlatSymbolRefAttr ref = callbackOf(op);
      if (!ref || !callbackKind[ref.getValue()].insert(kind.str()).second)
        return;
      if (auto cb = SymbolTable::lookupNearestSymbolFrom<LoopCallbackOp>(op, ref))
        kindOfCallbacks(cb, kind);
    });
  };
  for (auto p : module.getOps<ProgramOp>())
    kindOfCallbacks(p, p.getKind());
  for (auto fn : module.getOps<SubprogramOp>())
    for (const std::string &k : kindsOf.lookup(fn.getSymName()))
      kindOfCallbacks(fn, k);

  // Timer callbacks inherit the program kind that registers them.
  llvm::StringMap<std::set<std::string>> timerCallbackKind;
  for (auto p : module.getOps<ProgramOp>())
    p->walk([&](TimerSetCallbackOp sc) { timerCallbackKind[sc.getCallback()].insert(p.getKind().str()); });

  // User-ring callbacks inherit the program kind invoking drain.
  llvm::StringMap<std::set<std::string>> userRbCallbackKind;
  for (auto p : module.getOps<ProgramOp>())
    p->walk([&](UserRingbufDrainOp d) { userRbCallbackKind[d.getCallback()].insert(p.getKind().str()); });

  SmallVector<Operation *> owners;
  module.walk([&](Operation *op) {
    if (isa<ProgramOp, SubprogramOp, LoopCallbackOp, TimerCallbackOp, UserRingbufCallbackOp>(op))
      owners.push_back(op);
  });
  for (Operation *o : owners) {
    if (auto uc = dyn_cast<UserRingbufCallbackOp>(o)) {
      auto it = userRbCallbackKind.find(uc.getSymName());
      if (it == userRbCallbackKind.end()) {
        uc.emitOpError() << "is not used by any ebpf.user_ringbuf.drain in a program";
        return signalPassFailure();
      }
      ctx.programKinds.clear();
      for (const std::string &k : it->second)
        ctx.programKinds.push_back(StringAttr::get(module.getContext(), k).getValue());
    }
    if (auto tc = dyn_cast<TimerCallbackOp>(o)) {
      auto it = timerCallbackKind.find(tc.getSymName());
      if (it == timerCallbackKind.end()) {
        tc.emitOpError() << "is not used by any ebpf.timer.set_callback in a program";
        return signalPassFailure();
      }
      ctx.programKinds.clear();
      for (const std::string &k : it->second)
        ctx.programKinds.push_back(StringAttr::get(module.getContext(), k).getValue());
    }
    if (auto cb = dyn_cast<LoopCallbackOp>(o)) {
      auto it = callbackKind.find(cb.getSymName());
      if (it == callbackKind.end()) {
        cb.emitOpError() << "is not used by any ebpf.bpf_loop in a program";
        return signalPassFailure();
      }
      ctx.programKinds.clear();
      for (const std::string &k : it->second)
        ctx.programKinds.push_back(StringAttr::get(module.getContext(), k).getValue());
    }
    if (auto fn = dyn_cast<SubprogramOp>(o)) {
      auto it = kindsOf.find(fn.getSymName());
      if (it == kindsOf.end()) {
        fn.emitOpError() << "is not reachable from any ebpf.program; run "
                            "ebpf-verify-call-graph before convert-ebpf-to-bpfabi";
        return signalPassFailure();
      }
      ctx.programKinds.clear();
      for (const std::string &k : it->second)
        // Context-uniqued StringAttr keeps StringRefs alive throughout the pass.
        ctx.programKinds.push_back(StringAttr::get(module.getContext(), k).getValue());
    }
    ProgramLowering pl(o, ctx);
    if (failed(pl.run()) || ctx.failed) {
      signalPassFailure();
      return;
    }
  }
  // the arena size is consumed by the arena.check_br lowering; keep the
  // attribute out of the later stages (LLVM translation).
  module->removeAttr(Lowering::kArenaBytesAttr);
}

} // namespace
