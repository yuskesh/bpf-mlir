//===- BuildBTF.cpp - construct BTF IR from schema and lowered module --------===//
//
// Records become @records structs; kernel_types become local CO-RE @kernel
// structs. Used maps become .maps vars, records get const-pointer witnesses in
// .ebpf_records, license becomes a char-array var, and program functions get
// BTF signatures with void* contexts.
//===----------------------------------------------------------------------===//
#include <set>
#include "bpf-mlir/Dialect/BTF/Transforms/Passes.h"

#include "bpf-mlir/Dialect/BPFABI/KernelABI.h"
#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"
#include "bpf-mlir/Support/ProgramKinds.h"
#include "bpf-mlir/Support/StructOpsTypes.h"
#include "bpf-mlir/Target/EBPF/Schema.h"

#include "mlir/IR/Builders.h"
#include "llvm/Support/MemoryBuffer.h"

namespace mlir {
namespace btf {
#define GEN_PASS_DEF_EBPFBUILDBTF
#define GEN_PASS_DEF_EBPFBUILDBTFTYPES
#include "bpf-mlir/Dialect/BTF/Transforms/Passes.h.inc"
} // namespace btf
} // namespace mlir

using namespace mlir;

// C spellings for local CO-RE integer types. cilium/libbpf do not match INT names.
static const char *kernelIntName(unsigned bits, bool isSigned) {
  switch (bits) {
  case 8: return isSigned ? "signed char" : "unsigned char";
  case 16: return isSigned ? "short" : "unsigned short";
  case 64: return isSigned ? "long long" : "unsigned long long";
  default: return isSigned ? "int" : "unsigned int";
  }
}
using namespace mlir::btf;

namespace {

llvm::StringRef mapTypeName(::ebpf::MapKind k) { return ::ebpf::mapKindSpelling(k); } // Canonical NAME from MapKinds.def.

struct Builder {
  MLIRContext *ctx;
  const ::ebpf::Schema &schema;

  Attribute cInt() { return IntAttr::get(ctx, "int", 32, "signed"); }

  // Schema types to BTF types.
  Attribute typeOf(const ::ebpf::Type &t) {
    if (const auto *i = std::get_if<::ebpf::IntType>(&t.v))
      return IntAttr::get(ctx, (i->isSigned ? "s" : "u") + std::to_string(i->bits),
                          i->bits, i->isSigned ? "signed" : "unsigned");
    if (const auto *a = std::get_if<::ebpf::ArrayType>(&t.v))
      return ArrayOfAttr::get(ctx, typeOf(*a->element), a->count);
    // Lock fields reference @records bpf_spin_lock, created only when needed.
    if (std::holds_alternative<::ebpf::SpinLockType>(t.v))
      return recordRef("bpf_spin_lock");
    // Timer fields reference @records bpf_timer.
    if (std::holds_alternative<::ebpf::TimerType>(t.v))
      return recordRef("bpf_timer");
    // an embedded cpumask references the opaque @records __ebpf_cpumask_<N>.
    if (const auto *c = std::get_if<::ebpf::CpumaskType>(&t.v))
      return recordRef(cpumaskStructName(c->size));
    // Schema confines stack_build_id to untyped stack_trace values. If reached,
    // represent it as 32 opaque bytes.
    if (std::holds_alternative<::ebpf::StackBuildIdType>(t.v))
      return ArrayOfAttr::get(ctx, IntAttr::get(ctx, "u8", 8, "unsigned"), 32);
    // Referenced map-value kptr: PTR -> TYPE_TAG kptr -> local @kernel struct T.
    // Kernel resolves the target vmlinux struct by name.
    if (const auto *kp = std::get_if<::ebpf::KptrType>(&t.v))
      return PtrAttr::get(ctx, TypeTagAttr::get(ctx, "kptr",
                                                RefAttr::get(ctx, SymbolRefAttr::get(ctx, "kernel", {FlatSymbolRefAttr::get(ctx, kp->structName)}))));
    const auto &r = std::get<::ebpf::RecordRefType>(t.v);
    return recordRef(r.symbol);
  }
  static std::string cpumaskStructName(uint64_t n) { return "__ebpf_cpumask_" + std::to_string(n); }
  Attribute recordRef(llvm::StringRef sym) {
    return RefAttr::get(ctx, SymbolRefAttr::get(ctx, "records",
                                                {FlatSymbolRefAttr::get(ctx, sym)}));
  }
  uint64_t bitsOf(const ::ebpf::Type &t) {
    auto sz = schema.sizeOf(t);
    if (!sz) {
      llvm::consumeError(sz.takeError());
      return 0;
    }
    return *sz * 8;
  }
  // __uint(name,N) is int (*name)[N]. Preserve N=0, including perf_event_array
  // max_entries, matching clang C flexible/zero-length array encoding.
  MemberAttr uintMember(llvm::StringRef name, uint64_t value, uint64_t offsetBits) {
    return MemberAttr::get(ctx, name, offsetBits, 64,
                           PtrAttr::get(ctx, ArrayOfAttr::get(ctx, cInt(), value)));
  }
  // __type(name,T) is T *name.
  MemberAttr typeMember(llvm::StringRef name, const ::ebpf::Type &t, uint64_t offsetBits) {
    return MemberAttr::get(ctx, name, offsetBits, 64, PtrAttr::get(ctx, typeOf(t)));
  }
};


// Append @records/schema records and @kernel/local CO-RE declarations.
// Used before source kptr/field verification, or later if not already built.
bool hasScope(ModuleOp module, StringRef name) {
  for (auto sc : module.getOps<ScopeOp>())
    if (sc.getSymName() == name)
      return true;
  return false;
}

void buildTypeScopes(ModuleOp module, const ::ebpf::Schema &schema) {
  MLIRContext *ctx = module.getContext();
  Builder bb{ctx, schema};
  OpBuilder b(ctx);
  b.setInsertionPointToEnd(module.getBody());
  Location loc = module.getLoc();
  auto i64 = [&](int64_t v) { return b.getI64IntegerAttr(v); };
  const ::ebpf::Schema *sp = &schema;
  // record
  {
    auto scope = ScopeOp::create(b, loc, "records");
    scope.getBody().emplaceBlock();
    OpBuilder sb = OpBuilder::atBlockEnd(&scope.getBody().front());
    // Kernel identifies locks by name and size: bpf_spin_lock { u32 val; },
    // with size from ABI. Create it only for lock-bearing records.
    bool anyLock = false;
    for (const ::ebpf::Record &r : sp->records())
      for (const ::ebpf::Field &f : r.fields)
        anyLock |= std::holds_alternative<::ebpf::SpinLockType>(f.type.v);
    if (anyLock) {
      std::optional<int64_t> sz = mlir::bpfabi::lookupUapiStructSize("bpf_spin_lock");
      if (!sz) {
        module.emitError() << "struct bpf_spin_lock is not in the UAPI table";
        return;
      }
      Attribute u32 = IntAttr::get(ctx, "u32", 32, "unsigned");
      StructOp::create(sb, loc, sb.getStringAttr("bpf_spin_lock"), i64(*sz * 8), i64(32),
                       sb.getArrayAttr({MemberAttr::get(ctx, "val", 0, 32, u32)}));
    }
    // Kernel identifies timers by name and size: bpf_timer { u64 __opaque[2]; }.
    // Use ABI size and kTimerAlignment (UAPI aligned(8)) when needed.
    bool anyTimer = false;
    for (const ::ebpf::Record &r : sp->records())
      for (const ::ebpf::Field &f : r.fields)
        anyTimer |= std::holds_alternative<::ebpf::TimerType>(f.type.v);
    if (anyTimer) {
      std::optional<int64_t> sz = mlir::bpfabi::lookupUapiStructSize("bpf_timer");
      if (!sz || *sz % 8 != 0) {
        module.emitError() << "struct bpf_timer is not in the UAPI table (or its size is not a multiple of 8)";
        return;
      }
      Attribute u64 = IntAttr::get(ctx, "u64", 64, "unsigned");
      StructOp::create(sb, loc, sb.getStringAttr("bpf_timer"), i64(*sz * 8), i64(mlir::bpfabi::kTimerAlignment * 8),
                       sb.getArrayAttr({MemberAttr::get(ctx, "__opaque", 0, *sz * 8, ArrayOfAttr::get(ctx, u64, *sz / 8))}));
    }
    // one opaque __ebpf_cpumask_<N> { u8 __opaque[N] } per distinct size N
    // (alignment 8 — the schema keeps the field 8-byte aligned). Not named
    // bpf_cpumask: the kfunc protos in the same BTF refer to the kernel's struct.
    std::set<uint64_t> cpumaskSizes;
    for (const ::ebpf::Record &r : sp->records())
      for (const ::ebpf::Field &f : r.fields)
        if (const auto *c = std::get_if<::ebpf::CpumaskType>(&f.type.v))
          cpumaskSizes.insert(c->size);
    for (uint64_t n : cpumaskSizes) {
      Attribute u8 = IntAttr::get(ctx, "u8", 8, "unsigned");
      StructOp::create(sb, loc, sb.getStringAttr(Builder::cpumaskStructName(n)), i64(n * 8), i64(64),
                       sb.getArrayAttr({MemberAttr::get(ctx, "__opaque", 0, n * 8, ArrayOfAttr::get(ctx, u8, n))}));
    }
    for (const ::ebpf::Record &r : sp->records()) {
      SmallVector<Attribute> ms;
      for (const ::ebpf::Field &f : r.fields)
        ms.push_back(MemberAttr::get(ctx, f.name, f.offset * 8, bb.bitsOf(f.type),
                                     bb.typeOf(f.type)));
      StructOp::create(sb, loc, sb.getStringAttr(r.symbol), i64(r.size * 8), i64(r.alignment * 8),
                       sb.getArrayAttr(ms));
    }
  }
  // Local CO-RE integer fields use 8/16/32/64-bit widths and maximum-width alignment.
  // an arena map adds the local bpf_arena { user_vm_start: u64 } (provisional
  // offset 0, like kernel_types) for the window base's CO-RE read; the schema
  // reserves the name, so it never collides with a user kernel_types entry.
  const bool anyArena = llvm::any_of(sp->maps(), [](const ::ebpf::Map &m) { return m.kind == ::ebpf::MapKind::Arena; });
  // the arena size (pages × 4096 bytes) for ③'s arena.check_br compare —
  // ③ has no schema. Keyed by map symbol; consumed (removed) by ③.
  if (anyArena) {
    SmallVector<NamedAttribute> sizes;
    for (const ::ebpf::Map &m : sp->maps())
      if (m.kind == ::ebpf::MapKind::Arena)
        sizes.push_back(b.getNamedAttr(m.symbol, b.getI64IntegerAttr(static_cast<int64_t>(m.maxEntries * ::ebpf::kArenaPageSize))));
    module->setAttr("ebpf.arena_bytes", b.getDictionaryAttr(sizes));
  }
  if (!sp->kernelTypes().empty() || anyArena) {
    auto scope = ScopeOp::create(b, loc, "kernel");
    scope.getBody().emplaceBlock();
    OpBuilder sb = OpBuilder::atBlockEnd(&scope.getBody().front());
    if (anyArena)
      StructOp::create(sb, loc, sb.getStringAttr("bpf_arena"), i64(64), i64(64),
                       sb.getArrayAttr({MemberAttr::get(ctx, "user_vm_start", 0, 64,
                                                        IntAttr::get(ctx, kernelIntName(64, false), 64, "unsigned"))}));
    for (const ::ebpf::KernelType &k : sp->kernelTypes()) {
      SmallVector<Attribute> ms;
      unsigned align = 32;
      for (const ::ebpf::KernelField &f : k.fields) {
        if (!f.embedded.empty()) {
          const auto *child = sp->kernelType(f.embedded);
          align = std::max(align, static_cast<unsigned>(child->alignment * 8));
          ms.push_back(MemberAttr::get(ctx, f.name, f.offset * 8, child->size * 8,
              RefAttr::get(ctx, SymbolRefAttr::get(ctx, "kernel", {FlatSymbolRefAttr::get(ctx, f.embedded)}))));
          continue;
        }
        if (!f.ptrTo.empty()) { // PTR -> @kernel::T; cilium/libbpf poison a non-pointer local member.
          align = std::max(align, 64u);
          ms.push_back(MemberAttr::get(ctx, f.name, f.offset * 8, 64,
                                       PtrAttr::get(ctx, RefAttr::get(ctx, SymbolRefAttr::get(ctx, "kernel",
                                                                   {FlatSymbolRefAttr::get(ctx, f.ptrTo)})))));
          continue;
        }
        if (f.strPtr) { // char* is PTR -> INT char; CO-RE poisons a non-pointer local member.
          align = std::max(align, 64u);
          ms.push_back(MemberAttr::get(ctx, f.name, f.offset * 8, 64, PtrAttr::get(ctx, IntAttr::get(ctx, "char", 8, "char"))));
          continue;
        }
        if (f.voidPtr) { // void * is PTR -> VOID (type id 0), as clang's.
          align = std::max(align, 64u);
          ms.push_back(MemberAttr::get(ctx, f.name, f.offset * 8, 64, PtrAttr::get(ctx, VoidAttr::get(ctx))));
          continue;
        }
        if (f.arrayCount) { // Eight-bit integer array.
          ms.push_back(MemberAttr::get(ctx, f.name, f.offset * 8, f.arrayCount * 8,
                                       ArrayOfAttr::get(ctx,
                                                        IntAttr::get(ctx, kernelIntName(8, f.type.isSigned), 8,
                                                                     f.type.isSigned ? "signed" : "unsigned"),
                                                        f.arrayCount)));
          continue;
        }
        unsigned bits = f.type.bits;
        align = std::max(align, bits);
        if (f.isEnum) { // anonymous enum; an int local member would not relocate against a target ENUM.
          ms.push_back(MemberAttr::get(ctx, f.name, f.offset * 8, bits, EnumAttr::get(ctx, bits)));
          continue;
        }
        ms.push_back(MemberAttr::get(ctx, f.name, f.offset * 8, bits,
                                     IntAttr::get(ctx, kernelIntName(bits, f.type.isSigned), bits,
                                                  f.type.isSigned ? "signed" : "unsigned")));
      }
      StructOp::create(sb, loc, sb.getStringAttr(k.name), i64(k.size * 8), i64(align), sb.getArrayAttr(ms));
    }
  }
}

FailureOr<::ebpf::Schema> loadSchema(ModuleOp module, StringRef path) {
  if (path.empty()) {
    module.emitError() << "needs --schema=<path>";
    return failure();
  }
  auto buf = llvm::MemoryBuffer::getFile(path);
  if (!buf) {
    module.emitError() << "cannot read schema " << path;
    return failure();
  }
  auto schema = ::ebpf::Schema::parseJSON((*buf)->getBuffer());
  if (!schema) {
    module.emitError() << "schema: " << llvm::toString(schema.takeError());
    return failure();
  }
  return std::move(*schema);
}

struct EBPFBuildBTFTypesPass : public mlir::btf::impl::EBPFBuildBTFTypesBase<EBPFBuildBTFTypesPass> {
  using Base::Base;
  void runOnOperation() override {
    ModuleOp module = getOperation();
    auto schema = loadSchema(module, schemaPath);
    if (failed(schema))
      return signalPassFailure();
    if (hasScope(module, "records") || hasScope(module, "kernel")) {
      module.emitError() << "btf type declarations are already in the module";
      return signalPassFailure();
    }
    buildTypeScopes(module, *schema);
  }
};

struct EBPFBuildBTFPass : public mlir::btf::impl::EBPFBuildBTFBase<EBPFBuildBTFPass> {
  using Base::Base;

  void runOnOperation() override {
    ModuleOp module = getOperation();
    if (schemaPath.empty()) {
      module.emitError() << "ebpf-build-btf needs --schema=<path>";
      return signalPassFailure();
    }
    auto buf = llvm::MemoryBuffer::getFile(schemaPath);
    if (!buf) {
      module.emitError() << "cannot read schema " << schemaPath;
      return signalPassFailure();
    }
    auto schema = ::ebpf::Schema::parseJSON((*buf)->getBuffer());
    if (!schema) {
      module.emitError() << "schema: " << llvm::toString(schema.takeError());
      return signalPassFailure();
    }
    MLIRContext *ctx = &getContext();
    Builder bb{ctx, *schema};
    OpBuilder b(ctx);
    b.setInsertionPointToEnd(module.getBody());
    Location loc = module.getLoc();
    auto i64 = [&](int64_t v) { return b.getI64IntegerAttr(v); };

    // Reuse type scopes already created by ebpf-build-btf-types.
    if (!hasScope(module, "records"))
      buildTypeScopes(module, *schema);
    // @objects separates names from lowering's llvm.mlir.global/llvm.func symbols.
    auto objects = ScopeOp::create(b, loc, "objects");
    objects.getBody().emplaceBlock();
    OpBuilder ob = OpBuilder::atBlockEnd(&objects.getBody().front());
    // Include only maps with .maps placeholders emitted by lowering.
    bool bad = false;
    for (const ::ebpf::Map &mp : schema->maps()) {
      auto g = module.lookupSymbol<LLVM::GlobalOp>(mp.symbol);
      if (!g)
        continue;
      std::optional<int64_t> typeId = mlir::bpfabi::lookupMapType(mapTypeName(mp.kind));
      if (!typeId) {
        g.emitError() << "map \"" << mp.symbol << "\": map type \"" << mapTypeName(mp.kind)
                      << "\" is not in the UAPI table";
        bad = true;
        continue;
      }
      SmallVector<MemberAttr> ms{bb.uintMember("type", *typeId, 0),
                                 bb.uintMember("max_entries", mp.maxEntries, 64)};
      // prog_array uses key_size/value_size=4, not typed BTF: 6.12/6.6
      // map_check_no_btf reject types, which cilium would silently strip/retry.
      // cpumap/xskmap/devmap_hash also use untyped u32/u32 definitions.
      if (mp.kind == ::ebpf::MapKind::ProgArray || mp.kind == ::ebpf::MapKind::PerfEventArray || mp.kind == ::ebpf::MapKind::Devmap ||
          mp.kind == ::ebpf::MapKind::Cpumap || mp.kind == ::ebpf::MapKind::Xskmap || mp.kind == ::ebpf::MapKind::DevmapHash ||
          mp.kind == ::ebpf::MapKind::CgroupArray) { // cgroup_array, perf_event_array and devmap likewise reject typed BTF.
        // Untyped key_size/value_size=4 avoids cilium stripping BTF and retrying;
        // libbpf strips it without an initial typed attempt.
        ms.push_back(bb.uintMember("key_size", 4, 128));
        ms.push_back(bb.uintMember("value_size", 4, 192));
      } else if (mp.kind == ::ebpf::MapKind::Sockmap || mp.kind == ::ebpf::MapKind::Sockhash) {
        // sockmap/sockhash use map_check_no_btf. Untyped sizes follow schema:
        // integer key width for sockhash and u32/u64 socket-FD values.
        auto ksz = schema->sizeOf(*mp.key);
        if (!ksz) {
          g.emitError() << "map \"" << mp.symbol << "\": " << llvm::toString(ksz.takeError());
          bad = true;
          continue;
        }
        auto vsz = schema->sizeOf(*mp.value);
        if (!vsz) {
          g.emitError() << "map \"" << mp.symbol << "\": " << llvm::toString(vsz.takeError());
          bad = true;
          continue;
        }
        ms.push_back(bb.uintMember("key_size", *ksz, 128));
        ms.push_back(bb.uintMember("value_size", *vsz, 192));
      } else if (mp.kind == ::ebpf::MapKind::ArrayOfMaps || mp.kind == ::ebpf::MapKind::HashOfMaps) {
        // Outer map-in-map types reject typed BTF keys. Use key_size and libbpf's
        // __array(values,struct inner): final values is a zero-element array
        // of pointers to the anonymous template definition (type/max_entries/
        // key/value/map_flags). cilium creates <outer>_inner and sets outer
        // value_size to four.
        auto ksz = schema->sizeOf(*mp.key);
        const ::ebpf::Map *tpl = nullptr;
        for (const ::ebpf::Map &o : schema->maps())
          if (o.symbol == mp.inner)
            tpl = &o;
        std::optional<int64_t> tplType = tpl ? mlir::bpfabi::lookupMapType(mapTypeName(tpl->kind)) : std::nullopt;
        if (!ksz || !tpl || !tplType || !tpl->key || !tpl->value) {
          if (!ksz)
            g.emitError() << "map \"" << mp.symbol << "\": " << llvm::toString(ksz.takeError());
          else
            g.emitError() << "map \"" << mp.symbol << "\": inner map template \"" << mp.inner << "\" is not a map with a key, a value and a UAPI map type";
          bad = true;
          continue;
        }
        SmallVector<MemberAttr> tm{bb.uintMember("type", *tplType, 0), bb.uintMember("max_entries", tpl->maxEntries, 64),
                                   bb.typeMember("key", *tpl->key, 128), bb.typeMember("value", *tpl->value, 192)};
        if (tpl->flags != 0)
          tm.push_back(bb.uintMember("map_flags", tpl->flags, tm.size() * 64));
        auto tplDef = AnonStructAttr::get(ctx, tm.size() * 64, 64, tm);
        ms.push_back(bb.uintMember("key_size", *ksz, 128));
        if (mp.flags != 0)
          ms.push_back(bb.uintMember("map_flags", mp.flags, ms.size() * 64));
        uint64_t sizeBits = ms.size() * 64; // Zero-element values has size zero, like a C flexible-array member.
        ms.push_back(MemberAttr::get(ctx, "values", sizeBits, 0, ArrayOfAttr::get(ctx, PtrAttr::get(ctx, tplDef), 0)));
        auto ty = AnonStructAttr::get(ctx, sizeBits, 64, ms);
        Location vloc = loc;
        module.walk([&](LLVM::AddressOfOp a) {
          if (a.getGlobalName() == mp.symbol) {
            vloc = a.getLoc();
            return WalkResult::interrupt();
          }
          return WalkResult::advance();
        });
        VarOp::create(ob, vloc, mp.symbol, ty, ".maps");
        continue;
      } else if (mp.kind == ::ebpf::MapKind::StackTrace) {
        // stack_trace uses untyped key_size=4. Value size comes from schema:
        // eight bytes per IP or 32 per build-ID entry, times depth.
        auto vsz = schema->sizeOf(*mp.value);
        if (!vsz) {
          g.emitError() << "map \"" << mp.symbol << "\": " << llvm::toString(vsz.takeError());
          bad = true;
          continue;
        }
        ms.push_back(bb.uintMember("key_size", 4, 128));
        ms.push_back(bb.uintMember("value_size", *vsz, 192));
      } else if (mp.kind == ::ebpf::MapKind::Queue || mp.kind == ::ebpf::MapKind::Stack) {
        // queue/stack have no keys and use untyped type/max_entries/value_size.
        // With key BTF ID zero and no map_check_btf implementation, kernel
        // rejects typed definitions; avoid cilium's silent strip/retry.
        auto vsz = schema->sizeOf(*mp.value);
        if (!vsz) {
          g.emitError() << "map \"" << mp.symbol << "\": " << llvm::toString(vsz.takeError());
          bad = true;
          continue;
        }
        ms.push_back(bb.uintMember("value_size", *vsz, 128));
      } else if (mp.kind == ::ebpf::MapKind::BloomFilter) {
        // bloom_filter permits a typed value without a key member: bloom_map_check_btf accepts void keys.
        ms.push_back(bb.typeMember("value", *mp.value, 128));
      } else if (mp.kind == ::ebpf::MapKind::Arena) {
        // arena has no key/value members (kernel key_size / value_size 0);
        // map_flags and map_extra follow below.
      } else {
        if (mp.key)
          ms.push_back(bb.typeMember("key", *mp.key, 128));
        if (mp.value)
          ms.push_back(bb.typeMember("value", *mp.value, 192));
      }
      // Emit map_flags only when nonzero, preserving BTF for default-flag maps.
      if (mp.flags != 0)
        ms.push_back(bb.uintMember("map_flags", mp.flags, ms.size() * 64));
      // arena map_extra (the user address) is libbpf __ulong — an anonymous
      // ENUM64 member with one enumerator, always this one form. The __uint form
      // (int (*)[N]) cannot carry values above U32_MAX bytes (btf-verify K9).
      if (mp.kind == ::ebpf::MapKind::Arena)
        ms.push_back(MemberAttr::get(ctx, "map_extra", ms.size() * 64, 64, ULongAttr::get(ctx, mp.mapExtra)));
      auto ty = AnonStructAttr::get(ctx, ms.size() * 64, 64, ms);
      // Use the first referring addressof location for map definitions, returning
      // BTF diagnostics to frontend source. Fall back to module location if
      // only the placeholder exists.
      Location vloc = loc;
      module.walk([&](LLVM::AddressOfOp a) {
        if (a.getGlobalName() == mp.symbol) {
          vloc = a.getLoc();
          return WalkResult::interrupt();
        }
        return WalkResult::advance();
      });
      VarOp::create(ob, vloc, mp.symbol, ty, ".maps");
    }
    // struct_ops maps use a local kernel-named struct in @struct_ops plus a
    // .struct_ops.link var. Loaders find bpf_struct_ops_<name> in target BTF
    // and match members by name. Function pointers use minimal void() prototypes;
    // loaders only require their pointer shape. DATA rows follow them.
    // convert-btf-to-llvm-di builds initial addresses/data from the attributes.
    for (const ::ebpf::Map &mp : schema->maps()) {
      if (!mp.structOps)
        continue;
      ScopeOp sops;
      for (auto sc : module.getOps<ScopeOp>())
        if (sc.getSymName() == "struct_ops")
          sops = sc;
      if (!sops) {
        OpBuilder::InsertionGuard guard(b);
        b.setInsertionPoint(objects);
        sops = ScopeOp::create(b, loc, "struct_ops");
        sops.getBody().emplaceBlock();
      }
      OpBuilder sb = OpBuilder::atBlockEnd(&sops.getBody().front());
      auto fptr = PtrAttr::get(ctx, FuncProtoAttr::get(ctx, VoidAttr::get(ctx), ob.getArrayAttr({})));
      SmallVector<Attribute> ms, progs;
      uint64_t off = 0;
      for (const ::ebpf::Map::StructOps::Op &op : mp.structOps->ops) {
        auto fn = module.lookupSymbol<LLVM::LLVMFuncOp>(op.program);
        if (!fn || fn.isExternal()) {
          module.emitError() << "struct_ops map \"" << mp.symbol << "\": member \"" << op.member << "\" names program \"" << op.program
                             << "\", which is not a program of this module";
          bad = true;
          continue;
        }
        ms.push_back(MemberAttr::get(ctx, op.member, off, 64, fptr));
        progs.push_back(FlatSymbolRefAttr::get(ctx, op.program));
        off += 64;
      }
      // DATA rows follow table order: str char[BYTES] (name) always, integer
      // u32 / u64 only when the schema has the key (absent stays zero). Integers
      // are naturally aligned. tcp_congestion_ops has name[16]; types without
      // DATA have only callbacks.
      SmallVector<Attribute> data;
      for (const bpfmlir::StructOpsDataInfo *d : bpfmlir::structOpsDataOf(mp.structOps->type)) {
        if (bpfmlir::isStructOpsIntData(*d)) {
          auto it = llvm::find_if(mp.structOps->data, [&](const ::ebpf::Map::StructOps::Data &x) { return x.member == d->member; });
          if (it == mp.structOps->data.end())
            continue;
          uint64_t bits = uint64_t(d->bytes) * 8;
          off = llvm::alignTo(off, bits);
          ms.push_back(MemberAttr::get(ctx, d->member, off, bits, IntAttr::get(ctx, d->kind, bits, "unsigned")));
          off += bits;
          data.push_back(ob.getIntegerAttr(ob.getIntegerType(bits), APInt(bits, it->value)));
          continue;
        }
        if (d->kind != "str" || d->schemaKey != "name") {
          module.emitError() << "struct_ops map \"" << mp.symbol << "\": data member " << mp.structOps->type << "." << d->member
                             << " of kind " << d->kind << " (schema key " << d->schemaKey << ") is not supported yet";
          bad = true;
          continue;
        }
        ms.push_back(MemberAttr::get(ctx, d->member, off, uint64_t(d->bytes) * 8,
                                     ArrayOfAttr::get(ctx, IntAttr::get(ctx, "char", 8, "char"), d->bytes)));
        off += uint64_t(d->bytes) * 8;
        data.push_back(ob.getStringAttr(mp.structOps->name));
      }
      off = llvm::alignTo(off, 64); // Struct size rounds to the pointer alignment.
      StructOp::create(sb, loc, sb.getStringAttr(mp.structOps->type), i64(off), i64(64), sb.getArrayAttr(ms));
      auto v = VarOp::create(ob, loc, mp.symbol,
                             RefAttr::get(ctx, SymbolRefAttr::get(ctx, "struct_ops", {FlatSymbolRefAttr::get(ctx, mp.structOps->type)})),
                             ".struct_ops.link");
      v->setAttr("btf.struct_ops_programs", ob.getArrayAttr(progs));
      v->setAttr("btf.struct_ops_data", ob.getArrayAttr(data));
    }
    // Build schema integer .rodata/.bss globals only when lowering made placeholders.
    for (const ::ebpf::Global &gl : schema->globals()) {
      auto g = module.lookupSymbol<LLVM::GlobalOp>(gl.name);
      if (!g || !g->hasAttr("ebpf.global"))
        continue;
      if (gl.isRecord()) { // a record global (.data / .rodata / .bss) is a VAR of the record struct.
        VarOp::create(ob, loc, gl.name, bb.recordRef(gl.record), "." + gl.section);
        continue;
      }
      if (gl.isKptr()) { // a kptr global is a VAR of PTR -> TYPE_TAG kptr -> STRUCT in .data.<name>.
        auto v = VarOp::create(ob, loc, gl.name, bb.typeOf(::ebpf::Type{::ebpf::KptrType{gl.kptr}}), gl.elfSection());
        v->setAttr("btf.hidden", ob.getUnitAttr());
        continue;
      }
      if (gl.isKaddr()) { // a bss kaddr global is a VAR of PTR -> the local @kernel struct (no type tag, as clang).
        VarOp::create(ob, loc, gl.name, PtrAttr::get(ctx, RefAttr::get(ctx, SymbolRefAttr::get(ctx, "kernel", {FlatSymbolRefAttr::get(ctx, gl.kaddr)}))),
                      "." + gl.section);
        continue;
      }
      VarOp::create(ob, loc, gl.name, bb.typeOf(::ebpf::Type{gl.type}), "." + gl.section);
    }
    for (auto g : module.getOps<LLVM::GlobalOp>()) {
      auto format = g->getAttrOfType<StringAttr>("ebpf.trace_format");
      if (!format)
        continue;
      // the section is the lowering's (.rodata for trace.printk, .data for the sched_ext bstr kfuncs).
      std::optional<StringRef> section = g.getSection();
      if (!section || (*section != ".rodata" && *section != ".data")) {
        g.emitOpError("a compiler-owned format must be in .rodata or .data");
        return signalPassFailure();
      }
      auto v = VarOp::create(
          ob, loc, g.getSymName(),
          ArrayOfAttr::get(ctx, IntAttr::get(ctx, "char", 8, "char"),
                           format.getValue().size() + 1),
          *section);
      v->setAttr("btf.trace_format", format);
    }
    // Record witnesses: const struct X *__ebpf_record_X.
    for (const ::ebpf::Record &r : schema->records())
      if (!r.synthesized) // Synthesized USDT spec records have no schema witnesses; map values carry their types.
      VarOp::create(ob, loc, "__ebpf_record_" + r.symbol,
                    PtrAttr::get(ctx, ConstAttr::get(ctx, bb.recordRef(r.symbol))),
                    ".ebpf_records");
    // License char array includes terminal NUL. Carry initializer in a discardable attribute, not BTF.
    {
      auto v = VarOp::create(
          ob, loc, "_license",
          ArrayOfAttr::get(ctx, IntAttr::get(ctx, "char", 8, "char"), license.size() + 1),
          "license");
      v->setAttr("btf.string_init", ob.getStringAttr(license));
    }
    // Program functions with llvm.func definitions.
    SmallVector<LLVM::LLVMFuncOp> fns(module.getOps<LLVM::LLVMFuncOp>());
    for (auto fn : fns) {
      if (fn.isExternal())
        continue;
      // bpf_loop callback is static (u64 index,void* ctx)->u64. Kernel requires
      // static BTF FUNC and func_info; retain argument names.
      if (fn->hasAttr("bpfabi.callback")) {
        auto u64 = IntAttr::get(ctx, "u64", 64, "unsigned");
        auto f = FuncOp::create(ob, loc, fn.getSymName(),
                                ob.getArrayAttr({ParamAttr::get(ctx, "index", u64),
                                                 ParamAttr::get(ctx, "ctx", PtrAttr::get(ctx, VoidAttr::get(ctx)))}),
                                u64);
        f.setLinkage("static");
        continue;
      }
      // bpf_find_vma callback is static (void* task,vma,ctx)->u64:
      // verifier set_find_vma_callback_state registers r1..r3.
      if (fn->hasAttr("bpfabi.find_vma_callback")) {
        auto u64 = IntAttr::get(ctx, "u64", 64, "unsigned");
        auto vp = [&] { return PtrAttr::get(ctx, VoidAttr::get(ctx)); };
        auto f = FuncOp::create(ob, loc, fn.getSymName(),
                                ob.getArrayAttr({ParamAttr::get(ctx, "task", vp()), ParamAttr::get(ctx, "vma", vp()),
                                                 ParamAttr::get(ctx, "ctx", vp())}),
                                u64);
        f.setLinkage("static");
        continue;
      }
      // for_each_map_elem callback is static (void* map,key,value,ctx)->u64,
      // matching verifier set_map_elem_callback_state registers r1..r4.
      if (fn->hasAttr("bpfabi.foreach_callback")) {
        auto u64 = IntAttr::get(ctx, "u64", 64, "unsigned");
        auto vp = [&] { return PtrAttr::get(ctx, VoidAttr::get(ctx)); };
        auto f = FuncOp::create(ob, loc, fn.getSymName(),
                                ob.getArrayAttr({ParamAttr::get(ctx, "map", vp()), ParamAttr::get(ctx, "key", vp()),
                                                 ParamAttr::get(ctx, "value", vp()), ParamAttr::get(ctx, "ctx", vp())}),
                                u64);
        f.setLinkage("static");
        continue;
      }
      // user_ringbuf drain callback is static (void* dynptr,void* ctx)->long.
      // set_user_ringbuf_callback_state uses r1 sample/r2 context. Model the
      // opaque bpf_dynptr pointee as void.
      if (fn->hasAttr("bpfabi.user_ringbuf_callback")) {
        auto vp = PtrAttr::get(ctx, VoidAttr::get(ctx));
        auto f = FuncOp::create(ob, loc, fn.getSymName(),
                                ob.getArrayAttr({ParamAttr::get(ctx, "dynptr", vp), ParamAttr::get(ctx, "ctx", vp)}),
                                IntAttr::get(ctx, "long", 64, "signed"));
        f.setLinkage("static");
        continue;
      }
      // Timer callback is static (void* map,key-type* key,record* value)->int,
      // matching set_timer_callback_state r1/r2/r3 and the C int return.
      if (auto tcb = fn->getAttrOfType<ArrayAttr>("bpfabi.timer_callback")) {
        StringRef mapSym = cast<FlatSymbolRefAttr>(tcb[0]).getValue();
        auto rt = cast<mlir::ebpf::RecordType>(cast<TypeAttr>(tcb[1]).getValue());
        const ::ebpf::Map *mp = nullptr;
        for (const ::ebpf::Map &m : schema->maps())
          if (m.symbol == mapSym)
            mp = &m;
        if (!mp || !mp->key) {
          fn.emitOpError() << "timer callback map @" << mapSym << " has no key type in the schema";
          bad = true;
          continue;
        }
        auto cint = IntAttr::get(ctx, "int", 32, "signed");
        auto f = FuncOp::create(ob, loc, fn.getSymName(),
                                ob.getArrayAttr({ParamAttr::get(ctx, "map", PtrAttr::get(ctx, VoidAttr::get(ctx))),
                                                 ParamAttr::get(ctx, "key", PtrAttr::get(ctx, bb.typeOf(*mp->key))),
                                                 ParamAttr::get(ctx, "value", PtrAttr::get(ctx, bb.recordRef(rt.getSymbol())))}),
                                cint);
        f.setLinkage("static");
        continue;
      }
      // Subprogram signless integers become unsigned BTF INTs. Global FUNC
      // arguments need arg0... names; linkage follows llvm.func.
      if (auto link = fn->getAttrOfType<StringAttr>("bpfabi.subprogram")) {
        auto uint = [&](Type t) -> Attribute {
          unsigned w = cast<IntegerType>(t).getWidth();
          return IntAttr::get(ctx, "u" + std::to_string(w), w, "unsigned");
        };
        // Record pointees reference @records with exact schema layout.
        auto pointee = [&](Type t) -> Attribute {
          if (auto rt = dyn_cast<mlir::ebpf::RecordType>(t))
            return bb.recordRef(rt.getSymbol());
          return uint(t);
        };
        auto fty = fn.getFunctionType();
        bool isGlobal = fn.getLinkage() != LLVM::Linkage::Internal;
        // Recover source argument types from bpfabi.arg_types. maybe_ref<iN>
        // becomes an untagged nullable uN pointer; global borrowed<iN> adds
        // arg:nonnull. Static functions have no tags, which kernel ignores.
        auto argTypes = fn->getAttrOfType<ArrayAttr>("bpfabi.arg_types");
        if (!argTypes || argTypes.size() != fty.getNumParams()) {
          fn.emitOpError() << "subprogram has no bpfabi.arg_types for its "
                           << fty.getNumParams() << " argument(s)";
          bad = true;
          continue;
        }
        auto nonnull = fn->getAttrOfType<DenseBoolArrayAttr>("bpfabi.nonnull_args");
        if (!nonnull || nonnull.size() != (int64_t)argTypes.size()) {
          fn.emitOpError() << "subprogram has no bpfabi.nonnull_args for its arguments";
          bad = true;
          continue;
        }
        SmallVector<Attribute> ps;
        for (auto [i, a] : llvm::enumerate(argTypes)) {
          Type t = cast<TypeAttr>(a).getValue();
          std::string name = "arg" + std::to_string(i);
          if (isa<IntegerType>(t)) {
            ps.push_back(ParamAttr::get(ctx, name, uint(t)));
          } else if (auto m = dyn_cast<mlir::ebpf::MaybeRefType>(t)) {
            ps.push_back(ParamAttr::get(ctx, name, PtrAttr::get(ctx, pointee(m.getPointee()))));
          } else if (auto br = dyn_cast<mlir::ebpf::BorrowedType>(t)) {
            // Use lowering's bpfabi.nonnull_args decision, also shared by argtag requirements.
            ArrayAttr tags = nonnull[i] ? ob.getStrArrayAttr({"arg:nonnull"}) : ArrayAttr();
            if (nonnull[i] && !isGlobal) {
              fn.emitOpError() << "argument #" << i << " is marked arg:nonnull on a static function";
              bad = true;
            }
            ps.push_back(ParamAttr::get(ctx, name, PtrAttr::get(ctx, pointee(br.getPointee())), tags));
          } else if (isa<mlir::ebpf::PktWindowType>(t)) {
            // Static packet-window arguments use u8 pointers; verifier ignores static argument types.
            ps.push_back(ParamAttr::get(ctx, name, PtrAttr::get(ctx, IntAttr::get(ctx, "u8", 8, "unsigned"))));
          } else if (isa<mlir::ebpf::ContextType>(t)) {
            // Static context arguments use void* like entry contexts; verifier ignores their types.
            ps.push_back(ParamAttr::get(ctx, name, PtrAttr::get(ctx, VoidAttr::get(ctx))));
          } else {
            fn.emitOpError() << "subprogram argument #" << i << " has type " << t
                             << ", which has no BTF lowering";
            bad = true;
          }
        }
        if (!isa<IntegerType>(fty.getReturnType())) {
          fn.emitOpError() << "subprogram result is not an integer";
          bad = true;
          continue;
        }
        bool isStatic = fn.getLinkage() == LLVM::Linkage::Internal;
        if (isStatic != (link.getValue() == "static")) {
          fn.emitOpError() << "llvm.func linkage and bpfabi.subprogram \"" << link.getValue()
                           << "\" disagree";
          bad = true;
          continue;
        }
        auto f = FuncOp::create(ob, loc, fn.getSymName(), ob.getArrayAttr(ps),
                                uint(fty.getReturnType()));
        f.setLinkage(isStatic ? "static" : "global");
        continue;
      }
      // Entry context is void*. ext FUNC_PROTO instead follows the replacement's
      // schema signature as unsigned integers with named arguments. Do not
      // derive it from lowered llvm.func: those i64 argument registers only
      // extend through the largest used index. Kernel btf_check_func_type_match
      // checks argument count and return BTF kind against the target.
      std::string progAttach;
      if (const bpfmlir::ProgramKindInfo *k = bpfmlir::kindOfSection(fn.getSection() ? *fn.getSection() : StringRef(), progAttach);
          k && !bpfmlir::entryTakesCtx(k->attach)) {
        const ::ebpf::Program *decl = schema->program(fn.getSymName());
        if (!decl || decl->nargs < 0 || decl->args.size() != static_cast<size_t>(decl->nargs)) {
          fn.emitOpError() << "ext program has no signature (nargs / ret / args) in the schema";
          bad = true;
          continue;
        }
        auto u = [&](unsigned w) { return IntAttr::get(ctx, "u" + std::to_string(w), w, "unsigned"); };
        SmallVector<Attribute> ps;
        for (auto [i, a] : llvm::enumerate(decl->args)) {
          unsigned w = 0;
          if (StringRef(a).drop_front().getAsInteger(10, w)) {
            fn.emitOpError() << "ext program argument #" << i << " has no integer type in the schema";
            bad = true;
          }
          ps.push_back(ParamAttr::get(ctx, "arg" + std::to_string(i), u(w)));
        }
        FuncOp::create(ob, loc, fn.getSymName(), ob.getArrayAttr(ps), u(decl->ret.bits));
        continue;
      }
      auto voidPtr = PtrAttr::get(ctx, VoidAttr::get(ctx));
      SmallVector<Attribute> progParams;
      if (fn.getFunctionType().getNumParams() == 1)
        progParams.push_back(ParamAttr::get(ctx, "ctx", voidPtr));
      else if (fn.getFunctionType().getNumParams() != 0) {
        fn.emitOpError() << "program entry takes " << fn.getFunctionType().getNumParams()
                         << " arguments; only the context (1) or none (ext) has a BTF lowering";
        bad = true;
        continue;
      }
      // An i64 struct_ops entry returns the schema ret, as clang's
      // size_t BPF_PROG does; every i32 entry keeps int, byte for byte.
      Attribute progRet = bb.cInt();
      if (fn.getFunctionType().getReturnType().isInteger(64)) {
        const ::ebpf::Program *decl = schema->program(fn.getSymName());
        if (!decl || decl->nargs < 0 || decl->retVoid || decl->ret.bits != 64) {
          fn.emitOpError() << "program entry returns i64 but its schema signature has no 64-bit ret";
          bad = true;
          continue;
        }
        progRet = bb.typeOf(::ebpf::Type{decl->ret});
      }
      FuncOp::create(ob, loc, fn.getSymName(), ob.getArrayAttr(progParams), progRet);
    }
    if (bad)
      signalPassFailure();
  }
};

} // namespace
