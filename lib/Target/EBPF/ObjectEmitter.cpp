//===- ObjectEmitter.cpp - emit BPF ELF with BTF ----------------------------===//
#include "bpf-mlir/Target/EBPF/ObjectEmitter.h"

#include "bpf-mlir/Dialect/BPFABI/KernelABI.h"
#include "bpf-mlir/Support/ProgramKinds.h"
#include "bpf-mlir/Support/StructOpsTypes.h"
#include "bpf-mlir/Support/KernelFieldPath.h"
#include "bpf-mlir/Dialect/BTF/IR/BTFDialect.h"

#include "mlir/Dialect/LLVMIR/LLVMDialect.h"
#include "mlir/Target/LLVMIR/Dialect/All.h"
#include "mlir/Target/LLVMIR/Export.h"

#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/Transforms/Utils/ValueMapper.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/DiagnosticPrinter.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/CodeGen.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "bpf-mlir/Target/EBPF/PresentCost.h"
#include "bpf-mlir/Target/EBPF/PresentOutline.h"

#include <map>
#include <set>

using namespace llvm;

namespace ebpf {
namespace {

// Schema type spelling for shared-map matching: u32/i64/[16]i8/record:<symbol>.
std::string typeSpelling(const Type &t) {
  if (const auto *i = std::get_if<IntType>(&t.v))
    return (i->isSigned ? "i" : "u") + std::to_string(i->bits) +
           (i->endianness == Endianness::Little ? "" : "be");
  if (const auto *a = std::get_if<ArrayType>(&t.v))
    return "[" + std::to_string(a->count) + "]" + typeSpelling(*a->element);
  if (std::holds_alternative<StackBuildIdType>(t.v)) // stack_trace build-ID element.
    return "stack_build_id";
  return "record:" + std::get<RecordRefType>(t.v).symbol;
}

// Per-program CO-RE contract identifies kernel struct/field and read width/
// signedness. Precheck must match target BTF because cilium CO-RE does not
// validate INT widths or signs.
struct KFieldRequirement {
  std::string program, structName, field, type; // Type spelling: i8..u64 or ptr:<T>.
  bool operator<(const KFieldRequirement &o) const {
    return std::tie(program, structName, field, type) <
           std::tie(o.program, o.structName, o.field, o.type);
  }
  bool operator==(const KFieldRequirement &o) const {
    return !(*this < o) && !(o < *this);
  }
};

// Per-program requirements attached to llvm.func by bpfabi-requirements.
struct ProgramRequirement {
  std::string symbol, progType;
  int64_t progTypeId;
  std::vector<std::pair<int64_t, std::string>> helpers; // (number,name).
  std::vector<std::string> argTags; // <tag> <class>, for example arg:nonnull mem.
  std::vector<std::string> ctxAccess; // <attach type> <struct> <field> <r|w> <bytes>, sorted by ABI lowering.
  std::vector<std::string> kfuncs;    // Called kfunc names, including reachable subprograms, from bpfabi.requires.
  std::string tpbuf; // Actual buffer-access pointee contract; empty for older ELF profiles.
};

// Map kind to enum bpf_map_type name. Only KernelABI.h's generated table owns numbers.
llvm::StringRef mapTypeName(MapKind k) { return mapKindSpelling(k); } // MapKinds.def NAME.

// Local CO-RE types passed from btf.scope @kernel to the emission bridge.
struct KernelLocal {
  struct Field {
    std::string name;
    uint64_t offsetBits;
    bool isSigned;
    unsigned bits;     // Integer widths 8/16/32/64; pointers use 64, byte-array elements use eight.
    std::string ptrTo; // Nonempty names a pointer pointee local kernel type.
    uint64_t arrayCount = 0; // Nonzero specifies arrayCount integer elements of bits width.
    bool strPtr = false;     // char* field: PTR -> eight-bit INT, with pointer width 64.
    std::string embedded = {};
  };
  std::string name;
  uint64_t sizeBits;
  std::vector<Field> fields;
  uint32_t alignBits = 32;
  const Field *field(llvm::StringRef n) const {
    for (const Field &f : fields)
      if (f.name == n)
        return &f;
    return nullptr;
  }
};

// Records, maps, witnesses, license and function BTF were built in BTF IR,
// lowered to MLIR DI attributes and translated to LLVM. This layer adds
// requirements and the CO-RE bridge: preserve.access.index metadata and local
// type DI not representable by MLIR LLVM dialect. Build those from @kernel
// with DIBuilder reusing the existing compile unit, never a second CU.
struct Emitter {
  Module &m;
  const Schema &schema;
  Diagnostics &diags;
  std::vector<KernelLocal> kernelLocals;
  std::unique_ptr<DIBuilder> dbp;
  DIFile *file = nullptr;
  DICompileUnit *cu = nullptr;
  // Emitted map data used for requirement map-type rows.
  struct EmittedMap {
    std::string symbol, typeName;
    int64_t typeId;
    std::string key, value; // Schema type spelling, or '-' when absent.
    uint64_t maxEntries, flags;
    // Inner-template fields use the same tab-separated type/enum/key/value/
    // max_entries/flags spellings as map rows; empty for non-map-in-map kinds.
    std::string inner;
  };
  std::vector<EmittedMap> emittedMaps;
  std::vector<KFieldRequirement> kfields;
  std::vector<std::string> btfFeatures;    // Format-5 btf requirement rows.
  bool hasCore = false;                    // Whether any CO-RE read marker was expanded.
  std::set<std::string> kfuncDecls;        // kfunc extern declarations marked bpfabi.kfunc; translation drops their sections.

  Emitter(Module &mod, const Schema &s, Diagnostics &d, std::vector<KernelLocal> kl)
      : m(mod), schema(s), diags(d), kernelLocals(std::move(kl)) {
    if (m.debug_compile_units_begin() != m.debug_compile_units_end()) {
      cu = *m.debug_compile_units_begin();
      file = cu->getFile();
    }
    dbp = std::make_unique<DIBuilder>(m, /*AllowUnresolved=*/true, cu);
    if (!cu) {
      file = dbp->createFile("ebpf-schema", ".");
      cu = dbp->createCompileUnit(dwarf::DW_LANG_C99, file, "ebpf",
                                  /*isOptimized=*/true, "", 0);
    }
  }
  DIBuilder &db() { return *dbp; }

  const KernelLocal *kernelLocal(llvm::StringRef n) const {
    for (const KernelLocal &k : kernelLocals)
      if (k.name == n)
        return &k;
    return nullptr;
  }

  // Count maps with BTF .maps globals for requirements; do not rebuild BTF.
  void collectMaps() {
    // Share field formatting between outer map and inner template rows.
    auto typeIdOf = [&](const Map &mp) -> std::optional<int64_t> {
      std::optional<int64_t> typeId =
          mlir::bpfabi::lookupMapType(mapTypeName(mp.kind));
      if (!typeId)
        diags.error("map \"" + mp.symbol + "\": map type \"" +
                    mapTypeName(mp.kind) + "\" is not in the UAPI table");
      return typeId;
    };
    auto keySpelling = [](const Map &mp) -> std::string {
      return mp.key ? typeSpelling(*mp.key) : "-";
    };
    auto valueSpelling = [](const Map &mp) -> std::string {
      return mp.value            ? typeSpelling(*mp.value)
             : !mp.record.empty() ? "record:" + mp.record
                                  : "-";
    };
    for (const Map &mp : schema.maps()) {
      if (!m.getGlobalVariable(mp.symbol, true))
        continue;
      std::optional<int64_t> typeId = typeIdOf(mp);
      if (!typeId)
        continue;
      // Schema validation already required a distinct valid template symbol for
      // map-in-map. Serialize that template into innermap fields.
      std::string inner;
      if (!mp.inner.empty()) {
        const Map *t = nullptr;
        for (const Map &o : schema.maps())
          if (o.symbol == mp.inner)
            t = &o;
        if (!t) {
          diags.error("map \"" + mp.symbol + "\": inner map template \"" + mp.inner + "\" is not in the schema");
          continue;
        }
        std::optional<int64_t> innerId = typeIdOf(*t);
        if (!innerId)
          continue;
        inner = mapTypeName(t->kind).str() + "\t" + std::to_string(*innerId) + "\t" + keySpelling(*t) + "\t" +
                valueSpelling(*t) + "\t" + std::to_string(t->maxEntries) + "\t" + std::to_string(t->flags);
      }
      emittedMaps.push_back({mp.symbol, mapTypeName(mp.kind).str(), *typeId,
                             keySpelling(mp), valueSpelling(mp),
                             mp.maxEntries, mp.flags, inner});
    }
  }

  // Expand __ebpf_core.<struct>.<field> markers into preserve.struct.access.index
  // with elementtype/local DI metadata, followed by the declared load.
  // Local kernel_types use declaration-order member indices and provisional
  // naturally aligned offsets. BPFAbstractMemberAccess emits field-byte-offset
  // relocations in .BTF.ext. Match type/field/width against schema here because
  // ABI lowering does not read schema; reject any unresolved marker afterward.
  void expandCoreMarkers() {
    std::map<std::string, std::pair<StructType *, DICompositeType *>> types;
    // Pointer fields may reference self or later types. Cache struct types/DI
    // first, then populate members.
    std::function<std::pair<StructType *, DICompositeType *>(const KernelLocal &)> typeOf;
    typeOf = [&](const KernelLocal &k) -> std::pair<StructType *, DICompositeType *> {
      auto it = types.find(k.name);
      if (it != types.end())
        return it->second;
      uint32_t align0 = 32;
      for (const KernelLocal::Field &f : k.fields)
        align0 = std::max<uint32_t>(align0, f.bits);
      align0 = std::max(align0, k.alignBits);
      auto *st0 = StructType::create(m.getContext(), "struct." + k.name);
      auto *di0 = db().createStructType(cu, k.name, file, 0, k.sizeBits, align0, DINode::FlagZero, nullptr,
                                        db().getOrCreateArray({}));
      types[k.name] = {st0, di0};
      SmallVector<llvm::Type *, 4> elems;
      SmallVector<Metadata *, 4> members;
      uint32_t align = 32;
      for (const KernelLocal::Field &f : k.fields) {
        if (!f.embedded.empty()) {
          const auto *child = kernelLocal(f.embedded);
          if (!child) { diags.error("undeclared embedded kernel type " + f.embedded); continue; }
          auto [cs, cd] = typeOf(*child);
          elems.push_back(cs);
          members.push_back(db().createMemberType(cu, f.name, file, 0, child->sizeBits, 0, f.offsetBits, DINode::FlagZero, cd));
          continue;
        }
        if (f.arrayCount) { // Eight-bit integer array.
          auto *et = llvm::Type::getInt8Ty(m.getContext());
          elems.push_back(llvm::ArrayType::get(et, f.arrayCount));
          DIType *eb = db().createBasicType(f.isSigned ? "signed char" : "unsigned char", 8,
                                            f.isSigned ? dwarf::DW_ATE_signed_char : dwarf::DW_ATE_unsigned_char);
          DIType *at = db().createArrayType(f.arrayCount * 8, 8, eb,
                                            db().getOrCreateArray({db().getOrCreateSubrange(0, (int64_t)f.arrayCount)}));
          members.push_back(db().createMemberType(cu, f.name, file, 0, f.arrayCount * 8, 0, f.offsetBits, DINode::FlagZero, at));
          continue;
        }
        if (f.strPtr) { // char*: DWARF pointer to char becomes BTF PTR -> INT char.
          elems.push_back(PointerType::getUnqual(m.getContext()));
          align = std::max<uint32_t>(align, 64);
          DIType *pt = db().createPointerType(db().createBasicType("char", 8, dwarf::DW_ATE_signed_char), 64);
          members.push_back(db().createMemberType(cu, f.name, file, 0, 64, 0, f.offsetBits, DINode::FlagZero, pt));
          continue;
        }
        if (!f.ptrTo.empty()) {
          elems.push_back(PointerType::getUnqual(m.getContext()));
          align = std::max<uint32_t>(align, 64);
          const KernelLocal *tk = kernelLocal(f.ptrTo);
          DIType *pointee = tk ? static_cast<DIType *>(typeOf(*tk).second) : nullptr;
          DIType *pt = db().createPointerType(pointee, 64);
          members.push_back(db().createMemberType(cu, f.name, file, 0, 64, 0, f.offsetBits, DINode::FlagZero, pt));
          continue;
        }
        // Declared width uses the same C spelling as BuildBTF kernelIntName;
        // retain names/alignment for existing 32-bit local types.
        elems.push_back(llvm::Type::getIntNTy(m.getContext(), f.bits));
        align = std::max<uint32_t>(align, f.bits);
        const char *name = f.bits == 8    ? (f.isSigned ? "signed char" : "unsigned char")
                           : f.bits == 16 ? (f.isSigned ? "short" : "unsigned short")
                           : f.bits == 64 ? (f.isSigned ? "long long" : "unsigned long long")
                                          : (f.isSigned ? "int" : "unsigned int");
        DIType *ft = db().createBasicType(name, f.bits,
                                          f.isSigned ? dwarf::DW_ATE_signed : dwarf::DW_ATE_unsigned);
        members.push_back(db().createMemberType(cu, f.name, file, 0, f.bits, 0,
                                              f.offsetBits, DINode::FlagZero,
                                              ft));
      }
      (void)align;
      st0->setBody(elems);
      db().replaceArrays(di0, db().getOrCreateArray(members));
      return types[k.name];
    };

    using CoreStep = std::pair<const KernelLocal *, const KernelLocal::Field *>;
    auto resolvePath = [&](StringRef sname, StringRef path) {
      SmallVector<CoreStep, 3> steps;
      if (!bpfmlir::validKernelFieldPath(path)) return steps;
      SmallVector<StringRef> parts; path.split(parts, '.', -1, true);
      const KernelLocal *k = kernelLocal(sname);
      for (auto [i, part] : llvm::enumerate(parts)) {
        auto *f = k ? k->field(part) : nullptr;
        if (!f) { steps.clear(); return steps; }
        steps.push_back({k, f});
        if (i + 1 < parts.size()) {
          if (f->embedded.empty()) { steps.clear(); return steps; }
          k = kernelLocal(f->embedded);
        }
      }
      return steps;
    };
    auto fieldAddress = [&](IRBuilder<> &b, Value *base, ArrayRef<CoreStep> steps,
                            StringRef program, StringRef root) -> Value * {
      Value *p = base;
      std::string prefix;
      for (auto [k, f] : steps) {
        auto [st, di] = typeOf(*k);
        unsigned idx = static_cast<unsigned>(f - k->fields.data());
        p = b.CreatePreserveStructAccessIndex(st, p, idx, idx, di);
        if (!prefix.empty()) prefix += ".";
        prefix += f->name;
        if (!f->embedded.empty()) kfields.push_back({program.str(), root.str(), prefix, "struct:" + f->embedded});
      }
      return p;
    };
    SmallVector<Function *> markers;
    for (Function &f : m)
      if (f.getName().starts_with("__ebpf_core."))
        markers.push_back(&f);
    for (Function *mk : markers) {
      StringRef rest = mk->getName().drop_front(strlen("__ebpf_core."));
      auto [sname, fname] = rest.split('.');
      auto steps = resolvePath(sname, fname);
      const KernelLocal *k = steps.empty() ? nullptr : steps.front().first;
      const KernelLocal::Field *kf = steps.empty() ? nullptr : steps.back().second;
      if (!kf || !kf->embedded.empty()) {
        diags.error("CO-RE read of \"" + rest.str() +
                    "\": not declared in btf.scope @kernel (schema core.kernel_types)");
        continue;
      }
      bool ptrField = !kf->ptrTo.empty() || kf->strPtr; // Eight-byte pointer field reads.
      if (ptrField ? !mk->getReturnType()->isPointerTy() : !mk->getReturnType()->isIntegerTy(kf->bits)) {
        diags.error("CO-RE read of \"" + rest.str() + "\": the read width differs from the declared " +
                    std::to_string(kf->bits) + "-bit field");
        continue;
      }
      SmallVector<CallInst *> calls;
      for (User *u : mk->users())
        if (auto *c = dyn_cast<CallInst>(u))
          calls.push_back(c);
      for (CallInst *c : calls) {
        IRBuilder<> b(c);
        Value *p = fieldAddress(b, c->getArgOperand(0), steps, c->getFunction()->getName(), k->name);
        // kfield.load is always once: volatile prevents codegen from merging reads.
        // Emit one B/H/W/DW load at the declared width.
        llvm::Type *lt = !ptrField ? static_cast<llvm::Type *>(b.getIntNTy(kf->bits))
                                   : PointerType::getUnqual(m.getContext());
        LoadInst *ld = b.CreateAlignedLoad(lt, p, Align(kf->bits / 8), /*isVolatile=*/true);
        c->replaceAllUsesWith(ld);
        kfields.push_back({c->getFunction()->getName().str(), k->name, fname.str(),
                           kf->strPtr           ? std::string("strptr") // strptr requires minimum format 15.
                           : kf->ptrTo.empty() ? (kf->isSigned ? "i" : "u") + std::to_string(kf->bits)
                                               : "ptr:" + kf->ptrTo});
        c->eraseFromParent();
        hasCore = true;
      }
      if (!mk->use_empty()) {
        diags.error("CO-RE marker \"" + mk->getName().str() +
                    "\" is used by something other than a call");
        continue;
      }
      mk->eraseFromParent();
    }
    // __ebpf_core_addr.<S>.<field> returns the copy-source address through
    // preserve.struct.access.index, without loading.
    SmallVector<Function *> addrMarkers;
    for (Function &f : m)
      if (f.getName().starts_with("__ebpf_core_addr."))
        addrMarkers.push_back(&f);
    for (Function *mk : addrMarkers) {
      StringRef rest = mk->getName().drop_front(strlen("__ebpf_core_addr."));
      auto [sname, fname] = rest.split('.');
      auto steps = resolvePath(sname, fname);
      const KernelLocal *k = steps.empty() ? nullptr : steps.front().first;
      const KernelLocal::Field *kf = steps.empty() ? nullptr : steps.back().second;
      // Include integer kfield.store destinations; pointer fields are read-only.
      if (!kf || !kf->embedded.empty() || (!kf->arrayCount && (!kf->ptrTo.empty() || kf->strPtr))) {
        diags.error("CO-RE address of \"" + rest.str() + "\": not an array or integer field declared in btf.scope @kernel");
        continue;
      }
      SmallVector<CallInst *> calls;
      for (User *u : mk->users())
        if (auto *c = dyn_cast<CallInst>(u))
          calls.push_back(c);
      for (CallInst *c : calls) {
        IRBuilder<> b(c);
        Value *p = fieldAddress(b, c->getArgOperand(0), steps, c->getFunction()->getName(), k->name);
        c->replaceAllUsesWith(p);
        kfields.push_back({c->getFunction()->getName().str(), k->name, fname.str(),
                           kf->arrayCount ? "[" + std::to_string(kf->arrayCount) + "]" + (kf->isSigned ? "i8" : "u8")
                                          : (kf->isSigned ? "i" : "u") + std::to_string(kf->bits)}); // Integer stores record the same field contract as loads.
        c->eraseFromParent();
        hasCore = true;
      }
      if (!mk->use_empty()) {
        diags.error("CO-RE marker \"" + mk->getName().str() + "\" is used by something other than a call");
        continue;
      }
      mk->eraseFromParent();
    }
    for (Function &f : m)
      if (f.getName().starts_with("__ebpf_core.") || f.getName().starts_with("__ebpf_core_addr."))
        diags.error("unexpanded CO-RE marker \"" + f.getName().str() + "\"");
    // Add DISubprogram declarations to .ksyms externs so BPF emits extern FUNC,
    // FUNC_PROTO and DATASEC, matching clang __ksym. ABI kfunc rows own types;
    // *S uses the verified local @kernel CO-RE struct. Missing call locations
    // use function line zero, satisfying LLVM verification without line_info.
    for (const std::string &kn : kfuncDecls) {
      Function *fp = m.getFunction(kn);
      if (!fp || !fp->isDeclaration()) {
        diags.error("kfunc \"" + kn + "\" is not an extern function declaration in the LLVM module");
        continue;
      }
      Function &f = *fp;
      f.setSection(".ksyms");
      const mlir::bpfabi::KfuncABI *k = mlir::bpfabi::lookupKfunc(f.getName());
      if (!k) {
        diags.error("extern function \"" + f.getName().str() + "\" in .ksyms is not in the kfunc table");
        continue;
      }
      bool ok = true;
      std::function<DIType *(llvm::StringRef)> diOf = [&](llvm::StringRef s) -> DIType * {
        if (s == "void")
          return nullptr;
        if (s == "bool") // bpf_session_is_return uses BTF INT BOOL, like clang _Bool.
          return db().createBasicType("_Bool", 8, dwarf::DW_ATE_boolean);
        if (s == "*void") // Session context is void*.
          return db().createPointerType(nullptr, 64);
        if (s.size() > 2 && s.starts_with("*") && (s[1] == 'i' || s[1] == 'u') && llvm::all_of(s.drop_front(2), llvm::isDigit)) // Integer pointer.
          return db().createPointerType(diOf(s.drop_front()), 64);
        if (s.starts_with("*")) {
          const KernelLocal *kl = kernelLocal(s.drop_front());
          if (!kl) {
            diags.error("kfunc \"" + f.getName().str() + "\": struct " + s.drop_front().str() +
                        " is not declared in btf.scope @kernel (schema core.kernel_types)");
            ok = false;
            return nullptr;
          }
          return db().createPointerType(typeOf(*kl).second, 64);
        }
        bool isSigned = s.front() == 'i';
        unsigned bits = 0;
        s.drop_front().getAsInteger(10, bits);
        const char *name = bits == 8    ? (isSigned ? "signed char" : "unsigned char")
                           : bits == 16 ? (isSigned ? "short" : "unsigned short")
                           : bits == 64 ? (isSigned ? "long long" : "unsigned long long")
                                        : (isSigned ? "int" : "unsigned int");
        return db().createBasicType(name, bits, isSigned ? dwarf::DW_ATE_signed : dwarf::DW_ATE_unsigned);
      };
      SmallVector<Metadata *, 4> tys{diOf(k->ret)};
      for (auto &[pname, ptype] : k->paramList())
        tys.push_back(diOf(ptype));
      if (!ok)
        continue;
      DISubroutineType *sty = db().createSubroutineType(db().getOrCreateTypeArray(tys));
      DISubprogram *sp = db().createFunction(file, f.getName(), f.getName(), file, 0, sty, 0, DINode::FlagPrototyped,
                                             DISubprogram::SPFlagOptimized);
      f.setSubprogram(sp);
      for (User *u : f.users())
        if (auto *c = dyn_cast<CallInst>(u))
          if (!c->getDebugLoc())
            if (DISubprogram *caller = c->getFunction()->getSubprogram())
              c->setDebugLoc(DILocation::get(m.getContext(), 0, 0, caller));
    }
    // Replace type-tag marker pointers with unnamed btf_type_tag annotations,
    // matching clang's kptr attribute. Reuse the same local struct DI as kfunc
    // prototypes and kernel fields, yielding one BTF STRUCT T. MLIR lacks these
    // annotations; explicitly reject any marker left after this bridge.
    {
      DebugInfoFinder finder;
      finder.processModule(m);
      ValueToValueMapTy vm;
      for (DIType *t : finder.types()) {
        auto *dt = dyn_cast<DIDerivedType>(t);
        if (!dt || dt->getTag() != dwarf::DW_TAG_pointer_type || !dt->getName().starts_with(mlir::btf::kTypeTagMarkerPrefix))
          continue;
        StringRef tag = dt->getName().drop_front(mlir::btf::kTypeTagMarkerPrefix.size());
        DIType *base = dt->getBaseType();
        const KernelLocal *kl = base ? kernelLocal(base->getName()) : nullptr;
        if (!kl) {
          diags.error("type_tag \"" + tag.str() + "\": the tagged pointer must point to a struct declared in btf.scope @kernel "
                      "(schema core.kernel_types)");
          continue;
        }
        Metadata *ann = MDNode::get(m.getContext(), {MDString::get(m.getContext(), "btf_type_tag"), MDString::get(m.getContext(), tag)});
        DIDerivedType *np = db().createPointerType(typeOf(*kl).second, 64, 0, std::nullopt, "",
                                                   db().getOrCreateArray({ann}));
        vm.MD()[dt].reset(np);
      }
      if (!vm.MD().empty()) {
        const RemapFlags flags = RF_IgnoreMissingLocals | RF_ReuseAndMutateDistinctMDs;
        for (Function &F : m)
          if (!F.isDeclaration())
            RemapFunction(F, vm, flags);
          else if (DISubprogram *sp = F.getSubprogram())
            F.setSubprogram(cast<DISubprogram>(MapMetadata(sp, vm, flags)));
        for (GlobalVariable &gv : m.globals()) {
          SmallVector<std::pair<unsigned, MDNode *>> mds;
          gv.getAllMetadata(mds);
          for (auto &[kind, md] : mds)
            gv.setMetadata(kind, cast<MDNode>(MapMetadata(md, vm, flags)));
        }
        for (NamedMDNode &nmd : m.named_metadata())
          for (unsigned i = 0; i < nmd.getNumOperands(); ++i)
            nmd.setOperand(i, cast<MDNode>(MapMetadata(nmd.getOperand(i), vm, flags)));
      }
      DebugInfoFinder after;
      after.processModule(m);
      for (DIType *t : after.types())
        if (t->getName().starts_with(mlir::btf::kTypeTagMarkerPrefix))
          diags.error("type_tag marker \"" + t->getName().str() + "\" is still in the debug info after the bridge");
    }
    std::sort(kfields.begin(), kfields.end());
    kfields.erase(std::unique(kfields.begin(), kfields.end()), kfields.end());
  }

  // .ebpf_requirements records kernel capabilities and schema identity.
  // docs/requirements_format.md owns grammar, minimum formats, ordering, caps
  // queries and load policy. Rows are tab-separated in fixed reproducible order.
  // Use the maximum minimum version required by present rows/values; additions
  // must update docs and Go RowKinds in the same commit. Names match lowercase
  // unprefixed bpftool feature spellings.
  // This does not change instructions/BTF. A local symbol plus llvm.used keeps
  // the section while libbpf/cilium ignore its unfamiliar contents.
  void emitRequirements(std::vector<ProgramRequirement> progs,
                        StringRef schemaSHA256) {
    std::sort(progs.begin(), progs.end(),
              [](auto &a, auto &b) { return a.symbol < b.symbol; });
    // tp_btf target/args come from section and schema, matched before load
    // against btf_trace_<tracepoint>. trace_fentry names a kernel function and
    // checks target BTF FUNC presence without argument rows here.
    struct AttachRow {
      std::string program, tracepoint;
      std::vector<std::string> args;
      std::string type = "trace_raw_tp";
      std::string retsig; // fexit nargs and integer return-type spelling.
      std::vector<std::string> extra; // Probe arch/ctxfield/argument companions immediately follow attach.
    };
    std::vector<AttachRow> attaches;
    bool anyFarg = false;
    bool anyGenericAttach = false; // Generic attach rows require format 9.
    bool anyFmodRet = false;       // trace_fmod_ret requires format 10.
    bool anyV11 = false;           // trace_tp/trace_perf/trace_lsm/freplace/trace_struct_ops require format 11.
    bool anyMulti = false;         // Multi-probe families and mtarget require format 12.
    bool anyV13 = false;           // ksyscall/trace_lsm_cgroup/sysarg/mtargetarg require format 13; kfunc is counted below.
    bool anyTpbuf = false;         // Buffer access uses the existing format-14 companion.
    bool anyUserStrV16 = false;    // Typed tracepoint/syscall user pointers require format 16.
    bool anyTpArrayV17 = false;    // fixed byte-array fields.
    bool anyUserPtrV18 = false;   // user-probe ptr arguments, both raw identity and typed buffer.
    for (const ProgramRequirement &p : progs) {
      Function *fn = m.getFunction(p.symbol);
      // Resolve requirement type/target from attachment-table REQATTACH, not section-prefix branches.
      std::string progAttach;
      const bpfmlir::ProgramAttachInfo *attachRow = nullptr; // REQATTACH belongs to attachment rows.
      const bpfmlir::ProgramKindInfo *kindInfo = fn ? bpfmlir::kindOfSection(fn->getSection(), progAttach, &attachRow) : nullptr;
      // MapSymbol and StructOpsMap values are absent from sections; use schema
      // attach_target. VerifySchema already matched the program attachment,
      // and parsing established the target map kind.
      if (kindInfo && bpfmlir::attachFromSchemaMap(kindInfo->attach)) {
        const Program *decl = schema.program(p.symbol);
        if (!decl || decl->attachTarget.empty()) {
          diags.error(kindInfo->name.str() + " program \"" + p.symbol + "\" has no attach_target (its " +
                      (kindInfo->attach == bpfmlir::AttachForm::MapSymbol ? "sockmap / sockhash" : "struct_ops map") + ") in the schema");
          continue;
        }
        progAttach = decl->attachTarget;
      }
      // Multi-probe names also come from schema, not sections. VerifySchema
      // matched exact order; REQATTACH {} receives the number of names.
      const std::vector<std::string> *multiTargets = nullptr;
      if (kindInfo && bpfmlir::isAttachList(kindInfo->attach)) {
        const Program *decl = schema.program(p.symbol);
        if (!decl || decl->attachTargets.empty()) {
          diags.error(kindInfo->name.str() + " program \"" + p.symbol + "\" has no attach_target list in the schema");
          continue;
        }
        multiTargets = &decl->attachTargets;
        progAttach = std::to_string(decl->attachTargets.size());
      }
      // USDT provider:name comes from matched schema attach_target, not section.
      if (kindInfo && kindInfo->attach == bpfmlir::AttachForm::UsdtProbe) {
        const Program *decl = schema.program(p.symbol);
        if (!decl || decl->attachTarget.empty()) {
          diags.error(kindInfo->name.str() + " program \"" + p.symbol + "\" has no attach_target (its USDT probe) in the schema");
          continue;
        }
        progAttach = decl->attachTarget;
      }
      // ksyscall uses libbpf ksyscall/<name> sections but targets __<pfx>_sys_<name>
      // from architecture ABI syscallpfx. Requirements retain syscall name in
      // the distinct ksyscall family; readers derive wrappers. Missing prefix
      // is an explicit error, not an alternative attachment.
      if (kindInfo && kindInfo->attach == bpfmlir::AttachForm::SyscallName) {
        const Program *decl = schema.program(p.symbol);
        if (!decl || decl->arch.empty()) {
          diags.error(kindInfo->name.str() + " program \"" + p.symbol + "\" has no arch in the schema");
          continue;
        }
        if (!mlir::bpfabi::syscallWrapperSymbol(decl->arch, progAttach)) {
          diags.error(kindInfo->name.str() + " program \"" + p.symbol + "\": the UAPI table has no syscall wrapper prefix for arch " + decl->arch);
          continue;
        }
      }
      bpfmlir::RequirementsAttach ra;
      if (!kindInfo || !attachRow || !bpfmlir::requirementsAttachOf(*attachRow, progAttach, ra))
        continue;
      // LSM with schema args emits trace_lsm plus per-index farg types matched
      // against bpf_lsm_<hook> FUNC_PROTO. Without args, retain generic format-9
      // rows. lsm_cgroup analogously emits trace_lsm_cgroup/farg while readers
      // also retain the generic lsm_cgroup hook query.
      if (StringRef fam = bpfmlir::companionFamilyOf(ra.type); fam == "trace_lsm" || fam == "trace_lsm_cgroup") {
        const Program *decl = schema.program(p.symbol);
        if (decl && !decl->args.empty()) {
          AttachRow row{p.symbol, progAttach, {}, fam.str()};
          for (auto [i, a] : llvm::enumerate(decl->args))
            row.extra.push_back("farg\t" + p.symbol + "\t" + std::to_string(i) + "\t" +
                                (!a.empty() && a.back() == '?' ? a.substr(0, a.size() - 1) : a));
          attaches.push_back(std::move(row));
          (fam == "trace_lsm" ? anyV11 : anyV13) = true;
          continue;
        }
      }
      // ksyscall emits attach -> arch -> optional ctxfield -> sysarg. Context
      // rows cover the wrapper's first user-pt_regs pointer and each read user
      // argument field, once per struct/member. Sorted sysarg types are matched
      // against tracefs sys_enter_<name> format before load.
      if (ra.type == "ksyscall") {
        const Program *decl = schema.program(p.symbol);
        AttachRow row{p.symbol, ra.target, {}, "ksyscall"};
        row.extra.push_back("arch\t" + p.symbol + "\t" + decl->arch);
        std::vector<Program::Param> params = decl->params;
        std::sort(params.begin(), params.end(), [](auto &a, auto &b) { return a.n < b.n; });
        if (!params.empty()) {
          std::vector<const mlir::bpfabi::KprobeArgABI *> regs{mlir::bpfabi::lookupKprobeArg(decl->arch, 1)};
          for (const Program::Param &q : params)
            regs.push_back(mlir::bpfabi::lookupKsyscallArg(decl->arch, static_cast<int>(q.n)));
          std::set<std::pair<std::string, int64_t>> seenField;
          bool ok = true;
          for (const mlir::bpfabi::KprobeArgABI *k : regs) {
            if (!k) {
              ok = false;
              break;
            }
            if (seenField.insert({k->kernelField.str(), k->offset}).second)
              row.extra.push_back("ctxfield\t" + p.symbol + "\tpt_regs\t" + k->kernelField.str() + "\t" + std::to_string(k->offset) + "\t" +
                                  std::to_string(k->bytes));
          }
          if (!ok) {
            diags.error("ksyscall program \"" + p.symbol + "\": a syscall argument register of " + decl->arch + " is not in the UAPI table (ksyscallarg)");
            continue;
          }
        }
        for (const Program::Param &q : params)
          row.extra.push_back("sysarg\t" + p.symbol + "\t" + std::to_string(q.n) + "\t" +
                              (q.userStrArray ? std::string("strarray") : q.userStr ? std::string("strptr") : q.ptr ? std::string("ptr") : (q.type.isSigned ? "i" : "u") + std::to_string(q.type.bits)));
        anyUserStrV16 |= llvm::any_of(params, [](const Program::Param &q) { return q.userStr || q.userStrArray; });
        attaches.push_back(std::move(row));
        anyV13 = true;
        continue;
      }
      // Non-companion families use generic format-9 attachment rows.
      if (!bpfmlir::isCompanionAttachType(ra.type)) {
        AttachRow row{p.symbol, ra.target, {}, ra.type};
        if (!p.tpbuf.empty()) {
          if (!kindInfo || !bpfmlir::kindAllows(*kindInfo, "tp.buffer") || p.tpbuf != "i32") {
            diags.error("program \"" + p.symbol + "\":  tp.buffer: ABI shape mismatch");
            continue;
          }
          row.extra.push_back("tpbuf\t" + p.symbol + "\t" + p.tpbuf);
          anyTpbuf = true;
        }
        attaches.push_back(std::move(row));
        anyGenericAttach = true;
        continue;
      }
      if (ra.type == "trace_fentry") {
        AttachRow row{p.symbol, ra.target, {}, "trace_fentry"};
        // fentry emits per-index farg struct names or unread '-', matched against target FUNC_PROTO.
        if (const Program *decl = schema.program(p.symbol))
          for (auto [i, a] : llvm::enumerate(decl->args)) {
            row.extra.push_back("farg\t" + p.symbol + "\t" + std::to_string(i) + "\t" +
                                (!a.empty() && a.back() == '?' ? a.substr(0, a.size() - 1) : a));
            anyFarg = true;
          }
        attaches.push_back(std::move(row));
        continue;
      }
      // fexit emits attach and retsig from schema nargs/ret, matched against target FUNC_PROTO.
      if (ra.type == "trace_fexit") {
        const Program *decl = schema.program(p.symbol);
        if (!decl || decl->nargs < 0) {
          diags.error("fexit program \"" + p.symbol + "\" has no signature (nargs / ret) in the schema");
          continue;
        }
        attaches.push_back({p.symbol, ra.target, {}, "trace_fexit",
                            std::to_string(decl->nargs) + "\t" + (decl->ret.isSigned ? "i" : "u") +
                                std::to_string(decl->ret.bits)});
        continue;
      }
      // fmod_ret emits trace_fmod_ret attach, retsig and integer/unread farg rows;
      // zero-based schema index matches one-based FUNC_PROTO arguments.
      if (ra.type == "trace_fmod_ret") {
        const Program *decl = schema.program(p.symbol);
        if (!decl || decl->nargs < 0) {
          diags.error(kindInfo->name.str() + " program \"" + p.symbol + "\" has no signature (nargs / ret) in the schema");
          continue;
        }
        AttachRow row{p.symbol, ra.target, {}, "trace_fmod_ret",
                      std::to_string(decl->nargs) + "\t" + (decl->ret.isSigned ? "i" : "u") + std::to_string(decl->ret.bits)};
        for (auto [i, a] : llvm::enumerate(decl->args))
          row.extra.push_back("farg\t" + p.symbol + "\t" + std::to_string(i) + "\t" + a);
        attaches.push_back(std::move(row));
        anyFmodRet = true;
        continue;
      }
      // Every tracepoint uses trace_tp, even without fields. Emit all declared
      // tpfield rows in offset order, including unread declarations, for
      // pre-load matching against target tracefs.
      if (ra.type == "trace_tp") {
        AttachRow row{p.symbol, ra.target, {}, "trace_tp"};
        if (const Program *decl = schema.program(p.symbol)) {
          std::vector<Program::TpField> fs = decl->fields;
          std::sort(fs.begin(), fs.end(), [](auto &a, auto &b) { return a.offset < b.offset; });
          for (const Program::TpField &f : fs) {
            anyUserStrV16 |= f.userStr || f.userStrArray;
            anyTpArrayV17 |= f.arrayCount != 0;
            std::string type = f.arrayCount ? "[" + std::to_string(f.arrayCount) + "]" + (f.type.isSigned ? "i8" : "u8")
                                          : f.userStrArray ? "strarray" : f.userStr ? "strptr" : (f.type.isSigned ? "i" : "u");
            row.extra.push_back("tpfield\t" + p.symbol + "\t" + f.name + "\t" + std::to_string(f.offset) + "\t" + std::to_string(f.arrayCount ? f.arrayCount : f.type.bits / 8) +
                                "\t" + type);
          }
        }
        attaches.push_back(std::move(row));
        anyV11 = true;
        continue;
      }
      // perf_event emits trace_perf perf plus schema arch for fixed context
      // offsets. Separate ctxaccess rows describe actual field accesses.
      if (ra.type == "trace_perf") {
        const Program *decl = schema.program(p.symbol);
        if (!decl || decl->arch.empty()) {
          diags.error("perf_event program \"" + p.symbol + "\" has no arch in the schema");
          continue;
        }
        AttachRow row{p.symbol, ra.target, {}, "trace_perf"};
        row.extra.push_back("arch\t" + p.symbol + "\t" + decl->arch);
        attaches.push_back(std::move(row));
        anyV11 = true;
        continue;
      }
      // ext emits freplace attach, extret and per-index extarg from the schema
      // replacement signature, matched against loader-supplied target BTF.
      if (ra.type == "freplace") {
        const Program *decl = schema.program(p.symbol);
        if (!decl || decl->nargs < 0) {
          diags.error(kindInfo->name.str() + " program \"" + p.symbol + "\" has no signature (nargs / ret / args) in the schema");
          continue;
        }
        AttachRow row{p.symbol, ra.target, {}, "freplace"};
        row.extra.push_back("extret\t" + p.symbol + "\t" + std::to_string(decl->nargs) + "\t" + (decl->ret.isSigned ? "i" : "u") +
                            std::to_string(decl->ret.bits));
        for (auto [i, a] : llvm::enumerate(decl->args))
          row.extra.push_back("extarg\t" + p.symbol + "\t" + std::to_string(i) + "\t" + a);
        attaches.push_back(std::move(row));
        anyV11 = true;
        continue;
      }
      // struct_ops emits trace_struct_ops attach, structop type/member, retsig and
      // farg rows. PROMOTION maps verifier names back to BTF (tcp_sock -> sock).
      // Precheck matches target bpf_struct_ops_<type> and member FUNC_PROTO.
      if (ra.type == "trace_struct_ops") {
        const Program *decl = schema.program(p.symbol);
        const Map *sm = nullptr;
        for (const Map &mp : schema.maps())
          if (mp.symbol == ra.target && mp.structOps)
            sm = &mp;
        const Map::StructOps::Op *op = nullptr;
        if (sm)
          for (const Map::StructOps::Op &o : sm->structOps->ops)
            if (o.program == p.symbol)
              op = &o;
        if (!decl || decl->nargs < 0 || !op) {
          diags.error(kindInfo->name.str() + " program \"" + p.symbol + "\" has no member signature (nargs / ret) or no op in the struct_ops map \"" +
                      ra.target + "\" of the schema");
          continue;
        }
        const std::string &ops = sm->structOps->type;
        AttachRow row{p.symbol, ra.target, {}, "trace_struct_ops"};
        row.extra.push_back("structop\t" + p.symbol + "\t" + ops + "\t" + op->member);
        row.extra.push_back("retsig\t" + p.symbol + "\t" + std::to_string(decl->nargs) + "\t" +
                            (decl->retVoid ? std::string("void") : (decl->ret.isSigned ? "i" : "u") + std::to_string(decl->ret.bits)));
        for (auto [i, a] : llvm::enumerate(decl->args)) {
          std::string s = !a.empty() && a.back() == '?' ? a.substr(0, a.size() - 1) : a;
          row.extra.push_back("farg\t" + p.symbol + "\t" + std::to_string(i) + "\t" + bpfmlir::structOpsArgBTFName(ops, s).str());
        }
        attaches.push_back(std::move(row));
        anyV11 = true;
        continue;
      }
      // Multi-probes emit attach family/N, arch/ctxfield/optional binary, then N
      // mtarget rows in schema order, then entry argument rows. Cookie i follows
      // that order. Entry contexts declare each read argument register; return
      // families declare only the return register and forbid params.
      if (ra.type == "kprobe_multi" || ra.type == "kretprobe_multi" || ra.type == "uprobe_multi" || ra.type == "uretprobe_multi") {
        bool isU = ra.type == "uprobe_multi" || ra.type == "uretprobe_multi";
        bool isRet = ra.type == "kretprobe_multi" || ra.type == "uretprobe_multi";
        const Program *decl = schema.program(p.symbol);
        if (!decl || decl->arch.empty()) {
          diags.error(ra.type + " program \"" + p.symbol + "\" has no arch in the schema");
          continue;
        }
        if (isU && decl->binarySHA256.empty()) {
          diags.error(ra.type + " program \"" + p.symbol + "\" has no binary_sha256 in the schema");
          continue;
        }
        if (!multiTargets) {
          diags.error(ra.type + " program \"" + p.symbol + "\" has no attach list");
          continue;
        }
        // target_params emits per-function mtargetarg. Reject malformed counts or
        // return-family declarations rather than emit ELF without type matching.
        bool perTarget = !decl->targetParams.empty();
        if (perTarget && (isRet || decl->targetParams.size() != multiTargets->size())) {
          diags.error(ra.type + " program \"" + p.symbol + "\": per-target arguments (schema target_params — " +
                      std::to_string(decl->targetParams.size()) + " entries for " + std::to_string(multiTargets->size()) +
                      " attach targets) cannot be written as the requirements rows `mtargetarg <program> <i> <n> <type>` (one entry per attach target "
                      "of an entry probe); no ELF is written");
          continue;
        }
        AttachRow row{p.symbol, ra.target, {}, ra.type};
        row.extra.push_back("arch\t" + p.symbol + "\t" + decl->arch);
        std::vector<Program::Param> params = decl->params;
        std::sort(params.begin(), params.end(), [](auto &a, auto &b) { return a.n < b.n; });
        if (isRet) {
          const mlir::bpfabi::KprobeArgABI *k = mlir::bpfabi::lookupKprobeRet(decl->arch);
          if (!k) {
            diags.error(ra.type + " program \"" + p.symbol + "\": the return value register of " + decl->arch + " is not in the UAPI table");
            continue;
          }
          row.extra.push_back("ctxfield\t" + p.symbol + "\tpt_regs\t" + k->kernelField.str() + "\t" + std::to_string(k->offset) + "\t" +
                              std::to_string(k->bytes));
        } else {
          // target_params context fields are the union of argument indices across
          // targets; each register field appears once.
          std::set<int64_t> ns;
          for (const Program::Param &q : params)
            ns.insert(q.n);
          for (const std::vector<Program::Param> &tp : decl->targetParams)
            for (const Program::Param &q : tp)
              ns.insert(q.n);
          for (int64_t n : ns) {
            const mlir::bpfabi::KprobeArgABI *k = mlir::bpfabi::lookupKprobeArg(decl->arch, static_cast<int>(n));
            if (!k) {
              diags.error(ra.type + " program \"" + p.symbol + "\": argument " + std::to_string(n) + " has no register on " + decl->arch);
              continue;
            }
            row.extra.push_back("ctxfield\t" + p.symbol + "\tpt_regs\t" + k->kernelField.str() + "\t" + std::to_string(k->offset) + "\t" +
                                std::to_string(k->bytes));
          }
        }
        if (isU)
          row.extra.push_back("binary\t" + p.symbol + "\tsha256\t" + decl->binarySHA256);
        for (auto [i, name] : llvm::enumerate(*multiTargets))
          row.extra.push_back("mtarget\t" + p.symbol + "\t" + std::to_string(i) + "\t" + name);
        auto argType = [](const Program::Param &q) {
          return q.userStr ? std::string("strptr") : q.ptr || q.userBuf ? std::string("ptr") : (q.type.isSigned ? "i" : "u") + std::to_string(q.type.bits);
        };
        if (isU) {
          anyUserPtrV18 |= llvm::any_of(params, [](const Program::Param &q) { return q.ptr || q.userBuf; });
          for (const auto &ps : decl->targetParams)
            anyUserPtrV18 |= llvm::any_of(ps, [](const Program::Param &q) { return q.ptr || q.userBuf; });
        }
        if (!isRet)
          for (const Program::Param &q : params)
            row.extra.push_back(std::string(isU ? "uprobearg" : "kprobearg") + "\t" + p.symbol + "\t" + std::to_string(q.n) + "\t" + argType(q));
        // mtargetarg rows sort by (target index,argument index), exclusive with
        // shared kprobearg/uprobearg, like schema params/target_params.
        for (auto [i, tp] : llvm::enumerate(decl->targetParams)) {
          std::vector<Program::Param> ps = tp;
          std::sort(ps.begin(), ps.end(), [](auto &a, auto &b) { return a.n < b.n; });
          for (const Program::Param &q : ps)
            row.extra.push_back("mtargetarg\t" + p.symbol + "\t" + std::to_string(i) + "\t" + std::to_string(q.n) + "\t" + argType(q));
        }
        attaches.push_back(std::move(row));
        anyMulti = true;
        anyV13 |= perTarget;
        continue;
      }
      // USDT emits provider:name attach, arch, then all ABI usdtreg fields in
      // register-index order only when usdt.arg generated a spec placeholder.
      // binary/usdtsem/usdtarg follow; sorted argument rows match size/sign at
      // every note point. Synthesized schema maps supply the spec-map map row.
      if (ra.type == "usdt") {
        const Program *decl = schema.program(p.symbol);
        if (!decl || decl->arch.empty() || decl->binarySHA256.empty() || decl->usdtSemaphore.empty()) {
          diags.error("usdt program \"" + p.symbol + "\" needs arch, binary_sha256 and semaphore in the schema");
          continue;
        }
        AttachRow row{p.symbol, ra.target, {}, ra.type};
        row.extra.push_back("arch\t" + p.symbol + "\t" + decl->arch);
        if (m.getGlobalVariable(std::string(::ebpf::kUsdtSpecMapPrefix) + p.symbol, true))
          for (const mlir::bpfabi::UsdtRegABI &r : mlir::bpfabi::usdtRegs())
            if (r.arch == decl->arch)
              row.extra.push_back("ctxfield\t" + p.symbol + "\tpt_regs\t" + r.kernelField.str() + "\t" + std::to_string(r.offset) + "\t" +
                                  std::to_string(r.bytes));
        row.extra.push_back("binary\t" + p.symbol + "\tsha256\t" + decl->binarySHA256);
        row.extra.push_back("usdtsem\t" + p.symbol + "\t" + decl->usdtSemaphore);
        std::vector<Program::Param> params = decl->params;
        std::sort(params.begin(), params.end(), [](auto &a, auto &b) { return a.n < b.n; });
        for (const Program::Param &q : params)
          row.extra.push_back("usdtarg\t" + p.symbol + "\t" + std::to_string(q.n) + "\t" + (q.type.isSigned ? "i" : "u") +
                              std::to_string(q.type.bits));
        attaches.push_back(std::move(row));
        anyMulti = true; // Format-12 rows.
        continue;
      }
      // Probes emit attach/arch, fixed pt_regs ctxfield rows and parameter types.
      // Precheck matches target BTF offsets and FUNC_PROTO for kprobes; uprobes
      // additionally emit binary SHA-256 and match uprobearg against DWARF.
      bool isUprobe = ra.type == "uprobe";
      if (ra.type == "kprobe" || isUprobe) {
        const Program *decl = schema.program(p.symbol);
        if (!decl || decl->arch.empty()) {
          diags.error(std::string(isUprobe ? "uprobe" : "kprobe") + " program \"" + p.symbol + "\" has no arch in the schema");
          continue;
        }
        if (isUprobe && decl->binarySHA256.empty()) {
          diags.error("uprobe program \"" + p.symbol + "\" has no binary_sha256 in the schema");
          continue;
        }
        AttachRow row{p.symbol, ra.target, {}, ra.type};
        row.extra.push_back("arch\t" + p.symbol + "\t" + decl->arch);
        std::vector<Program::Param> params = decl->params;
        std::sort(params.begin(), params.end(), [](auto &a, auto &b) { return a.n < b.n; });
        for (const Program::Param &q : params) {
          const mlir::bpfabi::KprobeArgABI *k = mlir::bpfabi::lookupKprobeArg(decl->arch, static_cast<int>(q.n));
          if (!k) {
            diags.error("kprobe program \"" + p.symbol + "\": argument " + std::to_string(q.n) + " has no register on " + decl->arch);
            continue;
          }
          row.extra.push_back("ctxfield\t" + p.symbol + "\tpt_regs\t" + k->kernelField.str() + "\t" + std::to_string(k->offset) + "\t" +
                              std::to_string(k->bytes));
        }
        if (isUprobe)
          row.extra.push_back("binary\t" + p.symbol + "\tsha256\t" + decl->binarySHA256);
        if (isUprobe)
          anyUserPtrV18 |= llvm::any_of(params, [](const Program::Param &q) { return q.ptr || q.userBuf; });
        for (const Program::Param &q : params)
          row.extra.push_back(std::string(isUprobe ? "uprobearg" : "kprobearg") + "\t" + p.symbol + "\t" + std::to_string(q.n) + "\t" +
                              (q.userStr ? std::string("strptr") // One pointer level to eight-bit char, matched against DWARF.
                               : q.ptr || q.userBuf ? std::string("ptr")
                                         : (q.type.isSigned ? "i" : "u") + std::to_string(q.type.bits)));
        attaches.push_back(std::move(row));
        continue;
      }
      // tcx attach direction is checked against loader capabilities.
      if (ra.type == "tcx") {
        attaches.push_back({p.symbol, ra.target, {}, "tcx"});
        continue;
      }
      // Return probes emit attach/arch and ABI return-register ctxfield.
      // uretprobe also emits binary SHA-256. Entry argument registers are
      // clobbered at return, so no parameter rows are permitted.
      if (ra.type == "kretprobe" || ra.type == "uretprobe") {
        bool isUret = ra.type == "uretprobe";
        const Program *decl = schema.program(p.symbol);
        if (!decl || decl->arch.empty()) {
          diags.error(ra.type + " program \"" + p.symbol + "\" has no arch in the schema");
          continue;
        }
        if (isUret && decl->binarySHA256.empty()) {
          diags.error("uretprobe program \"" + p.symbol + "\" has no binary_sha256 in the schema");
          continue;
        }
        const mlir::bpfabi::KprobeArgABI *k = mlir::bpfabi::lookupKprobeRet(decl->arch);
        if (!k) {
          diags.error(ra.type + " program \"" + p.symbol + "\": the return value register of " + decl->arch + " is not in the UAPI table");
          continue;
        }
        AttachRow row{p.symbol, ra.target, {}, ra.type};
        row.extra.push_back("arch\t" + p.symbol + "\t" + decl->arch);
        row.extra.push_back("ctxfield\t" + p.symbol + "\tpt_regs\t" + k->kernelField.str() + "\t" + std::to_string(k->offset) + "\t" +
                            std::to_string(k->bytes));
        if (isUret)
          row.extra.push_back("binary\t" + p.symbol + "\tsha256\t" + decl->binarySHA256);
        attaches.push_back(std::move(row));
        anyGenericAttach = true; // Return-probe attachment types require format 9.
        continue;
      }
      if (ra.type != "trace_raw_tp") {
        diags.error("program \"" + p.symbol + "\": requirements attach type " + ra.type + " has no emitter");
        continue;
      }
      const Program *decl = schema.program(p.symbol);
      if (!decl) {
        diags.error("tp_btf program \"" + p.symbol +
                    "\" is not declared in the schema");
        continue;
      }
      attaches.push_back({p.symbol, ra.target,
                          decl->args});
    }
    // Raise format only for rows present, preserving existing ELF bytes. Every
    // emitted ELF has btf rows (minimum five); argtag raises its own minimum.
    bool anyArgTag = false;
    for (const ProgramRequirement &p : progs)
      anyArgTag |= !p.argTags.empty();
    bool anyCtxAccess = false; // ctxaccess and generic attachments require format 9.
    for (const ProgramRequirement &p : progs)
      anyCtxAccess |= !p.ctxAccess.empty();
    // tailslot requires format seven. Slot targets must be programs in this
    // ELF of the owning prog_array's type; reject mismatches before emission.
    std::vector<std::string> tailslots;
    for (const Map &mp : schema.maps()) {
      std::vector<Map::Slot> slots = mp.slots;
      std::sort(slots.begin(), slots.end(), [](auto &a, auto &b) { return a.index < b.index; });
      for (const Map::Slot &q : slots) {
        Function *fn = m.getFunction(q.program);
        std::string slotAttach; // Slot targets must belong to a tail_call-capable kind from OPS.
        const bpfmlir::ProgramKindInfo *slotKind = fn ? bpfmlir::kindOfSection(fn->getSection(), slotAttach) : nullptr;
        if (!fn || fn->isDeclaration() || !slotKind || !bpfmlir::kindAllows(*slotKind, "tail_call")) {
          diags.error("prog_array \"" + mp.symbol + "\" slot " + std::to_string(q.index) + ": program \"" + q.program +
                      "\" is not an " + bpfmlir::kindsAllowing("tail_call") + " program of this object");
          continue;
        }
        tailslots.push_back("tailslot\t" + mp.symbol + "\t" + std::to_string(q.index) + "\t" + q.program + "\n");
      }
    }
    // farg requires format eight; innermap requires twelve. Other objects
    // retain their previous minimum format and byte representation.
    bool anyInnerMap = false;
    for (const EmittedMap &mp : emittedMaps)
      anyInnerMap |= !mp.inner.empty();
    // Emit each reachable kfunc's ABI signature using requirement spellings
    // (*S -> ptr:S). Target BTF matching checks the exact signature at load.
    std::vector<std::string> kfuncRows;
    for (ProgramRequirement &p : progs) {
      std::sort(p.kfuncs.begin(), p.kfuncs.end());
      p.kfuncs.erase(std::unique(p.kfuncs.begin(), p.kfuncs.end()), p.kfuncs.end());
      for (const std::string &kn : p.kfuncs) {
        const mlir::bpfabi::KfuncABI *k = mlir::bpfabi::lookupKfunc(kn);
        if (!k) {
          diags.error("program \"" + p.symbol + "\": kfunc \"" + kn + "\" is not in the kfunc table");
          continue;
        }
        auto spell = [](StringRef t) { return t.starts_with("*") ? "ptr:" + t.drop_front().str() : t.str(); };
        std::string row = "kfunc\t" + p.symbol + "\t" + kn + "\t" + spell(k->ret);
        for (auto &[pname, ptype] : k->paramList())
          row += "\t" + spell(ptype);
        kfuncRows.push_back(row + "\n");
      }
    }
    anyV13 |= !kfuncRows.empty();
    // Map-value type_tag requires format 13.
    anyV13 |= llvm::is_contained(btfFeatures, "type_tag");
    // kfield strptr requires format 15 under value-specific minimum rules.
    bool anyStrPtr = llvm::any_of(kfields, [](const KFieldRequirement &k) { return k.type == "strptr"; });
    bool anyPathV17 = llvm::any_of(kfields, [](const KFieldRequirement &k) { return StringRef(k.field).contains('.') || StringRef(k.type).starts_with("struct:"); });
    std::string text = anyUserPtrV18 ? "ebpf-requirements 18\n"
                       : (anyTpArrayV17 || anyPathV17) ? "ebpf-requirements 17\n"
                       : anyUserStrV16 ? "ebpf-requirements 16\n"
                       : anyStrPtr  ? "ebpf-requirements 15\n"
                       : anyTpbuf ? "ebpf-requirements 14\n"
                       : anyV13 ? "ebpf-requirements 13\n" // Format-13 kfunc/ksyscall/trace_lsm_cgroup/sysarg/mtargetarg rows.
                       : (anyInnerMap || anyMulti) ? "ebpf-requirements 12\n" // Multi-probe rows require format 12.
                       : anyV11 ? "ebpf-requirements 11\n"
                       : anyFmodRet ? "ebpf-requirements 10\n"
                       : (anyCtxAccess || anyGenericAttach) ? "ebpf-requirements 9\n"
                       : anyFarg ? "ebpf-requirements 8\n"
                       : !tailslots.empty() ? "ebpf-requirements 7\n"
                       : anyArgTag ? "ebpf-requirements 6\n"
                                   : "ebpf-requirements 5\n";
    text += "schema\tsha256\t" + schemaSHA256.str() + "\n";
    for (const ProgramRequirement &p : progs)
      text += "program\t" + p.symbol + "\t" + p.progType + "\t" +
              std::to_string(p.progTypeId) + "\n";
    for (ProgramRequirement &p : progs) {
      std::sort(p.helpers.begin(), p.helpers.end());
      for (auto &[id, name] : p.helpers)
        text += "helper\t" + p.symbol + "\t" + name + "\t" +
                std::to_string(id) + "\n";
    }
    std::vector<EmittedMap> maps = emittedMaps;
    std::sort(maps.begin(), maps.end(),
              [](auto &a, auto &b) { return a.symbol < b.symbol; });
    for (const EmittedMap &mp : maps) {
      text += "map\t" + mp.symbol + "\t" + mp.typeName + "\t" +
              std::to_string(mp.typeId) + "\t" + mp.key + "\t" + mp.value +
              "\t" + std::to_string(mp.maxEntries) + "\t" +
              std::to_string(mp.flags) + "\n";
      // innermap binds positionally immediately after its outer map row.
      if (!mp.inner.empty())
        text += "innermap\t" + mp.symbol + "\t" + mp.inner + "\n";
    }

    // kfield rows sort by program/type/field.
    for (const KFieldRequirement &k : kfields)
      text += "kfield\t" + k.program + "\t" + k.structName + "\t" + k.field +
              "\t" + k.type + "\n";
    // trace_raw_tp attach and per-index argument rows.
    for (const AttachRow &at : attaches) {
      text += "attach\t" + at.program + "\t" + at.type + "\t" + at.tracepoint + "\n";
      if (!at.retsig.empty())
        text += "retsig\t" + at.program + "\t" + at.retsig + "\n";
      for (const std::string &x : at.extra)
        text += x + "\n";
      for (auto [i, a] : llvm::enumerate(at.args)) // Nullable S? arguments serialize as S: target type matching is unchanged.
        text += "arg\t" + at.program + "\t" + std::to_string(i) + "\t" +
                (!a.empty() && a.back() == '?' ? a.substr(0, a.size() - 1) : a) + "\n";
    }
    // BTF feature names sort lexically. Match target support before loading
    // rather than permit loader sanitization to erase required information.
    for (const std::string &f : btfFeatures)
      text += "btf\t" + f + "\n";
    // argtag rows sort by program then tag.
    for (ProgramRequirement &p : progs) {
      std::sort(p.argTags.begin(), p.argTags.end());
      for (const std::string &t : p.argTags) {
        auto [tag, cls] = StringRef(t).split(' ');
        text += "argtag\t" + p.symbol + "\t" + tag.str() + "\t" + cls.str() + "\n";
      }
    }
    // tailslot rows follow schema map order, then slot order.
    for (const std::string &t : tailslots)
      text += t;
    // ctxaccess rows follow program order, then ABI (struct,field,mode) order.
    for (const ProgramRequirement &p : progs)
      for (const std::string &c : p.ctxAccess) {
        SmallVector<StringRef> f;
        StringRef(c).split(f, ' ');
        text += "ctxaccess\t" + p.symbol;
        for (StringRef x : f)
          text += "\t" + x.str();
        text += "\n";
      }
    // kfunc rows follow program order, then name order.
    for (const std::string &r : kfuncRows)
      text += r;

    auto *data =
        ConstantDataArray::getString(m.getContext(), text, /*AddNull=*/false);
    auto *g = new GlobalVariable(m, data->getType(), /*isConstant=*/true,
                                 GlobalValue::InternalLinkage, data,
                                 "__ebpf_requirements");
    g->setSection(kRequirementsSection);
    g->setAlignment(Align(1));
    appendToUsed(m, {g});
  }

  // Move the BTF-built license global after requirements/llvm.used to retain
  // existing ELF section and symbol ordering.
  void moveLicenseLast() {
    if (GlobalVariable *g = m.getGlobalVariable("_license", true)) {
      g->removeFromParent();
      m.insertGlobalVariable(g);
    }
  }
};

} // namespace

mlir::LogicalResult emitObject(mlir::ModuleOp module, const Schema &schema,
                               StringRef schemaSHA256, raw_pwrite_stream &os,
                               Diagnostics &diags, StringRef license,
                               llvm::raw_ostream *llvmIROut,
                               llvm::raw_ostream *presentCostOut,
                               uint64_t presentOutlineThreshold) {
  // Reject a big-endian declaration before emitting little-endian BPF.
  auto checkLittle = [&](const ebpf::Type &t, StringRef where) {
    if (const auto *i = std::get_if<IntType>(&t.v))
      if (i->endianness != Endianness::Little)
        diags.error(where + ": the schema declares big-endian but the target "
                            "is bpfel (little endian)");
  };
  for (const Record &r : schema.records())
    for (const Field &f : r.fields)
      checkLittle(f.type, "record \"" + r.symbol + "\" field \"" + f.name +
                              "\"");
  for (const Map &mp : schema.maps()) {
    if (mp.key)
      checkLittle(*mp.key, "map \"" + mp.symbol + "\" key");
    if (mp.value)
      checkLittle(*mp.value, "map \"" + mp.symbol + "\" value");
  }
  if (diags.failed)
    return mlir::failure();

  // Read and remove requirement attributes before LLVM translation. Never
  // emit a program without requirements, which would bypass pre-load checks.
  std::vector<ProgramRequirement> progs;
  for (auto fn : module.getOps<mlir::LLVM::LLVMFuncOp>()) {
    if (fn.isExternal())
      continue;
    // Subprogram helper requirements belong to reaching programs; remove only
    // their marker, not independent requirement rows.
    if (fn->hasAttr("bpfabi.subprogram")) {
      fn->removeAttr("bpfabi.subprogram");
      continue;
    }
    std::string sym = fn.getName().str();
    auto req = fn->getAttrOfType<mlir::DictionaryAttr>("bpfabi.requires");
    if (!req) {
      diags.error("program \"" + sym + "\" has no requirements (bpfabi.requires); "
                  "compile it through the staged pipeline");
      continue;
    }
    ProgramRequirement pr;
    pr.symbol = sym;
    auto pt = req.getAs<mlir::StringAttr>("prog_type");
    auto hs = req.getAs<mlir::ArrayAttr>("helpers");
    std::optional<int64_t> ptId =
        pt ? mlir::bpfabi::lookupProgType(pt.getValue()) : std::nullopt;
    if (!pt || !hs || !ptId) {
      diags.error("program \"" + sym + "\": malformed bpfabi.requires");
      continue;
    }
    pr.progType = pt.getValue().str();
    pr.progTypeId = *ptId;
    for (mlir::Attribute a : hs) {
      auto name = mlir::dyn_cast<mlir::StringAttr>(a);
      const mlir::bpfabi::HelperABI *h =
          name ? mlir::bpfabi::lookupHelper(name.getValue()) : nullptr;
      if (!h) {
        diags.error("program \"" + sym + "\": helper not in the UAPI table");
        continue;
      }
      pr.helpers.push_back({h->id, h->name.str()});
    }
    if (auto ats = req.getAs<mlir::ArrayAttr>("arg_tags"))
      for (mlir::Attribute a : ats)
        pr.argTags.push_back(llvm::cast<mlir::StringAttr>(a).getValue().str());
    if (auto cas = req.getAs<mlir::ArrayAttr>("ctx_access"))
      for (mlir::Attribute a : cas)
        pr.ctxAccess.push_back(llvm::cast<mlir::StringAttr>(a).getValue().str());
    if (auto ks = req.getAs<mlir::ArrayAttr>("kfuncs"))
      for (mlir::Attribute a : ks)
        pr.kfuncs.push_back(llvm::cast<mlir::StringAttr>(a).getValue().str());
    if (auto tpbuf = req.getAs<mlir::StringAttr>("tpbuf"))
      pr.tpbuf = tpbuf.getValue().str();
    progs.push_back(std::move(pr));
    fn->removeAttr("bpfabi.requires");
    fn->removeAttr("bpfabi.prog_type");
  }
  if (diags.failed)
    return mlir::failure();

  // Read @kernel local types for the bridge, then remove BTF operations before
  // LLVM translation. Any other remaining BTF scope means the DI lowering
  // stage was skipped; fail explicitly.
  std::vector<KernelLocal> kernelLocals;
  {
    llvm::SmallVector<mlir::Operation *> btfOps;
    for (mlir::Operation &op : *module.getBody()) {
      if (!llvm::isa<mlir::btf::BTFDialect>(op.getDialect()))
        continue;
      auto scope = llvm::dyn_cast<mlir::btf::ScopeOp>(op);
      if (!scope || scope.getSymName() != "kernel") {
        diags.error("btf IR is still in the module (" + op.getName().getStringRef().str() +
                    "); run convert-btf-to-llvm-di before emitObject");
        return mlir::failure();
      }
      for (auto st : scope.getBody().front().getOps<mlir::btf::StructOp>()) {
        KernelLocal k{st.getSymName().str(), static_cast<uint64_t>(st.getSizeBits()), {}};
        k.alignBits = st.getAlignBits();
        for (mlir::Attribute a : st.getMembers()) {
          auto mb = llvm::cast<mlir::btf::MemberAttr>(a);
          if (auto ref = llvm::dyn_cast<mlir::btf::RefAttr>(mb.getType())) {
            KernelLocal::Field f{mb.getName().str(), mb.getOffsetBits(), false, 0, ""};
            f.embedded = ref.getTarget().getLeafReference().str();
            k.fields.push_back(std::move(f)); continue;
          }
          // Eight-bit integer array member.
          if (auto aa = llvm::dyn_cast<mlir::btf::ArrayOfAttr>(mb.getType())) {
            auto ei = llvm::dyn_cast<mlir::btf::IntAttr>(aa.getElement());
            if (!ei || ei.getBits() != 8) {
              diags.error("CO-RE local type " + k.name + "." + mb.getName().str() + ": an array member must have 8-bit integer elements");
              return mlir::failure();
            }
            KernelLocal::Field fa{mb.getName().str(), mb.getOffsetBits(), ei.getEncoding() == "signed", 8, ""};
            fa.arrayCount = aa.getCount();
            k.fields.push_back(fa);
            continue;
          }
          // PTR to local kernel struct, or PTR to eight-bit INT for strptr char*.
          if (auto pa = llvm::dyn_cast<mlir::btf::PtrAttr>(mb.getType())) {
            if (auto ci = llvm::dyn_cast<mlir::btf::IntAttr>(pa.getPointee()); ci && ci.getBits() == 8) {
              KernelLocal::Field fs{mb.getName().str(), mb.getOffsetBits(), false, 64, ""};
              fs.strPtr = true;
              k.fields.push_back(fs);
              continue;
            }
            auto ref = llvm::dyn_cast<mlir::btf::RefAttr>(pa.getPointee());
            if (!ref) {
              diags.error("CO-RE local type " + k.name + "." + mb.getName().str() + ": a pointer member must point to a kernel type");
              return mlir::failure();
            }
            k.fields.push_back({mb.getName().str(), mb.getOffsetBits(), false, 64, ref.getTarget().getLeafReference().str()});
            continue;
          }
          auto it = llvm::dyn_cast<mlir::btf::IntAttr>(mb.getType());
          unsigned bits = it ? it.getBits() : 0;
          if (bits != 8 && bits != 16 && bits != 32 && bits != 64) {
            diags.error("CO-RE local type " + k.name + "." + mb.getName().str() +
                        ": only 8 / 16 / 32 / 64-bit integer fields are supported");
            return mlir::failure();
          }
          k.fields.push_back({mb.getName().str(), mb.getOffsetBits(),
                              it.getEncoding() == "signed", bits, ""});
        }
        kernelLocals.push_back(std::move(k));
      }
      btfOps.push_back(&op);
    }
    for (mlir::Operation *op : btfOps)
      op->erase();
  }
  if (!module->getAttr("ebpf.btf_built")) {
    diags.error("the module has no BTF (run ebpf-build-btf and convert-btf-to-llvm-di)");
    return mlir::failure();
  }
  module->removeAttr("ebpf.btf_built");
  // BTF features counted from BTF IR become format-5 btf requirement rows.
  std::vector<std::string> btfFeatures;
  if (auto fs = module->getAttrOfType<mlir::ArrayAttr>("ebpf.btf_features")) {
    for (mlir::Attribute a : fs)
      btfFeatures.push_back(llvm::cast<mlir::StringAttr>(a).getValue().str());
    module->removeAttr("ebpf.btf_features");
  } else {
    diags.error("the module has no BTF feature list (ebpf.btf_features)");
    return mlir::failure();
  }

  // Read/remove btf.arg_tags and source argument-type attributes before LLVM
  // translation. Attach declaration tags afterward through the bridge below.
  std::map<std::string, std::vector<std::vector<std::string>>> argTags;
  std::set<std::string> kfuncDecls;
  for (auto fn : module.getOps<mlir::LLVM::LLVMFuncOp>()) {
    fn->removeAttr("bpfabi.arg_types");
    fn->removeAttr("bpfabi.nullable_args");
    fn->removeAttr("bpfabi.nonnull_args");
    fn->removeAttr("bpfabi.callback"); // Remove bpf_loop callback marker after BTF signature generation.
    fn->removeAttr("bpfabi.timer_callback"); // Remove timer callback marker after BTF signature generation.
    fn->removeAttr("bpfabi.user_ringbuf_callback"); // Remove user-ringbuf callback marker after BTF signature generation.
    if (fn->hasAttr("bpfabi.kfunc")) // Retain kfunc extern identity for the post-translation section/BTF bridge.
      kfuncDecls.insert(fn.getName().str());
    fn->removeAttr("bpfabi.kfunc");
    auto tags = fn->getAttrOfType<mlir::ArrayAttr>("btf.arg_tags");
    if (!tags)
      continue;
    auto &v = argTags[fn.getName().str()];
    for (mlir::Attribute per : tags) {
      v.emplace_back();
      for (mlir::Attribute t : llvm::cast<mlir::ArrayAttr>(per))
        v.back().push_back(llvm::cast<mlir::StringAttr>(t).getValue().str());
    }
    fn->removeAttr("btf.arg_tags");
  }

  LLVMContext ctx;
  // Route LLVM errors through Diagnostics and fail emission, including backend
  // stack-limit errors. The default handler only prints and can leave success
  // status with an invalid ELF. Print warnings normally, suppress remarks/notes,
  // and deduplicate repeated identical errors across frame references.
  struct BackendDiags {
    Diagnostics *diags;
    std::set<std::string> seen;
    bool failed = false;
  } backend{&diags, {}, false};
  ctx.setDiagnosticHandlerCallBack(
      [](const DiagnosticInfo *di, void *p) {
        auto *b = static_cast<BackendDiags *>(p);
        std::string msg;
        raw_string_ostream os(msg);
        DiagnosticPrinterRawOStream printer(os);
        di->print(printer);
        StringRef text = StringRef(msg).trim();
        if (di->getSeverity() == DS_Warning) {
          errs() << "warning: " << text << "\n";
          return;
        }
        if (di->getSeverity() != DS_Error)
          return; // Default behavior also suppresses remarks/notes unless enabled.
        b->failed = true;
        if (b->seen.insert(text.str()).second)
          b->diags->error("LLVM: " + text);
      },
      &backend);
  mlir::DialectRegistry registry;
  mlir::registerAllToLLVMIRTranslations(registry);
  module->getContext()->appendDialectRegistry(registry);
  auto llvmModule = mlir::translateModuleToLLVMIR(module, ctx, "ebpf");
  if (!llvmModule) {
    diags.error("could not translate the module to LLVM IR");
    return mlir::failure();
  }

  // LLVM emits DECL_TAG from argument DILocalVariable annotations in retainedNodes,
  // using argument index as component_idx. MLIR cannot represent them, so
  // replace each variable with an annotated one after translation.
  for (auto &[name, perArg] : argTags) {
    Function *F = llvmModule->getFunction(name);
    DISubprogram *SP = F ? F->getSubprogram() : nullptr;
    if (!SP) {
      diags.error("function " + name + " has argument tags but no DISubprogram");
      return mlir::failure();
    }
    SmallVector<Metadata *> nodes;
    unsigned tagged = 0;
    for (MDNode *n : SP->getRetainedNodes()) {
      auto *dv = dyn_cast<DILocalVariable>(n);
      unsigned arg = dv ? dv->getArg() : 0;
      if (!dv || arg == 0 || arg > perArg.size() || perArg[arg - 1].empty()) {
        nodes.push_back(n);
        continue;
      }
      SmallVector<Metadata *> anns;
      for (const std::string &t : perArg[arg - 1])
        anns.push_back(MDNode::get(ctx, {MDString::get(ctx, "btf_decl_tag"),
                                         MDString::get(ctx, t)}));
      nodes.push_back(DILocalVariable::get(
          ctx, dv->getScope(), dv->getName(), dv->getFile(), dv->getLine(),
          dv->getType(), dv->getArg(), dv->getFlags(), dv->getAlignInBits(),
          MDNode::get(ctx, anns)));
      tagged += perArg[arg - 1].size();
    }
    unsigned want = 0;
    for (auto &t : perArg)
      want += t.size();
    if (tagged != want) {
      diags.error("function " + name + ": " + std::to_string(want) +
                  " argument tag(s) but only " + std::to_string(tagged) +
                  " found an argument variable to attach to");
      return mlir::failure();
    }
    SP->replaceRetainedNodes(MDTuple::get(ctx, nodes));
  }

  // Embed empty DIFile source instead of allowing BPF to read line strings
  // from cwd-relative disk files, which would make ELF depend on build location.
  {
    DebugInfoFinder finder;
    finder.processModule(*llvmModule);
    SmallPtrSet<DIFile *, 8> files;
    auto add = [&](DIFile *f) {
      if (f)
        files.insert(f);
    };
    for (DICompileUnit *cu : finder.compile_units())
      add(cu->getFile());
    for (DISubprogram *sp : finder.subprograms())
      add(sp->getFile());
    for (DIScope *sc : finder.scopes())
      add(sc->getFile());
    for (DIType *t : finder.types())
      add(t->getFile());
    for (DIGlobalVariableExpression *g : finder.global_variables())
      add(g->getVariable()->getFile());
    for (Function &F : *llvmModule)
      for (Instruction &I : instructions(F))
        if (const DILocation *dl = I.getDebugLoc())
          add(dl->getFile());
    // LLVM 23 stores DIFile source as a field, not a mutable operand. Create
    // replacements and remap metadata, reusing/mutating distinct nodes.
    // Explicit DILexicalBlockFile locations get synthetic <file>:<line> source
    // for used lines only; unused lines remain empty. This lets 6.6 diagnostics
    // display locations without disk reads. BTFToLLVMDI already bounds line <= 2^20.
    DenseMap<DIFile *, SmallVector<unsigned>> usedLines;
    for (Function &F : *llvmModule)
      for (Instruction &I : instructions(F))
        if (const DILocation *dl = I.getDebugLoc())
          if (auto *lbf = dyn_cast<DILexicalBlockFile>(dl->getScope()))
            if (dl->getLine() != 0)
              usedLines[lbf->getFile()].push_back(dl->getLine());
    ValueToValueMapTy vm;
    for (DIFile *f : files) {
      if (f->getRawSource())
        continue;
      std::string source;
      auto it = usedLines.find(f);
      if (it != usedLines.end()) {
        SmallVector<unsigned> &lines = it->second;
        llvm::sort(lines);
        lines.erase(std::unique(lines.begin(), lines.end()), lines.end());
        unsigned next = 1;
        for (unsigned n : lines) {
          source.append(n - next, '\n');
          source += (f->getFilename() + ":" + Twine(n) + "\n").str();
          next = n + 1;
        }
      }
      vm.MD()[f].reset(DIFile::get(ctx, f->getFilename(), f->getDirectory(), f->getChecksum(), StringRef(source)));
    }
    if (!vm.MD().empty()) {
      const RemapFlags flags = RF_IgnoreMissingLocals | RF_ReuseAndMutateDistinctMDs;
      for (Function &F : *llvmModule)
        if (!F.isDeclaration())
          RemapFunction(F, vm, flags);
        else if (DISubprogram *sp = F.getSubprogram())
          F.setSubprogram(cast<DISubprogram>(MapMetadata(sp, vm, flags)));
      for (GlobalVariable &gv : llvmModule->globals()) {
        SmallVector<std::pair<unsigned, MDNode *>> mds;
        gv.getAllMetadata(mds);
        for (auto &[kind, md] : mds)
          gv.setMetadata(kind, cast<MDNode>(MapMetadata(md, vm, flags)));
      }
      for (NamedMDNode &nmd : llvmModule->named_metadata())
        for (unsigned i = 0; i < nmd.getNumOperands(); ++i)
          nmd.setOperand(i, cast<MDNode>(MapMetadata(nmd.getOperand(i), vm, flags)));
    }
  }

  LLVMInitializeBPFTargetInfo();
  LLVMInitializeBPFTarget();
  LLVMInitializeBPFTargetMC();
  LLVMInitializeBPFAsmPrinter();

  Triple triple("bpfel-unknown-none");
  std::string err;
  const Target *target = TargetRegistry::lookupTarget(triple, err);
  if (!target) {
    diags.error("no bpfel target: " + err);
    return mlir::failure();
  }
  TargetOptions opts;
  std::unique_ptr<TargetMachine> tm(target->createTargetMachine(
      triple, "v1", "", opts, std::optional<Reloc::Model>()));
  if (!tm) {
    diags.error("could not create the bpfel target machine");
    return mlir::failure();
  }
  llvmModule->setTargetTriple(triple);
  llvmModule->setDataLayout(tm->createDataLayout());

  bool hasCore = false;
  {
    Emitter e(*llvmModule, schema, diags, std::move(kernelLocals));
    e.kfuncDecls = kfuncDecls;
    e.collectMaps();
    e.expandCoreMarkers();
    hasCore = e.hasCore;
    e.btfFeatures = btfFeatures;
    e.emitRequirements(progs, schemaSHA256);
    e.moveLicenseLast();
    e.db().finalize();
  }
  // BTF derives from DWARF and needs Debug Info Version. Translation normally
  // adds it already; add only when absent, since duplicate module flags fail
  // LLVM IR verification even though legacy codegen does not run that verifier.
  if (!llvmModule->getModuleFlag("Debug Info Version"))
    llvmModule->addModuleFlag(Module::Warning, "Debug Info Version",
                              DEBUG_METADATA_VERSION);
  llvmModule->addModuleFlag(Module::Error, "Dwarf Version", 4);
  if (diags.failed)
    return mlir::failure();

  // Verify LLVM IR before legacy codegen, which does not verify it itself.
  // Never emit ELF from an invalid module.
  {
    std::string msg;
    raw_string_ostream vos(msg);
    if (verifyModule(*llvmModule, &vos)) {
      diags.error("the LLVM IR is broken (LLVM verifier): " + msg);
      return mlir::failure();
    }
  }
  // Estimate reservation-present cost diagnostically without changing ELF.
  if (presentCostOut)
    for (const PresentCost &pc : estimatePresentCosts(*llvmModule))
      *presentCostOut << pc.fn->getName() << "\t" << pc.index << "\t" << pc.estimate << "\t" << pc.blocks.size() << "\n";
  if (presentCostOut)
    presentCostOut->flush(); // Flush diagnostics before codegen fatal exits. Outline over-threshold
  // present bodies as internal noinline functions; reservation checks remain
  // outside calls. Requirements were emitted before outlining and are unchanged.
  if (!outlineLargePresents(*llvmModule, presentOutlineThreshold, [&](const Twine &msg) { diags.error(msg); }))
    return mlir::failure();
  {
    std::string msg;
    raw_string_ostream vos(msg);
    if (verifyModule(*llvmModule, &vos)) {
      diags.error("the LLVM IR is broken after moving a reservation's work to a function (LLVM verifier): " + msg);
      return mlir::failure();
    }
  }
  // Dump after outlining, immediately before codegen.
  if (llvmIROut)
    llvmModule->print(*llvmIROut, nullptr);

  // Run BPF PipelineStartEP passes, including BPFAbstractMemberAccess, only
  // when CO-RE reads exist. Legacy codegen omits these passes. Leave non-CO-RE
  // modules untouched to preserve existing ELF bytes.
  if (hasCore) {
    LoopAnalysisManager lam;
    FunctionAnalysisManager fam;
    CGSCCAnalysisManager cgam;
    ModuleAnalysisManager mam;
    PassBuilder pb(tm.get());
    pb.registerModuleAnalyses(mam);
    pb.registerCGSCCAnalyses(cgam);
    pb.registerFunctionAnalyses(fam);
    pb.registerLoopAnalyses(lam);
    pb.crossRegisterProxies(lam, fam, cgam, mam);
    ModulePassManager mpm;
    pb.invokePipelineStartEPCallbacks(mpm, OptimizationLevel::O0);
    mpm.run(*llvmModule, mam);
    for (Function &f : *llvmModule)
      for (Instruction &i : instructions(f))
        if (auto *ci = dyn_cast<CallInst>(&i))
          if (Function *callee = ci->getCalledFunction())
            if (callee->getIntrinsicID() ==
                Intrinsic::preserve_struct_access_index) {
              diags.error("CO-RE access in \"" + f.getName().str() +
                          "\" was not turned into a relocation");
              return mlir::failure();
            }
  }

  legacy::PassManager pm;
  if (tm->addPassesToEmitFile(pm, os, nullptr, CodeGenFileType::ObjectFile)) {
    diags.error("the bpfel target machine cannot emit an object file");
    return mlir::failure();
  }
  pm.run(*llvmModule);
  if (backend.failed)
    return mlir::failure();
  return mlir::success();
}

} // namespace ebpf
