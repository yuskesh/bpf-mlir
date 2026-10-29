//===- BTFToLLVMDI.cpp - lower BTF globals and debug information -------------===//
//
// .maps vars replace placeholders with pointer-field structs and dbg_exprs.
// .ebpf_records vars are null pointers to const record structs; license vars
// are initialized char arrays. Functions receive DISubprogram with retained
// argument DILocalVariables. Append globals in maps/witness/license order;
// ObjectEmitter moves license after requirements. Remove @records/@objects
// scopes but retain @kernel for the CO-RE bridge.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/BTF/Transforms/Passes.h"

#include "mlir/Dialect/LLVMIR/LLVMAttrs.h"
#include "mlir/IR/Builders.h"
#include "llvm/BinaryFormat/Dwarf.h"

#include <functional>
#include <set>

namespace mlir {
namespace btf {
#define GEN_PASS_DEF_CONVERTBTFTOLLVMDI
#include "bpf-mlir/Dialect/BTF/Transforms/Passes.h.inc"
} // namespace btf
} // namespace mlir

using namespace mlir;
using namespace mlir::btf;
namespace dw = llvm::dwarf;

namespace {

struct DIBuild {
  MLIRContext *ctx;
  ModuleOp module;
  LLVM::DIFileAttr file;
  LLVM::DICompileUnitAttr cu;
  bool failed = false;

  DIBuild(MLIRContext *c, ModuleOp m) : ctx(c), module(m) {
    file = LLVM::DIFileAttr::get(ctx, "ebpf-schema", ".");
    cu = LLVM::DICompileUnitAttr::get(DistinctAttr::create(UnitAttr::get(ctx)),
                                      dw::DW_LANG_C99, file,
                                      StringAttr::get(ctx, "ebpf"),
                                      /*isOptimized=*/true,
                                      LLVM::DIEmissionKind::Full);
  }

  LLVM::DITypeAttr derived(unsigned tag, StringAttr name, LLVM::DIFileAttr f,
                           LLVM::DITypeAttr base, uint64_t size, uint64_t offset) {
    return LLVM::DIDerivedTypeAttr::get(ctx, tag, name, f, 0, nullptr, base, size, 0,
                                        offset, std::nullopt, LLVM::DIFlags::Zero,
                                        nullptr);
  }
  LLVM::DITypeAttr composite(unsigned tag, StringAttr name, LLVM::DIFileAttr f,
                             LLVM::DITypeAttr base, uint64_t size, uint64_t align,
                             ArrayRef<LLVM::DINodeAttr> elements) {
    return LLVM::DICompositeTypeAttr::get(ctx, tag, name, f, 0, nullptr, base,
                                          LLVM::DIFlags::Zero, size, align, nullptr,
                                          nullptr, nullptr, nullptr, nullptr, nullptr,
                                          elements);
  }
  LLVM::DINodeAttr member(MemberAttr m) {
    return cast<LLVM::DINodeAttr>(derived(dw::DW_TAG_member,
                                          StringAttr::get(ctx, m.getName()), file,
                                          type(m.getType()), m.getSizeBits(),
                                          m.getOffsetBits()));
  }

  // BTF types to debug information types.
  LLVM::DITypeAttr type(Attribute t) {
    if (auto i = dyn_cast<IntAttr>(t)) {
      unsigned enc = i.getEncoding() == "signed"     ? dw::DW_ATE_signed
                     : i.getEncoding() == "unsigned" ? dw::DW_ATE_unsigned
                                                     : dw::DW_ATE_signed_char;
      return LLVM::DIBasicTypeAttr::get(ctx, dw::DW_TAG_base_type, i.getName(),
                                        i.getBits(), enc);
    }
    if (auto p = dyn_cast<PtrAttr>(t)) {
      // LLVM represents PTR -> TYPE_TAG -> T with btf_type_tag pointer annotations,
      // unavailable on MLIR DIDerivedType. Encode a named marker pointer;
      // ObjectEmitter replaces it after translation with an unnamed annotated
      // pointer and explicitly rejects leftover markers.
      if (auto tt = dyn_cast<TypeTagAttr>(p.getPointee()))
        return derived(dw::DW_TAG_pointer_type, StringAttr::get(ctx, (kTypeTagMarkerPrefix + tt.getTag()).str()), nullptr,
                       type(tt.getBase()), 64, 0);
      // void* has no pointee (BTF PTR to type ID zero).
      LLVM::DITypeAttr base = isa<VoidAttr>(p.getPointee()) ? LLVM::DITypeAttr() : type(p.getPointee());
      return derived(dw::DW_TAG_pointer_type, nullptr, nullptr, base, 64, 0);
    }
    if (auto fp = dyn_cast<FuncProtoAttr>(t)) {
      // FUNC_PROTO uses DISubroutineType types[0] for return; null means void.
      SmallVector<LLVM::DITypeAttr> tys{isa<VoidAttr>(fp.getResult()) ? LLVM::DITypeAttr(LLVM::DINullTypeAttr::get(ctx))
                                                                     : type(fp.getResult())};
      for (Attribute a : fp.getParams())
        tys.push_back(type(a));
      return LLVM::DISubroutineTypeAttr::get(ctx, tys);
    }
    if (auto c = dyn_cast<ConstAttr>(t))
      return derived(dw::DW_TAG_const_type, nullptr, nullptr, type(c.getBase()), 0, 0);
    if (auto a = dyn_cast<ArrayOfAttr>(t)) {
      auto sz = sizeInBits(a, module);
      auto i64 = IntegerType::get(ctx, 64);
      auto sub = LLVM::DISubrangeAttr::get(ctx, IntegerAttr::get(i64, a.getCount()),
                                           IntegerAttr::get(i64, 0), nullptr, nullptr);
      return composite(dw::DW_TAG_array_type, nullptr, nullptr, type(a.getElement()),
                       sz ? *sz : 0, 0, {sub});
    }
    if (auto s = dyn_cast<AnonStructAttr>(t)) {
      SmallVector<LLVM::DINodeAttr> els;
      for (MemberAttr m : s.getMembers())
        els.push_back(member(m));
      return composite(dw::DW_TAG_structure_type, nullptr, file, nullptr, s.getSizeBits(),
                       s.getAlignBits(), els);
    }
    if (auto r = dyn_cast<RefAttr>(t)) {
      auto st = dyn_cast_or_null<StructOp>(SymbolTable::lookupSymbolIn(module, r.getTarget()));
      if (!st) {
        module.emitError() << "unresolved btf reference " << r.getTarget();
        failed = true;
        return LLVM::DINullTypeAttr::get(ctx);
      }
      return named(st);
    }
    module.emitError() << "not a btf type: " << t;
    failed = true;
    return LLVM::DINullTypeAttr::get(ctx);
  }
  LLVM::DITypeAttr named(StructOp st) {
    SmallVector<LLVM::DINodeAttr> els;
    for (Attribute a : st.getMembers())
      els.push_back(member(cast<MemberAttr>(a)));
    return composite(dw::DW_TAG_structure_type, StringAttr::get(ctx, st.getSymName()), file,
                     nullptr, st.getSizeBits(), st.getAlignBits(), els);
  }

  LLVM::DIGlobalVariableExpressionAttr globalExpr(StringRef name, LLVM::DITypeAttr t) {
    auto n = StringAttr::get(ctx, name);
    auto v = LLVM::DIGlobalVariableAttr::get(ctx, cu, n, n, file, 0, t,
                                             /*isLocalToUnit=*/false, /*isDefined=*/true, 0);
    return LLVM::DIGlobalVariableExpressionAttr::get(ctx, v, LLVM::DIExpressionAttr::get(ctx));
  }
};

// Innermost FileLineColLoc: first in FusedLoc, child of NameLoc, caller of CallSiteLoc.
std::optional<FileLineColLoc> innermostFileLoc(Location l) {
  if (auto f = dyn_cast<FileLineColLoc>(l))
    return f;
  if (auto fu = dyn_cast<FusedLoc>(l)) {
    for (Location x : fu.getLocations())
      if (std::optional<FileLineColLoc> r = innermostFileLoc(x))
        return r;
    return std::nullopt;
  }
  if (auto n = dyn_cast<NameLoc>(l))
    return innermostFileLoc(n.getChildLoc());
  if (auto c = dyn_cast<CallSiteLoc>(l))
    return innermostFileLoc(c.getCaller());
  return std::nullopt;
}

// ELF file names must be relative without '..', avoiding build-path-dependent output.
bool reproducibleFileName(StringRef name) {
  if (name.empty() || name.starts_with("/"))
    return false;
  SmallVector<StringRef> parts;
  name.split(parts, '/');
  for (StringRef p : parts)
    if (p == "..")
      return false;
  return true;
}

// BTF line_col has 22 line bits and 10 column bits. LLVM 23 packs unchecked:
// column 1024 increments the line; line 2^22 wraps to zero. The 2^20 line cap
// stays below the BTF maximum and bounds synthetic source text to about 1 MB.
constexpr unsigned kMaxLineInfoLine = 1u << 20;
constexpr unsigned kMaxLineInfoColumn = (1u << 10) - 1;

struct ConvertBTFToLLVMDIPass
    : public mlir::btf::impl::ConvertBTFToLLVMDIBase<ConvertBTFToLLVMDIPass> {
  using ConvertBTFToLLVMDIBase::ConvertBTFToLLVMDIBase;
  bool badLoc = false;
  // Parser module location identifies the compile-input file. A module without
// a file has only explicit locations.
  std::optional<StringAttr> inputFile;

  void runOnOperation() override {
    ModuleOp module = getOperation();
    MLIRContext *ctx = &getContext();
    if (std::optional<FileLineColLoc> ml = innermostFileLoc(module.getLoc()))
      inputFile = ml->getFilename();
    DIBuild di(ctx, module);
    OpBuilder b(ctx);
    auto ptrTy = LLVM::LLVMPointerType::get(ctx);
    Location unknown = UnknownLoc::get(ctx);

    SmallVector<VarOp> maps, witnesses, others;
    SmallVector<FuncOp> funcs;
    ScopeOp objects;
    for (auto sc : module.getOps<ScopeOp>())
      if (sc.getSymName() == "objects")
        objects = sc;
    if (!objects) {
      module.emitError() << "no btf.scope @objects (run ebpf-build-btf first)";
      return signalPassFailure();
    }
    for (Operation &op : objects.getBody().front()) {
      if (auto v = dyn_cast<VarOp>(op))
        (v.getSection() == ".maps" ? maps : v.getSection() == ".ebpf_records" ? witnesses
                                                                             : others)
            .push_back(v);
      else if (auto f = dyn_cast<FuncOp>(op))
        funcs.push_back(f);
    }

    // Append globals before BTF ops in maps/witness/license order.
    Operation *firstBTF = nullptr;
    for (Operation &op : *module.getBody())
      if (isa<BTFDialect>(op.getDialect())) {
        firstBTF = &op;
        break;
      }
    auto place = [&]() {
      if (firstBTF)
        b.setInsertionPoint(firstBTF);
      else
        b.setInsertionPointToEnd(module.getBody());
    };
    auto zeroInit = [&](LLVM::GlobalOp g, Type t) {
      Block *blk = b.createBlock(&g.getInitializerRegion());
      b.setInsertionPointToStart(blk);
      Value z = LLVM::ZeroOp::create(b, unknown, t);
      LLVM::ReturnOp::create(b, unknown, z);
    };

    for (VarOp v : maps) {
      auto anon = dyn_cast<AnonStructAttr>(v.getType());
      if (!anon) {
        v.emitOpError() << "a .maps variable must be an anonymous struct";
        return signalPassFailure();
      }
      // Replace lowering placeholders by name, preserving addressof references.
      if (auto old = module.lookupSymbol<LLVM::GlobalOp>(v.getSymName()))
        old.erase();
      SmallVector<Type> fields(anon.getMembers().size(), ptrTy);
      // Map-in-map values is a zero-element pointer array, matching clang's
      // flexible-array member and zero contribution to symbol size.
      for (auto [i, m] : llvm::enumerate(anon.getMembers()))
        if (auto arr = dyn_cast<ArrayOfAttr>(m.getType()))
          fields[i] = LLVM::LLVMArrayType::get(ptrTy, arr.getCount());
      auto st = LLVM::LLVMStructType::getLiteral(ctx, fields);
      place();
      auto g = LLVM::GlobalOp::create(b, unknown, st, /*isConstant=*/false,
                                      LLVM::Linkage::External, v.getSymName(), Attribute(),
                                      /*alignment=*/8, 0, /*dsoLocal=*/true, false,
                                      SymbolRefAttr(), {}, {di.globalExpr(v.getSymName(), di.type(anon))});
      g.setSection(StringRef(".maps"));
      zeroInit(g, st);
    }
    for (VarOp v : witnesses) {
      place();
      auto g = LLVM::GlobalOp::create(b, unknown, ptrTy, /*isConstant=*/true,
                                      LLVM::Linkage::External, v.getSymName(), Attribute(),
                                      8, 0, true, false, SymbolRefAttr(), {},
                                      {di.globalExpr(v.getSymName(), di.type(v.getType()))});
      g.setSection(StringRef(".ebpf_records"));
      zeroInit(g, ptrTy);
    }
    for (VarOp v : others) {
      // Replace integer .rodata/.bss placeholders with zero-initialized typed
      // globals and DI for BTF VAR/DATASEC. Even .rodata is not isConstant:
      // codegen must not assume initial values, and reads are volatile.
      if (v.getSection() == ".rodata" || v.getSection() == ".bss") {
        auto it = dyn_cast<IntAttr>(v.getType());
        auto old = module.lookupSymbol<LLVM::GlobalOp>(v.getSymName());
        if (!it || !old || !old->hasAttr("ebpf.global")) {
          v.emitOpError() << "a " << v.getSection() << " variable must be an integer with a lowering placeholder";
          return signalPassFailure();
        }
        old.erase();
        Type ty = IntegerType::get(ctx, it.getBits());
        place();
        auto g = LLVM::GlobalOp::create(b, unknown, ty, /*isConstant=*/false, LLVM::Linkage::External, v.getSymName(),
                                        Attribute(), /*alignment=*/it.getBits() / 8, 0, /*dsoLocal=*/true, false,
                                        SymbolRefAttr(), {}, {di.globalExpr(v.getSymName(), di.type(it))});
        g.setSection(v.getSection());
        zeroInit(g, ty);
        continue;
      }
      // struct_ops globals use local structs in .struct_ops.link. Program addresses
      // become R_BPF_64_ABS64 relocations identifying each member's program.
      // Optional data follows function pointers as NUL-padded char arrays,
      // such as tcp_congestion_ops name[16].
      if (v.getSection() == ".struct_ops.link") {
        auto ref = dyn_cast<RefAttr>(v.getType());
        auto st = ref ? dyn_cast_or_null<StructOp>(SymbolTable::lookupSymbolIn(module, ref.getTarget())) : StructOp();
        auto progs = v->getAttrOfType<ArrayAttr>("btf.struct_ops_programs");
        auto data = v->getAttrOfType<ArrayAttr>("btf.struct_ops_data");
        SmallVector<uint64_t> dataBytes;
        bool ok = st && progs && data && st.getMembers().size() == progs.size() + data.size();
        for (size_t i = 0; ok && i < data.size(); ++i) {
          auto m = dyn_cast<MemberAttr>(st.getMembers()[progs.size() + i]);
          auto arr = m ? dyn_cast<ArrayOfAttr>(m.getType()) : ArrayOfAttr();
          auto s = dyn_cast<StringAttr>(data[i]);
          if (!arr || !s || s.getValue().size() >= arr.getCount()) {
            ok = false;
            break;
          }
          dataBytes.push_back(arr.getCount());
        }
        if (!ok) {
          v.emitOpError() << "a .struct_ops.link variable must be a struct of function pointers then char-array data members "
                             "with btf.struct_ops_programs / btf.struct_ops_data";
          return signalPassFailure();
        }
        auto i8 = IntegerType::get(ctx, 8);
        SmallVector<Type> fields(progs.size(), ptrTy);
        for (uint64_t n : dataBytes)
          fields.push_back(LLVM::LLVMArrayType::get(i8, n));
        auto sty = LLVM::LLVMStructType::getLiteral(ctx, fields);
        place();
        auto g = LLVM::GlobalOp::create(b, unknown, sty, /*isConstant=*/false, LLVM::Linkage::External, v.getSymName(), Attribute(),
                                        /*alignment=*/8, 0, /*dsoLocal=*/true, false, SymbolRefAttr(), {},
                                        {di.globalExpr(v.getSymName(), di.type(ref))});
        g.setSection(StringRef(".struct_ops.link"));
        Block *blk = b.createBlock(&g.getInitializerRegion());
        b.setInsertionPointToStart(blk);
        Value agg = LLVM::UndefOp::create(b, unknown, sty);
        for (auto [i, a] : llvm::enumerate(progs)) {
          Value addr = LLVM::AddressOfOp::create(b, unknown, ptrTy, cast<FlatSymbolRefAttr>(a).getValue());
          agg = LLVM::InsertValueOp::create(b, unknown, agg, addr, ArrayRef<int64_t>{static_cast<int64_t>(i)});
        }
        for (auto [i, n] : llvm::enumerate(dataBytes)) {
          std::string bytes = cast<StringAttr>(data[i]).getValue().str();
          bytes.resize(n, '\0');
          Value dv = LLVM::ConstantOp::create(b, unknown, LLVM::LLVMArrayType::get(i8, n), b.getStringAttr(bytes));
          agg = LLVM::InsertValueOp::create(b, unknown, agg, dv, ArrayRef<int64_t>{static_cast<int64_t>(progs.size() + i)});
        }
        LLVM::ReturnOp::create(b, unknown, agg);
        continue;
      }
      auto init = v->getAttrOfType<StringAttr>("btf.string_init");
      auto arr = dyn_cast<ArrayOfAttr>(v.getType());
      if (!init || !arr) {
        v.emitOpError() << "only the license (a char array with btf.string_init) is supported "
                           "outside .maps / .ebpf_records";
        return signalPassFailure();
      }
      std::string bytes = init.getValue().str();
      bytes.push_back('\0');
      auto ty = LLVM::LLVMArrayType::get(IntegerType::get(ctx, 8), bytes.size());
      place();
      auto g = LLVM::GlobalOp::create(b, unknown, ty, /*isConstant=*/false,
                                      LLVM::Linkage::External, v.getSymName(),
                                      b.getStringAttr(bytes), /*alignment=*/1, 0, true, false,
                                      SymbolRefAttr(), {},
                                      {di.globalExpr(v.getSymName(), di.type(arr))});
      g.setSection(v.getSection());
    }
    // Recursive DISubprogram: argument DILocalVariable scopes point back to it.
    for (FuncOp f : funcs) {
      auto fn = module.lookupSymbol<LLVM::LLVMFuncOp>(f.getSymName());
      if (!fn) {
        f.emitOpError() << "no llvm.func @" << f.getSymName();
        return signalPassFailure();
      }
      SmallVector<LLVM::DITypeAttr> tys{di.type(f.getResult())};
      for (Attribute a : f.getParams())
        tys.push_back(di.type(cast<ParamAttr>(a).getType()));
      auto sty = LLVM::DISubroutineTypeAttr::get(ctx, tys);
      auto recId = DistinctAttr::create(UnitAttr::get(ctx));
      auto self = cast<LLVM::DIScopeAttr>(LLVM::DISubprogramAttr::getRecSelf(recId));
      SmallVector<Attribute> retained;
      for (auto [i, a] : llvm::enumerate(f.getParams())) {
        auto p = cast<ParamAttr>(a);
        retained.push_back(LLVM::DILocalVariableAttr::get(
            ctx, self, StringAttr::get(ctx, p.getName()), di.file, 0, i + 1, 0,
            tys[i + 1], LLVM::DIFlags::Zero));
      }
      auto name = StringAttr::get(ctx, f.getSymName());
      auto sp = LLVM::DISubprogramAttr::get(
          ctx, recId, /*isRecSelf=*/false, DistinctAttr::create(UnitAttr::get(ctx)), di.cu,
          nullptr, name, name, di.file, 0, 0,
          // LocalToUnit makes LLVM emit static BTF FUNC linkage for subprograms.
          f.getLinkage() == "static"
              ? LLVM::DISubprogramFlags::Definition | LLVM::DISubprogramFlags::LocalToUnit
              : LLVM::DISubprogramFlags::Definition,
          sty,
          retained, {});
      fn->setLoc(FusedLoc::get(ctx, {FileLineColLoc::get(ctx, "ebpf-schema", 0, 0)}, sp));
      // MLIR 23 DILocalVariableAttr has no annotations. Carry argument decl tags
      // on llvm.func for ObjectEmitter to attach as btf_decl_tag after translation.
      {
        bool any = false;
        SmallVector<Attribute> perArg;
        for (Attribute a : f.getParams()) {
          ArrayAttr t = cast<ParamAttr>(a).getTags();
          any |= t && !t.empty();
          perArg.push_back(t ? t : ArrayAttr::get(ctx, {}));
        }
        if (any)
          fn->setAttr("btf.arg_tags", ArrayAttr::get(ctx, perArg));
      }
      // Remove implicit operation locations to avoid adding per-instruction
      // BTF.ext line_info. Calls between DISubprogram-bearing BPF functions
      // still need debug locations for LLVM verification: line zero satisfies
      // that requirement without creating line_info. Leave helper calls
      // unlocated to preserve their debug information.
      Location fnLoc = fn->getLoc();
      // Explicit frontend locations become line_info through per-file
      // DILexicalBlockFile scopes with empty directory names.
      LLVM::DISubprogramAttr spAttr;
      if (auto fl = dyn_cast<FusedLoc>(fnLoc))
        spAttr = dyn_cast_or_null<LLVM::DISubprogramAttr>(fl.getMetadata());
      auto explicitLoc = [&](Operation *op) -> std::optional<Location> {
        if (!lineInfo || !spAttr)
          return std::nullopt;
        std::optional<FileLineColLoc> fl = innermostFileLoc(op->getLoc());
        if (!fl || (inputFile && fl->getFilename() == *inputFile))
          return std::nullopt;
        StringRef name = fl->getFilename().getValue();
        if (!reproducibleFileName(name)) {
          op->emitError() << "the loc file name \"" << name
                          << "\" is an absolute path or contains '..'; a frontend must give a relative name "
                             "(the name is written into the ELF as it is — reproducibility); to compile without line_info, "
                             "use ebpf-compile --line-info=off (pass option line-info=false)";
          badLoc = true;
          return std::nullopt;
        }
        if (fl->getLine() > kMaxLineInfoLine || fl->getColumn() > kMaxLineInfoColumn) {
          op->emitError() << "the loc " << name << ":" << fl->getLine() << ":" << fl->getColumn()
                          << " is out of the BTF line_info range (line <= " << kMaxLineInfoLine
                          << ", column <= " << kMaxLineInfoColumn
                          << " — LLVM would silently corrupt the line); to compile without line_info, "
                             "use ebpf-compile --line-info=off (pass option line-info=false)";
          badLoc = true;
          return std::nullopt;
        }
        auto lbf = LLVM::DILexicalBlockFileAttr::get(ctx, spAttr, LLVM::DIFileAttr::get(ctx, name, ""), 0);
        return FusedLoc::get(ctx, {*fl}, lbf);
      };
      auto isSubprogramCall = [&](Operation *op) {
        auto call = dyn_cast<LLVM::CallOp>(op);
        if (!call || !call.getCallee())
          return false;
        auto callee = module.lookupSymbol<LLVM::LLVMFuncOp>(*call.getCallee());
        return callee && !callee.isExternal();
      };
      fn.walk([&](Operation *op) {
        if (op == fn.getOperation())
          return;
        if (std::optional<Location> l = explicitLoc(op))
          op->setLoc(*l);
        else
          op->setLoc(isSubprogramCall(op) ? fnLoc : unknown);
      });
      for (Block &blk : fn.getBody())
        for (BlockArgument arg : blk.getArguments())
          arg.setLoc(unknown);
    }
    if (di.failed || badLoc)
      return signalPassFailure();

    // Record emitted BTF features (kinds/global linkage) for ObjectEmitter's
    // format-5 btf requirements. BPF emits INT array indices and all named/local
    // structs referenced by record witnesses or CO-RE reads.
    {
      std::set<std::string> feats;
      std::function<void(Attribute)> visit = [&](Attribute t) {
        if (isa<IntAttr>(t))
          feats.insert("int");
        else if (auto p = dyn_cast<PtrAttr>(t)) {
          feats.insert("ptr");
          visit(p.getPointee());
        } else if (auto c = dyn_cast<ConstAttr>(t)) {
          feats.insert("const");
          visit(c.getBase());
        } else if (auto tt = dyn_cast<TypeTagAttr>(t)) { // Map-value kptr requires format 13.
          feats.insert("type_tag");
          visit(tt.getBase());
        } else if (auto a = dyn_cast<ArrayOfAttr>(t)) {
          feats.insert("array");
          feats.insert("int"); // __ARRAY_SIZE_TYPE__ array-index type.
          visit(a.getElement());
        } else if (auto s = dyn_cast<AnonStructAttr>(t)) {
          feats.insert("struct");
          for (MemberAttr m : s.getMembers())
            visit(m.getType());
        } else if (isa<RefAttr>(t))
          feats.insert("struct");
        else if (auto fp = dyn_cast<FuncProtoAttr>(t)) { // Function-pointer member.
          feats.insert("func_proto");
          visit(fp.getResult());
          for (Attribute a : fp.getParams())
            visit(a);
        }
      };
      module.walk([&](Operation *op) {
        if (auto st = dyn_cast<StructOp>(op)) {
          feats.insert("struct");
          for (Attribute a : st.getMembers())
            visit(cast<MemberAttr>(a).getType());
        } else if (auto v = dyn_cast<VarOp>(op)) {
          feats.insert("var");
          feats.insert("datasec");
          visit(v.getType());
        } else if (auto f = dyn_cast<FuncOp>(op)) {
          feats.insert("func");
          feats.insert("func_proto");
          if (f.getLinkage() == "global") // Static subprograms do not require global linkage.
            feats.insert("func_global");
          for (Attribute a : f.getParams())
            if (ArrayAttr t = cast<ParamAttr>(a).getTags(); t && !t.empty())
              feats.insert("decl_tag"); // Argument BTF_KIND_DECL_TAG.
          visit(f.getResult());
          for (Attribute a : f.getParams())
            visit(cast<ParamAttr>(a).getType());
        }
      });
      SmallVector<Attribute> fs;
      for (const std::string &f : feats)
        fs.push_back(StringAttr::get(ctx, f));
      module->setAttr("ebpf.btf_features", ArrayAttr::get(ctx, fs));
    }

    // Remove BTF operations except @kernel, retained for the bridge.
    SmallVector<Operation *> dead;
    for (Operation &op : *module.getBody())
      if (auto s = dyn_cast<ScopeOp>(op); s && s.getSymName() != "kernel")
        dead.push_back(&op);
    for (Operation *op : dead)
      op->erase();
    // Mark BTF-built modules for ObjectEmitter validation; removed before LLVM translation.
    module->setAttr("ebpf.btf_built", UnitAttr::get(ctx));
  }
};

} // namespace
