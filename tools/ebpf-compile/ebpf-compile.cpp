// Compile .mlir plus canonical schema into BTF-enabled BPF ELF:
//   ebpf-compile input.mlir --schema schema.json -o program.bpf.o
// Schema and ownership checks run by default before staged lowering and emission.
#include "bpf-mlir/Dialect/BTF/Transforms/Passes.h"
#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"
#include "bpf-mlir/Version.inc"
#include "bpf-mlir/Dialect/EBPF/Transforms/ArithLegality.h"
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h"
#include "bpf-mlir/Target/EBPF/ObjectEmitter.h"
#include "bpf-mlir/Target/EBPF/Schema.h"

#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/SHA256.h"

#include "mlir/Conversion/ArithToLLVM/ArithToLLVM.h"
#include "mlir/Conversion/ReconcileUnrealizedCasts/ReconcileUnrealizedCasts.h"
#include "mlir/Dialect/Arith/IR/Arith.h"
#include "mlir/Dialect/ControlFlow/IR/ControlFlow.h"
#include "mlir/Dialect/Func/IR/FuncOps.h"
#include "mlir/Dialect/LLVMIR/LLVMDialect.h"
#include "mlir/Dialect/SCF/IR/SCF.h"
#include "mlir/IR/MLIRContext.h"
#include "mlir/IR/OwningOpRef.h"
#include "mlir/IR/Verifier.h"
#include "mlir/Parser/Parser.h"
#include "mlir/Pass/PassManager.h"

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include <cstdlib>
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

static cl::opt<std::string> inputFile(cl::Positional, cl::desc("<input .mlir>"),
                                      cl::Required);
static cl::opt<std::string> schemaFile("schema",
                                       cl::desc("canonical schema (JSON)"),
                                       cl::Required);
static cl::opt<std::string> outputFile("o", cl::desc("output .bpf.o"),
                                       cl::Required);
// Optionally retain debug-enabled LLVM IR before codegen for developer comparisons.
static cl::opt<std::string> dumpLLVMIR("dump-llvm-ir",
                                       cl::desc("write LLVM IR before codegen (development)"),
                                       cl::value_desc("file"));
// Optional present-region cost TSV; does not change the ELF.
static cl::opt<std::string> reportPresentCost("report-present-cost",
                                              cl::desc("write present-region instruction estimates as TSV (diagnostic: program, reservation order, estimate, block count)"),
                                              cl::value_desc("file"));
// Outline reservations above this cost; threshold 1 selects all in tests.
static cl::opt<uint64_t> presentOutlineThreshold("present-outline-threshold", cl::init(23552),
                                                 cl::desc("outline reservation present regions whose instruction estimate exceeds this threshold into internal functions"));
// C3 conversion is enabled by default; =false selects the older conversion.
// Debug auto preserves explicit frontend op locations in BTF line_info/DWARF;
// off removes them all.
// testing only (hidden) — skip the BPF CO-RE relocation passes so the
// emitter's leftover-intrinsic check must stop the compile.
static cl::opt<bool> testSkipCoreRelocationPass("test-skip-core-relocation-pass", cl::init(false), cl::Hidden,
                                                cl::desc("testing only: skip the CO-RE relocation passes (the compile must fail)"));
static cl::opt<std::string> lineInfoOpt("line-info", cl::init("auto"),
                                        cl::desc("auto (frontend-explicit op locations in line_info) | off (remove all)"));
static cl::opt<bool> tuneSinkWindowLoads("tune-sink-window-loads", cl::init(true),
                                         cl::desc("sink packet.window_load immediately before its first use"));
static cl::opt<bool> tuneSkipFullCoverMemset("tune-skip-full-cover-memset", cl::init(true),
                                             cl::desc("omit memset when record.make covers every byte"));
static cl::opt<bool> tuneStoreRecordDirect("tune-store-record-direct", cl::init(false),
                                           cl::desc("store record.make fields directly into the reservation when store_record is its only use"));
static cl::opt<bool> tuneStoreRecordMerge("tune-store-record-merge", cl::init(true),
                                          cl::desc("merge adjacent constant fields into wider stores, including direct record stores (enabled by default)"));
static cl::opt<bool> tuneShareKeySlot("tune-share-key-slot", cl::init(false),
                                      cl::desc("share one scalar map-key spill slot per function and integer width"));
static cl::opt<bool> tuneSpillLifetime("tune-spill-lifetime", cl::init(true),
                                       cl::desc("mark scalar map key/value spill slots with lifetimes to allow slot reuse (enabled by default; false restores v0.15.0 output)"));
static cl::opt<bool> tuneWindowLoadNested("tune-window-load-nested", cl::init(true),
                                          cl::desc("replace constant-offset packet.load dominated by in_range with window_load (enabled by default)"));
// Warn about ref.index forms rejected by some non-root loaders, without
// changing the ELF or successful exit status.
static cl::opt<bool> warnNonrootIndex("warn-nonroot-index", cl::init(true),
                                      cl::desc("warn about ref.index index shapes that non-root loaders may reject (mixed constant/unknown values and non-unrolled loop values)"));
// opt-in (default off) warning about non-atomic read-modify-writes of
// shared map values and .bss globals within one function (rules).
static cl::opt<bool> warnSharedRMW("warn-shared-rmw", cl::init(false),
                                   cl::desc("warn when a value loaded from a shared (not per-CPU) map value or .bss global reaches a write of the same location in the same function (non-atomic read-modify-write; default off)"));
static cl::opt<bool> tuneThreadI1Join("tune-thread-i1-join", cl::init(false),
                                      cl::desc("thread constant i1 joins per arm at the end of stage 2"));
static cl::opt<bool> tuneBackedgeSpill("tune-backedge-spill", cl::init(true),
                                       cl::desc("S (enabled by default; false restores v1.12.0 output): volatile-store the IV into a dedicated stack slot on each back-edge loop iteration "
                                                "(speculative-path barrier for loaders without CAP_PERFMON on 7.1.8 — avoids the bounded loop's 8193 jumps)"));
static cl::opt<bool> tuneBackedgeRotate("tune-backedge-rotate", cl::init(false),
                                        cl::desc("R (disabled by default): rotate back-edge loops (entry only guards the bound 0 < n; "
                                                 "the latch tests i + 1 -> i < n -> i < N before the body — one fewer speculative push on the constant-trip main path)"));
static cl::opt<bool> tuneReuseDominatedLookup("tune-reuse-dominated-lookup", cl::init(true),
                                              cl::desc("(enabled by default; false restores the previous output): at stage 2, reuse a dominating present "
                                                       "lookup of the same array map and key SSA values instead of a repeated lookup and its NULL branch"));
static cl::opt<bool> tuneAlignedPacketLoad("tune-aligned-packet-load", cl::init(true),
                                           cl::desc("read a packet of width W at a constant offset off with (2 + off) mod W = 0 as one wide load "
                                                    "(accepted by the strict-alignment verifier, NET_IP_ALIGN = 2); other reads stay bytewise (enabled by default; false restores v1.19-style bytewise reads)"));
static cl::opt<bool> tuneMaskCheckedIndex("tune-mask-checked-index", cl::init(true),
                                          cl::desc("barrier, mask and recheck each ref.index index on the true edge of its range check (enabled by default)"));
// Warn when a masked ref.index range can exceed the record; do not alter ELF
// or turn the warning into a compilation failure.
static cl::opt<bool> warnIndexMaskFit("warn-index-mask-fit", cl::init(true),
                                      cl::desc("warn if an index mask can extend outside the record (diagnostic only; does not change output)"));
static cl::opt<bool> tuneMaskSkipConstantIndex("tune-mask-skip-constant-index", cl::init(true),
                                               cl::desc("omit the mask and recheck for dimensions with a direct constant index (such as an unrolled IV), enabled by default"));
static cl::opt<std::string> targetProfile("target-profile", cl::init(""),
                                          cl::desc("target profile (kernel/profiles/*.tsv — named facts); check program-kind legality at compile time; empty defers target checks to load"));
static cl::opt<std::string> licenseOpt("license", cl::init("GPL"),
                                       cl::desc("license section contents"));

// Accept only high-level input: downstream dialects could bypass stage checks
// and requirements derivation.
static mlir::LogicalResult verifyHighLevelBody(mlir::Operation *owner) {
  for (mlir::Region &region : owner->getRegions())
    for (mlir::Block &block : region)
      for (mlir::Operation &op : block) {
        llvm::StringRef dialect = op.getName().getDialectNamespace();
        if (dialect != "ebpf" && dialect != "arith" && dialect != "scf") {
          op.emitOpError() << "is not a supported ebpf-compile input operation; "
                             "expected ebpf, arith, or scf dialect";
          return mlir::failure();
        }
        if (mlir::failed(verifyHighLevelBody(&op)))
          return mlir::failure();
      }
  return mlir::success();
}

// Only ebpf-expand-regions may create Stage2InternalOp operations, whose set
// is defined in td. Reject all of them before op verification: handwritten
// packet windows or tail-call regions could bypass high-level input checks.
static mlir::LogicalResult rejectStage2Ops(mlir::ModuleOp module) {
  bool bad = false;
  module.walk<mlir::WalkOrder::PreOrder>([&](mlir::ebpf::Stage2InternalOp op) {
    bad = true;
    op->emitOpError() << "is a stage ② op produced by ebpf-expand-regions, not an ebpf-compile input; write "
                      << op.getStage1Form() << " instead";
  });
  return mlir::failure(bad);
}

static mlir::LogicalResult verifyHighLevelInput(mlir::ModuleOp module) {
  for (mlir::Operation &op : module.getBody()->getOperations()) {
    if (!mlir::isa<mlir::ebpf::ProgramOp, mlir::ebpf::SubprogramOp,
                   mlir::ebpf::TimerCallbackOp, mlir::ebpf::UserRingbufCallbackOp>(op)) { // user_ringbuf callback.
      op.emitOpError() << "is not a supported top-level ebpf-compile input; "
                         "expected ebpf.program, ebpf.func, ebpf.timer.callback or "
                         "ebpf.user_ringbuf.callback";
      return mlir::failure();
    }
    if (mlir::failed(verifyHighLevelBody(&op)))
      return mlir::failure();
  }
  return mlir::success();
}

// LLVM BPF report_fatal_error bypasses LLVMContext diagnostics. Large present
// regions can exceed the signed 16-bit branch offset (32767 instructions).
// Save the largest reservation's location/size before lowering, install a
// handler only during emission, delete partial output and exit 1 instead of
// aborting. The fatal handler must not return.
namespace {
struct FatalContext {
  std::string largestLoc;
  uint64_t largestSize = 0;
  std::string outputPath;
};
FatalContext gFatal;

void onLLVMFatal(void *, const char *reason, bool) {
  StringRef why(reason);
  if (why.contains("Branch target out of insn range") && gFatal.largestSize > 0) {
    errs() << gFatal.largestLoc << ": error: 'ebpf.ringbuf.reserve' op the "
           << gFatal.largestSize
           << "-byte event makes a branch in the generated code longer than a "
              "BPF jump can reach (32767 instructions) — LLVM stopped with \""
           << why
           << "\". The work of a reservation is moved to its own function when its "
              "estimated size is over the outline threshold (--present-outline-threshold, "
              "the present-region estimate), but a single branch in the generated code is still too long; make "
              "the work inside one branch smaller or split the event\n";
  } else {
    errs() << "ebpf-compile: error: LLVM stopped the BPF code generation: "
           << why << "\n";
  }
  errs().flush();
  if (!gFatal.outputPath.empty())
    (void)sys::fs::remove(gFatal.outputPath);
  std::_Exit(1);
}
} // namespace

int main(int argc, char **argv) {
  // Standard LLVM signal, stack-trace and shutdown setup.
  InitLLVM init(argc, argv);
  // Embed version/commit from gen-version so callers can match compiler and modules.
  cl::AddExtraVersionPrinter([](raw_ostream &os) {
    os << "bpf-mlir " << BPF_MLIR_DESCRIBE << " (commit " << BPF_MLIR_COMMIT << ")\n";
  });
  cl::ParseCommandLineOptions(argc, argv, "ebpf object compiler\n");

  // Create MLIRContext before any early return, including schema checks.
  // Returning without ever creating one reproduced a cleanup double free;
  // InitLLVM changes the symptom but does not fix it. Creating the context
  // first avoids it.
  mlir::DialectRegistry registry;
  registry.insert<mlir::ebpf::EBPFDialect, mlir::bpfabi::BPFABIDialect,
                  mlir::btf::BTFDialect,
                  mlir::func::FuncDialect,
                  mlir::arith::ArithDialect, mlir::cf::ControlFlowDialect,
                  mlir::scf::SCFDialect, mlir::LLVM::LLVMDialect>();
  mlir::MLIRContext ctx(registry);
  ctx.loadAllAvailableDialects();
  // Keep <loc>: <severity>: <message> formatting and attached notes, including
  // target-unsupported reasons omitted by the default note printer.
  ctx.getDiagEngine().registerHandler([](mlir::Diagnostic &d) {
    auto sev = [](mlir::DiagnosticSeverity k) {
      switch (k) {
      case mlir::DiagnosticSeverity::Error: return "error";
      case mlir::DiagnosticSeverity::Warning: return "warning";
      case mlir::DiagnosticSeverity::Remark: return "remark";
      case mlir::DiagnosticSeverity::Note: return "note";
      }
      return "note";
    };
    errs() << d.getLocation() << ": " << sev(d.getSeverity()) << ": " << d << "\n";
    for (mlir::Diagnostic &n : d.getNotes())
      errs() << n.getLocation() << ": note: " << n << "\n";
    return mlir::success();
  });

  auto schemaBuf = MemoryBuffer::getFile(schemaFile);
  if (!schemaBuf) {
    errs() << "ebpf-compile: cannot read " << schemaFile << ": "
           << schemaBuf.getError().message() << "\n";
    return 1;
  }
  auto schema = ebpf::Schema::parseJSON((*schemaBuf)->getBuffer());
  if (!schema) {
    errs() << "ebpf-compile: invalid schema: "
           << toString(schema.takeError()) << "\n";
    return 1;
  }

  // Delay verification until internal stage-2 input has been rejected by name,
  // so input-contract diagnostics precede operation-verifier errors.
  mlir::ParserConfig parseConfig(&ctx, /*verifyAfterParse=*/false);
  auto module = mlir::parseSourceFile<mlir::ModuleOp>(inputFile, parseConfig);
  if (!module)
    return 1;
  if (mlir::failed(rejectStage2Ops(*module)))
    return 1;
  if (mlir::failed(mlir::verify(*module)))
    return 1;
  if (mlir::failed(verifyHighLevelInput(*module)))
    return 1;
  // Reject arithmetic shapes that can produce LLVM UB/poison unless value
  // ranges prove safety. See docs/arith_contract.md.
  if (mlir::failed(mlir::ebpf::verifyArithLegality(*module)))
    return 1;
  // Save the largest reservation's source location before lowering for fatal diagnostics.
  module->walk([&](mlir::ebpf::RingbufReserveOp r) {
    auto ty = mlir::cast<mlir::ebpf::MaybeReservationType>(r.getResult().getType());
    uint64_t size = 0;
    if (auto rt = mlir::dyn_cast<mlir::ebpf::RecordType>(ty.getRecordType()))
      size = rt.getSize();
    if (size > gFatal.largestSize) {
      gFatal.largestSize = size;
      std::string s;
      llvm::raw_string_ostream os(s);
      r.getLoc().print(os);
      gFatal.largestLoc = s;
    }
  });

  mlir::PassManager pm(&ctx);
  pm.addPass(mlir::ebpf::createEBPFVerifyOwnership());
  // Verify subprogram reachability, non-recursion and call depth.
  pm.addPass(mlir::ebpf::createEBPFVerifyCallGraph());
  // the context-dependent ops of each ebpf.func, per reaching context
  // (kind level; the member and sleepable rules are in ebpf-verify-schema).
  pm.addPass(mlir::ebpf::createEBPFVerifyCallContexts());
  {
    mlir::ebpf::EBPFVerifySchemaOptions o;
    o.schemaPath = schemaFile;
    pm.addPass(mlir::ebpf::createEBPFVerifySchema(o));
  }
  // Build schema-derived @records/@kernel BTF types in the high-level stage
  // and check kptr/kfield against them.
  {
    mlir::btf::EBPFBuildBTFTypesOptions o;
    o.schemaPath = schemaFile;
    pm.addPass(mlir::btf::createEBPFBuildBTFTypes(o));
  }
  pm.addPass(mlir::ebpf::createEBPFVerifyKPtr());
  // Check record types and field accesses against @records declarations.
  pm.addPass(mlir::ebpf::createEBPFVerifyRecords());
  // Nonblocking warnings leave IR unchanged.
  if (warnNonrootIndex)
    pm.addPass(mlir::ebpf::createEBPFWarnNonrootIndex());
  if (warnSharedRMW)
    pm.addPass(mlir::ebpf::createEBPFWarnSharedRMW());
  // Staged high-level-to-LLVM lowering, including each stage's exit checks.
  {
    mlir::ebpf::TuneOptions tune;
    tune.sinkWindowLoads = tuneSinkWindowLoads;
    tune.skipFullCoverMemset = tuneSkipFullCoverMemset;
    tune.storeRecordDirect = tuneStoreRecordDirect;
    tune.storeRecordMerge = tuneStoreRecordMerge;
    tune.shareKeySlot = tuneShareKeySlot;
    tune.spillLifetime = tuneSpillLifetime;
    tune.maskCheckedIndex = tuneMaskCheckedIndex;
    tune.maskSkipConstantIndex = tuneMaskSkipConstantIndex;
    tune.windowLoadNested = tuneWindowLoadNested;
    tune.threadI1Join = tuneThreadI1Join;
    tune.warnIndexMaskFit = warnIndexMaskFit;
    tune.backedgeSpill = tuneBackedgeSpill;
    tune.backedgeRotate = tuneBackedgeRotate;
    tune.alignedPacketLoad = tuneAlignedPacketLoad;
    tune.reuseDominatedLookup = tuneReuseDominatedLookup;
    mlir::ebpf::buildEBPFToLLVMPipeline(pm, tune, targetProfile);
  }
  pm.addPass(mlir::createArithToLLVMConversionPass());
  pm.addPass(mlir::createReconcileUnrealizedCastsPass());
  // Lower schema-derived BTF IR into MLIR debug attributes; ObjectEmitter
  // does not construct these types.
  {
    mlir::btf::EBPFBuildBTFOptions o;
    o.schemaPath = schemaFile;
    o.license = licenseOpt;
    pm.addPass(mlir::btf::createEBPFBuildBTF(o));
  }
  // Check BTF kind, linkage and context rules before emission; violations
  // must stop loudly.
  pm.addPass(mlir::btf::createBTFVerify());
  if (lineInfoOpt != "auto" && lineInfoOpt != "off") {
    errs() << "ebpf-compile: --line-info must be auto or off, got " << lineInfoOpt << "\n";
    return 1;
  }
  {
    mlir::btf::ConvertBTFToLLVMDIOptions o;
    o.lineInfo = lineInfoOpt == "auto";
    pm.addPass(mlir::btf::createConvertBTFToLLVMDI(o));
  }
  if (mlir::failed(pm.run(*module)))
    return 1;

  std::error_code ec;
  ToolOutputFile out(outputFile, ec, sys::fs::OF_None);
  if (ec) {
    errs() << "ebpf-compile: cannot open " << outputFile << ": "
           << ec.message() << "\n";
    return 1;
  }

  ebpf::Diagnostics diags;
  diags.sink = [](StringRef m) { errs() << "ebpf-compile: " << m << "\n"; };
  // Hash exact schema file bytes, independently checked by bindgen against ELF.
  std::string schemaSHA256 = toHex(
      SHA256::hash(arrayRefFromStringRef((*schemaBuf)->getBuffer())),
      /*LowerCase=*/true);
  std::unique_ptr<ToolOutputFile> irOut;
  if (!dumpLLVMIR.empty()) {
    irOut = std::make_unique<ToolOutputFile>(dumpLLVMIR, ec, sys::fs::OF_Text);
    if (ec) {
      errs() << "ebpf-compile: cannot open " << dumpLLVMIR << ": " << ec.message() << "\n";
      return 1;
    }
  }
  std::unique_ptr<ToolOutputFile> costOut;
  if (!reportPresentCost.empty()) {
    costOut = std::make_unique<ToolOutputFile>(reportPresentCost, ec, sys::fs::OF_Text);
    if (ec) {
      errs() << "ebpf-compile: cannot open " << reportPresentCost << ": " << ec.message() << "\n";
      return 1;
    }
    costOut->keep(); // Retain diagnostics even when codegen exits through the fatal handler.
  }
  gFatal.outputPath = outputFile;
  {
    llvm::ScopedFatalErrorHandler fatal(onLLVMFatal, nullptr);
    if (mlir::failed(ebpf::emitObject(*module, *schema, schemaSHA256, out.os(),
                                       diags, licenseOpt,
                                       irOut ? &irOut->os() : nullptr,
                                       costOut ? &costOut->os() : nullptr,
                                       presentOutlineThreshold, testSkipCoreRelocationPass)))
      return 1;
  }
  if (irOut)
    irOut->keep();
  out.keep();
  return 0;
}
