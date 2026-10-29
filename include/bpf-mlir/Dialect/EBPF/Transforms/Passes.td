// ebpf pass declarations.
#ifndef EBPF_TRANSFORMS_PASSES
#define EBPF_TRANSFORMS_PASSES

include "mlir/Pass/PassBase.td"

def EBPFVerifyOwnership : Pass<"ebpf-verify-ownership", "mlir::ModuleOp"> {
  let summary = "Check exactly one submit/discard on every CFG path from reserve";
  let description = [{
    Counting uses alone accepts a submission on only one branch as one use.
    Walk the CFG to reject such path-dependent consumption.
  }];
}

// --convert-ebpf-to-llvm is a pipeline, not one pass:
// ebpf-expand-regions -> ebpf-verify-structured -> convert-ebpf-to-bpfabi
// -> bpfabi-verify -> convert-bpfabi-to-llvm. Exit checks separate the stages.
def EBPFExpandRegions : Pass<"ebpf-expand-regions", "mlir::ModuleOp"> {
  let summary = "Stage 1 to 2: expand ref.check / ringbuf.if_reserved / map.atomic_add null checks into cf branches";
  let description = [{
    Replace region-based checks with explicit branches and ebpf.is_present /
    ebpf.assume_present. The ebpf.program body becomes multi-block.
    Stage-1 programs accept only one block; multi-block stage-1 input is rejected.
  }];
  let dependentDialects = ["::mlir::cf::ControlFlowDialect"];
  let options = [
    Option<"sinkWindowLoads", "sink-window-loads", "bool", /*default=*/"true",
           "sink an in_range-entry packet.window_load immediately before its first use (only across whitelisted ops, without duplication)">,
    Option<"windowLoadNested", "window-load-nested", "bool", /*default=*/"true",
           "after expansion, replace packet.load with constant-foldable offset by window_load in blocks dominated by pkt.check_br in_range">,
    Option<"threadI1Join", "thread-i1-join", "bool", /*default=*/"false",
           "after window-load conversion and sinking, thread constant i1 joins ending in cf.cond_br per arm (no duplication or new phi)">,
    Option<"maskCheckedIndex", "mask-checked-index", "bool", /*default=*/"true",
           "on the ref.index true edge, mask each dimension with elem.mask (barrier and 2^k-1 AND at stage 3), recheck elem.in_range with the same out_of_range on false, and use the masked index for elem.at (constant cost per ref.index)">,
    Option<"maskSkipConstantIndex", "mask-skip-constant-index", "bool", /*default=*/"true",
           "omit the mask and recheck for dimensions whose index is a direct constant, such as an unrolled IV">,
    Option<"backedgeSpill", "backedge-spill", "bool", /*default=*/"true",
           "place ebpf.loop.spill %i at each iteration's start in back-edge loops (N >= 2, not unroll/callback); lower to a volatile store in a dedicated stack slot (speculative-path barrier for loaders without CAP_PERFMON on 7.1.8; false restores v1.12.0 output)">,
    Option<"backedgeRotate", "backedge-rotate", "bool", /*default=*/"false",
           "rotate back-edge loops: entry only guards bound 0 < n and starts at the body; latch tests i + 1 -> i < n -> i < N before returning to the body (one fewer speculative push on the constant-trip main path)">
  ];
}

def EBPFVerifyStructured : Pass<"ebpf-verify-structured", "mlir::ModuleOp"> {
  let summary = "Stage 2 exit check: explicit null branches and linear reservations";
  let description = [{
    (1) assume_present must be in a block reachable only from the true edge of
        is_present on the same value.
    (2) Unchecked values (maybe_ref / maybe_reservation) may flow only to
        is_present / assume_present. Each reservation is checked exactly once.
    (3) Checked references / reservations are used only by permitted ops,
        dominated by assume_present; not carried by block arguments or branch operands.
    (4) An acquired reservation is submitted / discarded exactly once on every
        CFG path after assume_present. After consumption it cannot be used by
        non-consuming ops (store_field, store_record, task.comm, user.read_str).
        This applies the ownership check to region-free form.
    Verdicts are Verified / Rejected / Conditional / Unknown. Any Rejected fails.
  }];
  let options = [
    Option<"report", "report", "bool", /*default=*/"false",
           "print verdict counts as remarks">
  ];
}

def ConvertEBPFToBPFABI : Pass<"convert-ebpf-to-bpfabi", "mlir::ModuleOp"> {
  let summary = "Stage 2 to 3: lower ebpf.program to llvm.func and kernel accesses to bpfabi ops";
  let description = [{
    Helper calls, context reads and verdicts become bpfabi ops with numbers from
    KernelABI.h's UAPI table. Other operations (branches, loads/stores, map
    addressof, stack spills) become LLVM dialect. Program kinds outside the
    compiler's supported capability are rejected explicitly.
  }];
  let dependentDialects = ["::mlir::LLVM::LLVMDialect",
                           "::mlir::bpfabi::BPFABIDialect"];
  let options = [
    Option<"skipFullCoverMemset", "skip-full-cover-memset", "bool", /*default=*/"true",
           "omit memset only when record.make field stores cover every record byte">,
    Option<"storeRecordDirect", "store-record-direct", "bool", /*default=*/"false",
           "if store_record is record.make's only use and covers every byte, store fields directly into the reservation at store_record without a stack record">,
    Option<"storeRecordMerge", "store-record-merge", "bool", /*default=*/"true",
           "merge adjacent constant fields in direct stores into i64/i32/i16 stores when proven by reservation alignment (8) and offset; includes direct record stores">,
    Option<"shareKeySlot", "share-key-slot", "bool", /*default=*/"false",
           "share one scalar map-key stack spill slot per function and integer width">,
    Option<"spillLifetime", "spill-lifetime", "bool", /*default=*/"true",
           "add lifetime.start/end to scalar map key/value spill slots, allowing slot reuse after the helper call (false restores v0.15.0 output)">,
    Option<"warnIndexMaskFit", "warn-index-mask-fit", "bool", /*default=*/"true",
           "warn when a ref.index mask may extend outside the record (diagnostic only; does not change output)">,
    Option<"alignedPacketLoad", "aligned-packet-load", "bool", /*default=*/"true",
           "read packet.load / window_load of width W at a constant packet offset off with (2 + off) mod W = 0 as one wide load (the strict-alignment verifier accepts it); other reads stay bytewise">
  ];
}

def EBPFVerifySchema : Pass<"ebpf-verify-schema", "mlir::ModuleOp"> {
  let summary = "Check program map bindings against the schema";
  let description = [{
    Beyond structural and duplicate checks on `maps [...]`, verify schema map
    existence and kind/key/value equality. Supply the schema through
    `--schema=<path>`: the pass owns the comparison, without embedding the schema
    in the dialect.
  }];
  let options = [
    Option<"schemaPath", "schema", "std::string", /*default=*/"\"\"",
           "canonical schema (JSON) path">
  ];
}

def EBPFVerifyKPtr : Pass<"ebpf-verify-kptr", "mlir::ModuleOp"> {
  let summary = "Check kptr / kfield against BTF declarations (btf.scope @kernel)";
  let description = [{
    Resolve S in `!ebpf.kptr<"S">` as a btf.struct in `@kernel::@S`, resolve each
    ebpf.kfield.load field as a member, and compare result width with its #btf.int.
    ebpf-build-btf-types builds declarations from the schema. Restrictions on
    kptr origins (ebpf.ctx.arg only) remain in the dialect verifier.
  }];
}

def EBPFVerifyCallGraph : Pass<"ebpf-verify-call-graph", "mlir::ModuleOp"> {
  let summary = "Check subprogram call graph: nonrecursive, reachable, bounded depth";
  let description = [{
    The op verifier resolves ebpf.call targets and checks types. This pass checks
    module-wide properties: no self or mutual recursion; every ebpf.func is
    reachable from an ebpf.program, so its requirements can be attributed;
    call depth including entry is at most 8 frames. This is a conservative
    compiler limit, not a kernel contract or a guarantee of kernel acceptance.
    The kernel decides depth and total stack use (512 bytes).
  }];
}

def EBPFVerifyRecords : Pass<"ebpf-verify-records", "mlir::ModuleOp"> {
  let summary = "Check record types and field accesses against BTF declarations (btf.scope @records)";
  let description = [{
    Resolve `!ebpf.record<"S", N>` as `@records::@S` and compare size. Resolve
    ebpf.ref.field.load / store fields as members and compare integer widths.
    Map-value records are flat (all members are integers). ebpf-build-btf-types
    builds declarations using schema sizes / offsets without changing them.
  }];
}

def EBPFVerifyTargetLegality : Pass<"ebpf-verify-target-legality", "mlir::ModuleOp"> {
  let summary = "Check program-kind / target legality separately from op semantics (currently timers)";
  let description = [{
    For programs containing timer ops, implemented and tested kind xdp is Native;
    other kinds are compiler unsupported. A target profile's rejected fact
    `map-with-timer <program type>` means target unsupported, including programs
    that only use a timer-containing map without timer ops. An absent profile
    or unknown fact defers to load-time checking, not Native or a weaker fallback.
    Kernel versions are not compared.
  }];
  let options = [
    Option<"profilePath", "profile", "std::string", /*default=*/"\"\"",
           "target profile (kernel/profiles/*.tsv — named facts); empty checks compiler capability only">
  ];
}

// Diagnostic-only pass outside the default pipeline: print facts to stderr
// without changing IR.
def EBPFPrintSemanticFacts : Pass<"ebpf-print-semantic-facts", "mlir::ModuleOp"> {
  let summary = "Analyze and print eBPF semantic facts: integer ranges, checked non-null values, packet-window validity";
  let description = [{
    Print MLIR IntegerRangeAnalysis results (+ DeadCodeAnalysis /
    SparseConstantPropagation). Ranges narrowed by branch conditions (a preceding
    cf.cond_br / ebpf.if arith.cmpi with a constant) appear separately as
    kind=integer-edge, without propagation. Non-null facts cover only existing
    checked values: present block arguments of ref.check / ringbuf.if_reserved,
    and assume_present results satisfying the structured placement check.
    For packet windows, inspect ops from packet.check / pkt.check_br to the use
    through PacketNeutral. Invalidating ops (adjust_head / adjust_tail and
    pktinval helpers) yield valid=false; unproven neutrality yields valid=unknown.
    Compiler knowledge does not guarantee that the kernel verifier proves it.
  }];
}

def EBPFWarnNonrootIndex : Pass<"ebpf-warn-nonroot-index", "mlir::ModuleOp"> {
  let summary = "Warn about ref.index shapes rejected by non-root loaders on some kernels (stage 1, nonblocking)";
  let description = [{
    Trace index origins (constant, unknown, back-edge-loop values). Warn when
    constant and unknown values reach one index on different paths, or when a
    back-edge loop supplies the index: measured refusal by 6.12 / 6.6 verifiers
    (REASON_PATHS) without CAP_PERFMON. Region results retain arm tags; evaluate
    an enclosing ebpf.if's arith.cmpi-with-constant condition using each arm's
    constant to exclude unreachable constants. IR is unchanged. These facts are
    a compiler approximation, not the kernel verifier's path exploration.
    Kernel versions are not compared.
  }];
}

#endif // EBPF_TRANSFORMS_PASSES
