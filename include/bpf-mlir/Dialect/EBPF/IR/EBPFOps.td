// Root TableGen file for ebpf-specific helpers, maps, attachment, ownership,
// bounded loops, branches and subprograms. ebpf-compile accepts ebpf/arith/scf
// input, not cf/func. Each description is canonical for semantics, constraints
// and evidence; see docs/reference/ebpf_ops.md.

#ifndef EBPF_OPS
#define EBPF_OPS

include "mlir/IR/OpBase.td"
include "mlir/IR/SymbolInterfaces.td"
include "mlir/Interfaces/SideEffectInterfaces.td"
include "EBPFTypes.td"

// Memory-effect resources from EBPFDialect.h are declared only for the
// five packet-access/reservation-store operations.
def EBPF_PacketResource : Resource<"::mlir::ebpf::PacketResource">;
def EBPF_ReservationResource : Resource<"::mlir::ebpf::ReservationResource">;
def EBPF_ArenaResource : Resource<"::mlir::ebpf::ArenaResource">;

class EBPF_Op<string mnemonic, list<Trait> traits = []>
    : Op<EBPF_Dialect, mnemonic, traits>;

// This interface canonically identifies internal stage-2 operations created
// only by ebpf-expand-regions. ebpf-compile rejects them by name; the developer
// ebpf-opt accepts them. Reference stage labels and ebpf-reference check use
// this same set.
def EBPF_Stage2InternalOpInterface : OpInterface<"Stage2InternalOp"> {
  let description = [{
    Stage-② internal operations created only by ebpf-expand-regions.
    Rejected in ebpf-compile source input.
  }];
  let cppNamespace = "::mlir::ebpf";
  let methods = [
    StaticInterfaceMethod<"Stage-1 input form to write instead of this operation", "::llvm::StringRef", "getStage1Form">,
  ];
}

class EBPF_Stage2Op<string mnemonic, string stage1Form, list<Trait> traits = []>
    : EBPF_Op<mnemonic, !listconcat(traits, [EBPF_Stage2InternalOpInterface])> {
  let extraClassDeclaration = "static ::llvm::StringRef getStage1Form() { return \"" # stage1Form # "\"; }";
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_ProgramOp : EBPF_Op<"program",
    [IsolatedFromAbove, Symbol]> {
  let summary = "eBPF program with an attach kind";
  let description = [{
    **Stage**: ① Input

    **Meaning**: An attach unit, represented by a top-level module symbol. Kinds are defined in ProgramKinds.def, including xdp / tp_btf / fentry / fexit / kprobe / uprobe / sched_cls / raw_tp / kretprobe / uretprobe / iter / syscall / fmod_ret. The entry block takes one context (`!ebpf.ctx<kind>`) followed by zero or more map handles. Handles correspond **by position** to symbols in `maps [...]`; schema declares their capacity, flags, and BTF.
    Exits use `ebpf.verdict`, `verdict.if`, `return` (kinds marked `|int` in VERDICTS), `redirect`, `redirect_map`, or `tail_call`.

    **Constraints**: The op verifier rejects unknown kinds, mismatched context/program kinds, mismatched or duplicate map arguments/symbols, and a second context.
    For ext (freplace), `attach` names the global BPF function being replaced (section `freplace/<function>`); the loader supplies the target program. Only `ebpf.ext.arg` may use the entry context. Stage ③ produces `llvm.func @name(i64 × (highest used index + 1)) -> i32|i64`; schema supplies the unsigned FUNC_PROTO signature (nargs / args / ret). Requirements carry family `freplace` and extret / extarg (format 11). All ebpf.return operations in a program must have the same type.
    `attach` is required for tp_btf / raw_tp (tracepoint); fentry / fexit / kprobe / kretprobe / fmod_ret (kernel function); uprobe / uretprobe (symbol); sched_cls (`ingress` / `egress` for TCX, `netkit_primary` / `netkit_peer` for netkit); iter (target); and sk_skb / sk_msg (a sockmap / sockhash symbol present in program maps). The latter have no map value in the section name; requirements use the schema attach_target `map:<symbol>`. sk_skb stream_parser uses `attach "stream_parser:<map>"` and `ebpf.return` for the integer message length. sk_reuseport optionally accepts `attach "migrate"` (select_or_migrate); absence means select. `arch` is required for kprobe / uprobe / kretprobe / uretprobe and is not accepted by other kinds, except the multi-probe forms below.
    sk_skb accepts `attach "verdict:<map>"` for the non-stream verdict hook (`sk_skb/verdict`, expected type sk_skb_verdict). A bare map retains stream_verdict, and `stream_parser:<map>` retains stream_parser. The prefix is excluded from the map symbol in requirements; the named target must be a bound sockmap or sockhash.
    Multi probes (kprobe_multi / kretprobe_multi / uprobe_multi / uretprobe_multi) require `arch` and an enumerated name list, e.g. `attach ["f1", "f2"]`. The verifier rejects an empty list, empty or duplicate names, and glob characters `*`, `?`, `[`. Other kinds cannot use a list. Item i becomes `mtarget <p> <i> <name>`; the loader attaches in list order and supplies cookie i, read by `ebpf.probe.target_index` (requirements_format.md §8). Schema attach_target must contain the identical ordered JSON string array, checked by ebpf-verify-schema.
    A GCC-suffixed kprobe name such as `__do_pipe_flags.part.0` may exist only in kallsyms, while BTF FUNC has the unsuffixed name. A program that reads no arguments can pass precheck, attach, and fire, but **does not observe the original function's semantics**: `.part` is an outlined remainder and omits calls returning in the inlined prefix. Argument readers stop with `kprobearg_unknown` when BTF FUNC is absent. An unsuffixed name absent from kallsyms fails attach; no other function is substituted. Downstream measurements cover three kernels.
    Schema checking requires declarations when coverage.programs = complete and checks kind / attach_target. fentry / fexit / sched_cls / kprobe / uprobe require declarations regardless of coverage. ebpf-compile accepts only program / func / timer.callback / user_ringbuf.callback directly under the module, and only `ebpf` / `arith` / `scf` operations in their bodies.

    **Lowering**: Stage ② (ebpf-expand-regions) expands checked regions into cf branches and multiple blocks. Stage ③ normally creates `llvm.func @name(ptr) -> i32`, with kind-derived sections: `xdp`, `tp_btf/<tp>`, `fentry/<fn>`, `fexit/<fn>`, `kprobe/<fn>`, `uprobe/<sym>`, `tcx/<direction>` or `netkit/primary` / `netkit/peer`, `raw_tp/<tp>`, `kretprobe/<fn>`, `uretprobe/<sym>`, `iter/<target>`, `syscall`, `fmod_ret/<fn>`, or suffix-free `kprobe.multi` / `kretprobe.multi` / `uprobe.multi` / `uretprobe.multi`. It attaches `bpfabi.prog_type`, consumed by bpfabi-requirements.

    **Evidence**: F01, F20, F21, F23, F24, F25, F54. Staged lowering; identical XDP ELF on two targets; tp_btf / fentry / fexit / kprobe / uprobe / sched_cls fixtures; kind × target legality; enumerated multi-probe targets.

    **Unsupported**: Kinds outside the supported kind table are rejected. Non-context arguments other than map handles are not accepted. Stage ① does not accept a multi-block body mixed with cf operations. ebpf-verify-target-legality and load-time gates enforce kind × target restrictions for maps with timers / spin locks.
  }];
  // attach matches schema attach_target for tp_btf; xdp attachment interfaces
  // are chosen by userspace at load time. arch specifies probe calling
  // convention/pt_regs (x86_64) and matches the schema. Multi-probe attach_list
  // uses the same attach keyword with a name array and custom parsing/printing.
  let arguments = (ins SymbolNameAttr:$sym_name, StrAttr:$kind,
                       OptionalAttr<StrAttr>:$attach,
                       OptionalAttr<StrArrayAttr>:$attach_list,
                       OptionalAttr<StrAttr>:$arch,
                       UnitAttr:$sleepable,
                       OptionalAttr<SymbolRefArrayAttr>:$map_symbols);
  let regions = (region MinSizedRegion<1>:$body);
  let assemblyFormat =
      "$sym_name $kind custom<ProgramAttach>($attach, $attach_list) (`arch` $arch^)? (`sleepable` $sleepable^)? (`maps` $map_symbols^)? attr-dict-with-keyword $body";
  let hasVerifier = 1;
  let extraClassDeclaration = [{
    // ProgramAttaches.def FLAGS key: "sleepable" when the keyword is present, else "".
    ::llvm::StringRef getAttachFlags() { return getSleepable() ? ::llvm::StringRef("sleepable") : ::llvm::StringRef(); }
    // Attach-table key: string attach, first multi-attach name, or empty.
    ::llvm::StringRef getAttachValue() {
      if (auto a = getAttach())
        return *a;
      if (auto l = getAttachListAttr(); l && !l.empty())
        if (auto s = ::llvm::dyn_cast<::mlir::StringAttr>(l[0]))
          return s.getValue();
      return {};
    }
  }];
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_VerdictOp : EBPF_Op<"verdict",
    [Terminator, ParentOneOf<["ProgramOp", "TailCallOp", "RedirectOp"]>]> {
  let summary = "Terminate by returning a program verdict";
  let description = [{
    **Stage**: ① Input

    **Meaning**: A terminator returning a kind-specific verdict. xdp accepts `aborted` / `drop` / `pass` / `tx` / `redirect`; sched_cls accepts `pass` / `drop`; tp_btf / fentry / fexit / kprobe / uprobe accept only `done` (return value 0, not a verdict).
    For sock_ops in the `cgroup` verdict family (deny 0 / allow 1), deny does not block a connection: kernel tcp_call_bpf discards the reply and returns -1, and callers of callbacks such as ESTABLISHED ignore that return value.

    **Constraints**: ParentOneOf permits ebpf.program or a tail_call or redirect fallback region. The func verifier rejects it inside `ebpf.func`, which terminates with ebpf.return. The op verifier rejects verdicts absent from the kind table, such as sched_cls `redirect` or kprobe `pass`.

    **Lowering**: Unchanged in ②. Stage ③ creates `bpfabi.return` using UAPI `verdict` rows (xdp_action / tcx_action_base), or KernelABI.h's 0 for `done`. bpfabi-verify checks the table at the ③ exit; ④ emits a constant `llvm.return`.

    **Evidence**: F01. UAPI verdict values; tp_btf and fentry done; sched_cls pass / drop; fallback terminators.

    **Unsupported**: Use `ebpf.verdict.if` to select by value. sched_cls `redirect` / `next` are not accepted; use `ebpf.redirect`. xdp `redirect` only returns a constant and does not call a helper; use `ebpf.redirect_map` for forwarding.
  }];
  let arguments = (ins StrAttr:$action);
  let assemblyFormat = "$action attr-dict";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_VerdictIfOp : EBPF_Op<"verdict.if",
    [Terminator, ParentOneOf<["ProgramOp", "TailCallOp", "RedirectOp"]>]> {
  let summary = "Terminate by selecting between two verdicts";
  let description = [{
    **Stage**: ① Input

    **Meaning**: An i1 condition selects one of two verdicts: `ebpf.verdict.if %c "pass" else "drop"` returns the first when true and the second when false.

    **Constraints**: ParentOneOf permits only `ebpf.program` or a `ebpf.tail_call` fallback. The op verifier checks both verdicts against the program kind's table.

    **Lowering**: Stage ② (ebpf-expand-regions) creates `cf.cond_br` and two blocks ending in `ebpf.verdict`. Later stages follow `ebpf.verdict`; remaining occurrences at ③ are rejected as stage-① operations.

    **Evidence**: F11. pass / drop selected by packet.check's range i1; three-target measurements; fallback terminators.

    **Unsupported**: Exactly two verdicts, with no multi-way selection.
  }];
  let arguments = (ins I1:$cond, StrAttr:$then_action, StrAttr:$else_action);
  let assemblyFormat = "$cond $then_action `else` $else_action attr-dict";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_XdpAdjustHeadOp : EBPF_Op<"xdp.adjust_head"> {
  let summary = "bpf_xdp_adjust_head: move the packet start by delta bytes and return status (XDP only; invalidates packet pointers)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls `xdp_adjust_head(ctx, delta)` to move the packet start by delta bytes and returns raw status (0 or negative errno) as i64. Positive delta removes leading bytes; negative delta extends the head. The kernel checks bounds.
    The compiler treats packet pointers as invalidated on both success and failure (UAPI table `pktinval`).

    **Constraints**: The op verifier requires an XDP context inside an XDP program.
    - Not allowed in `ebpf.loop` bodies.
    - The stage-② may-invalidate check rejects `packet.store` / `packet.window_load` if any path from window definition to use contains this op. Re-read with a new `packet.check` or `packet.load` (which reads ctx every time).
    - It is absent from `isPacketNeutral`, so packet-neutral C1 / W1 / packet-check rewrites cannot cross it.

    **Lowering**: Stage ③ sign-extends delta to i64, calls helper `xdp_adjust_head`, and returns its status. No MLIR memory effects are declared (unknown effects).

    **Evidence**: F12. C oracle; may-invalidate checks; decapsulation on three targets with root / non-root, including failure −22 leaving the packet unchanged; actual veth attach; encapsulation with negative delta.

    **Unsupported**: Non-XDP programs, loop bodies, and old-window uses after the helper (compile-time rejection). Physical NIC headroom has not been measured.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$delta);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $delta attr-dict `:` type($ctx) `->` type($status)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_XdpAdjustMetaOp : EBPF_Op<"xdp.adjust_meta"> {
  let summary = "bpf_xdp_adjust_meta: move the packet metadata start by delta bytes and return status (XDP only; invalidates packet pointers)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls `xdp_adjust_meta(ctx, delta)` to move `data_meta` by delta bytes and returns raw status (0 or negative errno) as i64. Negative delta extends the metadata area toward the head. The kernel checks `data_meta` against `data_hard_start + sizeof(struct xdp_frame)` and `data`, and requires the resulting `data - data_meta` to be a multiple of 4 and at most 255 bytes. Only the pointer moves: no byte is written or zeroed.
    The compiler treats packet pointers as invalidated on both success and failure (UAPI table `pktinval`).

    **Constraints**: The op verifier requires an XDP context inside an XDP program. Delta is any i32 value; the compiler checks nothing about it (the kernel decides).
    - Not allowed in `ebpf.loop` bodies.
    - The stage-② may-invalidate check rejects `packet.store` / `packet.window_load` if any path from window definition to use contains this op. Re-read with a new `packet.check` or `packet.load`.
    - It is absent from `isPacketNeutral`, so packet-neutral C1 / W1 / packet-check rewrites cannot cross it.

    **Lowering**: Stage ③ sign-extends delta to i64, calls helper `xdp_adjust_meta`, and returns its status. No MLIR memory effects are declared (unknown effects).

    **Evidence**: Out of scope — no release F row yet. Static contracts (effect table, may-invalidate, C1 / W1 negative controls); also measured in VMs on 7.3.1, 7.1.8, 6.12.111 and 6.6.157 as root against an independent C oracle with XDP BPF_PROG_TEST_RUN (ctx_in data_end 64, every load strict-aligned): status 0 for a 4-byte-multiple delta within the limit, -13 for a misaligned delta, -22 for a positive delta from no meta and for a delta beyond the headroom, data_out = meta + the original frame; a 216-byte meta is accepted on 7.x and 6.12 and refused with -13 on 6.6.157 (the limit there is below 216 and at least 32, not measured exactly). XDP TEST_RUN only: no real attach, tc-side read, chain, AF_XDP or multi-buffer.

    **Unsupported**: Non-XDP programs and loop bodies (compile-time rejection). Reading or writing the metadata area (the meta window is a separate stage). Physical NIC headroom is unmeasured.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$delta);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $delta attr-dict `:` type($ctx) `->` type($status)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_XdpAdjustTailOp : EBPF_Op<"xdp.adjust_tail"> {
  let summary = "bpf_xdp_adjust_tail: move the packet end by delta bytes and return status (XDP only; invalidates packet pointers)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls `xdp_adjust_tail(ctx, delta)` and returns raw status (0 or negative errno) as i64. The compiler accepts shrinking only. Like adjust_head, the helper invalidates packet pointers on both success and failure (`pktinval`).

    **Constraints**: The op verifier requires an XDP program and context, and **delta must be a direct i32 `arith.constant` whose signed value is ≤ 0**. Positive constants and nonconstant values are rejected.
    Even delta 0 calls the helper and participates in may-invalidate checking. It is not allowed in loop bodies. Old-window rejection and packet-neutral C1 / W1 / packet-check rewrite barriers follow adjust_head.

    **Lowering**: Stage ③ sign-extends delta to i64 and calls `xdp_adjust_tail`, returning status. No memory effects are declared.

    **Evidence**: F13. C oracle (failure −22 leaves the packet unchanged); may-invalidate checking; trailer stripping on three targets with root / non-root; actual veth attach; restriction to constant delta ≤ 0.

    **Unsupported**: Growth (positive delta; driver tailroom is unmeasured), nonconstant delta even if provably negative at runtime, non-XDP programs, and loop bodies. Physical NICs are unmeasured.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$delta);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $delta attr-dict `:` type($ctx) `->` type($status)";
  let hasVerifier = 1;
}

// lwt_seg6local helpers; canonical semantics/evidence are in each description.
def EBPF_LwtSeg6StoreBytesOp : EBPF_Op<"lwt.seg6_store_bytes"> {
  let summary = "bpf_lwt_seg6_store_bytes: write a complete record to SRH flags, tag, or TLVs and return status (lwt_seg6local only; invalidates packet pointers)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls `lwt_seg6_store_bytes(ctx, offset, &rec, sizeof rec)` to write every record byte at the packet's byte offset from data (the IPv6 header start), returning **raw** i64 status. The kernel permits only SRH flags / tag (bytes 5–7 from the SRH start) and the TLV area; other locations return −EFAULT (net/core/filter.c). TLV writes cause post-program SRH revalidation; malformed packets are dropped (`seg6_bpf_has_valid_srh`).
    Packet pointers are invalidated on success and failure (UAPI `pktinval`).

    **Constraints**: Only lwt_seg6local programs (OPS marker `lwt.seg6`) and their entry context are accepted; static-function context arguments are not accepted by this invalidating operation. Data must be an `ebpf.record.make` result (all bytes, zero padding). Not allowed in `ebpf.loop`. The stage-② may-invalidate check rejects `packet.window_load` if any path from window definition to use crosses this operation. Packet-neutral C1 / W1 / packet-check rewrites do not cross it, as with adjust_head.

    **Lowering**: Stage ③ zero-extends offset to i64 and calls `lwt_seg6_store_bytes`, with record.make's stack storage as data and the record size as len. The result is status.

    **Evidence**: F57. Actual 7.1.8 netns seg6local route attach and differential measurement against equivalent C.

    **Unsupported**: Other program kinds, variable-length data, and loop bodies. 6.12 / 6.6 are unverified.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$offset, EBPF_RecordType:$record);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `[` $offset `]` `,` $record attr-dict `:` type($ctx) `,` type($offset) `,` type($record) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_LwtSeg6AdjustSrhOp : EBPF_Op<"lwt.seg6_adjust_srh"> {
  let summary = "bpf_lwt_seg6_adjust_srh: insert or remove delta bytes in the SRH TLV area and return status (lwt_seg6local only; invalidates packet pointers)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls `lwt_seg6_adjust_srh(ctx, offset, delta)` to insert (positive delta) or remove (negative delta) bytes at an offset between the TLV area start and the SRH end, returning **raw** i64 status. Inserted bytes must not be assumed zero; the caller writes TLVs with `ebpf.lwt.seg6_store_bytes`. After the program, the kernel revalidates SRH, updates hdrlen, and drops malformed packets. It also updates IPv6 payload_len.
    Packet pointers are invalidated on success and failure (`pktinval`).

    **Constraints**: Only lwt_seg6local programs and their entry context (OPS `lwt.seg6`). Delta is signed i32 and need not be constant; the kernel checks bounds. Loop bodies and static-function contexts are rejected. Old-window rejection follows store_bytes.

    **Lowering**: Stage ③ zero-extends offset, sign-extends delta, and calls `lwt_seg6_adjust_srh`, returning status.

    **Evidence**: F57. Actual 7.1.8 attach with +8 bytes and a PadN TLV at the SRH end.

    **Unsupported**: Other program kinds and loop bodies. 6.12 / 6.6 and removal (negative delta) are unmeasured.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$offset, I32:$delta);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `[` $offset `]` `,` $delta attr-dict `:` type($ctx) `,` type($offset) `,` type($delta) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_LwtSeg6ActionOp : EBPF_Op<"lwt.seg6_action"> {
  let summary = "bpf_lwt_seg6_action: perform End.X, End.T, or End.DT6 and return status (lwt_seg6local only; invalidates packet pointers)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls `lwt_seg6_action(ctx, action, &param, sizeof param)` and returns **raw** i64 status. Action spellings come from UAPI `seg6action` rows (`SEG6_LOCAL_ACTION_*`). The compiler accepts:
    - `end_x`: a 16-byte next-hop IPv6 address. The kernel looks up its route and sets skb dst.
    - `end_t` / `end_dt6`: a 4-byte int route table number. end_dt6 removes the outer IPv6 header and SRH.
    The program must return `redirect` to use the selected dst. With `ok`, the kernel looks up the next segment and discards the action's dst (net/ipv6/seg6_local.c input_action_end_bpf). Packet pointers are invalidated on success and failure (`pktinval`).

    **Constraints**: Only lwt_seg6local programs and their entry context (OPS `lwt.seg6`); loop bodies and static-function contexts are rejected. Param must be an `ebpf.record.make` result of the action's exact size: 16 for end_x, 4 for end_t / end_dt6. `end_b6` / `end_b6_encap` exist in UAPI but are explicitly rejected: constructing SRH parameters is outside compiler scope.

    **Lowering**: Stage ③ obtains the action value from UAPI (absence is an error) and calls `lwt_seg6_action`, with record.make's stack storage as param and record size as len.

    **Evidence**: F57. Actual 7.1.8 attach with End.X plus redirect and End.X plus ok.

    **Unsupported**: end_t / end_dt6 are unmeasured (no route-table observation). end_b6 / end_b6_encap, other program kinds, and 6.12 / 6.6 are unverified.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, StrAttr:$action, EBPF_RecordType:$param);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx $action `,` $param attr-dict `:` type($ctx) `,` type($param) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_CloneRedirectOp : EBPF_Op<"clone_redirect"> {
  let summary = "Clone an skb to an interface and return raw helper status";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Request an egress or ingress clone while continuing the original skb.
    The raw status is neither a TC verdict nor a delivery acknowledgement.
    **Constraints**: Own sched_cls entry context; i32 interface index; flags egress or ingress.
    Packet windows are invalidated on success and failure. Recheck bounds before reading again.
    **Lowering**: Zero-extend the interface index and call clone_redirect with the UAPI direction flag.
    **Evidence**: F79. Static contracts; kernel delivery measurements are pending.
    **Unsupported**: Other program kinds, loop/static-function use, and delivery acknowledgement.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$ifindex, StrAttr:$flags);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $ifindex `flags` $flags attr-dict `:` type($ctx) `,` type($ifindex) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_SkbLoadBytesOp : EBPF_Op<"skb.load_bytes"> {
 let summary = "Read fixed skb bytes into a packed integer and return raw status";
 let description = [{
  **Stage**: ① Input

  **Meaning**: Call skb_load_bytes once into a compiler-owned buffer. Byte j occupies bits 8j..8j+7 of the i64 value and higher bits are zero. Return raw i64 status. Kernel failures clear the requested bytes; value is read on both status paths. This is a helper read, including non-linear skb data, not a direct packet load.

  **Constraints**: Own entry sk_skb context, unsigned offset bits in i32, constant length 1..8. Bounded/unrolled loops allowed. Unknown effects preserve the helper call.

  **Lowering**: Initialize eight stack bytes, call helper26 with zero-extended offset and constant length, then pack exactly len bytes. No arbitrary output pointer.

  **Evidence**: F61 helper-based stream operations; kernel execution checks belong to the handler experiment.

  also sched_cls (OPS `skb.load_bytes`), with the same shape, loop acceptance and lowering.

  **Unsupported**: Static functions, callbacks, other program kinds, variable length or arbitrary memory destination.
 }];
 let arguments = (ins EBPF_ContextType:$ctx, I32:$offset, I64Attr:$len);
 let results = (outs I64:$value, I64:$status);
 let assemblyFormat = "$ctx `,` $offset `len` $len attr-dict `:` type($ctx) `,` type($offset) `->` type($value) `,` type($status)";
 let hasVerifier = 1;
}

// TCX entry-only helpers. None are Pure or packet-neutral.
def EBPF_SkbVlanPushOp : EBPF_Op<"skb.vlan_push"> {
 let summary = "Push a VLAN tag and return raw status";
 let description = [{
  **Stage**: ① Input
  **Meaning**: Call skb_vlan_push once with raw BE i16 protocol and host i16 TCI. The kernel defaults unknown protocols to 8021Q. The first tag may be hardware metadata; a subsequent push can move the previous tag into packet bytes.
  **Constraints**: Own sched_cls entry context at TCX ingress/egress only, outside static functions, loops and helper callbacks. Netkit is not supported.
  **Lowering**: Zero-extend both 16-bit operands and call the UAPI helper. Return raw i64 status. Invalidates packet windows on both status paths and is not packet-neutral.
  **Evidence**: F84. Static ABI/effect checks; 7.1.8 VM differential against C (TEST_RUN and TCX egress delivery, one boot).
  **Unsupported**: Other kinds/attachments and generic VLAN memory access.
 }];
 let arguments = (ins EBPF_ContextType:$ctx, I16:$proto, I16:$tci);
 let results = (outs I64:$status);
 let assemblyFormat = "$ctx `,` $proto `,` $tci attr-dict `:` type($ctx) `,` type($proto) `,` type($tci) `->` type($status)";
 let hasVerifier = 1;
}
def EBPF_SkbVlanPopOp : EBPF_Op<"skb.vlan_pop"> {
 let summary = "Pop a VLAN tag and return raw status";
 let description = [{
  **Stage**: ① Input
  **Meaning**: Call skb_vlan_pop once, including hardware tag removal/next-tag promotion. An untagged packet can return zero without losing four bytes.
  **Constraints**: Own sched_cls TCX ingress/egress entry only; no static function, loop, callback or netkit.
  **Lowering**: UAPI helper, raw i64 status. Invalidates packet windows on both paths; not packet-neutral.
  **Evidence**: F84. Static ABI/effect checks; 7.1.8 VM differential against C (TEST_RUN and TCX egress delivery, one boot).
  **Unsupported**: Other kinds/attachments.
 }];
 let arguments = (ins EBPF_ContextType:$ctx);
 let results = (outs I64:$status);
 let assemblyFormat = "$ctx attr-dict `:` type($ctx) `->` type($status)";
 let hasVerifier = 1;
}
def EBPF_SkbLoadBytesRelativeOp : EBPF_Op<"skb.load_bytes_relative"> {
 let summary = "Read fixed bytes relative to the MAC or network header";
 let description = [{
  **Stage**: ① Input
  **Meaning**: Call skb_load_bytes_relative into compiler-owned memory. Byte j occupies bits 8j..8j+7 of the i64 value; upper bits are zero. Return raw i64 status and read the value on both paths; kernel errors clear the requested bytes.
  **Constraints**: Own sched_cls TCX ingress/egress entry, i32 unsigned offset, len 1..8, start mac/net. Bounded/unrolled loops match skb.load_bytes; no static functions, helper callbacks or netkit.
  **Lowering**: Zero-initialize eight stack bytes, call the UAPI helper with zero-extended offset, constant len and generated header selector, then pack len bytes. Not packet-neutral; does not invalidate packet windows.
  **Evidence**: F84. Static ABI/effect checks; 7.1.8 VM differential against C (TEST_RUN only, one boot; no delivery measured).
  **Unsupported**: Arbitrary output pointers, variable len, other kinds/attachments.
 }];
 let arguments = (ins EBPF_ContextType:$ctx, I32:$offset, I64Attr:$len, StrAttr:$start);
 let results = (outs I64:$value, I64:$status);
 let assemblyFormat = "$ctx `,` $offset `len` $len `start` $start attr-dict `:` type($ctx) `,` type($offset) `->` type($value) `,` type($status)";
 let hasVerifier = 1;
}
def EBPF_SkbCheckMtuOp : EBPF_Op<"skb.check_mtu"> {
 let summary = "Check a non-GSO representative MTU with a fixed in/out u32 slot";
 let description = [{
  **Stage**: ① Input
  **Meaning**: Call check_mtu with flags zero. mtu_in zero uses ctx length; otherwise it specifies L3 length. ifindex zero selects ctx's device. Return the raw i64 status and the u32 slot after the call: nonnegative statuses update it to device MTU, early errors preserve the input. Positive FRAG_NEEDED is distinct from zero and negative errno. Kernel flags-zero GSO behavior is preserved but not separately measured here.
  **Constraints**: GPL; own sched_cls TCX ingress/egress entry, outside functions/loops/callbacks. Unsigned ifindex/mtu i32; signed len_diff i32. No netkit.
  **Lowering**: Allocate a four-byte, four-aligned slot; store mtu_in, call with zero-extended ifindex and signed len_diff, then load the slot. No generic pointer escape. Not packet-neutral and not pktinval.
  **Evidence**: F84. Static ABI/effect checks; 7.1.8 VM differential against C (TEST_RUN only, one boot; no delivery measured).
  **Unsupported**: XDP, GSO segment flags, arbitrary mutable memory.
 }];
 let arguments = (ins EBPF_ContextType:$ctx, I32:$ifindex, I32:$mtuIn, I32:$lenDiff);
 let results = (outs I32:$mtuOut, I64:$status);
 let assemblyFormat = "$ctx `,` $ifindex `,` $mtuIn `,` $lenDiff attr-dict `:` type($ctx) `,` type($ifindex) `,` type($mtuIn) `,` type($lenDiff) `->` type($mtuOut) `,` type($status)";
 let hasVerifier = 1;
}
def EBPF_SkbCsumLevelOp : EBPF_Op<"skb.csum_level"> {
 let summary = "Query or update skb checksum level metadata";
 let description = [{
  **Stage**: ① Input
  **Meaning**: Execute query/inc/dec/reset with a generated UAPI selector. Return raw i64 status; query can return a nonnegative level or -EACCES. Mutating modes affect checksum metadata, not arbitrary packet memory.
  **Constraints**: Own sched_cls TCX ingress/egress entry only; no function/loop/callback/netkit.
  **Lowering**: One helper call; not Pure, packet-neutral or pktinval.
  **Evidence**: F84. Static ABI/effect checks; 7.1.8 VM differential against C (TEST_RUN only, one boot; no delivery measured).
  **Unsupported**: Dynamic or unknown modes, other attachments/kinds.
 }];
 let arguments = (ins EBPF_ContextType:$ctx, StrAttr:$mode);
 let results = (outs I64:$status);
 let assemblyFormat = "$ctx `mode` $mode attr-dict `:` type($ctx) `->` type($status)";
 let hasVerifier = 1;
}
def EBPF_SkbSetHashOp : EBPF_Op<"skb.set_hash"> {
 let summary = "Set the skb software L4 hash";
 let description = [{
  **Stage**: ① Input
  **Meaning**: Set the raw unsigned i32 hash; return raw i64 status. A subsequent hash read uses it until invalidated.
  **Constraints**: Own sched_cls TCX ingress/egress entry; no function/loop/callback/netkit.
  **Lowering**: Zero-extend hash and call set_hash. Preserve the call even with unused status; not packet-neutral or pktinval.
  **Evidence**: F84. Static ABI/effect checks; 7.1.8 VM differential against C (TEST_RUN only, one boot; no delivery measured).
  **Unsupported**: Other attachments/kinds.
 }];
 let arguments = (ins EBPF_ContextType:$ctx, I32:$hash);
 let results = (outs I64:$status);
 let assemblyFormat = "$ctx `,` $hash attr-dict `:` type($ctx) `,` type($hash) `->` type($status)";
 let hasVerifier = 1;
}
def EBPF_SkbSetHashInvalidOp : EBPF_Op<"skb.set_hash_invalid"> {
 let summary = "Invalidate the skb hash for lazy recalculation";
 let description = [{
  **Stage**: ① Input
  **Meaning**: Clear hash/sw_hash/l4_hash. This UAPI helper has void return and the operation exposes no result.
  **Constraints**: Own sched_cls TCX ingress/egress entry; no function/loop/callback/netkit.
  **Lowering**: Preserve one set_hash_invalid helper call. Not Pure, packet-neutral or pktinval.
  **Evidence**: F84. Static ABI/effect checks; 7.1.8 VM differential against C (TEST_RUN only, one boot; no delivery measured).
  **Unsupported**: Other attachments/kinds and a numeric return value.
 }];
 let arguments = (ins EBPF_ContextType:$ctx);
 let assemblyFormat = "$ctx attr-dict `:` type($ctx)";
 let hasVerifier = 1;
}
def EBPF_SkbEcnSetCeOp : EBPF_Op<"skb.ecn_set_ce"> {
 let summary = "Set ECN CE on an eligible skb packet";
 let description = [{
  **Stage**: ① Input
  **Meaning**: Call skb_ecn_set_ce once, preserving the raw i64 result (including 0 for ineligible packets and 1 for eligible/already-CE packets). IPv4 checksum changes with CE bits.
  **Constraints**: Own sched_cls TCX ingress/egress entry; no function/loop/callback/netkit.
  **Lowering**: One UAPI helper call. Packet write, not Pure/packet-neutral; no packet pointer invalidation.
  **Evidence**: F84. Static ABI/effect checks; 7.1.8 VM differential against C (TEST_RUN only, one boot; no delivery measured).
  **Unsupported**: Other kinds/attachments.
 }];
 let arguments = (ins EBPF_ContextType:$ctx);
 let results = (outs I64:$status);
 let assemblyFormat = "$ctx attr-dict `:` type($ctx) `->` type($status)";
 let hasVerifier = 1;
}

def EBPF_SkbGetTunnelKeyOp : EBPF_Op<"skb.get_tunnel_key"> {
 let summary = "Read the skb tunnel key into a 44-byte struct bpf_tunnel_key view record and return the raw status";
 let description = [{
  **Stage**: ① Input
  **Meaning**: Calls `skb_get_tunnel_key(ctx, buf, 44, flags)` once on a compiler-owned 44-byte copy of the input record and returns the helper-written copy plus the raw i64 status (0, −EINVAL when the skb has no tunnel info or flags are rejected, −EPROTO when the tunnel family differs from the `tuninfo_ipv6` flag). On every failure the kernel zeroes all 44 bytes. The input record's bytes are only the helper's starting content (a sentinel makes the failure zeroing observable); the input is never modified. Flags is `"none"` or a comma-separated subset of `tuninfo_ipv6` and `tuninfo_flags` (UAPI BPF_F_TUNINFO_IPV6 / BPF_F_TUNINFO_FLAGS; the table names are the UAPI names without BPF_F_, lowercase). `tuninfo_flags` also fills `tunnel_flags` (a `__be16`, raw bytes — no byte-order conversion); otherwise the kernel writes 0 there. **remote and local are swapped relative to `set_tunnel_key`**: set stores remote→dst / local→src, get returns remote←src / local←dst.
  **Constraints**: Own sched_cls TCX ingress/egress entry context (OPS `skb.datapath`; not netkit, not lwt_xmit, not XDP), outside functions, loops and callbacks. The input is an `ebpf.record.make` result and the output record type equals it; the output may only be read with `ebpf.record.field`. The record must be the exact 44-byte struct bpf_tunnel_key view of the flags' family (the UAPI table's `tunnelfield` rows: view `v6` when `tuninfo_ipv6` is set, else `v4`; `ebpf-verify-records` checks names, offsets and widths). Size is always 44 (the kernel's compat sizes are not used). The status is raw: it is not converted to a predicate.
  **Lowering**: Stage ③ allocates a 44-byte stack buffer aligned to 8, copies the input record, calls helper 20 with size 44 and the flag value from the UAPI table, and binds the output to the buffer. The call has no memory attributes and stays when the status is unused. Not packet-neutral and not in the UAPI `pktinval` table (the helper changes no packet data). Requirements: the helper row only.
  **Evidence**: Out of scope — no release F row yet; static checks cover it, and a separate run covers it in a VM on 4 kernels (7.1.8, 7.3.1, 6.12.111, 6.6.157) against an independent C oracle with TEST_RUN only (no tunnel device, no delivery).
  **Unsupported**: lwt_xmit (the kernel allows it; this compiler does not), XDP, netkit, compat key sizes, dynamic flags, the `_opt` helpers.
 }];
 let arguments = (ins EBPF_ContextType:$ctx, EBPF_RecordType:$input, StrAttr:$flags);
 let results = (outs EBPF_RecordType:$output, I64:$status);
 let assemblyFormat = "$ctx `,` $input `flags` $flags attr-dict `:` type($ctx) `,` type($input) `->` type($output) `,` type($status)";
 let hasVerifier = 1;
}
def EBPF_SkbSetTunnelKeyOp : EBPF_Op<"skb.set_tunnel_key"> {
 let summary = "Set the skb tunnel key from a 44-byte struct bpf_tunnel_key view record and return the raw status";
 let description = [{
  **Stage**: ① Input
  **Meaning**: Calls `skb_set_tunnel_key(ctx, buf, 44, flags)` once on a compiler-owned copy of the input record and returns the raw i64 status (0 or −EINVAL). On success the kernel replaces the skb's dst with this CPU's shared metadata_dst carrying the key; packet bytes and pointers are unchanged. −EINVAL leaves the skb's dst as it was: `tunnel_flags` (the `__be16` field that is `tunnel_ext` for set) non-zero is rejected for every family, and `tunnel_label` non-zero is rejected for IPv4 only (for IPv6 the kernel keeps `be32(label) & IPV6_FLOWLABEL_MASK`). Both are returned as the kernel's status, not stopped at compile time. Flags is `"none"` or a comma-separated subset of `tuninfo_ipv6`, `zero_csum_tx`, `dont_fragment`, `seq_number`, `no_tunnel_key` (UAPI BPF_F_*, lowercase without the prefix).
  **Constraints**: As `ebpf.skb.get_tunnel_key`: own sched_cls TCX entry context, not in functions, loops or callbacks; the input is an `ebpf.record.make` result that is the exact 44-byte `v4` / `v6` view of the flags' family (all bytes, padding 0).
  **Lowering**: Stage ③ copies the record into a 44-byte, 8-aligned stack buffer and calls helper 21 with size 44 and the flag value. No memory attributes; the call stays when the status is unused. Not packet-neutral, not pktinval. The helper's prototype lookup allocates a per-CPU metadata_dst at load time (kernel side).
  **Evidence**: Out of scope — no release F row yet; static checks cover it, and a separate run covers it in a VM on 4 kernels (7.1.8, 7.3.1, 6.12.111, 6.6.157) against an independent C oracle with TEST_RUN only (no tunnel device, no delivery).
  **Unsupported**: lwt_xmit, XDP, netkit, compat key sizes, dynamic flags, `skb_set_tunnel_opt`, real tunnel delivery.
 }];
 let arguments = (ins EBPF_ContextType:$ctx, EBPF_RecordType:$key, StrAttr:$flags);
 let results = (outs I64:$status);
 let assemblyFormat = "$ctx `,` $key `flags` $flags attr-dict `:` type($ctx) `,` type($key) `->` type($status)";
 let hasVerifier = 1;
}

def EBPF_TracePrintkOp : EBPF_Op<"trace.printk"> {
 let summary = "Print a limited literal format with up to three integer or literal-string arguments";
 let description = [{
  **Stage**: ① Input

  **Meaning**: Call trace_printk with a read-only literal plus one terminal NUL and its size. The raw i64 result is not the decorated trace line length or a delivery count. Compile-time format checks are a limited language contract; kernel format errors are runtime helper results. `strs ["…", …]` gives the literal strings of the format's %s conversions, in order; a runtime pointer cannot be written (`$args` are integers, the strings are attributes only).

  **Constraints**: sk_skb, sched_cls or struct_ops program; a struct_ops program must implement a sched_ext_ops member (ebpf-verify-schema — the other struct_ops types' get_func_proto is not read). No embedded NUL in the format. Accept %d/%u/%x with i32, %ld/%lu/%lx/%llx with i64 and %s; %% consumes no argument and no literal. The number of %s equals the number of strs elements and the number of integer conversions equals the number of `$args`; %s and integers together are at most three (the helper's slots). Every strs element is a string attribute without an embedded NUL. %s takes no flag, width or precision, and the character after %s is the end of the format, a space or an ASCII punctuation character (C isspace / ispunct — the kernel returns -EINVAL otherwise). The compiler's conservative bin_args bound: sum over strs of (length + 1 + 7) plus 8 × (number of integers) ≤ 512 (MAX_BPRINTF_BIN_ARGS); e.g. one %s alone takes a literal of at most 504 bytes. No other printf flags, width, precision or pointers. Unknown memory effects retain unused calls. ELF emission requires an exact kernel GPL-compatible license. In an ebpf.func body the op verifier checks the format only; ebpf-verify-call-contexts requires every program kind that reaches the function to allow trace.printk, and ebpf-verify-schema requires a reaching struct_ops owner to implement a sched_ext_ops member (a context reached through a timer or helper callback is rejected).

  **Lowering**: Deterministic compiler-owned .rodata format, then helper6 with fmt/size/three slots in the format's conversion order. Unused slots are zero. Signed %d is sign-extended and unsigned i32 formats zero-extended; i64 bits are preserved. Each %s literal is a compiler-owned .rodata string `__ebpf_trace_str_<sha256>` (one symbol per content, with a BTF VAR like the format) whose address (llvm.mlir.addressof, ptrtoint to i64) fills its slot.

  **Evidence**: F61 stream helpers; format/license/trace runtime checks are deferred to the handler experiment. compile only (lit) for the ebpf.func case. compile only (lit and ELF) for struct_ops and %s; no kernel load (the trace line is unobserved).

  **Unsupported**: General printf compatibility, runtime string pointers in %s (e.g. a task's comm) and strings chosen at run time, four or more arguments (bpf_trace_vprintk), struct_ops types other than sched_ext_ops, helper callbacks (also through a function they call), other program kinds. CAP_PERFMON (a loader without it has no trace_printk) is a loader permission and is not checked. Trace payload/pid attribution is a separate observation.
 }];
 let arguments = (ins StrAttr:$format, OptionalAttr<ArrayAttr>:$strs, Variadic<AnySignlessInteger>:$args);
 let results = (outs I64:$status);
 let assemblyFormat = "$format (`strs` $strs^)? `(` $args `)` attr-dict `:` functional-type($args, $status)";
 let hasVerifier = 1;
}

def EBPF_SkbAdjustRoomOp : EBPF_Op<"skb.adjust_room"> {
 let summary = "Adjust sk_skb headroom with zero mode and flags and return raw status";
 let description = [{
  **Stage**: ① Input

  **Meaning**: Use sk_skb's skb_adjust_room implementation: signed delta removes head bytes when negative and inserts zero bytes when positive. It differs from TC network-header adjustment. Failures are raw helper results, without compiler clamping.

  **Constraints**: Own entry sk_skb context, any i32 delta, mode=0 and flags=0. Bounded/unrolled loop bodies allowed. Both success and failure invalidate old packet pointers; the kind still has no direct packet/window capability.

  **Lowering**: Sign-extend delta and call helper50(ctx,delta,0,0), returning raw i64.

  **Evidence**: F61 stream operations; kernel outcomes and delivery are checked with the handlers.

  (sched_cls): `mode "net"` (default) or `mode "mac"` selects the UAPI adjroommode value; flags stay 0. The call is outside loops (sched_cls has packet windows) and invalidates them on success and failure (UAPI pktinval). sk_skb rejects the mode word and keeps its loop acceptance.

  **Unsupported**: Nonzero flags, encapsulation flags, sched_cls inside loops, static functions, callbacks, implicit fallback or direct packet access.
 }];
 let arguments = (ins EBPF_ContextType:$ctx, I32:$delta, DefaultValuedAttr<I64Attr,"0">:$mode, DefaultValuedAttr<I64Attr,"0">:$flags, OptionalAttr<StrAttr>:$room_mode);
 let results = (outs I64:$status);
 let assemblyFormat = "$ctx `,` $delta (`mode` $room_mode^)? attr-dict `:` type($ctx) `,` type($delta) `->` type($status)";
 let hasVerifier = 1;
}

def EBPF_SkbStoreBytesOp : EBPF_Op<"skb.store_bytes"> {
  let summary = "Write initialized scalar bytes into an skb and return raw status";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Write exactly len bytes at an unsigned byte offset. Failure does not terminate the program.
    **Constraints**: Own sched_cls context. Constant len/type pairs are 1/i8, 4/i32, 6/i64 and 8/i64.
    Six bytes use the low 48 bits, in little-endian byte order; the high 16 bits are ignored.
    Flags must be zero. Packet windows are invalidated even on failure; subsequent reads need fresh bounds.
    **Lowering**: Initialize exactly len stack bytes, then call skb_store_bytes with constant length and zero flags.
    **Evidence**: F79. Static contracts; kernel delivery measurements are pending.
    **Unsupported**: Runtime lengths, nonzero flags, arbitrary pointers, record sources and other program kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$offset, AnyInteger:$value, I64Attr:$len, I64Attr:$flags);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $offset `,` $value `len` $len `flags` $flags attr-dict `:` type($ctx) `,` type($offset) `,` type($value) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_L3CsumReplaceOp : EBPF_Op<"l3_csum_replace"> {
  let summary = "Apply an IPv4 checksum difference and return raw helper status";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Apply a checksum difference at an unsigned byte offset, without terminating on failure.
    **Constraints**: Own sched_cls context. This exposes only the difference mode, not L4 checksum updates.
    All existing packet windows are invalidated on success and failure.
    **Lowering**: Call l3_csum_replace with from=0, to=diff and size=0. In net/core/filter.c,
    the zero BPF_F_HDR_FIELD_MASK branch passes to as a difference to csum_replace_by_diff.
    **Evidence**: F79. Static contracts; kernel delivery measurements are pending.
    **Unsupported**: Nonzero field sizes, general from/to replacement, L4 checksum helpers and other program kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$offset, I64:$diff);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $offset `,` $diff attr-dict `:` type($ctx) `,` type($offset) `,` type($diff) `->` type($status)";
  let hasVerifier = 1;
}

// sched_cls / xdp packet helpers. Semantics: docs/reference/ebpf_ops.md.
def EBPF_L4CsumReplaceOp : EBPF_Op<"l4_csum_replace"> {
  let summary = "Apply an L4 checksum difference (optional pseudo-header / mangled-zero flags) and return raw status";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Apply a checksum difference to the L4 checksum at an unsigned byte offset, like `l3_csum_replace`. `pseudo_hdr` marks the difference as covering pseudo-header fields (address / length changes); `mark_mangled_0` keeps a zero UDP checksum zero. Failure does not terminate the program.
    **Constraints**: Own sched_cls entry context (OPS `tc.mutation`), outside loops, static functions and callbacks. Only the difference mode (from 0, field size 0). All packet windows are invalidated on success and failure (UAPI pktinval).
    **Lowering**: Call helper l4_csum_replace(ctx, zext offset, 0, diff, flags) with flags the OR of the UAPI table's `csumflag` values for the given keywords.
    **Evidence**: F81. static contracts (lit, effect unit test); kernel execution is measured separately.
    **Unsupported**: Field sizes 2 / 4, BPF_F_MARK_ENFORCE, BPF_F_IPV6, other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$offset, I64:$diff, UnitAttr:$pseudo_hdr, UnitAttr:$mark_mangled_0);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $offset `,` $diff (`pseudo_hdr` $pseudo_hdr^)? (`mark_mangled_0` $mark_mangled_0^)? attr-dict `:` type($ctx) `,` type($offset) `,` type($diff) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_SkbPullDataOp : EBPF_Op<"skb.pull_data"> {
  let summary = "Pull non-linear skb data into the linear area and return raw status";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Raw i64 result of skb_pull_data(ctx, len): make the first len bytes linear and writable (len 0 = the current linear head, skb_headlen — not the whole skb; net/core/filter.c `len ? : skb_headlen(skb)` on 7.1.8 / 6.12.111 / 6.6.157). Packet windows must be re-established by a new packet.check.
    **Constraints**: Own sched_cls entry context (OPS `skb.resize`), outside loops, static functions and callbacks. Invalidates all packet windows on success and failure (UAPI pktinval).
    **Lowering**: Zero-extend len and call helper skb_pull_data.
    **Evidence**: F81. Static contracts; kernel execution is a separate measurement.
    **Unsupported**: Other kinds, implicit re-check of windows.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$len);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $len attr-dict `:` type($ctx) `,` type($len) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_SkbChangeTailOp : EBPF_Op<"skb.change_tail"> {
  let summary = "Resize the skb to len bytes (flags 0) and return raw status";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Raw i64 result of skb_change_tail(ctx, len, 0): trim or grow (zero-filled) the packet to len bytes.
    **Constraints**: Own sched_cls entry context (OPS `skb.resize`), outside loops, static functions and callbacks. Invalidates all packet windows (UAPI pktinval).
    **Lowering**: Zero-extend len and call helper skb_change_tail with flags 0.
    **Evidence**: F81. Static contracts; kernel execution is a separate measurement.
    **Unsupported**: Nonzero flags, other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$len);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $len attr-dict `:` type($ctx) `,` type($len) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_SkbChangeHeadOp : EBPF_Op<"skb.change_head"> {
  let summary = "Grow skb headroom by len bytes at the MAC header (flags 0) and return raw status";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Raw i64 result of skb_change_head(ctx, len, 0): prepend len bytes in front of the MAC header; the kernel zero-fills the new bytes (`memset(skb->data, 0, head_room)` on 7.1.8 / 6.12.111 / 6.6.157) — write a header with skb.store_bytes.
    **Constraints**: Own sched_cls entry context (OPS `skb.resize`), outside loops, static functions and callbacks. Invalidates all packet windows (UAPI pktinval).
    **Lowering**: Zero-extend len and call helper skb_change_head with flags 0.
    **Evidence**: F81. Static contracts; kernel execution is a separate measurement.
    **Unsupported**: Nonzero flags, other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$len);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $len attr-dict `:` type($ctx) `,` type($len) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_SkbChangeProtoOp : EBPF_Op<"skb.change_proto"> {
  let summary = "Change the skb protocol (IPv4 / IPv6 translation, flags 0) and return raw status";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Raw i64 result of skb_change_proto(ctx, proto, 0). `proto` is the EtherType in network byte order (e.g. `byteorder.to_be` of 0x86dd); the kernel only accepts IPv4 / IPv6 transitions.
    **Constraints**: Own sched_cls entry context (OPS `skb.resize`), outside loops, static functions and callbacks. i16 proto. Invalidates all packet windows (UAPI pktinval).
    **Lowering**: Zero-extend proto and call helper skb_change_proto with flags 0.
    **Evidence**: F81. Static contracts; kernel execution is a separate measurement.
    **Unsupported**: Nonzero flags, other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I16:$proto);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $proto attr-dict `:` type($ctx) `,` type($proto) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_SkbChangeTypeOp : EBPF_Op<"skb.change_type"> {
  let summary = "Set skb->pkt_type and return raw status";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Raw i64 result of skb_change_type(ctx, type) (PACKET_HOST etc.). Writes skb metadata; packet pointers remain valid, but the op is outside the packet-neutral whitelist (C1 / W1 do not cross it).
    **Constraints**: Own sched_cls entry context (OPS `skb.meta`), outside loops, static functions and callbacks.
    **Lowering**: Zero-extend type and call helper skb_change_type.
    **Evidence**: F81. Static contracts; kernel execution is a separate measurement.
    **Unsupported**: Other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$pkt_type);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $pkt_type attr-dict `:` type($ctx) `,` type($pkt_type) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_CsumUpdateOp : EBPF_Op<"csum.update"> {
  let summary = "Add a checksum difference to skb->csum (CHECKSUM_COMPLETE) and return the raw result";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Raw i64 result of csum_update(ctx, csum): the new skb->csum, or a negative errno when the skb is not CHECKSUM_COMPLETE. Writes skb metadata; outside the packet-neutral whitelist.
    **Constraints**: Own sched_cls entry context (OPS `skb.meta`), outside loops, static functions and callbacks.
    **Lowering**: Zero-extend csum and call helper csum_update.
    **Evidence**: F81. Static contracts; kernel execution is a separate measurement.
    **Unsupported**: Other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$csum);
  let results = (outs I64:$result);
  let assemblyFormat = "$ctx `,` $csum attr-dict `:` type($ctx) `,` type($csum) `->` type($result)";
  let hasVerifier = 1;
}

def EBPF_CsumDiffOp : EBPF_Op<"csum.diff", [AttrSizedOperandSegments]> {
  let summary = "Compute a checksum difference over 0 / 4 / 8-byte from and to values (raw i64)";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Raw i64 result of csum_diff(from, from_size, to, to_size, seed). Each present value's in-memory little-endian bytes are summed (use `byteorder.to_be` for network-order data); an absent side is a NULL pointer with size 0. The helper does not touch the packet.
    **Constraints**: Directly in a sched_cls or xdp program body (OPS `csum.diff`), outside loops, static functions and callbacks. Each present value is i32 or i64; at least one of from / to is present. Seed is i32.
    **Lowering**: Each present value gets its own 4 / 8-byte stack slot (align 4), fully written by one store before the call (no uninitialized stack reaches the helper); seed is zero-extended.
    **Evidence**: F81. Static contracts; kernel execution is a separate measurement.
    **Unsupported**: Arbitrary buffers, packet ranges, sizes other than 4 / 8, other kinds.
  }];
  let arguments = (ins Optional<AnyInteger>:$from, Optional<AnyInteger>:$to, I32:$seed);
  let results = (outs I64:$result);
  let assemblyFormat = "(`from` $from^ `:` type($from))? (`to` $to^ `:` type($to))? `seed` $seed attr-dict `:` type($seed) `->` type($result)";
  let hasVerifier = 1;
}

def EBPF_SkbHashRecalcOp : EBPF_Op<"skb.hash_recalc"> {
  let summary = "Recompute and store skb->hash, returning the raw value";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Raw i64 result of get_hash_recalc(ctx). The helper recomputes the flow hash and **writes skb->hash** (side effect), then returns it. Outside the packet-neutral whitelist.
    **Constraints**: Own sched_cls entry context (OPS `skb.meta`), outside loops, static functions and callbacks.
    **Lowering**: Call helper get_hash_recalc.
    **Evidence**: F81. Static contracts; kernel execution is a separate measurement.
    **Unsupported**: Other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx);
  let results = (outs I64:$hash);
  let assemblyFormat = "$ctx attr-dict `:` type($ctx) `->` type($hash)";
  let hasVerifier = 1;
}

def EBPF_SkbCgroupClassidOp : EBPF_Op<"skb.cgroup_classid"> {
  let summary = "Raw net_cls classid of the current task (get_cgroup_classid)";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Raw i64 result of get_cgroup_classid(ctx): the cgroup-v1 net_cls classid of the current task; in softirq context (most ingress) the classid of the skb's full socket, or 0 without one (include/net/cls_cgroup.h `task_get_classid`); 0 without CONFIG_CGROUP_NET_CLASSID.
    **Constraints**: Own sched_cls entry context (OPS `skb.meta`), outside loops, static functions and callbacks.
    **Lowering**: Call helper get_cgroup_classid.
    **Evidence**: F81. Static contracts; kernel execution is a separate measurement.
    **Unsupported**: skb_cgroup_classid (socket owner's classid), other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx);
  let results = (outs I64:$classid);
  let assemblyFormat = "$ctx attr-dict `:` type($ctx) `->` type($classid)";
  let hasVerifier = 1;
}

// socket helpers that need only the entry context and scalars.
def EBPF_SkbSocketUidOp : EBPF_Op<"skb.socket_uid"> {
  let summary = "Raw uid bits of the skb's socket (get_socket_uid)";
  let description = [{
    **Stage**: ① Input
    **Meaning**: The u32 bits returned by get_socket_uid(ctx) as an i32: the uid of the skb's full socket mapped through from_kuid_munged, or overflowuid without a full socket (source reading; the value is measured separately). The result is not a status and no i64 result is offered; zero-extend it explicitly when an i64 is needed.
    **Constraints**: Own socket_filter or sched_cls entry context (OPS `skb.socket_uid`), outside loops, static functions and callbacks.
    **Lowering**: Call helper get_socket_uid with the context and truncate the i64 return to i32.
    **Evidence**: Out of scope — no release F row yet; static checks cover it, and a separate run covers it in a VM on 3 kernels (7.1.8, 6.12.111, 6.6.157) against an independent C oracle.
    **Unsupported**: sk_skb (accepted by the kernel but unmeasured), other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx);
  let results = (outs I32:$uid);
  let assemblyFormat = "$ctx attr-dict `:` type($ctx) `->` type($uid)";
  let hasVerifier = 1;
}

def EBPF_SkbCgroupIdOp : EBPF_Op<"skb.cgroup_id"> {
  let summary = "Raw cgroup id of the skb's socket (skb_cgroup_id)";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Raw u64 bits returned by skb_cgroup_id(ctx): the cgroup v2 id of the skb's socket, not of the current task; 0 without a full socket (source reading; the value is measured separately). Distinct from `ebpf.skb.cgroup_classid`.
    **Constraints**: Own cgroup_skb or sched_cls entry context (OPS `skb.cgroup_id`), outside loops, static functions and callbacks.
    **Lowering**: Call helper skb_cgroup_id with the context.
    **Evidence**: Out of scope — no release F row yet; static checks cover it, and a separate run covers it in a VM on 3 kernels (7.1.8, 6.12.111, 6.6.157) against an independent C oracle.
    **Unsupported**: Other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx);
  let results = (outs I64:$id);
  let assemblyFormat = "$ctx attr-dict `:` type($ctx) `->` type($id)";
  let hasVerifier = 1;
}

def EBPF_SkbAncestorCgroupIdOp : EBPF_Op<"skb.ancestor_cgroup_id"> {
  let summary = "Raw id of an ancestor cgroup of the skb's socket (skb_ancestor_cgroup_id)";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Raw u64 bits returned by skb_ancestor_cgroup_id(ctx, level): the id of the ancestor of the socket's cgroup at `level` (0 is the root); 0 without a full socket, for a negative level or for a level deeper than the socket's cgroup (source reading; the values are measured separately).
    **Constraints**: Own cgroup_skb or sched_cls entry context (OPS `skb.ancestor_cgroup_id`), outside loops, static functions and callbacks. `level` is any i32 value and is not range-checked by the compiler.
    **Lowering**: Call helper skb_ancestor_cgroup_id with the context and the sign-extended level.
    **Evidence**: Out of scope — no release F row yet; static checks cover it, and a separate run covers it in a VM on 3 kernels (7.1.8, 6.12.111, 6.6.157) against an independent C oracle.
    **Unsupported**: Other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$level);
  let results = (outs I64:$id);
  let assemblyFormat = "$ctx `,` $level attr-dict `:` type($ctx) `,` type($level) `->` type($id)";
  let hasVerifier = 1;
}

def EBPF_SockOpsCbFlagsSetOp : EBPF_Op<"sock_ops.cb_flags_set"> {
  let summary = "Replace the socket's sock_ops callback flags (sock_ops_cb_flags_set)";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Raw i64 status of sock_ops_cb_flags_set(ctx, flags). The helper replaces the whole callback-flag field of the TCP socket with `flags & 0x7F` (not an OR) and returns the bits it did not accept, `flags & ~0x7F`, so 0 means all were accepted; negative flags yield a negative remainder that is not an errno. -EINVAL without a full socket; -EOPNOTSUPP outside a locked TCP callback on kernels that have that check (source reading; measures status and effect, the two errors are not promised).
    **Constraints**: Own sock_ops entry context (OPS `sock_ops.cb_flags_set`), outside loops, static functions and callbacks. `flags` is any i32 value; the compiler gives its bits no meaning. The call changes later callbacks, so it is kept when the status is unused.
    **Lowering**: Call helper sock_ops_cb_flags_set with the context and the sign-extended flags.
    **Evidence**: Out of scope — no release F row yet; static checks cover it, and a separate run covers it in a VM on 3 kernels (7.1.8, 6.12.111, 6.6.157) against an independent C oracle.
    **Unsupported**: Other kinds, named flag constants.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$flags);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $flags attr-dict `:` type($ctx) `,` type($flags) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_SockOpsSetsockoptOp : EBPF_Op<"sock_ops.setsockopt"> {
  let summary = "Set an integer socket option from a sock_ops program, returning raw bpf_setsockopt status";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Raw i64 status of setsockopt(ctx, level, optname, &value, 4): 0 or a negative errno. `-EINVAL` includes a socket that is not a full socket (a request socket), and a value the kernel refuses (`tcp_bpf_iw` and `tcp_bpf_sndcwnd_clamp` need a positive value). The compiler does not check the value. The option name selects level and optname from the closed table; the numbers come from the UAPI table.
    **Constraints**: Own sock_ops entry context (OPS `sock_ops.sockopt`), outside loops, static functions and helper callbacks. `option` is one of so_sndbuf, so_rcvbuf, so_mark, ip_tos, tcp_maxseg, tcp_window_clamp, tcp_bpf_iw, tcp_bpf_sndcwnd_clamp; any other name is rejected. The call is kept when the status is unused.
    **Lowering**: Stage ③ spills value to a 4-byte stack slot and calls helper setsockopt once with UAPI level and optname and size 4. Requirements carry the existing helper row; which option exists on a kernel is not a requirement (an absent option is a runtime status).
    **Evidence**: Out of scope — no release F row yet; static checks cover it, and a separate run covers it in VMs on 7.3.1, 7.1.8, 6.12.111 and 6.6.157 as root against an independent C oracle over IPv4 loopback TCP: the status, the value userspace reads for the 6 readable options, and -EINVAL for request sockets and invalid values all matched. `tcp_bpf_iw` and `tcp_bpf_sndcwnd_clamp` are observed by status only.
    **Unsupported**: TCP_NODELAY (6.6 and 6.12 lack the header-option callback rejection), string options (TCP_CONGESTION, SO_BINDTODEVICE), non-i32 values, other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, StrAttr:$option, I32:$value);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx $option `,` $value attr-dict `:` type($ctx) `,` type($value) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_SockOpsGetsockoptOp : EBPF_Op<"sock_ops.getsockopt"> {
  let summary = "Read an integer socket option from a sock_ops program, returning raw bpf_getsockopt status and the value";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Raw i64 status of getsockopt(ctx, level, optname, &value, 4) and the i32 value. For the options of the closed table a failing status reads 0: the kernel zeroes the buffer on its ordinary paths and leaves it unwritten at the sock_ops lock gate (7.1.8 and 7.3.1), where the compiler's zero initialization shows (source reading; the gate path is not measured). Read the value only after checking the status.
    **Constraints**: Own sock_ops entry context (OPS `sock_ops.sockopt`), outside loops, static functions and helper callbacks. `option` is one of so_sndbuf, so_rcvbuf, so_mark, ip_tos, tcp_maxseg, tcp_window_clamp; the set-only tcp_bpf_iw and tcp_bpf_sndcwnd_clamp and any other name are rejected.
    **Lowering**: Stage ③ writes 0 to a 4-byte stack slot, calls helper getsockopt once with UAPI level and optname and size 4, then loads the slot. Requirements carry the existing helper row.
    **Evidence**: Out of scope — no release F row yet; static checks cover it, and a separate run covers it in VMs on 7.3.1, 7.1.8, 6.12.111 and 6.6.157 as root against an independent C oracle over IPv4 loopback TCP: the status and the value after a set of each of the 6 options, and -EINVAL with value 0 for request sockets, all matched. The zero initialization at the sock_ops lock gate is not measured.
    **Unsupported**: TCP_BPF_SYN* and other partial-copy or buffer options, string options, non-i32 values, other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, StrAttr:$option);
  let results = (outs I64:$status, I32:$value);
  let assemblyFormat = "$ctx $option attr-dict `:` type($ctx) `->` type($status) `,` type($value)";
  let hasVerifier = 1;
}

def EBPF_SockOpsSetsockoptNameOp : EBPF_Op<"sock_ops.setsockopt_name"> {
  let summary = "Set a string socket option to a constant name from a sock_ops program, returning raw bpf_setsockopt status";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Raw i64 status of setsockopt(ctx, level, optname, name, length + 1): 0 or a negative errno. The kernel resolves the name: an unregistered name, and `cdg` on every measured source, are negative statuses. A BPF program never loads a module for the name.
    **Constraints**: Own sock_ops entry context (OPS `sock_ops.sockopt`), outside loops, static functions and helper callbacks. `option` is `tcp_congestion`, the only row of the closed table. `literal` is 1..15 bytes with no NUL and no control character (0x01-0x1f, 0x7f). 15 is the compiler's conservative limit, not a kernel contract: TCP_CA_NAME_MAX is not UAPI, and the kernel silently truncates a longer name.
    **Lowering**: Stage ③ writes the name and its NUL to a stack buffer and calls helper setsockopt once with UAPI level and optname and optlen = length + 1. Requirements carry the existing helper row.
    **Evidence**: Out of scope — no release F row yet; static checks cover it, and a separate run covers it in VMs on 7.3.1, 7.1.8, 6.12.111 and 6.6.157 as root against an independent C oracle over IPv4 loopback TCP at `ACTIVE_ESTABLISHED_CB`: setting `reno` returned 0 and userspace `getsockopt(TCP_CONGESTION)` read `reno` (control `cubic`), `cdg` returned -524, unregistered 9-byte, 1-byte and 15-byte names returned -2. The 15-byte name is a load-and-call observation only; the length evidence is the ELF.
    **Unsupported**: reading a string option, a name that is not a constant, SO_BINDTODEVICE, other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, StrAttr:$option, StrAttr:$literal);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx $option `name` $literal attr-dict `:` type($ctx) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_SockAddrSetsockoptOp : EBPF_Op<"sock_addr.setsockopt"> {
  let summary = "Set an integer socket option from a cgroup_sock_addr connect4 or bind4 program, returning raw bpf_setsockopt status";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Raw i64 status of setsockopt(ctx, level, optname, &value, 4): 0 or a negative errno, as `ebpf.sock_ops.setsockopt`.
    **Constraints**: Own cgroup_sock_addr entry context (OPS `sock_addr.sockopt`) of a program with an explicit `attach "connect4"` or `attach "bind4"`, outside loops, static functions and helper callbacks; the compiler opens only those two measured attaches. `option` is one of so_sndbuf, so_rcvbuf, so_mark, ip_tos, tcp_maxseg, tcp_window_clamp, tcp_bpf_iw, tcp_bpf_sndcwnd_clamp; any other name is rejected. The value is i32.
    **Lowering**: Stage ③ spills value to a 4-byte stack slot and calls helper setsockopt once with UAPI level and optname and size 4. Requirements carry the existing helper row.
    **Evidence**: Out of scope — no release F row yet; static checks cover it, and a separate run covers it in VMs on 7.3.1, 7.1.8, 6.12.111 and 6.6.157 as root against an independent C oracle over IPv4 loopback TCP on connect4 and bind4: status 0 and the userspace value for the 6 readable options, -EINVAL for invalid `tcp_bpf_iw` / `tcp_bpf_sndcwnd_clamp`, and the call kept when the status is unused. `tcp_bpf_iw` and `tcp_bpf_sndcwnd_clamp` are observed by status only.
    **Unsupported**: other attaches and an omitted attach, TCP_NODELAY, string options, non-i32 values.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, StrAttr:$option, I32:$value);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx $option `,` $value attr-dict `:` type($ctx) `,` type($value) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_SockAddrGetsockoptOp : EBPF_Op<"sock_addr.getsockopt"> {
  let summary = "Read an integer socket option from a cgroup_sock_addr connect4 or bind4 program, returning raw bpf_getsockopt status and the value";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Raw i64 status of getsockopt(ctx, level, optname, &value, 4) and the i32 value, as `ebpf.sock_ops.getsockopt`.
    **Constraints**: Own cgroup_sock_addr entry context (OPS `sock_addr.sockopt`) of a program with an explicit `attach "connect4"` or `attach "bind4"`, outside loops, static functions and helper callbacks. `option` is one of so_sndbuf, so_rcvbuf, so_mark, ip_tos, tcp_maxseg, tcp_window_clamp; the set-only tcp_bpf_iw and tcp_bpf_sndcwnd_clamp and any other name are rejected.
    **Lowering**: Stage ③ writes 0 to a 4-byte stack slot, calls helper getsockopt once with UAPI level and optname and size 4, then loads the slot. Requirements carry the existing helper row.
    **Evidence**: Out of scope — no release F row yet; static checks cover it, and a separate run covers it in VMs on 7.3.1, 7.1.8, 6.12.111 and 6.6.157 as root against an independent C oracle over IPv4 loopback TCP on connect4 and bind4: status 0 and values equal to userspace for the 6 options, except `tcp_maxseg` after connect4 (get 1200, userspace 1188; bind4 reads 1200 for both).
    **Unsupported**: other attaches and an omitted attach, partial-copy or buffer options, string options, non-i32 values.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, StrAttr:$option);
  let results = (outs I64:$status, I32:$value);
  let assemblyFormat = "$ctx $option attr-dict `:` type($ctx) `->` type($status) `,` type($value)";
  let hasVerifier = 1;
}

def EBPF_SkbNetnsCookieOp : EBPF_Op<"skb.netns_cookie"> {
  let summary = "Raw network-namespace cookie of the skb's socket (get_netns_cookie)";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Raw i64 result of get_netns_cookie(ctx): the cookie of the skb socket's netns (init netns without a socket).
    **Constraints**: Own sched_cls entry context (OPS `skb.meta`), outside loops, static functions and callbacks. Kernel availability for sched_cls is a load-time requirement (the helper is offered to tc programs only by newer kernels — the compiler does not compare versions).
    **Lowering**: Call helper get_netns_cookie with the context.
    **Evidence**: F81. Static contracts; kernel execution is a separate measurement.
    **Unsupported**: Other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx);
  let results = (outs I64:$cookie);
  let assemblyFormat = "$ctx attr-dict `:` type($ctx) `->` type($cookie)";
  let hasVerifier = 1;
}

def EBPF_XdpBuffLenOp : EBPF_Op<"xdp.buff_len"> {
  let summary = "Raw total XDP buffer length including fragments (xdp_get_buff_len)";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Raw i64 result of xdp_get_buff_len(ctx): linear plus fragment bytes.
    **Constraints**: Own xdp entry context (OPS `xdp.bytes`), outside loops, static functions and callbacks.
    **Lowering**: Call helper xdp_get_buff_len.
    **Evidence**: F81. Static contracts; kernel execution is a separate measurement.
    **Unsupported**: Other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx);
  let results = (outs I64:$len);
  let assemblyFormat = "$ctx attr-dict `:` type($ctx) `->` type($len)";
  let hasVerifier = 1;
}

def EBPF_XdpLoadBytesOp : EBPF_Op<"xdp.load_bytes"> {
  let summary = "Read fixed XDP buffer bytes into a packed integer and return raw status";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Like `skb.load_bytes` for xdp: call xdp_load_bytes once into a compiler-owned buffer (including fragments). Byte j occupies bits 8j..8j+7 of the i64 value; higher bits are zero. Raw i64 status; the value is read on both status paths.
    **Constraints**: Own xdp entry context (OPS `xdp.bytes`), unsigned i32 offset, constant length 1..8, outside loops, static functions and callbacks.
    **Lowering**: Initialize eight stack bytes, call helper xdp_load_bytes with zero-extended offset and constant length, then pack exactly len bytes.
    **Evidence**: F81. Static contracts; kernel execution is a separate measurement.
    **Unsupported**: Variable length, arbitrary destinations, other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$offset, I64Attr:$len);
  let results = (outs I64:$value, I64:$status);
  let assemblyFormat = "$ctx `,` $offset `len` $len attr-dict `:` type($ctx) `,` type($offset) `->` type($value) `,` type($status)";
  let hasVerifier = 1;
}

def EBPF_XdpStoreBytesOp : EBPF_Op<"xdp.store_bytes"> {
  let summary = "Write fixed bytes into the XDP buffer and return raw status";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Like `skb.store_bytes` for xdp: write exactly len bytes of the value (little-endian byte order of the integer) at an unsigned offset via xdp_store_bytes (including fragments). Packet pointers stay valid, but the op writes packet bytes and is outside the packet-neutral whitelist (C1 / W1 do not cross it).
    **Constraints**: Own xdp entry context (OPS `xdp.bytes`), outside loops, static functions and callbacks. Constant len/type pairs 1/i8, 4/i32, 6/i64, 8/i64.
    **Lowering**: Store len bytes into a stack slot (all bytes written before the call), then call helper xdp_store_bytes(ctx, zext offset, slot, len).
    **Evidence**: F81. Static contracts; kernel execution is a separate measurement.
    **Unsupported**: Runtime lengths, record sources, other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$offset, AnyInteger:$value, I64Attr:$len);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $offset `,` $value `len` $len attr-dict `:` type($ctx) `,` type($offset) `,` type($value) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_FibLookupOp : EBPF_Op<"fib.lookup"> {
  let summary = "Look up the kernel FIB with a 64-byte record and return a readonly output record and the raw status";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Call fib_lookup (helper 69) once on a compiler-owned 64-byte copy of the input record, with plen = sizeof(struct bpf_fib_lookup) and flags 0 (`"none"`) or BPF_FIB_LOOKUP_DIRECT (`"direct"`). The first result is the helper-written copy, readable only with `ebpf.record.field`; the input record is never modified. The second result is the raw i64 status (0 success, positive FIB reasons, negative errno) — it is not converted to a predicate, and a nonzero status leaves whatever bytes the kernel wrote.
    **Constraints**: Own xdp entry context (OPS `fib.lookup`), directly in the program body, `ebpf.if` or `packet.check` regions — not inside loops, static functions, helper callbacks or other regions. The input is an `ebpf.record.make` result; the output is used only by `ebpf.record.field`. Flags are exactly `"none"` or `"direct"`. The record's schema declaration must be the exact 64-byte view of struct bpf_fib_lookup (the UAPI table's `fibfield` rows; ebpf-verify-records checks names, offsets and types).
    **Lowering**: Stage ③ allocates a 64-byte stack buffer aligned to 8, copies the input record into it, calls fib_lookup(ctx, buffer, plen, flags) with plen and the flag value from the UAPI table, and binds the output record to the buffer. The call has no memory attributes and remains when the status is unused. Requirements: the helper row and one `fibflags <program> <none|direct> <mask>` row per program and flag.
    **Evidence**: F82. static contracts (compile, lowering, ELF and requirements); kernel execution, flags probes and packet delivery are measured separately.
    **Unsupported**: sched_cls and other kinds, flags other than none / direct (MARK, VLAN, OUTPUT, SKIP_NEIGH, TBID, SRC), dynamic flags, map values or borrowed records as input, multi-buffer packets.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, EBPF_RecordType:$input, StrAttr:$flags);
  let results = (outs EBPF_RecordType:$output, I64:$status);
  let assemblyFormat = "$ctx `,` $input `flags` $flags attr-dict `:` type($ctx) `,` type($input) `->` type($output) `,` type($status)";
  let hasVerifier = 1;
}

def EBPF_RecordFieldOp : EBPF_Op<"record.field"> {
  let summary = "Read one integer leaf of an ebpf.fib.lookup output record";
  let description = [{
    **Stage**: ① Input
    **Meaning**: The reading entry for the output record of `ebpf.fib.lookup` and `ebpf.skb.get_tunnel_key` only (a closed list of producers). It reads one integer leaf (`"ifindex"`) or one element of a fixed array leaf at a constant index (`"src[3]"`, `"mac[11]"`) from the helper-written buffer, as raw bytes (no byte-order conversion). The result is an ordinary integer, so it may be yielded from regions.
    **Constraints**: The operand is the first result of `ebpf.fib.lookup` or `ebpf.skb.get_tunnel_key` (a closed list; reading by the first producer type is not widened) — not a `record.make` result, a map value or another record. The path names a leaf of the record declaration with a constant in-range index for arrays; the result type equals the declared element type (ebpf-verify-records). This op is not a general record reader: other records are a separate plan.
    **Lowering**: Stage ③ loads the declared width from the buffer at the leaf's @records offset, after the helper call.
    **Evidence**: F82. static contracts; kernel values are measured separately.
    **Unsupported**: Variable indices, nested records, whole-record reads, other producers.
  }];
  let arguments = (ins EBPF_RecordType:$record, StrAttr:$path);
  let results = (outs AnyInteger:$value);
  let assemblyFormat = "$record $path attr-dict `:` type($record) `->` type($value)";
  let hasVerifier = 1;
}

def EBPF_RedirectOp : EBPF_Op<"redirect",
    [Terminator, HasParent<"ProgramOp">]> {
  let summary = "Terminate with the bpf_redirect result (sched_cls or lwt_xmit)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: A sched_cls / lwt_xmit terminator returning the unmodified result of `redirect(ifindex, 0)`. This requests an action; it does not report delivery. Even a nonexistent ifindex returns REDIRECT while the packet is not delivered.
    In lwt_xmit, 7 (TC_ACT_REDIRECT) equals BPF_REDIRECT and causes post-program forwarding to the ifindex device. Its skb lacks an L2 header, so **redirect to a device with a MAC header (veth, dummy, etc.) is silently dropped by the kernel**, via −ERANGE in `__bpf_redirect_common`, despite appearing successful to the sender. Only headerless devices such as tun receive it.
    With `when %c else "<verdict>"`, false returns the verdict. Alternatively, `when %c fallback { ... }` executes its region only on the false edge. The else form is semantically a single-verdict fallback; its existing lowering is retained. Ifindex belongs to the program's netns.
    In sched_cls, optional `flags "egress"` explicitly selects the default zero flags; `flags "ingress"` selects BPF_F_INGRESS. Both still return the requested action, not delivery status.

    **Constraints**: HasParent<"ProgramOp"> restricts this terminator to the program's top-level body. The kind must have OPS marker `redirect` (sched_cls / lwt_xmit). `when` requires exactly one of `else` or `fallback`. The fallback has one block without arguments, containing only integer arithmetic and ending in verdict or verdict.if. Helpers, nested redirects, tail calls and nested regions are rejected. Verdicts must be valid for the kind (sched_cls pass / drop; lwt_xmit ok / drop).

    **Lowering**: Stage ② expands the conditional form into `cf.cond_br` and unconditional `ebpf.redirect` / `ebpf.verdict`, retaining the flags. For a fallback region, its operations move to the false-edge block and verdict.if expands normally. Stage ③ zero-extends ifindex, calls `redirect` with zero or the UAPI ingress flag, truncates the result to i32, and returns. A conditional form remaining at ③ is rejected.

    **Evidence**: F20. C oracle; program-kind checks; three-target and non-root measurements with nonexistent ifindex returning REDIRECT without delivery. F57: lwt_xmit test run and actual 7.1.8 netns route attach.

    in sched_cls, `via "neigh"` calls redirect_neigh(ifindex, NULL, 0, 0) (the kernel fills L2 from the neighbour table; OPS `redirect.neigh`) and `via "peer"` calls redirect_peer(ifindex, 0) (switch to the peer device's netns; OPS `redirect.peer`, only attach "ingress" — the kernel drops it at egress). `via` excludes `flags`; `when` / `else` / `fallback` combine as before. Both still return the requested action, not delivery status.

    **Unsupported**: XDP (use `ebpf.redirect_map`), redirect_neigh nexthop params, lwt_in / lwt_out (kernel warns and converts BPF_REDIRECT to OK), redirect inside regions, flags other than egress/ingress, explicit flags in lwt_xmit, and delivery-status observation. lwt_xmit cannot prepend L2 for MAC-header devices: no head-growth helper op exists.
  }];
  let arguments = (ins I32:$ifindex, Optional<I1>:$cond, OptionalAttr<StrAttr>:$else_action, OptionalAttr<StrAttr>:$flags, OptionalAttr<StrAttr>:$via);
  let regions = (region AnyRegion:$fallback);
  let assemblyFormat = "$ifindex `:` type($ifindex) (`flags` $flags^)? (`via` $via^)? (`when` $cond^)? (`else` $else_action^)? (`fallback` $fallback^)? attr-dict";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_RedirectMapOp : EBPF_Op<"redirect_map",
    [Terminator, HasParent<"ProgramOp">]> {
  let summary = "Terminate with bpf_redirect_map (XDP with devmap, devmap_hash, cpumap, or xskmap)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: An XDP terminator returning the unmodified result of `redirect_map(map, key, flags)`. Without flags, a present entry yields REDIRECT and an absent entry yields the fallback verdict. For devmap / devmap_hash, `redirect_flags = "broadcast"` selects all entries regardless of key; `"broadcast_exclude_ingress"` excludes ingress. Even an empty map returns REDIRECT for broadcast; this is distinct from delivery. Userspace supplies devmap ifindices; updating a nonexistent ifindex fails with **-EINVAL** on all three measured targets. A `when %c else "<verdict>"` form is also available.

    **Constraints**: A top-level terminator (HasParent<"ProgramOp">), only in XDP. Map kind must be devmap / devmap_hash / cpumap / xskmap, with matching i32 key and i32 value (ifindex / ifindex / qsize / AF_XDP socket fd respectively, supplied by userspace). Fallback is aborted / drop / pass / tx. redirect_flags is absent, broadcast, or broadcast_exclude_ingress, and may be set only for devmap / devmap_hash. Standalone exclude_ingress, unknown names, and broadcast on cpumap / xskmap are rejected. `when` requires `else` with an XDP verdict.
    checkMapKind rejects generic lookup / update / try_update / delete / try_delete / atomic_add on these four map kinds. Dedicated scalar lookups exist for devmap_hash / xskmap. A cpumap key is a CPU number: that CPU's kthread turns the redirected frame into an skb and passes it to the original device's stack. A devmap_hash key is a hash key rather than an index. An xskmap key is an RX queue number; delivery requires the socket to be bound to the frame's device and queue.

    **Lowering**: Stage ② expands `when` into cf.cond_br and unconditional redirect / verdict operations, preserving redirect_flags. Stage ③ ORs the UAPI fallback verdict with optional broadcast / exclude flags, zero-extends key, calls redirect_map, truncates to i32, and returns. Instructions without redirect_flags remain unchanged.

    **Evidence**: F14, F60. C oracle; three-target and non-root tests for present / unset / nonexistent-ifindex / GRO-off paths. Actual 7.1.8 netns veth packets match C for cpumap / devmap_hash / xskmap. Non-root checks cover broadcast / conditional lowering / ABI, 4-byte MapSpec and existing requirements, and wide / signed / record rejection. On 7.1.8 own-netns veth native XDP, 24 four-byte C/ebpf arms match; six eight-byte arms are C-oracle only. Removing exclude_ingress is caught by ingress receive 1 versus expected 0. Requested flags 0 and actual RDONLY_PROG are distinguished.

    **Unsupported**: Non-XDP kinds; fallback redirect; generic map operations. Program lookups are limited to the dedicated devmap_hash / xskmap scalar ops. Eight-byte cpumap / devmap / devmap_hash values and compiler-side second-program attachment remain separate work; C-only measurements cover PASS / DROP and ordinary-XDP-fd rejection. Broadcast evidence is limited to 7.1.8 own-netns veth native XDP; 6.12 / 6.6, generic XDP, physical NICs, and hotplug are unmeasured. The cpumap / devmap_hash / xskmap extension is unverified on 6.12 / 6.6. cilium v0.22 reduces cpumap max_entries to the possible CPU count.
  }];
  let arguments = (ins AnyType:$map, I32:$key, StrAttr:$fallback, Optional<I1>:$cond, OptionalAttr<StrAttr>:$else_action, OptionalAttr<StrAttr>:$redirect_flags);
  let assemblyFormat = "$map `[` $key `]` `:` type($map) `,` type($key) `fallback` $fallback (`when` $cond^ `else` $else_action)? attr-dict";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_TailCallOp : EBPF_Op<"tail_call",
    [Terminator, HasParent<"ProgramOp">, NoRegionArguments]> {
  let summary = "bpf_tail_call: transfer without return on success, execute fallback only on failure (XDP with prog_array)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: An XDP terminator tail-calling the program in prog_array slot `index`. Success does not return; only failure executes the fallback region. The program cannot distinguish out-of-range, limit, or empty-slot failures.
    With `when %c else "<verdict>"`, false returns the verdict without attempting a tail call or executing fallback. Schema prog_array `slots` declares slots; the loader installs them (requirements `tailslot`).

    **Constraints**: HasParent<"ProgramOp"> restricts it to the top-level body: loops, packet.check, ref.check, and reservation regions are rejected. Requires XDP program / context and prog_array with i32 key / value. Fallback is one block ending in ebpf.verdict / ebpf.verdict.if and cannot contain tail_call. `when` requires `else` with an XDP verdict. checkMapKind rejects program-side prog_array lookup / update. Failed calls invalidate packet pointers; fallback packet reads must re-read ctx with packet.load.

    **Lowering**: Stage ② creates `ebpf.tail_call.try` followed by the fallback contents; `when` adds cond_br and a false-edge verdict. Stage ③ zero-extends index and calls tail_call, ignoring its return value.

    **Evidence**: F15. C oracle; fallback re-reads; three-target / non-root tests including version differences in counting the limit 33; binding slot contract; checks preventing stage-② tail_call.try bypasses.

    **Unsupported**: Non-XDP, nested region / fallback tail calls, multiple attempts in one program, and program-side prog_array reads / writes.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, AnyType:$map, I32:$index, Optional<I1>:$cond, OptionalAttr<StrAttr>:$else_action);
  let regions = (region SizedRegion<1>:$fallback);
  let assemblyFormat = "$ctx `,` $map `[` $index `]` `:` type($ctx) `,` type($map) `,` type($index) (`when` $cond^ `else` $else_action)? `fallback` $fallback attr-dict";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_StackKernelIdOp : EBPF_Op<"stack.kernel_id"> {
  let summary = "bpf_get_stackid: kernel stack ID or negative errno (fentry with stack_trace)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls `get_stackid(ctx, stack_trace, skip | reuse)` to record a kernel stack and return **raw** i64 status: ID ≥ 0 on success, negative errno otherwise. Depth ≤ skip gives −EFAULT (observed with skip 255). A different stack in the same hash bucket gives −EEXIST without reuse. **Even with reuse, the kernel allocates a new freelist element before releasing the old one**, so no free entry gives −ENOMEM (collision in a one-entry map; stackmap.c on 6.6.157 / 6.12.111 / 7.1.8). **Reuse silently reassigns the old ID to the later stack**: looking up an earlier event's ID returns the new stack. Without reuse, −EEXIST leaves the bucket unchanged. Collisions depend on stackmap.c jhash2, bucket count, and IPs including program addresses, so they vary by load. A downstream model matches three-kernel root measurements; those measurements were not run here. **Avoid reuse when looking up stacks later**: use a larger map and count −EEXIST. With skip 0, frame 0 is the helper return address and varies by call site. Userspace looks up the IP sequence by ID.

    **Constraints**: Only fentry program / context, including a static function's fentry context argument. Map type is `!ebpf.map<"stack_trace", i32, !ebpf.stack<D>>`, D ≥ 1; skip ≥ 0. D must equal schema's u64 value-array length (ebpf-verify-schema). Schema requires u32 key and flags 0. Other program-side uses of stack_trace are rejected, as are loop bodies.

    **Lowering**: Stage ③ calls get_stackid with skip and optional reuse_stackid. UAPI stackflag rows supply skip limits and reuse values; excessive skip is rejected at ③.

    **Evidence**: F27. C oracle; map / op tests; skip 255 −EFAULT; three targets and non-root.

    **Unsupported**: Use ebpf.stack.user_id for user stacks. No build-ID kernel stacks or non-fentry kinds. `D × 8 ≤ perf_event_max_stack` depends on the environment and is not checked at compile time.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, AnyType:$map, I64Attr:$skip, UnitAttr:$reuse);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $map `skip` $skip (`reuse` $reuse^)? attr-dict `:` type($ctx) `,` type($map) `->` type($status)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_StackUserIdOp : EBPF_Op<"stack.user_id"> {
  let summary = "bpf_get_stackid with BPF_F_USER_STACK: user stack ID or negative errno (uprobe, kprobe, or fentry with stack_trace)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls `get_stackid(ctx, stack_trace, skip | user_stack | reuse)` to record the current task's **user stack**, returning **raw** i64 status: ID ≥ 0 on success, negative errno otherwise. Collision / reuse behavior follows stack.kernel_id: reuse silently reassigns an old ID to the later stack. Frame 0 is the current user IP (the probed function's entry for uprobes), followed by caller return addresses.
    **x86_64 user unwinding uses frame pointers only**. For a binary without frame pointers, the kernel follows rbp as a frame chain. An unreadable value silently truncates the stack to the probed function; a readable value can produce **false frames** from writable data or heap addresses. Even build-ID maps report status valid for false frames in file mappings. **Depth 1 or a frame outside an executable (r-x) mapping can indicate missing frame pointers**; status valid does not establish correctness. Precheck cannot decide this because the target binary is loader input.
    **Build IDs**: The kernel reads build-ID notes only from ELF PT_NOTE segments. Go's internal linker places .note.gnu.build-id outside PT_NOTE, so all frames have status ip on three measured kernels. External linking (`-ldflags=-linkmode=external` or cgo) places it inside PT_NOTE and all measured frames have status valid on three kernels.

    **Constraints**: Matching program / context kind must be uprobe, kprobe, or fentry, including static-function context arguments. Map is `!ebpf.map<"stack_trace", i32, !ebpf.stack<D>>` or `!ebpf.stack_build_id<D>` (schema element `{"kind": "stack_build_id"}` paired with flags 32). D ≥ 1, skip ≥ 0, and D equals schema's value element count (ebpf-verify-schema). Not allowed in loop bodies.

    **Lowering**: Stage ③ calls get_stackid with skip, user_stack, and optional reuse_stackid. UAPI stackflag rows supply flag values and the skip limit; excessive skip is rejected at ③.

    **Evidence**: F27. Source / C oracle with frame-pointer and no-frame-pointer fixtures on three kernels; uprobe / fentry / kprobe differential tests on three kernels × two privilege levels; build-ID maps match C on three kernels × three privilege levels; IP fallback and false-frame / Go-build-ID measurements on three kernels.

    **Unsupported**: DWARF unwinding and frames beyond D. Non-root uprobe attachment requires CAP_SYS_ADMIN (loader condition).
  }];
  let arguments = (ins EBPF_ContextType:$ctx, AnyType:$map, I64Attr:$skip, UnitAttr:$reuse);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $map `skip` $skip (`reuse` $reuse^)? attr-dict `:` type($ctx) `,` type($map) `->` type($status)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_PerfOutputOp : EBPF_Op<"perf.output"> {
  let summary = "bpf_perf_event_output: zero or negative errno (fentry with perf_event_array and a fixed record)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls `perf_event_output(ctx, perf_event_array, current_cpu, &rec, sizeof rec)` to output a record to a perf ring. Returns **raw** i64 status: 0 on success, −ENOENT for an empty slot, −ENOSPC for ring overflow (observed).

    **Constraints**: Only fentry program / context, including a static function's fentry context argument. Map is `!ebpf.map<"perf_event_array", i32, i32>`. Data is an ebpf.record.make result (all bytes, zero padding). Its record name / size must equal schema's map `record` nominal payload declaration (ebpf-verify-schema). Schema requires max_entries 0 (loader substitutes possible CPU count) and flags 0. Other program-side uses of perf_event_array are rejected.

    **Lowering**: Stage ③ calls perf_event_output with UAPI `perfflag current_cpu`, record.make stack storage, and record size.

    **Evidence**: F28. C oracle; success / −ENOENT / overflow tests and correction of BuildBTF's max_entries 0 → 1 handling; three targets and non-root.

    **Unsupported**: Non-fentry kinds, explicit output CPU, and variable-length data. Compare lost / −ENOSPC counts only after draining and a successful flush on the same CPU.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, AnyType:$map, EBPF_RecordType:$record);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $map `,` $record attr-dict `:` type($ctx) `,` type($map) `,` type($record) `->` type($status)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_SkSelectReuseportOp : EBPF_Op<"sk.select_reuseport"> {
  let summary = "bpf_sk_select_reuseport: select a reuseport_sockarray, sockmap, or sockhash socket by key and return status (sk_reuseport only)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls `sk_select_reuseport(ctx, map, &key, 0)` to select the keyed socket for SO_REUSEPORT group lookup, returning **raw** i64 status. Success is 0; out-of-range / empty slots give −ENOENT; sockets in another group give −EPROTOTYPE / −EAFNOSUPPORT / −EBADFD (7.1.8 net/core/filter.c). Selection takes effect only when the program returns `pass`. Without selection, pass uses the kernel hash. Regardless of selection, `drop` discards UDP datagrams and treats TCP SYN as having no listener (ECONNREFUSED).

    **Constraints**: Context kind must have OPS marker sk.select_reuseport (sk_reuseport), including static-function context arguments. Map is `!ebpf.map<"reuseport_sockarray", i32, i32|i64>` with matching i32 key, or sockmap (i32 key) / sockhash (matching map key type). For the latter, the kernel returns −EINVAL for a socket outside the group. Flags are fixed at 0 and cannot be supplied. Other reuseport_sockarray lookup / update / delete / atomic_add uses are rejected, matching kernel check_map_func_compatibility. Not allowed in loop bodies.

    **Lowering**: Stage ③ stores key on the stack and calls sk_select_reuseport using the UAPI helper number and flags 0.

    **Evidence**: F43. Actual 7.1.8 netns UDP / TCP SO_ATTACH_REUSEPORT_EBPF matches C: selected receiver, empty-slot −ENOENT hash fallback, and drop. Listener-close migration moves accept-queue children to the selected listener; sockmap / sockhash selection is measured. Dedicated tests cover −ENOENT (empty / out-of-range / closed), −EINVAL (sockmap socket outside the group), −EPROTOTYPE / −EAFNOSUPPORT / −EBADFD; no-selection / errno pass uses hashing, drop ignores selection, and SO_DETACH_REUSEPORT_BPF prevents further execution.

    **Unsupported**: Reading ctx migrating_sk to distinguish migration from SYN selection (the migration measurement does not read ctx), and configurable flags.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, AnyType:$map, AnyType:$key);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $map `[` $key `]` attr-dict `:` type($ctx) `,` type($map) `,` type($key) `->` type($status)";
  let hasVerifier = 1;
}

// Pass sk_reuseport ctx sk/migrating_sk directly to get_socket_cookie
// without exposing socket pointers in IR.
def EBPF_SkReuseportCookieOp : EBPF_Op<"sk.reuseport_cookie"> {
  let summary = "Raw get_socket_cookie u64 for sk_reuseport ctx sk or migrating_sk (NULL yields zero)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads context pointer field `sk` (PTR_TO_SOCKET: the group lookup's socket, or closing listener during migration) or `migrating_sk` (PTR_TO_SOCK_COMMON_OR_NULL: migrating child, NULL during SYN selection), passes it directly to get_socket_cookie, and returns its **raw** i64 cookie, or 0 for NULL. The value uses the same sock_gen_cookie as userspace getsockopt(SO_COOKIE): 7.1.8 bpf_get_socket_ptr_cookie returns `sk ? sock_gen_cookie(sk) : 0`. Pointers never appear in IR, nor create ownership / borrows; the context-read socket pointer has no reference count and needs no release. A nonzero migrating_sk cookie directly identifies listener-close migration.

    **Constraints**: Context kind must have OPS marker sk.reuseport_cookie (sk_reuseport), including static-function context arguments. Field is exactly sk or migrating_sk; other fields are explicitly rejected (use ebpf.ctx.field for integer fields). Result is i64. Not allowed in loop bodies or the packet-neutral table: it calls get_socket_cookie, whose effects do not include pktinval.

    **Lowering**: Stage ③ performs one volatile eight-byte pointer load at ctx plus UAPI `ctxfield sk_reuseport_md <field>` offset, then calls get_socket_cookie using the UAPI number. The kernel's ARG_PTR_TO_BTF_ID_SOCK_COMMON | PTR_MAYBE_NULL accepts PTR_TO_SOCKET and nullable PTR_TO_SOCK_COMMON, so no NULL check is emitted. Requirements include only the helper row, not ctxaccess for pointer fields (capability tables omit pointer fields).

    **Evidence**: F63. In 7.1.8 child-netns own socket groups, C and ebpf match SO_COOKIE identities: selection sk belongs to the group and migrating_sk is 0; migration sk is the closed listener and migrating_sk is the accepted child. Swapping fields changes only predicted cases. 6.12 / 6.6 were not measured in this experiment.

    **Unsupported**: Pointee fields such as state / family (bpf_sock reads) and socket reference types. Cookies vary by run and serve as identity tokens.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, StrAttr:$field);
  let results = (outs I64:$cookie);
  let assemblyFormat = "$ctx $field attr-dict `:` type($ctx) `->` type($cookie)";
  let hasVerifier = 1;
}

// Sockmap/sockhash redirect terminals for sk_skb/sk_msg and updates for
// sock_ops; see descriptions in docs/reference/ebpf_ops.md.
def EBPF_SkRedirectOp : EBPF_Op<"sk.redirect",
    [Terminator, HasParent<"ProgramOp">]> {
  let summary = "Terminate with bpf_sk_redirect_map or bpf_sk_redirect_hash (sk_skb with sockmap or sockhash)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: An sk_skb terminator returning the unmodified result of `sk_redirect_map(skb, sockmap, key, flags)` or `sk_redirect_hash(skb, sockhash, &key, flags)`. A present socket sets skb's destination and returns SK_PASS; the kernel redirects to it. An absent socket or LISTEN TCP socket yields SK_DROP. `ingress` (BPF_F_INGRESS) queues to the destination socket's receive path; otherwise egress sends from it. Redirection is asynchronous on a workqueue: status accepts the request, not delivery. With `when %c else "<verdict>"`, false returns the verdict.

    **Constraints**: HasParent<"ProgramOp"> allows only the top-level body. Program / context kind must have OPS sk.redirect (sk_skb). Map is sockmap (i32 key) or sockhash (matching map key type); key type must match. `when` requires `else` with a kind-valid verdict.

    **Lowering**: Stage ② expands `when` into cf.cond_br, unconditional redirect, and verdict. Stage ③ passes a zero-extended key for sockmap or stack key slot for sockhash, with UAPI redirflag ingress or flags 0; it truncates helper result to i32 and returns.

    **Evidence**: F61. Actual 7.1.8 netns TCP pairs match C: ingress / egress reach different receivers and an empty slot yields SK_DROP without delivery.

    **Unsupported**: Non-sk_skb (sk_msg uses ebpf.msg.redirect), nested redirects, flags other than BPF_F_INGRESS, and vsock destinations.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, AnyType:$map, AnyType:$key, UnitAttr:$ingress, Optional<I1>:$cond, OptionalAttr<StrAttr>:$else_action);
  let assemblyFormat = "$ctx `,` $map `[` $key `]` (`ingress` $ingress^)? `:` type($ctx) `,` type($map) `,` type($key) (`when` $cond^ `else` $else_action)? attr-dict";
  let hasVerifier = 1;
}

def EBPF_SkRedirectRequestOp : EBPF_Op<"sk.redirect.request"> {
  let summary = "Request a socket redirect and continue with raw helper status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Request sk_redirect_map or sk_redirect_hash without terminating. The raw i64 status is SK_PASS on success and SK_DROP on failure. A successful request sets the destination and ingress flag; a failed request preserves an earlier successful destination and flag. The final pass verdict applies the last successful request; drop suppresses delivery. The kernel clears the destination before the next program execution. Status acknowledges a request, not delivery.

    **Constraints**: Only the entry context of an sk_skb program, sockmap with i32 key or sockhash with matching key type. Flags are zero or ingress. Multiple requests and bounded/unrolled loop bodies are allowed. Unknown effects preserve calls even when status is unused.

    **Lowering**: Stage ② preserves the operation and result through region expansion. Stage ③ calls helper52/72 with a zero-extended sockmap key or stack sockhash key, returning raw i64 without truncation or return.

    **Evidence**: F61. On 7.1.8, 20 C/MLIR pairs using own TCP sockets match raw status, post-request state and full payload, including destination/flag overwrite, failed-request preservation, final drop and next-skb clearing. Observations on each of 6.12.111 and 6.6.157 show 20 MLIR modes matching expectations and 16 complete C/MLIR pairs. Four C loop fixtures per older kernel are rejected as infinite loops (the IV address is passed to map update); those modes have no C oracle and are not differential successes.

    **Unsupported**: Static functions, helper callbacks, non-sk_skb contexts, arbitrary flags, and when syntax. The existing terminating sk.redirect keeps its own semantics.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, AnyType:$map, AnyType:$key, UnitAttr:$ingress);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $map `[` $key `]` (`ingress` $ingress^)? `:` type($ctx) `,` type($map) `,` type($key) `->` type($status) attr-dict";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_MsgRedirectOp : EBPF_Op<"msg.redirect",
    [Terminator, HasParent<"ProgramOp">]> {
  let summary = "Terminate with bpf_msg_redirect_map or bpf_msg_redirect_hash (sk_msg with sockmap or sockhash)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: An sk_msg terminator returning `msg_redirect_map(msg, sockmap, key, flags)` or `msg_redirect_hash(msg, sockhash, &key, flags)` unchanged. A present socket sets the message destination and yields SK_PASS. ingress queues to that socket's receive path; otherwise egress sends from it (TCP destinations only). Absent or LISTEN TCP sockets yield SK_DROP (sendmsg returns EACCES). A conditional `when %c else "<verdict>"` form is available.
    **The destination persists within one write**: msg->sk_redir is cleared only per write chunk by sk_msg_init. After ebpf.msg.apply_bytes limits a verdict, a subsequent run for the same write still redirects to the previous destination even if it returns pass (net/core/skmsg.c sk_psock_map_verd). Split writes to send the remainder through the original socket.

    **Constraints**: Same form as ebpf.sk.redirect, for program / context kind with OPS msg.redirect (sk_msg).

    **Lowering**: Stage ② follows ebpf.sk.redirect. Stage ③ calls msg_redirect_map with a zero-extended key or msg_redirect_hash with a stack key, uses UAPI redirflag flags, truncates to i32, and returns.

    **Evidence**: F61. Actual 7.1.8 netns TCP pairs match C for ingress / egress and empty-slot EACCES. Further C comparisons cover pass after apply retaining the previous destination within a write; apply extending beyond a write carries the destination into a later write without running the program; redirect / drop after pop.

    **Unsupported**: Non-sk_msg (sk_skb uses ebpf.sk.redirect), nested redirects, flags other than BPF_F_INGRESS, and msg_push_data (inserted bytes are not kernel-zeroed). apply / cork / pull / pop have separate ebpf.msg.* operations.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, AnyType:$map, AnyType:$key, UnitAttr:$ingress, Optional<I1>:$cond, OptionalAttr<StrAttr>:$else_action);
  let assemblyFormat = "$ctx `,` $map `[` $key `]` (`ingress` $ingress^)? `:` type($ctx) `,` type($map) `,` type($key) (`when` $cond^ `else` $else_action)? attr-dict";
  let hasVerifier = 1;
}

// sk_msg helpers apply/cork/pull/pop control verdict extent, buffering,
// direct windows and removed bytes. See docs/reference/ebpf_ops.md.
def EBPF_MsgApplyBytesOp : EBPF_Op<"msg.apply_bytes"> {
  let summary = "bpf_msg_apply_bytes: apply the sk_msg verdict to the next n bytes (raw status; always zero on 7.1.8)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls `msg_apply_bytes(msg, n)` to apply this run's pass / redirect / drop verdict to the first n bytes (u32), returning **raw** i64 status (always 0 in 7.1.8 / 6.12 / 6.6 source). Kernel tcp_bpf_send_verdict sends min(size, n) bytes and reruns the program for any remainder. If n exceeds the message, the verdict and destination carry into later writes until n bytes are consumed, without running the program; the kernel holds the destination socket reference. **The apply value persists across runs within one write**, because msg is cleared only per write chunk, even if later runs do not call apply. **Combined with drop, sendmsg returns `size − n` but delivers nothing** (`*copied -= tosend`); the caller must not interpret that return as delivered bytes.

    **Constraints**: Requires a program body with OPS msg.apply_bytes (sk_msg) and that program's entry context; static functions / callbacks are rejected. n is i32 (zero-extended as u32); result is i64. No ebpf.loop bodies. It does not invalidate packet pointers, but is not packet-neutral; C1 / W1 cannot cross it.

    **Lowering**: Stage ③ zero-extends n to i64 and calls msg_apply_bytes(ctx, n) using the UAPI helper number, returning status.

    **Evidence**: F61. On 7.1.8 child-netns TCP sockmap links, C matches: a 10-byte write with apply 4 runs three times at sizes 10 / 6 / 2; apply 100 preserves verdict / destination into the next write; apply 4 with drop returns 6 and delivers nothing.

    **Unsupported**: Non-sk_msg, loop bodies, combinations with cork or egress redirect. 6.12 / 6.6 have source-only evidence.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$bytes);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $bytes attr-dict `:` type($ctx) `,` type($bytes) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_MsgCorkBytesOp : EBPF_Op<"msg.cork_bytes"> {
  let summary = "bpf_msg_cork_bytes: buffer an sk_msg message until n bytes accumulate (raw status; always zero on 7.1.8)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls `msg_cork_bytes(msg, n)`. If message size is below n (u32), the kernel buffers it without sending or applying a verdict; sendmsg returns accepted bytes. A later write reaching n reruns the program on the complete buffered message. Returns **raw** i64 status, always 0 in source for all three versions. **Removing the socket from sockmap / sockhash discards buffered bytes**, without delivery (net/core/skmsg.c sk_psock_stop).

    **Constraints**: Same as ebpf.msg.apply_bytes: OPS msg.cork_bytes, entry context only, no loop bodies, i32 n and i64 result. Neither pktinval nor packet-neutral.

    **Lowering**: Stage ③ zero-extends n to i64, calls msg_cork_bytes(ctx, n), and returns status.

    **Evidence**: F61. C matches on 7.1.8: cork 8 buffers a 3-byte write returning 3; the next 5 bytes cause one 8-byte delivery; removing the socket from the map discards buffered bytes.

    **Unsupported**: Non-sk_msg and loop bodies. ENOSPC termination, combinations with apply, and buffered scatterlist element count / window length are unmeasured. 6.12 / 6.6 have source-only evidence.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$bytes);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $bytes attr-dict `:` type($ctx) `,` type($bytes) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_MsgPullDataOp : EBPF_Op<"msg.pull_data"> {
  let summary = "bpf_msg_pull_data: replace the direct sk_msg window with message range [start, end), returning status (invalidates packet pointers)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls `msg_pull_data(msg, start, end, 0)` to make the u32 range [start, end) contiguous. A single scatterlist element needs no copy; a range crossing elements is copied into a new page. Success sets the direct packet.check data / data_end window to **exactly [start, end)** and returns 0, without changing message contents. Failures return **raw** negative i64 errno: −EINVAL for end ≤ start or start / end outside the message, −ENOMEM for page allocation failure. Failure leaves the window unchanged. Flags are fixed at 0; the kernel rejects other values with −EINVAL.
    On success and failure the compiler invalidates packet pointers (UAPI pktinval; kernel verifier clears them after the helper). Re-read with a new packet.check / packet.load, which reloads ctx data / data_end.

    **Constraints**: Program body must have OPS msg.pull_data (sk_msg), and context must be its entry context; static-function context arguments are rejected. start / end are i32, zero-extended; they need not be constant because the kernel checks bounds and returns errno. Result is i64. No ebpf.loop bodies. At the stage-② exit, may-invalidate checking rejects packet.window_load and window-passing calls across this op. Packet-neutral C1 / W1 / packet-check rewrites cannot cross it, as with adjust_head / seg6 operations.

    **Lowering**: Stage ③ zero-extends start / end to i64 and calls msg_pull_data(ctx, start, end, 0) using the UAPI helper number. Status is returned. Later packet reads reload ctx data / data_end; packet.check lowering always reloads them.

    **Evidence**: F61. Actual 7.1.8 attach matches C: pull [2, 6) gives exactly four bytes starting at start; end ≤ start and out-of-message bounds give −EINVAL with the original window unchanged. Swapping operands changes only predicted cases.

    **Unsupported**: Non-sk_msg, loop bodies, cross-element copy paths, −ENOMEM, and copy-marked windows with NULL data (kTLS / splice). 6.12 / 6.6 have source-only evidence.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$start, I32:$end);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $start `,` $end attr-dict `:` type($ctx) `,` type($start) `,` type($end) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_MsgPopDataOp : EBPF_Op<"msg.pop_data"> {
  let summary = "bpf_msg_pop_data: remove message bytes [start, start + len) and return status (sk_msg; invalidates packet pointers)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls `msg_pop_data(msg, start, len, 0)` to remove the u32 byte range from both delivered data and message size, returning 0. Length 0 is a no-op returning 0. Failures return **raw** negative i64 errno: −EINVAL for start outside the message or start + len exceeding size; −ENOMEM when an interior removal has neither a free slot nor a page. After success, the direct window returns to **the entire first element**, not start. An interior pop splits an element, so the window may contain only its prefix (start minus element start bytes). Subsequent drop / redirect applies to the modified message. Flags are fixed at 0.
    Packet pointers are invalidated on success and failure (pktinval).

    **Constraints**: Same as ebpf.msg.pull_data: OPS msg.pop_data, entry context only, no loop bodies, i32 start / len, i64 result, old-window rejection, and packet-neutral C1 / W1 / packet-check rewrite barriers.

    **Lowering**: Stage ③ zero-extends start / len to i64, calls msg_pop_data(ctx, start, len, 0), and returns status.

    **Evidence**: F61. Actual 7.1.8 attach matches C: an interior pop leaves a one-byte prefix window, a leading pop exposes the entire remainder, −EINVAL, and post-pop drop (EACCES) / redirect affects the modified message.

    **Unsupported**: Non-sk_msg, loop bodies, cross-element pop, copy paths without a free slot, and −ENOMEM. No push operation: inserted bytes are not kernel-zeroed. 6.12 / 6.6 have source-only evidence.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$start, I32:$len);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $start `,` $len attr-dict `:` type($ctx) `,` type($start) `,` type($len) `->` type($status)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_SockMapUpdateOp : EBPF_Op<"sock.map_update"> {
  let summary = "bpf_sock_map_update or bpf_sock_hash_update: insert the sock_ops socket by key and return status (sock_ops only)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls `sock_map_update(skops, sockmap, &key, flags)` or sock_hash_update to insert the callback socket at key, returning **raw** i64 status (0 or negative errno). Errno depends on callback, map kind, flags, and previous state. In 7.1.8 net/core/sock_map.c, callbacks other than PASSIVE_ESTABLISHED / ACTIVE_ESTABLISHED / TCP_LISTEN give −EOPNOTSUPP; sockmap key ≥ max_entries gives −E2BIG; noexist with an existing key gives −EEXIST. Flags are any / noexist / exist. Closing a socket makes the kernel remove it from the map.

    **Constraints**: Context kind must have OPS sock.map_update (sock_ops), including static-function context arguments. Map is sockmap (i32 key) or sockhash (matching map key type). Key must match map key type; flags must be one of the three names. No loop bodies.

    **Lowering**: Stage ③ stores key on the stack and calls sock_map_update / sock_hash_update using UAPI helper numbers and updateflag values.

    **Evidence**: F61. Actual 7.1.8 child-cgroup sock_ops on child-process netns TCP pairs matches C for TCP_CONNECT_CB −EOPNOTSUPP, ESTABLISHED 0, −E2BIG, and noexist −EEXIST.

    **Unsupported**: Non-sock_ops and socket-field reads. XDP lookup / delete use dedicated types, with C agreement on 7.1.8 child-netns TCP pairs; 6.12 / 6.6 are unmeasured.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, AnyType:$map, AnyType:$key, StrAttr:$flags);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $map `[` $key `]` `flags` $flags attr-dict `:` type($ctx) `,` type($map) `,` type($key) `->` type($status)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_SpinRegionOp : EBPF_Op<"spin.region", [RecursiveMemoryEffects, NoRegionArguments]> {
  let summary = "Acquire a map value's bpf_spin_lock, execute a closed critical region, and release it";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Locks field $lock of a borrowed record map value, executes the region, and unlocks. There is one exit path, so forgetting unlock is structurally impossible. Concurrent updates preserve both fields (a == b == total count).

    **Constraints**: Only inside an ebpf.program body, not ebpf.func. %ref is a record borrow. Region has one block ending in valueless ebpf.yield. Only arith and ref.field.load / store on **the same %ref** are accepted. Helpers (including ktime), map ops, loops, nested spin.region, calls and other borrows are rejected; a call of a **global** ebpf.func is rejected by name (the kernel rejects a global call while a bpf_spin_lock is held — 6.12.111 / 7.1.8 / 7.3.1, and 6.6.157 rejects every call there; the compiler applies it on every version).
    ebpf-verify-records requires $lock to name a spin_lock field, rejects direct lock-field access (including lock.val), and rejects record.make of lock-bearing records. Kinds are xdp / fentry / fexit / tp_btf; other kinds are compiler unsupported in ebpf-verify-target-legality. A profile fact `map-with-spin-lock kprobe rejected` also adds a target-unsupported note. Schema permits only array values, one lock per record, and 4-byte-aligned lock offsets.

    **Lowering**: Stage ② expands to internal ebpf.spin.lock, body, ebpf.spin.unlock. Stage ③ calls spin_lock / spin_unlock on the value pointer plus @records lock-field offset. BTF uses `struct bpf_spin_lock { u32 val }`, sized by UAPI.
    On 7.1.8 fentry / fexit / tp_btf, own-child-cgroup / netns measurements filtered to own tgid give a=b=128 for parallel k=4 / N=32 and no C/ebpf difference. Missing-unlock C is verifier-rejected; omitting b causes mismatch. Actual 6.x ops are unmeasured.

    **Evidence**: F17, F31. C oracle rejects helpers under lock and missing unlock; host observations; three-target root / non-root tests; kprobe-family lock maps rejected on all three targets; target-legality and load gates; Go binding access holes.

    **Unsupported**: Other kinds (kprobe family also target-rejected), non-array maps, multiple locks per record, and coexistence with timer (schema rejection). No BPF_F_LOCK userspace updates; unflagged updates do not acquire the lock. Go bindgen exposes lock fields as inaccessible holes.
  }];
  let arguments = (ins EBPF_BorrowedType:$ref, StrAttr:$lock);
  let regions = (region SizedRegion<1>:$body);
  let assemblyFormat = "$ref $lock `:` type($ref) $body attr-dict";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_TimerInitOp : EBPF_Op<"timer.init"> {
  let summary = "Raw bpf_timer_init(&value->field, map, clock) status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Initializes a borrowed record map value's timer field with `bpf_timer_init(&value->field, map, clock)`, returning **raw** i64 status (0 / negative errno). A second init returns −EBUSY and leaves the timer initialized. The caller must check init == 0 before set_callback / start; ignoring status rearms the timer (C and ebpf mutations demonstrate this).

    **Constraints**: Only in ebpf.program bodies, not ebpf.func. %ref is a record borrow directly from map.lookup → ref.check present; $map is that same lookup map value. Clock is a clockid row of the UAPI table (monotonic, boottime). ebpf-verify-records checks the timer field. No loop bodies. Kinds are xdp / fentry / fexit / tp_btf and struct_ops in a sleepable sched_ext_ops member only (VerifySchema names the others); other kinds are compiler unsupported in target legality. Target-profile fact `map-with-timer <type> rejected` adds a target-unsupported note. Schema permits array values only, one timer per record, 8-byte-aligned offset, and no lock in the same record.

    **Lowering**: Stage ③ calls timer_init(value pointer + @records timer offset, &map, clock), with the clock from the UAPI clockid row (monotonic 1, boottime 7).
    On 7.1.8 fentry / fexit / tp_btf in own child cgroup / netns filtered to own tgid, first init / callback / start status is 0, second init is −EBUSY, and C/ebpf agree. Actual 6.x ops are unmeasured.

    **Evidence**: F18, F31. C oracle for −EBUSY, unstarted / no-callback / invalid-clock statuses; ELF shape and host observations; three-target root / non-root; kprobe timer maps rejected on 6.x but accepted on 7.1.8; target-legality and load gates.

    **Unsupported**: Clocks outside the UAPI table, non-array maps, other program kinds (struct_ops outside sleepable sched_ext_ops members), and direct measurement of callback contents after last uref close (own IDs disappear within five seconds). Go bindgen exposes timer fields as inaccessible holes; userspace updates stop running timers.
  }];
  let arguments = (ins EBPF_BorrowedType:$ref, StrAttr:$field, EBPF_MapType:$map, StrAttr:$clock);
  let results = (outs I64:$result);
  let assemblyFormat = "$ref $field `,` $map `clock` $clock attr-dict `:` type($ref) `,` type($map) `->` type($result)";
  let hasVerifier = 1;
}
// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_TimerSetCallbackOp : EBPF_Op<"timer.set_callback"> {
  let summary = "Raw bpf_timer_set_callback(&value->field, callback) status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Binds callback @cb (ebpf.timer.callback) to a borrowed record's timer via bpf_timer_set_callback, returning **raw** i64 status (0 / negative errno). Repeating set_callback / start without checking init status succeeds even after −EBUSY and fires the timer again, as shown by C / ebpf mutations.

    **Constraints**: Shares timer.init checks: program body, record borrow directly from map.lookup. $callback names an ebpf.timer.callback whose record equals %ref's record and whose map @m equals the originating lookup map. Field checking, loop exclusion, and target-legality kind restrictions follow timer.init.

    **Lowering**: Stage ③ calls timer_set_callback(value pointer + timer offset, &callback). Callback address relocates into .text. Requirements traverse the set_callback addressof edge to include callback-only helpers in the program's rows.
    On 7.1.8 fentry / fexit / tp_btf, callback fires with count1 and fired_ns inside the MONOTONIC range; C/ebpf agree. Callback helper set is unchanged; actual 6.x ops are unmeasured.

    **Evidence**: F18, F31. C no-callback start −EINVAL; callback relocation / BTF shape; three targets; callback-only helper requirement reachability.

    **Unsupported**: Callback must be an ebpf.timer.callback in the same ELF, not a subprogram or bpf_loop callback. Kinds other than xdp / fentry / fexit / tp_btf are compiler unsupported.
  }];
  let arguments = (ins EBPF_BorrowedType:$ref, StrAttr:$field, FlatSymbolRefAttr:$callback);
  let results = (outs I64:$result);
  let assemblyFormat = "$ref $field `,` $callback attr-dict `:` type($ref) `->` type($result)";
  let hasVerifier = 1;
}
// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_TimerStartOp : EBPF_Op<"timer.start"> {
  let summary = "Raw bpf_timer_start(&value->field, nsecs, 0) status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Starts a borrowed record's timer one-shot after relative nsecs via timer_start(&value->field, nsecs, 0). Returns **raw** i64 status (0 / negative errno). Without start it does not fire; without a callback, start gives −EINVAL.

    **Constraints**: Shares timer.init checks; nsecs is i64. Field checking, loop exclusion, and kind restrictions follow timer.init. Inside ebpf.timer.callback, only the **callback block argument's own map value timer** may be started (periodic timer, with an ebpf.if bound); program behavior is unchanged.

    **Lowering**: Stage ③ calls timer_start(value pointer + timer offset, nsecs, 0). Flags are constant 0.
    On 7.1.8 fentry / fexit / tp_btf, one-shot count1 / armed1 stays stable for 200 ms; firing after detach and ID disappearance after last own uref close were observed with C/ebpf agreement. Direct callback observation after close and actual 6.x ops are outside that measurement.

    **Evidence**: F18, F31. C one-shot persistence and unstarted / no-callback status; host C agreement; three-target root / non-root; callback timestamp inequalities; own-timer callback restart with bounded N and an unbounded mutation stopped by last uref close, measured on XDP on three kernels.

    **Unsupported**: Flags other than 0 (no ABS / CPU_PIN); cancel is ebpf.timer.cancel. A second program-side start (rearm) is a negative control. Periodic own-timer restart has three-kernel evidence only for XDP. Other than xdp / fentry / fexit / tp_btf, kinds are compiler unsupported.
  }];
  let arguments = (ins EBPF_BorrowedType:$ref, StrAttr:$field, I64:$nsecs);
  let results = (outs I64:$result);
  let assemblyFormat = "$ref $field `,` $nsecs attr-dict `:` type($ref) `,` type($nsecs) `->` type($result)";
  let hasVerifier = 1;
}
// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_TimerCancelOp : EBPF_Op<"timer.cancel"> {
  let summary = "Raw bpf_timer_cancel(&value->field) status (also drops the timer's callback)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls timer_cancel(&value->field) on a borrowed record's timer and returns the **raw** i64 result: 0 = the timer was not pending (never started, or already fired), 1 = it was pending and is now cancelled, negative errno otherwise (-EINVAL for a timer never initialized; -EOPNOTSUPP in NMI / deferred contexts; -EDEADLK for cancelling from a callback, outside this op's scope). **Cancel is not "stop and keep the callback"**: the kernel drops the timer's callback and program reference, so a later timer.start returns -EINVAL until ebpf.timer.set_callback succeeds again (ebpf.timer.init is not needed again).

    **Constraints**: Same borrow, map, field, loop and program-kind rules as timer.start. Allowed only in a program body: inside ebpf.timer.callback it is rejected. The call is never removed even if the result is unused (it changes timer state). timer_cancel is a GPL-only helper like the other timer helpers.

    **Lowering**: Stage ③ calls timer_cancel(value pointer + timer offset). The helper number is the UAPI table's. Requirements record the helper through the existing helper rows (no new row kind).

    **Evidence**: F18 (timer family). No measurement of cancel yet: plans a C differential on four kernels.

    **Unsupported**: Cancel inside ebpf.timer.callback, cancelling another timer, waiting for a running callback, and any claim after the last map userspace reference is closed (the timer is reclaimed then; link detach alone does not cancel it).
  }];
  let arguments = (ins EBPF_BorrowedType:$ref, StrAttr:$field);
  let results = (outs I64:$result);
  let assemblyFormat = "$ref $field attr-dict `:` type($ref) `->` type($result)";
  let hasVerifier = 1;
}
// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_TimerCallbackOp: EBPF_Op<"timer.callback", [IsolatedFromAbove, Symbol]> {
  let summary = "Timer callback with restricted map-value access and arithmetic";
  let description = [{
    **Stage**: ① Input

    **Meaning**: A timer-specific callback symbol at module top level, separate from a bpf_loop callback. `map @m : !ebpf.record<…>` declares its map and record. Its single block argument borrows the value; the kernel calls it when the timer fires. Terminates with ebpf.timer.done.

    **Constraints**: One block, exactly one !ebpf.borrowed<record> argument, and timer.done terminator. Only arith, ref.field.load / store on that argument, ebpf.ktime.ns, **ebpf.timer.start on that argument's own timer**, and wrapping ebpf.if are accepted; nested regions use the same allowed set. Other helpers, timer.init / set_callback, map operations, and loops are rejected. timer.start explicitly rejects a ref other than the callback block argument. When every owner (a program whose set_callback names it) is struct_ops — sleepable sched_ext_ops members — the callback also accepts ebpf.call and the closed set of ScxAny ops in ScxContract.h kScxTimerCallbackOps; struct_ops owners mixed with other kinds are rejected. ** For sched_ext_ops owners the body also takes the ebpf.func body op set**: kfunc.call and kref.check, iter.num, iter.scx_dsq and rcu.region (closed inside the callback), the kptr ops (kptr.xchg / kptr.load_rcu on its map value, global.kptr_xchg / global.kptr_load_rcu, kptr.check, kfield.load / kfield.ptr), the global ops (global.load / store / ref / atomic_add / cmpxchg / atomic_or) and field ops on any borrowed record (a global record borrow too); nested regions use the same set. Map ops stay out (no `maps` — a function the callback calls may use them). **The callback context** (the callback body and every function it reaches, also through 2 or more calls) is **not sleepable and assumes no RCU** — 7.3.1 / 7.1.8 never run a timer callback sleepable, while 6.12.111 runs a sleepable owner's callback sleepable (outside RCU), so the compiler takes the side every version accepts: may-sleep ops and KF_SLEEPABLE kfuncs (scx.create_dsq, ...) are rejected, and the RCU-dependent ops (iter.scx_dsq, kptr.load_rcu, global.kptr_load_rcu, task_struct.cpus_ptr) need an explicit ebpf.rcu.region held at the op (the callback's own, or a caller's when every call on the way to the op is static — a global function does not inherit its caller's section). A sched_ext op is accepted only when it is in kScxTimerCallbackOps **and**, if RCU-dependent, inside a held rcu.region; **kScxTimerCallbackOps is a conservative subset of the compiler, not the kernel's filter** (7.3.1 / 7.1.8's scx kfunc filter looks at the program only and applies the owner member's table to the callback too) — scx.cpu_curr / scx.dsq_peek stay outside it also inside rcu.region, and scx.dump, the task-argument ops and the member-only ops stay out. The owner's context (member table, sleepable flag) never flows into the callback. trace.printk stays rejected (also through calls). The program-body placement / ownership rules (call sites inside if_reserved / packet.check / ebpf.loop / scf.if / iterator bodies, live references across a call to an iterator — only ebpf.iter.scx_dsq for a reference, ebpf.iter.num being accepted) hold with the same text in the callback body and in the functions it reaches: the op verifiers, ebpf-verify-ownership, ebpf-verify-call-contexts and ebpf-verify-schema walk the callback body as a top, one context per owner. A non-sched_ext owner's callback keeps the base set. ebpf-verify-records rejects direct timer / spin_lock field accesses. Stage ③ rejects callbacks unused by any program's set_callback. This is a permitted top-level ebpf-compile input.

    **Lowering**: Stage ③ emits an internal/static .text llvm.func `(ptr map, ptr key, ptr value) -> i32`; the body uses the third argument. BTF is static FUNC `cb(void *map, <key type> *key, struct <R> *value) -> int`, matching C rather than the bpf_loop callback shape. The callback is a root of stage ②'s reachability (a function a program calls only inside an N = 0 loop body and the callback calls is kept) and of ebpf-verify-structured's frame check; the kfunc / helper rows of the callback and the functions it reaches go to every owner program's requirements rows.
    On 7.1.8 fentry / fexit / tp_btf, callback count1 and fired_ns within the MONOTONIC range match C. Helper set is not broadened; actual 6.x operations are unmeasured.

    **Evidence**: F18. Callback ELF / BTF shape and return-type correction; three-target tests; C callback ktime oracle; ktime.ns permission and requirement reachability; own-timer start and ebpf.if. lit only (compile, the requirements rows of two owners); no kernel load of the widened body.

    **Unsupported**: Map and key arguments cannot be used. Helpers other than ktime (and the explicitly allowed own timer restart) are rejected in a non-sched_ext owner's callback. Callbacks of programs outside xdp / fentry / fexit / tp_btf / struct_ops (sleepable sched_ext_ops members) are compiler unsupported; for struct_ops owners the callback calls run on (is compile only). ebpf.loop, ring buffer ops, trace.printk and the sched_ext ops outside kScxTimerCallbackOps in the callback body.
  }];
  let arguments = (ins SymbolNameAttr:$sym_name, FlatSymbolRefAttr:$map, TypeAttr:$record);
  // High-level form has one block; stage 2 can have multiple blocks after
  // expanding callback ebpf.if regions. The op verifier checks the shape.
  let regions = (region AnyRegion:$body);
  let assemblyFormat = "$sym_name `map` $map `:` $record attr-dict-with-keyword $body";
  let hasVerifier = 1;
}
def EBPF_TimerDoneOp : EBPF_Op<"timer.done", [Terminator, HasParent<"TimerCallbackOp">]> {
  let summary = "End a timer callback by returning zero";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Terminates ebpf.timer.callback, returning 0 as required by the verifier contract.

    **Constraints**: HasParent permits only ebpf.timer.callback. It must be the callback block's last operation, checked by the callback verifier. No operands.

    **Lowering**: Stage ③ emits llvm.return with i32 constant 0.

    **Evidence**: F18. Return type corrected to C's int; corrected ELF rerun on three targets.

    **Unsupported**: Nonzero return values.
  }];
  let assemblyFormat = "attr-dict";
}

// Internal stage-2 spin lock/unlock uses value pointer plus lock-field offset;
// only ebpf-expand-regions creates it.
def EBPF_SpinLockOp : EBPF_Stage2Op<"spin.lock", "ebpf.spin.region (closed critical region)"> {
  let summary = "bpf_spin_lock (stage ② internal)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Acquires a borrowed record's spin-lock field.

    **Constraints**: Only at the start of stage-② spin.region expansion, paired with ebpf.spin.unlock around the body.

    **Lowering**: Stage ③ calls spin_lock with the lock field address.

    **Evidence**: Internal — generated by ebpf-expand-regions from stage-① ebpf.spin.region. ebpf-compile rejects it in source input, preventing bypass of stage-① restrictions. The input op owns feature-path evidence.

    **Unsupported**: Not writable in input; use stage-① ebpf.spin.region for a closed critical region.
  }];
  let arguments = (ins EBPF_BorrowedType:$ref, StrAttr:$lock);
  let assemblyFormat = "$ref $lock `:` type($ref) attr-dict";
}
def EBPF_SpinUnlockOp : EBPF_Stage2Op<"spin.unlock", "ebpf.spin.region (closed critical region)"> {
  let summary = "bpf_spin_unlock (stage ② internal)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Releases a borrowed record's spin-lock field.

    **Constraints**: Only at the end of stage-② spin.region expansion.

    **Lowering**: Stage ③ calls spin_unlock with the lock field address.

    **Evidence**: Internal — generated by ebpf-expand-regions from stage-① ebpf.spin.region. ebpf-compile rejects it in source input, preventing bypass of stage-① restrictions. The input op owns feature-path evidence.

    **Unsupported**: Not writable in input; use stage-① ebpf.spin.region.
  }];
  let arguments = (ins EBPF_BorrowedType:$ref, StrAttr:$lock);
  let assemblyFormat = "$ref $lock `:` type($ref) attr-dict";
}

// Stage-2 helper call is not a terminator: success never returns, so
// subsequent operations in the block are fallback only.
def EBPF_TailCallTryOp : EBPF_Stage2Op<"tail_call.try", "ebpf.tail_call ... fallback { ... } (top-level program-body terminator)"> {
  let summary = "bpf_tail_call attempt (stage ②; only failure continues)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: A nonterminal tail-call attempt. Success never returns; failure (out-of-range / limit / empty slot, indistinguishable to the program) continues into the original fallback contents.

    **Constraints**: In stage ②, the fallback contents immediately follow the original tail_call expansion. Failure invalidates packet pointers.

    **Lowering**: Stage ③ calls tail_call(ctx, prog_array, index).

    **Evidence**: Internal — generated by ebpf-expand-regions from `ebpf.tail_call ... fallback { ... }`. ebpf-compile rejects it as input; allowing it in regions would bypass stage-① restrictions. The input op owns feature-path evidence.

    **Unsupported**: Not writable in input; use stage-① ebpf.tail_call, a top-level program terminator.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, AnyType:$map, I32:$index);
  let assemblyFormat = "$ctx `,` $map `[` $index `]` `:` type($ctx) `,` type($map) `,` type($index) attr-dict";
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_SubprogramOp : EBPF_Op<"func", [IsolatedFromAbove, Symbol]> {
  let summary = "Directly called BPF subprogram (static or global)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: A BPF-to-BPF call target with static or global linkage. The kernel verifies static functions in caller context, but global functions independently from argument BTF types.
    At most five arguments: i8 / i16 / i32 / i64 or !ebpf.maybe_ref / !ebpf.borrowed pointing to such integers or records. **Static functions may also take !ebpf.pkt_window<N>**, passed from a caller's packet.check in_range region. Three-kernel verifier observations preserve packet pointers / bounds across static calls. A callee window may be used only by packet.window_load, packet.store (only if all reaching programs are XDP; stage ③ checks), or calls to other static functions. Global-window arguments are verifier-rejected: the kernel treats global pointer arguments as non-packet memory.
    **Static functions may take caller context !ebpf.ctx<"K">**. Three-kernel observations over seven kinds preserve PTR_TO_CTX. Context type fixes one callee kind. Permitted uses are packet.load / packet.check / stack.kernel_id / stack.user_id / perf.output and calls to other static functions. Attach-dependent ctx.arg / ctx.retval / kprobe.arg / uprobe.arg are explicitly rejected: checking one caller's schema would not cover callers attached elsewhere. Invalidating xdp.adjust_head / adjust_tail / tail_call are also rejected, as are global context arguments.
    Exactly one integer result is required. Entry arguments are followed by map handles corresponding by position to `maps [...]`.
    **Body ops and contexts** — besides the reference-argument ops, calls, arith, map ops and the global ops (global.load / store / ref / atomic_add / cmpxchg / atomic_or — already allowed), a static or global function body may hold the **context-dependent ops** kfunc.call (and kref.check), iter.num, iter.scx_dsq and rcu.region (each closed inside the function — never across a call), kptr.xchg / kptr.load_rcu on a map value the function looks up, global.kptr_xchg / global.kptr_load_rcu, trace.printk and the sched_ext ops. Such an op is accepted only when **every context that reaches the function** allows it as its owner's body would. A context is the owner program (its kind; its sched_ext_ops member and schema sleepable flag), the entry — the program body, an ebpf.timer.callback, a helper callback (a callback does not inherit its owner's context) — and the regions around the call sites on the way. Contexts pass through ebpf.call (`@p → @f → @g`: @g has every context of @f, adjusted at the call site): a call inside ebpf.rcu.region makes the callee not sleepable (the kernel's in_sleepable_context), so a may-sleep op / KF_SLEEPABLE kfunc there is rejected and an rcu.region there would nest (in a static callee — a global callee starts a fresh section, below); a call inside ebpf.loop / scf.if, an ebpf.iter.num body or an ebpf.iter.scx_dsq body applies those bodies' rules (and the ownership placement) to the callee's ops. **A global function does not inherit its caller's RCU section**: 7.1.8 / 6.12.111 / 6.6.157 verify a global function once with the program's sleepable flag (7.3.1 per call context), so an RCU-dependent op (kptr.load_rcu, global.kptr_load_rcu, iter.scx_dsq, task_struct.cpus_ptr, the RCU-section sched_ext ops) in a global function of a sleepable program — or in a static function reached through one — needs an ebpf.rcu.region in the global function's body; a caller's section counts only through static calls (verified on the caller's state). What the global boundary drops is the guarantee and the nesting rule (the verifier checks a global function from a fresh state, so a global function reached through a call inside ebpf.rcu.region may hold its own rcu.region; a nested bpf_rcu_read_lock is correct at run time): the constraint of the caller's section (no may-sleep op) and the placement / ownership marks carry on. ** A timer callback context** (a sched_ext_ops owner's ebpf.timer.callback and every function it reaches) is not sleepable and assumes no RCU: may-sleep ops and KF_SLEEPABLE kfuncs are rejected, the RCU-dependent ops need a held ebpf.rcu.region, the sched_ext ops are limited to ScxContract.h kScxTimerCallbackOps (a conservative compiler subset, not the kernel's filter; an RCU-dependent sched_ext op also needs a held section — scx.cpu_curr / scx.dsq_peek are outside the set), and trace.printk is rejected. A function no entry reaches has no context (ebpf-verify-call-graph rejects it). A single failing context is named per op (owner, kind, member, entry, call path, sleepable).

    **Constraints**: The op verifier rejects unknown linkage, six or more arguments, i1 / kptr or other unsupported argument types, non-single-integer results, global contexts, context after map handles, and exits other than ebpf.return. Reference arguments support ref.check / ref.load / ref.field.load / ref.store / ref.field.store / ref.atomic_add / ref.field.atomic_add and forwarding through ebpf.call. Passing an lpm_trie value to a writing callee, including transitively, is rejected; these values remain read-only in programs. Lock / timer fields follow program rules.
    **Global functions** — a `borrowed` argument whose record has a kptr, spin_lock or timer as a direct, non-array member is rejected by name in ebpf-verify-records — the kernel checks a global function's pointer argument as helper memory access and rejects such a field on every kernel (6.6.157 / 6.12.111 / 7.1.8 / 7.3.1, "Caller passes invalid args"). `maybe_ref` arguments, a special field in a nested record or array, cpumask fields and static functions are accepted (the kernel may accept them).
    ebpf-verify-call-graph requires no recursion, reachability from a program, and ≤ 8 frames. Loops in callees have path depth ≤ 2 from the program entry. The path product limit is 4096 when a bounded back edge is present and no helper callback is present; otherwise it is 64. Individual strategy limits still apply.
    The context-dependent ops: the op verifiers check what does not depend on the caller (types, the regions inside the function); **ebpf-verify-call-contexts** (after ebpf-verify-call-graph in ebpf-compile) checks the kind level per context — kfunc program types (also of iter.num / iter.scx_dsq / rcu.region's kfuncs), the OPS tags `scx` / `scx.dsq_reenq` / `trace.printk` / `sleepable`, the call path's regions above — and the timer callback context's rules, and rejects these ops in a function reached through a helper callback; **ebpf-verify-schema** checks the sched_ext_ops member table (scx_kf_allow_flags), KF_SLEEPABLE and SleepableOps.def ops only in a sleepable context, the RCU-section ops and sleepable-member kptr RCU reads / iter.scx_dsq / task cpus_ptr only outside one, dump only in the dump members and the generic sched_ext kfuncs only for sched_ext_ops owners. scx_bpf_task_cgroup is rejected in a function (no member task argument). A call of a global function inside ebpf.spin.region is rejected by name.

    **Lowering**: Stage ② expands bodies like programs and removes functions made unreachable by expansion. Stage ③ emits noinline .text llvm.func: internal for static, external for global. Global borrowed arguments carry arg:nonnull through BTF DECL_TAG and requirements argtag. The context-dependent ops lower as in a program body (the lowering uses no owner fact for them); their kfunc / helper rows go to every program that reaches the function (the requirements' call-graph reachability set).

    **Evidence**: F08. Three-target C noinline oracle; op / call graph / reference arguments; three-target arg:nonnull; record borrows; callee / callback loops; lit for static context arguments. lit only (compile, requirements rows of two owners); no kernel load. the timer callback context and the global-RCU correction are lit only (compile); whether 6.12.111 / 7.1.8 load them as predicted is unmeasured.

    **Unsupported**: Reservation, kptr, and pointer arguments except the static window / context cases; attach-dependent and invalidating callee operations; pointer returns; functions without results. spin.region and timer operations require program bodies. A function called from a loop cannot reach ring-buffer operations. Iterators, RCU sections and kernel references passed to or held across a call; the context-dependent ops in a function reached through a helper callback.
  }];
  let arguments = (ins SymbolNameAttr:$sym_name, StrAttr:$linkage,
                       TypeAttrOf<FunctionType>:$function_type,
                       OptionalAttr<SymbolRefArrayAttr>:$map_symbols);
  let regions = (region MinSizedRegion<1>:$body);
  let assemblyFormat =
      "$sym_name $linkage $function_type (`maps` $map_symbols^)? attr-dict-with-keyword $body";
  let hasVerifier = 1;
}

def EBPF_ReturnOp : EBPF_Op<"return", [Terminator, ParentOneOf<["SubprogramOp", "ProgramOp"]>]> {
  let summary = "Terminate by returning one integer from a subprogram or program";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Returns one integer from ebpf.func. Also terminates ebpf.program by returning a raw i32 for unnamed-verdict kinds: socket_filter retains that many bytes (0 drops, ≥ len retains all); syscall exposes BPF_PROG_TEST_RUN retval; fmod_ret calls the original function only for 0, otherwise substitutes the returned value; ext returns from the replacement function.

    **Constraints**: ParentOneOf accepts ebpf.func or ebpf.program, not a tail-call fallback. In a function, operand type must match the result type. In a program, kind must have VERDICTS `|int` (including socket_filter / syscall / fmod_ret, whose verifier does not impose a return range). Operand is i32, or i32 / i64 for ext and struct_ops as checked against schema ret (struct_ops i64 is for 64-bit members such as tcp_congestion_ops.get_info size_t; ③ then returns i64 and BTF gives the program the schema ret type, and a path ending in ebpf.verdict is rejected there). struct_ops members with schema ret void cannot contain ebpf.return. Out-of-range **constants** for `|int:<range>` are rejected: u32 means all 32 bits; lo..hi is signed. Nonconstant values are not range-checked here.

    **Lowering**: Unchanged in ②; stage ③ emits llvm.return, not a UAPI verdict. For kinds with negative range lower bounds (currently lsm), constant arms of a defining arith.select, recursively through arm selects, pass through an instruction-free inline-asm barrier (`"=r,0"`). This prevents the BPF backend folding `select c, -1, 0` to sign extension / BPF_NEG (`r = -r`), whose range the 6.12 verifier cannot track. The select becomes branches with constant R0 on each path.

    **Evidence**: F08, F40, F41, F47. Direct function return; syscall retval; fmod_ret replacement; socket_filter truncation matching C test-run retval; ext replacement return measured through its target XDP program's test run; LSM select returns matching C on actual 7.1.8 / 6.12.111 / 6.6.157 attach.

    **Unsupported**: Multiple or zero results. Kinds whose verifier enforces verdict ranges (XDP / cgroup family / iter / fentry etc.) use named ebpf.verdict instead.
  }];
  let arguments = (ins AnyType:$value);
  let assemblyFormat = "$value attr-dict `:` type($value)";
  let hasVerifier = 1;
}

def EBPF_CallOp : EBPF_Op<"call", [DeclareOpInterfaceMethods<SymbolUserOpInterface>]> {
  let summary = "Direct BPF-to-BPF call to an ebpf.func in the same module";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Directly calls an ebpf.func in the same module and returns the callee's integer result.

    **Constraints**: Symbol-use checking rejects absent callees, ebpf.program entries, non-functions, and argument / result type mismatches. ebpf-verify-call-graph rejects cycles and depth > 8 frames including entry (a conservative compiler limit), and rejects loop calls whose callee reaches ring-buffer operations. After stage ②, ebpf-verify-structured rechecks recursion and ≤ 8 frames across both calls and bpf_loop callback edges. Checked borrowed references may be passed only within ref.check present regions. A call passes each context of its caller — adjusted by the regions around the call: ebpf.rcu.region (not sleepable), ebpf.loop / scf.if, the iterator bodies, a helper callback — to the callee, where ebpf-verify-call-contexts and ebpf-verify-schema check the context-dependent ops (see ebpf.func); ebpf.spin.region rejects every call and names a call of a global function. A call does not bypass the program body's placement rules: the regions around the call site count as ancestors of the callee's ops — the sched_ext ops' allowlist of ancestors (a call inside ebpf.ringbuf.if_reserved, ebpf.packet.check, ebpf.ref.index, ... reaching an ebpf.scx.* op is rejected), scf.if around ebpf.iter.num / ebpf.rcu.region, and the loop body's allowlist (ebpf.rcu.region reached from an ebpf.loop body with no iterator body in between is rejected); two or more calls carry them. ebpf-verify-ownership rejects a call made while a ring buffer reservation (ebpf.ringbuf.if_reserved or reserve_dynptr) is live when the callee reaches, at any depth, ebpf.loop, ebpf.iter.num, ebpf.iter.scx_dsq or ebpf.rcu.region (the ops a live reservation may not cross), naming the callee, the call path and the op; a callee reaching none of them, and any call after the submit / discard, is accepted. A call into a **global** function drops only the RCU guarantee of a caller's ebpf.rcu.region (the kernel verifies a global function once with the program's sleepable flag) — the RCU-dependent ops of the callee need the callee's own section; the no-sleep constraint and the placement / ownership marks carry on, and a static callee keeps the caller's whole state. Calls from a sched_ext_ops owner's ebpf.timer.callback carry the timer callback context (not sleepable, no RCU unless a section is held, kScxTimerCallbackOps — see ebpf.timer.callback) to every function they reach.

    **Lowering**: Unchanged in ②. Stage ③ emits llvm.call, distinct from helper bpfabi.helper_call. Requirements record each program's call-graph reachability set.

    **Evidence**: F08, F09. Direct calls, calls inside loops, three-target loop / function tests, cross-function loops on three targets, and callback calls.

    **Unsupported**: Indirect calls, function pointers, helper names as callees, and out-of-module functions including kfuncs. The eight-frame compiler limit does not guarantee kernel acceptance.
  }];
  let arguments = (ins FlatSymbolRefAttr:$callee, Variadic<AnyType>:$args);
  let results = (outs Variadic<AnyType>:$results);
  let assemblyFormat =
      "$callee `(` $args `)` attr-dict `:` functional-type($args, $results)";
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_LoopOp : EBPF_Op<"loop", [RecursiveMemoryEffects, AttrSizedOperandSegments]> {
  let summary = "Bounded loop with constant count or runtime count clamped to it (integer carried values only)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Bounded loop with constant attribute N, i32 IV starting at 0 with step 1 and unsigned comparison. Integer iter_args carry values across iterations; results are final values. Optional i32 `bound(%n)` is evaluated once at entry; iteration count is unsigned min(n, N). Strategies are default (B) bounded back edge, (U) unroll, and (H) callback via bpf_loop.

    **Constraints**: 0 ≤ N ≤ 4096 for (B), and 0 ≤ N ≤ 64 for (U) / (H); one body block ending in ebpf.loop.yield; carried types i8 / i16 / i32 / i64; nesting depth ≤ 2. Path products use max(N, 1): the limit is 4096 for paths containing (B) without (H), and 64 for pure (U) or any path containing (H). Mixed (U)/(B) paths retain the individual (U) count limit and estimated unrolled size ≤ 4096 ops. unroll and callback are mutually exclusive. Body ops come only from the allowlist, including arith, scf.if, map lookup / update / atomic_add / try_*, ref.*, packet.load, ktime, if / break / continue, loop, call, and record.make. Captures are integers, context, and map handles; (H) allows only integers and map handles. ebpf-verify-call-graph checks depth / product and strategy across callee paths; sibling loops do not multiply. ebpf-verify-ownership rejects a live reservation crossing a loop. Limits are conservative compiler restrictions, not a guarantee of kernel acceptance or verifier processing cost.

    **Lowering**: Stage ② expands (B), N ≥ 2, into header (i < N plus bound comparison), body, and latch (i + 1); N = 0 / 1 degenerate. (U) copies the body N times into straight-line code. (H) moves the body into module-level ebpf.loop_callback and replaces the loop with ebpf.bpf_loop, lowered in ③ to helper loop and a static LLVM callback. Remaining loops at ③ are rejected.

    **Evidence**: F07, F09. B / U on three targets; bound / stop, control flow, nesting, calls and callbacks across three targets; cross-function loops; callback extensions. For the N=4096 integer loop combining runtime bound and trailing stop, root loads succeed on 7.1.8; both MLIR and C are rejected with 8193 jumps on 6.12.111 and return EFAULT on 6.6.157. The EFAULT cause and verifier verdict are unknown. Without CAP_PERFMON, the runtime-bound N=65 representative loads on 7.1.8, is rejected on 6.12.111, and returns EFAULT on 6.6.157 (verdict unknown). These observations do not guarantee load acceptance for other bodies within the compiler limits.

    **Unsupported**: Counts or path products beyond the strategy-specific limits above, and depth 3; ring-buffer operations, packet.store, adjust_head / adjust_tail, tail_call, and map.delete in bodies. **packet.check / packet.window_load are accepted only within (U)**: all enclosing loops must be unrolled, because stage-② (U) has no cycle. Any enclosing B / H, including nesting, is explicitly rejected. References, reservations, and records cannot cross loops. There is no automatic fallback between U / B / H. A non-root loader's rejection of B is reported at load time without changing lowering.
  }];
  // callback explicitly selects bpf_loop helper 181, mutually exclusive with
  // unroll and without fallback.
  let arguments = (ins I64Attr:$count, UnitAttr:$unroll, UnitAttr:$callback, Optional<I32>:$bound,
                       Variadic<AnySignlessInteger>:$inits);
  let results = (outs Variadic<AnySignlessInteger>:$results);
  let regions = (region SizedRegion<1>:$body);
  let assemblyFormat =
      "$count (`unroll` $unroll^)? (`callback` $callback^)? (`bound` `(` $bound^ `)`)? `(` $inits `)` attr-dict `:` functional-type($inits, $results) $body";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_LoopYieldOp : EBPF_Op<"loop.yield", [Terminator, HasParent<"LoopOp">, AttrSizedOperandSegments]> {
  let summary = "End a loop iteration with carried values and an optional stop condition";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Ends an ebpf.loop body, passing values to the next iteration. Optional i1 `stop %c` is tested at the iteration end. If true, this iteration's values become loop results; its effects remain and no next iteration executes.

    **Constraints**: HasParent permits only ebpf.loop; types / count must match parent iter_args, checked by the loop verifier.

    **Lowering**: Stage ②: B branches to latch, or conditionally exits for stop; U joins the current copy or exits past all copies for stop; H writes carried values to context and emits ebpf.callback.return 0 (continue) / 1 (stop). Absent at ③.

    **Evidence**: F07, F09. B expansion, stop on three targets, H callback.return.

    **Unsupported**: Not an arbitrary-position break: only tested at the body end. Use ebpf.if and ebpf.break to exit earlier.
  }];
  let arguments = (ins Variadic<AnySignlessInteger>:$values, Optional<I1>:$stop);
  let assemblyFormat = "$values (`stop` $stop^)? attr-dict (`:` type($values)^)?";
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_MapForEachOp : EBPF_Op<"map.for_each", [RecursiveMemoryEffects]> {
  let summary = "Run a callback for each map element (bpf_for_each_map_elem; invocation count and carried results)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Runs a body per map element via bpf_for_each_map_elem. Block arguments are key value, writable borrowed value !ebpf.borrowed<V> (current CPU slot for per-CPU maps), and carried values. ebpf.map.for_each.yield passes values onward; true stop ends at that element. Results are **invoked element count** as i64, including the stopping element (helper result), followed by final carried values. Arrays iterate in index order; hash-family order is unspecified.

    **Constraints**: Map kind is array / percpu_array / hash / percpu_hash / lru_hash / lru_percpu_hash. Integer key only, integer or record value, carried i8 / i16 / i32 / i64 as in bpf_loop callbacks. Body allowlist follows loops minus ebpf.loop / call / break / continue (no callback nesting / calls). Value borrow is used only by ref.load / store / atomic_add / field.*. Captures are integers and program / func map handles, passed to the stage-② callback; inner-map handles are rejected. Not allowed in loop bodies.

    **Lowering**: Stage ② moves the body into module-level ebpf.loop_callback with for_each attribute (entry key / value / carried / captures / maps), replacing it by ebpf.for_each_map_elem. Terminator is callback.return 0 / 1. Stage ③ emits a static `(ptr map, ptr key, ptr value, ptr ctx) -> i64` callback, helper for_each_map_elem(map, &callback, ctx, 0), and carried reloads from ctx. Frame / recursion checks and requirement reachability follow bpf_loop callbacks.

    **Evidence**: F53. Array stop / writeback and hash sum match equivalent C in 7.1.8 XDP test runs.

    **Unsupported**: Callback loops / calls / nested for_each and record keys. Semantics of modifying the iterated map with update / delete depend on the kernel; the compiler does not prevent it. 6.12 / 6.6 are unverified.
  }];
  let arguments = (ins EBPF_MapType:$map, Variadic<AnySignlessInteger>:$inits);
  let results = (outs I64:$count, Variadic<AnySignlessInteger>:$results);
  let regions = (region SizedRegion<1>:$body);
  let assemblyFormat = "$map `(` $inits `)` attr-dict `:` type($map) `,` functional-type($inits, results) $body";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_MapForEachYieldOp : EBPF_Op<"map.for_each.yield", [Terminator, HasParent<"MapForEachOp">, AttrSizedOperandSegments]> {
  let summary = "End a map.for_each callback with carried values and an optional stop condition";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Ends ebpf.map.for_each body. Values carry to the next element; true i1 stop makes this element's values final and returns callback status 1.

    **Constraints**: Parent is ebpf.map.for_each only. Value types / count match the parent's carried values, checked by the parent verifier.

    **Lowering**: Stage ② writes carried values to context and emits callback.return 0 (continue) / 1 (stop). Absent at ③.

    **Evidence**: F53. Stopping at array key 2 reports invocation count 3.

    **Unsupported**: Not arbitrary-position break; evaluated only at the body end.
  }];
  let arguments = (ins Variadic<AnySignlessInteger>:$values, Optional<I1>:$stop);
  let assemblyFormat = "$values (`stop` $stop^)? attr-dict (`:` type($values)^)?";
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_TaskFindVmaOp : EBPF_Op<"task.find_vma", [RecursiveMemoryEffects]> {
  let summary = "Run a callback on the vma containing an address (bpf_find_vma; raw status and carried results)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls bpf_find_vma(task, addr, callback, ctx, 0). The kernel looks up the vma of the task's mm with `find_vma(mm, addr)` and runs the body **at most once**, only when `vm_start <= addr < vm_end` holds for it (the lookup may return the *next* vma — a vma starting after addr does not run the body). Block arguments are the task `!ebpf.kptr<"task_struct">`, the vma `!ebpf.kptr<"vm_area_struct">` and the carried values. Results are the helper's **raw i64 status** (0 = the body ran; −ENOENT = no vma contains addr, no task or no mm; −EBUSY = the mmap lock was not available or the irq work was busy) followed by the final carried values: the body's yield when the status is 0, the inits otherwise. flags are 0 (no −EINVAL).

    **Constraints**: The task operand comes directly from ebpf.task.current_btf. addr is i64 (a plain number, never read by the helper). Program kind fentry only (OPS `task.find_vma`; other kinds are a compiler-unsupported by ebpf-verify-target-legality). Carried values are i8 / i16 / i32 / i64. The body takes (task, vma, carried…) and ends with ebpf.task.find_vma.yield of the carried types. The task and vma arguments reach **only ebpf.kfield.load** (no yield, select, store, call, kfunc argument or capture escape); the body is a closed set — arith ops, ebpf.kfield.load and the yield. Captured values are integers only. Not allowed in loop bodies, callbacks, funcs or another find_vma; the body has no loops, calls, nested regions or helpers.

    **Lowering**: Stage ② moves the body into a module-level ebpf.loop_callback with the find_vma attribute (entry task / vma / carried / captures; the terminator is callback.return 0), replacing the op by ebpf.find_vma_call. Stage ③ emits a static `(ptr task, ptr vma, ptr ctx) -> i64` callback that returns constant 0, and helper find_vma (180) with flags 0; carried values and captures travel through eight-byte stack slots as in bpf_loop. Requirements gain the helper row `find_vma` and the callback is a reachability edge.

    **Evidence**: Out of scope — no release F row yet; static (lit, opcheck -static, elf-snapshot of the existing inputs unchanged). Kernel behaviour: measured separately.

    **Unsupported**: A task other than the current one, kinds other than fentry, a stop condition (the kernel ignores the return), maps and records in the body, vma fields other than ones declared in core.kernel_types, flags other than 0. Not measured: any kernel load.
  }];
  let arguments = (ins EBPF_KPtrType:$task, I64:$addr, Variadic<AnySignlessInteger>:$inits);
  let results = (outs I64:$status, Variadic<AnySignlessInteger>:$results);
  let regions = (region SizedRegion<1>:$body);
  let assemblyFormat = "$task `[` $addr `]` `(` $inits `)` attr-dict `:` type($task) `,` functional-type($inits, results) $body";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_TaskFindVmaYieldOp : EBPF_Op<"task.find_vma.yield", [Terminator, HasParent<"TaskFindVmaOp">]> {
  let summary = "End a task.find_vma body with its carried values";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Ends the ebpf.task.find_vma body; the values are the carried results when the body ran.

    **Constraints**: Parent is ebpf.task.find_vma only. Types and count match the parent's carried values, checked by the parent verifier.

    **Lowering**: Stage ② writes carried values to context and emits callback.return 0. Absent at ③.

    **Evidence**: Out of scope — no release F row yet; static.

    **Unsupported**: A stop condition (the kernel ignores the callback's return value in bpf_find_vma).
  }];
  let arguments = (ins Variadic<AnySignlessInteger>:$values);
  let assemblyFormat = "$values attr-dict (`:` type($values)^)?";
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_IterNumOp : EBPF_Op<"iter.num", [RecursiveMemoryEffects]> {
  let summary = "Open-coded number iterator over [lo, hi) as a closed region (bpf_iter_num_new / next / destroy)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Runs the body once for each i32 i in [lo, hi), in increasing order, through the kernel's open-coded number iterator (`bpf_for` in C). Integer iter_args carry values across iterations; results are the final values. lo > hi (bpf_iter_num_new -EINVAL) and a range over BPF_MAX_LOOPS (-E2BIG) run the body zero times: the failed iterator's first next returns NULL (6.6.157 / 6.12.111 / 7.1.8 / 7.3.1 kernel/bpf/bpf_iter.c). Unlike ebpf.loop there is no compile-time count: the verifier checks the body by state convergence, not by unrolling.

    **Constraints**: lo / hi are i32; carried values i8 / i16 / i32 / i64; one body block taking (i32, carried…) and ending in ebpf.iter.yield. ebpf.loop and ebpf.iter.num nest at most 2 deep together (an enclosing ebpf.iter.scx_dsq counts one level too — a third level is rejected by name); an iterator counts as factor 1 in the loop count product. Allowed in an ebpf.program body or an ebpf.func body (also inside ebpf.if, ref.check, kptr.check, ebpf.loop (B) / (U), ebpf.rcu.region and an ebpf.iter.scx_dsq body, whose exclusions — no ebpf.loop, iterator, rcu.region or kptr read / exchange — hold in the nested body too); the iterator closes inside that body (never across a call); rejected in callbacks other than a sched_ext_ops owner's ebpf.timer.callback (a place like an ebpf.func body), and an (H) callback loop inside it is rejected. In an ebpf.func, every context that reaches the function must allow bpf_iter_num_new for its program type and must not come through a helper callback (ebpf-verify-call-contexts — a call inside an ebpf.iter.scx_dsq body is accepted, the DSQ body's exclusions holding in the callee), and loops / iterators of the callers on the call path count toward the depth (ebpf-verify-call-graph). Body ops: the ebpf.loop allowlist plus kfunc.call without acquire / release, the sched_ext ops, kptr.check and ebpf.rcu.region. Acquire / release kfuncs, kref.check and kptr.xchg are rejected directly in the body (allowed only inside an rcu.region with no iterator or loop in between — also through calls: a function reached from the body follows the same rule). Captures are integers, context and map handles. ** A live reference may cross the iterator**: a resource that is not a reservation (a kfunc kref or kref_or_null, a socket reference) taken before the iterator and released after it — directly, or at a call whose callee (any depth) holds the iterator — is accepted wherever the iterator stands (an ebpf.iter.scx_dsq body, a program, function or timer callback body); the verifier's refsafe compares the reference set at the iterator's next and a reference held from before keeps its id (7.3.1 states.c:868-919). The premise is that the body cannot capture the reference (the capture rule above), so it is neither used nor released inside — a change that widens the captures must re-check this. A ring buffer reservation or dynptr may not cross it (ebpf-verify-ownership), and every resource stays rejected across ebpf.loop and ebpf.iter.scx_dsq. break / continue in ebpf.if / ref.check arms leave or continue the nearest ebpf.loop or ebpf.iter.num.

    **Lowering**: Stage ② expands to ebpf.iter_num.begin (stack slot + new), a header ending in ebpf.iter_num.next_br, the body, a latch back to the header, and one done block with ebpf.iter_num.end (destroy). next's NULL and break both reach done, so destroy runs exactly once on every exit, including after a failed new. Stage ③ calls bpf_iter_num_new / _next / _destroy (UAPI kfunc rows) on a dedicated 8-byte entry alloca (of the function in an ebpf.func).

    **Evidence**: Out of scope — kernel evidence: compile only; a separate VM run covers it on 4 kernels. the ebpf.func case is compile only. the iterator in an ebpf.iter.scx_dsq body and a reference live across it are compile only (lit — the kernel's acceptance is).

    **Unsupported**: Other iterators (bpf_iter_task, bpf_for_each), iterators in callbacks (also in functions reached only through them), an iterator passed to or across a call, two iterators advanced alternately (no iterator value type), and spin.region around an iterator (KF_SPINLOCK_SAFE of 7.3.1 is not modelled). Acceptance of an arbitrary body depends on verifier convergence and the kernel version.
  }];
  let arguments = (ins I32:$lo, I32:$hi, Variadic<AnySignlessInteger>:$inits);
  let results = (outs Variadic<AnySignlessInteger>:$results);
  let regions = (region SizedRegion<1>:$body);
  let assemblyFormat = "$lo `,` $hi `(` $inits `)` attr-dict `:` functional-type($inits, $results) $body";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_IterScxDsqOp : EBPF_Op<"iter.scx_dsq", [RecursiveMemoryEffects]> {
  let summary = "Open-coded sched_ext DSQ iterator as a closed region (bpf_iter_scx_dsq_new / next / destroy)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Runs the body once for each task queued on the user DSQ dsq_id when the iterator starts (`bpf_for_each(scx_dsq, p, dsq_id, 0)` in C), in dispatch order. The body's first argument is the task as a checked `!ebpf.rcu_ptr<"task_struct">` (KF_RET_NULL: NULL ends the iteration, so the body never sees NULL); integer iter_args carry values across iterations and the results are the final values. A failed bpf_iter_scx_dsq_new (-ENODEV / -EINVAL / -ENOENT — e.g. a built-in or unknown dsq_id) runs the body zero times: next returns NULL (7.3.1 ext.c:9910-9949).

    **Constraints**: dsq_id is i64; flags is 0 (SCX_DSQ_ITER_REV is rejected by name); carried values i8 / i16 / i32 / i64; one body block taking (!ebpf.rcu_ptr<"task_struct">, carried…) and ending in ebpf.iter.yield. Only in a struct_ops program that implements a sched_ext_ops member: in a member that is not sleepable, or inside ebpf.rcu.region in any member (ebpf-verify-schema — KF_RCU_PROTECTED, 7.3.1 verifier.c:13993-13994); also inside ebpf.if, ref.check and kptr.check. Also in an ebpf.func body when every context that reaches the function is such a program body (kind struct_ops in ebpf-verify-call-contexts; the sched_ext_ops member and, in a sleepable context — sleepable member, no ebpf.rcu.region on the call path or around the iterator — the RCU section rule in ebpf-verify-schema), not through a helper callback, and with no ebpf.loop, scf.if, ebpf.iter.num or ebpf.iter.scx_dsq around a call on the path. Also in a sched_ext_ops owner's ebpf.timer.callback body and the functions it reaches, but only inside a held ebpf.rcu.region (the callback context assumes no RCU); a caller's region counts only through static calls — a global function needs its own region (also for a sleepable member's program body). Rejected in other callbacks, ebpf.loop, ebpf.iter.num, another iter.scx_dsq and other kinds (tp_btf / fentry / syscall are out of scope). Body ops: the ebpf.iter.num body allowlist without ebpf.loop, ebpf.iter.scx_dsq, ebpf.rcu.region and the kptr reads / exchanges, plus — as the exception to the iterator rule of — kfunc acquire / release and ebpf.kref.check directly in the body (allowed only bpf_task_from_pid, its kref.check and bpf_task_release; any kfunc reference, e.g. scx_bpf_get_online_cpumask / scx_bpf_put_cpumask — each reference must be released on every path of the iteration, before break / continue and the iteration's end, which ebpf-verify-ownership checks; kptr.xchg stays rejected). The same holds in a function reached from the body (ebpf-verify-call-contexts). One nested ebpf.iter.num is allowed — directly or in a function called from the body — and counts toward the depth with the DSQ iterator (2 at most; a third level is named by the op verifier or, through calls, by ebpf-verify-call-graph). Its body keeps the DSQ body's exclusions (no ebpf.loop, iterator, rcu.region or kptr read / exchange) and its own rules (no acquire / release directly in it; no capture of a reference). A reference of the DSQ body (the task from bpf_task_from_pid, a cpumask from scx_bpf_get_online_cpumask) may be live across the nested ebpf.iter.num (see ebpf.iter.num), not across ebpf.loop or ebpf.iter.scx_dsq; a reservation may not. The task argument is used only by ebpf.kfield.load (not yielded, broken out with, stored, captured, passed to calls or kfuncs — a KF_RCU-less kfunc would need a trusted pointer, 7.3.1 verifier.c:13096-13110 — or checked again). break / continue in ebpf.if / ref.check / kref.check / kptr.check arms leave or continue the nearest iterator.

    **Lowering**: Stage ② expands to ebpf.iter_scx_dsq.begin (stack slot + new), a header ending in ebpf.iter_scx_dsq.next_br, the body, a latch back to the header, and one done block with ebpf.iter_scx_dsq.end (destroy) — the expansion of ebpf.iter.num with the DSQ ops. next's NULL and break both reach done, so destroy runs exactly once on every exit; continue reaches the latch and the next next. Stage ③ calls the UAPI kfunc rows on a dedicated entry alloca of the struct's UAPI-table size. A nested ebpf.iter.num expands inside the body with its own entry alloca (a separate slot): its break reaches its own destroy and then the rest of the DSQ body, its continue its own latch; the DSQ iterator's break / continue (after the nested one has closed) reach the DSQ done / latch.

    **Evidence**: Out of scope — kernel evidence: compile only; a separate VM run covers it. the ebpf.func case is compile only. the nested ebpf.iter.num and any kfunc reference in the body are compile only (lit — the kernel's acceptance is).

    **Unsupported**: SCX_DSQ_ITER_REV, scx_bpf_dsq_move* with the iterator, the iterator in TRACING / SYSCALL programs, callbacks (also functions reached only through them), and passing the task to scx ops or kfuncs (take a reference with bpf_task_from_pid of its pid instead — LAVD main.bpf.c:1377).
  }];
  let arguments = (ins I64:$dsqId, I64Attr:$flags, Variadic<AnySignlessInteger>:$inits);
  let results = (outs Variadic<AnySignlessInteger>:$results);
  let regions = (region SizedRegion<1>:$body);
  let assemblyFormat = "$dsqId `flags` $flags `(` $inits `)` attr-dict `:` functional-type($inits, $results) $body";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_IterYieldOp : EBPF_Op<"iter.yield", [Terminator, ParentOneOf<["IterNumOp", "IterScxDsqOp"]>]> {
  let summary = "End an iterator iteration with carried values";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Ends an ebpf.iter.num or ebpf.iter.scx_dsq body, passing values to the next iteration (or to the results when the iterator ends).

    **Constraints**: The parent is ebpf.iter.num or ebpf.iter.scx_dsq; types / count match the parent's carried values, checked by the parent verifier.

    **Lowering**: Stage ② branches to the latch, which returns to the header's next. Absent at ③.

    **Evidence**: Out of scope — kernel evidence: compile only.

    **Unsupported**: A stop condition (use ebpf.if and ebpf.break).
  }];
  let arguments = (ins Variadic<AnySignlessInteger>:$values);
  let assemblyFormat = "$values attr-dict (`:` type($values)^)?";
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_RcuRegionOp : EBPF_Op<"rcu.region", [RecursiveMemoryEffects, NoRegionArguments]> {
  let summary = "Closed RCU read section (bpf_rcu_read_lock / bpf_rcu_read_unlock) with one exit";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Runs the region between bpf_rcu_read_lock and bpf_rcu_read_unlock. The only exit is the terminating ebpf.yield, so the unlock cannot be missed. Inside, the RCU-protected sched_ext ops (scx.cpu_curr / scx.dsq_peek) and task_struct.cpus_ptr are allowed even in a sleepable member, and an acquire / release kfunc pair is allowed when it closes inside the region.

    **Constraints**: Only in an ebpf.program body, an ebpf.func body or the body of an ebpf.timer.callback whose owners are sched_ext_ops programs (also inside ebpf.if, ref.check, kptr.check, ebpf.iter.num); the section closes inside that body (never across a call); rejected in other callbacks. Nested rcu.region is rejected (6.6.157 / 6.12.111 reject a nested bpf_rcu_read_lock — the compiler takes the strict side), also through calls: a function holding an rcu.region may not be reached through a call inside another rcu.region when every call from that region to the function is static (a global function is verified from a fresh state and may open its own section — addendum 1, decision (A)) (ebpf-verify-call-contexts, which also requires bpf_rcu_read_lock for every reaching program type and rejects the region in a function reached through a helper callback or a call inside an ebpf.iter.scx_dsq body). A call inside the region makes the callee's context not sleepable: a may-sleep op or KF_SLEEPABLE sched_ext kfunc in a function reached that way is rejected naming the context (ebpf-verify-schema) — also past a global function. ** The region's RCU guarantee reaches a callee only through static calls**: a global function does not inherit it (7.1.8 / 6.12.111 / 6.6.157 verify a global function once with the program's sleepable flag), so an RCU-dependent op there needs the global function's own region. In a timer callback context (the callback body and the functions it reaches) the region is the only RCU section — the RCU-dependent ops need it; scx.cpu_curr / scx.dsq_peek stay rejected inside it (outside kScxTimerCallbackOps). break / continue that leave the region for an enclosing loop or iterator are rejected (yield a flag and break after the region). Ops that may sleep (ebpf.sys.bpf, ebpf.sys.close and KF_SLEEPABLE sched_ext kfuncs such as scx.create_dsq) are rejected. rcu_ptr / rcu_ptr_or_null / kref / kref_or_null values may not be yielded; a kref defined outside may not be consumed inside; a reservation may not cross the region.

    **Lowering**: Stage ② expands to ebpf.rcu.lock, the body, ebpf.rcu.unlock. Stage ③ calls the kfuncs bpf_rcu_read_lock / bpf_rcu_read_unlock (UAPI kfunc rows).

    **Evidence**: Out of scope — kernel evidence: compile only; a separate VM run covers it on 4 kernels. the ebpf.func case and the call inside a region are compile only. the timer callback case and the global-function rule are compile only.

    **Unsupported**: Nested sections (7.1.8 / 7.3.1 accept them), exits other than the yield, and releasing a reference acquired outside the section (a compiler restriction that keeps ownership region-local — the kernel allows it).
  }];
  let results = (outs Variadic<AnySignlessInteger>:$results);
  let regions = (region SizedRegion<1>:$body);
  let assemblyFormat = "(`->` type($results)^)? $body attr-dict";
  let hasVerifier = 1;
}

// Internal stage-2 helper loops; descriptions in docs/reference/ebpf_ops.md
// define their semantics, constraints and evidence.
def EBPF_IterNumBeginOp : EBPF_Stage2Op<"iter_num.begin", "ebpf.iter.num (closed iterator region)"> {
  let summary = "Take an iterator stack slot and call bpf_iter_num_new(slot, lo, hi) (stage ② internal)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Starts the number iterator of one expanded ebpf.iter.num. The status of bpf_iter_num_new is discarded: a failed iterator's next returns NULL (kernel/bpf/bpf_iter.c), so the body runs zero times and the done block's destroy still runs.

    **Constraints**: Not writable in input (Stage2InternalOp; ebpf-compile explicitly rejects it). Its slot is used by exactly one next_br and one end.

    **Lowering**: Stage ③ emits a dedicated 8-byte entry-block alloca (align 8, no lifetime markers) and bpfabi.kfunc_call bpf_iter_num_new(slot, lo, hi).

    **Evidence**: Out of scope — kernel evidence: compile only.

    **Unsupported**: Use outside ebpf-expand-regions output.
  }];
  let arguments = (ins I32:$lo, I32:$hi);
  let results = (outs EBPF_IterNumSlotType:$slot);
  let assemblyFormat = "$lo `,` $hi attr-dict";
}

def EBPF_IterNumNextBrOp : EBPF_Stage2Op<"iter_num.next_br", "ebpf.iter.num (closed iterator region)", [Terminator]> {
  let summary = "Call bpf_iter_num_next and branch to the body with the index, or to the exit on NULL (stage ② internal)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Iterator header terminator. A non-NULL next result enters $body with the loaded i32 index as its only block argument; NULL goes to $exit.

    **Constraints**: Not writable in input (Stage2InternalOp; ebpf-compile explicitly rejects it). $body takes exactly one i32 argument; $exit takes none.

    **Lowering**: Stage ③ calls bpf_iter_num_next(slot) (ret_null), compares the pointer with NULL, and on the present edge loads the i32 index before branching to the body.

    **Evidence**: Out of scope — kernel evidence: compile only.

    **Unsupported**: Use outside ebpf-expand-regions output.
  }];
  let arguments = (ins EBPF_IterNumSlotType:$slot);
  let successors = (successor AnySuccessor:$body, AnySuccessor:$exit);
  let assemblyFormat = "$slot `,` $body `,` $exit attr-dict";
  let hasVerifier = 1;
}

def EBPF_IterNumEndOp : EBPF_Stage2Op<"iter_num.end", "ebpf.iter.num (closed iterator region)"> {
  let summary = "Call bpf_iter_num_destroy(slot) (stage ② internal)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Ends the iterator in the single done block of an expanded ebpf.iter.num, reached by next's NULL and by break.

    **Constraints**: Not writable in input (Stage2InternalOp; ebpf-compile explicitly rejects it).

    **Lowering**: Stage ③ emits bpfabi.kfunc_call bpf_iter_num_destroy(slot).

    **Evidence**: Out of scope — kernel evidence: compile only.

    **Unsupported**: Use outside ebpf-expand-regions output.
  }];
  let arguments = (ins EBPF_IterNumSlotType:$slot);
  let assemblyFormat = "$slot attr-dict";
}

def EBPF_IterScxDsqBeginOp : EBPF_Stage2Op<"iter_scx_dsq.begin", "ebpf.iter.scx_dsq (closed iterator region)"> {
  let summary = "Take a DSQ iterator stack slot and call bpf_iter_scx_dsq_new(slot, dsq_id, 0) (stage ② internal)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Starts the DSQ iterator of one expanded ebpf.iter.scx_dsq. The status of bpf_iter_scx_dsq_new is discarded: on failure the kernel leaves the iterator's dsq NULL, so the first next returns NULL and destroy does nothing (7.3.1 ext.c:9910-9931, :9943-9944, :9961-9962).

    **Constraints**: Not writable in input (Stage2InternalOp; ebpf-compile explicitly rejects it). Its slot is used by exactly one next_br and one end.

    **Lowering**: Stage ③ emits a dedicated entry-block alloca of struct bpf_iter_scx_dsq's UAPI-table size (align 8, no lifetime markers) and bpfabi.kfunc_call bpf_iter_scx_dsq_new(slot, dsq_id, 0).

    **Evidence**: Out of scope — kernel evidence: compile only.

    **Unsupported**: Use outside ebpf-expand-regions output.
  }];
  let arguments = (ins I64:$dsqId);
  let results = (outs EBPF_IterScxDsqSlotType:$slot);
  let assemblyFormat = "$dsqId attr-dict";
}

def EBPF_IterScxDsqNextBrOp : EBPF_Stage2Op<"iter_scx_dsq.next_br", "ebpf.iter.scx_dsq (closed iterator region)", [Terminator]> {
  let summary = "Call bpf_iter_scx_dsq_next and branch to the body with the task, or to the exit on NULL (stage ② internal)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Iterator header terminator. A non-NULL next result enters $body with the task as its only block argument (!ebpf.rcu_ptr<"task_struct"> — the verifier marks it PTR_TO_BTF_ID | MEM_RCU, 7.3.1 verifier.c:14117-14133); NULL goes to $exit.

    **Constraints**: Not writable in input (Stage2InternalOp; ebpf-compile explicitly rejects it). $body takes exactly one !ebpf.rcu_ptr<"task_struct"> argument; $exit takes none.

    **Lowering**: Stage ③ calls bpf_iter_scx_dsq_next(slot) (ret_null), compares the pointer with NULL and passes it to the body on the present edge.

    **Evidence**: Out of scope — kernel evidence: compile only.

    **Unsupported**: Use outside ebpf-expand-regions output.
  }];
  let arguments = (ins EBPF_IterScxDsqSlotType:$slot);
  let successors = (successor AnySuccessor:$body, AnySuccessor:$exit);
  let assemblyFormat = "$slot `,` $body `,` $exit attr-dict";
  let hasVerifier = 1;
}

def EBPF_IterScxDsqEndOp : EBPF_Stage2Op<"iter_scx_dsq.end", "ebpf.iter.scx_dsq (closed iterator region)"> {
  let summary = "Call bpf_iter_scx_dsq_destroy(slot) (stage ② internal)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Ends the iterator in the single done block of an expanded ebpf.iter.scx_dsq, reached by next's NULL and by break.

    **Constraints**: Not writable in input (Stage2InternalOp; ebpf-compile explicitly rejects it).

    **Lowering**: Stage ③ emits bpfabi.kfunc_call bpf_iter_scx_dsq_destroy(slot).

    **Evidence**: Out of scope — kernel evidence: compile only.

    **Unsupported**: Use outside ebpf-expand-regions output.
  }];
  let arguments = (ins EBPF_IterScxDsqSlotType:$slot);
  let assemblyFormat = "$slot attr-dict";
}

def EBPF_RcuLockOp : EBPF_Stage2Op<"rcu.lock", "ebpf.rcu.region (closed RCU read section)"> {
  let summary = "bpf_rcu_read_lock at the start of an expanded rcu.region (stage ② internal)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Opens the RCU read section of one expanded ebpf.rcu.region.

    **Constraints**: Not writable in input (Stage2InternalOp; ebpf-compile explicitly rejects it).

    **Lowering**: Stage ③ emits bpfabi.kfunc_call bpf_rcu_read_lock().

    **Evidence**: Out of scope — kernel evidence: compile only.

    **Unsupported**: Use outside ebpf-expand-regions output.
  }];
  let assemblyFormat = "attr-dict";
}

def EBPF_RcuUnlockOp : EBPF_Stage2Op<"rcu.unlock", "ebpf.rcu.region (closed RCU read section)"> {
  let summary = "bpf_rcu_read_unlock at the single exit of an expanded rcu.region (stage ② internal)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Closes the RCU read section of one expanded ebpf.rcu.region, before its only exit.

    **Constraints**: Not writable in input (Stage2InternalOp; ebpf-compile explicitly rejects it).

    **Lowering**: Stage ③ emits bpfabi.kfunc_call bpf_rcu_read_unlock().

    **Evidence**: Out of scope — kernel evidence: compile only.

    **Unsupported**: Use outside ebpf-expand-regions output.
  }];
  let assemblyFormat = "attr-dict";
}

def EBPF_LoopSpillOp : EBPF_Stage2Op<"loop.spill", "ebpf.loop N (--tune-backedge-spill inserts this in back-edge loops)"> {
  let summary = "Volatile IV store to a dedicated stack slot per bounded-loop iteration (stage ② internal speculative-path barrier)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: With --tune-backedge-spill (enabled by default; =false disables it), ebpf-expand-regions inserts this at the header start of B back-edge loops with N ≥ 2, or body start with --tune-backedge-rotate. Not inserted for unroll / callback. No operation reads the dead store; program semantics are unchanged.

    **Constraints**: Not writable in input (Stage2InternalOp; ebpf-compile explicitly rejects it). One per loop; i32 IV.

    **Lowering**: Stage ③ emits `llvm.store volatile (zext i64 %iv)` into a dedicated entry alloca i64, one unread eight-byte stack slot per loop. BPF uses one `*(u64 *)(r10 - X) = rN`. The slot starts STACK_INVALID then becomes STACK_SPILL. For loaders without CAP_PERFMON (!bypass_spec_v4), the 7.1.8 verifier marks the store nospec_result (kernel/bpf/verifier.c Spectre-v4 sanitization), ending speculative paths at that instruction. This breaks the B-loop bound failure chain `The sequence of 8193 jumps` / `infinite loop detected`, where final-iteration speculative re-entry narrows IV across generations.

    **Evidence**: F07. Stage-③ b8cf1 / c4cf1 / c64cf1 with the store alone are accepted on 7.1.8 with {bpf, net_admin}; lowering incorporates that behavior.

    **Unsupported**: Does not help CAP_PERFMON-less 6.12 / 6.6: sanitize_stack_spill fixup inserts BPF_ST_NOSPEC but does not terminate speculative paths at the store. Not inserted for U / H. Does not change main-path speculative push count for constant loops (8192 boundary); --tune-backedge-rotate addresses that.
  }];
  let arguments = (ins I32:$iv);
  let assemblyFormat = "$iv attr-dict `:` type($iv)";
}

def EBPF_LoopCallbackOp : EBPF_Stage2Op<"loop_callback", "ebpf.loop N callback", [IsolatedFromAbove, Symbol]> {
  let summary = "bpf_loop callback body with IV, carried integers, captured integers, and maps";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Module-level callback symbol for ebpf.bpf_loop. Block arguments are IV, carried values, captured integers, and maps. Context is a sequence of eight-byte caller-stack slots: num_carried values, then num_captured integers. With for_each attribute, it is a for_each_map_elem callback and replaces IV with key value and borrowed value arguments. With the find_vma attribute (exclusive with for_each), it is a bpf_find_vma callback and replaces IV with the task and vma kernel pointers (`!ebpf.kptr<"task_struct">`, `!ebpf.kptr<"vm_area_struct">`).

    **Constraints**: IsolatedFromAbove. IV is i32; for_each has integer key and !ebpf.borrowed value; find_vma has the two kptr arguments (in that order), no map arguments, and returns constant 0. Attributes record carried / captured counts and map_symbols.

    **Lowering**: Stage ③ emits a static llvm.func: `(u64 index, ptr ctx)` for bpf_loop, `(ptr map, ptr key, ptr value, ptr ctx)` for for_each, `(ptr task, ptr vma, ptr ctx)` for find_vma (the kernel's R1 / R2 / R3, the context in the third argument). Key is loaded through its pointer; value preserves its pointer; task and vma stay pointers. Map arguments follow map_symbols order and become symbol addressof, not stack captures.

    **Evidence**: Internal — ebpf-expand-regions creates it from stage-① ebpf.loop N callback / ebpf.map.for_each. ebpf-compile rejects it in input to prevent bypassing stage-① restrictions. Feature-path evidence belongs to those input ops, including callback calls / nesting and for_each.

    **Unsupported**: Not writable in input; permitted top-level inputs are program / func / timer.callback / user_ringbuf.callback only.
  }];
  let arguments = (ins SymbolNameAttr:$sym_name, I64Attr:$num_carried, I64Attr:$num_captured,
                       ArrayAttr:$map_symbols, UnitAttr:$for_each, UnitAttr:$find_vma);
  let regions = (region AnyRegion:$body);
  let assemblyFormat = "$sym_name attr-dict-with-keyword $body";
  let hasVerifier = 1;
}

def EBPF_CallbackReturnOp : EBPF_Stage2Op<"callback.return", "ebpf.loop.yield in an ebpf.loop callback body", [Terminator, HasParent<"LoopCallbackOp">]> {
  let summary = "Write carried values to context and return constant zero (continue) or one (stop)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Terminates ebpf.loop_callback by writing carried values to context and returning stop: 0 continues, 1 stops. The same contract applies to for_each callbacks (next element / stop).

    **Constraints**: Parent is ebpf.loop_callback only.

    **Lowering**: Stage ③ writes carried values to context and returns constant 0 / 1 from the callback function.

    **Evidence**: Internal — ebpf-expand-regions creates it from loop.yield inside stage-① callback loops. ebpf-compile rejects it in source input, preventing stage-① bypasses. The input op owns feature-path evidence.

    **Unsupported**: Not writable in input; use stage-① ebpf.loop.yield.
  }];
  let arguments = (ins I64Attr:$stop, Variadic<AnySignlessInteger>:$values);
  let assemblyFormat = "$stop ($values^ `:` type($values))? attr-dict";
  let hasVerifier = 1;
}

def EBPF_BpfLoopOp : EBPF_Stage2Op<"bpf_loop", "ebpf.loop N callback", [AttrSizedOperandSegments]> {
  let summary = "bpf_loop(count, callback, &context, 0), returning carried values reloaded from context";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Helper call invoking ebpf.loop_callback count times, with runtime count, initial carried values, and captures. Results are final carried values.

    **Constraints**: Callback must name an ebpf.loop_callback.

    **Lowering**: Stage ③ calls loop(count, callback address, ctx, flags = 0). Requirements and HelperCalls treat function addresses as reachability edges.

    **Evidence**: Internal — ebpf-expand-regions creates it from stage-① ebpf.loop N callback. ebpf-compile rejects it in source input, preventing stage-① bypasses. The input op owns feature-path evidence, including callback calls.

    **Unsupported**: Not writable in input; use stage-① ebpf.loop ... callback.
  }];
  let arguments = (ins FlatSymbolRefAttr:$callback, I32:$count, Variadic<AnySignlessInteger>:$inits,
                       Variadic<AnySignlessInteger>:$captures);
  let results = (outs Variadic<AnySignlessInteger>:$results);
  let assemblyFormat =
      "$callback `count` `(` $count `)` `(` $inits `)` `captures` `(` $captures `)` attr-dict `:` functional-type(operands, results)";
  let hasVerifier = 1;
}

def EBPF_ForEachMapElemOp : EBPF_Stage2Op<"for_each_map_elem", "ebpf.map.for_each", [AttrSizedOperandSegments]> {
  let summary = "bpf_for_each_map_elem(map, callback, &context, 0), returning invocation count and reloaded carried values";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Calls an ebpf.loop_callback with for_each attribute for each map element. Passes initial carried values and captures, returning invoked element count (helper result) and final carried values.

    **Constraints**: Callback names an ebpf.loop_callback with for_each attribute; key / value block argument types match the map.

    **Lowering**: Stage ③ calls for_each_map_elem(map, callback address, ctx, flags = 0). Requirements and HelperCalls follow function-address reachability edges, as with bpf_loop.

    **Evidence**: Internal — ebpf-expand-regions creates it from stage-① ebpf.map.for_each; ebpf-compile rejects it in input. The input op owns feature-path evidence.

    **Unsupported**: Not writable in input; use ebpf.map.for_each.
  }];
  let arguments = (ins FlatSymbolRefAttr:$callback, EBPF_MapType:$map, Variadic<AnySignlessInteger>:$inits,
                       Variadic<AnySignlessInteger>:$captures);
  let results = (outs I64:$count, Variadic<AnySignlessInteger>:$results);
  let assemblyFormat =
      "$callback `map` `(` $map `)` `(` $inits `)` `captures` `(` $captures `)` attr-dict `:` functional-type(operands, results)";
  let hasVerifier = 1;
}

def EBPF_FindVmaCallOp : EBPF_Stage2Op<"find_vma_call", "ebpf.task.find_vma", [AttrSizedOperandSegments]> {
  let summary = "bpf_find_vma(task, addr, callback, &context, 0), returning the raw status and reloaded carried values";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Calls an ebpf.loop_callback with the find_vma attribute at most once (when the helper finds a vma containing addr). Passes initial carried values and captures, returning the helper's status and the carried values read back from the context (the inits when the callback did not run).

    **Constraints**: Callback names an ebpf.loop_callback with find_vma; its task / vma entry arguments are the kptrs of the operand's struct and `vm_area_struct`.

    **Lowering**: Stage ③ calls find_vma(task, addr, callback address, ctx, flags = 0). Requirements and HelperCalls follow function-address reachability edges, as with bpf_loop.

    **Evidence**: Internal — ebpf-expand-regions creates it from stage-① ebpf.task.find_vma; ebpf-compile rejects it in input.

    **Unsupported**: Not writable in input; use ebpf.task.find_vma.
  }];
  let arguments = (ins FlatSymbolRefAttr:$callback, EBPF_KPtrType:$task, I64:$addr, Variadic<AnySignlessInteger>:$inits,
                       Variadic<AnySignlessInteger>:$captures);
  let results = (outs I64:$status, Variadic<AnySignlessInteger>:$results);
  let assemblyFormat =
      "$callback `task` `(` $task `)` `addr` `(` $addr `)` `(` $inits `)` `captures` `(` $captures `)` attr-dict `:` functional-type(operands, results)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_IfOp : EBPF_Op<"if", [RecursiveMemoryEffects]> {
  let summary = "Conditional regions joining with if.yield or exiting a loop with break / continue";
  let description = [{
    **Stage**: ① Input

    **Meaning**: An i1 selects then / else regions, returning integers only. Each arm joins via ebpf.if.yield or exits the nearest ebpf.loop via ebpf.break / continue. Also usable outside loops.

    **Constraints**: Arms take no arguments and end in if.yield / break / continue. If both exit, no results are permitted. Allowed in loops; stage-② expansion estimate counts it as four operations.

    **Lowering**: Stage ② creates cf.cond_br, then / else blocks, and a merge block with result block arguments. Unreachable blocks after two exiting arms are removed so requirements match ELF instructions. Absent at ③.

    **Evidence**: F07. break / continue, nesting, three-target tests, and result-width / i1 differential tests.

    **Unsupported**: Non-integer results (references / reservations / records — the one exception is `!ebpf.str_buf<N>`, merged for an ebpf.scx.dump `%s`) and missing else; express an empty else with valueless if.yield. Result widths are i1 or 8 / 16 / 32 / 64 only; other widths are verifier-rejected (older behavior accepted i1–i128). i1 has three-target differential evidence in kernel/cmd/i1check. Loop-carried values remain i8 / i16 / i32 / i64.
  }];
  let arguments = (ins I1:$cond);
  let results = (outs Variadic<AnyTypeOf<[AnySignlessInteger, EBPF_StrBufType]>>:$results);
  let regions = (region SizedRegion<1>:$thenRegion, SizedRegion<1>:$elseRegion);
  let assemblyFormat = "$cond (`->` type($results)^)? $thenRegion `else` $elseRegion attr-dict";
  let hasVerifier = 1;
}

def EBPF_IfYieldOp : EBPF_Op<"if.yield", [Terminator, HasParent<"IfOp">]> {
  let summary = "Join an ebpf.if arm normally";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Normal ebpf.if arm join; operands become parent results.

    **Constraints**: Parent is ebpf.if only; operand types must match its result types.

    **Lowering**: Stage ② emits cf.br to the merge block with values as block arguments.

    **Evidence**: F07. Conditional-region expansion tests.

    **Unsupported**: Non-integer values.
  }];
  let arguments = (ins Variadic<AnyTypeOf<[AnySignlessInteger, EBPF_StrBufType]>>:$values);
  let assemblyFormat = "($values^ `:` type($values))? attr-dict";
  let hasVerifier = 1;
}

def EBPF_BreakOp : EBPF_Op<"break", [Terminator]> {
  let summary = "Exit the nearest ebpf.loop with an explicit carried-value tuple";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Exits the nearest ebpf.loop; the explicit carried-value tuple becomes loop results.

    **Constraints**: Parent is an ebpf.if or ebpf.ref.check arm (or an ebpf.kref.check arm when the nearest loop is ebpf.iter.scx_dsq; an acquired reference must be released before it). Between it and the nearest loop, only ebpf.if / ebpf.ref.check / scf.if may be crossed (also ebpf.kref.check / ebpf.kptr.check for ebpf.iter.scx_dsq). Rejected outside loops. Types must match nearest-loop iter_args. Reservation-region exits cannot arise because ring-buffer operations are forbidden in loops.

    **Lowering**: Stage ② branches to the exit: after the loop for B, after all copies for U, or callback.return 1 for H (write context and stop).

    **Evidence**: F07. Expansion tests, three targets, and H break.

    **Unsupported**: Labeled breaks to outer loops; target is always the nearest loop.
  }];
  let arguments = (ins Variadic<AnySignlessInteger>:$values);
  let assemblyFormat = "($values^ `:` type($values))? attr-dict";
  let hasVerifier = 1;
}

def EBPF_ContinueOp : EBPF_Op<"continue", [Terminator]> {
  let summary = "Continue the nearest ebpf.loop with explicit carried values, incrementing IV once and rechecking bounds";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Continues the nearest loop with the explicit carried-value tuple. B increments IV once and rechecks count / bound at the header.

    **Constraints**: Same as ebpf.break: parent if / ref.check arm (kref.check for ebpf.iter.scx_dsq), inside nearest loop, types matching iter_args.

    **Lowering**: Stage ② branches to latch (B), current copy's join / next guard (U), or callback.return 0 (H).

    **Evidence**: F07. B with continue has two back edges; three-target tests.

    **Unsupported**: Labeled continues to outer loops.
  }];
  let arguments = (ins Variadic<AnySignlessInteger>:$values);
  let assemblyFormat = "($values^ `:` type($values))? attr-dict";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_RecordMakeOp : EBPF_Op<"record.make", [Pure]> {
  let summary = "Construct a record from every field, with zero padding";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Constructs all bytes of a schema record from every field, stored at declared offsets / widths with remaining padding zeroed. Fields are leaf paths (`x`, `x.y`, `x[i]`) in any order.

    **Constraints**: Name / value counts match; names are unique. Result uses are limited to map.update / try_update values; map.lookup / update / delete / try_update / try_delete keys; ringbuf.store_record values; and perf.output records. No yield / call / block-crossing / loop-carried / atomic_add-key uses. ebpf-verify-records requires each @records leaf exactly once with matching width. Records with spin_lock / timer cannot be constructed. Allowed inside loop / callback bodies if the result does not cross the loop.

    **Lowering**: Stage ③ normally allocates record-sized stack storage with alignment 8, zeros it via memset, and stores each field at @records offsets; the value is its pointer. When stores cover every byte, memset is omitted (C2). When the sole use is store_record and every byte is covered, D2 stores directly into the reservation without a stack record.

    **Evidence**: F03, F02. C byte oracle; record values / keys on three targets; nested and array leaves; loops; non-root tests establishing that zero padding is the compiler's responsibility.

    **Unsupported**: Partial construction, modifying an existing record, and spin_lock / timer records.
  }];
  let arguments = (ins StrArrayAttr:$fields, Variadic<AnySignlessInteger>:$values);
  let results = (outs EBPF_RecordType:$result);
  let assemblyFormat = "$fields `(` $values `)` attr-dict `:` functional-type($values, $result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_MapLookupOp : EBPF_Op<"map.lookup"> {
  let summary = "Look up a map, returning an unchecked nullable reference";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Looks up key and returns an **unchecked** !ebpf.maybe_ref<V>, where V is map value type. The helper can return NULL: ebpf.ref.check is required before use, and access goes through present-region !ebpf.borrowed<V>.

    **Constraints**: The op verifier rejects devmap (redirect_map only), prog_array (tail_call only), stack_trace (stack.kernel_id only), perf_event_array (perf.output only), and unknown kinds (including ringbuf here). Key type matches the map key; result pointee matches its value. Record keys are accepted only for hash / percpu_hash / lru_hash / lru_percpu_hash and lpm_trie, and must be record.make results. ebpf-verify-schema checks map kind / key / value; ebpf-verify-records checks record-value depth / dimensions.

    **Lowering**: Unchanged in ②; ref.check expansion supplies the NULL branch. After expansion, ebpf-reuse-dominated-lookup (default; `ebpf-compile --tune-reuse-dominated-lookup=false` keeps every lookup) removes a lookup of an `array` map whose map and key are the same SSA values as an earlier lookup whose assume_present properly dominates it in the same region, when its only uses are is_present branch conditions and assume_present: its NULL branch becomes the present edge and its borrow becomes the earlier one (an in-range array cell is fixed and cannot be deleted). Stage ③ calls map_lookup_elem(map, &key): integer keys use stack slots; record keys reuse record.make stack pointers. Integer key / value slots have store-to-helper lifetime.start / end markers (enabled by default), allowing LLVM to overlap per-op slots: stack use no longer scales with op count; without markers, 32 sixteen-byte operations hit the BPF stack limit. Measured processed-instruction counts mostly stay equal or decrease but sometimes increase: repository maximum is sdiv_i32_floordivsi on 6.6.157, 1057 → 1251 (+18%). **Downstream maximum on 7.1.8 is +145%, mojo-bpf-mlir testdata pkt 185 → 454**; constant-key NULL elision likely marks shared slots precise and weakens pruning. 6.x and acceptance are unchanged. `ebpf-compile --tune-spill-lifetime=false` restores v0.15.0 output.

    **Evidence**: F01, F04, F16. 7.1.8 acceptance and NULL-check-removal mutation rejected as map_value_or_null; record keys; hash-family records; three-target lpm_trie lookup / map-kind tests.

    **Unsupported**: The four dedicated map kinds cannot use this program-side lookup. lpm_trie keys are limited by schema to eight-byte IPv4 records. To avoid lookup on out-of-bounds packets, enclose it in packet.check: packet.load otherwise returns 0 out of bounds and still performs the lookup.
  }];
  let arguments = (ins EBPF_MapType:$map, AnyType:$key);
  let results = (outs EBPF_MaybeRefType:$result);
  let assemblyFormat =
      "$map `[` $key `]` attr-dict `:` type($map) `,` type($key) `->` type($result)";
  let hasVerifier = 1;
}

def EBPF_MapUpdateOp : EBPF_Op<"map.update"> {
  let summary = "Update a map";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Replaces the keyed element with value using any flags (0). Helper status is not exposed; use ebpf.map.try_update when status is needed.

    **Constraints**: lpm_trie is compiler-restricted to read-only program access. Other kind rules follow map.lookup. Key / value types match map parameters. Record keys require hash-family maps; record keys / values must be record.make results, including all bytes and zero padding. Allowed in loop bodies.

    **Lowering**: Unchanged in ②. Stage ③ calls map_update_elem(map, &key, &value, 0). Integers use stack slots; records reuse record.make pointers. Integer key / value lifetime markers, stack-slot overlap, processed-instruction costs, and --tune-spill-lifetime=false behavior follow ebpf.map.lookup: observed repository maximum +18% on 6.6.157 and downstream maximum +145% on 7.1.8, with unchanged acceptance.

    **Evidence**: F01, F03, F04. 7.1.8 acceptance; record values / keys and three-target byte agreement with C; map-kind tests.

    **Unsupported**: Configurable flags (noexist / exist use try_update). Program-side lpm_trie / devmap updates are rejected; userspace supplies them.
  }];
  let arguments = (ins EBPF_MapType:$map, AnyType:$key, AnyType:$value);
  let assemblyFormat =
      "$map `[` $key `]` `,` $value attr-dict `:` type($map) `,` type($key) `,` type($value)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_MapDeleteOp : EBPF_Op<"map.delete"> {
  let summary = "Delete a keyed map element (hash family or XDP socket maps)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Deletes key's element without exposing helper status. Use ebpf.map.try_delete for status.

    **Constraints**: sockmap / sockhash are accepted only in XDP program bodies and if / sock.ref_check arms (measured on 7.1.8 against C and full manifest acceptance). Otherwise only hash / percpu_hash / lru_hash / lru_percpu_hash. array / percpu_array are rejected because the kernel would return -EINVAL without a change. lpm_trie / devmap follow map.update exclusions. Key type matches; record keys must be record.make results. **Not allowed in loop bodies**; try_delete is allowed there.

    **Lowering**: Unchanged in ②. Stage ③ calls map_delete_elem(map, &key), discarding status. Integer key / value stack-slot lifetime and cost follow map.lookup; --tune-spill-lifetime=false restores v0.15.0 output.

    **Evidence**: F04. C oracle for array delete -EINVAL without changes; op tests; three targets.

    **Unsupported**: Array-family delete is rejected at compile time. Use try_delete inside loops.
  }];
  let arguments = (ins EBPF_MapType:$map, AnyType:$key);
  let assemblyFormat = "$map `[` $key `]` attr-dict `:` type($map) `,` type($key)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_MapTryUpdateOp : EBPF_Op<"map.try_update"> {
  let summary = "Update a map and return raw helper status (zero or negative errno)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Updates a map and returns **raw** i64 status (0 / negative errno). Errno semantics depend on map kind, flags, and prior state; do not generalize them. Flags are any / noexist / exist.

    **Constraints**: Kind / key / value rules follow map.update. Only those three flag names. noexist on array / percpu_array is accepted: in-range gives -EEXIST and out-of-range gives -E2BIG. Allowed in loop bodies.

    **Lowering**: Unchanged in ②. Stage ③ calls map_update_elem(map, &key, &value, flags), with numeric UAPI updateflag values; unknown names also fail explicitly at ③. Stack lifetime / cost follow map.lookup; --tune-spill-lifetime=false restores v0.15.0 output.

    **Evidence**: F05. C oracle; flag checks and correction allowing array NOEXIST; matching C status / map state on three targets.

    **Unsupported**: Other flags. Interpreting status is the caller's responsibility; compile time does not predict it.
  }];
  let arguments = (ins EBPF_MapType:$map, AnyType:$key, AnyType:$value, StrAttr:$flags);
  let results = (outs I64:$status);
  let assemblyFormat =
      "$map `[` $key `]` `,` $value `flags` $flags attr-dict `:` type($map) `,` type($key) `,` type($value) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_MapTryDeleteOp : EBPF_Op<"map.try_delete"> {
  let summary = "Delete a keyed map element and return raw helper status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Deletes key's element and returns **raw** i64 status (0 / negative errno), dependent on kind / previous state. Missing hash keys give -ENOENT. On 7.1.8, C comparisons show sockmap empty / out-of-range -EINVAL and sockhash missing key -ENOENT.

    **Constraints**: Same as map.delete: XDP sockmap / sockhash or hash family; no array family / lpm_trie / devmap; matching key type; record keys only from record.make. Hash-family operations are allowed in loop bodies; socket maps are rejected in loops / calls / callbacks. Socket-map XDP acceptance was measured on 7.1.8, not 6.12 / 6.6.

    **Lowering**: Unchanged in ②. Stage ③ calls map_delete_elem(map, &key) and exposes status. Stack-slot lifetime / cost follow map.lookup; --tune-spill-lifetime=false restores v0.15.0 output.

    **Evidence**: F05. C oracle and three-target status tests.

    **Unsupported**: Array-family delete is rejected at compile time.
  }];
  let arguments = (ins EBPF_MapType:$map, AnyType:$key);
  let results = (outs I64:$status);
  let assemblyFormat = "$map `[` $key `]` attr-dict `:` type($map) `,` type($key) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_MapAtomicAddOp : EBPF_Op<"map.atomic_add"> {
  let summary = "Atomically add to a map value";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Atomically adds delta to the keyed value. Missing elements are unchanged and not created. No result.

    **Constraints**: Rejects read-only lpm_trie, devmap / prog_array / stack_trace / perf_event_array, and unknown kinds. Delta matches value type, which must be signless integer, not record, and **32 or 64 bits only** (BPF atomics; i8 / i16 previously aborted in the LLVM BPF backend). record.make rejects use as atomic_add key. Allowed in loop bodies.

    **Lowering**: Stage ② expands to map.lookup → is_present branch → assume_present plus ref.atomic_add on the true edge, making the NULL check explicit. Stage ③ uses map_lookup_elem and a result-unused monotonic atomicrmw add (BPF non-FETCH lock +=).

    **Evidence**: F01. Stage-② expansion; array / hash / percpu_array acceptance on 7.1.8; ELF non-FETCH lock +=; width rules.

    **Unsupported**: Upsert, FETCH returning the old value, and atomic operations other than add.
  }];
  let arguments = (ins EBPF_MapType:$map, AnyType:$key, AnyType:$delta);
  let assemblyFormat =
      "$map `[` $key `]` `,` $delta attr-dict `:` type($map) `,` type($key) `,` type($delta)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_StorageGetOp : EBPF_Op<"storage.get"> {
  let summary = "Look up an owner's local storage, optionally creating a zeroed value (unchecked nullable reference)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Looks up local-storage map value attached to a kernel owner object: socket / task / inode / cgroup for sk_storage / task_storage / inode_storage / cgrp_storage. create allocates a missing zero-filled value. Returns **unchecked** !ebpf.maybe_ref<V>, possibly NULL even with create if allocation fails. Access through ref.check present !ebpf.borrowed<V> and existing ref.* operations, like map.lookup.

    **Constraints**: Only the four local-storage map kinds. Owner is !ebpf.kptr<"S"> for sock / task_struct / inode / cgroup respectively (Support/LocalStorage.h), obtained from kptr.check present, LSM / tracing ctx.arg, or kfield.ptr traversal. Result pointee equals map value. No loop bodies. ebpf-verify-schema checks map kind / key / value; schema requires 32-bit integer key, max_entries 0, flags no_prealloc.
    Kernel program-type compatibility is not decided by the compiler. In 7.1.8 func_proto, task / cgrp storage support all types, inode storage only LSM, sk storage LSM / tracing / network types. Requirements helper rows check at load time; otherwise the verifier explicitly rejects unsupported combinations.

    **Lowering**: Unchanged in ② (ref.check supplies the NULL branch). Stage ③ calls <kind>_get(map, owner, NULL, flags), using UAPI helper numbers and storageflag create or 0.

    **Evidence**: F51. Actual 7.1.8 LSM task_getioprio / file_ioctl / socket_getsockopt owners match C for all four kinds.

    **Unsupported**: Supplied initial values (only zero-filled creation). Owner must be kptr, not cgroup_sock context (ARG_PTR_TO_CTX), a network context sk field, or other sock_common-derived structs such as tcp_sock. Schema rejects BPF_F_CLONE. 6.12 / 6.6 are unverified.
  }];
  let arguments = (ins EBPF_MapType:$map, EBPF_KPtrType:$owner, UnitAttr:$createIfMissing);
  let results = (outs EBPF_MaybeRefType:$result);
  let assemblyFormat =
      "$map `,` $owner (`create` $createIfMissing^)? attr-dict `:` type($map) `,` type($owner) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_StorageDeleteOp : EBPF_Op<"storage.delete"> {
  let summary = "Delete an owner's local storage and return raw helper status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Deletes the owner's local-storage value and returns **raw** i64 status (0 / negative errno; -ENOENT if absent).

    **Constraints**: Map / owner rules follow storage.get. Do not use borrows of the deleted value afterward: kernel frees it after RCU; the compiler does not track this, so it is the caller's responsibility. No loop bodies.

    **Lowering**: Unchanged in ②; ③ exposes <kind>_delete(map, owner) status.

    **Evidence**: F51. First delete 0 and second -ENOENT match equivalent C on actual 7.1.8 attach.

    **Unsupported**: No post-delete borrow-use checking. 6.12 / 6.6 are unverified.
  }];
  let arguments = (ins EBPF_MapType:$map, EBPF_KPtrType:$owner);
  let results = (outs I64:$status);
  let assemblyFormat = "$map `,` $owner attr-dict `:` type($map) `,` type($owner) `->` type($status)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_MapLookupPercpuOp : EBPF_Op<"map.lookup_percpu"> {
  let summary = "Look up a specified CPU's per-CPU map slot (unchecked nullable reference)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Looks up key in percpu_array / percpu_hash / lru_percpu_hash and returns the **specified CPU's** slot (%cpu, i32), unlike map.lookup's current-CPU slot. Result is unchecked !ebpf.maybe_ref<V>; absent key or cpu ≥ kernel nr_cpu_ids gives NULL. Access uses ref.check borrows as with map.lookup.

    **Constraints**: Only these three per-CPU kinds, matching kernel check_map_func_compatibility. Key matches map type; record keys follow hash-family record.make rules. Result pointee equals map value. No loop bodies. Writes to another CPU's slot are unsynchronized; races are the caller's responsibility.

    **Lowering**: Unchanged in ②. Stage ③ calls map_lookup_percpu_elem(map, &key, zext(cpu)); integer keys use stack storage as in map.lookup.

    **Evidence**: F53. CPU 0 / 1 percpu_array slots and out-of-range CPU NULL match C in 7.1.8 XDP test runs.

    **Unsupported**: 6.12 / 6.6 are unverified.
  }];
  let arguments = (ins EBPF_MapType:$map, AnyType:$key, I32:$cpu);
  let results = (outs EBPF_MaybeRefType:$result);
  let assemblyFormat =
      "$map `[` $key `]` `,` $cpu attr-dict `:` type($map) `,` type($key) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_MapInnerOp : EBPF_Op<"map.inner", [Pure]> {
  let summary = "Convert a checked outer map-in-map borrow to an inner map handle";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Converts a ref.check-validated outer array_of_maps / hash_of_maps lookup borrow !ebpf.borrowed<!ebpf.map<"…", K, V>> to inner !ebpf.map<"…", K, V>. The handle works with map.lookup / update / delete / atomic_add / try_update / try_delete. Pure.

    **Constraints**: Operand is borrowed map and result equals its pointee. Result cannot escape via yield / call argument / loop-carried value: validity is confined to the checked region's present path. A borrowed map can be used only by map.inner; ref.check and stage-② exit verification reject ref.load and other uses. ebpf-verify-schema checks inner kind / key / value against the outer schema inner template.

    **Lowering**: Unchanged in ②; ref.check emits a NULL branch and assume_present borrow. Stage ③ preserves the pointer. After NULL checking, the kernel treats the outer lookup result as CONST_PTR_TO_MAP with template metadata and accepts it as the inner helper's map argument.

    **Evidence**: F52. array_of_maps with inner hash and hash_of_maps with inner array match C for lookup / update / atomic_add in 7.1.8 XDP test runs.

    **Unsupported**: Program-side inner-map insertion / outer-map update (kernel rejection; userspace inserts). Schema permits only hash / array families inside, rejecting lpm_trie / ringbuf / local storage / two-level map-in-map. 6.12 / 6.6 are unverified.
  }];
  let arguments = (ins EBPF_BorrowedType:$ref);
  let results = (outs EBPF_MapType:$inner);
  let assemblyFormat = "$ref attr-dict `:` type($ref) `->` type($inner)";
  let hasVerifier = 1;
}

// Keyless queue/stack/bloom operations; see docs/reference/ebpf_ops.md.
def EBPF_MapPushOp : EBPF_Op<"map.push"> {
  let summary = "Push a value to queue, stack, or bloom_filter and return helper status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Inserts a value into a keyless map and returns **raw** i64 status (0 / negative errno). Full queue / stack gives -E2BIG; exist (BPF_EXIST) drops the oldest element and inserts, returning 0. bloom_filter sets the value's hash bits and returns 0.

    **Constraints**: Map is queue / stack / bloom_filter with none key parameter; value matches its integer value type. Queue / stack allow any / exist; bloom_filter only any. noexist and bloom exist are rejected because the kernel would only return -EINVAL. No loop bodies (compiler restriction).

    **Lowering**: Unchanged in ②. Stage ③ stores value in a stack slot and calls map_push_elem(map, &value, flags), with UAPI updateflag values. Slot lifetime follows map.lookup keys.

    **Evidence**: F59. Queue full -E2BIG / exist overwrite, stack, and bloom push match C in 7.1.8 XDP test runs.

    **Unsupported**: Record values (schema rejection); NUMA_NODE / RDONLY / WRONLY map flags; configurable bloom hash count (map_extra 0 uses kernel default 5). 6.12 / 6.6 are unverified.
  }];
  let arguments = (ins EBPF_MapType:$map, AnyType:$value, StrAttr:$flags);
  let results = (outs I64:$status);
  let assemblyFormat = "$map `,` $value `flags` $flags attr-dict `:` type($map) `,` type($value) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_MapPopOp : EBPF_Op<"map.pop"> {
  let summary = "Remove a queue or stack element and return status and value";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Removes the oldest queue element (FIFO) or newest stack element (LIFO). Returns **raw** helper status (0 / negative errno; empty -ENOENT) and value. **Nonzero status yields value 0**: kernel zeros empty results but does not write on lock-failure -EBUSY, so the compiler zeros the slot before calling.

    **Constraints**: Queue / stack only, with none key parameter and integer result matching map value. bloom_filter is rejected (kernel -EOPNOTSUPP). No loop bodies (compiler restriction).

    **Lowering**: Unchanged in ②. Stage ③ zeros a stack slot, calls map_pop_elem(map, &slot), and loads the value width afterward. Lifetime ends after the load.

    **Evidence**: F59. Queue FIFO, stack LIFO, empty -ENOENT / value 0 match C in 7.1.8 XDP test runs.

    **Unsupported**: Record values. 6.12 / 6.6 are unverified.
  }];
  let arguments = (ins EBPF_MapType:$map);
  let results = (outs I64:$status, AnyInteger:$value);
  let assemblyFormat = "$map attr-dict `:` type($map) `->` type($status) `,` type($value)";
  let hasVerifier = 1;
}

def EBPF_MapPeekOp : EBPF_Op<"map.peek"> {
  let summary = "Read the next queue or stack element without removing it, returning status and value";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads the same element as map.pop without removal. Status / value follow pop: nonzero status yields value 0. Bloom uses separate ebpf.bloom.peek.

    **Constraints**: Queue / stack only, none key parameter, integer result matching map value. No loop bodies (compiler restriction).

    **Lowering**: Unchanged in ②. Stage ③ zeros a stack slot, calls map_peek_elem(map, &slot), then loads it as with pop.

    **Evidence**: F59. Queue / stack peek match C in 7.1.8 XDP test runs.

    **Unsupported**: Record values. 6.12 / 6.6 are unverified.
  }];
  let arguments = (ins EBPF_MapType:$map);
  let results = (outs I64:$status, AnyInteger:$value);
  let assemblyFormat = "$map attr-dict `:` type($map) `->` type($status) `,` type($value)";
  let hasVerifier = 1;
}

def EBPF_BloomPeekOp : EBPF_Op<"bloom.peek"> {
  let summary = "Query possible bloom_filter membership and return raw status (zero or -ENOENT)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Returns 0 if every hash bit is set (possibly present: **false positives are possible**), or -ENOENT if any bit is unset (absent: no false negatives). Result is **raw** i64 helper status.

    **Constraints**: bloom_filter only, none key parameter, value matching its integer value type. No loop bodies (compiler restriction).

    **Lowering**: Unchanged in ②. Stage ③ stores value in a stack slot and calls map_peek_elem(map, &value). Kernel resolve_map_arg_type changes bloom peek's value parameter to a read argument.

    **Evidence**: F59. Inserted / absent values in a zero_seed bloom_filter match C in 7.1.8 XDP test runs.

    **Unsupported**: False-positive rate depends on map size / hash count (kernel default 5), not checked at compile time. 6.12 / 6.6 are unverified.
  }];
  let arguments = (ins EBPF_MapType:$map, AnyType:$value);
  let results = (outs I64:$status);
  let assemblyFormat = "$map `,` $value attr-dict `:` type($map) `,` type($value) `->` type($status)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_RefCheckOp : EBPF_Op<"ref.check", [RecursiveMemoryEffects]> {
  let summary = "Check a nullable reference, introducing a borrow only inside the present region";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Checks unchecked !ebpf.maybe_ref<T>: non-NULL executes present, NULL executes absent. In stage ① the checked !ebpf.borrowed<T> exists as a present-region block argument; syntax provides no unchecked dereference path. Both regions may return values with ebpf.yield.

    **Constraints**: Both regions have bodies; present has one borrowed argument preserving T, absent none. The borrow is used only within present by ref.load / store / atomic_add / field.load / field.store, call arguments, ref.index, spin.region, or timer.init / set_callback / start. If T is a map handle (outer map-in-map element), only map.inner is permitted. Integer results are i1 / i8 / i16 / i32 / i64; other widths are rejected (older behavior accepted i1–i128). i1 is tested across three targets by kernel/cmd/i1check. Borrows cannot be yielded or transported via block arguments. If both arms break / continue, no results are permitted.

    **Lowering**: Stage ② creates is_present cf.cond_br and true-edge assume_present; results become merge-block arguments. Stage ③ compares pointer against NULL (icmp ne) and branches, preserving the pointer for the borrow.

    **Evidence**: F01. NULL-check-removal mutation rejected by kernel as map_value_or_null; stage-② expansion / exit checks; borrowed subprogram arguments; break / continue; result widths.

    **Unsupported**: Borrow storage in maps / aggregates or escape outside the region. No unchecked unwrap.
  }];
  let arguments = (ins EBPF_MaybeRefType:$ref);
  let results = (outs Variadic<AnyType>:$results);
  let regions = (region AnyRegion:$presentRegion, AnyRegion:$absentRegion);
  let assemblyFormat = [{
    $ref attr-dict `:` type($ref) (`->` type($results)^)?
    `present` $presentRegion `absent` $absentRegion
  }];
  let hasVerifier = 1;
}

def EBPF_YieldOp : EBPF_Op<"yield",
    [Terminator, ParentOneOf<["RefCheckOp", "RingbufIfReservedOp", "RefIndexOp", "PacketCheckOp", "MetaCheckOp", "ArenaCheckOp", "ArenaAllocOp", "SpinRegionOp", "KPtrCheckOp", "KRefCheckOp", "SockRefCheckOp", "RcuRegionOp", "KsymPerCpuLoadOp"]>]> {
  let summary = "Close a checked region and return its values";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Terminates checked regions: ref.check / ringbuf.if_reserved / ref.index / packet.check / spin.region, returning values if the parent has results. kptr.check and kref.check are also supported parents.

    **Constraints**: ParentOneOf restricts parents to these operations. ref.check forbids borrowed escape and requires result-type agreement. ref.index forbids elem / borrowed escape. packet.check forbids pkt_window escape. arena.check forbids arena_window escape and requires matching results. ringbuf.if_reserved forbids reservation escape and requires matching results. spin.region returns no values. kptr.check / kref.check forbid kptr / kref escape and require matching results. Within loops, ref.check arms may also end with break / continue.

    **Lowering**: Stage ② branches to the merge block with result block arguments. In spin.region it disappears into lock / body / unlock. Absent at ③; ebpf-verify-structured rejects leftovers as stage-① ops.

    **Evidence**: F01, F02, F06, F10, F17. Region expansion, ref.index, packet.check, and spin.region tests.

    **Unsupported**: Borrow / reservation / window / element escape. ebpf.if uses if.yield; ebpf.loop uses loop.yield.
  }];
  let arguments = (ins Variadic<AnyType>:$results);
  let assemblyFormat = "($results^ `:` type($results))? attr-dict";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_RefStoreOp : EBPF_Op<"ref.store"> {
  // AnyType deliberately preserves the 'not checked' diagnostic attribution;
  // a borrowed-only constraint would emit a generic ODS type mismatch.
  let summary = "Store through a borrowed reference (unchecked references are rejected)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Writes the integer pointed to by a borrow. once follows ref.load and becomes a volatile store at ③.

    **Constraints**: Operand is !ebpf.borrowed<T> and value type is T; unchecked references are rejected with a note. No whole-record stores (use ref.field.store). lpm_trie lookup borrows are read-only by compiler restriction. Subprogram-argument borrows are excluded by this documented constraint (read-only callee). once uses ref.load width limits.

    **Lowering**: Stage ③ stores to the borrowed pointer, with alignment derived from map-value alignment 8; once makes it volatile.

    **Evidence**: F01, F29. 7.1.8 acceptance; lpm_trie-write rejection; once tests. Borrowed writes originate in the predecessor compiler's borrowed-reference implementation.

    **Unsupported**: Whole-record stores and lpm_trie value writes.
  }];
  // once emits one access at the declared width (volatile in the ABI stage).
  // See docs/memory_semantics.md.
  let arguments = (ins AnyType:$ref, AnyType:$value, UnitAttr:$once);
  let assemblyFormat = "(`once` $once^)? $ref `,` $value attr-dict `:` type($ref) `,` type($value)";
  let hasVerifier = 1;
}

def EBPF_RefLoadOp : EBPF_Op<"ref.load"> {
  // AnyType deliberately keeps the 'not checked' attribution rather than
  // replacing it with a generic ODS borrowed-type mismatch.
  let summary = "Load through a borrowed reference (unchecked references are rejected)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads the integer pointed to by a borrow. once emits each access exactly once at its declared width (volatile at ③), not acquire / release or atomicity; see docs/memory_semantics.md.

    **Constraints**: Operand !ebpf.borrowed<T>, result T. An unchecked maybe_ref is rejected with a note to use ref.check first. No whole-record reads (use ref.field.load). Subprogram-argument borrows are accepted for callee reads. once supports 8 / 16 / 32 / 64-bit integers only, checked at ③.

    **Lowering**: Stage ③ loads from the pointer with alignment provable from map-value alignment 8; once adds volatile.

    **Evidence**: F01, F29. 7.1.8 acceptance; subprogram arguments; once width checks and normal / once paired tests.

    **Unsupported**: Whole-record reads; once i1 / i24 and other unsupported widths fail at ③.
  }];
  let arguments = (ins AnyType:$ref, UnitAttr:$once); // once has the same semantics as ref.store.
  let results = (outs AnyType:$result);
  let assemblyFormat = "(`once` $once^)? $ref attr-dict `:` type($ref) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_RefIndexOp : EBPF_Op<"ref.index", [RecursiveMemoryEffects]> {
  let summary = "Check variable indices into a record array field and execute in-range or out-of-range regions";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Indexes a borrowed record's array field with variable i32 indices. Each [] in a field template represents one variable index: arr equals arr[], and ins[].addr / m[][] are supported. For every dimension, checks unsigned index < element count. All checks passing executes in_range with a checked !ebpf.elem<iN> block argument; any failure executes out_of_range. : a template ending at an element of a record array (items[] / rows[].items[]) gives in_range a !ebpf.borrowed<!ebpf.record<"S", N>> of that element instead (S and N match the @records element). The program explicitly defines out-of-range behavior: no implicit zero / clamp / mask result.

    **Constraints**: Operand is a record borrow, with at least one index. in_range has one elem argument; out_of_range has none. Only elem.load / elem.store inside in_range may use it; no yield / block-argument transport. A borrowed record element is used by the ref ops and calls inside in_range only, never by yield or a terminator; passing it to a function requires an element alignment of 8 (offset and every stride a multiple of 8 — a function assumes an 8-byte aligned borrow), a nested element is never passed. Writes through an element of a .rodata global are rejected like any .rodata write (ebpf-verify-schema). ebpf-verify-records checks template, [] / index count, and width against @records. Subprogram-argument borrows are excluded. Integer result widths are i1 / 8 / 16 / 32 / 64 only (other widths rejected; older behavior allowed i1–i128). i1 is differentially tested on three targets with kernel/cmd/i1check.

    **Lowering**: Stage ② zero-extends each index once, then emits per-dimension elem.in_range cf.cond_br checks and true-edge elem.at. Stage ③ uses icmp ult and base + field offset + index × stride with the same compared / addressed value. **A loop IV may cause codegen to form the address using a different induction variable**; inspect ELF.

    **Evidence**: F06. Variable indices, multidimensional / record arrays, C agreement on three targets, and loop-IV indexing rejected on all three targets without CAP_PERFMON. Result-width checks.

    **M1 (default)**: On each true checked edge, stage ② passes the index through elem.mask (③ inline-asm barrier plus and 2^k − 1), rechecks elem.in_range (same out_of_range on false), and uses that value in elem.at. Values are unchanged. This removes non-root 6.12 / 6.6 speculative-path rejection at a repeated index comparison. **The guarantee requires the masked address range to fit the value**: field offset + (2^k − 1) × stride + element size ≤ record size. Non-fitting arrays, such as a trailing non-power-of-two array, produce a warning, disabled by --warn-index-mask-fit=false without ELF changes. If spilling loses the recheck's narrowing, 6.6 may reject; padding after the array through the next power of two brings it within the guarantee. For nonconstant indices, cost is +2 instructions per dimension (and / recheck; barrier emits no instruction), with measured processed change −7 to +6. **Direct constant dimensions, including unrolled IVs, omit M1 by default**: the verifier knows them exactly. --tune-mask-skip-constant-index=false restores the earlier form. Previously each unrolled copy cost +5–6 instructions because the barrier obscured constants and retained register load / and / recheck / shift / add; eight copies cost +40–48 instructions and +8–84 processed. --tune-mask-checked-index=false restores pre-M1 output.

    **Diagnostics**: ebpf-compile warns, without stopping or changing ELF, when constant and unknown values reach the same index on different paths (e.g. a lookup-failure default) or when a non-unrolled loop carries it. --warn-nonroot-index=false disables this. Such shapes were rejected by some kernels without CAP_PERFMON. Conditions of enclosing ebpf.if are evaluated with arm constants to exclude unreachable defaults. **An unflagged rejection shape** remains: a user if compares the index with a threshold below element count, and arm helpers preserve the branch through LLVM. Different index ranges then reach the same addition, causing non-root REASON_PATHS rejection on three kernels. M1 does not unify those ranges. Stage ① cannot know whether optimization retains the branch; warning would falsely flag variants with empty arms or thresholds ≥ count. Move ref.index inside the user-if arms or use CAP_PERFMON.

    **Unsupported**: CAP_PERFMON-less loop-IV indexing can fail at load; lowering / requirements are not changed for it. No implicit out-of-range value.
  }];
  let arguments = (ins EBPF_BorrowedType:$ref, StrAttr:$field, Variadic<I32>:$indices);
  let results = (outs Variadic<AnyType>:$results);
  let regions = (region AnyRegion:$inRange, AnyRegion:$outOfRange);
  let assemblyFormat = [{
    $ref $field `[` $indices `]` attr-dict `:` type($ref) `,` type($indices) (`->` type($results)^)?
    `in_range` $inRange `out_of_range` $outOfRange
  }];
  let hasVerifier = 1;
}

def EBPF_ElemLoadOp : EBPF_Op<"elem.load"> {
  let summary = "Load a checked array element";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads !ebpf.elem<iN> validated by ref.index in_range. once follows ref.load (volatile at ③).

    **Constraints**: Result matches iN. Elements exist only as ref.index in_range block arguments, so uses are confined there. once requires 8–64 bits and natural alignment provable at ③ from offset / dimension strides.

    **Lowering**: Stage ③ loads elem.at address with alignment proven from constant offset / strides.

    **Evidence**: F06, F29. Variable / multidimensional array tests, three targets, once.

    **Unsupported**: Uses outside in_range or inside out_of_range.
  }];
  let arguments = (ins EBPF_ElemType:$elem, UnitAttr:$once); // once
  let results = (outs AnySignlessInteger:$result);
  let assemblyFormat = "(`once` $once^)? $elem attr-dict `:` type($elem) `->` type($result)";
  let hasVerifier = 1;
}

def EBPF_ElemStoreOp : EBPF_Op<"elem.store"> {
  let summary = "Store to a checked array element";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Writes an integer to an element checked by ref.index in_range. once follows ref.store.

    **Constraints**: Value type equals element iN; in_range only. Callees cannot use this documented form because ref.index excludes subprogram-argument borrows. once restrictions follow elem.load.

    **Lowering**: Stage ③ stores to elem.at address with provable alignment; once adds volatile.

    **Evidence**: F06, F29. Variable / multidimensional array tests, three targets, once.

    **Unsupported**: Uses outside in_range.
  }];
  let arguments = (ins EBPF_ElemType:$elem, AnySignlessInteger:$value, UnitAttr:$once); // once
  let assemblyFormat = "(`once` $once^)? $elem `,` $value attr-dict `:` type($elem) `,` type($value)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_ElemInRangeOp : EBPF_Stage2Op<"elem.in_range", "ebpf.ref.index (in_range / out_of_range regions)"> {
  let summary = "Test unsigned index against array element count (stage ② internal)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Returns i1 indicating whether a variable index is within the record array field's dimension, selected by dim.

    **Constraints**: Only within stage-② ref.index expansion, using the single zero-extended index value.

    **Lowering**: Stage ③ emits icmp ult against element count.

    **Evidence**: Internal — ebpf-expand-regions creates it from ref.index. ebpf-compile rejects source-input occurrences to prevent bypassing stage-① restrictions. Feature-path evidence belongs to ref.index, including multidimensional arrays.

    **Unsupported**: Not writable in input; use ref.index.
  }];
  let arguments = (ins AnyType:$ref, StrAttr:$field, I64:$index, OptionalAttr<I64Attr>:$dim);
  let results = (outs I1:$result);
  let assemblyFormat = "$ref $field `[` $index `]` attr-dict `:` type($ref)";
}

def EBPF_ElemMaskOp : EBPF_Stage2Op<"elem.mask", "ebpf.ref.index in_range index (--tune-mask-checked-index)"> {
  let summary = "Obscure and mask a checked index (stage ② internal M1)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: On an elem.in_range true edge, obscures the index from the compiler and masks with 2^k − 1, using the smallest 2^k ≥ dimension count. Since the checked index is smaller, this is an identity. Stage ② rechecks elem.in_range on the result (same out_of_range on false), then uses it in elem.at. This reestablishes a range immediately before addition, independent of register history such as speculative unknown values or narrowing lost after spill.

    **Constraints**: Only inside stage-② ref.index expansion with --tune-mask-checked-index.

    **Lowering**: Stage ③ uses an instruction-free inline-asm barrier (`"=r,0"`, like libbpf barrier_var) to prevent known-bits mask elimination, then and.

    **Evidence**: Internal — speculative index probes and M1 implementation tests.

    **Unsupported**: Not writable in input. Does not solve constant / unknown indices reaching the same addition (REASON_PATHS).
  }];
  let arguments = (ins AnyType:$ref, StrAttr:$field, I64:$index, OptionalAttr<I64Attr>:$dim);
  let results = (outs I64:$result);
  let assemblyFormat = "$ref $field `[` $index `]` attr-dict `:` type($ref)";
}

def EBPF_ElemAtOp : EBPF_Stage2Op<"elem.at", "ebpf.ref.index in_range !ebpf.elem with ebpf.elem.load / elem.store"> {
  let summary = "Form a checked element on elem.in_range true edges (stage ② internal)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Refers to a record array element as !ebpf.elem<iN> after range-check true edges, or to an element of a record array as a borrowed record (!ebpf.borrowed<!ebpf.record<…>>).

    **Constraints**: Stage-② exit verification (ebpf-verify-structured 1b) walks backward from the last dimension. Each block must have exactly one incoming true edge from cf.cond_br whose elem.in_range condition has the same ref / field / dimension index / dim (CheckedEdge defines the checked-edge condition). Elem uses are limited to elem.load / elem.store; a borrowed element may be used by any non-terminator (the ref ops and calls — never a branch operand).

    **Lowering**: Stage ③ forms record field offset (@records) + index × stride. Loop-IV indexing can cause codegen to form the address with another induction variable; inspect ELF.

    **Evidence**: Internal — ebpf-expand-regions creates it from ref.index in_range. Source input is rejected to prevent stage-① bypass. ref.index owns feature evidence; checked-edge placement is shared.

    **Unsupported**: Not writable in input; use ref.index.
  }];
  let arguments = (ins AnyType:$ref, StrAttr:$field, Variadic<I64>:$indices);
  let results = (outs AnyTypeOf<[EBPF_ElemType, EBPF_BorrowedType]>:$result);
  let assemblyFormat = "$ref $field `[` $indices `]` attr-dict `:` type($ref) `->` type($result)";
}

def EBPF_RefFieldLoadOp : EBPF_Op<"ref.field.load"> {
  let summary = "Load a named field from a borrowed record";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads a named path in !ebpf.borrowed<!ebpf.record<"S", N>>. Paths are x / x.y / x[i] with constant indices. Schema determines offsets / widths, read from @records BTF declarations; the compiler does not compute layout. once follows ref.load.

    **Constraints**: Operand must be a record borrow; unchecked refs are rejected with a note. ebpf-verify-records checks field presence, path form (≤ 3 components, integer arrays ≤ 2 dimensions, record arrays one dimension, constant in-range indices), and result width. spin_lock / timer field reads, including lock.val paths, are rejected. Subprogram-argument borrows can be read. once needs 8–64-bit width and naturally aligned access provable at ③.

    **Lowering**: Stage ③ loads borrowed pointer + @records offset with alignment proved from map-value alignment 8 and offset; once adds volatile.

    **Evidence**: F03, F29. @records checks on three targets; nested / array elements; depth 3 / two dimensions; borrowed record subprogram arguments; rejection of once without provable alignment.

    **Unsupported**: Variable indices (use ref.index) and non-leaf paths.
  }];
  let arguments = (ins AnyType:$ref, StrAttr:$field, UnitAttr:$once); // once
  let results = (outs AnySignlessInteger:$result);
  let assemblyFormat = "(`once` $once^)? $ref $field attr-dict `:` type($ref) `->` type($result)";
  let hasVerifier = 1;
}

def EBPF_RefFieldStoreOp : EBPF_Op<"ref.field.store"> {
  let summary = "Store a named field of a borrowed record";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Writes an integer by path, following ref.field.load's offset / path rules. once follows ref.store.

    **Constraints**: Operand is a record borrow; lpm_trie writes are rejected. ebpf-verify-records checks path / width and rejects spin_lock / timer field writes. Subprogram-argument borrows cannot be used (callees read only). Within spin.region, only non-lock fields of that same borrow can be written.

    **Lowering**: Stage ③ stores at borrowed pointer + @records offset with provable alignment; once adds volatile.

    **Evidence**: F03, F29. Three-target record / nested / array tests and borrowed-record subprogram arguments. Subsequent callee-write support permits these writes in callees.

    **Unsupported**: Variable indices use ref.index / elem.store; whole-record replacement uses map.update / record.make.
  }];
  let arguments = (ins AnyType:$ref, StrAttr:$field, AnySignlessInteger:$value, UnitAttr:$once); // once
  let assemblyFormat = "(`once` $once^)? $ref $field `,` $value attr-dict `:` type($ref) `,` type($value)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_RefFieldAtomicAddOp : EBPF_Op<"ref.field.atomic_add"> {
  let summary = "Atomically add to a named field of a borrowed record, without a result";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Atomically adds delta to a field using ref.field.load path rules. No FETCH of the old value, like ref.atomic_add. Shared-map counters do not lose multi-CPU updates; field.load / add / field.store does lose them.

    **Constraints**: Checked record borrow only (unchecked rejection includes a note); no lpm_trie; **delta width 32 / 64 only**. ebpf-verify-records checks path / width, rejects spin_lock / timer fields, and requires field offset divisible by access byte width, together with map-value alignment 8 proving natural alignment. Rejected inside spin.region / timer.callback; accepted inside loops and per-CPU record fields (safe, allowing a common frontend form).

    **Lowering**: Unchanged in ②. Stage ③ emits result-unused monotonic atomicrmw add at pointer + @records offset (BPF non-FETCH lock *(u32|u64) +=). Insufficient alignment / unexpected widths also fail explicitly at ③ as defense in depth.

    **Evidence**: F03. Three-target root / non-root concurrent multi-CPU fieldatomic test runs preserve counts, while the same-record load / store += control loses them. ELF has non-FETCH lock +=.

    **Unsupported**: FETCH, non-add atomics, and elem.atomic_add for ref.index elements. No acquire / release ordering semantics (docs/memory_semantics.md).
  }];
  let arguments = (ins AnyType:$ref, StrAttr:$field, AnySignlessInteger:$delta);
  let assemblyFormat = "$ref $field `,` $delta attr-dict `:` type($ref) `,` type($delta)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_RefFieldCmpxchgOp : EBPF_Op<"ref.field.cmpxchg", [AllTypesMatch<["expected", "desired", "old"]>]> {
  let summary = "Atomically compare and exchange a named field of a borrowed record, returning the old value";
  let description = [{
    **Stage**: ① Input

    **Meaning**: `%old = ebpf.ref.field.cmpxchg %r "path", %expected, %new : !ebpf.borrowed<!ebpf.record<…>>, iN` atomically compares the field with expected and, when equal, writes new; %old is the field's value before the operation either way (C's `__sync_val_compare_and_swap`). A boolean CAS is `arith.cmpi eq %old, %expected`. Path rules are ref.field.load's.

    **Constraints**: Checked record borrow only (map value, ebpf.global.ref of a .bss record, a record-array element borrow), no lpm_trie value; **width 32 / 64 only**; expected, new and the result share the type. ebpf-verify-records checks path / width, rejects spin_lock / timer / kptr fields and requires the field offset to be a multiple of the access width (natural alignment, the kernel's strict atomic access). A .rodata record borrow is read-only (ebpf-verify-schema's walk rejects it). Allowed in ebpf.loop / ebpf.iter.num bodies (the retry loop) and in static functions that write their borrowed argument; rejected inside spin.region / timer.callback.

    **Lowering**: Unchanged in ②. Stage ③ GEPs pointer + @records offset; i64 is llvm.cmpxchg seq_cst seq_cst (result 0 — BPF `r0 = cmpxchg_64`); i32 is inline asm `w0 = cmpxchg32_32($1 + 0, w0, w2)` with constraints `={r0},r,{r0},{r2},~{memory}` (the same form — LLVM rejects a 32-bit cmpxchg below CPU v3 and ObjectEmitter targets v1). The kernel's cmpxchg instruction is a full barrier (x86 JIT `lock cmpxchg`); the asm `~{memory}` clobber is a compiler barrier only.

    **Evidence**: Out of scope — release evidence: no F id yet. Static: lit (③ IR, asm string, negatives), instruction match against clang -mcpu=v3 with the value paths (expected → r0, new → r2, old from r0), named mutants, elf-snapshot, opcheck host row run by the B0 root smoke (7.1.8 load). Values and multi-CPU atomicity: measured separately.

    **Unsupported**: 8 / 16-bit widths, ref.cmpxchg (non-record borrows), elem.* (ref.index integer elements), acquire / release orderings (docs/memory_semantics.md).
  }];
  let arguments = (ins AnyType:$ref, StrAttr:$field, AnySignlessInteger:$expected, AnySignlessInteger:$desired);
  let results = (outs AnySignlessInteger:$old);
  let assemblyFormat = "$ref $field `,` $expected `,` $desired attr-dict `:` type($ref) `,` type($old)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_RefFieldAtomicOrOp : EBPF_Op<"ref.field.atomic_or"> {
  let summary = "Atomically OR into a named field of a borrowed record, without a result";
  let description = [{
    **Stage**: ① Input

    **Meaning**: `ebpf.ref.field.atomic_or %r "path", %v : !ebpf.borrowed<!ebpf.record<…>>, iN` atomically ORs v into the field. No FETCH of the old value, like ref.field.atomic_add. Path rules are ref.field.load's.

    **Constraints**: The ref.field.atomic_add rules: checked record borrow only, no lpm_trie value, **width 32 / 64 only**, ebpf-verify-records path / width / spin_lock / timer / kptr / natural-alignment checks, read-only .rodata record borrows rejected (ebpf-verify-schema), allowed in loops and writing static functions, rejected inside spin.region / timer.callback.

    **Lowering**: Unchanged in ②. Stage ③: i64 is result-unused monotonic llvm.atomicrmw or (BPF non-FETCH `lock *(u64 *) |=`); i32 is inline asm `lock *(u32 *)($0 + 0) |= w2` with constraints `r,{r2},~{memory}` (LLVM rejects a 32-bit atomicrmw or below CPU v3). The contract is monotonic non-FETCH, as atomic_add — not the seq_cst of C's `__sync_fetch_and_or` (clang emits atomic_fetch_or there); the asm `~{memory}` clobber is a compiler barrier only.

    **Evidence**: Out of scope — release evidence: no F id yet. Static: lit, instruction match against clang -mcpu=v3 (__sync arm: C's FETCH or at both widths is a named expected row; relaxed `__atomic_fetch_or` arm: exact match), named mutant M-or-add, elf-snapshot, opcheck host row run by the B0 root smoke (7.1.8 load). Values and multi-CPU atomicity: measured separately.

    **Unsupported**: FETCH, and / xor / xchg, 8 / 16-bit widths, ref.atomic_or / map.atomic_or / elem.*, acquire / release orderings.
  }];
  let arguments = (ins AnyType:$ref, StrAttr:$field, AnySignlessInteger:$value);
  let assemblyFormat = "$ref $field `,` $value attr-dict `:` type($ref) `,` type($value)";
  let hasVerifier = 1;
}

def EBPF_RefFieldAddrOp : EBPF_Op<"ref.field.addr", [Pure]> {
  let summary = "The address of an embedded cpumask field of a borrowed record, for cpumask kfuncs";
  let description = [{
    **Stage**: ① Input

    **Meaning**: `%m = ebpf.ref.field.addr %r "path" : !ebpf.borrowed<!ebpf.record<"S", N>> -> !ebpf.cpumask_mem<M>` takes the address of a schema `{"kind": "cpumask", "size": M}` field (path rules are ref.field.load's) so cpumask kfuncs (`bpf_cpumask_set_cpu`, `test_cpu`, `copy`, …) work on the embedded struct in place — LAVD's `struct bpf_cpumask cpdom_cpumask[128]`.

    **Constraints**: Checked record borrow only (map value, .bss record global, record-array element). ebpf-verify-records requires the path to name a cpumask field of size M (other fields are rejected — ref.field.load / store / atomic_add on a cpumask field are rejected there too). A .rodata record cannot hold a cpumask (schema), and ebpf-verify-schema's read-only walk rejects the op through any .rodata borrow. The result is used only as a `*bpf_cpumask` / `*cpumask` argument of an ebpf.kfunc.call that neither acquires nor releases (UAPI table flags), in the same region; yield, stores, calls, other ops and loop capture are rejected by name.

    **Lowering**: Unchanged in ②. Stage ③ is the ref.field.* GEP (pointer + @records offset) as !llvm.ptr, passed to the kfunc call. ObjectEmitter writes `kstructsize bpf_cpumask <M>` once per distinct M (ascending; format 28) — the loader stops when the target's struct bpf_cpumask is larger than any M (`kstructsize`), absent or unknown (`kstructsize_unknown`).

    **Evidence**: Out of scope — release evidence: no F id yet. Static: lit (op / @records / schema negatives, btf-verify C7), BTF / ELF shape against C (argument = value or global address + field offset, same kfunc relocs), requirements corpus, layout and bindgen-hole tests, three named mutants (Check of the largest N only, GEP without the offset, yield allowed); 7.1.8 load by the B0 root smoke's opcheck row; values (neighbouring elements unchanged) are measured separately.

    **Unsupported**: acquire / release kfuncs (bpf_cpumask_release etc. take kptrs only), cpumask arrays (use an array of records), .rodata cpumasks, reading or writing the bytes directly.
  }];
  let arguments = (ins AnyType:$ref, StrAttr:$field);
  let results = (outs EBPF_CpumaskMemType:$addr);
  let assemblyFormat = "$ref $field attr-dict `:` type($ref) `->` type($addr)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_RefAtomicAddOp : EBPF_Op<"ref.atomic_add"> {
  let summary = "Atomically add to an integer through a borrowed reference (unchecked references are rejected)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Result-unused monotonic atomic add through a borrow. Also produced by stage-② map.atomic_add expansion, but directly writable in stage ①.

    **Constraints**: Operand !ebpf.borrowed<T>, delta T; unchecked refs are rejected with a note. No lpm_trie addition or subprogram-argument borrows. **Only 32 / 64-bit widths**, as with map.atomic_add.

    **Lowering**: Unchanged in ②. Stage ③ emits result-unused monotonic LLVM atomicrmw add (BPF non-FETCH lock +=), with explicit defensive rejection of unexpected widths.

    **Evidence**: F01. Stage-② expansion; direct and expanded forms accepted on 7.1.8; ELF lock *(u32|u64) +=; width rules.

    **Unsupported**: FETCH and non-add atomics.
  }];
  let arguments = (ins AnyType:$ref, AnySignlessInteger:$delta);
  let assemblyFormat = "$ref `,` $delta attr-dict `:` type($ref) `,` type($delta)";
  let hasVerifier = 1;
}

// Structured stage-2 operations created only by ebpf-expand-regions.
// Descriptions in docs/reference/ebpf_ops.md define semantics and constraints.
def EBPF_IsPresentOp : EBPF_Stage2Op<"is_present", "ebpf.ref.check / ebpf.ringbuf.if_reserved (present / absent regions)", [Pure]> {
  let summary = "Test an unchecked reference or reservation for non-NULL (stage ② internal)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Returns i1 for non-NULL !ebpf.maybe_ref / !ebpf.maybe_reservation / !ebpf.sock_ref_or_null.

    **Constraints**: Checked by ebpf-verify-structured at the stage-② exit. Paired with assume_present so only true edges can use contents. Packet-neutral (isPacketNeutral table): W1 and diagnostic passes may cross it between window definition / use.

    **Lowering**: Stage ③ emits icmp ne against NULL.

    **Evidence**: Internal — generated from ref.check / ringbuf.if_reserved by ebpf-expand-regions. Source input is rejected to prevent stage-① bypass. Input ops own feature evidence; adding it to PacketNeutral preserves existing ELF, with W1-changing synthetic inputs gated on three targets.

    **Unsupported**: Not writable in input; use ref.check / ringbuf.if_reserved / sock.ref_check.
  }];
  let arguments = (ins AnyType:$value);
  let results = (outs I1:$result);
  let assemblyFormat = "$value attr-dict `:` type($value)";
  let hasVerifier = 1;
}

def EBPF_AssumePresentOp : EBPF_Stage2Op<"assume_present", "ebpf.ref.check / ebpf.ringbuf.if_reserved (present-region block argument)"> {
  let summary = "Obtain a checked reference or reservation on an is_present true edge (stage ② internal)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Uses an unchecked value as !ebpf.borrowed / !ebpf.reservation / !ebpf.sock_ref on an is_present true edge.

    **Constraints**: Op verifier checks only type conversion (maybe_ref → borrowed, maybe_reservation → reservation, sock_ref_or_null → sock_ref). Placement is checked at stage-② exit (ebpf-verify-structured 1): block must have a single incoming true edge from cf.cond_br conditioned on is_present of the same value. A false edge into the same block is rejected, preventing unchecked borrows. CheckedEdge defines the condition and is shared with diagnostic passes. Packet-neutral.

    **Lowering**: Stage ③ preserves the pointer; is_present supplies the comparison.

    **Evidence**: Internal — generated from ref.check / ringbuf.if_reserved present regions. Source input is rejected to prevent stage-① bypass. Input ops own feature evidence; tests cover PacketNeutral and both edges targeting the same block.

    **Unsupported**: Not writable in input.
  }];
  let arguments = (ins AnyType:$value);
  let results = (outs AnyType:$result);
  let assemblyFormat = "$value attr-dict `:` type($value) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_PacketLoadOp : EBPF_Op<"packet.load", [MemoryEffects<[MemRead<EBPF_PacketResource>]>]> {
  let summary = "Load an integer from the context packet";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads little-endian integer bytes at unsigned zero-extended offset. Returns 0 if data + offset + width exceeds data_end, or a variable offset exceeds its limit. Interpreting an out-of-range zero is the caller's responsibility.

    **Constraints**: Context kind must have a PACKET range pair: XDP / __sk_buff data / data_end, cgroup_sockopt optval / optval_end, sk_msg_md data / data_end, or sk_reuseport_md data / data_end. For reuseport, UDP selection starts at UDP header, TCP SYN at TCP header, migration has length 0. **Result and offset widths are i8 / i16 / i32 / i64**; previous unsupported widths caused crashes, silent 3/16-byte reads, or internal errors. Stage ③ rejects constant offset > 65535 − width. Allowed in loops except callbacks, which cannot capture context.

    **Lowering**: Stage ③ reads the kind's range pair with UAPI widths via bpfabi.ctx_packet (cgroup_sockopt uses eight-byte optval / optval_end). For variable offsets, first branches to zero if off > MAX_PACKET_OFF − width, also catching high bits of i64 offsets. Then checks at + width ≤ data_end and loads bytes individually for strict alignment, except that a constant offset off with (2 + off) mod width = 0 (the strict-alignment verifier's NET_IP_ALIGN = 2 rule) is one width-aligned load (--tune-aligned-packet-load, default; =false keeps bytewise reads). i64 offsets are not zero-extended. Stage ② replaces provably in-range constant-offset reads with packet.window_load via W1.

    **Evidence**: F10, F20. Kernel op checks exposed variable-offset rejection; explicit offset bound; byte loads; one wide load at strict-aligned constant offsets (three targets, normal and BPF_F_STRICT_ALIGNMENT, misaligned mutant rejected); window_load rewrites; width checks and three-target i64 offsets 2^32 + 12 / 2^63 returning 0.

    **Unsupported**: Contexts whose PACKET entry is -, and widths outside 8 / 16 / 32 / 64 bits.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, AnySignlessInteger:$offset);
  let results = (outs AnySignlessInteger:$result);
  let assemblyFormat =
      "$ctx `[` $offset `]` attr-dict `:` type($ctx) `,` type($offset) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_PacketCheckOp : EBPF_Op<"packet.check", [RecursiveMemoryEffects]> {
  let summary = "Check a packet range and introduce a scoped window (stores only for XDP or cgroup_sockopt entry; window_load reads)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Checks [offset, offset + len) against data_end. Success executes in_range with its sole block argument !ebpf.pkt_window<len>; failure executes explicit out_of_range. Both arms may return values via ebpf.yield (`-> T…`).

    **Constraints**: Context kind must have PACKET range: XDP / __sk_buff, cgroup_sockopt optval / optval_end, sk_msg, or sk_reuseport. Only XDP and cgroup_sockopt own-entry programs support writes. Constant len is 1..65535 (MAX_PACKET_OFF). Constant offsets use subtraction-form offset ≤ 65535 − len. in_range has exactly one matching window argument; out_of_range has none. Window uses are packet.store / packet.window_load within in_range, or an operand to a **static ebpf.func call** with exactly the same pkt_window<len> (no shrinking). No yield escape or block-argument transport.
    packet.store accepts XDP and cgroup_sockopt own-entry windows only. cgroup_sockopt requires a direct checked window built from entry ctx; stores to static-function windows are rejected. sched_cls and other read-only kinds reject stores. Stores are packet-write barriers (MemWrite<packet>) for C1 / W1. Actual 7.1.8 own-child-cgroup / fresh-netns / own-socket SET / GET measurements cover 40 normal cases, two distinct mutations, and zero cleanup residue, with no C difference; older kernels and actual non-root are unmeasured.
    Inside ebpf.loop, **all enclosing loops must be U / unroll**. Variable offsets such as iter_args-driven walks are allowed; B / H bodies are rejected. To stop a walk out of bounds, test the i1 result with ebpf.if then ebpf.break (break parents remain if / ref.check only). Offset widths are i8 / i16 / i32 / i64.

    **Lowering**: Stage ② ebpf-expand-regions first replaces constant-offset packet.load directly in the in_range entry block with window_load, sinks rewritten reads to first use (C1), zero-extends offset to i64, then emits pkt.check_br and ^in(%w) / ^out blocks.
    Stage ③ reads the kind's PACKET pair using UAPI offsets: xdp_md data / data_end 0 / 4, __sk_buff 76 / 80 (four-byte fields), bpf_sockopt optval / optval_end 8 / 16 (eight-byte fields). It branches on data + off + len ≤ data_end, preserving the comparison's pointer register as the window.

    **Evidence**: F10, F11, F20. Subtraction-form bounds; three-target tests and removed-boundary mutation; sched_cls read-only; window_load / C1 / W1; rejection of input pkt.check_br. Integer result widths are i1 / 8 / 16 / 32 / 64; others are rejected. Three-target i1 differential tests use kernel/cmd/i1check.

    **Unsupported**: B / H body checks (future B work needs DominatedBackward structured verification; H needs context capture). Windows cannot escape regions or cross iterations. No writes for read-only kinds. Loop-carried values and function arguments remain i8 / i16 / i32 / i64, excluding i1 even though checked-region results allow it.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, AnySignlessInteger:$offset, I64Attr:$len);
  let results = (outs Variadic<AnySignlessInteger>:$results);
  let regions = (region AnyRegion:$inRange, AnyRegion:$outOfRange);
  let assemblyFormat = [{
    $ctx `[` $offset `]` `len` $len attr-dict `:` type($ctx) `,` type($offset) (`->` type($results)^)?
    `in_range` $inRange `out_of_range` $outOfRange
  }];
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_PacketStoreOp : EBPF_Op<"packet.store", [MemoryEffects<[MemWrite<EBPF_PacketResource>]>]> {
  let summary = "Store an integer to a checked packet window";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Writes a little-endian integer at constant index in a checked window, for XDP or a cgroup_sockopt own-entry window.

    **Constraints**: Value is i8 / i16 / i32 / i64. [index, index + width) must fit the window, checked by subtraction to avoid overflow such as index −1. Window is a packet.check in_range argument. cgroup_sockopt stores require the own-entry checked optval window, not a static function. packet.check rejects read-only kinds such as sched_cls. Stage-② may-invalidate checking rejects uses if any path from definition crosses xdp.adjust_head / adjust_tail.

    **Lowering**: Stage ③ extracts bytes with lshr / trunc and stores each at window + index + k, alignment 1. Memory effect is packet write.

    **Evidence**: F11, F10. Three-target bounds / removed-check mutation / non-root variable offsets; rewrite and receiver checksum; post-helper-use rejection; closed sched_cls bypass.

    **Unsupported**: Read-only kinds, static-function cgroup_sockopt windows, variable indices, and out-of-window stores.
  }];
  let arguments = (ins EBPF_PktWindowType:$window, I64Attr:$index, AnySignlessInteger:$value);
  let assemblyFormat = "$window `[` $index `]` `,` $value attr-dict `:` type($window) `,` type($value)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_PacketWindowLoadOp : EBPF_Op<"packet.window_load", [MemoryEffects<[MemRead<EBPF_PacketResource>]>]> {
  let summary = "Load an integer from a checked packet window";
  let description = [{
    **Stage**: ① Input (packet.check in_range window), also generated at ② by packet.load rewrites

    **Meaning**: Reads at a constant index without another range check.

    **Constraints**: Bytes must fit the window; out-of-range indices are rejected. Window is a packet.check in_range argument. Stage-② may-invalidate checking rejects any definition-to-use path crossing packet-pointer invalidation such as adjust_head / adjust_tail.

    **Lowering**: Stage ③ loads bytes individually at window + constant, with strict alignment; when the window's pkt.check_br offset c is constant and (2 + c + index) mod width = 0 it is one width-aligned load (--tune-aligned-packet-load, default). Stage ② rewrites constant-offset packet.load directly in in_range entry (initial rewrite), sinks it before first use (C1), and also rewrites loads in blocks dominated by in_range (W1).

    **Evidence**: F10, (aligned wide reads). Initial rewrite / C1 / W1, non-neutral rewrite barriers, and the decision to retain this as a source-writable op rather than stage-②-only.

    **Unsupported**: Variable indices (use packet.load). In loops, only windows from packet.check inside U loops are allowed; windows cannot cross iterations.
  }];
  let arguments = (ins EBPF_PktWindowType:$window, I64Attr:$index);
  let results = (outs AnySignlessInteger:$result);
  let assemblyFormat = "$window `[` $index `]` attr-dict `:` type($window) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_PktCheckBrOp : EBPF_Stage2Op<"pkt.check_br", "ebpf.packet.check (in_range / out_of_range regions)", [Terminator]> {
  let summary = "Branch on packet bounds, passing a window to the true successor (stage ② internal)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Terminates with a branch testing [offset, offset + len). The in-range successor ^in has a sole !ebpf.pkt_window<len> argument.

    **Constraints**: Op verifier checks successor count / arguments. Offset is one zero-extended i64 value. ebpf-verify-structured checks invalidating helpers before window uses.

    **Lowering**: Stage ③ preserves the pointer register used for data + offset + len versus data_end comparison (ugt / ule). Constant-offset checking uses subtraction to avoid overflow.

    **Evidence**: Internal — expanded from packet.check; source input is rejected to prevent bypassing stage-① restrictions, including read-only sched_cls windows. packet.check owns feature evidence.

    **Unsupported**: Not writable in input; use packet.check (window stores are XDP-only).
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I64:$offset, I64Attr:$len);
  let successors = (successor AnySuccessor:$inRange, AnySuccessor:$outOfRange);
  let assemblyFormat = "$ctx `[` $offset `]` `len` $len `,` $inRange `,` $outOfRange attr-dict `:` type($ctx)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_MetaCheckOp : EBPF_Op<"xdp.meta_check", [RecursiveMemoryEffects]> {
  let summary = "Check that len bytes of XDP metadata exist before data and introduce a scoped meta window (XDP only)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Checks `data_meta + len <= data` (both read from the XDP context). Success executes in_range with its sole block argument !ebpf.meta_window<len>; failure executes the explicit out_of_range region. Neither arm yields values. `data_end` is not consulted.

    **Constraints**: The context is the entry context of an XDP program (not a static function's argument). len is 1..255. in_range takes exactly one !ebpf.meta_window<len> argument and out_of_range none. The window may only be used by ebpf.xdp.meta_store / ebpf.xdp.meta_load inside this in_range region — block-argument transport, yield, results, call arguments, select, record / map storage and loop / callback forwarding are rejected. Not allowed in ebpf.loop. Stage ② requires every window use to be free of packet-pointer invalidators (adjust_head / adjust_tail / adjust_meta / tail_call / seg6 …) on every path from the check; check again after one.

    **Lowering**: Stage ② ebpf-expand-regions emits meta.check_br with ^in(%w) / ^out blocks. Stage ③ reads `data_meta` and `data` (4-byte context fields), computes `data_meta + len` and branches on `ule data`.

    **Evidence**: Out of scope — no release F row yet; static checks cover it, and a separate run covers it in VMs on 7.3.1, 7.1.8, 6.12.111 and 6.6.157 as root with byte-wise meta accesses against an independent C oracle (XDP BPF_PROG_TEST_RUN, strict-aligned loads): the stored bytes appear at the start of data_out, the out_of_range arm is taken when the meta is shorter than the window, and a re-check after adjust_meta reads the stored value back from a real load. XDP TEST_RUN only.

    **Unsupported**: Non-XDP programs, windows across regions, loops, calls and callbacks, variable indices, a tc-side read (a separate plan), and any claim about what the metadata bytes contain.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I64Attr:$len);
  let regions = (region AnyRegion:$inRange, AnyRegion:$outOfRange);
  let assemblyFormat = [{
    $ctx `len` $len attr-dict `:` type($ctx) `in_range` $inRange `out_of_range` $outOfRange
  }];
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_MetaLoadOp : EBPF_Op<"xdp.meta_load"> {
  let summary = "Load an integer from a checked XDP meta window";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads a little-endian integer at a constant index of a checked meta window, without another range check. The bytes read are whatever the metadata area holds: adjust_meta does not zero them, so reading a byte nobody wrote returns unspecified data.

    **Constraints**: Result is i8 / i16 / i32 / i64. [index, index + width) must fit the window, checked by subtraction (index > len or width > len − index is rejected, so a huge index cannot wrap). The window is the in_range argument of an xdp.meta_check and the use is inside that region.

    **Lowering**: Stage ③ always reads byte by byte (width loads of align 1) and assembles the value. The first stage never uses a wide access: the strict alignment of PTR_TO_PACKET_META is `NET_IP_ALIGN`-relative and a 4-multiple `data - data_meta` does not imply an aligned start.

    **Evidence**: Out of scope — no release F row yet; static checks cover it, and a separate run covers it in VMs on 7.3.1, 7.1.8, 6.12.111 and 6.6.157 as root with byte-wise meta accesses against an independent C oracle (XDP BPF_PROG_TEST_RUN, strict-aligned loads): the stored bytes appear at the start of data_out, the out_of_range arm is taken when the meta is shorter than the window, and a re-check after adjust_meta reads the stored value back from a real load. XDP TEST_RUN only.

    **Unsupported**: Variable indices, sign-extending loads, wide accesses, reads after an invalidating operation.
  }];
  let arguments = (ins EBPF_MetaWindowType:$window, I64Attr:$index);
  let results = (outs AnySignlessInteger:$result);
  let assemblyFormat = "$window `[` $index `]` attr-dict `:` type($window) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_MetaStoreOp : EBPF_Op<"xdp.meta_store"> {
  let summary = "Store an integer to a checked XDP meta window";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Writes a little-endian integer at a constant index of a checked meta window. Only the written bytes change; the compiler never zero-fills the metadata area, so the caller writes every byte it wants a reader to see.

    **Constraints**: Value is i8 / i16 / i32 / i64. [index, index + width) must fit the window, checked by subtraction. The window is the in_range argument of an xdp.meta_check and the use is inside that region.

    **Lowering**: Stage ③ stores byte by byte (align 1, little-endian) and never as a wide access.

    **Evidence**: Out of scope — no release F row yet; static checks cover it, and a separate run covers it in VMs on 7.3.1, 7.1.8, 6.12.111 and 6.6.157 as root with byte-wise meta accesses against an independent C oracle (XDP BPF_PROG_TEST_RUN, strict-aligned loads): the stored bytes appear at the start of data_out, the out_of_range arm is taken when the meta is shorter than the window, and a re-check after adjust_meta reads the stored value back from a real load. XDP TEST_RUN only.

    **Unsupported**: Variable indices, wide accesses, stores after an invalidating operation, atomics.
  }];
  let arguments = (ins EBPF_MetaWindowType:$window, I64Attr:$index, AnySignlessInteger:$value);
  let assemblyFormat = "$window `[` $index `]` `,` $value attr-dict `:` type($window) `,` type($value)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_MetaCheckBrOp : EBPF_Stage2Op<"meta.check_br", "ebpf.xdp.meta_check (in_range / out_of_range regions)", [Terminator]> {
  let summary = "Branch on the XDP metadata bound, passing a window to the true successor (stage ② internal)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Terminates with a branch testing `data_meta + len <= data`. The in-range successor ^in has a sole !ebpf.meta_window<len> argument.

    **Constraints**: Op verifier checks successor count / arguments and that the context is an XDP context. ebpf-verify-structured requires ^in to be entered only from this branch and walks invalidators before window uses.

    **Lowering**: Stage ③ reads the two context fields with bpfabi.ctx_meta and compares the advanced meta pointer against data (ule).

    **Evidence**: Internal — expanded from xdp.meta_check; source input is rejected to prevent bypassing stage-① restrictions. xdp.meta_check owns feature evidence.

    **Unsupported**: Not writable in input; use xdp.meta_check.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I64Attr:$len);
  let successors = (successor AnySuccessor:$inRange, AnySuccessor:$outOfRange);
  let assemblyFormat = "$ctx `len` $len `,` $inRange `,` $outOfRange attr-dict `:` type($ctx)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_ArenaAllocOp : EBPF_Op<"arena.alloc"> {
  let summary = "Allocate a fixed arena page range with explicit success and failure";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Requests page_count pages at canonical base + page_offset * 4096,
    NUMA_NO_NODE, flags zero. Success requires a non-NULL result equal to the
    entire requested address and its low 32 bits. Any mismatch takes failure.
    A non-NULL mismatch does not guarantee cleanup; map destruction remains the
    final owner. Success introduces a lexical arena_pages proof, not a pointer.
    **Constraints**: One arena, x86_64, sleepable syscall entry body, constant
    nonnegative offset and positive count inside the schema map. No nesting,
    loops, callbacks, unknown free effects or proof transport..
    **Lowering**: ② arena.alloc_br; ③ named kfunc call and address comparisons;
    ④ BTF-resolved extern relocation. No automatic free on region exit.
    **Evidence**: Out of scope — the static contract is checked; kernel execution is a separate experiment.
    **Unsupported**: Automatic address selection, partial free, external free,
    first-class pointers, allocation proof across programs or calls.
  }];
  let arguments = (ins EBPF_MapType:$map, I64Attr:$page_offset, I64Attr:$page_count);
  let results = (outs Variadic<AnyType>:$results);
  let regions = (region AnyRegion:$allocated, AnyRegion:$failed);
  let hasVerifier = 1;
}

def EBPF_ArenaFreeOp : EBPF_Op<"arena.free"> {
  let summary = "Invalidate a lexical allocation proof and request page release";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Frees the full allocation range, once. The kfunc returns void;
    neither physical completion nor the timing of a later fault is acknowledged.
    **Constraints**: Directly in the owning success block, outside every window.
    No subsequent arena access or reconstituted proof in that success arm.
    **Lowering**: ② arena.free_pages; ③ named void kfunc; ④ extern relocation.
    **Evidence**: Out of scope — checks the static contract; kernel completion is not measured.
    **Unsupported**: Partial release, conditional release, external concurrent free.
  }];
  let arguments = (ins EBPF_ArenaPagesType:$pages);
  let hasVerifier = 1;
}

def EBPF_ArenaAllocBrOp : EBPF_Stage2Op<"arena.alloc_br", "ebpf.arena.alloc", [Terminator]> {
  let summary = "Internal branch on the exact address returned by arena allocation";
  let description = [{
    **Stage**: ② Internal
    **Meaning**: Allocates the original fixed page range and chooses success or failure.
    **Constraints**: Generated from a checked arena.alloc; successors have no arguments.
    **Lowering**: Named kfunc plus non-NULL/full-address/low32 comparisons.
    **Evidence**: Internal — generated from the checked arena.alloc.
    **Unsupported**: Direct input.
  }];
  let arguments = (ins EBPF_MapType:$map, I64Attr:$page_offset, I64Attr:$page_count);
  let successors = (successor AnySuccessor:$allocated, AnySuccessor:$failed);
  let hasVerifier = 1;
}

def EBPF_ArenaFreePagesOp : EBPF_Stage2Op<"arena.free_pages", "ebpf.arena.free"> {
  let summary = "Internal release of a checked fixed allocation range";
  let description = [{
    **Stage**: ② Internal
    **Meaning**: Carries the original allocation map and full constant range.
    **Constraints**: Only generated from a checked lexical arena.free.
    **Lowering**: Named void kfunc with map, canonical address, count.
    **Evidence**: Internal — generated from the checked arena.free.
    **Unsupported**: Direct input.
  }];
  let arguments = (ins EBPF_MapType:$map, I64Attr:$page_offset, I64Attr:$page_count);
}

def EBPF_ArenaBaseOp : EBPF_Op<"arena.base"> {
  let summary = "Read the arena's user-space start address (window base) from its map";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads `user_vm_start` of the arena map — the user address at which the arena memory is mapped (the schema's `map_extra`). The result `!ebpf.arena_base` is only the base operand of ebpf.arena.check; it addresses nothing by itself.

    **Constraints**: The map is a schema `arena` map bound as `!ebpf.map<"arena", none, none>` (the schema allows one arena per module). Only in an ebpf.program body (nested regions included): an ebpf.func, ebpf.timer.callback, ebpf.user_ringbuf.callback, a callback loop (H) body or an ebpf.map.for_each body is rejected by name — the result is not passed through calls. Inside ebpf.loop, only when every enclosing loop is unroll (like arena.check); the result may be captured by a loop without callback.

    **Lowering**: Stage ③ reads `bpf_arena.user_vm_start` (u64) through a CO-RE relocation from the map's `.maps` placeholder address: `bpfabi.core_field_load` → ④ marker `__ebpf_core.bpf_arena.user_vm_start` → ObjectEmitter preserve.struct.access.index and one volatile 8-byte load. ebpf-build-btf-types adds the local type `bpf_arena { user_vm_start: u64 }` to `@kernel` for an arena map; the requirements carry `kfield <prog> bpf_arena user_vm_start u64`. an arena map also gets an `arena <map>` row (format 29, after the map rows), which precheck checks against the loader declarations `arena_cast` / `arena_premmap` — a loader that rewrites addr_space_cast or does not mmap the arena at `map_extra` (the cilium v0.22 presets) blocks with `arena_loader`, an undeclared one with `arena_loader_unknown`; bml-libbpf-v1.7 passes.

    **Evidence**: Out of scope — kernel evidence is not yet measured (a separate VM run covers it); static checks cover compile, ELF form and comparison with clang's C.

    **Unsupported**: Use in subprograms and callbacks; generic arena kfunc calls (use arena.alloc/free for page lifecycle); more than one arena.
  }];
  let arguments = (ins EBPF_MapType:$map);
  let results = (outs EBPF_ArenaBaseType:$base);
  let assemblyFormat = "$map attr-dict `:` type($map) `->` type($base)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_ArenaCheckOp : EBPF_Op<"arena.check", [RecursiveMemoryEffects]> {
  let summary = "Check an arena range and introduce a scoped window";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Checks [offset, offset + len) against the arena size (schema pages × 4096). The offset is an unsigned bit pattern, zero-extended to 64 bits. Success executes in_range with its sole block argument !ebpf.arena_window<len>; failure executes explicit out_of_range. Both arms may return integer values via ebpf.yield (`-> T…`). **The check is only a range check; it does not prove allocation** — a read of a page that is not allocated gives 0 and a write to it is discarded; after a fault on 7.3.1 kernels the read is not guaranteed to be 0.

    **Constraints**: The base is an ebpf.arena.base result. len is 1..65535. The offset is i8 / i16 / i32 / i64. len ≤ size and, for a constant offset c, c ≤ size − len (subtraction form) are checked by ebpf-verify-schema against the schema pages (the op verifier does not know the size). in_range has exactly one matching window argument; out_of_range has none. Window uses are arena.load / arena.store within in_range only — no yield, block-argument transport, call argument, or capture into an ebpf.loop / callback body. Same placement as arena.base: only in an ebpf.program body (ebpf.func, timer / user_ringbuf callbacks, callback loop (H) and map.for_each bodies are rejected by name). Inside ebpf.loop, **all enclosing loops must be U / unroll** (like packet.check). Integer result widths are i1 / 8 / 16 / 32 / 64.

    **Lowering**: Stage ② ebpf-expand-regions zero-extends the offset to i64 and emits arena.check_br with ^in(%w) / ^out blocks (no window-load rewrites — the packet optimizations W0 / C1 / W1 do not apply). Stage ③ compares `off64 ule size − len` once (an unsigned scalar compare, no address) and creates the window address `bpfabi.arena_addr base, off64` (`!llvm.ptr<1>`) inside the in-range block only; ④ expands it to add and inttoptr into address space 1, and the BPF backend emits addr_space_cast before the first access.

    **Evidence**: Out of scope — kernel evidence is not yet measured (a separate VM run covers it); static checks cover compile rules, ELF form, comparison with clang's C.

    **Unsupported**: B / H body checks, windows across regions, iterations, calls or callbacks, use in subprograms and callbacks, variable indices (check a window at the variable offset instead), and atomics / ordering between program and user-space accesses.
  }];
  let arguments = (ins EBPF_ArenaBaseType:$base, AnySignlessInteger:$offset, I64Attr:$len);
  let results = (outs Variadic<AnySignlessInteger>:$results);
  let regions = (region AnyRegion:$inRange, AnyRegion:$outOfRange);
  let assemblyFormat = [{
    $base `[` $offset `]` `len` $len attr-dict `:` type($offset) (`->` type($results)^)?
    `in_range` $inRange `out_of_range` $outOfRange
  }];
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_ArenaLoadOp : EBPF_Op<"arena.load"> {
  let summary = "Load an integer from a checked arena window";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads a little-endian integer at a constant index of a checked arena window, without another range check. Always volatile: each read is one access at the declared width or, when the alignment is not provable, one access per byte — reads are never merged (the memory is shared with user space). A page that is not allocated reads as 0 (not guaranteed after a fault on 7.3.1).

    **Constraints**: Result is i8 / i16 / i32 / i64. [index, index + width) must fit the window, checked by subtraction (index > len or width > len − index is rejected). The window is the in_range argument of an arena.check, used inside that region.

    **Lowering**: Stage ③ reads at `arena_addr + index` (address space 1). When the window's arena.check_br offset c is constant (looking through ②'s extui) and (c + index) mod width = 0 it is one volatile width-aligned load; otherwise one volatile byte load per byte assembled with zext / shl / or. No memory-effect interface (effects unknown, like the `once` loads ref.load / ref.field.load / kfield.load), so ① cse / canonicalize neither merge nor erase reads before ③ makes them volatile.

    **Evidence**: Out of scope — kernel evidence is not yet measured (a separate VM run covers it); static checks cover ELF form and comparison with clang's C.

    **Unsupported**: Variable indices, sign-extending loads (no LDSX), atomics, ordering with user-space writes.
  }];
  let arguments = (ins EBPF_ArenaWindowType:$window, I64Attr:$index);
  let results = (outs AnySignlessInteger:$result);
  let assemblyFormat = "$window `[` $index `]` attr-dict `:` type($window) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_ArenaStoreOp : EBPF_Op<"arena.store", [MemoryEffects<[MemWrite<EBPF_ArenaResource>]>]> {
  let summary = "Store an integer to a checked arena window";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Writes a little-endian integer at a constant index of a checked arena window. Always volatile: one access at the declared width or, when the alignment is not provable, one access per byte (user space may observe the bytes one at a time). A write to a page that is not allocated is discarded.

    **Constraints**: Value is i8 / i16 / i32 / i64. [index, index + width) must fit the window, checked by subtraction. The window is the in_range argument of an arena.check, used inside that region.

    **Lowering**: Stage ③ writes at `arena_addr + index` (address space 1): one volatile width-aligned store when the window's constant offset c satisfies (c + index) mod width = 0, otherwise lshr / trunc and one volatile byte store per byte. Memory effect is arena write.

    **Evidence**: Out of scope — kernel evidence is not yet measured (a separate VM run covers it); static checks cover ELF form and comparison with clang's C.

    **Unsupported**: Variable indices, atomics, ordering with user-space accesses.
  }];
  let arguments = (ins EBPF_ArenaWindowType:$window, I64Attr:$index, AnySignlessInteger:$value);
  let assemblyFormat = "$window `[` $index `]` `,` $value attr-dict `:` type($window) `,` type($value)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_ArenaCheckBrOp : EBPF_Stage2Op<"arena.check_br", "ebpf.arena.check (in_range / out_of_range regions)", [Terminator]> {
  let summary = "Branch on arena bounds, passing a window to the true successor (stage ② internal)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: Terminates with a branch testing [offset, offset + len) against the arena size. The in-range successor ^in has a sole !ebpf.arena_window<len> argument.

    **Constraints**: Op verifier checks successor count / arguments. Offset is one zero-extended i64 value. ebpf-verify-structured requires the ^in block to be entered only from this branch.

    **Lowering**: Stage ③ compares `off64 ule size − len` (size from the schema pages, recorded by ebpf-build-btf-types) and branches without an address; the window becomes `bpfabi.arena_addr` created at the entry of the in-range block.

    **Evidence**: Internal — expanded from arena.check; source input is rejected to prevent bypassing stage-① restrictions. arena.check owns feature evidence.

    **Unsupported**: Not writable in input; use arena.check.
  }];
  let arguments = (ins EBPF_ArenaBaseType:$base, I64:$offset, I64Attr:$len);
  let successors = (successor AnySuccessor:$inRange, AnySuccessor:$outOfRange);
  let assemblyFormat = "$base `[` $offset `]` `len` $len `,` $inRange `,` $outOfRange attr-dict";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_CtxArgOp : EBPF_Op<"ctx.arg", [Pure]> {
  let summary = "Read a tracing context argument as a kernel-struct pointer or integer";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads slot index of the u64 context array (tp_btf, also fentry / iter / fmod_ret / LSM) as !ebpf.kptr<"S">, nullable !ebpf.kptr_or_null<"S"> (checked by kptr.check), or integer iN. This op creates kernel pointers without side effects (Pure).

    **Constraints**: For tp_btf / fentry, index is 0..11. tp_btf results are kptr or i8 / i16 / i32 / i64. fentry struct results must be kptr_or_null; integer results are i8–i64. Function pointer arguments may be NULL; PROBE_MEM silently yields zero. Schema program.args declares each read argument: struct name S, nullable struct with nullable:true for kptr_or_null, or integer of matching width. Reading a nullable declaration as kptr is rejected. null schema entries mean unread and cannot be accessed. S must exist in btf.scope @kernel (ebpf-verify-kptr).
    Load-time attach trace_raw_tp / arg rows are checked against target BTF tracepoint signatures. BTF lacks argument nullability, so arg_nullable_unknown is recorded but does not block load.

    **Lowering**: Stage ③ emits bpfabi.ctx_arg at offset 8 × index, reading eight bytes and truncating integer results. Stage ④ loads the u64 context slot. No helper.

    **Evidence**: F23, F39, F41. tp_btf / CO-RE; attach / argument precheck; @kernel pointer declarations; sched_switch integer / unread-argument differential tests; fentry wake_up_new_task matching C on three kernels × root / {bpf, perfmon}, with farg FUNC_PROTO checks; iter metadata and fmod_ret arguments.

    **iter**: Only index 0 as !ebpf.kptr<"bpf_iter_meta">, the first argument guaranteed by DEFINE_BPF_ITER_FUNC for all targets. No schema args. Read metadata with kfield.load / kfield.ptr, checked by requirements kfield.

    **fmod_ret**: Integers i8 / i16 / i32 / i64 only, matching schema argument width. **Argument types are not checked at load time**, because the generic attach row has no companion signature rows; wrong declarations can silently misread values. Too many arguments are verifier-rejected as doesn't have N-th argument.

    **LSM**: Uses fentry-style slots via btf_ctx_access. Struct results must be kptr_or_null, not kptr, since hook nullability is unknown to the compiler. Integers i8–i64 truncate slots. With schema args (struct / integer / null), requirements use attach trace_lsm and farg rows, format 11, checked against bpf_lsm_<hook> FUNC_PROTO via func_args / func_param. Mismatch or unknown blocks load. 7.1.8 socket_create family / type match C; an incorrect i64 declaration passes the verifier but fails farg precheck.
    **lsm_s / lsm_cgroup**: lsm_s follows LSM / trace_lsm. lsm_cgroup accepts the same values and args with attach trace_lsm_cgroup plus farg, format 13, checking bpf_lsm_<hook>; the reader also queries generic lsm_cgroup lsm:<hook> attach type / target. Without args it retains generic rows.

    **struct_ops**: Reads member function-pointer arguments with the LSM value domain (nullable struct or truncated integer). Schema declares nargs / ret (integer or void) / args. Requirements attach trace_struct_ops / structop / retsig / farg, format 11, check target member FUNC_PROTO. The verifier promotes tcp_congestion_ops sock arguments to tcp_sock: schema / ctx.arg use tcp_sock, while farg uses BTF sock according to StructOpsTypes.def PROMOTION. A 7.1.8 Reno-style controller reading / writing tcp_sock snd_cwnd matches C.
    **Evidence**: F49. On a 6.12.111 VM, sched_ext_ops.tick records task_struct tgid into an array and normalized observations match C. Signature mutation is rejected by structop; 6.6.157 stops before load with structop_unknown. Short watchdog / enqueue depend on a C donor; explicit compiler-tick composition exists only in the experiment runner. No compiler-only scheduler, public-loader composition, or host sched_ext load is demonstrated.

    **Unsupported**: iter arguments after the first (target-specific nullable types), fmod_ret struct arguments, and kinds without ctx.arg. No conversion from integers or nullable references to kptr.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I64Attr:$index);
  let results = (outs AnyTypeOf<[EBPF_KPtrType, EBPF_KPtrOrNullType, I8, I16, I32, I64]>:$result);
  let assemblyFormat =
      "$ctx `[` $index `]` attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_ExtArgOp : EBPF_Op<"ext.arg", [Pure]> {
  let summary = "Read an argument of the function replaced by an ext/freplace program";
  let description = [{
    **Stage**: ① Input

    **Meaning**: ext replaces another BPF program's global function and receives its arguments rather than a context pointer. Reads argument index from a 64-bit BPF register, truncated to result integer width. Pure.

    **Constraints**: Context kind must have OPS ext.arg (ext). Index 0..4 (five BPF function arguments); result i8 / i16 / i32 / i64. ebpf-verify-schema requires index < schema nargs and width matching args[index]. ProgramOp permits only ext.arg to use ext entry ctx.
    Load-time attach freplace / extret nargs ret / extarg rows (format 11) check the loader-supplied target program BTF FUNC for global linkage, argument count, and integer width / sign of arguments / return. ebpf-precheck --ext-target is required; absence blocks with ext_target_unknown. **Kernel btf_check_func_type_match checks only argument size and return BTF kind**, so wrong argument sign or return width can pass the kernel and silently corrupt values; precheck is the guard.

    **Lowering**: Stage ③ emits entry llvm.func `@p(i64 × (highest used index + 1)) -> i32|i64` and truncates the selected argument. ebpf-build-btf constructs FUNC_PROTO from schema (`u<ret> (u<a0> arg0, …)`, unsigned).

    **Evidence**: F47. On 7.1.8, four C/ebpf combinations replacing one-argument g agree in test runs; i64-returning replong passes kernel but fails ext_target precheck.

    **Unsupported**: Pointer arguments (context structs / memory); omitted unread-argument declarations (BTF needs all widths, so schema args declares all integers). 6.12 / 6.6 are unverified.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I64Attr:$index);
  let results = (outs AnyTypeOf<[I8, I16, I32, I64]>:$result);
  let assemblyFormat =
      "$ctx `[` $index `]` attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_KprobeArgOp : EBPF_Op<"kprobe.arg", [Pure]> {
  let summary = "Read function argument register n from kprobe pt_regs";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads one-based argument n from pt_regs. Returns **raw register bits** (eight bytes) truncated to iW, without type semantics. Pure.

    **Constraints**: Context is kprobe only, n ≥ 1, width i8 / i16 / i32 / i64. Program requires arch; schema accepts x86_64 only. n must fit the UAPI register count (six on x86_64) and match declared schema params width.
    For **pointer arguments**, schema kind ptr requires result i64: an eight-byte raw address used as identity / correlation key, **without dereference**. Requirements kprobearg ptr checks that the target parameter is a pointer.
    Load gates check arch / ctxfield pt_regs offset-size / kprobearg type and attach target against BTF; mismatch and Unknown both block. Because cilium can silently retry failed X attach as __x64_X, precheck also requires that alias to be absent (attach_alias).

    **Lowering**: Stage ③ emits bpfabi.kprobe_arg using fixed eight-byte UAPI kprobearg offset, not CO-RE, then truncates. Stage-③ exit verification is Conditional: offset correctness depends on target pt_regs. No helper.

    **Evidence**: F24. C oracle; load-time checking preventing silent wrong values; three targets / non-root and discovered __x64_ fallback; pointer values match runner buffer addresses and C.

    **Unsupported**: Non-x86_64 (schema rejection), other contexts (uprobe uses uprobe.arg), and stack-passed argument 7 onward. External unchecked loaders can use __x64_ fallback. kernel.read_scalar reads a fixed-width value via helper only from this op's direct ptr-declared result. Pointer checking verifies pointer-ness, not pointee type or address space. No generic probe_read_user op.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I64Attr:$n);
  let results = (outs AnySignlessInteger:$result);
  let assemblyFormat = "$ctx $n attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_UprobeArgOp : EBPF_Op<"uprobe.arg", [Pure]> {
  let summary = "Read a user-function argument register from uprobe pt_regs (integer or typed user string)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads one-based user-function argument n from pt_regs, using raw bits like kprobe.arg. Integer results truncate to iW; !ebpf.user_str preserves 64 raw bits as a user string pointer, usable only by user.read_str. Pure.

    **Constraints**: Context is uprobe only; n ≥ 1; result i8 / i16 / i32 / i64 or user_str. Schema params must declare matching width or kind user_str paired with that result.
    Load gates check binary sha256 / symbol / uprobearg iN|uN|strptr against the loader-supplied binary's hashed fd and DWARF. strptr requires one pointer level to eight-bit char; Unknown also blocks. Policy 16 reads a unique non-declaration definition whose direct low_pc equals the main binary symbol address. If main DWARF info is absent, separate DWARF is used only after GNU build-ID and optional debuglink CRC matching (F25 / F54; requirements_format.md). Attach stays on the main binary; no unknown-type fallback.

    **Lowering**: Stage ③ uses bpfabi.kprobe_arg and UAPI offsets, like kprobe.arg. Integers truncate; user_str remains 64 bits. No helper.

    **Buffer / raw pointer**: Schema user_buf returns !ebpf.user_buf, consumed for reads only by user.read; schema ptr returns raw i64. Both emit requirements ptr, minimum format 18, matched against a one-level, eight-byte DWARF pointer. No integer-to-readable-buffer cast.

    **Evidence**: F25, F78. C oracle / fixture and binary identity; three targets (non-root attach needs CAP_SYS_ADMIN); user_str; buffer / ptr declarations and static checks, whose runtime evidence is owned by the user.read experiment.

    **Unsupported**: user_str cannot feed integer ops; no kprobe context. Missing DWARF in both main / matched separate files and char** stop before load. void* must use ptr / user_buf declarations. Placement path and PID are loader inputs, not compiler inputs.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I64Attr:$n);
  let results = (outs AnyTypeOf<[AnySignlessInteger, EBPF_UserStrType, EBPF_UserBufType]>:$result);
  let assemblyFormat = "$ctx $n attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

def EBPF_CtxRetvalOp : EBPF_Op<"ctx.retval", [Pure]> {
  let summary = "Read a kernel-function return value from fexit context";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads target return slot N (`after N`, target argument count) after the argument slots, truncating its u64 value to iW. Pure.

    **Constraints**: fexit context only; N 0..12; result i8 / i16 / i32 / i64. ebpf-verify-schema checks N / width against required fexit nargs / ret signature. Allowed in loop bodies. Load-time retsig rows check target FUNC_PROTO; mismatch and unknown caps (retsig_unknown) both block.

    **Lowering**: Stage ③ truncates bpfabi.ctx_arg's u64 at offset 8 × N. No helper.

    **Evidence**: F22. C oracle, retsig, three-target / non-root tests. Too many declared arguments fail verifier doesn't have N-th argument; too few or wrong return width / sign can pass verifier and silently change values, so retsig precheck is the only guard (three targets).

    **Unsupported**: Non-fexit, pointer / void results, and fexit argument-reading operations.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I64Attr:$nargs);
  let results = (outs AnySignlessInteger:$result);
  let assemblyFormat = "$ctx `after` $nargs attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_CtxFuncIpOp : EBPF_Op<"ctx.func_ip"> {
  let summary = "Read the traced function address as raw integer bits";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls get_func_ip and returns raw address bits, including a possible zero. It creates no typed pointer.

    **Constraints**: Own program context, program body or non-callback loop. The kind table permits the KPROBE family and fentry/fexit/fmod_ret/fsession, a conservative subset of kernel permissions.

    **Lowering**: Stage ③ calls UAPI get_func_ip(ctx). The call has effects and remains when unused.

    **Evidence**: Out of scope — kernel values are reserved for a later measurement. Static contract only.

    **Unsupported**: Static functions, helper callbacks, tp_btf, raw_tp, iter, LSM and non-tracing kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx);
  let results = (outs I64:$result);
  let assemblyFormat = "$ctx attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

def EBPF_CtxFuncArgOp : EBPF_Op<"ctx.func_arg"> {
  let summary = "Read an indexed raw function argument with status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls get_func_arg(ctx, unsigned n, &slot). Returns raw i64 status and the low W bits of the u64 slot on status zero, otherwise value zero. iW carries no signedness; upper bits of narrow kernel arguments are not guaranteed.

    **Constraints**: Own fentry/fexit/fmod_ret/fsession/tp_btf context, program body or non-callback loop. W is 8/16/32/64; n is an unsigned i32, constant or dynamic. Availability on the target is checked by helper requirements, never a compile-time kernel version.

    **Lowering**: Stage ③ allocates an entry 8-byte slot aligned to 8, clears it on each call, zero-extends n, calls UAPI get_func_arg, loads i64, truncates, then selects zero on failure.

    **Evidence**: Out of scope — kernel values are reserved for a later measurement. Static contract only.

    **Unsupported**: Static functions, helper callbacks, LSM, and arbitrary output pointers or buffers.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$n);
  let results = (outs I64:$status, AnySignlessInteger:$value);
  let assemblyFormat = "$ctx `,` $n attr-dict `:` type($ctx) `,` type($n) `->` type($status) `,` type($value)";
  let hasVerifier = 1;
}

def EBPF_CtxFuncArgCntOp : EBPF_Op<"ctx.func_arg_cnt"> {
  let summary = "Read the runtime function argument count";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Returns the raw get_func_arg_cnt(ctx) value. No argument count is baked into the object from schema.

    **Constraints**: Own fentry/fexit/fmod_ret/fsession/tp_btf context, program body or non-callback loop. Target availability uses helper requirements.

    **Lowering**: Stage ③ calls UAPI get_func_arg_cnt(ctx); unused calls remain.

    **Evidence**: Out of scope — kernel values are reserved for a later measurement. Static contract only.

    **Unsupported**: Static functions, helper callbacks, LSM and other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx);
  let results = (outs I64:$result);
  let assemblyFormat = "$ctx attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

def EBPF_CgroupRetvalOp : EBPF_Op<"cgroup.retval"> {
  let summary = "Read the cgroup run-context retval integer";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads get_retval (helper 186), the signed int bits in the cgroup run context. This is distinct from ctx.func_ret (helper 184).

    **Constraints**: Program body or non-callback loop, cgroup_sock/device/sysctl/sockopt or sock_addr bind/connect/sendmsg hooks. The verifier uses a conservative subset of kernel permissions.

    **Lowering**: Stage ③ calls UAPI get_retval and truncates the returned register to i32; unused calls remain.

    **Evidence**: Out of scope — kernel values are reserved for a later measurement. Static contract only.

    **Unsupported**: Static functions, callbacks, cgroup_skb, sock_ops, LSM_CGROUP and sock_addr receive/name hooks.
  }];
  let results = (outs I32:$result);
  let assemblyFormat = "attr-dict `:` type($result)";
  let hasVerifier = 1;
}

def EBPF_CgroupSetRetvalOp : EBPF_Op<"cgroup.set_retval"> {
  let summary = "Write the cgroup run-context retval integer";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls set_retval with the i32 int bits and returns raw helper status. A negative retval can set the caller's errno; this is not a program verdict.

    **Constraints**: Same conservative kind/hook and program/loop placement as cgroup.retval.

    **Lowering**: Stage ③ calls UAPI set_retval; unused calls remain.

    **Evidence**: Out of scope — kernel values are reserved for a later measurement. Static contract only.

    **Unsupported**: Static functions, callbacks and hooks excluded by cgroup.retval.
  }];
  let arguments = (ins I32:$value);
  let results = (outs I64:$result);
  let assemblyFormat = "$value attr-dict `:` type($value) `->` type($result)";
  let hasVerifier = 1;
}

def EBPF_TaskNsPidTgidOp : EBPF_Op<"task.ns_pid_tgid"> {
  let summary = "Read namespace-relative current pid and tgid with status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls get_ns_current_pid_tgid with u64 device/inode identity. Returns raw status and u32 pid/tgid; both values are zero on error.

    **Constraints**: Program body, static function or B/U loop, outside direct helper callbacks. Target helper availability is checked at load.

    **Lowering**: Stage ③ uses an internal entry stack bpf_pidns_info, clears it every call, passes its ABI extent, loads its generated fields and selects zero on failure.

    **Evidence**: Out of scope — kernel values are reserved for a later measurement. Static contract only.

    **Unsupported**: Public output buffer or pointer, direct helper callback. Static tests do not prove target namespace identity or availability.
  }];
  let arguments = (ins I64:$dev, I64:$ino);
  let results = (outs I64:$status, I32:$pid, I32:$tgid);
  let assemblyFormat = "$dev `,` $ino attr-dict `:` type($dev) `,` type($ino) `->` type($status) `,` type($pid) `,` type($tgid)";
  let hasVerifier = 1;
}

def EBPF_TaskSendSignalOp : EBPF_Op<"task.send_signal"> {
  let summary = "Send a signal to the current thread group";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls send_signal with unsigned i32 signal number and returns raw i64 status. Delivery targets the current TGID, not just the current thread. The helper can fail and successful status does not count delivered acknowledgements.

    **Constraints**: Program body, static function or B/U loop, outside direct helper callbacks. Target helper availability is checked at load. All calls have effects, including repeated calls with unused status.

    **Lowering**: Stage ③ zero-extends the signal number and calls UAPI send_signal.

    **Evidence**: Out of scope — BPF signal delivery is unmeasured; uses a dedicated masked single-thread receiver. static contract.

    **Unsupported**: Direct helper callback; no send_signal_thread operation or implicit signal masking.
  }];
  let arguments = (ins I32:$signal);
  let results = (outs I64:$result);
  let assemblyFormat = "$signal attr-dict `:` type($signal) `->` type($result)";
  let hasVerifier = 1;
}

def EBPF_TaskSendSignalThreadOp : EBPF_Op<"task.send_signal_thread"> {
  let summary = "Send a signal to the current thread only";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls send_signal_thread with unsigned i32 signal number and returns raw i64 status. Unlike task.send_signal (the whole thread group of the current TGID) the target is the current thread (TID) only. The helper can fail and successful status does not count delivered acknowledgements.

    **Constraints**: The same as task.send_signal: program body, static function or B/U loop, outside direct helper callbacks. Target helper availability is checked at load. All calls have effects, including repeated calls with unused status.

    **Lowering**: Stage ③ zero-extends the signal number and calls UAPI send_signal_thread.

    **Evidence**: Out of scope — no release F row yet; static checks cover it, and it was also run in a VM as root on 4 kernels (7.3.1, 7.1.8, 6.12.111, 6.6.157) with a two-thread worker: the signal stays in the calling thread's private pending set and the sibling thread never acknowledges it, while task.send_signal reaches the sibling; C and MLIR agree on every cell.

    **Unsupported**: Direct helper callback; no implicit signal masking.
  }];
  let arguments = (ins I32:$signal);
  let results = (outs I64:$result);
  let assemblyFormat = "$signal attr-dict `:` type($signal) `->` type($result)";
  let hasVerifier = 1;
}

def EBPF_CtxFuncRetOp : EBPF_Op<"ctx.func_ret"> {
  let summary = "Read a kernel-function return value through bpf_get_func_ret";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads the traced function's return value with bpf_get_func_ret (helper 184) and truncates the u64 to iW. The kernel supplies the argument count at run time, so the object does not fix N (unlike `ctx.retval after N`). The helper's status is discarded: it is always 0 for fexit.

    **Constraints**: fexit context of the program body only (not static / global funcs or callbacks — the meaning depends on the attach point); result i8 / i16 / i32 / i64. Allowed in loop bodies. ebpf-verify-schema checks the width only against the schema's fexit `ret` (iW carries no sign). The schema's `nargs` may be omitted for fexit; the requirements then carry `funcret <p> <i|u><width>`, checked before load against the target FUNC_PROTO's return width and sign (Unmet funcret; no query or Unknown — funcret_unknown — also blocks).

    **Lowering**: Stage ③ passes an entry-block 8-byte stack slot (align 8) to helper get_func_ret with the context, loads the u64 and truncates.

    **Evidence**: F22. offline checking against four pinned target BTFs (7.3.1 / 7.1.8 / 6.12.111 / 6.6.157) — sign / width / void mismatches block as funcret; an absent function is checked on a synthetic target name and in the corpus. Kernel values versus C bpf_get_func_ret are measured separately.

    **Unsupported**: Non-fexit kinds (fmod_ret / fsession and others), pointer / void results, static funcs and callbacks.
  }];
  let arguments = (ins EBPF_ContextType:$ctx);
  let results = (outs AnySignlessInteger:$result);
  let assemblyFormat = "$ctx attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_SockAddrSetSunPathOp : EBPF_Op<"sock_addr.set_sun_path"> {
  let summary = "Replace an own Unix-connect entry's sun_path with fixed bytes";
  let description = [{
    **Stage**: ① Input

    **Meaning**: bpf_sock_addr_set_sun_path synchronously copies a literal. i32 status is 0 on success or negative errno. No NUL append or strlen.

    **Constraints**: Own entry ctx of cgroup_sock_addr / connect_unix, literal 1..108 bytes only. Rejects static functions / loops / callbacks, variable buffers / lengths, and pointer escape. Permission verdict and status are independent.

    **Lowering**: Initializes entry-stack bytes, then calls internal bpf_cast_to_kern_ctx and extern kfunc bpf_sock_addr_set_sun_path. Borrowed kernel ctx stays inside the op; no public pointer type. Prototype / program type come from generated UAPI; requirements use existing kfunc signature rows. Unix profile remains Unknown.

    **Evidence**: F73. 7.1.8 root, own AF_UNIX/SOCK_DGRAM connect_unix: 20 normal C/compiler arms match, including 1 / 108 bytes, abstract paths, embedded NUL; two distinct mutations (destination / deny→allow), zero cleanup residue. Older kernels / actual non-root are unmeasured.

    **Unsupported**: Other Unix attach types, SOCK_STREAM, dynamic buffers, existing host paths / sockets, older kernels. Experiment pathnames are relative to own private tmpfs; abstract names use own fresh netns.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, StrAttr:$literal);
  let results = (outs I32:$status);
  let assemblyFormat = "$ctx $literal attr-dict `:` type($ctx) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_SysctlSetNewValueOp : EBPF_Op<"sysctl.set_new_value"> {
  let summary = "Replace a cgroup_sysctl new value with fixed literal bytes and return raw status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Passes fixed bytes to bpf_sysctl_set_new_value. Raw i64 status is 0 or negative errno. Even successful replacement never reaches the handler if verdict denies; handler rejection after allow is a separate outcome.

    **Constraints**: Own entry ctx of a kind whose OPS permits sysctl.set. Literal is 1–64 raw bytes, counting embedded NUL; no implicit trailing NUL. No callee / loop / callback / generic pointer.

    **Lowering**: Allocates N entry-stack bytes and initializes every byte. Stage-③ bpfabi.helper_call sysctl_set_new_value takes ctx / read-only buffer / constant N; stage ④ uses UAPI helper104. No Pure / readnone attributes; even unused status preserves the call.

    **Evidence**: F71. 7.1.8 root own-child-cgroup / netns: 14 independent normal C/compiler arms match. Helper 0 with handler EINVAL, deny EPERM, and read helper EINVAL are checked separately from actual TTL. Two complete semantic mutations; host / sibling TTL unchanged; 32 own map / program IDs ENOENT; 16-arm cleanup zero. Compiler boundaries have non-root lit evidence.

    **Unsupported**: get_name / current / new helpers, dynamic buffers, PAGE_SIZE boundary, and file_pos changes. Actual writes are confined to own cgroup / netns and explicitly named paths. Older-kernel and attach evidence retain the measurement's limits.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, StrAttr:$literal);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx $literal attr-dict `:` type($ctx) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_TpBufferLoadOp : EBPF_Op<"tp.buffer.load", [MemoryEffects<[MemRead, MemWrite]>]> {
  let summary = "Read i32 once from the raw_tp_writable args[0] buffer";
  let description = [{
    **Stage**: ① Input

    **Meaning**: One volatile signless-i32 read at byte offset 0 of the buffer pointed to by args[0]. Raw i32 result. DefaultResource Read + Write preserves even unused reads. Volatile is neither thread synchronization nor a full memory barrier.

    **Constraints**: Own raw_tp_writable entry context with tp.buffer capability, constant offset 0 / i32 only. No static functions, other contexts / offsets / widths, or exposed private pointer.

    **Lowering**: Stage ③ bpfabi.tp_buffer_load; stage ④ one UAPI args[0] DW volatile pointer load, then one buffer W volatile load. Strict exit checks width / order / pointer escape. Requirements tpbuf i32 (format14) immediately after attach checks target signed-i32 pointer before load.

    **Evidence**: F46. On 7.1.8 bpf_test_finish filtered to own TGID, 14 normal C/ebpf arms / 72 calls match; complete observations detect store-omission / -12 mutations (two arms / ten calls). BTF / load / attach, C7 Close / ENOENT, and zero remaining own 76 IDs are checked. Separate checks cover stage-①②③ CSE, stage-④ strict exit, and LLVM / ELF R2/W1 order. Earlier C-only evidence is preserved.

    **Unsupported**: Other offsets / widths / arguments, context transport to subprograms, and exposed private pointers. Matching target BTF alone does not guarantee writable_size or attach acceptance.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I64Attr:$offset);
  let results = (outs I32:$result);
  let assemblyFormat = "$ctx `[` $offset `]` attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

def EBPF_TpBufferStoreOp : EBPF_Op<"tp.buffer.store", [MemoryEffects<[MemRead, MemWrite]>]> {
  let summary = "Write i32 once to the raw_tp_writable args[0] buffer";
  let description = [{
    **Stage**: ① Input

    **Meaning**: One volatile i32 store at buffer offset 0. Read + Write effects prevent merging surrounding loads / stores.

    **Constraints**: Same own raw_tp_writable entry context / constant offset0 / signless i32 as tp.buffer.load. No result or public pointer.

    **Lowering**: Stage ③ bpfabi.tp_buffer_store; ④ one UAPI args[0] DW volatile pointer load, then one buffer W volatile store. Strict exit checks value / width / order / pointer escape; emits tpbuf i32 requirements.

    **Evidence**: F46. 7.1.8 bpf_test_finish / own TGID: 14 normal C/ebpf arms / 72 calls match. Store omission gives before/after0 / errno0; -12 gives after-12 / errno12, each detected in five calls. Preserves one Close per own 76 IDs and absence checks, independent C7 detach evidence, and earlier C-only evidence.

    **Unsupported**: Other offsets / widths / arguments, static functions, pointer exposure, and nonvolatile access.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I64Attr:$offset, I32:$value);
  let assemblyFormat = "$ctx `[` $offset `]` `,` $value attr-dict `:` type($ctx) `,` type($value)";
  let hasVerifier = 1;
}

def EBPF_CtxFieldOp : EBPF_Op<"ctx.field"> {
  let summary = "Read a named context integer field or trusted BTF-struct pointer field";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads a named field of the kind's CTX struct and returns its declared integer width: xdp_md for XDP, __sk_buff for sched_cls, bpf_sk_lookup, bpf_nf_ctx, bpf_raw_tracepoint_args, or bpf_perf_event_data. perf_event offsets depend on arch pt_regs size, requiring program arch x86_64, UAPI values, and trace_perf arch requirements. Reads after ctx.field.store observe the stored value; not Pure and cannot be reordered / merged.
    **Pointer fields** marked btf in capability-table column 8 (e.g. netfilter state → nf_hook_state, skb → sk_buff) return non-NULL !ebpf.kptr<"S">, kernel type PTR_TO_BTF_ID | PTR_TRUSTED. Use CO-RE kfield.load for pointee fields. Flexible arrays with UAPI count 0, such as raw_tp args, require a constant element index: `ebpf.ctx.field %ctx "args"[1] : !ebpf.ctx<"raw_tp"> -> i64`.

    **Constraints**: Context must be an ebpf.program entry argument, not static-function context, because attach type matters. Kind must have CTX; field must exist in UAPI ctxfield and abi/ctxaccess.tsv for program type / expected_attach_type / struct / field / r / width. Result width must match. Packet pointer fields data / data_end / data_meta are absent: use packet ops. A btf-marked field permits only the corresponding kptr type, rejecting integer address exposure / another struct name. Non-btf fields cannot yield kptr. S must exist in btf.scope @kernel / schema core.kernel_types. Flexible arrays require index 0..11 (bpf_tracing_ctx_access 8 × MAX_BPF_FUNC_ARGS; KernelABI.h kMaxFlexCtxIndex); scalar indices and fixed-length arrays are rejected.

    **Lowering**: Stage ③ bpfabi.ctx_field_load uses UAPI offset + index × element width and capability-table width (eight-byte pointer result for kptr). Exit checks both tables. Stage ④ emits one load at the declared width; verifier ctx access depends on exact offset / width, so it is neither split nor combined. No helper.

    **Evidence**: F36, F37. UAPI-header offsetof agreement and all capability rows accepted by 7.1.8 load probes; XDP ingress_ifindex / sched_cls len / mark C differential test runs; raw_tp indexed args test-run / sys_enter attach; sk_lookup five reads and netns attach; netfilter state / skb pointers plus CO-RE reads; child-cgroup bpf_sock / bpf_sock_addr / bpf_sock_ops reads and mark / user_port stores; netns sk_skb len / local_port and sk_msg size / family; reuseport len / eth_protocol / ip_protocol / bind_inany / hash; sk_msg addresses / ports and reuseport migration len; own-thread cpu-clock perf_event sample_period, all compared with C.

    **Unsupported**: Type / attach / field / width absent from the table, fixed arrays, struct-valued fields, and narrow loads. Pointee struct names are hand-maintained is_valid_access facts, not checked at load; ctxaccess asks only whether reads are accepted. Compile time does not check raw_tp index against tracepoint argument count; attach rejects excessive max_ctx_offset with -EINVAL in bpf_probe_register.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, StrAttr:$field, OptionalAttr<I64Attr>:$index);
  let results = (outs AnyTypeOf<[AnySignlessInteger, EBPF_KPtrType]>:$result);
  let assemblyFormat = "$ctx $field (`[` $index^ `]`)? attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_CtxFieldStoreOp : EBPF_Op<"ctx.field.store"> {
  let summary = "Write a writable integer field of a struct context";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Writes a context integer field, such as sched_cls __sk_buff.mark. Kernel converts it into a store on the underlying object (e.g. skb).

    **Constraints**: Follows ctx.field entry context / CTX / UAPI integer-field rules, requiring a capability-table w row and exact value width. Missing w rows are rejected with a diagnostic listing writable fields.

    **Lowering**: Stage ③ bpfabi.ctx_field_store, checked against the table at exit. Stage ④ emits one store at the declared width / offset.

    **Evidence**: F36. Writable-row probes and negative controls for read-only fields; sched_cls mark matches C test-run ctx_out.

    **Unsupported**: Fields without w rows. Table does not describe value-range restrictions imposed by the kernel; each added capability row needs those checked.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, StrAttr:$field, AnySignlessInteger:$value);
  let assemblyFormat = "$ctx $field `,` $value attr-dict `:` type($ctx) `,` type($value)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_FlowKeysLoadOp : EBPF_Op<"flow_keys.load"> {
  let summary = "Read a named integer field of flow_dissector's bpf_flow_keys";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads through ctx flow_keys (PTR_TO_FLOW_KEYS) into UAPI struct bpf_flow_keys, returning raw declared-width bits. Kernel zeros it before execution and initializes nhoff, thoff (= nhoff), n_proto (Ethernet h_proto, network order), and flags (BPF_FLOW_DISSECTOR_F_*). Reads observe these inputs and earlier program stores; not Pure. Four-element ipv6_src / ipv6_dst require constant indices, e.g. ipv6_src[2] -> i32. Network-order n_proto / sport / dport / addresses / flow_label preserve byte order as raw integers; use ebpf.byteorder to convert.

    **Constraints**: Own program entry context with OPS flow_keys (flow_dissector), not static functions. Field is a UAPI ctxfield bpf_flow_keys row; result width matches (i8 / i16 / i32). Four-element fields require index 0..3; scalar fields reject indices.

    **Lowering**: Stage ③ performs one volatile eight-byte pointer load at UAPI __sk_buff.flow_keys offset, then one volatile declared-width load at field offset + index × width. Kernel check_flow_keys_access checks only off + size ≤ sizeof(struct bpf_flow_keys). No helper or requirements row.

    **Evidence**: F50. IPv4 / IPv6 TCP / UDP dissectors match equivalent C test-run data_out (flow_keys) and retval on 7.1.8.

    **Unsupported**: Not an abi/ctxaccess.tsv capability row: this is not a ctx access, so ctxprobe does not cover it. Fields beyond an older kernel's struct end (e.g. flags / flow_label) fail verifier at load; compiler does not inspect kernel versions.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, StrAttr:$field, OptionalAttr<I64Attr>:$index);
  let results = (outs AnySignlessInteger:$result);
  let assemblyFormat = "$ctx $field (`[` $index^ `]`)? attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_FlowKeysStoreOp : EBPF_Op<"flow_keys.store"> {
  let summary = "Write a named bpf_flow_keys integer field as flow_dissector output";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Writes raw integer bits to flow_keys fields: nhoff / thoff / addr_proto / is_frag / is_first_frag / is_encap / ip_proto / n_proto / sport / dport / ipv4_src / ipv4_dst / ipv6_src / ipv6_dst elements / flags / flow_label. For BPF_OK or other verdicts except flow_dissector_continue, kernel __skb_flow_bpf_to_target copies them into flow keys. Kernel then clamps nhoff to [original nhoff, hlen] and thoff to [nhoff, hlen]. flow_dissector_continue (129) resumes the kernel dissector and ignores stores, though test-run data_out retains them.

    **Constraints**: Same as flow_keys.load: flow_dissector entry ctx, UAPI field, matching width, index 0..3 for four-element fields. Integer values only; the type system excludes pointers, which the kernel rejects as leaks addr into flow keys.

    **Lowering**: Stage ③ performs one volatile ctx pointer load, then one volatile declared-width store at field offset + index × width. No helper or requirements row.

    **Evidence**: F50. 7.1.8 test-run complete data_out fields and ok / drop / flow_dissector_continue verdict combinations match C, including thoff clamping.

    **Unsupported**: No actual netns flow-dissector-link / traffic hash / RPS observation (test runs only). Compile time does not enforce meanings such as thoff ≥ nhoff; kernel clamps them.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, StrAttr:$field, OptionalAttr<I64Attr>:$index, AnySignlessInteger:$value);
  let assemblyFormat = "$ctx $field (`[` $index^ `]`)? `,` $value attr-dict `:` type($ctx) `,` type($value)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_ProbeRetvalOp : EBPF_Op<"probe.retval", [Pure]> {
  let summary = "Read a function return register from kretprobe or uretprobe pt_regs";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads the return register (x86_64 rax, UAPI kproberet) as **raw eight-byte register bits**, truncated to iW with no type interpretation, like kprobe.arg. Pure.

    **Constraints**: Context kind must have OPS probe.retval (kretprobe / uretprobe); width i8 / i16 / i32 / i64. Program requires arch; schema accepts x86_64 only and no params. Load-time attach companion arch / ctxfield pt_regs ax 80 8 rows check target BTF. attach_alias blocks cilium Kretprobe __x64_ fallback. uretprobe also checks binary hash / symbol and **target CU DW_AT_language C / C++**: Go gives uretprobe_abi; unknown language gives uretprobe_abi_unknown (policy8).

    **Lowering**: Stage ③ uses bpfabi.kprobe_arg n = 0 for the fixed UAPI return-register offset / eight bytes, not CO-RE, then truncates. Exit checks UAPI with Conditional outcome because correctness depends on target pt_regs. No helper.

    **Evidence**: F38. kretprobe bpf_fentry_test1 and uretprobe fixture probe_target return the same values as C; precheck blocks Go-function uretprobe.

    **Unsupported**: Return type width / sign / pointer-ness is not checked: format9 companion rows contain only arch / ctxfield. rax has no defined meaning for void / struct-by-value returns. No other arch or argument reads (argument registers are clobbered at return).
  }];
  let arguments = (ins EBPF_ContextType:$ctx);
  let results = (outs AnySignlessInteger:$result);
  let assemblyFormat = "$ctx attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_ProbeTargetIndexOp : EBPF_Op<"probe.target_index"> {
  let summary = "Attach-list index of the current multi-probe function or symbol (attach cookie)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Returns zero-based attach-list index i as i64 for kprobe_multi / kretprobe_multi / uprobe_multi / uretprobe_multi. It is raw get_attach_cookie(ctx), meaningful as an index only under the **loader contract of attaching name i with cookie i** (requirements mtarget, requirements_format.md §8). Without cookies, all functions return 0 and are indistinguishable (7.1.8 source-only, unmeasured). Neither compiler nor verifier enforces bounds; callers must bound map keys / array indices, e.g. with arith.minui.
    USDT also uses it: loader attaches note point i with cookie i and writes that point's spec at map index i (§8).

    **Constraints**: Own program context of OPS probe.target_index kinds: the four multi probes and usdt. Single k/u probes and return probes are rejected: one attach, no cookie contract. Result i64; no static-function context because semantics depend on attach.

    **Lowering**: Stage ③ calls UAPI get_attach_cookie using kmulti / umulti prototypes when expected_attach_type is trace_kprobe_multi / trace_uprobe_multi; requirements include helper row. Not pktinval, but deliberately absent from PacketNeutral because these kinds have no packets; C1 / W1 conservatively do not cross absent entries.

    **Evidence**: F54. 7.1.8 root cilium KprobeMulti / KretprobeMulti / UprobeMulti / UretprobeMulti with Symbols in mtarget order and Cookies i; per-function counts compared to equivalent C using bpf_get_attach_cookie.

    **Unsupported**: Arbitrary-u64 cookie API, single-probe / fentry / perf_event cookies, and kprobe.session bpf_session_cookie.
  }];
  let arguments = (ins EBPF_ContextType:$ctx);
  let results = (outs I64:$result);
  let assemblyFormat = "$ctx attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_UsdtArgOp : EBPF_Op<"usdt.arg"> {
  let summary = "Read a USDT argument using the cookie-indexed loader-written note specification, returning value and status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads one-based argument n of the current USDT point, returning value iW (schema params width) and i64 status. Compiler cannot know each point's register / memory / constant placement. **Loader writes note-derived specifications** into __ebpf_usdt_spec_<program>; keys are point indices and layout is in requirements_format.md §8. Attach cookies index this map. const uses spec off, reg uses register bits, deref reads W/8 user bytes at register + off. Result retains low bits of declared width; usdtarg checks width / sign against note <±size>@, and the caller uses extsi / extui to widen.
    Status is 0 for successful const / reg / deref, **raw probe_read_user negative errno** on deref failure (value 0), −ENOENT (-2) with value 0 for cookie outside map max_entries / NULL lookup, or −EINVAL (-22) with value 0 for kind 0 (unwritten array slot / unreadable location), unknown kind, or invalid register. −2 / −22 are compiler-defined statuses, not kernel helper returns. **Using value without checking status is allowed**, as with user.read_str; caller distinguishes failure.

    **Constraints**: Own program context with OPS usdt.arg; n 1..12; value i8 / i16 / i32 / i64; status i64. No static-function context. n must exist in schema params at matching width. Load gates check attach usdt provider:name plus arch / ctxfield rows for every read register / binary / usdtsem / usdtarg, and loader usdt_attach declaration against binary notes. Missing points, semaphore disagreement, argument count / size / sign mismatch, unreadable placement, or point count > max_points all block.

    **Lowering**: Stage ③ truncates get_attach_cookie to u32 key, then map_lookup_elem on compiler-placeholder __ebpf_usdt_spec_<program> (one added map / ebpf_usdt_spec record per schema USDT program). NULL yields (0, −ENOENT). Reads argument kind at +16(n−1), reg at +16(n−1)+1, off at +16(n−1)+8. **All UAPI usdtreg registers are read once, volatile, at fixed pt_regs offsets**; register numbers select values rather than variable-offset context pointers, preventing LLVM pointer selection. Invalid numbers yield (0, −EINVAL). Kind1 returns off; kind2 returns register; kind3 calls probe_read_user(&tmp, W/8, reg + off) with a zeroed eight-byte temporary, preserving raw status and zero failure value. Others yield (0, −EINVAL). Value truncates to iW.

    **Evidence**: F55. On 7.1.8 root, all points in clang -O0 / -O2 and gcc -O2 fixtures match stdout values with status 0. Loader-filled maps match note parsing. Semaphore-point ref_ctr_offset has a zero-event control when omitted.

    **Unsupported**: SIB off(base,index,scale), RIP-relative placement, and non-x86_64 are precheck-rejected (no spec kinds). Deref-failure status is unmeasured. Two programs at one point are outside scope (spec map is per program). Without loader cookies all points read spec0; precheck does not observe cookies, so §8's contract is essential.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I64Attr:$n);
  let results = (outs AnyTypeOf<[I8, I16, I32, I64]>:$value, I64:$status);
  let assemblyFormat = "$ctx $n attr-dict `:` type($ctx) `->` type($value) `,` type($status)";
  let hasVerifier = 1;
}

// Per-target multi-probe arguments; see the canonical description.
def EBPF_ProbeTargetArgOp : EBPF_Op<"probe.target_arg"> {
  let summary = "Read argument n for multi-probe target i only when it is the current target; otherwise return zero";
  let description = [{
    **Stage**: ① Input

    **Meaning**: For entry kprobe_multi / uprobe_multi, when attach cookie equals i (%hit), reads one-based argument n (%v) at target_params[i]'s width. **Other targets produce value 0**, not another function's register interpreted with target i's type. This supports different signatures (e.g. int / int / char) while common kprobe.arg / uprobe.arg params describe a shared type. Cookie contract follows target_index: attach item i gets cookie i (§8).

    **Constraints**: Own context with OPS probe.target_arg (kprobe_multi / uprobe_multi), i < attach-list length, n ≥ 1. Value i8 / i16 / i32 / i64 or, for uprobe_multi, user_str / user_buf; hit i1. Schema must have target_params[i][n] with matching width / type: ptr only i64; user_str / user_buf only their matching types. user_buf may escape only to user.read. Raw ptr / user_buf emit format18 mtargetarg ptr and require one-level eight-byte DWARF pointers (F78).

    **Lowering**: Stage ③ compares get_attach_cookie to i, reads fixed UAPI kprobearg register n, truncates, and selects hit ? value : 0. user_str preserves raw i64 and false address0; it cannot convert to integer. user.read_str reports raw read status.

    **Requirements**: With target_params, emit mtargetarg rows after mtarget in (i, n) order (format13), replacing kprobearg / uprobearg. ctxfield appears once for the union of all register n values. Load checks each target's parameter using existing argument rules. Wrong target_params count or n without an arch register fails explicitly without writing ELF.

    **Evidence**: F68. Stage-③ lit shape; 7.1.8 root reads bpf_fentry_test1–3 parameter1 as int / int / char and compares to C. Per-target uprobe_multi user_str has compile checks; its runtime differential evidence belongs to its dedicated experiment.

    **Unsupported**: Return-probe families and usdt.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I64Attr:$target, I64Attr:$n);
  let results = (outs AnyTypeOf<[I8, I16, I32, I64, EBPF_UserStrType, EBPF_UserBufType]>:$value, I1:$hit);
  let assemblyFormat = "$ctx `target` $target `arg` $n attr-dict `:` type($ctx) `->` type($value) `,` type($hit)";
  let hasVerifier = 1;
}

// ksyscall syscall arguments; see the canonical description.
def EBPF_KsyscallArgOp : EBPF_Op<"ksyscall.arg"> {
  let summary = "Read syscall argument n through the wrapper's saved user pt_regs (two-stage load)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: ksyscall attaches a kprobe to __<pfx>_sys_<name>. Wrapper argument1 points to saved user pt_regs; syscall argument n (1..6) is read from that struct using the **syscall convention**, x86_64 di / si / dx / **r10** / r8 / r9. Function argument4 cx instead holds the user return address after syscall. Raw bits truncate to iW. A kernel-memory read failure (not expected) returns zero because the helper zeros its destination.

    **Constraints**: Own context with OPS ksyscall.arg; n 1..6; result i8 / i16 / i32 / i64 or user_str. Schema n must fit arch UAPI ksyscallarg and match ksyscall params width; ptr declarations require i64 and expose the address without dereference. Load checks attach ksyscall name, arch, ctxfield for wrapper di and syscall registers, and sysarg type against tracefs syscalls/sys_enter_<name>/format, falling back to __do_sys_<name> BTF only when format is absent. Mismatch or unknown blocks with sysarg / sysarg_unknown (§4).

    **Lowering**: Stage ③ reads wrapper argument1 via bpfabi.kprobe_arg, adds UAPI ksyscallarg offset, then probe_read_kernel (113) copies eight bytes into a zeroed stack slot and truncates. Same two-stage shape as BPF_KSYSCALL / PT_REGS_PARMn_CORE_SYSCALL, but fixed offsets rather than CO-RE.

    **user_str**: Requires matching schema kind user_str; cannot substitute i64 / ptr despite equal width. Preserves raw 64-bit pointer from the two-stage read; separate user.read_str (helper114) reads bytes. sysarg strptr minimum format16 matches one-level tracefs char pointers or BTF char pointers after qualifier / typedef removal. Both mismatch and Unknown block. char** / void* / unsigned char* / arrays are not strptr. Three-kernel helper114 runtime evidence belongs to the dedicated syscall-string experiment.

    **Evidence**: F67. 7.1.8 root prctl five arguments compared with equivalent C. The C-only two-stage measurement establishes cx is the return address.

    **Unsupported**: Other architectures (UAPI ksyscallarg supports x86_64 only), compat ia32 entries, and generic user-memory dereference. kprobe.arg remains rejected for ksyscall because wrapper registers are not syscall arguments. No loop bodies or static-function context arguments.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I64Attr:$n);
  let results = (outs AnyTypeOf<[I8, I16, I32, I64, EBPF_UserStrType, EBPF_UserStrArrayType]>:$result);
  let assemblyFormat = "$ctx $n attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

// Session entry/return tests and cookies; see the canonical description.
def EBPF_SessionIsReturnOp : EBPF_Op<"session.is_return"> {
  let summary = "Test whether a session program is executing at function return (bpf_session_is_return kfunc)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: kprobe_session / fsession run the same program at entry and return. Returns i1 true at return, interpreting nonzero bpf_session_is_return(ctx) bool as true.

    **Constraints**: Own context with OPS session, not static-function context. Program type must occur in the UAPI kfunc table generated from kernel source / vmlinux BTF.

    **Lowering**: Stage ③ calls bpfabi.kfunc_call bpf_session_is_return(ctx) -> i8 and compares != 0. Stage ④ calls an extern .ksyms function; BTF FUNC_PROTO follows table bool(void *ctx). The 7.1.8 verifier inlines fsession calls.

    **Evidence**: F66. 7.1.8 root kprobe-session / fsession entry / return counts compared with C.

    **Unsupported**: **Signature varies by kernel**: 7.1.8 bool(void *ctx), 6.12 bool(void), absent on 6.6. Format13 kfunc requirement rows check target FUNC_PROTO before load; 6.12's void signature and 6.6 absence stop with kfunc_sig. Handwritten-requirement checks exist, but generated-ELF checking on 6.12 / 6.6 was not measured in the original extension. No uprobe session.
  }];
  let arguments = (ins EBPF_ContextType:$ctx);
  let results = (outs I1:$result);
  let assemblyFormat = "$ctx attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

def EBPF_SessionCookieLoadOp : EBPF_Op<"session.cookie.load"> {
  let summary = "Read the eight-byte cookie shared between session entry and return";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads the i64 cookie shared by entry / return for one invocation of the link's function (kernel session run-context data). Typically store at entry and load at return. Initial entry value is expected zero from 7.1.8 source reading only, not measured.

    **Constraints**: Follows session.is_return: own session-kind context and kfunc-table program type.

    **Lowering**: Stage ③ calls bpf_session_cookie(ctx) -> ptr, then loads eight bytes. No ret_null in the table: kernel type is non-null PTR_TO_MEM of size8.

    **Evidence**: F66. Entry stores 0xE473 and return sums it, compared with C.

    **Unsupported**: Kernel signature differences follow session.is_return. No op exposes the cookie pointer itself; load / store only.
  }];
  let arguments = (ins EBPF_ContextType:$ctx);
  let results = (outs I64:$result);
  let assemblyFormat = "$ctx attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

def EBPF_SessionCookieStoreOp : EBPF_Op<"session.cookie.store"> {
  let summary = "Write the eight-byte cookie shared between session entry and return";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Writes i64 to the cookie described by session.cookie.load.

    **Constraints**: Same as session.is_return; value i64.

    **Lowering**: Stage ③ calls bpf_session_cookie(ctx) -> ptr and stores eight bytes.

    **Evidence**: F66. Session cookie differential tests.

    **Unsupported**: Same as session.cookie.load.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I64:$value);
  let assemblyFormat = "$ctx `,` $value attr-dict `:` type($ctx) `,` type($value)";
  let hasVerifier = 1;
}

// sched_ext kfuncs of the family "insert". Shared constraints are in
// each description; the callback and sleepable table is ScxContract.def.
def EBPF_ScxDsqInsertOp : EBPF_Op<"scx.dsq_insert"> {
  let summary = "Insert a task into a dispatch queue (scx_bpf_dsq_insert)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_dsq_insert(p, dsq_id, slice, enq_flags), queueing the task on the DSQ with the time slice in ns. The kfunc returns nothing; the kernel reports misuse with scx_error and aborts the scheduler, not with a status.

    **Constraints**: The module declares `ebpf.scx_kfuncs = "insert"`. The program is a struct_ops program implementing a member of a schema struct_ops map of type sched_ext_ops whose member may call ENQUEUE kfuncs (select_cpu, enqueue, dispatch — ScxContract.def, the kernel's scx_kf_allow_flags without its #ifdef rows). The task is a checked !ebpf.kptr<"task_struct">; dsq, slice and flags are i64 (no implicit extension). Only in the program body and ebpf.if / ref.check / kptr.check regions (no loop, callback, map.for_each or spin.region). (the placement every sched_ext op shares) Also in an ebpf.func body and the same regions inside it, when every context that reaches the function allows the op as its owner's body would: a sched_ext struct_ops owner (ebpf-verify-call-contexts — kind and kfunc program type), the owner's sched_ext_ops member in the member table, KF_SLEEPABLE only in a sleepable context (a sleepable member with no ebpf.rcu.region on the call path), the RCU-section ops only outside a sleepable context, dump only in the dump members (ebpf-verify-schema); no ebpf.loop / scf.if around a call on the path; not through a helper callback; through a sched_ext_ops owner's ebpf.timer.callback only the ops of kScxTimerCallbackOps — the compiler's conservative subset, not the kernel's filter — and nothing KF_SLEEPABLE (as in the callback body). The failing context is named (owner, kind, member, entry, call path, sleepable).

    **Lowering**: Stage ③ bpfabi.kfunc_call scx_bpf_dsq_insert; ④ and ObjectEmitter use the kfunc path (.ksyms extern, BTF FUNC_PROTO from the UAPI kfunc row, format-13 kfunc requirement row). The UAPI row is the BPF-visible prototype: KF_IMPLICIT_ARGS drops the trailing bpf_prog_aux.

    **Evidence**: Out of scope — kernel evidence: compile only, no kernel load or verifier result yet (a separate VM run covers it).

    **Unsupported**: Other DSQ kfuncs and member allow rows under kernel config #ifdef (cgroup_*).
  }];
  let arguments = (ins AnyType:$task, AnyType:$dsq, AnyType:$slice, AnyType:$flags);
  let assemblyFormat = "$task `,` $dsq `,` $slice `,` $flags attr-dict `:` type($task) `,` type($dsq) `,` type($slice) `,` type($flags)";
  let hasVerifier = 1;
}
def EBPF_ScxDsqInsertVtimeOp : EBPF_Op<"scx.dsq_insert_vtime"> {
  let summary = "Insert a task into a dispatch queue in virtual-time order (scx_bpf_dsq_insert_vtime)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_dsq_insert_vtime(p, dsq_id, slice, vtime, enq_flags), queueing the task on a user DSQ ordered by vtime.

    **Constraints**: As scx.dsq_insert (ENQUEUE members); all scalars are i64.

    **Lowering**: Stage ③ bpfabi.kfunc_call scx_bpf_dsq_insert_vtime, then the kfunc path.

    **Evidence**: Out of scope — kernel evidence: compile only, no kernel load or verifier result yet.

    **Unsupported**: As scx.dsq_insert.
  }];
  let arguments = (ins AnyType:$task, AnyType:$dsq, AnyType:$slice, AnyType:$vtime, AnyType:$flags);
  let assemblyFormat = "$task `,` $dsq `,` $slice `,` $vtime `,` $flags attr-dict `:` type($task) `,` type($dsq) `,` type($slice) `,` type($vtime) `,` type($flags)";
  let hasVerifier = 1;
}
def EBPF_ScxDsqMoveToLocalOp : EBPF_Op<"scx.dsq_move_to_local"> {
  let summary = "Move the first task of a DSQ to the local DSQ (scx_bpf_dsq_move_to_local)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_dsq_move_to_local(dsq_id) and returns i1 true if a task was moved (the kfunc's bool).

    **Constraints**: As scx.dsq_insert, but the member must allow DISPATCH kfuncs (dispatch). dsq is i64, the result i1.

    **Lowering**: Stage ③ bpfabi.kfunc_call scx_bpf_dsq_move_to_local -> i8 compared != 0.

    **Evidence**: Out of scope — kernel evidence: compile only, no kernel load or verifier result yet.

    **Unsupported**: Other DSQ move kfuncs.
  }];
  let arguments = (ins AnyType:$dsq);
  let results = (outs AnyType:$moved);
  let assemblyFormat = "$dsq attr-dict `:` type($dsq) `->` type($moved)";
  let hasVerifier = 1;
}
def EBPF_ScxCreateDsqOp : EBPF_Op<"scx.create_dsq"> {
  let summary = "Create a user dispatch queue (scx_bpf_create_dsq)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_create_dsq(dsq_id, node) and returns its raw i32 status (0 or negative errno).

    **Constraints**: As scx.dsq_insert, but the member must allow UNLOCKED kfuncs (init_task, dump, sub_attach, sub_detach, cpu_online, cpu_offline, init, exit) and the program must be sleepable (schema program key "sleepable": true — KF_SLEEPABLE). Rejected in a timer callback context — the callback body and every function it reaches, directly or through calls (the callback is not sleepable; the owner's sleepable flag does not flow into it) — and in a function reached through a call inside ebpf.rcu.region, also past a global function. dsq is i64, node i32, result i32.

    **Lowering**: Stage ③ bpfabi.kfunc_call scx_bpf_create_dsq; the program section is struct_ops.s (cilium loads it with BPF_F_SLEEPABLE).

    **Evidence**: Out of scope — kernel evidence: compile only, no kernel load or verifier result yet.

    **Unsupported**: Destroying DSQs.
  }];
  let arguments = (ins AnyType:$dsq, AnyType:$node);
  let results = (outs AnyType:$status);
  let assemblyFormat = "$dsq `,` $node attr-dict `:` type($dsq) `,` type($node) `->` type($status)";
  let hasVerifier = 1;
}
def EBPF_ScxSelectCpuDflOp : EBPF_Op<"scx.select_cpu_dfl"> {
  let summary = "Run the default CPU selection (scx_bpf_select_cpu_dfl)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle) and returns the selected CPU (i32) and whether it was idle (i1 from the bool out parameter).

    **Constraints**: As scx.dsq_insert, but the member must allow SELECT_CPU or UNLOCKED kfuncs. prev is i32, wake i64; results i32 and i1.

    **Lowering**: Stage ③ allocates a one-byte stack slot, stores 0, passes its address as is_idle, calls the kfunc and loads the byte (!= 0).

    **Evidence**: Out of scope — kernel evidence: compile only, no kernel load or verifier result yet.

    **Unsupported**: scx_bpf_select_cpu_and and cpumask kfuncs.
  }];
  let arguments = (ins AnyType:$task, AnyType:$prev, AnyType:$wake);
  let results = (outs AnyType:$cpu, AnyType:$idle);
  let assemblyFormat = "$task `,` $prev `,` $wake attr-dict `:` type($task) `,` type($prev) `,` type($wake) `->` type($cpu) `,` type($idle)";
  let hasVerifier = 1;
}
def EBPF_ScxTaskSetDsqVtimeOp : EBPF_Op<"scx.task_set_dsq_vtime"> {
  let summary = "Set a task's DSQ virtual time (scx_bpf_task_set_dsq_vtime)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_task_set_dsq_vtime(p, vtime). The kfunc's bool result (false for a task it does not own) is dropped.

    **Constraints**: As scx.dsq_insert, but any sched_ext_ops member may call it (scx_kfunc_ids_any). vtime is i64.

    **Lowering**: Stage ③ bpfabi.kfunc_call scx_bpf_task_set_dsq_vtime -> i8, result unused.

    **Evidence**: Out of scope — kernel evidence: compile only, no kernel load or verifier result yet.

    **Unsupported**: Reading the bool result.
  }];
  let arguments = (ins AnyType:$task, AnyType:$vtime);
  let assemblyFormat = "$task `,` $vtime attr-dict `:` type($task) `,` type($vtime)";
  let hasVerifier = 1;
}
def EBPF_ScxErrorOp : EBPF_Op<"scx.error"> {
  let summary = "Abort the scheduler with a formatted message (scx_bpf_error_bstr)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_error_bstr(fmt, data, data__sz): the kernel formats the message with bstr_printf and disables the scheduler.

    **Constraints**: As scx.dsq_insert, but any sched_ext_ops member may call it, and a timer.callback whose owners are sched_ext_ops programs. The format is a non-empty literal without NUL; 0 to 12 i64 arguments (MAX_BPRINTF_VARARGS). A format with only i64 arguments, no `%s` and no ambiguous `%` (a `%` right after flags / width, or at the end) is not parsed further (unchanged earlier); otherwise it is strict — see scx.dump — and scx.error / scx.exit reject it: `%s` and `!ebpf.str_buf` are for scx.dump only.

    **Lowering**: Stage ③ places the format (with one NUL) in a compiler-owned static of writable .data (`__ebpf_scx_fmt_<sha256>` — as C's scx_bpf_bstr_preamble, not .rodata: the kfunc's char *fmt is a fixed-size memory argument the verifier checks for read and write, which a BPF_F_RDONLY_PROG .rodata map value fails), stores the arguments to a stack u64 array in order and passes data__sz = 8 × count; with no arguments a zeroed one-element stack u64 array and data__sz = 8 (as C's ___param[narg ?: 1] = {} — the data pointer is not a nullable kfunc argument, and 7.3.1 rejects NULL; earlier NULL and 0 was a design error).

    **Evidence**: Out of scope — kernel evidence: compile only. : the 7.3.1 verifier rejected the earlier .rodata format (write into map forbidden in simple_init); moves it to .data, and loaded simple / cpu0 / b1cover on 7.3.1 but rejected the zero-argument call's NULL data (Possibly NULL pointer passed to trusted R2 — scx-insert); the zeroed one-element array's 7.3.1 load is pending.

    **Unsupported**: Format checking of the i64-only formats, `%s` (scx.dump only) and non-i64 integer arguments (adds scx.exit and scx.dump with the same shape).
  }];
  let arguments = (ins StrAttr:$format, Variadic<AnyType>:$args);
  let assemblyFormat = "$format `(` $args `)` attr-dict (`:` type($args)^)?";
  let hasVerifier = 1;
}
def EBPF_ScxConstOp : EBPF_Op<"scx.const", [Pure]> {
  let summary = "A sched_ext enum constant checked against the target BTF at load time";
  let description = [{
    **Stage**: ① Input

    **Meaning**: The i64 bit pattern of a sched_ext enum constant (SCX_DSQ_LOCAL, SCX_SLICE_DFL) from the UAPI table scxenum rows, which abigen takes from the canonical vmlinux BTF.

    **Constraints**: The name is a scxenum row; the result is i64. Placement and program rules are those of scx.dsq_insert, but any member may use it. Also in a timer.callback whose owners are sched_ext_ops programs.

    **Lowering**: As ebpf.core.enum_value: Stage ③ bpfabi.core_enum_value, ④ marker `__ebpf_core_enum.<enum>.<name>`, which ObjectEmitter turns into a CO-RE enum value relocation (clang's `bpf_core_enum_value` — `ld_imm64`, `.BTF.ext` kind 11 enumval_value) on a local ENUM64 with one enumerator. The loader writes the target's value; an absent constant is poisoned by the loader. The requirements row `coreenum <prog> <enum> <name>` (format 26) makes the loader check that the constant exists (coreenum / coreenum_unknown block the load). earlier the value was an immediate checked by `enumval <prog> <enum> <name> <value>` (format 20) — the reader still checks that row in old ELFs.

    **Evidence**: Out of scope — kernel evidence: is compile and requirements only; resolves the relocation offline (cilium v0.22 CORERelocate) against four kernels' BTF; the VM load is measured separately.

    **Unsupported**: Constants of other enums.
  }];
  let arguments = (ins StrAttr:$name);
  let results = (outs AnyType:$value);
  let assemblyFormat = "$name attr-dict `:` type($value)";
  let hasVerifier = 1;
}
def EBPF_CoreEnumValueOp : EBPF_Op<"core.enum_value", [Pure]> {
  let summary = "A kernel enum constant read through a CO-RE enum value relocation (any program kind)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: C's `bpf_core_enum_value(enum E, NAME)`: the i64 value of the target kernel's enumerator NAME of enum E, which the loader writes into the instruction at load (the compiler does not choose it). The compiler's local value (the UAPI table's) is the relocation's expected value only.

    **Constraints**: The (enum, name) pair is a scxenum row of the UAPI table (the enum must be the row's enum); the result is i64. Unlike ebpf.scx.const it does not depend on the program kind: allowed wherever arith is (any program body, ebpf.if / ebpf.loop bodies, ebpf.func, loop callbacks, ebpf.map.for_each, ebpf.iter.num, ebpf.timer.callback and ebpf.user_ringbuf.callback) — not inside ebpf.spin.region.

    **Lowering**: Stage ③ bpfabi.core_enum_value, ④ marker `__ebpf_core_enum.<enum>.<name>` → ObjectEmitter llvm.bpf.preserve.enum.value(seq, "<name>:<value>", 1) with a local ENUM64 E (unsigned, one enumerator) — `ld_imm64` and `.BTF.ext` kind 11 (enumval_value). Requirements row `coreenum <prog> <enum> <name>` (format 26) for every program reaching the use; the loader checks existence only (coreenum / coreenum_unknown block the load).

    **Evidence**: Out of scope — kernel evidence: is compile and offline (cilium v0.22 CORERelocate against 7.3.1 / 7.1.8 / 6.12.111 / 6.6.157 BTF); a separate VM run covers it.

    **Unsupported**: Enums outside the scxenum rows, the enum value existence relocation (kind 10) and a guard on it.
  }];
  let arguments = (ins StrAttr:$enum_name, StrAttr:$name);
  let results = (outs I64:$value);
  let assemblyFormat = "$enum_name $name attr-dict `:` type($value)";
  let hasVerifier = 1;
}
def EBPF_ScxExitInfoOp : EBPF_Op<"scx.exit_info"> {
  let summary = "Record a sched_ext exit (the UEI_RECORD of tools/sched_ext) into a .data record global";
  let description = [{
    **Stage**: ① Input

    **Meaning**: In the order of UEI_RECORD (7.3.1 user_exit_info.bpf.h): probe_read_kernel_str(&uei.reason, 128, ei->reason); probe_read_kernel_str(&uei.msg, 1024, ei->msg); uei.exit_code = ei->exit_code; uei.exit_cpu = −1; then a 32-bit compare-and-exchange of uei.kind from its value just read to ei->kind (the publish — a memory clobber also stops compiler reordering). Helper statuses are discarded, as in C.

    **Constraints**: Placement and program rules are those of scx.dsq_insert (the family declaration, a sched_ext struct_ops program body and its if / ref.check / kptr.check regions — or an ebpf.func body every reaching context of which is such a program body), but any member may use it — it calls no kfunc. ei is !ebpf.kptr<"scx_exit_info">; core.kernel_types declares scx_exit_info with kind {"kind": "enum", "bits": 32}, exit_code i64, reason and msg strptr (ebpf-verify-kptr). @uei is a core.globals entry with "section": "data" whose record is exactly {kind i32 @0, exit_cpu i32 @4, exit_code i64 @8, reason [128]i8 @16, msg [1024]i8 @144} of 1168 bytes — the C struct user_exit_info (ebpf-verify-schema).

    **Lowering**: Stage ③ reads the four kernel fields with bpfabi.core_field_load (requirements kfield rows `scx_exit_info kind enum:32`, `exit_code i64`, `reason strptr`, `msg strptr`), calls helper probe_read_kernel_str twice into the global at offsets 16 and 144, stores exit_code at 8 and −1 at 4, volatile-loads kind and swaps it with inline asm `w0 = cmpxchg32_32(r + 0, w0, w2)` (ObjectEmitter's CPU v1 has no 32-bit cmpxchg in LLVM; the instruction encodes at any CPU version).

    **Evidence**: Out of scope — kernel evidence: is compile and offline precheck only, no sched_ext load.

    **Unsupported**: The dump buffer (uei_dump), the exit_cpu field of 7.3.1 (always −1; reading it would block 6.12 / 7.1.8), and other exit records.
  }];
  let arguments = (ins EBPF_KPtrType:$info, FlatSymbolRefAttr:$uei);
  let assemblyFormat = "$info `,` $uei attr-dict `:` type($info)";
  let hasVerifier = 1;
}

// the scalar, query and callback kfuncs. All are in
// scx_kfunc_ids_any (pick_idle_cpu in scx_kfunc_ids_idle); the placement and
// family rules are those of scx.dsq_insert.
def EBPF_ScxTaskCpuOp : EBPF_Op<"scx.task_cpu"> {
  let summary = "The CPU a task is on (scx_bpf_task_cpu)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_task_cpu(p) and returns the i32 CPU.

    **Constraints**: As scx.dsq_insert, but any sched_ext_ops member may call it. The task is a checked !ebpf.kptr<"task_struct">, a checked !ebpf.rcu_ptr<"task_struct"> or a nonnull owned !ebpf.kref<"task_struct"> (the kfunc is KF_RCU, which takes trusted, referenced and RCU pointers — 7.3.1 verifier.c:13092-13120; the kref is not consumed). The result is i32.

    **Lowering**: Stage ③ bpfabi.kfunc_call scx_bpf_task_cpu, then the kfunc path.

    **Evidence**: Out of scope — kernel evidence: compile only, no kernel load or verifier result yet (a separate VM run covers it).

    **Unsupported**: Tasks from other origins.
  }];
  let arguments = (ins AnyType:$task);
  let results = (outs AnyType:$cpu);
  let assemblyFormat = "$task attr-dict `:` type($task) `->` type($cpu)";
  let hasVerifier = 1;
}
def EBPF_ScxKickCpuOp : EBPF_Op<"scx.kick_cpu"> {
  let summary = "Kick a CPU to reschedule (scx_bpf_kick_cpu)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_kick_cpu(cpu, flags). The kfunc returns nothing.

    **Constraints**: As scx.dsq_insert, but any sched_ext_ops member may call it, and a timer.callback whose owners are sched_ext_ops programs. cpu is i32, flags i64 (SCX_KICK_IDLE / PREEMPT / WAIT through scx.const).

    **Lowering**: Stage ③ bpfabi.kfunc_call scx_bpf_kick_cpu, then the kfunc path.

    **Evidence**: Out of scope — kernel evidence: compile only, no kernel load or verifier result yet (a separate VM run covers it).

    **Unsupported**: None beyond the shared placement rules.
  }];
  let arguments = (ins AnyType:$cpu, AnyType:$flags);
  let assemblyFormat = "$cpu `,` $flags attr-dict `:` type($cpu) `,` type($flags)";
  let hasVerifier = 1;
}
def EBPF_ScxDsqNrQueuedOp : EBPF_Op<"scx.dsq_nr_queued"> {
  let summary = "The number of tasks in a DSQ (scx_bpf_dsq_nr_queued)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_dsq_nr_queued(dsq_id) and returns its raw i32 (the count, or a negative errno for a missing DSQ).

    **Constraints**: As scx.dsq_insert, but any sched_ext_ops member may call it, and a timer.callback whose owners are sched_ext_ops programs. dsq is i64, the result i32.

    **Lowering**: Stage ③ bpfabi.kfunc_call scx_bpf_dsq_nr_queued, then the kfunc path.

    **Evidence**: Out of scope — kernel evidence: compile only, no kernel load or verifier result yet (a separate VM run covers it).

    **Unsupported**: None beyond the shared placement rules.
  }];
  let arguments = (ins AnyType:$dsq);
  let results = (outs AnyType:$count);
  let assemblyFormat = "$dsq attr-dict `:` type($dsq) `->` type($count)";
  let hasVerifier = 1;
}
def EBPF_ScxDsqPeekOp : EBPF_Op<"scx.dsq_peek"> {
  let summary = "The first task of a DSQ, RCU-protected (scx_bpf_dsq_peek)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_dsq_peek(dsq_id) and returns the first task as !ebpf.rcu_ptr_or_null<"task_struct"> (KF_RCU_PROTECTED | KF_RET_NULL — the verifier marks it MEM_RCU | PTR_MAYBE_NULL, not trusted).

    **Constraints**: As scx.dsq_insert, but any sched_ext_ops member may call it, and only in a member program that is not sleepable (the RCU read section — ebpf-verify-schema; ScxContract.h scxNeedsRcuSection) or inside ebpf.rcu.region (a caller's region counts only through static calls). In a timer callback context (a sched_ext_ops owner's ebpf.timer.callback and the functions it reaches) it is rejected also inside ebpf.rcu.region: it is outside kScxTimerCallbackOps, the compiler's conservative subset (not the kernel's filter). dsq is i64. The result must be checked with ebpf.kptr.check; its present !ebpf.rcu_ptr reaches only scx.task_cpu and kfield.load.

    **Lowering**: Stage ③ bpfabi.kfunc_call scx_bpf_dsq_peek -> pointer, then the kfunc path (BTF *task_struct of the local @kernel type).

    **Evidence**: Out of scope — kernel evidence: compile only, no kernel load or verifier result yet (a separate VM run covers it).

    **Unsupported**: Sleepable members (no explicit RCU lock — B2), and passing the task to trusted-argument kfuncs.
  }];
  let arguments = (ins AnyType:$dsq);
  let results = (outs EBPF_RcuPtrOrNullType:$task);
  let assemblyFormat = "$dsq attr-dict `:` type($dsq) `->` type($task)";
  let hasVerifier = 1;
}
def EBPF_ScxTaskSetSliceOp : EBPF_Op<"scx.task_set_slice"> {
  let summary = "Set a task's time slice (scx_bpf_task_set_slice)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_task_set_slice(p, slice). The kfunc's bool result is dropped, as in scx.task_set_dsq_vtime.

    **Constraints**: As scx.dsq_insert, but any sched_ext_ops member may call it. The task is a checked !ebpf.kptr<"task_struct"> (not an rcu_ptr); slice is i64.

    **Lowering**: Stage ③ bpfabi.kfunc_call scx_bpf_task_set_slice -> i8, result unused.

    **Evidence**: Out of scope — kernel evidence: compile only, no kernel load or verifier result yet (a separate VM run covers it).

    **Unsupported**: Reading the bool result.
  }];
  let arguments = (ins AnyType:$task, AnyType:$slice);
  let assemblyFormat = "$task `,` $slice attr-dict `:` type($task) `,` type($slice)";
  let hasVerifier = 1;
}
def EBPF_ScxNowOp : EBPF_Op<"scx.now"> {
  let summary = "The sched_ext clock in ns (scx_bpf_now)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_now() and returns the u64 clock as i64.

    **Constraints**: As scx.dsq_insert, but any sched_ext_ops member may call it, and a timer.callback whose owners are sched_ext_ops programs. Also a syscall program (the kind's OPS tag scx.now — scx_kfunc_context_filter allows the in_any kfuncs for BPF_PROG_TYPE_SYSCALL in 7.3.1 / 7.1.8), directly and through ebpf.func (every reaching context checked by ebpf-verify-call-contexts). The result is i64. Not Pure: each occurrence is one call.

    **Lowering**: Stage ③ bpfabi.kfunc_call scx_bpf_now, then the kfunc path.

    **Evidence**: Out of scope — kernel evidence: compile only, no kernel load or verifier result yet (a separate VM run covers it). the syscall case is compile only (lit); 6.12.111 has no scx_bpf_now, so its kfunc row stops the load before it (observes it).

    **Unsupported**: Other sched_ext kfunc ops in syscall programs (the kernel's filter also allows the unlocked / select_cpu / idle sets — not opened). Nothing else beyond the shared placement rules.
  }];
  let results = (outs AnyType:$ns);
  let assemblyFormat = "attr-dict `:` type($ns)";
  let hasVerifier = 1;
}
def EBPF_ScxPickIdleCpuOp : EBPF_Op<"scx.pick_idle_cpu"> {
  let summary = "Pick an idle CPU from a task's allowed CPUs (scx_bpf_pick_idle_cpu)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_pick_idle_cpu(cpus_allowed, flags) and returns the raw i32 (an idle CPU it claimed, or −EBUSY).

    **Constraints**: As scx.dsq_insert, but any sched_ext_ops member may call it (scx_kfunc_ids_idle), and only in a member program that is not sleepable (task->cpus_ptr is MEM_RCU only in the RCU read section). The cpumask is the checked !ebpf.kptr<"cpumask"> of `ebpf.kfield.ptr %t "cpus_ptr"` where %t is a checked !ebpf.kptr<"task_struct"> (the op verifier follows the definitions; schema core.kernel_types declares task_struct.cpus_ptr as {"kind": "kptr", "struct": "cpumask"}). flags is i64 (SCX_PICK_IDLE_CORE through scx.const, or 0). If the struct_ops has an update_idle member, its flags must have SCX_OPS_KEEP_BUILTIN_IDLE (UAPI scxenum row; ebpf-verify-schema).

    **Lowering**: Stage ③ bpfabi.kfunc_call scx_bpf_pick_idle_cpu, then the kfunc path (BTF *cpumask of the local @kernel type).

    **Evidence**: Out of scope — kernel evidence: compile only, no kernel load or verifier result yet (a separate VM run covers it).

    **Unsupported**: Other cpumasks (B3) and sleepable members.
  }];
  let arguments = (ins AnyType:$cpus, AnyType:$flags);
  let results = (outs AnyType:$cpu);
  let assemblyFormat = "$cpus `,` $flags attr-dict `:` type($cpus) `,` type($flags) `->` type($cpu)";
  let hasVerifier = 1;
}
def EBPF_ScxCpuCurrOp : EBPF_Op<"scx.cpu_curr"> {
  let summary = "The task running on a CPU, RCU-protected (scx_bpf_cpu_curr)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_cpu_curr(cpu) and returns !ebpf.rcu_ptr_or_null<"task_struct"> (KF_RET_NULL | KF_RCU_PROTECTED).

    **Constraints**: As scx.dsq_peek (non-sleepable members or inside ebpf.rcu.region; rejected in a timer callback context also inside ebpf.rcu.region; checked with kptr.check). cpu is i32.

    **Lowering**: Stage ③ bpfabi.kfunc_call scx_bpf_cpu_curr -> pointer, then the kfunc path. The 7.1.8 BTF keeps the bpf_prog_aux argument (no decl tag); the UAPI row is normalized (rule).

    **Evidence**: Out of scope — kernel evidence: compile only, no kernel load or verifier result yet (a separate VM run covers it).

    **Unsupported**: As scx.dsq_peek.
  }];
  let arguments = (ins AnyType:$cpu);
  let results = (outs EBPF_RcuPtrOrNullType:$task);
  let assemblyFormat = "$cpu attr-dict `:` type($cpu) `->` type($task)";
  let hasVerifier = 1;
}
def EBPF_ScxCpuperfCapOp : EBPF_Op<"scx.cpuperf_cap"> {
  let summary = "A CPU's relative performance capacity (scx_bpf_cpuperf_cap)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_cpuperf_cap(cpu) and returns the u32 capacity as i32.

    **Constraints**: As scx.dsq_insert, but any sched_ext_ops member may call it, and a timer.callback whose owners are sched_ext_ops programs. cpu is i32, the result i32.

    **Lowering**: Stage ③ bpfabi.kfunc_call scx_bpf_cpuperf_cap, then the kfunc path.

    **Evidence**: Out of scope — kernel evidence: compile only, no kernel load or verifier result yet (a separate VM run covers it).

    **Unsupported**: None beyond the shared placement rules.
  }];
  let arguments = (ins AnyType:$cpu);
  let results = (outs AnyType:$cap);
  let assemblyFormat = "$cpu attr-dict `:` type($cpu) `->` type($cap)";
  let hasVerifier = 1;
}
def EBPF_ScxCpuperfSetOp : EBPF_Op<"scx.cpuperf_set"> {
  let summary = "Set a CPU's performance target (scx_bpf_cpuperf_set)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_cpuperf_set(cpu, perf). The kfunc returns nothing.

    **Constraints**: As scx.dsq_insert, but any sched_ext_ops member may call it, and a timer.callback whose owners are sched_ext_ops programs. cpu is i32, perf i32 (the u32 parameter).

    **Lowering**: Stage ③ bpfabi.kfunc_call scx_bpf_cpuperf_set, then the kfunc path. The 7.1.8 BTF row is normalized as for scx.cpu_curr.

    **Evidence**: Out of scope — kernel evidence: compile only, no kernel load or verifier result yet (a separate VM run covers it).

    **Unsupported**: None beyond the shared placement rules.
  }];
  let arguments = (ins AnyType:$cpu, AnyType:$perf);
  let assemblyFormat = "$cpu `,` $perf attr-dict `:` type($cpu) `,` type($perf)";
  let hasVerifier = 1;
}
def EBPF_ScxDsqReenqOp : EBPF_Op<"scx.dsq_reenq"> {
  let summary = "Re-enqueue the tasks of a DSQ (scx_bpf_dsq_reenq)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_dsq_reenq(dsq_id, reenq_flags) with reenq_flags 0. The kfunc returns nothing.

    **Constraints**: As scx.dsq_insert, but any sched_ext_ops member may call it, and a timer.callback whose owners are sched_ext_ops programs. dsq is i64; flags is i64 and must be an arith.constant 0 (the SCX_REENQ_* flags are outside B1).

    **Lowering**: Stage ③ bpfabi.kfunc_call scx_bpf_dsq_reenq, then the kfunc path.

    **Evidence**: Out of scope — kernel evidence: compile only, no kernel load or verifier result yet (a separate VM run covers it).

    **Unsupported**: Non-zero reenq flags.
  }];
  let arguments = (ins AnyType:$dsq, AnyType:$flags);
  let assemblyFormat = "$dsq `,` $flags attr-dict `:` type($dsq) `,` type($flags)";
  let hasVerifier = 1;
}
def EBPF_ScxExitOp : EBPF_Op<"scx.exit"> {
  let summary = "Exit the scheduler with a code and formatted message (scx_bpf_exit_bstr)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_exit_bstr(exit_code, fmt, data, data__sz): the kernel formats the message with bstr_printf and disables the scheduler with SCX_EXIT_UNREG_BPF.

    **Constraints**: As scx.error (any member; non-empty literal without NUL; 0 to 12 i64 arguments), with a leading i64 exit code. Also in a timer.callback whose owners are sched_ext_ops programs.

    **Lowering**: As scx.error: the format in a compiler-owned static of writable .data, the arguments in a stack u64 array, data__sz = 8 × count, and a zeroed one-element array with data__sz = 8 for none.

    **Evidence**: Out of scope — kernel evidence: compile only, no kernel load or verifier result yet (a separate VM run covers it); the zero-argument form's data follows scx.error.

    **Unsupported**: As scx.error — `%s` and string buffers are for scx.dump only.
  }];
  let arguments = (ins AnyType:$code, StrAttr:$format, Variadic<AnyType>:$args);
  let assemblyFormat = "$code `,` $format `(` $args `)` attr-dict `:` type($code) (`,` type($args)^)?";
  let hasVerifier = 1;
}
def EBPF_ScxDumpOp : EBPF_Op<"scx.dump"> {
  let summary = "Write a formatted line to the sched_ext debug dump (scx_bpf_dump_bstr)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls scx_bpf_dump_bstr(fmt, data, data__sz), appending to the dump the kernel collects when the scheduler exits with a dump.

    **Constraints**: As scx.error, but only in the dump, dump_cpu and dump_task members (ebpf-verify-schema; ScxContract.h scxDumpMember). The kernel puts the kfunc in the any set and reports misuse outside ops.dump* with scx_error at run time; the compiler is the stricter side.
 An argument may be a `!ebpf.str_buf<N>` at a `%s`. The format is checked strictly when it has a str_buf argument, a `%s`, or an ambiguous `%` (the whole format is classified first, so an unsupported conversion before or after a `%s` cannot return it to the i64-only path): plain text without ASCII control bytes other than whitespace, `%%`, and conversions of `[0 +-]` flags, a width, then `s` (before NUL, whitespace or punctuation) or `[l[l]]{i,d,u,x,X}` — a closed subset of the kernel's bpf_bprintf_prepare (7.3.1 helpers.c:846-1049); every parse error is a rejection. Exactly one argument per conversion; `%s` takes a str_buf and the others an i64. The bin_args bound: Σ N over the `%s` + Σ (3 + 4 | 8) over the integers ≤ MAX_BPRINTF_BIN_ARGS 512 (else the kernel fails the dump with -ENOSPC — a compile error). A str_buf argument must come from the same program body (the nearest enclosing boundary skipping ebpf.if / kptr.check / kref.check / ref.check).

    **Lowering**: As scx.error, calling scx_bpf_dump_bstr. A `%s` argument's data entry is the buffer's stack address (ptrtoint of its alloca); the kernel copies it with copy_from_kernel_nofault_str.

    **Evidence**: Out of scope — kernel evidence: compile only, no kernel load or verifier result yet (a separate VM run covers it).

    **Unsupported**: The `%p` family, `%c`, a precision and other kernel conversions in a strict format; `%s` of anything other than a `!ebpf.str_buf` (a kernel char pointer or a .rodata string); string buffers longer than 64 bytes.
  }];
  let arguments = (ins StrAttr:$format, Variadic<AnyType>:$args);
  let assemblyFormat = "$format `(` $args `)` attr-dict (`:` type($args)^)?";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_SeqWriteOp : EBPF_Op<"seq.write"> {
  let summary = "bpf_seq_write: write complete record bytes to an iterator seq_file and return status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls seq_write(seq, &rec, sizeof rec), returning **raw** i64 status: 0 on success, −E2BIG for seq_file-buffer overflow. Bytes become read(2) output from the iterator fd.

    **Constraints**: iter programs only (OPS seq.write). seq is !ebpf.kptr<"seq_file"> read from bpf_iter_meta.seq with kfield.ptr and validated by kptr.check. Data is record.make (all bytes, zero padding). Kernel tracing_prog_func_proto permits this GPL helper only with expected_attach_type BPF_TRACE_ITER.

    **Lowering**: Stage ③ calls UAPI seq_write with record.make stack storage and record size.

    **Evidence**: F39. iter/bpf_map_elem read output is byte-identical to equivalent C.

    **Unsupported**: seq_printf / seq_printf_btf and variable-length data.
  }];
  let arguments = (ins EBPF_KPtrType:$seq, EBPF_RecordType:$record);
  let results = (outs I64:$status);
  let assemblyFormat = "$seq `,` $record attr-dict `:` type($seq) `,` type($record) `->` type($status)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_CtxLoadOp : EBPF_Op<"ctx.load"> {
  let summary = "Read an integer at a fixed byte offset of a user-supplied syscall-program context";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads a little-endian declared-width integer from syscall BPF_PROG_TEST_RUN ctx_in, an untyped user-supplied byte sequence. Not Pure; reads are not reordered / merged.

    **Constraints**: Own syscall entry context with OPS ctx.load. Width i8 / i16 / i32 / i64; offset ≥ 0 and aligned to width (compiler restriction; kernel syscall_prog_is_valid_access does not check alignment). Offset + width ≤ 65535; kernel requires offset < U16_MAX and ctx_size_in ≤ U16_MAX. Test run rejects ctx_in smaller than max accessed offset + width with -EINVAL (max_ctx_offset).

    **Lowering**: Stage ③ emits one volatile declared-width load at ctx + offset, not split / merged because verifier checks exact ctx offset / width. No helper.

    **Evidence**: F40. Syscall test-run retval and maps match C.

    **Unsupported**: Context stores (kernel accepts them and test run writes back to ctx_in) are not exposed. Neither compiler nor requirements describes context layout; byte meanings are a caller / author contract.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I64Attr:$offset);
  let results = (outs AnySignlessInteger:$result);
  let assemblyFormat = "$ctx `[` $offset `]` attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_SysBpfOp : EBPF_Op<"sys.bpf"> {
  let summary = "Invoke a pointer-free bpf() command from a syscall program (raw fd or negative errno)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls sys_bpf(cmd, &attr, sizeof attr) in the kernel. map_create / map_get_fd_by_id return a new fd installed O_CLOEXEC in **the test-run caller's fd table**; map_freeze returns 0; failure returns negative errno. Early kernel/bpf/syscall.c paths include map_create CHECK_ATTR / map_alloc_check −EINVAL, freeze missing-fd −EBADF / already-frozen −EBUSY, get_fd_by_id without CAP_SYS_ADMIN −EPERM / missing-ID −ENOENT. Attr record byte meanings are the author's contract; compiler does not interpret field names.

    **Constraints**: Own syscall program-body entry context with OPS sys.bpf, not subprogram / loop callback. Cmd is UAPI bpfcmd map_create / map_freeze / map_get_fd_by_id, the three pointer-free commands among nine accepted by bpf_sys_bpf. Attr is record.make and **size must not exceed the command's pointer boundary** (SysBpfAttr.def): map_create80 (7.1.8 excl_prog_hash), map_freeze8 (key), map_get_fd_by_id16 (struct end, no pointer). Kernel reads KERNEL_BPFPTR and treats pointer fields as kernel pointers, so these limits keep integer record bytes away from pointer fields. go/internal/abigen checks boundaries against three-kernel BTF. Kernel exposes the helper only to CAP_PERFMON loaders; otherwise load gives −EINVAL. Compiler does not inspect privilege; requirements helper rows support precheck.

    **Lowering**: Stage ③ calls sys_bpf with UAPI command number, record.make stack pointer, and record size; i64 result.

    **Evidence**: F40. Three-kernel test-run differential measurement against equivalent C.

    **Unsupported**: Pointer-bearing MAP_UPDATE / DELETE_ELEM / PROG_LOAD / BTF_LOAD / LINK_CREATE / RAW_TRACEPOINT_OPEN (no way to write pointers into records), btf_find_by_name_kind / kallsyms_lookup_name, and semantic fd checks (fds remain integers).
  }];
  let arguments = (ins EBPF_ContextType:$ctx, StrAttr:$cmd, EBPF_RecordType:$attr);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $cmd `,` $attr attr-dict `:` type($ctx) `,` type($attr) `->` type($status)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_SysCloseOp : EBPF_Op<"sys.close"> {
  let summary = "Close a file descriptor from a syscall program, returning raw bpf_sys_close status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: sys_close(fd) closes a descriptor in the test-run caller's fd table. Raw status is 0 or −EBADF for an absent fd (fs/file.c close_fd).

    **Constraints**: Own syscall program-body entry context with OPS sys.close. fd is i32 (truncate sys.bpf status with arith.trunci).

    **Lowering**: Stage ③ calls sys_close with zero-extended u32 fd; result i64.

    **Evidence**: F40. Syscall helper differential tests.

    **Unsupported**: No check that sys.bpf created the fd; any descriptor of the test-run caller can be closed.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, I32:$fd);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $fd attr-dict `:` type($ctx) `->` type($status)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_LircSampleOp : EBPF_Op<"lirc.sample"> {
  let summary = "Read a lirc_mode2 context sample as u32 (mode << 24 | value)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads one raw-IR device sample from rc-core. UAPI linux/lirc.h uses high eight bits for LIRC_MODE2_SPACE0 / PULSE1 / FREQUENCY2 / TIMEOUT3 / OVERFLOW4 shifted by24, low24 for microseconds or Hz. Result i32. Not Pure; reads are not reordered / merged. Decompose mode / value with arith and input-defined masks.

    **Constraints**: Own lirc_mode2 entry context with OPS lirc.sample, not static functions; result i32. This is exactly the sole access permitted by 7.1.8 drivers/media/rc/bpf-lirc.c lirc_mode2_is_valid_access: offset0, four-byte read.

    **Lowering**: Stage ③ emits one volatile four-byte load at ctx + 0, like ctx.load. No helper.

    **Evidence**: F48. BPF_PROG_ATTACH to rc-loopback LIRC device: pulse / space / timeout counts and value sums match C.

    **Unsupported**: No ctxaccess requirement row: context is not a struct, and its single offset0 u32 read is kernel-version invariant. No input-event helpers rc_keydown / rc_repeat / rc_pointer_rel.
  }];
  let arguments = (ins EBPF_ContextType:$ctx);
  let results = (outs I32:$result);
  let assemblyFormat = "$ctx attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_TpFieldOp : EBPF_Op<"tp.field"> {
  let summary = "Read a tracepoint event field at its schema-declared offset and width";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads a named context field from a tracefs event record. TRACE_EVENT uses the perf record; syscall events use local syscall_tp_t. In both, the first eight bytes are replaced by struct pt_regs*. Integer example: `ebpf.tp.field %ctx "fd" [16] : !ebpf.ctx<"tracepoint"> -> i64`. Returns raw bits without signed interpretation; schema declares sign and arith controls extension. Not Pure; reads are not reordered / merged.

    **Constraints**: Own tracepoint program entry context with OPS tp.field, not static functions. Integer widths i8 / i16 / i32 / i64; offset ≥ 8, aligned to width; offset + width ≤ 8192 (7.1.8 tp_prog_is_valid_access / PERF_MAX_TRACE_SIZE). Schema fields must contain the name with identical offset / width; the op copies the declaration, while schema is the checking authority.
    Load gates use attach trace_tp category/event plus tpfield name offset byte-count i|u for **all schema fields, including unread declarations**. Compare target events/category/event/format. Mismatch tpfield and unknown tpfield_unknown block load; tracefs is root-readable, so non-root can use root-recorded caps (format11 / policy9).

    **Lowering**: Stage ③ emits one volatile load at ctx + offset with declared width, like ctx.load. No split / combined access or helper.

    **user_str**: Also accepts !ebpf.user_str, strictly matching schema kind user_str, eight-byte size / alignment. Format16 tpfield strptr checks tracefs char* before load. char** / embedded arrays / data_loc do not match. Unknown types or unreadable formats are blocking Unknown. user.read_str exposes raw helper status; no integer cast or direct dereference.

    **Evidence**: F44. Actual C comparisons for syscall sys_enter_getppid __syscall_nr and sys_enter_write __syscall_nr / fd / count, plus TRACE_EVENT task_rename pid / oom_score_adj. Tracefs offsets equal BPF ctx offsets; wrong-offset declarations fail tpfield before load.

    **Unsupported**: __data_loc pointees, array scalar results, and scalars wider than eight bytes. Fixed-byte-array copying uses tp.field.copy (F75). Schema / requirements reject syscall fields outside the special BPF context.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, StrAttr:$field, I64Attr:$offset);
  let results = (outs AnyTypeOf<[AnySignlessInteger, EBPF_UserStrType, EBPF_UserStrArrayType]>:$result);
  let assemblyFormat = "$ctx $field `[` $offset `]` attr-dict `:` type($ctx) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_TpFieldCopyOp : EBPF_Op<"tp.field.copy"> {
  let summary = "Copy a fixed tracepoint byte array to an equal-length checked record array";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Copies fixed N bytes from an entry-context tracepoint field to a borrowed map record or checked ring reservation array. No result, NUL interpretation, or reservation consumption.

    **Constraints**: Schema type {kind:array,elem:u8|i8,n:N}, N 1..64. Name / offset must match; offset ≥ 8; offset + N ≤ 8192. Destination RecordPath is a one-dimensional eight-bit array of the same N. Own tracepoint entry context only; no static functions / loops / callbacks. Reservation present / consumption rules follow kfield.copy.

    **Lowering**: Stage ③ emits N volatile i8 loads at ctx + offset and i8 destination stores, alignment1. No helper / CO-RE.

    **Evidence**: F75. Format17 tpfield [N]u8/i8 checks tracefs fixed-array declaration, element width / count / sign / offset / size. Mismatch and Unknown block load.

    **Unsupported**: Dynamic / data_loc / multidimensional / non-eight-bit arrays, arbitrary pointers, and string semantics. Existing same-size scalar reinterpretation contracts remain unchanged.
  }];
  let arguments = (ins AnyTypeOf<[EBPF_BorrowedType, EBPF_ReservationType]>:$dst, StrAttr:$path,
                       EBPF_ContextType:$ctx, StrAttr:$field, I64Attr:$offset);
  let extraClassDeclaration = [{
    ::mlir::ebpf::RecordType getDstRecord();
    bool writesReservation() { return ::llvm::isa<::mlir::ebpf::ReservationType>(getDst().getType()); }
  }];
  let assemblyFormat = "$dst $path `,` $ctx $field `[` $offset `]` attr-dict `:` type($dst) `,` type($ctx)";
  let hasVerifier = 1;
}

def EBPF_KFieldCopyOp : EBPF_Op<"kfield.copy"> {
  let summary = "Copy fixed N bytes from a kernel-struct array field into a borrowed record or ring reservation array (CO-RE)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Copies all N bytes from a kptr<"S"> struct's declared eight-bit-integer array to an equal-length eight-bit record array. **Fixed N bytes**: neither NUL nor trailing bytes are interpreted; no string truncation. Destination is !ebpf.borrowed<!ebpf.record<…>> or checked !ebpf.reservation<!ebpf.record<…>>. No result; copying does not consume the reservation.

    **Constraints**: Nonempty source field / destination path, borrowed record or record reservation. ebpf-verify-kptr requires an N-element eight-bit source array and equal-N one-dimensional destination array. Reservation placement follows task.comm: present region only, not absent, after consumption, inside scf.if, or in loop-called subprograms, checked by if_reserved / ownership / call graph. Requirements kfield [N]i8 checks target BTF element width / count; cilium alone does not check array length.

    **Lowering**: Stage ③ core_field_addr locates the field through CO-RE; stage ④ __ebpf_core_addr.<S>.<field> is expanded by ObjectEmitter into llvm.preserve.struct.access.index. Emit N volatile byte loads and byte stores to destination pointer + record-field offset, without helper calls (direct comm-read shape).
    **Embedded paths** (F76): Up to a.b.c, at most three levels, intermediate embedded structs only (no pointer / union / array); leaf retains this op's type rules. Chained CO-RE intrinsics plus format17 path / all-prefix struct:T rows also check intermediate target type names. Unknown blocks load.

    **Evidence**: F23. task->comm 16 bytes match C on three kernels × root / {bpf, perfmon}; reservation destination tests.

    **Unsupported**: Non-record destinations (stack / packet / untyped reservation). N outside 1..64. NUL-terminated probe_read_kernel_str semantics are separate work. Wrong N can silently copy only a prefix or bytes of subsequent fields; only kfield [N]i8 precheck prevents it.
  }];
  let arguments = (ins EBPF_KPtrType:$ptr, StrAttr:$field, AnyTypeOf<[EBPF_BorrowedType, EBPF_ReservationType]>:$dst, StrAttr:$path);
  let extraClassDeclaration = [{
    // Destination record: borrowed pointee or reservation record type; otherwise null.
    ::mlir::ebpf::RecordType getDstRecord();
    // Whether the destination is a ring-buffer reservation, for reservation-use tracking.
    bool writesReservation() { return ::llvm::isa<::mlir::ebpf::ReservationType>(getDst().getType()); }
  }];
  let assemblyFormat =
      "$ptr $field `,` $dst $path attr-dict `:` type($ptr) `,` type($dst)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_KFieldPtrOp : EBPF_Op<"kfield.ptr"> {
  let summary = "Read a nullable kernel-struct pointer field using CO-RE";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads named field declared {kind:kptr,struct:T} from a checked !ebpf.kptr<"S"> or a nonnull owned !ebpf.kref<"S"> (non-consuming, as kfield.load), yielding !ebpf.kptr_or_null<"T">. Uses an eight-byte CO-RE field-offset read, always once. **Result is always nullable**; pointee reads require kptr.check present. The result does not inherit the kref (the verifier gives the walked pointer no ref_obj_id — 7.3.1 verifier.c mark_btf_ld_reg): it stays usable after the kref is released inside the RCU read section, which the compiler does not restrict further.

    **Constraints**: Nonempty field name. ebpf-verify-kptr checks S member points to T; load-time kfield ptr:T checks target BTF pointer-to-struct T.

    **Lowering**: Stage ③ core_field_load yields pointer; ④ marker __ebpf_core.<S>.<field> becomes preserve.struct.access.index plus an eight-byte volatile load. Local member BTF is PTR → struct T.
    **Embedded paths** (F76): Up to three a.b.c levels; intermediate embedded structs only, not pointer / union / array; leaf retains this op's rules. Chained CO-RE and format17 path / all-prefix struct:T rows check intermediate target names. Unknown blocks load.

    **Evidence**: F23. task->real_parent->tgid, task->mm->total_vm, and task->vfork_done (NULL / absent in ordinary fork) match C.

    **Unsupported**: Kernel verifier determines traversed pointer type from base / field: trusted-base __safe_rcu fields can be non-NULL RCU pointers, while unlisted fields use PROBE_MEM (NULL silently reads zero). Compiler does not know that list and always requires a nullable check. No RCU lifetime guarantee or non-struct pointer such as char*.
  }];
  let arguments = (ins AnyTypeOf<[EBPF_KPtrType, EBPF_KRefType]>:$ptr, StrAttr:$field);
  let results = (outs EBPF_KPtrOrNullType:$result);
  let assemblyFormat =
      "$ptr $field attr-dict `:` custom<KFieldPtrBase>(type($ptr)) `->` type($result)";
  let hasVerifier = 1;
  let extraClassDeclaration = [{
    // the base struct of a kptr or kref operand.
    ::llvm::StringRef getBaseStructName() {
      if (auto r = ::llvm::dyn_cast<::mlir::ebpf::KRefType>(getPtr().getType()))
        return r.getStructName();
      return ::llvm::cast<::mlir::ebpf::KPtrType>(getPtr().getType()).getStructName();
    }
  }];
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_KPtrAddrOp : EBPF_Op<"kptr.addr", [Pure]> {
  let summary = "Expose all 64 address bits of a checked kernel pointer as an integer";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Converts checked kptr<"S"> or nonnull kref<"S"> address bits to i64 without reading pointee, acquiring, or consuming a reference. Result is an ordinary integer usable in map keys / values, events, arithmetic, or yield. kref release obligations remain.

    **Constraints**: Only program bodies of tp_btf / fentry / fexit / iter / fmod_ret / fsession. Rejects function / callback / loop placement, direct nullable input, and non-i64 result. S must be declared in schema core.kernel_types (ebpf-verify-kptr).

    **Lowering**: Stage ③ LLVM ptrtoint i64. No helper / new requirement row; format17 / policy15 / caps9 unchanged. Tracing load's CAP_PERFMON requirement and actual verifier enforce pointer-value use with map helpers.

    **Evidence**: F77. Type / placement / ownership controls and request C differential tests.

    **Unsupported**: Integer-to-pointer conversion or direct typed-pointer storage. Addresses correlate live objects but provide no generation identity across free / reuse or ownership. Actual kernel evidence covers fentry kptr only; other five kinds and kref have static controls.
  }];
  let arguments = (ins AnyTypeOf<[EBPF_KPtrType, EBPF_KRefType]>:$ptr);
  let results = (outs I64:$result);
  let assemblyFormat = "$ptr attr-dict `:` type($ptr) `->` type($result)";
  let hasVerifier = 1;
}

def EBPF_KPtrCheckOp : EBPF_Op<"kptr.check", [RecursiveMemoryEffects]> {
  let summary = "Check a nullable kernel pointer and introduce kptr only in the present region";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Executes present with kptr<"S"> argument for non-NULL kptr_or_null<"S">, absent otherwise. Results come from both arms' yields, like ref.check.

    **Constraints**: Present has one kptr with identical S; absent no arguments; both yields match result types. on `!ebpf.rcu_ptr_or_null<"S">` (scx.cpu_curr / scx.dsq_peek / kptr.load_rcu) the present argument is `!ebpf.rcu_ptr<"S">` instead, and neither pointer type may be yielded.

    **Lowering**: Stage ② emits is_present cf.cond_br and true-edge assume_present with merge-block results. Stage ③ compares != NULL and preserves the pointer.

    **Evidence**: F23. 7.1.8 / 6.12.111 × root / {bpf, perfmon, sys_nice}: sched_pi_setprio pi_task present / absent counts and PID match C.

    **Unsupported**: On 6.6.157, and arguments absent from 7.1 / 6.12 raw_tp_null_args tables, verifier may treat arguments as non-NULL and remove the comparison as dead (source-only, runtime unconfirmed). Thus checking does not guarantee runtime safety. arg_nullable gate blocks 6.6.
  }];
  let arguments = (ins AnyTypeOf<[EBPF_KPtrOrNullType, EBPF_RcuPtrOrNullType]>:$ptr);
  let results = (outs Variadic<AnyType>:$results);
  let regions = (region AnyRegion:$presentRegion, AnyRegion:$absentRegion);
  let assemblyFormat = [{
    $ptr attr-dict `:` type($ptr) (`->` type($results)^)?
    `present` $presentRegion `absent` $absentRegion
  }];
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_KfuncCallOp : EBPF_Op<"kfunc.call"> {
  let summary = "Call a named kfunc using UAPI-declared types, flags, and program types";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls a kernel BTF-published function, e.g. bpf_task_from_pid(i32) -> kref_or_null<task_struct>. UAPI kfunc rows define name, signature, flags (KF_ACQUIRE / KF_RELEASE / KF_RET_NULL), and allowed program types. ebpf-abigen generates them from vmlinux FUNC_PROTO and kernel BTF_ID_FLAGS / register_btf_kfunc_id_set, not manual edits. Integer table types match widths. *S arguments accept kref<S> or kptr<S>, except release requires kref and **consumes it**. acquire + ret_null returns kref_or_null checked by kref.check; acquire alone returns kref. void has no result. a bool result is one i1 (the kernel defines only r0's low byte); a KF_RCU kfunc also takes the checked rcu_ptr<S>; a kfunc that neither acquires nor releases takes a T of the UAPI firstmember table (struct T whose offset-0 member is S — bpf_cpumask for cpumask) for *S (btf_struct_ids_match's walk; release and acquire stay strict). A non-NULL acquire result (kref) is used only by kfunc.call, kfield.load and kptr.xchg.

    **Constraints**: Name must exist; flags must be known (acquire / release / ret_null / rcu / implicit_args: the kernel fills the trailing aux, the table row already omits it); argument count / types / result must match. Release requires exactly one *S argument. Pointer results without acquire are rejected (unowned returns unsupported). A memory-region parameter (`*void` followed by `<name>__sz`, e.g. bpf_cpumask_populate) is rejected by name. An rcu_ptr argument to a kfunc without KF_RCU is rejected. Enclosing program type must be listed; the sched_ext kfuncs of ScxContract.def's generic rows (scx_bpf_get_online_cpumask / scx_bpf_put_cpumask / scx_bpf_task_cgroup) are allowed in struct_ops only for sched_ext_ops members (ebpf-verify-schema — scx_kfunc_context_filter of 7.1.8 / 7.3.1). scx_bpf_task_cgroup is rejected outside struct_ops (fentry / tp_btf / syscall — the table registers tracing / syscall, but no task is in kf_tasks there) and in a call no schema member check reaches; it takes only a task argument of the member at a current->scx.kf_tasks position (ScxContract.def EBPF_SCX_TASKARGS — ctx.arg, then kptr.check); any other task (init_task / cgroup_prep_move / cgroup_cancel_move arguments, a field-chased task, scx.cpu_curr) is rejected by name (the kernel fails the scheduler with scx_error on it), and in an ebpf.func it is rejected by name (a function has no member task argument). Only program bodies or ebpf.func bodies: no callback / loop / map.for_each / scf.if / spin.region, which ownership checking does not traverse; in an ebpf.func the ownership closes in the function, and every context that reaches it must allow the call as its owner's body would (ebpf-verify-call-contexts: the program type of every reaching kind, no ebpf.loop / scf.if around a call on the path, the iterator rule for acquire / release through calls, not through a helper callback; also in a sched_ext_ops owner's ebpf.timer.callback body and the functions it reaches, with the owner's program type — scx_bpf_task_cgroup is rejected there; ebpf-verify-schema: the generic sched_ext rows only for sched_ext_ops owners) — the failing context is named. Every kref path must release exactly once; every kref_or_null path must check exactly once. Ownership diagnostics identify missing release / double release / use after release.

    **Lowering**: Stage ③ emits bpfabi.kfunc_call; exit checking validates table and leaves availability as Unknown for load-time loader / verifier. Stage ④ emits llvm.call to extern .ksyms llvm.func. ObjectEmitter attaches DISubprogram declaration with signature and local CO-RE structs for *S; BPF backend emits extern BTF FUNC / FUNC_PROTO / .ksyms DATASEC, call -1 (src_reg1), and R_BPF_64_32 relocation like clang __ksym. Loader resolves kernel BTF ID and rewrites src_reg2. Format13 requirements record each program / reachable subprogram kfunc signature (`*S` becomes ptr:S). Missing or differing target FUNC_PROTO blocks with kfunc_sig, guarding integer width / sign mismatches that loader / verifier may silently accept.

    **Evidence**: F56. Root-stage 7.1.8 syscall test-run retval / maps match C for bpf_task_from_pid / bpf_task_acquire / bpf_task_release.

    **Unsupported**: The table covers bpf_task_from_pid / bpf_task_acquire / bpf_task_release, lowering-only rows and 26 bpf_cpumask_* and 2 scx_bpf_*_cpumask rows (bpf_cpumask_populate is a row but not callable), bpf_cgroup_from_id / bpf_cgroup_release / bpf_cgroup_ancestor / scx_bpf_task_cgroup; later groups add rows. rows are compile only (kernel evidence is); are compile only (kernel evidence is). Unowned pointer returns, unknown flags such as KF_SLEEPABLE, dynptr / iter / variable-length parameters, and krefs passed to or returned from an ebpf.func are excluded. The ebpf.func case is compile only. Availability / flags / signatures vary by kernel; original evidence is 7.1.8 only, not 6.12 / 6.6. Passing kptr such as fentry arguments to KF_RCU is unmeasured.
  }];
  let arguments = (ins StrAttr:$callee, Variadic<AnyType>:$args);
  let results = (outs Variadic<AnyType>:$results);
  let assemblyFormat = "$callee `(` $args `)` attr-dict `:` functional-type($args, $results)";
  let hasVerifier = 1;
}

// Socket references use a dedicated linear type; semantics and constraints
// are described in docs/reference/ebpf_ops.md.
def EBPF_SockMapLookupOp : EBPF_Op<"sock.map_lookup"> {
  let summary = "Acquire an owned socket reference from sockmap or sockhash";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Returns a socket reference acquired by map_lookup_elem; even NULL must pass through sock.ref_check.
    **Constraints**: Only XDP program bodies and ebpf.if / sock.ref_check arms. Key matches map; sockmap key i32, value i32 / i64. Only sock.ref_check may use the unchecked result.
    **Lowering**: Unchanged in ②; ③ calls existing map_lookup_elem(map, &key). Key spill lifetime ends after helper.
    **Evidence**: F61. Type / all-path ownership checks; lookup / release / delete match C in 7.1.8 child-netns TCP pairs.
    **Unsupported**: Field reads, kref conversion, and function / loop / callback placement.
  }];
  let arguments = (ins EBPF_MapType:$map, AnyType:$key);
  let results = (outs EBPF_SockRefOrNullType:$result);
  let assemblyFormat = "$map `[` $key `]` attr-dict `:` type($map) `,` type($key) `->` type($result)";
  let hasVerifier = 1;
}
def EBPF_SockLookupTcpOp : EBPF_Op<"sock.lookup_tcp"> {
  let summary = "Look up a TCP socket by tuple in the current netns, acquiring an owned reference or NULL";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Calls sk_lookup_tcp(ctx, tuple, size, BPF_F_CURRENT_NETNS, 0). NULL means the helper did not return a usable full socket; the cause is not distinguishable. Even NULL must pass through sock.ref_check.
    **Constraints**: Own entry context of an xdp or sched_cls program (OPS sock.lookup), in the program body or ebpf.if / sock.ref_check arms; not in packet.check, loops, callbacks or functions. The tuple is an ebpf.record.make result whose record is exactly the ipv4 (12 B: saddr, daddr u32; sport, dport u16) or ipv6 (36 B: saddr[4], daddr[4] u32; sport, dport u16) view from the UAPI socktuple rows, all unsigned; the size selects the family. Only sock.ref_check may use the result; every path checks it once and releases a present reference once.
    **Lowering**: Unchanged in ②; ③ passes the record.make stack slot without a copy, the declared record size, the UAPI sklookupnetns current_netns value and flags 0. Requirements carry the existing helper rows.
    **Evidence**: Out of scope — no release F row yet; static checks cover it, and a separate run covers it in a VM as root with BPF_PROG_TEST_RUN on 4 kernels (7.3.1, 7.1.8, 6.12.111, 6.6.157), matching an independent C oracle on every cell.
    **Unsupported**: skc_lookup_tcp, other netns values, nonzero flags, field reads of the socket, cgroup_skb / sk_skb and other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, EBPF_RecordType:$tuple);
  let results = (outs EBPF_SockRefOrNullType:$result);
  let assemblyFormat = "$ctx `,` $tuple attr-dict `:` type($ctx) `,` type($tuple) `->` type($result)";
  let hasVerifier = 1;
}
def EBPF_SockLookupUdpOp : EBPF_Op<"sock.lookup_udp"> {
  let summary = "Look up a UDP socket by tuple in the current netns, acquiring an owned reference or NULL";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Calls sk_lookup_udp(ctx, tuple, size, BPF_F_CURRENT_NETNS, 0). NULL means the helper did not return a usable full socket; the cause is not distinguishable. Even NULL must pass through sock.ref_check.
    **Constraints**: The same as ebpf.sock.lookup_tcp: own entry context of an xdp or sched_cls program (OPS sock.lookup), in the program body or ebpf.if / sock.ref_check arms, a record.make tuple that is exactly the UAPI ipv4 or ipv6 view, and the linear check / release ownership.
    **Lowering**: Unchanged in ②; ③ passes the record.make stack slot without a copy, the declared record size, the UAPI sklookupnetns current_netns value and flags 0. Requirements carry the existing helper rows.
    **Evidence**: Out of scope — no release F row yet; static checks cover it, and a separate run covers it in a VM as root with BPF_PROG_TEST_RUN on 4 kernels (7.3.1, 7.1.8, 6.12.111, 6.6.157), matching an independent C oracle on every cell.
    **Unsupported**: Other netns values, nonzero flags, field reads of the socket, cgroup_skb / sk_skb and other kinds.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, EBPF_RecordType:$tuple);
  let results = (outs EBPF_SockRefOrNullType:$result);
  let assemblyFormat = "$ctx `,` $tuple attr-dict `:` type($ctx) `,` type($tuple) `->` type($result)";
  let hasVerifier = 1;
}
def EBPF_SockSkcLookupTcpOp : EBPF_Op<"sock.skc_lookup_tcp"> {
  let summary = "Look up a TCP socket (including TIME_WAIT) by tuple in the current netns, acquiring an owned reference or NULL";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls skc_lookup_tcp(ctx, tuple, size, BPF_F_CURRENT_NETNS, 0). The kernel result is PTR_TO_SOCK_COMMON (`RET_PTR_TO_SOCK_COMMON_OR_NULL`), not PTR_TO_SOCKET: unlike sock.lookup_tcp it returns a TCP_TIME_WAIT minisock (sock.lookup_tcp converts through sk_to_full_sk and gets NULL); a TCP_NEW_SYN_RECV request socket is returned as is (sock.lookup_tcp gets its rsk_listener). NULL means no socket was found; the cause is not distinguishable. Even NULL must pass through sock.ref_check.

    **Constraints**: The same as ebpf.sock.lookup_tcp: own entry context of an xdp or sched_cls program (OPS sock.lookup), program body or ebpf.if / sock.ref_check arms, a record.make tuple that is exactly the UAPI ipv4 or ipv6 view, the linear check / release ownership. The result type is the shared !ebpf.sock_ref_or_null, so the only use of a present reference is sock.release (bpf_sk_release takes PTR_TO_SOCK_COMMON | OBJ_RELEASE on the four kernels); there are no socket field reads. The result cannot reach sk.assign (sk_lookup kind only, which has no sock.lookup).

    **Lowering**: Unchanged in ②; ③ passes the record.make stack slot without a copy, the declared record size, the UAPI sklookupnetns current_netns value and flags 0 to helper skc_lookup_tcp. Requirements carry the existing helper rows.

    **Evidence**: Out of scope — no release F row yet; static checks cover it, and it was also run in a VM as root with BPF_PROG_TEST_RUN on 4 kernels (7.3.1, 7.1.8, 6.12.111, 6.6.157): skc_lookup_tcp returns a TIME_WAIT minisock where sk_lookup_tcp returns NULL, the other cells agree, and C and MLIR match on every cell.

    **Unsupported**: Field reads of the socket (a future P that adds them must split the type), other netns values, nonzero flags, cgroup_skb / sk_skb / cgroup_sock_addr kinds, and SYN_RECV behaviour is unmeasured.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, EBPF_RecordType:$tuple);
  let results = (outs EBPF_SockRefOrNullType:$result);
  let assemblyFormat = "$ctx `,` $tuple attr-dict `:` type($ctx) `,` type($tuple) `->` type($result)";
  let hasVerifier = 1;
}
def EBPF_SockRefCheckOp : EBPF_Op<"sock.ref_check", [RecursiveMemoryEffects]> {
  let summary = "Check a nullable socket and pass an owned reference to the present region";
  let description = [{
    **Stage**: ① Input
    **Meaning**: NULL executes absent; non-NULL executes present. Both arms may yield scalars. NULL is not released.
    **Constraints**: Single-block regions; present has one sock_ref argument, absent none. Ownership checking requires exactly one release on every present path. Reference cannot escape.
    **Lowering**: Stage ② is_present plus true-edge assume_present; ③ same pointer and NULL branch.
    **Evidence**: F61. NULL / present all-path ownership checks and C agreement in 7.1.8 child netns.
    **Unsupported**: Reference yield / call / loop capture.
  }];
  let arguments = (ins EBPF_SockRefOrNullType:$ptr);
  let results = (outs Variadic<AnyType>:$results);
  let regions = (region SizedRegion<1>:$presentRegion, SizedRegion<1>:$absentRegion);
  let assemblyFormat = [{
    $ptr attr-dict `:` type($ptr) (`->` type($results)^)?
    `present` $presentRegion `absent` $absentRegion
  }];
  let hasVerifier = 1;
}
def EBPF_SkAssignOp : EBPF_Op<"sk.assign"> {
  let summary = "Select a checked socket as an sk_lookup result, returning raw bpf_sk_assign status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Calls sk_assign(ctx, sk, flags) using the sk_lookup bpf_sk_lookup_assign prototype to select a sock.map_lookup-acquired socket. Raw status 0 selects it; negative errno leaves previous selection unchanged: invalid flags −EINVAL; refcounted sockets, non-LISTEN TCP, or non-CLOSE UDP −ESOCKTNOSUPPORT; protocol mismatch −EPROTOTYPE; family mismatch −EAFNOSUPPORT; already selected without replace −EEXIST (net/core/filter.c, same on three kernels). Selection becomes the lookup result only for SK_PASS; destination address / port are unchanged. replace replaces earlier selection; no_reuseport skips reselecting within the chosen socket's reuseport group.

    **Constraints**: Own sk_lookup body entry context with OPS sk.assign. Socket is sock.ref_check present sock_ref (assume_present at ②). **Nonconsuming use**, permitted only before release; ownership checking rejects post-release use and separately requires exactly one release on every path. No NULL deselection form.

    **Lowering**: Unchanged in ②; stage ③ calls sk_assign(ctx, sock, flags), ORing UAPI sklookupflag replace / no_reuseport, or 0 if absent. i64 result.

    **Evidence**: F61. Three-kernel test-run ctx_out cookies / status for eight arms compared to C, plus actual netns-link dispatch.

    **Unsupported**: NULL deselection, ctx sk reads, and other kinds (TC bpf_sk_assign has another prototype).
  }];
  let arguments = (ins EBPF_ContextType:$ctx, EBPF_SockRefType:$sock, UnitAttr:$replace, UnitAttr:$no_reuseport);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $sock (`replace` $replace^)? (`no_reuseport` $no_reuseport^)? attr-dict `:` type($ctx) `,` type($sock) `->` type($status)";
  let hasVerifier = 1;
}
def EBPF_SockReleaseOp : EBPF_Op<"sock.release"> {
  let summary = "Return an acquired socket reference with sk_release";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Releases a checked socket exactly once on every path; later use is rejected.
    **Constraints**: Only sock_ref from sock.ref_check present.
    **Lowering**: Unchanged in ②; ③ calls sk_release(socket), ignoring return.
    **Evidence**: F61. Present-path single-release checks and C agreement in 7.1.8 child netns; no release on NULL paths.
    **Unsupported**: NULL / kref / kptr inputs.
  }];
  let arguments = (ins EBPF_SockRefType:$ptr);
  let assemblyFormat = "$ptr attr-dict `:` type($ptr)";
  let hasVerifier = 1;
}
def EBPF_DevmapLookupOp : EBPF_Op<"devmap.lookup"> {
  let summary = "Read devmap_hash ifindex and presence";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Present key yields (ifindex, true); NULL yields (0, false).
    **Constraints**: XDP program body; devmap_hash with i32 key / value. No pointer result.
    **Lowering**: Unchanged in ②; ③ calls map_lookup_elem and branches on NULL, reading u32 ifindex only when non-NULL.
    **Evidence**: F60. 7.1.8 child-netns veth ifindex / missing results match C.
    **Unsupported**: devmap, eight-byte values, and entry write / atomic / delete.
  }];
  let arguments = (ins EBPF_MapType:$map, AnyType:$key);
  let results = (outs I32:$ifindex, I1:$present);
  let assemblyFormat = "$map `[` $key `]` attr-dict `:` type($map) `,` type($key) `->` type($ifindex) `,` type($present)";
  let hasVerifier = 1;
}
def EBPF_XskLookupOp : EBPF_Op<"xsk.lookup"> {
  let summary = "Test socket presence in xskmap";
  let description = [{
    **Stage**: ① Input
    **Meaning**: True for non-NULL lookup. Does not read fd or an ordinary map value.
    **Constraints**: XDP program body, xskmap with i32 key / value.
    **Lowering**: Unchanged in ②; ③ compares map_lookup_elem result against NULL without dereferencing PTR_TO_XDP_SOCK.
    **Evidence**: F60. 7.1.8 child-netns AF_XDP present / missing / out-of-range match C.
    **Unsupported**: queue_id reads and entry write / atomic / delete.
  }];
  let arguments = (ins EBPF_MapType:$map, AnyType:$key);
  let results = (outs I1:$present);
  let assemblyFormat = "$map `[` $key `]` attr-dict `:` type($map) `,` type($key) `->` type($present)";
  let hasVerifier = 1;
}

def EBPF_KRefCheckOp : EBPF_Op<"kref.check", [RecursiveMemoryEffects]> {
  let summary = "Check a nullable kfunc-acquired reference and introduce an owned kref in present";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Non-NULL kref_or_null<S> executes present with owned kref<S>; NULL executes absent. Results come from both arm yields, like kptr.check. Each present path must transfer the reference exactly once to a release kfunc or kptr.xchg (map ownership). Absent holds no reference; NULL is not released.

    **Constraints**: Present has one kref with identical S; absent none; yields match result types without kref escape. kref uses are kfunc.call, kfield.load, and the new-reference operand of kptr.xchg. Each arm ends with ebpf.yield, or ebpf.break / ebpf.continue when the nearest loop is ebpf.iter.scx_dsq — the present reference must be released before it, and both arms escaping allows no results.

    **Lowering**: Stage ② emits is_present cf.cond_br / true-edge assume_present and merge arguments. Stage ③ compares != NULL and preserves the pointer.

    **Evidence**: F56. Acquired-reference ownership tests.

    **Unsupported**: Reference transport outside the region, into functions (as arguments) or loops; ownership checking is region-local (a kref.check in an ebpf.func body checks a reference the function took itself).
  }];
  let arguments = (ins EBPF_KRefOrNullType:$ptr);
  let results = (outs Variadic<AnyType>:$results);
  let regions = (region AnyRegion:$presentRegion, AnyRegion:$absentRegion);
  let assemblyFormat = [{
    $ptr attr-dict `:` type($ptr) (`->` type($results)^)?
    `present` $presentRegion `absent` $absentRegion
  }];
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_KPtrXchgOp : EBPF_Op<"kptr.xchg"> {
  let summary = "Exchange an owned reference with a map-record kptr field (bpf_kptr_xchg helper194)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Installs a new reference into a schema kptr field (BTF PTR → TYPE_TAG kptr → STRUCT T), returning the old reference as kref_or_null<T>. The null form empties the field and returns its reference. **New-reference ownership transfers to the map**, consuming it like release; later use is rejected. The program owns the returned reference and must check it exactly once, then release or transfer its present kref exactly once. Kernel dtors release references left in maps on element deletion, userspace update, or map destruction.

    **Constraints**: Destination is checked borrowed record; new value is acquired kref<T> or null, not kptr / unchecked kref_or_null. Result is kref_or_null<T> with exactly one kref.check use. Program-body placement only, as with kfunc.call: no callback / loop / map.for_each / scf.if / spin.region; also an ebpf.func body (the map value looked up in the function — a function's reference argument cannot reach it), with kfunc.call's per-context rules. Record checking requires nonempty dotted record_ref path of depth ≤ 3 (e.g. in.t), no array indices, matching kptr leaf T, and each / cumulative offset divisible by8. T must be @kernel struct / schema core.kernel_types. Ownership checks every-path new-reference consumption and one result check. Direct kptr-field ref.field.load / store / atomic_add / ref.index are rejected, as is record.make of kptr-bearing records or nested parents; kernel forbids direct stores.

    **Lowering**: Unchanged in ②. Stage ③ calls UAPI kptr_xchg (194) with field pointer + @records offset and new pointer (null is0). Nullable result is checked by kref.check expansion. Requirements include helper kptr_xchg, btf type_tag (format13), and map value record:S.

    **Evidence**: F69. kptr exchange and ownership tests.

    **Unsupported**: kptr_untrusted, direct RCU field reads, percpu_kptr, and arrays of kptr / kptr-bearing records. Ordinary kptr compiles in ten hash / array / per-CPU / LRU / local-storage value kinds and nested record_ref; runtime evidence for extended placement belongs to its dedicated experiment. 6.6 source does not search nested fields: successful map creation alone cannot establish xchg acceptance. Compiler does not check a type has a dtor; kernel rejects map creation otherwise, and cilium may retry without BTF, after which xchg program load fails explicitly.
  }];
  let arguments = (ins AnyType:$ref, StrAttr:$field, Optional<EBPF_KRefType>:$newRef);
  let results = (outs EBPF_KRefOrNullType:$old);
  let assemblyFormat = [{
    $ref $field `,` ($newRef^):(`null`)? attr-dict `:` type($ref) (`,` type($newRef)^)? `->` type($old)
  }];
  let hasVerifier = 1;
}

def EBPF_KPtrLoadRcuOp : EBPF_Op<"kptr.load_rcu"> {
  let summary = "Read a map-record kptr field as an RCU pointer (bpf_cpumask only)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads the schema kptr field (BTF PTR → TYPE_TAG kptr → STRUCT S) of a checked map value record without taking ownership. The verifier marks the loaded register MEM_RCU | PTR_MAYBE_NULL when S is in rcu_protected_types (bpf_cpumask is in it in 6.6.157 / 6.12.111 / 7.1.8 / 7.3.1) and the load is in the RCU read section: an RCU lock is held, or the program is not sleepable (in_rcu_cs). Outside the section a sleepable program reads it untrusted. The result is `!ebpf.rcu_ptr_or_null<"S">`; check it with ebpf.kptr.check, whose present `!ebpf.rcu_ptr<"S">` reaches only KF_RCU kfunc.call arguments (the bpf_cpumask read kfuncs).

    **Constraints**: The record is a checked borrow (the block argument of ebpf.ref.check). The field path follows kptr.xchg: a non-empty dotted path of at most 3 record fields, no array indices, with a kptr leaf of struct S (ebpf-verify-records). **S is bpf_cpumask only** (the compiler's capability; other rcu_protected_types are rejected by name). Placement: an ebpf.program body, an ebpf.func body or a sched_ext_ops owner's ebpf.timer.callback body (also inside ebpf.if, ref.check, kptr.check, ebpf.iter.num, ebpf.rcu.region); rejected in other callbacks, ebpf.loop, map.for_each, spin.region and scf.if. In an ebpf.func every reaching context is checked as its owner's body (ebpf-verify-call-contexts / ebpf-verify-schema: the sleepable rule below with the call path's ebpf.rcu.region — counted only through static calls, a global function needs its own region — no ebpf.loop / scf.if / ebpf.iter.scx_dsq around a call on the path, not through a helper callback). In a timer callback context (the callback body and the functions it reaches) it must be inside a held ebpf.rcu.region (the callback assumes no RCU). In a sleepable program — a kind with the OPS tag `sleepable` (syscall, lsm_s) or a struct_ops member declared sleepable (ebpf-verify-schema) — it must be inside ebpf.rcu.region. The result is used only by one ebpf.kptr.check; rcu_ptr values are not yielded, captured, stored, passed to calls, released or exchanged.

    **Lowering**: Unchanged in ②. Stage ③ is one volatile 8-byte load at the field's @records offset (not split, not merged). No requirements row of its own; the map value kptr keeps the format-13 `btf type_tag` row.

    **Evidence**: Out of scope — kernel evidence: compile only (lit, ELF compare with the C arm); a separate VM run covers it.

    **Unsupported**: Struct types other than bpf_cpumask, arrays of kptr, percpu_kptr, and kptr fields of local storage or nested maps beyond kptr.xchg's placements. The compiler does not take an RCU lock implicitly.
  }];
  let arguments = (ins AnyType:$ref, StrAttr:$field);
  let results = (outs EBPF_RcuPtrOrNullType:$ptr);
  let assemblyFormat = [{
    $ref $field attr-dict `:` type($ref) `->` type($ptr)
  }];
  let hasVerifier = 1;
}

def EBPF_GlobalKPtrXchgOp : EBPF_Op<"global.kptr_xchg"> {
  let summary = "Exchange an owned reference with a kptr global (bpf_kptr_xchg helper194, bpf_cpumask only)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Installs a new reference into a schema core.globals kptr (section "data:<name>" — the hidden C private(name) global, BTF PTR → TYPE_TAG kptr → STRUCT bpf_cpumask in the .data.<name> DATASEC), returning the old reference as kref_or_null<"bpf_cpumask">. The null form empties the global and returns its reference. Ownership is that of ebpf.kptr.xchg: the new reference transfers to the global's map, consuming it like release, and later use is rejected; the program checks the returned reference exactly once, then releases or transfers its present kref exactly once. The verifier treats the global's address (BPF_PSEUDO_MAP_VALUE) as the PTR_TO_MAP_VALUE of a lookup, with the kptr in the map's record built from the DATASEC VAR.

    **Constraints**: @name is a core.globals entry with "section": "data:<name>" and a kptr type of struct bpf_cpumask (ebpf-verify-schema; other structs are rejected by the schema). New value is an acquired kref<"bpf_cpumask"> or null. Result is kref_or_null<"bpf_cpumask"> with exactly one kref.check use. Placement and ownership follow ebpf.kptr.xchg: an ebpf.program body or an ebpf.func body with kfunc.call's per-context rules (also ebpf.if, ref.check, kref.check / kptr.check, and an ebpf.rcu.region inside ebpf.iter.num with no iterator or loop in between); rejected in callbacks, ebpf.loop, map.for_each, spin.region and scf.if. A kptr global cannot be read by global.load or written by global.store / global.atomic_add.

    **Lowering**: Unchanged in ②. Stage ③ calls UAPI kptr_xchg (194) with the global's address (an addressof of the placeholder llvm.mlir.global marked ebpf.global) and the new pointer (null is 0). BTFToLLVMDI places the global in .data.<name> with hidden visibility (8-byte, zero-initialized). Requirements include helper kptr_xchg, btf type_tag (format 13) and datakptr .data.<name> (format 23 — the loader declaration hidden_data_vars).

    **Evidence**: Out of scope — kernel evidence: (static ELF / BTF compare with the C private() arm, offline precheck, and the host cilium load of a syscall program).

    **Unsupported**: Struct types other than bpf_cpumask, kptr arrays, percpu_kptr, kptr_untrusted, and kptr globals in rodata / bss / data sections.
  }];
  let arguments = (ins FlatSymbolRefAttr:$name, Optional<EBPF_KRefType>:$newRef);
  let results = (outs EBPF_KRefOrNullType:$old);
  let assemblyFormat = [{
    $name `,` ($newRef^ `:` type($newRef)):(`null`)? attr-dict `->` type($old)
  }];
  let hasVerifier = 1;
}

def EBPF_GlobalKPtrLoadRcuOp : EBPF_Op<"global.kptr_load_rcu"> {
  let summary = "Read a kptr global as an RCU pointer (bpf_cpumask only)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads a schema core.globals kptr (section "data:<name>") without taking ownership, like ebpf.kptr.load_rcu reads a map value's kptr field: the verifier marks the loaded register MEM_RCU | PTR_MAYBE_NULL in the RCU read section (bpf_cpumask is in rcu_protected_types in 6.6.157 / 6.12.111 / 7.1.8 / 7.3.1). The result is `!ebpf.rcu_ptr_or_null<"bpf_cpumask">`; check it with ebpf.kptr.check, whose present `!ebpf.rcu_ptr<"bpf_cpumask">` reaches only KF_RCU kfunc.call arguments.

    **Constraints**: @name is a core.globals kptr of struct bpf_cpumask (ebpf-verify-schema). Placement follows ebpf.kptr.load_rcu: an ebpf.program body or an ebpf.func body checked per reaching context (also inside ebpf.if, ref.check, kptr.check, ebpf.iter.num, ebpf.rcu.region); rejected in callbacks, ebpf.loop, map.for_each, spin.region and scf.if. In a sleepable program (a kind with the OPS tag `sleepable`, or a struct_ops member declared sleepable — ebpf-verify-schema) it must be inside ebpf.rcu.region. The result is used only by one ebpf.kptr.check.

    **Lowering**: Unchanged in ②. Stage ③ is one volatile 8-byte load of the global's address (not split, not merged). Requirements are those of the global (btf type_tag, datakptr).

    **Evidence**: Out of scope — kernel evidence: (static compare and the host cilium load of a syscall program).

    **Unsupported**: Struct types other than bpf_cpumask. The compiler does not take an RCU lock implicitly.
  }];
  let arguments = (ins FlatSymbolRefAttr:$name);
  let results = (outs EBPF_RcuPtrOrNullType:$ptr);
  let assemblyFormat = "$name attr-dict `:` type($ptr)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_KFieldLoadOp : EBPF_Op<"kfield.load"> {
  let summary = "Read a kernel-struct field with CO-RE";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads named field through kptr<S>, checked kfunc-acquired kref<S> or the checked rcu_ptr<S> of scx.cpu_curr / scx.dsq_peek. Borrowed read does not consume the reference. Field-byte-offset relocation is resolved against target BTF at load. **Always once**: one volatile load per occurrence, never merged. Treated as effectful.

    **Constraints**: Nonempty field; result i8 / i16 / i32 / i64. S is btf.scope @kernel struct from schema core.kernel_types. Local fields are little-endian integers with naturally aligned placeholder offsets in declaration order. ebpf-verify-kptr checks member presence / width. Load-time kfield iN|uN checks target BTF. kfield_unknown also blocks (policy2); caps lacking KernelTypes, e.g. bpftool-recorded ebpf-target, stop CO-RE ELF loads.

    **Lowering**: Stage ③ core_field_load has no offset and is Conditional. Stage-④ marker __ebpf_core.S.field becomes preserve.struct.access.index plus volatile declared-width B / H / W / DW load. Only CO-RE modules run the BPF backend PipelineStartEP pass.
    **Embedded paths** (F76): Up to three a.b.c levels; intermediate embedded structs only, no pointer / union / array. Leaf retains existing type rules. Chained CO-RE plus format17 path / prefix struct:T rows check intermediate names. Unknown blocks load.

    **Evidence**: F23, F49, F56. CO-RE relocation / offline oracle; load checks; @kernel validation; always-once correction after merged loads; 8 / 16 / 64-bit C agreement per fork on three kernels × root / {bpf, perfmon} with kernel/cmd/kfieldcheck; kref pid / tgid; 6.12.111 VM sched_ext_ops.tick task_struct.tgid with a compiler callback composed into a C donor (composition only in runner).

    **Unsupported**: Bitfields / unions. Pointer fields use kfield.ptr; eight-bit arrays use kfield.copy; neither accepts kref in the original acquired-reference extension. No loop bodies. cilium CO-RE poisons missing fields instead of reporting errors, and **does not rewrite load width or check width / sign**. Narrow declarations such as u32 for target u64 can pass verifier and silently read low bits; wider reads fail access beyond the end of member. Only kfield precheck guards correct width / sign.
  }];
  let arguments = (ins AnyTypeOf<[EBPF_KPtrType, EBPF_KRefType, EBPF_RcuPtrType]>:$ptr, StrAttr:$field);
  let results = (outs AnySignlessInteger:$result);
  let assemblyFormat =
      "$ptr $field attr-dict `:` type($ptr) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_KFieldStoreOp : EBPF_Op<"kfield.store"> {
  let summary = "Store a kernel-struct integer field with CO-RE (struct_ops only)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: The write counterpart of kfield.load: one volatile declared-width store at the relocated field address through kptr<S>. No result.

    **Constraints**: Nonempty field, i8 / i16 / i32 / i64 value, enclosing kind with OPS kfield.store (struct_ops only). Kernel allows BTF-pointer writes only where program-type btf_struct_access permits; tracing is rejected. kptr checking requires @kernel S with a matching-width integer member, not array / pointer. Requirements kfield iN|uN check target BTF as for reads. **Kernel decides writable fields**: tcp_congestion_ops bpf_tcp_ca_btf_struct_access permits selected tcp_sock fields such as snd_cwnd / snd_cwnd_cnt / snd_cwnd_stamp / snd_ssthresh / ecn_flags; others fail verifier. Compiler has no list.

    **Lowering**: Stage ③ core_field_addr, stage-④ __ebpf_core_addr.S.field expanded by ObjectEmitter to preserve.struct.access.index, then a volatile declared-width store. Integer-field kfield requirements match reads.

    **Evidence**: F49. 7.1.8 Reno-style tcp_congestion_ops cong_avoid writes snd_cwnd / snd_cwnd_cnt; netns client cwnd grows as with C.

    **Unsupported**: Non-struct_ops (tracing BTF pointers read-only), bitfields / arrays / pointer fields. 6.12 / 6.6 unverified.
  }];
  let arguments = (ins EBPF_KPtrType:$ptr, StrAttr:$field, AnyTypeOf<[I8, I16, I32, I64]>:$value);
  let assemblyFormat =
      "$ptr $field `,` $value attr-dict `:` type($ptr) `,` type($value)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_ByteorderToBeOp : EBPF_Op<"byteorder.to_be", [AllTypesMatch<["value", "result"]>]> {
  let summary = "Convert a CPU-order little-endian integer to big-endian byte order";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Explicit byte swap to big-endian order. Schema integers are little-endian; network order is explicit through this op, not an implicit type-name rule.

    **Constraints**: Width i16 / i32 / i64 (BPF_END widths); input / result types match (AllTypesMatch). Allowed in loops.

    **Lowering**: bpfel only; stage ③ llvm.intr.bswap becomes BPF_END be16 / be32 / be64. Same instruction as from_be.

    **Evidence**: F19. C bpf_htons / htonl value agreement, packet→key differential tests, three targets.

    **Unsupported**: i8 and widths outside 16 / 32 / 64, including i1 / i24 / i128; big-endian target.
  }];
  let arguments = (ins AnySignlessInteger:$value);
  let results = (outs AnySignlessInteger:$result);
  let assemblyFormat = "$value attr-dict `:` type($value)";
  let hasVerifier = 1;
}

def EBPF_ByteorderFromBeOp : EBPF_Op<"byteorder.from_be", [AllTypesMatch<["value", "result"]>]> {
  let summary = "Convert a big-endian integer byte sequence to CPU-order little endian";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Explicitly swaps a network-order value, such as one read by packet.load, into CPU little-endian order.

    **Constraints**: Width i16 / i32 / i64; matching input / result types. Allowed in loops.

    **Lowering**: Stage ③ llvm.intr.bswap, same as to_be for bpfel; BPF backend emits BPF_END.

    **Evidence**: F19. packet→key agrees with C bpf_ntohs / ntohl; removing conversion gives wrong key; three targets.

    **Unsupported**: i8 and widths outside 16 / 32 / 64; big-endian target.
  }];
  let arguments = (ins AnySignlessInteger:$value);
  let results = (outs AnySignlessInteger:$result);
  let assemblyFormat = "$value attr-dict `:` type($value)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_TaskPidTgidOp : EBPF_Op<"task.pid_tgid"> {
  let summary = "Raw bpf_get_current_pid_tgid() value (tgid << 32 | pid)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Returns raw i64 helper value: high32 tgid (process), low32 pid (thread).

    **Constraints**: No op verifier. Compile time does not restrict kinds; load-time requirements helper checks determine availability for program type. Allowed in loops / subprograms.

    **Lowering**: Stage ③ calls UAPI get_current_pid_tgid.

    **Evidence**: F21. C oracle; per-tgid count agreement; three-target / non-root; ring events.

    **Unsupported**: Separate PID / TGID operations (caller shifts / truncates). Timer callbacks permit only ktime.ns among ordinary helpers.
  }];
  let results = (outs I64:$result);
  let assemblyFormat = "attr-dict `:` type($result)";
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_TaskUnderCgroupOp : EBPF_Op<"task.under_cgroup"> {
  let summary = "Compare current-task ancestry to a cgroup_array slot, returning raw status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Raw i64 current_task_under_cgroup(map, index): 1 for current task cgroup-v2 membership / descendant, 0 otherwise, -EAGAIN for empty slot, -E2BIG for out-of-range index. Not reduced to bool.

    **Constraints**: cgroup_array i32 / i32, i32 index interpreted u32. Userspace supplies cgroup fds. Helper availability follows requirements / load verifier. Allowed in loops / static subprograms.

    **Lowering**: Unchanged in ②; ③ zero-extends index and calls UAPI helper, retaining i64 result.

    **Evidence**: F70. 7.1.8 root C/ebpf: same / descendant1, sibling0, deleted / empty -EAGAIN, out-of-range / negative index -E2BIG. Untyped map BTF and program BTF accepted. Non-root compile / precheck and mutation controls; kernel helpers.c source.

    **Unsupported**: cgroup-v1, timer.callback, other-kind helper runtime acceptance, non-root runtime, and 6.12 / 6.6 measurements. Generic cgroup_array map.* rejected.
  }];
  let arguments = (ins EBPF_MapType:$map, I32:$index);
  let results = (outs I64:$status);
  let assemblyFormat = "$map `[` $index `]` attr-dict `:` type($map) `,` type($index) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_SkbUnderCgroupOp : EBPF_Op<"skb.under_cgroup"> {
  let summary = "Compare skb socket ancestry to a cgroup_array slot (sched_cls; raw status)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Raw i64 skb_under_cgroup(ctx, map, index): 1 if full-socket owner belongs to the slot cgroup or descendant, 0 otherwise. No full socket gives -ENOENT before index -E2BIG / empty -EAGAIN checks. This concerns socket owner, not current-task cgroup.

    **Constraints**: Own sched_cls entry ctx, cgroup_array i32 / i32, i32 index as u32. Callee context rejected.

    **Lowering**: Unchanged in ②; ③ zero-extends index and calls UAPI helper, retaining i64.

    **Evidence**: F70. 7.1.8 root child-netns loopback egress matches C for ancestry1 / 0, including different sender / owner. Empty -EAGAIN, out-of-range / negative -E2BIG; synthetic TEST_RUN dummy full socket checked. Untyped map / program BTF accepted; net/core/filter.c source.

    **Unsupported**: Other kinds such as LWT_OUT, cgroup-v1, timer.callback, 6.12 / 6.6, actual non-root. True NULL / non-full-socket -ENOENT unmeasured: initial TEST_RUN no-full prediction was unsupported. Do not reinterpret missing full socket as false. Generic cgroup_array map.* rejected.
  }];
  let arguments = (ins EBPF_ContextType:$ctx, EBPF_MapType:$map, I32:$index);
  let results = (outs I64:$status);
  let assemblyFormat = "$ctx `,` $map `[` $index `]` attr-dict `:` type($ctx) `,` type($map) `,` type($index) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_TaskCgroupIdOp : EBPF_Op<"task.cgroup_id"> {
  let summary = "Raw bpf_get_current_cgroup_id() value for the current task's cgroup v2";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Returns i64 current-task default-hierarchy cgroup ID (directory inode number; cgroup_id(task_dfl_cgroup(current))).

    **Constraints**: No op verifier. Like task.pid_tgid, compile time does not restrict kinds; requirements helper rows check availability at load. CONFIG_CGROUPS absence removes the helper. Allowed in loops / subprograms.

    **Lowering**: Stage ③ calls UAPI get_current_cgroup_id.

    **Evidence**: F42. Actual 7.1.8 LSM attach matches C, rejecting socket(2) only in own child cgroup with matching ID; outside / different / unset IDs do not reject.

    **Unsupported**: Ancestor-cgroup ID helper, cgroup-v1 IDs, and timer callbacks (ordinary helper set limited to ktime.ns).
  }];
  let results = (outs I64:$result);
  let assemblyFormat = "attr-dict `:` type($result)";
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_GlobalLoadOp : EBPF_Op<"global.load"> {
  let summary = "Read a schema core.globals variable";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads a named integer global in rodata or bss. Volatile, like C const volatile, prevents assuming its value. ELF symbols determine byte positions; compiler does not calculate layout. Loader sets / freezes rodata before load; verifier tracks the configured value as constant. : a bss kaddr global (`{"kind": "kaddr", "struct": S}`) reads as an untrusted !ebpf.kaddr<"S"> (a scalar to the verifier — C's `static struct S *g`).

    **Constraints**: The op verifier confines a !ebpf.kaddr<"S"> result (a bss kaddr global) to the kaddr ops and global.store, like other untrusted kernel addresses. ebpf-verify-schema checks declared name / width in **both program and function bodies**; older behavior missed functions. No timer.callback; allowed in loops. Schema rejects map / program name collisions; stage ③ rejects other symbol collisions.

    **Lowering**: Stage ③ emits addressof of a placeholder llvm.mlir.global marked ebpf.global and a volatile load aligned to width/8. BuildBTF creates btf.var in .rodata / .bss DATASEC. No helper.

    **Evidence**: F26. C oracle; rodata configuration; three-target DATASEC / CheckGlobals (cilium replaces zero-size DATASEC offsets from symbols and does not inspect VAR type); function-body validation.

    **Unsupported**: Record / array globals (borrowed with ebpf.global.ref instead), kaddr globals outside bss and a void kaddr, .data, and post-load rodata updates. Go LoadObjectsWithRodata configures before load.
  }];
  let arguments = (ins FlatSymbolRefAttr:$name);
  let results = (outs AnyTypeOf<[AnySignlessInteger, EBPF_KAddrType]>:$result);
  let hasVerifier = 1;
  let assemblyFormat = "$name attr-dict `:` type($result)";
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_GlobalStoreOp : EBPF_Op<"global.store"> {
  let summary = "Store to a schema core.globals bss integer variable";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Stores value once to a named integer .bss global (a volatile store of the declared width, like global.load — each occurrence is one access, never merged). Not atomic and not a synchronization: concurrent stores race as in C (scx_simple's vtime_now update is racy in C too). : a !ebpf.kaddr<"S"> value is stored to a bss kaddr global of the same S (8 bytes).

    **Constraints**: Value width equals the declared width (no implicit extension). Schema checks name / width / section in **both program and function bodies** (like global.load): .rodata is frozen after load and rejected by name, a .data record global is not an integer and rejected by name, an undeclared name is rejected. No timer.callback; loops allowed. Not in the packet-neutral table (an op outside the table stops C1 / W1, the safe side).

    **Lowering**: Stage ③ emits addressof of the placeholder llvm.mlir.global marked ebpf.global and a volatile store aligned to width/8. No helper.

    **Evidence**: Out of scope — release evidence: no F id yet. Static: lit for ③ store, schema negatives (rodata / width / undeclared / data record), opcheck host row (global-store — load acceptance only on the host, run by the B0 root smoke; opcheck does not test-run the program or compare the stored value — corrected, the stored value is not verified on a kernel).

    **Unsupported**: rodata and .data stores, atomic or ordered stores (use global.atomic_add for a counter), stores narrower or wider than the declaration.
  }];
  let arguments = (ins FlatSymbolRefAttr:$name, AnyTypeOf<[AnySignlessInteger, EBPF_KAddrType]>:$value);
  let assemblyFormat = "$name `,` $value attr-dict `:` type($value)";
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_GlobalRefOp : EBPF_Op<"global.ref", [Pure]> {
  let summary = "Borrow a schema core.globals rodata / bss record global";
  let description = [{
    **Stage**: ① Input

    **Meaning**: `%r = ebpf.global.ref @g : !ebpf.borrowed<!ebpf.record<"S", N>>` borrows a record global of .rodata or .bss (C's struct and array globals — an array global is a one-field record) so the existing ref ops read and write it: ref.field.load / store (normal or once), ref.field.atomic_add, ref.index (integer elements, and record elements as a borrowed record), and calls to functions taking a borrowed record. The address is always valid (an ELF data section), so there is no null check. Field offsets come from @records; the compiler does not compute layout.

    **Constraints**: The op verifier requires a borrowed record. Allowed in an ebpf.loop (B / U) and ebpf.iter.num body, borrowed in each iteration (a borrow from outside is not captured — the loop capture rule); rejected in a callback loop (H) — directly in its body or in any ebpf.func reached through its calls, named by the call path — and in ebpf.map.for_each. ebpf-verify-schema requires a declared rodata / bss record global of the same record and size (a .data record is written only by scx.exit_info), in program and function bodies. A .rodata borrow is read-only (frozen after load): stores, atomics and kptr.xchg through it, through ref.index elements and element borrows, and passing it to a callee argument that writes are rejected (the read-only walk keyed by callee and argument position). Record globals hold no kptr, spin_lock or timer fields (the schema rejects them).

    **Lowering**: Stage ③ emits addressof of the placeholder llvm.mlir.global (a byte array of the record size, marked ebpf.global); BuildBTF makes a VAR of the record struct in the section's DATASEC, and BTF-to-DI turns the placeholder into a zero-initialized, non-constant typed global (codegen never assumes its value). No helper.

    **Evidence**: Out of scope — release evidence: no F id yet. Static: lit (schema, ref ops, read-only negatives, ELF / BTF shape), elf-snapshot, opcheck host row run by the B0 root smoke.

    **Unsupported**: .data record globals (scx.exit_info only), kptr / spin_lock / timer fields in global records, Go bindings for record globals (bindgen stops by name).
  }];
  let arguments = (ins FlatSymbolRefAttr:$name);
  let results = (outs EBPF_BorrowedType:$ref);
  let assemblyFormat = "$name attr-dict `:` type($ref)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_KsymExistsOp : EBPF_Op<"ksym.exists"> {
  let summary = "Test whether a weak per-CPU typed ksym VAR resolved (a guard)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: C's `bpf_ksym_exists(&v)` for a weak schema core.ksyms VAR: true when the loader resolved v in the target's BTF. libbpf 1.7 leaves an unresolved weak typed ksym at address 0 with src_reg 0, so the verifier prunes the false branch of `if (&v)` as a constant. It is a **guard**: the requirements rows of the reads it dominates carry `guarded <g>`, and the precheck excuses them only when absence is certain (requirements_format.md §9).

    **Constraints**: @v is a weak core.ksyms entry (ebpf-verify-schema). Its i1 has exactly one use, the condition of an ebpf.if. Stores, arith (and / or / select), call arguments, yield and other uses are rejected, so the compare stays the direct NULL test the verifier can prune (C's `a || b` folds the addresses with a bitwise OR the verifier rejects — compat.bpf.h:535-539). Write `!a || !b` as nested ebpf.if.

    **Lowering**: Stage ③ emits addressof of the extern_weak .ksyms global and icmp ne NULL (ld_imm64 v plus a compare with 0, like clang). ObjectEmitter writes the guard row and the ksymvar row.

    **Evidence**: Out of scope — kernel evidence: compile only (C shape with clang 23.1.1 and offline precheck); a separate VM run covers it.

    **Unsupported**: Strong VARs (they need no guard — absence fails the load), kfunc existence (bpf_ksym_exists of a function), and guards used other than as an ebpf.if condition.
  }];
  let arguments = (ins FlatSymbolRefAttr:$name);
  let results = (outs I1:$result);
  let assemblyFormat = "$name attr-dict";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_KsymPerCpuLoadOp : EBPF_Op<"ksym.per_cpu_load", [RecursiveMemoryEffects]> {
  let summary = "Read a CPU's copy of a per-CPU typed ksym VAR (bpf_per_cpu_ptr and the slot load)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: C's `T *p = bpf_per_cpu_ptr(&v, cpu); if (p) { … *p … }` for a schema core.ksyms VAR with per_cpu true. bpf_per_cpu_ptr returns NULL for an out-of-range cpu, so the absent region runs then. Otherwise the present region receives the slot value: an integer iN for an integer slot, or `!ebpf.kaddr<"S">` for a `{"kind": "ptr", "struct": S}` slot (the verifier types the slot load as a scalar).

    **Constraints**: @v is a core.ksyms entry and the present argument matches its slot (ebpf-verify-schema). cpu is i32. Both regions end in ebpf.yield with integer results only; the slot value and kaddr do not escape. **A weak @v is read only inside the then region of an ebpf.if whose condition is ebpf.ksym.exists @v** (the same name — another VAR's guard does not count), in the same function and not across a loop callback. Otherwise ebpf-verify-guards rejects it, because the verifier could not prune the unresolved address.

    **Lowering**: Stage ② becomes ksym.per_cpu_br (the helper, NULL test and slot load) with the arms spliced in. Stage ③ calls helper per_cpu_ptr (153) on the address of the extern .ksyms global, compares it with NULL, and loads the slot (8 bytes for kaddr) on the true edge.

    **Evidence**: Out of scope — kernel evidence: compile only; a separate VM run covers it.

    **Unsupported**: Struct slots (runqueues, pcpu_hot — PTR_TO_BTF_ID, another contract), plain (non-per-CPU) typed VARs, pointer-to-pointer slots, writes (MEM_RDONLY), and bpf_this_cpu_ptr.
  }];
  let arguments = (ins FlatSymbolRefAttr:$name, I32:$cpu);
  let results = (outs Variadic<AnyType>:$results);
  let regions = (region AnyRegion:$presentRegion, AnyRegion:$absentRegion);
  let assemblyFormat = [{
    $name `[` $cpu `]` attr-dict (`->` type($results)^)?
    `present` $presentRegion `absent` $absentRegion
  }];
  let hasVerifier = 1;
}

def EBPF_KsymPerCpuBrOp : EBPF_Stage2Op<"ksym.per_cpu_br", "ebpf.ksym.per_cpu_load (present / absent regions)", [Terminator]> {
  let summary = "Branch on bpf_per_cpu_ptr, passing the loaded slot to the present successor (stage ② internal)";
  let description = [{
    **Stage**: ② Internal

    **Meaning**: The expanded ksym.per_cpu_load. It goes to present with the slot value when bpf_per_cpu_ptr(&v, cpu) is non-NULL, and to absent otherwise.

    **Constraints**: present takes exactly one argument (the slot value — iN or kaddr); absent takes none.

    **Lowering**: Stage ③ calls helper per_cpu_ptr, compares with NULL, loads the slot in a block on the true edge and branches to present with it.

    **Evidence**: Internal — generated from ksym.per_cpu_load by ebpf-expand-regions. Source input is rejected to prevent bypassing the stage-① guard checks.

    **Unsupported**: Not writable in input.
  }];
  let arguments = (ins FlatSymbolRefAttr:$name, I32:$cpu);
  let successors = (successor AnySuccessor:$present, AnySuccessor:$absent);
  let assemblyFormat = "$name `[` $cpu `]` `,` $present `,` $absent attr-dict";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_KAddrNonNullOp : EBPF_Op<"kaddr.nonnull", [Pure]> {
  let summary = "Test an untrusted kernel address for non-NULL";
  let description = [{
    **Stage**: ① Input

    **Meaning**: i1 true when a `!ebpf.kaddr<"S">` (a per-CPU slot's pointer value) is not NULL — C's `if (*pp)` after bpf_per_cpu_ptr. It is an integer compare on a scalar; it does not make the address trusted.

    **Constraints**: The operand is a kaddr. The i1 is an ordinary integer.

    **Lowering**: Stage ③ emits icmp ne against NULL.

    **Evidence**: Out of scope — kernel evidence: compile only; records the NULL / non-NULL witness in a VM.

    **Unsupported**: Reading through the address as a trusted BTF pointer (ebpf.kaddr.read reads it with bpf_probe_read_kernel).
  }];
  let arguments = (ins EBPF_KAddrType:$addr);
  let results = (outs I1:$result);
  let assemblyFormat = "$addr attr-dict `:` type($addr)";
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_KAddrEqOp : EBPF_Op<"kaddr.eq", [Pure]> {
  let summary = "Compare two untrusted kernel addresses for equality";
  let description = [{
    **Stage**: ① Input

    **Meaning**: i1 true when two `!ebpf.kaddr` values are the same address — C's `BPF_CORE_READ(sg_cpu, sg_policy) == BPF_CORE_READ(policy, governor_data)`. Any two kaddr types may be compared (`kaddr<"">` is a `void *`); it is an integer compare of scalars and makes neither trusted.

    **Constraints**: Both operands are kaddr. The i1 is an ordinary integer.

    **Lowering**: Stage ③ emits icmp eq of the two pointers.

    **Evidence**: Out of scope — kernel evidence: compile only; runs the LAVD power path in a VM.

    **Unsupported**: Ordering compares and address arithmetic.
  }];
  let arguments = (ins EBPF_KAddrType:$lhs, EBPF_KAddrType:$rhs);
  let results = (outs I1:$result);
  let assemblyFormat = "$lhs `,` $rhs attr-dict `:` type($lhs) `,` type($rhs)";
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_KAddrReadOp : EBPF_Op<"kaddr.read"> {
  let summary = "Read a kernel-struct field through an untrusted kernel address (CO-RE + bpf_probe_read_kernel)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: C's `BPF_CORE_READ(p, path)` on an untrusted `!ebpf.kaddr<"S">`: bpf_probe_read_kernel(tmp, sizeof(T), &p->path) with the field address relocated by CO-RE (byte_off). status is the raw helper value (0, or -EFAULT on a fault — the kernel then zeroes the copy); value is the field, 0 when the read failed. The field type T follows schema core.kernel_types: an integer field reads as iN of its width (8 / 16 / 32 / 64 — the sign is checked by the kfield row); a `{"kind": "kptr", "struct": U}` field reads as `!ebpf.kaddr<"U">` (still untrusted — probe_read_kernel output is a scalar); a `{"kind": "ptr"}` (void *) field reads as `!ebpf.kaddr<"">`.

    **Constraints**: The operand is a kaddr of a declared struct (not `kaddr<"">`). path has 1 to 3 components (a.b.c — intermediate components are embedded structs). ebpf-verify-kptr matches the leaf and the result type. In the body of an ebpf.program or a static ebpf.func. CO-RE guards (ebpf.core.field_exists / type_exists) enclosing it bind its kfield row like kfield.load's.

    **Lowering**: Stage ③ zeroes an 8-byte aligned stack slot, gets the field address with bpfabi.core_field_addr (stage ④ marker __ebpf_core_addr.<S>.<path>, expanded by ObjectEmitter into llvm.preserve.struct.access.index), calls helper probe_read_kernel (113) with sizeof(T), and loads T from the slot. requirements: kfield <prog> S path <iN | ptr:U | ptr:void> (ptr:void is format 25) and helper 113.

    **Evidence**: Out of scope — kernel evidence: compile only (the ELF matches clang's BPF_CORE_READ); a separate VM run covers it. probe_read_kernel needs CAP_PERFMON (bpf_base_func_proto).

    **Unsupported**: Struct and array leaves, strptr fields (ebpf.kernel.read_str), trusted kptr bases (ebpf.kfield.load), and writes.
  }];
  let arguments = (ins EBPF_KAddrType:$addr, StrAttr:$field);
  let results = (outs I64:$status, AnyType:$value);
  let assemblyFormat = "$addr $field attr-dict `:` type($addr) `->` type($status) `,` type($value)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_KAddrStrncmpOp : EBPF_Op<"kaddr.strncmp"> {
  let summary = "Read a kernel char-array field through an untrusted address and compare it with a literal (probe_read_kernel_str + bpf_strncmp)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: C's `char buf[sizeof(lit)]; bpf_core_read_str(buf, sizeof(buf), &p->field); bpf_strncmp(buf, sizeof(buf), lit)` (LAVD power.bpf.c:1016-1017). status is the raw probe_read_kernel_str value (length including the NUL, truncated to len(lit) + 1, or negative — the kernel then zeroes buf); cmp is bpf_strncmp's raw value (-1 / 0 / 1 on x86_64 — only `== 0` is a contract). When status < 0 the buffer is zeros, so cmp compares lit with an empty string.

    **Constraints**: The operand is a kaddr of a declared struct (not `kaddr<"">`); field is a declared 8-bit integer array (1 to 3 path components). lit is 1 to 64 bytes without NUL. Same placement and guard rules as ebpf.kaddr.read.

    **Lowering**: Stage ③ a len(lit) + 1 byte stack buffer, bpfabi.core_field_addr for the source, helper probe_read_kernel_str (115), then helper strncmp (182) with the buffer, len(lit) + 1 and the address of a compiler-owned .rodata NUL-terminated literal (bpf_strncmp's arg 3 is ARG_PTR_TO_CONST_STR: a frozen BPF_F_RDONLY_PROG map value — cilium and libbpf freeze .rodata). requirements: kfield [N]i8 / [N]u8 and helpers 115 and 182.

    **Evidence**: Out of scope — kernel evidence: compile only; a separate VM run covers it.

    **Unsupported**: char * (strptr) sources, literals longer than 64 bytes, and using the order of cmp.
  }];
  let arguments = (ins EBPF_KAddrType:$addr, StrAttr:$field, StrAttr:$literal);
  let results = (outs I64:$status, I64:$cmp);
  let assemblyFormat = "$addr $field `,` $literal attr-dict `:` type($addr) `->` type($status) `,` type($cmp)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_KFieldStrncmpOp : EBPF_Op<"kfield.strncmp"> {
  let summary = "Compare a trusted kernel-struct char-array field with a literal (bpf_strncmp)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: C's `bpf_strncmp(p->comm, N, lit)` on a trusted `!ebpf.kptr<"S">` (LAVD introspec.bpf.c:111): the field's address (CO-RE relocated) is bpf_strncmp's arg 1 directly, no copy. cmp is the raw value (-1 / 0 / 1 on x86_64 — only `== 0` is a contract).

    **Constraints**: field is a declared 8-bit integer array of at least N elements (1 to 3 path components); 1 ≤ N. lit is 1 to 64 bytes without NUL and may differ in length from N. In the body of an ebpf.program or a static ebpf.func; CO-RE guards bind its kfield row. the pointer must be shown trusted (bpf_strncmp takes PTR_TO_BTF_ID only with PTR_TRUSTED) — ebpf.task.current_btf, or an ebpf.ctx.arg of a tp_btf or struct_ops program directly or through ebpf.kptr.check; a field traversal (kfield.ptr — MEM_RCU), a ctx.arg of another kind (fentry) and a ctx.field pointer are rejected by name.

    **Lowering**: Stage ③ bpfabi.core_field_addr on the kptr, then helper strncmp (182) with N and a compiler-owned .rodata literal (as ebpf.kaddr.strncmp). requirements: kfield [M]i8 / [M]u8 (M the declared count) and helper 182.

    **Evidence**: Out of scope — kernel evidence: compile only; a separate VM run covers it (the trusted-origin rule follows the 7.3.1 source — not a kernel load).

    **Unsupported**: kref / rcu bases, strptr fields, and using the order of cmp. The trusted-origin rule is not a guarantee that every tp_btf ctx.arg is trusted: a raw_tp_null_args 0x2 (IS_ERR) argument (e.g. cachefiles_lookup's) becomes SCALAR_VALUE (7.3.1 btf.c:7094 → :7150-7153) and a NULL check does not make it trusted — the kernel rejects it at load (the same limit as for a direct ctx.arg).
  }];
  let arguments = (ins EBPF_KPtrType:$ptr, StrAttr:$field, I64Attr:$len, StrAttr:$literal);
  let results = (outs I64:$cmp);
  let assemblyFormat = "$ptr $field `len` $len `,` $literal attr-dict `:` type($ptr) `->` type($cmp)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_KAddrContainerOfOp : EBPF_Op<"kaddr.container_of"> {
  let summary = "Step back from an embedded-member address to its containing struct (CO-RE field offset)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: C's `(void *)a - bpf_core_field_offset(struct S, field)` (container_of — LAVD power.bpf.c:1030-1031): a is the address of S's embedded member field (of struct T), and the result is the untrusted address of the S. The offset is CO-RE relocated (BPF_FIELD_BYTE_OFFSET), so it is the target kernel's.

    **Constraints**: a is `!ebpf.kaddr<"T">`; S.field is declared in core.kernel_types as the embedded struct `{"kind": "struct", "struct": T}` (1 to 3 path components); the result is `!ebpf.kaddr<"S">`. Same placement and guard rules as ebpf.kaddr.read.

    **Lowering**: Stage ③ bpfabi.core_field_offset (stage ④ marker __ebpf_core_offset.<S>.<field>, expanded by ObjectEmitter into llvm.bpf.preserve.field.info(…, 0)) and a byte GEP by its negation. requirements: kfield <prog> S field struct:T (format 17).

    **Evidence**: Out of scope — kernel evidence: compile only; a separate VM run covers it.

    **Unsupported**: Non-embedded fields (pointers, integers, arrays) and trusted kptr bases.
  }];
  let arguments = (ins EBPF_KAddrType:$addr, StrAttr:$struct_name, StrAttr:$field);
  let results = (outs EBPF_KAddrType:$result);
  let assemblyFormat = "$addr $struct_name $field attr-dict `:` type($addr) `->` type($result)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_CoreTypeExistsOp : EBPF_Op<"core.type_exists"> {
  let summary = "CO-RE type existence of a kernel struct (a guard)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: C's `bpf_core_type_exists(struct S)`: a CO-RE type-existence relocation the loader resolves to 1 or 0 against the target BTF at load. The compiler does not decide it. It is a **guard** for the kfield rows of struct S it dominates (`guarded <g>`).

    **Constraints**: S is a btf.scope @kernel struct (schema core.kernel_types — ebpf-verify-kptr). Its i1 has exactly one use, the condition of an ebpf.if (as ksym.exists).

    **Lowering**: Stage ③ bpfabi.core_exists. Stage ④ marker `__ebpf_core_exists.type.S` becomes llvm.bpf.preserve.type.info(seq, 0) with the local S debug type, and a compare with 0 (clang's form).

    **Evidence**: Out of scope — kernel evidence: compile only (CO-RE relocation kind type_exists in the ELF, compared with clang); a separate VM run covers it.

    **Unsupported**: Type size / match relocations, enums and typedefs.
  }];
  let arguments = (ins StrAttr:$struct_name);
  let results = (outs I1:$result);
  let assemblyFormat = "$struct_name attr-dict";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_CoreFieldExistsOp : EBPF_Op<"core.field_exists"> {
  let summary = "CO-RE field existence of a kernel struct field (a guard)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: C's `bpf_core_field_exists(p->a.b)`: a CO-RE field-existence relocation the loader resolves to 1 or 0 at load. It is a **guard** for the kfield rows of the same struct and path it dominates.

    **Constraints**: S and the path (up to three embedded levels, as kfield.load) are declared in btf.scope @kernel. Its i1 has exactly one use, the condition of an ebpf.if.

    **Lowering**: Stage ③ bpfabi.core_exists. Stage ④ marker `__ebpf_core_exists.field.S.path` becomes preserve.struct.access.index from a NULL base and llvm.bpf.preserve.field.info(…, 2), and a compare with 0 (clang's form).

    **Evidence**: Out of scope — kernel evidence: compile only (CO-RE relocation kind field_exists in the ELF, compared with clang); a separate VM run covers it.

    **Unsupported**: Other field-info kinds (byte size / offset / signedness), bitfields and arrays.
  }];
  let arguments = (ins StrAttr:$struct_name, StrAttr:$field);
  let results = (outs I1:$result);
  let assemblyFormat = "$struct_name $field attr-dict";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_KconfigLoadOp : EBPF_Op<"kconfig.load"> {
  let summary = "Read a kernel config option (C's extern __kconfig)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads a schema core.kconfig option, which the loader fills from the target's kconfig file at load (libbpf's .kconfig map, frozen read-only). bool and char read i8, tristate i32 (enum libbpf_tristate — 0 no, 1 yes, 2 module), integers their width. A weak option absent from the file reads 0; a strong one fails the load (the requirements kconfig row lets precheck stop it first). The compiler never knows the value.

    **Constraints**: @CONFIG_X is a core.kconfig entry and the result width matches its type (ebpf-verify-schema).

    **Lowering**: Stage ③ emits addressof of the extern (or extern_weak) .kconfig global and a load of the declared width (not volatile — C's form; the map is frozen). ObjectEmitter writes the kconfig row and the VAR type (bool is _Bool, char is char, tristate is enum libbpf_tristate).

    **Evidence**: Out of scope — kernel evidence: compile only (DATASEC .kconfig compared with clang, offline precheck with saved config files); a separate VM run covers it.

    **Unsupported**: String options (char arrays) and libbpf's virtual LINUX_* values.
  }];
  let arguments = (ins FlatSymbolRefAttr:$name);
  let results = (outs AnySignlessInteger:$result);
  let assemblyFormat = "$name attr-dict `:` type($result)";
}

def EBPF_GlobalAtomicAddOp : EBPF_Op<"global.atomic_add"> {
  let summary = "Atomically add to a schema core.globals bss variable";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Adds delta atomically to a .bss global without returning a value (non-FETCH).

    **Constraints**: Delta i32 / i64 only (BPF atomics). Schema checks declared name / width and bss section in both program / function bodies; rodata is frozen after load. Older behavior missed function-body rodata writes / width mismatches. No timer.callback; loops allowed.

    **Lowering**: Stage ③ addressof placeholder global plus monotonic llvm.atomicrmw add, like ref.atomic_add. No helper.

    **Evidence**: F26. Four-thread concurrent counts match C; rodata additions fail compile, post-load updates fail kernel EPERM; three-target / non-root and function-body checks.

    **Unsupported**: 8 / 16-bit additions, FETCH, other atomics (and / or / xchg / cmpxchg), and rodata additions.
  }];
  let arguments = (ins FlatSymbolRefAttr:$name, AnySignlessInteger:$delta);
  let assemblyFormat = "$name `,` $delta attr-dict `:` type($delta)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_GlobalCmpxchgOp : EBPF_Op<"global.cmpxchg", [AllTypesMatch<["expected", "desired", "old"]>]> {
  let summary = "Atomically compare and exchange a schema core.globals bss variable, returning the old value";
  let description = [{
    **Stage**: ① Input

    **Meaning**: `%old = ebpf.global.cmpxchg @g, %expected, %new : iN` atomically compares the .bss global with expected and, when equal, writes new; %old is the value before the operation either way (C's `__sync_val_compare_and_swap`). A boolean CAS is `arith.cmpi eq %old, %expected`.

    **Constraints**: Width i32 / i64 only (BPF atomics); expected, new and the result share the type. ebpf-verify-schema requires a declared integer .bss global of that width in program and function bodies (.rodata is frozen after load; record / kptr / kaddr globals are rejected). Allowed in ebpf.loop / ebpf.iter.num bodies (the retry loop); rejected in timer.callback.

    **Lowering**: Stage ③ addressof of the placeholder global; i64 is llvm.cmpxchg seq_cst seq_cst (result 0 — BPF `r0 = cmpxchg_64`); i32 is inline asm `w0 = cmpxchg32_32($1 + 0, w0, w2)` with constraints `={r0},r,{r0},{r2},~{memory}` (the same form — LLVM rejects a 32-bit cmpxchg below CPU v3). The kernel's cmpxchg instruction is a full barrier; the asm `~{memory}` clobber is a compiler barrier only. No helper.

    **Evidence**: Out of scope — release evidence: no F id yet. Static: lit, instruction match against clang -mcpu=v3 with the value paths, named mutants, elf-snapshot, opcheck host row run by the B0 root smoke (7.1.8 load). Values and multi-CPU atomicity: measured separately.

    **Unsupported**: 8 / 16-bit widths, .rodata globals, acquire / release orderings.
  }];
  let arguments = (ins FlatSymbolRefAttr:$name, AnySignlessInteger:$expected, AnySignlessInteger:$desired);
  let results = (outs AnySignlessInteger:$old);
  let assemblyFormat = "$name `,` $expected `,` $desired attr-dict `:` type($old)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_GlobalAtomicOrOp : EBPF_Op<"global.atomic_or"> {
  let summary = "Atomically OR into a schema core.globals bss variable";
  let description = [{
    **Stage**: ① Input

    **Meaning**: `ebpf.global.atomic_or @g, %v : iN` ORs v atomically into a .bss global without returning a value (non-FETCH).

    **Constraints**: The global.atomic_add rules: width i32 / i64 only, a declared integer .bss global of that width (ebpf-verify-schema, program and function bodies), allowed in loops, rejected in timer.callback.

    **Lowering**: Stage ③ addressof of the placeholder global; i64 is result-unused monotonic llvm.atomicrmw or (BPF non-FETCH `lock *(u64 *) |=`); i32 is inline asm `lock *(u32 *)($0 + 0) |= w2` with constraints `r,{r2},~{memory}`. The contract is monotonic non-FETCH (not C's seq_cst `__sync_fetch_and_or`); the asm clobber is a compiler barrier only. No helper.

    **Evidence**: Out of scope — release evidence: no F id yet. Static: lit, instruction match against clang -mcpu=v3 (__sync arm: C's FETCH or at both widths is a named expected row; relaxed `__atomic_fetch_or` arm: exact match), named mutant M-or-add, elf-snapshot, opcheck host row run by the B0 root smoke (7.1.8 load). Values and multi-CPU atomicity: measured separately.

    **Unsupported**: FETCH, and / xor / xchg, 8 / 16-bit widths, .rodata globals, acquire / release orderings.
  }];
  let arguments = (ins FlatSymbolRefAttr:$name, AnySignlessInteger:$value);
  let assemblyFormat = "$name `,` $value attr-dict `:` type($value)";
  let hasVerifier = 1;
}

def EBPF_KtimeOp : EBPF_Op<"ktime.ns"> {
  let summary = "Raw bpf_ktime_get_ns() value";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Returns raw i64 monotonic-clock nanoseconds from ktime_get_ns.

    **Constraints**: No op verifier or compile-time kind restriction; requirements helper checks determine availability at load. Allowed in loops / subprograms / timer.callback, whose ordinary helper set is limited to this op. Packet-neutral for C1 / W1.

    **Lowering**: Stage ③ calls UAPI ktime_get_ns.

    **Evidence**: F30. Kernel op acceptance, requirements helper rows, and timer callback time reads.

    **Unsupported**: Other clocks use ktime.boot_ns / ktime.coarse_ns / ktime.tai_ns.
  }];
  let results = (outs I64:$result);
  let assemblyFormat = "attr-dict `:` type($result)";
}

// ctx-free scalar helpers and the current task. The ten
// integer ops share one placement verifier; task.current_btf has its own.
// Each op is a plain EBPF_Op definition (opcheck and the reference generator
// read plain EBPF_Op definitions, not TableGen subclasses).
def EBPF_CpuIdOp : EBPF_Op<"cpu.id"> {
  let results = (outs I32:$result);
  let assemblyFormat = "attr-dict `:` type($result)";
  let hasVerifier = 1;
  let summary = "Raw bpf_get_smp_processor_id() value";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Returns the u32 CPU number the program runs on as raw i32 bits. Not a NUMA node or task identity.

    **Constraints**: Result i32 only. No compile-time kind restriction; requirements helper rows check availability at load. Program bodies, static functions and B / U loops. Direct placement in helper callbacks ((H) loop callback, bpf_loop, map.for_each, timer.callback, user_ringbuf.callback) is rejected; reaching it through a static function called from a callback is not rejected. Unknown memory effects: unused or repeated calls are retained. Not packet-neutral.

    **Lowering**: Stage ③ calls UAPI get_smp_processor_id and truncates its i64 return to i32.

    **Evidence**: F80. Static: lit for ③ helper / truncation, placement negatives and ELF requirements. Kernel load and value meaning is measured separately.

    **Unsupported**: Kernel measurement earlier. Callback placement.
  }];
}

def EBPF_RandomU32Op : EBPF_Op<"random.u32"> {
  let results = (outs I32:$result);
  let assemblyFormat = "attr-dict `:` type($result)";
  let hasVerifier = 1;
  let summary = "Raw bpf_get_prandom_u32() value";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Returns a u32 pseudo-random value as raw i32 bits. Not cryptographically secure.

    **Constraints**: Result i32 only. Same placement as cpu.id: program bodies, static functions and B / U loops; direct helper-callback placement rejected. Unknown memory effects keep each call (two ops are two calls). Not packet-neutral.

    **Lowering**: Stage ③ calls UAPI get_prandom_u32 and truncates its i64 return to i32.

    **Evidence**: F80. Static: lit for ③ helper, truncation, retained repeated calls and ELF requirements. Kernel load is measured separately.

    **Unsupported**: Entropy or cryptographic quality, reproducible sequences, kernel measurement.
  }];
}

def EBPF_NumaNodeIdOp : EBPF_Op<"numa.node_id"> {
  let results = (outs I64:$result);
  let assemblyFormat = "attr-dict `:` type($result)";
  let hasVerifier = 1;
  let summary = "Raw bpf_get_numa_node_id() value";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Returns the NUMA node of the current CPU as the helper's raw long (i64) return, without narrowing.

    **Constraints**: Result i64 only. Same placement as cpu.id. Unknown memory effects; not packet-neutral.

    **Lowering**: Stage ③ calls UAPI get_numa_node_id and keeps its i64 return.

    **Evidence**: F80. Static: lit for ③ helper and ELF requirements. Kernel load is measured separately.

    **Unsupported**: Kernel measurement earlier; multi-node behavior is not claimed from a single-node VM.
  }];
}

def EBPF_TaskUidGidOp : EBPF_Op<"task.uid_gid"> {
  let results = (outs I64:$result);
  let assemblyFormat = "attr-dict `:` type($result)";
  let hasVerifier = 1;
  let summary = "Raw bpf_get_current_uid_gid() value (gid << 32 | uid)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Returns raw i64 helper value: high32 GID, low32 UID of the current task (in the initial user namespace, as the kernel helper defines).

    **Constraints**: Result i64 only. Same placement as cpu.id. Unknown memory effects; not packet-neutral.

    **Lowering**: Stage ③ calls UAPI get_current_uid_gid and keeps its i64 return.

    **Evidence**: F80. Static: lit for ③ helper and ELF requirements. Kernel load and pack order is measured separately.

    **Unsupported**: Separate UID / GID operations (caller shifts / truncates). Kernel measurement earlier.
  }];
}

def EBPF_Jiffies64Op : EBPF_Op<"jiffies64"> {
  let results = (outs I64:$result);
  let assemblyFormat = "attr-dict `:` type($result)";
  let hasVerifier = 1;
  let summary = "Raw bpf_jiffies64() value";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Returns raw 64-bit jiffies. Not converted to nanoseconds; the tick rate is the kernel's HZ.

    **Constraints**: Result i64 only. Same placement as cpu.id. Unknown memory effects; not packet-neutral.

    **Lowering**: Stage ③ calls UAPI jiffies64 and keeps its i64 return.

    **Evidence**: F80. Static: lit for ③ helper and ELF requirements. Kernel load is measured separately.

    **Unsupported**: Unit conversion, kernel measurement.
  }];
}

def EBPF_KtimeBootNsOp : EBPF_Op<"ktime.boot_ns"> {
  let results = (outs I64:$result);
  let assemblyFormat = "attr-dict `:` type($result)";
  let hasVerifier = 1;
  let summary = "Raw bpf_ktime_get_boot_ns() value";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Returns raw i64 nanoseconds of the boot-time clock (includes suspend), unlike ktime.ns (monotonic).

    **Constraints**: Result i64 only. Same placement as cpu.id. Unknown memory effects; not packet-neutral (unlike ktime.ns).

    **Lowering**: Stage ③ calls UAPI ktime_get_boot_ns.

    **Evidence**: F80. Static: lit for ③ helper and ELF requirements. Kernel load is measured separately.

    **Unsupported**: timer.callback (its helper set stays ktime.ns only), kernel measurement.
  }];
}

def EBPF_KtimeCoarseNsOp : EBPF_Op<"ktime.coarse_ns"> {
  let results = (outs I64:$result);
  let assemblyFormat = "attr-dict `:` type($result)";
  let hasVerifier = 1;
  let summary = "Raw bpf_ktime_get_coarse_ns() value";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Returns raw i64 nanoseconds of the coarse monotonic clock (tick resolution).

    **Constraints**: Result i64 only. Same placement as cpu.id. Unknown memory effects; not packet-neutral. 7.1.8 offers the helper only to networking program types (bpf_sk_base_func_proto: xdp, tc, socket kinds; also sock_addr / sk_reuseport), not to tracing; a tracing ELF stops at load precheck (requirements helper row), not at compile.

    **Lowering**: Stage ③ calls UAPI ktime_get_coarse_ns.

    **Evidence**: F80. Static: lit for ③ helper and ELF requirements. Kernel load is measured separately.

    **Unsupported**: Precision claims, kernel measurement.
  }];
}

def EBPF_KtimeTaiNsOp : EBPF_Op<"ktime.tai_ns"> {
  let results = (outs I64:$result);
  let assemblyFormat = "attr-dict `:` type($result)";
  let hasVerifier = 1;
  let summary = "Raw bpf_ktime_get_tai_ns() value";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Returns raw i64 nanoseconds of the TAI clock.

    **Constraints**: Result i64 only. Same placement as cpu.id. Unknown memory effects; not packet-neutral.

    **Lowering**: Stage ③ calls UAPI ktime_get_tai_ns.

    **Evidence**: F80. Static: lit for ③ helper and ELF requirements. Kernel load is measured separately.

    **Unsupported**: Clock synchronization claims, kernel measurement.
  }];
}

def EBPF_TaskAncestorCgroupIdOp : EBPF_Op<"task.ancestor_cgroup_id"> {
  let summary = "Raw bpf_get_current_ancestor_cgroup_id(level) value";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Returns the cgroup-v2 ID of the current task's ancestor at the given level (0 is the root) as raw i64. The kernel returns 0 for levels the task's cgroup does not have; that 0 is not an errno.

    **Constraints**: Level i32 (the helper takes int), result i64. Same placement as cpu.id. Unknown memory effects; not packet-neutral.

    **Lowering**: Stage ③ zero-extends the level to i64 (the same 32-bit move clang emits for an int argument) and calls UAPI get_current_ancestor_cgroup_id.

    **Evidence**: F80. Static: lit for ③ helper / zero extension and ELF requirements. Kernel load and level semantics is measured separately.

    **Unsupported**: cgroup-v1, kernel measurement.
  }];
  let arguments = (ins I32:$level);
  let results = (outs I64:$result);
  let assemblyFormat = "$level attr-dict `:` type($level) `->` type($result)";
  let hasVerifier = 1;
}

def EBPF_TaskCurrentRawOp : EBPF_Op<"task.current_raw"> {
  let results = (outs I64:$result);
  let assemblyFormat = "attr-dict `:` type($result)";
  let hasVerifier = 1;
  let summary = "Raw bpf_get_current_task() value as an integer";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Returns the current task_struct address as an ordinary i64 (RET_INTEGER). It is not a pointer: no operation turns it into a kptr, and it grants no dereference.

    **Constraints**: Result i64 only. Same placement as cpu.id. GPL-only helper: ELF emission with a non-GPL license is rejected through the UAPI helpergpl rows. Unknown memory effects; not packet-neutral.

    **Lowering**: Stage ③ calls UAPI get_current_task and keeps its i64 return (no inttoptr).

    **Evidence**: F80. Static: lit for ③ helper, absence of pointer conversion, GPL rejection and ELF requirements. Kernel load is measured separately.

    **Unsupported**: Integer-to-pointer conversion; typed access uses task.current_btf. Kernel measurement earlier.
  }];
}

def EBPF_TaskPtRegsOp : EBPF_Op<"task.pt_regs"> {
  let summary = "Pointer to a task's saved user registers (bpf_task_pt_regs)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: `bpf_task_pt_regs(task)` (helper 175) returns the task's `struct pt_regs` as `!ebpf.kptr<"pt_regs">` (RET_PTR_TO_BTF_ID — never NULL, without PTR_TRUSTED). The values are the registers saved on the task's entry to the kernel; for a kernel thread they have no defined meaning.

    **Constraints**: The operand is `!ebpf.kptr<"task_struct">` and the result `!ebpf.kptr<"pt_regs">`, both declared in schema core.kernel_types (ebpf-verify-kptr). Program bodies only; functions, callbacks and loops are rejected. The result's only use is the pointer of `ebpf.kfield.load` — not `kfield.ptr`, `kfield.copy`, `kptr.addr`, a kfunc argument or a yield, because the pointer is not trusted. No compile-time kind restriction (requirements helper rows check availability at load), except that a sleepable fentry body rejects it by its closed whitelist. GPL-only.

    **Lowering**: Stage ③ calls UAPI task_pt_regs and converts the integer return of the UAPI signature to a pointer, without a NULL branch.

    **Evidence**: Out of scope — not yet in release_scope (no F id until it is measured): static; real kernels.

    **Unsupported**: Sleepable fentry bodies; acquired references as the operand; register names of architectures other than x86_64 are unmeasured.
  }];
  let arguments = (ins EBPF_KPtrType:$task);
  let results = (outs EBPF_KPtrType:$result);
  let assemblyFormat = "$task attr-dict `:` type($task) `->` type($result)";
  let hasVerifier = 1;
}

def EBPF_TaskCurrentBtfOp : EBPF_Op<"task.current_btf"> {
  let summary = "Typed non-NULL pointer to the current task_struct (bpf_get_current_task_btf)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Returns `!ebpf.kptr<"task_struct">` for the current task (RET_PTR_TO_BTF_ID_TRUSTED, never NULL). Borrowed: no reference is acquired or released, and no lifetime beyond the program invocation is claimed.

    **Constraints**: Program bodies only; functions, callbacks and loops are rejected. Result must be kptr<"task_struct">, declared in schema core.kernel_types (ebpf-verify-kptr). The kptr is used by the existing kfield.load / kfield.ptr / kfield.copy / kptr.addr rules (kptr.addr stays tracing-kind only). No compile-time kind restriction; requirements helper rows check availability at load. GPL-only helper: non-GPL ELF emission is rejected through UAPI helpergpl rows. Unknown memory effects.

    **Lowering**: Stage ③ calls UAPI get_current_task_btf and uses the returned pointer directly, without a NULL branch.

    **Evidence**: F80. Static: lit for ③ helper / no NULL check, placement and declaration negatives, GPL rejection and ELF requirements. Kernel load and BTF use is measured separately.

    **Unsupported**: Storing the pointer, passing it to functions, loop carry, reference ownership, other tasks. Kernel measurement earlier.
  }];
  let results = (outs EBPF_KPtrType:$result);
  let assemblyFormat = "attr-dict `:` type($result)";
  let hasVerifier = 1;
}

// Ring-buffer operation semantics/constraints are canonical in their
// descriptions; see docs/reference/ebpf_ops.md.
def EBPF_RingbufReserveOp : EBPF_Op<"ringbuf.reserve"> {
  let summary = "Attempt to reserve ring-buffer storage";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reserves the result record's size from the schema ringbuf map named by attribute. Returns **unchecked** maybe_reservation<record<S,N>>; helper may return NULL. Must pass ringbuf.if_reserved before use; a valid reservation exists only as its present-region argument.

    **Constraints**: Schema map kind ringbuf and record name / size must match. Ringbuf schema requires a nominal record, so integer reservations are unsupported. Every path consumes a valid reservation exactly once by submit or discard (ownership checking). No scf.if or loop-called subprogram placement. No kind restriction.
    **Reservation size ≤ max_entries − 16** (schema verifier): kernel requires round_up(size + BPF_RINGBUF_HDR_SZ, 8) ≤ max_entries − 1 even for an empty ring (three-kernel __bpf_ringbuf_reserve; UAPI ringbufconst hdr_sz). Oversized requests would load but always return absent, so compile rejects them: a4096 ring allows4080.

    **Lowering**: Stage ③ ringbuf_reserve(map, record size, flags0); stage ② expands if_reserved to a NULL branch.

    **Evidence**: F02. Identical-ELF two-target differential tests; record flow on three targets; C ring-event oracle and three targets. Record/schema matching descends from the predecessor compiler. Three kernels reserve4080 but always reject4088 at runtime.

    **Unsupported**: Flags other than0, dynamic sizes, and dynptr reserve (reservation-free copy uses ringbuf.output). **Ring size ≤ 2^29 bytes (512 MiB)**: btf-verify K9 rejects max_entries >1073741823, including 2^30 rings, because BTF int (*max_entries)[N] exceeds U32_MAX bytes. All three kernels reject that BTF; libbpf silently drops it. Clang C emits the same BTF.
  }];
  let arguments = (ins StrAttr:$ringbuf);
  let results = (outs EBPF_MaybeReservationType:$result);
  let assemblyFormat = "$ringbuf attr-dict `:` type($result)";
}

def EBPF_RingbufIfReservedOp : EBPF_Op<"ringbuf.if_reserved",
    [RecursiveMemoryEffects]> {
  let summary = "Execute present only when ring-buffer reservation succeeded";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Checks an unchecked reserve result and selects present / absent. A valid reservation<R> exists **only as a present-region block argument**; no op returns it in stage ①, so unchecked use has no syntactic path, like ref.check. Both regions can yield results (-> T…), e.g. submit then true / absent false.

    **Constraints**: Both regions have bodies; present has one reservation preserving record type, absent no arguments. Absent cannot store / submit / discard / task.comm / user.read_str. Integer result widths are i1 / 8 / 16 / 32 / 64; others rejected (older behavior accepted i1–i128). Three-target i1 evidence uses kernel/cmd/i1check. Reservation uses are store_field / store_record / submit / discard / task.comm / user.read_str, confined to present without block-argument transport.
    **Exactly one consumption on every path**: branch-wise submit / discard is allowed through ebpf.if, ref.check, packet.check, nesting, and result yields. Op verifier requires at least one submit / discard syntactically. Every-path single consumption, missing / double consumption, and nonconsuming use after consumption are checked by ebpf-verify-ownership, unconditionally first in ebpf-compile, and stage-② checkLinear. **Standalone ebpf-opt op verification does not inspect paths**; contract applies to ebpf-compile input. Yield types must match parent results and cannot carry reservation. Yield neither consumes nor uses it; results do not change ownership rules.

    **Lowering**: Stage ② is_present branch plus true-edge assume_present; results become merge-block arguments. Stage ③ NULL compare / branch, results as phi.

    **Evidence**: F02. Post-consumption-use rejection; three targets; ringresult runner compares success / event counts and absent-status-selected verdicts, with inverted-result mutation failing. Width checks. Branch-wise consumption C/ebpf ELF accepted on three kernels × root / non-root.

    **Unsupported**: Reservation subprogram arguments and cross-block transport.
  }];
  let arguments = (ins EBPF_MaybeReservationType:$reservation);
  let results = (outs Variadic<AnyType>:$results);
  let regions = (region AnyRegion:$presentRegion, AnyRegion:$absentRegion);
  let assemblyFormat = [{
    $reservation attr-dict `:` type($reservation) (`->` type($results)^)?
    `present` $presentRegion `absent` $absentRegion
  }];
  let hasVerifier = 1;
}

def EBPF_RingbufStoreFieldOp : EBPF_Op<"ringbuf.store_field", [MemoryEffects<[MemWrite<EBPF_ReservationResource>]>]> {
  let summary = "Store an integer at a reserved record's byte offset";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Writes one integer's bytes at [offset] of a valid reserved record. Does not consume it.

    **Constraints**: Op verifier requires record reservation and in-record offset / width. Schema verifier additionally requires that range to match an integer record field. No absent / scf.if / post-consumption placement. Only written bytes are defined; compiler does not initialize unwritten bytes or padding. To define all bytes use record.make / store_record.

    **Lowering**: Stage ③ stores at reservation pointer + offset with alignment provable from reservation alignment8 / offset.

    **Evidence**: F02. Field-based stores replace the removed whole-scalar ringbuf.store; one integer uses a one-field record. Record-flow tests and schema-offset validation inherited from the predecessor compiler.

    **Unsupported**: Named fields (use record.make names); this op uses byte offsets.
  }];
  let arguments = (ins EBPF_ReservationType:$reservation,
                       AnySignlessInteger:$value, I64Attr:$offset);
  let assemblyFormat =
      "$reservation `[` $offset `]` `,` $value attr-dict `:` type($reservation) `,` type($value)";
  let hasVerifier = 1;
}

def EBPF_RingbufStoreRecordOp : EBPF_Op<"ringbuf.store_record", [MemoryEffects<[MemWrite<EBPF_ReservationResource>]>]> {
  let summary = "Copy every byte of a record.make result into a reserved record";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Copies all declared record bytes, including zero padding, into a valid reservation. Does not consume it; submit / discard is still required.

    **Constraints**: Record reservation and value must have identical nominal name / size. Value must come directly from record.make, not block arguments / other ops. Placement follows store_field: no absent / scf.if / post-consumption use.

    **Lowering**: Stage ③ normally copies record.make stack storage into reservation with explicit source / destination alignment. If this is the sole use and field stores cover every byte, D2 avoids stack storage and stores fields directly, merging adjacent constants at provable widths. --tune-store-record-merge=false restores pre-D2 output.

    **Evidence**: F02. Copy / alignment tests; D1 rejected because constant stores did not merge into wide stores; D2 adoption / regression checks.

    **Unsupported**: Integer values (not restoration of removed scalar ringbuf.store) and partial-record copy.
  }];
  let arguments = (ins EBPF_ReservationType:$reservation, EBPF_RecordType:$value);
  let assemblyFormat =
      "$reservation `,` $value attr-dict `:` type($reservation) `,` type($value)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_TaskCommOp : EBPF_Op<"task.comm"> {
  let summary = "Write current-task comm into a reservation's byte-array field and return raw helper status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: get_current_comm writes task name into a checked ring reservation byte-array field, returning **raw** i64 helper status. Does not consume it.

    **Constraints**: Record reservation; one-dimensional eight-bit integer array field (record checking). Present only, not absent / post-consumption; also excluded from loop-called subprograms. Compiler does not restrict kinds; load gates check helper availability.

    **Lowering**: Stage ③ get_current_comm(reservation + field offset, element count), with constant size from @records.

    **Evidence**: F21. C oracle; record.make → store_record → task.comm → status defines all bytes; three-target / non-root; post-consumption rejection.

    **Unsupported**: Map / stack / packet writes (reservation only; no generic helper memory writer), multidimensional / non-eight-bit arrays. Nonzero status paths are unmeasured.
  }];
  let arguments = (ins EBPF_ReservationType:$reservation, StrAttr:$field);
  let results = (outs I64:$status);
  let assemblyFormat = "$reservation $field attr-dict `:` type($reservation) `->` type($status)";
  let hasVerifier = 1;
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_CtxStackOp : EBPF_Op<"ctx.stack"> {
  let summary = "Write a kernel stack into a reserved i64 array and return raw status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: get_stack writes kernel PCs into a reservation field; raw i64 status is bytes written or negative errno. Nonconsuming and effectful even if status is unused.

    **Constraints**: Ordinary kprobe entry context, flags0 only; present record reservation, one-dimensional i64[1..16], offset aligned to eight bytes. No function, loop, callback, absent or post-consumption use.

    **Lowering**: Stage ③ get_stack(ctx, reservation + schema offset, 8 * count, flags0). Success zeros the unwritten tail; failure clears the destination.

    **Evidence**: Out of scope — no release F row yet; measured on 3 kernels (7.1.8 / 6.12.111 / 6.6.157) in a VM as root, ordinary kprobe: status, pcs[0] against the C witness, zero tail and invalid flags -EINVAL matched C. Source witness depends on x86 perf_hw_regs and raw regs.ip, not an assumed symbol PC.

    **Unsupported**: User stacks, build IDs, frame skipping, dynamic flags, generic writable buffers and dynamic whole-callchain equality.
  }];
  let arguments = (ins EBPF_ReservationType:$reservation, StrAttr:$field, EBPF_ContextType:$ctx);
  let results = (outs I64:$status);
  let assemblyFormat = "$reservation $field `,` $ctx `flags0` attr-dict `:` type($reservation) `,` type($ctx) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_KernelDPathOp : EBPF_Op<"kernel.d_path"> {
  let summary = "Write a checked kernel path into a reservation's byte array";
  let description = [{
    **Stage**: ① Input

    **Meaning**: d_path writes a path into the reserved field, returning raw i64 status. Positive status counts the NUL-inclusive prefix. The tail and negative-result payload are not promised zero. Nonconsuming and effectful.

    **Constraints**: fentry on the closed table vfs_getattr / security_inode_getattr only (not the kernel's d_path allowlist). vfs_getattr attaches on every target but is inlined into the stat path of some kernels, where an ordinary stat does not fire it (firing observed on 6.12.111 only). security_inode_getattr needs CONFIG_SECURITY; without it the symbol is absent and the load stops loudly. Checked struct path pointer from the same entry context's argument0; i8[1..128] field. Present reservation only, no function, loop, callback or post-consumption use. Requires the target-specific typed helper query.

    **Lowering**: Stage ③ d_path(path, reservation + field offset, count). Requirements carry helper_target with actual target and farg0/path; a generic helper prototype probe cannot authorize it.

    **Evidence**: Out of scope — no release F row yet; measured on 3 kernels (7.1.8 / 6.12.111 / 6.6.157) in a VM as root, fentry security_inode_getattr only: status and path bytes matched C; a disallowed target is refused by the C verifier and by helper_target before load. vfs_getattr values are not formally measured.

    **Unsupported**: Arbitrary pointers, field-derived paths, other hooks/targets, generic buffers and interpretation of bytes beyond the returned prefix.
  }];
  let arguments = (ins EBPF_ReservationType:$reservation, StrAttr:$field, EBPF_KPtrType:$ptr);
  let results = (outs I64:$status);
  let assemblyFormat = "$reservation $field `,` $ptr attr-dict `:` type($reservation) `,` type($ptr) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_StrSnprintfOp : EBPF_Op<"str.snprintf"> {
  let summary = "Format i64 values into a reserved byte field using a frozen readonly literal";
  let description = [{
    **Stage**: ① Input

    **Meaning**: snprintf writes a NUL-terminated formatted prefix and returns raw i64 would-have-written length including NUL. Truncation may return a positive length greater than capacity; an empty format returns1. Nonconsuming and effectful.

    **Constraints**: Ordinary kprobe, present reservation i8[1..128], literal format up to128 bytes excluding NUL, no embedded NUL, 0..12 i64 arguments. Only %% / %lld / %llu / %llx / %llX. No function, loop, callback or post-consumption use.

    **Lowering**: Stage ③ snprintf(field address, capacity, compiler-owned .rodata format, eight-byte argument slots, argc*8). argc0 passes NULL/0. The loader freezes the readonly format map before program load.

    **Evidence**: Out of scope — no release F row yet; measured on 3 kernels (7.1.8 / 6.12.111 / 6.6.157) in a VM as root, ordinary kprobe: frozen format map accepted, status 41 / 14 / 1 and the NUL-terminated text matched C; a stack format is refused with the same verifier text.

    **Unsupported**: Stack/writable/dynamic format, pointers and strings, width/precision, smaller integer arguments, generic writable buffers and normalization of truncation status.
  }];
  let arguments = (ins EBPF_ReservationType:$reservation, StrAttr:$field, StrAttr:$format, Variadic<I64>:$args);
  let results = (outs I64:$status);
  let assemblyFormat = "$reservation $field `,` $format `(` $args `)` attr-dict `:` type($reservation) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_KernelReadScalarOp : EBPF_Op<"kernel.read_scalar"> {
  let summary = "Read a fixed-width scalar from a ptr kprobe argument, returning value and raw helper status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reads a fixed-width scalar through a ptr-declared kprobe argument and returns raw helper status.

    **Constraints**: Ordinary x86_64 kprobe only. Address is the direct i64 result of entry-context kprobe.arg, declared ptr in schema params. Constant offset0..4095; width8 /16 /32 /64.

    **Lowering**: Compiler-owned aligned eight-byte scratch is zeroed before probe_read_kernel. Failure returns value0 / raw negative i64 status; success status0. ptr declaration implies neither pointee layout nor address space. Ignoring status conflates a failed read with successful zero. Effectful memory read, not Pure; scratch cannot escape.

    **Evidence**: F24. On7.1.8 /6.12.111 /6.6.157, 45 C/compiler pairs (nine public,36 private) match value / raw status / hit. Host-status and7.1.8-VM value mutations produce distinct differences. Close / FD / bounded disappearance match for own599 IDs. Private arms are VM-only with FixtureCaps auxiliary oracle, not public-module support. ABI matches kernel/ksyscall helper113 scratch.

    **Unsupported**: Public module caps, pointee-layout checking, uprobe fixed-length reads, variable widths / offsets, and memory stores.
  }];
  let arguments = (ins I64:$addr, I64Attr:$offset);
  let results = (outs AnySignlessInteger:$value, I64:$status);
  let assemblyFormat = "$addr `offset` $offset attr-dict `:` type($addr) `->` type($value) `,` type($status)";
  let hasVerifier = 1;
}

def EBPF_KernelReadStrOp : EBPF_Op<"kernel.read_str"> {
  let summary = "Read a kernel-struct char-pointer string into a reserved byte array, returning raw helper status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: CO-RE reads a kptr<S> field declared kind strptr, then probe_read_kernel_str copies its kernel string into a checked ring reservation byte array. **Raw** i64 status is length including NUL on success, or array count when truncated (last byte NUL); disallowed NULL / user addresses give -ERANGE, read faults -EFAULT. Negative status zeros the entire field. **Empty string returns1**, same implementation on all three kernels, without user.read_str's version difference. Success leaves bytes after NUL unchanged, so initialize all bytes first with record.make → store_record. Nonconsuming.

    **Constraints**: Nonempty field / destination paths, record reservation. kptr verification requires strptr (BTF PTR → eight-bit INT). Destination is one-dimensional eight-bit integer array of1..64 elements. Placement follows task.comm / user.read_str: present only, not absent / post-consumption / scf.if / loop-called subprogram. No compile-time kind restriction; load checks helper, which kernel withholds without CAP_PERFMON. Requirements kfield strptr minimum format15 checks target pointer whose qualifier / typedef-stripped pointee is a one-byte integer.

    **Lowering**: Stage ③ core_field_load eight-byte pointer; ④ __ebpf_core.S.field becomes preserve.struct.access.index plus volatile load. Then probe_read_kernel_str(reservation + path offset, count, pointer).
    **Embedded paths** (F76): At most three a.b.c levels, intermediate embedded structs only (no pointer / union / array), existing leaf rules. Chained CO-RE and format17 path / all-prefix struct:T rows check target names. Unknown blocks load.

    **Evidence**: F23. Kernel-string field tests.

    **Unsupported**: Pointer traversal in intermediate paths, chained char pointers, non-reservation destinations, and non-x86_64 address rules (copy_from_kernel_nofault_allowed is architecture-specific). Status is not normalized.
  }];
  let arguments = (ins EBPF_ReservationType:$reservation, StrAttr:$path, EBPF_KPtrType:$ptr, StrAttr:$field);
  let results = (outs I64:$status);
  let assemblyFormat = "$reservation $path `,` $ptr $field attr-dict `:` type($reservation) `,` type($ptr) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_StrBufLiteralOp : EBPF_Op<"str_buf.literal"> {
  let summary = "A stack string buffer holding a literal, for a sched_ext dump's %s";
  let description = [{
    **Stage**: ① Input

    **Meaning**: A fresh `!ebpf.str_buf<N>` holding the literal followed by zero bytes up to N. The way to give `%s` a constant string (C passes a .rodata address; the printed text is the same) and the fallback value of a read (LAVD's `"unknown"` when there is no cgroup).

    **Constraints**: 1 <= N <= 64; the literal has no NUL and no ASCII control byte other than whitespace (the format's plain-text line — a compiler rule for the value); len + 1 <= N. Only in the body of a sched_ext dump member program (dump / dump_cpu / dump_task — ebpf-verify-schema, as scx.dump). Uses follow `!ebpf.str_buf`.

    **Lowering**: Stage ③ a dedicated entry-block `alloca [N x i8]` (align 8, no lifetime markers) and stores of all N bytes (literal + zeros).

    **Evidence**: Out of scope — kernel evidence: compile only; a separate VM run covers it.

    **Unsupported**: Literals longer than 63 bytes.
  }];
  let arguments = (ins StrAttr:$literal);
  let results = (outs EBPF_StrBufType:$buf);
  let assemblyFormat = "$literal attr-dict `:` type($buf)";
  let hasVerifier = 1;
}

def EBPF_KernelReadStrBufOp : EBPF_Op<"kernel.read_str_buf"> {
  let summary = "Snapshot a kernel-struct char-pointer string into a stack string buffer, returning raw helper status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: As kernel.read_str, but into a fresh `!ebpf.str_buf<N>`: CO-RE reads the kptr<S> strptr field, then probe_read_kernel_str(buf, N, ptr). The helper writes up to and including the NUL (at most N − 1 bytes and a NUL), or on failure zeroes all N bytes (an empty string — 7.3.1 bpf_trace.c:280-298), so no initial value survives the read; the bytes after the NUL are never read by the allowed uses. The snapshot is the string at the time of the read (a later rename or free does not change it). **Raw** i64 status as kernel.read_str.

    **Constraints**: The pointer is a checked kptr; the field is declared strptr (ebpf-verify-kptr, requirements kfield strptr — format 15). 1 <= N <= 64. Only in the body of a sched_ext dump member program (ebpf-verify-schema, as scx.dump). Uses follow `!ebpf.str_buf`.

    **Lowering**: Stage ③ a dedicated entry-block `alloca [N x i8]` (align 8, no lifetime markers, not prefilled — the helper's ARG_PTR_TO_UNINIT_MEM), core_field_load of the 8-byte pointer, then probe_read_kernel_str(alloca, N, pointer).

    **Evidence**: Out of scope — kernel evidence: compile only; a separate VM run covers it.

    **Unsupported**: As kernel.read_str; other destinations.
  }];
  let arguments = (ins EBPF_KPtrType:$ptr, StrAttr:$field);
  let results = (outs EBPF_StrBufType:$buf, I64:$status);
  let assemblyFormat = "$ptr $field attr-dict `:` type($ptr) `->` type($buf) `,` type($status)";
  let hasVerifier = 1;
}

def EBPF_UserStrAtOp : EBPF_Op<"user.str_at"> {
  let summary = "Read string pointer, raw status, and presence at a fixed user char** index (0..19)";
  let description = [{
    **Stage**: ① Input
    **Meaning**: Reads eight bytes at source raw address +8*index with probe_read_user(112). Results are user_str, raw i64 status, and present = status==0 && pointer!=0. A select guarantees pointer0 on failure. NULL terminator gives status0 / present=false; fault gives negative status / present=false; empty string is non-NULL and present=true.
    **Constraints**: Integer attribute index0..19 only. Source must be a same-program direct tp.field / ksyscall.arg user_str_array result, in tracepoint / ksyscall kinds with user.str_at. No loop / static function / SSA index / escape. Caller stops on present=false. Twenty non-NULL entries mean first20 truncation, not complete argv.
    **Lowering**: Zero eight-byte scratch → helper112 → load → status-based pointer select → presence comparison. Spill lifetime ends after load. Separate user.read_str reads string contents.
    **Evidence**: F74. Static controls and B0 opcheck ref-p128-str-at acceptance. Three-kernel C differential checks value / errno / NULL / empty for root TP / ksyscall and non-root ksyscall. Non-root TP fails reading tracefs ID. Failure-pointer-zero evidence inherits structural ABI-select verification, not an exposed raw-pointer observation.
    **Unsupported**: Arbitrary-integer pointers, uprobe-derived arrays, dynamic indices / variable buffers / other architectures / compat.
  }];
  let arguments = (ins EBPF_UserStrArrayType:$array, I64Attr:$index);
  let results = (outs EBPF_UserStrType:$ptr, I64:$status, I1:$present);
  let assemblyFormat = "$array `[` $index `]` attr-dict `:` type($array) `->` `(` type($ptr) `,` type($status) `,` type($present) `)`";
  let hasVerifier = 1;
}

def EBPF_UserReadOp : EBPF_Op<"user.read"> {
  let summary = "Read a signed-clamped length from a typed user buffer and initialize the entire destination";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Computes signed n=max(0,min(len,N)), zeros all N bytes of the reservation's direct byte-array field, then always calls probe_read_user(dst,n,ptr) once. Returns raw i64 status and i32 clamped requested count, **not successfully read bytes**. NUL has no significance. Failure zeros the whole field including suffix.

    **Constraints**: uprobe / uprobe_multi only. Pointer is a direct same-program uprobe.arg / probe.target_arg user_buf result. len i8 / i16 / i32 / i64; direct one-dimensional u8 / i8 field, N1..8192. Inside reservation present, before submit / discard. Caller initializes other fields / padding.

    **Lowering**: Sign-extends len to i64, applies register barrier, compares lower / upper bounds. Volatile constant8 /4 /2 /1-byte stores honoring reservation alignment initialize the field, followed by probe_read_user. No large stack allocation, memset libcall, or new loop.

    **Evidence**: F78. Source / ptr checks and boundary / three-kernel differential tests. Uses existing helper / ptr requirement rows.

    **Unsupported**: Pointers from arbitrary integers / casts / select, slices, map borrows, or arbitrary kinds. Does not establish complete TLS tools or successful reads from arbitrary addresses.
  }];
  let arguments = (ins EBPF_ReservationType:$reservation, StrAttr:$field,
                       EBPF_UserBufType:$ptr, AnyType:$len);
  let results = (outs I64:$status, I32:$count);
  let assemblyFormat = "$reservation $field `,` $ptr `,` $len attr-dict `:` type($reservation) `,` type($ptr) `,` type($len) `->` type($status) `,` type($count)";
  let hasVerifier = 1;
}

def EBPF_UserReadStrOp : EBPF_Op<"user.read_str"> {
  let summary = "Read a typed user string into a reservation byte array, returning raw helper status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: probe_read_user_str reads user_str into a reservation byte-array field, returning **raw** i64 status: length including NUL on success, element count on truncation, negative errno on failure. **Empty-string status varies by kernel**: 1 on7.1.8, 0 on6.12 /6.6. Detect empty via signed status ≥0 && field[0]==0; status ≤1 would also include failures. Successful reads leave bytes after NUL unchanged; initialize all record bytes with record.make → store_record first.

    **Constraints**: Program kind must have user.read_str: uprobe / uprobe_multi / tracepoint / ksyscall. Nonempty field; one-dimensional eight-bit integer array with count ≥1. Placement follows store_field: no absent / post-consumption use. ksyscall pointers originate from typed ksyscall.arg.

    **Lowering**: Stage ③ probe_read_user_str(reservation + field offset, count, raw64 user_str).

    **Evidence**: F25. C oracle; user_str and post-consumption rejection; three-target / non-root measurements including empty-string status differences.

    **Unsupported**: Runtime-length user buffers use user.read (F78). Other kind families rejected. Status is not normalized; compiler does not know kernel versions. TP-derived three-kernel empty / errno evidence belongs to the dedicated differential experiment. Kernel strings use kernel.read_str.
  }];
  let arguments = (ins EBPF_ReservationType:$reservation, StrAttr:$field, EBPF_UserStrType:$ptr);
  let results = (outs I64:$status);
  let assemblyFormat = "$reservation $field `,` $ptr attr-dict `:` type($reservation) `,` type($ptr) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_UserAddrOp : EBPF_Op<"user.addr"> {
  let summary = "Reinterpret an i64 as a user address for ebpf.user.copy";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Reinterprets any i64 as `!ebpf.user_addr`. This is an explicit, unchecked assertion by the author — it does not prove the value is a valid user pointer; a bad address makes `ebpf.user.copy` return −EFAULT.

    **Constraints**: Only in a `fentry` program written `sleepable` (the attach table row with FLAGS `sleepable`), directly in the program body (not in an `ebpf.func`, callback or loop). The result may be used only as the address operand of `ebpf.user.copy` or `ebpf.user.copy_task` — no store, return, yield, region or block-argument transport, call argument or integer operation. The usual source is an `ebpf.global.load`.

    **Lowering**: Stage ③ binds the i64 itself; no helper is called.

    **Evidence**: Out of scope — not yet in release_scope (no F id until it is measured): static verifier and lit; the real-kernel behavior of the address is measured separately.

    **Unsupported**: Any kind other than a sleepable fentry; a user address that outlives the program's own thread (the address must belong to the mm the helper reads — see `ebpf.user.copy`).
  }];
  let arguments = (ins I64:$value);
  let results = (outs EBPF_UserAddrType:$result);
  let assemblyFormat = "$value attr-dict `:` type($value) `->` type($result)";
  let hasVerifier = 1;
}

def EBPF_UserCopyOp : EBPF_Op<"user.copy"> {
  let summary = "Copy user memory into a reservation byte array with bpf_copy_from_user, returning the raw status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: `bpf_copy_from_user(dst, size, user_ptr)` (helper 148) copies `size` bytes — the destination field's length — from the user address into a byte-array field of a checked ring buffer reservation and returns the **raw** i64 status: 0 on success, −EFAULT (−14) when the user memory cannot be read, in which case the helper zeroes the destination. The helper may sleep, so it exists only on a sleepable program; it is not GPL-only.

    **Constraints**: Only in a `fentry` program written `sleepable`, directly in the program body. The destination is a nonempty field of a record reservation: a one-dimensional array of 8-bit integers with at least one element; the reservation must still be live (no use after submit / discard) and, like `ebpf.task.comm`, must first be fully initialized with `record.make` → `store_record`. The address operand must be an `ebpf.user.addr` result. The helper reads the memory of the mm that is current when the program fires; the program must not assume that the address belongs to the task that triggered the attach — callers that need that exclude other tasks' firings themselves (states the boundary it measured).

    **Lowering**: Stage ③ `copy_from_user(reservation + field offset, field length, address)`. requirements record the helper; the program's `sleepable` row makes a loader load it as `fentry.s/<function>`.

    **Evidence**: Out of scope — not yet in release_scope (no F id until it is measured): static (verifier, lowering shape, C oracle ELF); real kernels (success, −EFAULT, non-sleepable rejection).

    **Unsupported**: Non-sleepable programs, other kinds and `fexit.s` / `fmod_ret.s` / `iter.s` / `uprobe.s` / LSM / syscall sleepable forms; runtime-length copies; a status normalized by the compiler. `copy_from_user_task` is `ebpf.user.copy_task`.
  }];
  let arguments = (ins EBPF_ReservationType:$reservation, StrAttr:$field, EBPF_UserAddrType:$addr);
  let results = (outs I64:$status);
  let assemblyFormat = "$reservation $field `,` $addr attr-dict `:` type($reservation) `,` type($addr) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_UserCopyTaskOp : EBPF_Op<"user.copy_task"> {
  let summary = "Copy another task's user memory into a reservation byte array with bpf_copy_from_user_task, returning the raw status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: `bpf_copy_from_user_task(dst, size, user_ptr, task, 0)` (helper 191) copies `size` bytes — the destination field's length — from the user address **in the address space of `task`** into a byte-array field of a checked ring buffer reservation and returns the **raw** i64 status: 0 on success; on failure the helper zeroes the destination and returns the negative `access_process_vm` result, or −EFAULT for a partial read. The flags argument is always 0 and is not exposed (the helper defines no flag). The helper may sleep; it is GPL-only.

    **Constraints**: Only in a `fentry` program written `sleepable`, in the program body — directly, or inside the present region of `ebpf.kref.check` or `ebpf.ringbuf.if_reserved`; not in an `ebpf.func`, callback or loop. The destination is a nonempty one-dimensional array of 8-bit integers in a live record reservation. Initializing the whole reservation first (`record.make` → `store_record`) is the writer's precondition: the fixtures meet it, but the compiler does not check the initialization order. A `!ebpf.kref` task together with the reservation destination gives the helper two arguments that carry a reference: 7.3.1 loads it, while 6.6.157, 6.12.111 and 7.1.8 refuse the load (`more than one arg with ref_obj_id`; the C equivalent is refused the same way). The compiler does not know the kernel version, so it accepts the program and the load refuses it. A `!ebpf.kptr` task (the current task) loads on all four kernels. The address must be an `ebpf.user.addr` result. The task is either the `!ebpf.kptr<"task_struct">` result of `ebpf.task.current_btf` or the `!ebpf.kref<"task_struct">` present block argument of `ebpf.kref.check` (from `bpf_task_from_pid`); other kptrs, `rcu_ptr`, and kptrs from a context argument or field are rejected. The operation does not consume the reference: the writer still releases it, and a use after release is rejected by ownership checking.

    **Lowering**: Stage ③ `copy_from_user_task(reservation + field offset, field length, address, task, 0)`. requirements record the helper and the program's `sleepable` row.

    **Evidence**: Out of scope — not yet in release_scope (no F id until it is measured): static (verifier, lowering shape, C oracle ELF); real kernels.

    **Unsupported**: Non-sleepable programs, other kinds and other sleepable entries; task pointers other than the two above; runtime-length copies; nonzero flags; a status normalized by the compiler. An exited task (no mm) is not measured.
  }];
  let arguments = (ins EBPF_ReservationType:$reservation, StrAttr:$field, EBPF_UserAddrType:$addr, AnyType:$task);
  let results = (outs I64:$status);
  let assemblyFormat = "$reservation $field `,` $addr `,` $task attr-dict `:` type($reservation) `,` type($addr) `,` type($task) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_RingbufSubmitOp : EBPF_Op<"ringbuf.submit"> {
  let summary = "Commit a reservation (consumes it)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Makes a valid reservation visible to userspace readers. **Consumes** it; no subsequent use.

    **Constraints**: Reservation is if_reserved present block argument. Every CFG path submits or discards exactly once: double consumption is kernel use-after-free, omission leaks ring space. Ownership checking rejects later nonconsuming store_field / task.comm etc.

    **Lowering**: Stage ③ ringbuf_submit(ptr, flags0).

    **Evidence**: F02. Ownership rejection and three-target observations / negative controls.

    **Unsupported**: NO_WAKEUP / FORCE_WAKEUP flags; only0.
  }];
  let arguments = (ins EBPF_ReservationType:$reservation);
  let assemblyFormat = "$reservation attr-dict `:` type($reservation)";
}

def EBPF_RingbufDiscardOp : EBPF_Op<"ringbuf.discard"> {
  let summary = "Discard a reservation (consumes it)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Discards it without reader visibility. **Consumes** reservation; no later use.

    **Constraints**: Same as submit: exactly one consumption per present path; post-consumption use rejected.

    **Lowering**: Stage ③ ringbuf_discard(ptr, flags0).

    **Evidence**: F02. Ownership and three-target tests.

    **Unsupported**: Flags other than0.
  }];
  let arguments = (ins EBPF_ReservationType:$reservation);
  let assemblyFormat = "$reservation attr-dict `:` type($reservation)";
}

// Semantics, constraints and evidence: docs/reference/ebpf_ops.md.
def EBPF_RingbufOutputOp : EBPF_Op<"ringbuf.output"> {
  let summary = "bpf_ringbuf_output: copy and commit a record.make result without exposed reservation, returning status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: ringbuf_output(&ringbuf, &rec, sizeof rec, flags) copies every record byte and commits it. **Raw** i64 status is0 or −EAGAIN for insufficient ring space (7.1.8 kernel/bpf/ringbuf.c; same internal __bpf_ringbuf_reserve). No ownership tracking is exposed, unlike reserve / if_reserved / store / submit: helper closes the lifecycle. Absent flags mean0, waking readers only when the consumer has caught up. no_wakeup suppresses notification; force_wakeup always notifies (UAPI ringbufconst).

    **Constraints**: Data is record.make (all bytes, zero padding); named flags limited to no_wakeup / force_wakeup. Schema map kind ringbuf and nominal record name / size must match. Size bound follows reserve: round_up(N + hdr_sz,8) > max_entries−1 fails schema checking, otherwise every call would give −EAGAIN. No kind restriction (base helper prototype). No loop bodies.

    **Lowering**: Stage ③ calls UAPI ringbuf_output with record.make stack data, record size, and UAPI flags.

    **Evidence**: F02. 7.1.8 XDP test runs match C for success / −EAGAIN counts, event bytes, and wakeup notifications.

    **Unsupported**: Variable lengths (use dynptr), non-record data, loop bodies. 6.12 /6.6 unmeasured.
  }];
  let arguments = (ins StrAttr:$ringbuf, EBPF_RecordType:$record, OptionalAttr<StrAttr>:$flags);
  let results = (outs I64:$status);
  let assemblyFormat = "$ringbuf `,` $record (`flags` $flags^)? attr-dict `:` type($record) `->` type($status)";
  let hasVerifier = 1;
}

// Ring-buffer dynptr operations; see docs/reference/ebpf_ops.md.
def EBPF_RingbufReserveDynptrOp : EBPF_Op<"ringbuf.reserve_dynptr"> {
  let summary = "Reserve a runtime-sized ring-buffer dynptr, returning status (consumption required even on failure)";
  let description = [{
    **Stage**: ① Input

    **Meaning**: ringbuf_reserve_dynptr(&ringbuf, size,0,&dynptr) reserves runtime i32 size interpreted u32. Returns stack dynptr<ringbuf> and **raw** i64 status:0, −EINVAL for full ring (unlike output −EAGAIN on7.1.8), −E2BIG beyond dynptr limit2^24−1. **Failed dynptrs must still be consumed**, as kernel verifier requires. They are null; read / write gives −EINVAL, submit / discard does nothing. No NULL-check region; inspect status.

    **Constraints**: Dynptr uses only write / read / submit_dynptr / discard_dynptr, no yield / call / loop capture. No scf.if / loop bodies. Every path from definition through region exit consumes exactly once; later use, crossing loops while live, or reaching tail_call while live is rejected. Schema requires ringbuf map; direct constant size uses reserve's size bound. **No match against map record declaration**: event size / layout are author's responsibility. No loop-called subprograms.

    **Lowering**: Stage ③ allocates16 entry-stack bytes aligned8, used only as helper argument, then calls ringbuf_reserve_dynptr(&map,zext(size),0,slot).

    **Evidence**: F02. 7.1.8 XDP test-run success / status / event bytes match C.

    **Unsupported**: Flags other than0; 6.12 /6.6 unmeasured.
  }];
  let arguments = (ins StrAttr:$ringbuf, I32:$size);
  let results = (outs EBPF_DynptrType:$dynptr, I64:$status);
  let assemblyFormat = "$ringbuf `,` $size attr-dict `:` type($size) `->` type($dynptr) `,` type($status)";
  let hasVerifier = 1;
}

def EBPF_DynptrWriteOp : EBPF_Op<"dynptr.write"> {
  let summary = "bpf_dynptr_write: write an integer at dynptr offset and return raw status";
  let description = [{
    **Stage**: ① Input

    **Meaning**: dynptr_write(&dynptr,offset,&v,N/8,0) writes little-endian i8 /i16 /i32 /i64 at runtime i32 offset as u32. **Raw** i64 status:0, −E2BIG if offset+N/8 exceeds dynptr size, −EINVAL for null failed reservation or read-only dynptr.

    **Constraints**: Direct ringbuf.reserve_dynptr result; read-only user_ringbuf rejected. Integer widths8 /16 /32 /64. No post-consumption use.

    **Lowering**: Stage ③ stores v in scratch and calls dynptr_write(slot_d,zext(offset),&v,N/8,0).

    **Evidence**: F02. Dynptr differential tests.

    **Unsupported**: Records / arrays, variable lengths, or flags.
  }];
  let arguments = (ins EBPF_DynptrType:$dynptr, I32:$offset, AnySignlessInteger:$value);
  let results = (outs I64:$status);
  let assemblyFormat = "$dynptr `[` $offset `]` `,` $value attr-dict `:` type($dynptr) `,` type($value) `->` type($status)";
  let hasVerifier = 1;
}

def EBPF_DynptrReadOp : EBPF_Op<"dynptr.read"> {
  let summary = "bpf_dynptr_read: read an integer and raw status from dynptr offset, returning zero value on failure";
  let description = [{
    **Stage**: ① Input

    **Meaning**: dynptr_read(&v,N/8,&dynptr,offset,0) reads little-endian bytes at runtime i32 offset. Returns iN and **raw** i64 status:0, −E2BIG for out-of-bounds, −EINVAL for null. **Failure value is0**: helper does not write on failure, so stage ③ zeros destination first.

    **Constraints**: Direct ringbuf.reserve_dynptr result or user_ringbuf callback argument. Width8 /16 /32 /64. Post-consumption use rejected.

    **Lowering**: Stage ③ zeros N/8-byte scratch, calls dynptr_read(slot,N/8,slot_d,zext(offset),0), then loads it.

    **Evidence**: F02. Dynptr differential tests.

    **Unsupported**: Record / array reads and bpf_dynptr_data direct pointers.
  }];
  let arguments = (ins EBPF_DynptrType:$dynptr, I32:$offset);
  let results = (outs AnySignlessInteger:$value, I64:$status);
  let assemblyFormat = "$dynptr `[` $offset `]` attr-dict `:` type($dynptr) `->` type($value) `,` type($status)";
  let hasVerifier = 1;
}

def EBPF_RingbufSubmitDynptrOp : EBPF_Op<"ringbuf.submit_dynptr"> {
  let summary = "Commit and consume a dynptr reservation; failed reservations are no-ops";
  let description = [{
    **Stage**: ① Input

    **Meaning**: ringbuf_submit_dynptr(&dynptr,0) commits to the reader and **consumes** dynptr, forbidding later use. Failed/null reservations do nothing.

    **Constraints**: Direct reserve_dynptr result; exactly one submit / discard per path. No scf.if / loop bodies.

    **Lowering**: Stage ③ ringbuf_submit_dynptr(slot_d,0).

    **Evidence**: F02. Dynptr differential tests.

    **Unsupported**: Wakeup flags other than0.
  }];
  let arguments = (ins EBPF_DynptrType:$dynptr);
  let assemblyFormat = "$dynptr attr-dict `:` type($dynptr)";
  let hasVerifier = 1;
}

def EBPF_RingbufDiscardDynptrOp : EBPF_Op<"ringbuf.discard_dynptr"> {
  let summary = "Discard and consume a dynptr reservation; failed reservations are no-ops";
  let description = [{
    **Stage**: ① Input

    **Meaning**: ringbuf_discard_dynptr(&dynptr,0) hides the event from readers; storage remains until consumer passes it. **Consumes** dynptr. Failed reservations do nothing.

    **Constraints**: Same as submit_dynptr.

    **Lowering**: Stage ③ ringbuf_discard_dynptr(slot_d,0).

    **Evidence**: F02. Dynptr differential tests.

    **Unsupported**: Flags other than0.
  }];
  let arguments = (ins EBPF_DynptrType:$dynptr);
  let assemblyFormat = "$dynptr attr-dict `:` type($dynptr)";
  let hasVerifier = 1;
}

// Userspace-to-kernel user_ringbuf operations; see docs/reference/ebpf_ops.md.
def EBPF_UserRingbufCallbackOp : EBPF_Op<"user_ringbuf.callback", [IsolatedFromAbove, Symbol]> {
  let summary = "user_ringbuf drain callback, restricted to sample reads, arithmetic, globals, and time";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Module-level callback invoked for each sample by user_ringbuf.drain, like timer.callback. Sole block argument is dynptr<user_ringbuf> (kernel BPF_DYNPTR_TYPE_LOCAL), read with dynptr.read. Terminates with user_ringbuf.done (continue0) or done stop %c (true stops1). Kernel releases the sample afterward, including the stopping sample.

    **Constraints**: One block, exactly one matching dynptr argument, done terminator. Only arith, dynptr.read of that argument, global.load / global.atomic_add, and ktime.ns; no map ops / other helpers / regions / calls. Stage ③ rejects callbacks unused by any program drain. Allowed as ebpf-compile top-level input.

    **Lowering**: Stage ③ internal/static .text llvm.func(ptr dynptr,ptr ctx)->i64; ctx unused because drain passes NULL. BTF static FUNC long cb(void *dynptr,void *ctx). Requirement reachability follows callback address.

    **Evidence**: F02. 7.1.8 XDP test-run drain results / callback global sums match C.

    **Unsupported**: Map ops, callback ctx (drain third argument), and dynptr writes.
  }];
  let arguments = (ins SymbolNameAttr:$sym_name);
  let regions = (region SizedRegion<1>:$body);
  let assemblyFormat = "$sym_name attr-dict-with-keyword $body";
  let hasVerifier = 1;
}

def EBPF_UserRingbufDoneOp : EBPF_Op<"user_ringbuf.done", [Terminator, HasParent<"UserRingbufCallbackOp">]> {
  let summary = "End a user_ringbuf callback with continue zero or stop one";
  let description = [{
    **Stage**: ① Input

    **Meaning**: Terminates user_ringbuf.callback. No operand returns0 and advances to next sample; stop %c returns1 if true, ending after this sample. Verifier callback range is0..1.

    **Constraints**: Parent user_ringbuf.callback only; stop i1.

    **Lowering**: Stage ③ i64 llvm.return select(c,1,0), or constant0 without operand.

    **Evidence**: F02. User-ring-buffer callback tests.

    **Unsupported**: Other return values.
  }];
  let arguments = (ins Optional<I1>:$stop);
  let assemblyFormat = "(`stop` $stop^)? attr-dict";
}

def EBPF_UserRingbufDrainOp : EBPF_Op<"user_ringbuf.drain"> {
  let summary = "bpf_user_ringbuf_drain: process userspace samples with a callback, returning count or negative errno";
  let description = [{
    **Stage**: ① Input

    **Meaning**: user_ringbuf_drain(&map,callback,NULL,0) passes samples in order. **Raw** i64 result is consumed sample count excluding userspace-DISCARD samples; −EBUSY if another consumer is draining; −EINVAL / −E2BIG for corrupt userspace headers (7.1.8 kernel/bpf/ringbuf.c). Callback stop1 ends after that sample.

    **Constraints**: Program bodies only, no function / callback / loop bodies. Callback names user_ringbuf.callback; schema map kind user_ringbuf.

    **Lowering**: Stage ③ UAPI helper with callback address (pseudo-function ld_imm64), NULL ctx, flags0.

    **Evidence**: F02. User-ring-buffer differential tests.

    **Unsupported**: Wakeup flags other than0, callback context, and measurements on6.12 /6.6.
  }];
  let arguments = (ins StrAttr:$ringbuf, FlatSymbolRefAttr:$callback);
  let results = (outs I64:$status);
  let assemblyFormat = "$ringbuf `,` $callback attr-dict `->` type($status)";
  let hasVerifier = 1;
}

#endif // EBPF_OPS
