# Non-root load and attach

Measured paths, required privileges and known refusals for loading/attaching bpf-mlir programs as **non-root users (uid ≠0) with selected capabilities**. The tables retain measured conditions and distinguish unmeasured claims. Original experiment locators are retained in the development translation correspondence, outside the public package.

## Representative path: xdp-counter with CAP_BPF + CAP_NET_ADMIN

The measured XDP-counter path used pre-load requirements checking, native XDP attachment and a ring-buffer reader. **uid 1000 with only CAP_BPF and CAP_NET_ADMIN** successfully loaded, attached and produced counter/record output on 7.1.8 / 6.12.111 / 6.6.157. The child's /proc status recorded all effective privileges. A root parent prepared the netns/veth; this does not claim unprivileged environment setup.

The non-root child had Uid/Gid 1000 and CapInh/CapPrm/CapEff/CapBnd/CapAmb all 0000008000001000. The binary and parent directories permitted that UID to read/execute; setuid and file-capability binaries were not used. The source package contains the compiler and conformance data, not this development loader or reproduction script.

| Privileges (uid 1000) | Results on all three kernels | Stopping stage |
|---|---|---|
| CAP_BPF + CAP_NET_ADMIN | Native load/attach; counter/ring records >0; -check-target target-ok, undetermined 0 | — |
| CAP_BPF only | Nonzero xdp-counter exit | **Pre-load checking**: XDP program-type probe load returns EPERM, observed in strace-bpf_only.txt, before embedded-program load; probes may create kernel objects such as maps |
| No capabilities | Nonzero exit | RemoveMemlock setup: first bpf(2) returns EPERM |

The CAP_BPF-only failure reports a target-precheck probe failure before embedded-program load. A pre-load probe error is distinct from a definite target mismatch. It can contain a verifier error as its cause, so **classify the precheck failure before its nested verifier error**. Do not infer insufficient privilege versus verifier rejection solely from EPERM/EACCES. Probe EPERM is an error, not Unknown, and stops checking loudly before load.

For an owned interface the same privilege-dropping arrangement applies. Granting file capabilities with setcap is **unmeasured**.

## Measured privileges by program kind

**XDP used a checked loader; other kinds used internal measurement runners**. These observations describe measured load/attach paths, not tools shipped in the source package. Non-root tcx / kprobe / fentry / fexit / uprobe / tp_btf attachments were measured on three kernels.

| Kind/path | Privileges (uid 1000) | Kernel | Observation | Measurement/reproduction boundary |
|---|---|---|---|---|
| xdp, checked native loader | CAP_BPF + CAP_NET_ADMIN | 7.1.8 / 6.12.111 / 6.6.157 | Load/attach/counter/ring buffer | xdp-counter path above |
| xdp, native veth decap/encap delivery | CAP_BPF + CAP_NET_ADMIN | 7.1.8 | 15/15 frames matched | Internal packet-delivery runners |
| xdp devmap redirect | CAP_BPF + CAP_NET_ADMIN | 7.1.8 | 5/5, including devmap update | Internal redirect runner |
| sched_cls / tcx | CAP_BPF + CAP_NET_ADMIN | All three | 4/4; root parent prepares netns, non-root inner attaches | Internal tcx runner |
| kprobe | CAP_BPF + CAP_PERFMON | All three | Perf-kprobe attach; 6/6 results same as root | Internal kprobe runner |
| fentry | CAP_BPF + CAP_PERFMON; CAP_BPF alone load EPERM on 7.1.8 | All three | Attach and observation | Internal entry runner |
| fexit | CAP_BPF + CAP_PERFMON | All three | Attach and return values | Internal exit runner |
| uprobe | CAP_BPF + CAP_PERFMON + **CAP_SYS_ADMIN**; without SYS_ADMIN attach permission denied on 7.1.8 | All three | pos 5, sym 2, other 1 all match root | Internal user-probe runners |
| tp_btf precheck, nullable probe and ebpf-precheck --live | CAP_BPF + CAP_PERFMON | All three | Definite marking answers: 7.1.8/6.12 mark nullable arguments, 6.6 does not. Fork ELF ok on first two, arg_nullable on 6.6, matching root | Nullable-probe / fork-check runners |
| tp_btf load/attach, tpcheck | CAP_BPF + CAP_PERFMON | All three | First two pass checking/load/CO-RE/attach/fork counts like root. 6.6 blocks as arg_nullable; bypassing checking with -no-target gives verifier acceptance, attach and counts | Internal tpcheck, including bypass negative boundary |
| kprobe pointer argument, kind ptr | CAP_BPF + CAP_PERFMON | All three | ebpf/C values match runner buffer address, like root | Pointer-argument runner |
| User stack, IP list / build-id map | Entry/kprobe: CAP_BPF + CAP_PERFMON; uprobe additionally **CAP_SYS_ADMIN**, otherwise attach denied | All three | ebpf/C stack rows match root | User-stack runners; npp means bpf/perfmon, npsa adds sys_admin |
| Timer/spin_lock maps × program kind (F31) | XDP bpf+net_admin; entry/kprobe bpf+perfmon | All three | Accepted combinations attach/fire like C without corrupting lock/timer bytes. **On 6.x, kprobe×timer blocks as map_field for root, but non-root without NET_ADMIN gets undecidable map_field_unknown (nonblocking), then loud verifier rejection**, as designed | Internal map-field differential runners |
| Ring reserve outcome (if_reserved→i1), record-field atomic add | CAP_BPF + CAP_NET_ADMIN | All three | ebpf/C test-run rows match root | Reservation-result / field-atomic runners |
| Representative test-run sweep: records, byte order, percpu/LRU, try_update/delete, signed division, i1, U walk, devmap, uprobe ABI, precheck | bpf+net_admin, and with perfmon; uprobe additionally sys_admin, tracing precheck bpf+perfmon | All three | With perfmon all match root. Without it, only the known B-loop / REASON_PATHS refusals below | Internal sweep |
| Multiple globals per .rodata/.bss section, XDP | CAP_BPF + CAP_NET_ADMIN for load/write/freeze/test-run; **CAP_SYS_ADMIN additionally for BPF_BTF_GET_FD_BY_ID** to inspect map DATASEC (source on all three kernels) | All three | ebpf/clang values match root; DATASEC offsets match root with bpf/net_admin/sys_admin | Globals differential runner |
| ebpf-precheck --live | XDP requires bpf+net_admin; bpf+perfmon gives XDP-type probe EPERM/precheck_failed. kprobe/fentry requires bpf+perfmon | All three | Run checking with loading-process privileges ([requirements §11](requirements_format.md#11-pre-load-checking-process-interface)); insufficient privilege is checking error, fail closed | Precheck privilege runner |
| SYS_ADMIN instead of NET_ADMIN: bpf+perfmon+sys_admin, **downstream measurements, not rerun in bpf-mlir** | XDP/tc load succeeds on 7.1.8/6.12 because bpf_net_capable accepts NET_ADMIN or SYS_ADMIN. 6.6 devmap creation checks NET_ADMIN alone, predicting redirect failure. Uprobe attach succeeded with SYS_ADMIN alone (CapEff 0x200000) on 7.1.8 | 7.1.8 / 6.12; 6.6 inference | go-bpf-mlir runner observation, commit 8870292 | Do not generalize the inferred 6.6 result as a measurement |

Non-root attachments on 6.12.111/6.6.157 cover only the kinds listed above. **Only XDP has a measured non-root generated-binding attach path.**

## Known refusals without CAP_PERFMON

For loaders such as CAP_BPF+CAP_NET_ADMIN, these forms compile but fail kernel verifier load loudly; compiler/requirements were not changed to reject them.

| Form | Kernel | Rejection | Workaround | Evidence boundary |
|---|---|---|---|---|
| Loop IV used as ref.index, adding IV×stride to map-value pointer (F06), same shape in clang C | All three | pointer arithmetic with it prohibited for !root | Add PERFMON; use U/H loop | Internal indexed-loop comparison |
| B loop with header/backedge (F07) | 6.12.111 / 6.6.157; 7.1.8 accepted a small constant-four loop, but unknown-bound/break B loops were observed rejected there as 8193 jumps | too large / 8193 jumps / infinite loop detected, same for C | PERFMON (accepted on three kernels) or U/H | Same refusals in sweep l_lh/l_lph/l_lh_wrongval; the bounded-loop boundary was measured separately |
| Variable packet-pointer addition | All three | permission denied, including pointer arithmetic … !root, same for C | PERFMON: root-equivalent values on three kernels | Variable-offset packet runner |
| Packet walk inside loops: TCP options / IPv6 extension headers advance variable offset through packet.check | All three | permission denied / pointer arithmetic … !root regardless of U/B/H loop shape, same for C | PERFMON: root-equivalent values | Packet-walk differential runner |
| **Different index ranges reach one ref.index addition from different user-if paths**; compiler gives no warning because LLVM decides whether branches survive. E.g. if i<4 { map.update … } before ref.index hist[i], also threshold 2 | All three; root accepts. Threshold ≥element count (one path unreachable after checking), and helper-free arms whose branch LLVM removes, are accepted | R<n> tried to add from different maps, paths or scalars, pointer arithmetic with it prohibited for !root; REASON_PATHS ranges [0,12] / [16,28] | Put ref.index in the user-if arm on the same post-comparison path; add PERFMON | User-check path controls |
| **Constant and unknown indices reach one ref.index addition from different paths** (F06); compiler warns. E.g. lookup-failure default 0, load/store/loop IV | All cases on 6.12/6.6, some on 7.1.8; newer verifier does not treat failed constant-key array lookup as a normal path, so simple forms pass | Same REASON_PATHS text | Place ref.index within index-origin present region; use nonconstant default (accepted on three kernels); add PERFMON; use U/H loops | Sweep x_load/x_store/x_loop/g_rarr/g_mdim/g_d3 still fails with default M1: M1 does not equalize ranges |
| ref.index **after a second comparison of the same index**, where branch direction is known; non-root verifier explores misprediction and makes comparison register unknown | 6.12/6.6 reject; 7.1.8 accepts | math between map_value pointer and register with unbounded min value is not allowed | **Accepted with default M1**: mask on true edge then recheck, guaranteed for arrays whose mask range fits the record; otherwise warning | Second-comparison / rebind / in-loop controls |

## Wider bounded-loop observations

The compiler permits bounded backedges up to 4096 iterations, subject to the
path-product and nesting limits. This is a compiler limit, not a promise that a
kernel will load every permitted loop. A root-loaded integer loop combining a
runtime bound and a trailing stop at N=4096 was accepted on 7.1.8. Both the MLIR
and C forms were rejected on 6.12.111 with "The sequence of 8193 jumps is too
complex." Both returned EFAULT on 6.6.157; no verifier log or processing count was
available. The EFAULT cause and verifier verdict remain unknown. The other ten
measured loop pairs loaded and matched their scalar model on all three kernels.

With CAP_BPF + CAP_NET_ADMIN and no CAP_PERFMON, the runtime-bound N=65
representative loaded on 7.1.8 and was rejected on 6.12.111. On 6.6.157 it returned
EFAULT, so acceptance or rejection is unconfirmed. A separate derived Client
measurement also returned EFAULT on 6.6.157 without PERFMON. Neither result is a
confirmed verifier rejection or evidence that all loops fail there. VM dmesg
snapshots around the wider-loop loads had matching prefixes and empty deltas;
they did not explain the EFAULT. No log was cleared.

## Limits

- External loaders iproute2 / libbpf / bpftool do not read .ebpf_requirements. Privileged or not, pre-load checking requires a separate implementation of the requirements contract; it is not performed by the compiler or these external loaders.
- Claim only the measured capability combinations. Smaller/other combinations, such as SYS_ADMIN alone beyond the explicitly labeled downstream observation, are unmeasured.
- Non-root netns/veth preparation through user namespaces is unmeasured.
- Generic-mode XDP (XDPGenericMode) and non-root attachment to physical NICs are unmeasured.
