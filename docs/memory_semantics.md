# Shared-memory access semantics

- **Date**: 2026-09-25 (initial contract).
- **Scope**: the normative promises made, and not made, by ebpf memory-access operations to the compiler. This is a **compiler-level contract**; kernel versions, CPU memory models and verifier acceptance are not part of these semantics.
- Related operation families: CO-RE, global.load, spin.region and store_record.

## 1. Four categories

| Category | Promises | Does not promise |
|---|---|---|
| **normal** (default) | A read observes the last write in program order under single-thread semantics. The compiler may merge, eliminate or move reads, and eliminate or merge stores | Each access reaching memory, access width or access count |
| **once** (`once` keyword, e.g. `ebpf.ref.field.load once %r "a"`) | **Each execution of that access produces one access of the declared width**: no elimination, merging, duplication, splitting or widening. Program order among once accesses is preserved | Acquire/release, CPU barriers, ordering with other CPUs, atomic read-modify-write, or ordering with normal accesses or accesses inside helpers |
| **atomic** (`ref.atomic_add` / `ref.field.atomic_add` for naturally aligned 32 / 64 bit record fields / `global.atomic_add` / expansion of `map.atomic_add`) | Monotonic atomicrmw add with unused result (non-FETCH: BPF `lock … +=`), 32 / 64 bit | Ordering with other accesses (monotonic), or a FETCH value |
| **atomic** — or (`ref.field.atomic_or` for naturally aligned 32 / 64 bit record fields / `global.atomic_or`) | Atomic or with unused result (non-FETCH: BPF `lock … \|=`), 32 / 64 bit — the same monotonic contract as add | Ordering with other accesses (monotonic — not the seq_cst of C's `__sync_fetch_and_or`, which clang emits as `atomic_fetch_or`), or a FETCH value |
| **atomic** — compare-and-exchange (`ref.field.cmpxchg` / `global.cmpxchg`, 32 / 64 bit) | Atomically compares with expected and writes new when equal; returns the value before the operation either way. The IR ordering is seq_cst (64 bit `cmpxchg … seq_cst seq_cst`); the BPF cmpxchg instruction is a full barrier in the kernel's JITs (x86 `lock cmpxchg`) | Acquire / release as separate orderings, or a weak (spurious-failure) form |
| **synchronization** | `spin.region` emits lock (helper 93) → body → unlock (helper 94); body accesses remain between the calls, whose effects are unknown to the compiler. Ringbuf uses reserve → field writes → submit/discard, checked by ownership analysis | Other synchronization; once is not a synchronization mechanism |

**Once implementation**: LLVM `load volatile` / `store volatile` at the ABI stage. **Once supports only 8 / 16 / 32 / 64 bit integer accesses. An access cannot be once unless the ABI stage can prove natural alignment for its declared width.** Unsupported accesses are rejected loudly as a compiler limitation.
The BPF backend splits under-aligned volatile accesses: measured examples include an i32 load with align 2 becoming two u16 accesses, an i16 store with align 1 becoming two u8 accesses, and an i64 store with align 4 becoming two u32 accesses.

Whether a single once access can **tear** (another CPU observing an intermediate value) depends on the BPF ISA and JIT and is not promised here. A single aligned instruction of at most 8 bytes does not tear on many architectures, but that is outside this compiler contract.

## 2. Historical baseline and current behavior by operation

| Operation | Initial baseline | Evidence | Current contract |
|---|---|---|---|
| `ref.load` / `ref.store` | normal, nonvolatile | ref.load / ref.store lowering in EBPFToBPFABI.cpp | normal by default, volatile with `once` |
| `ref.field.load` / `ref.field.store` | normal; **codegen merged two reads of the same field and removed overwritten stores** | Disassembly: one load plus `r1 += r1`; only the final `c = 2` store remained | Same as above |
| `elem.load` / `elem.store` (ref.index in_range) | normal | Element lowering in EBPFToBPFABI.cpp | Same as above |
| `kfield.load` | **normal, nonvolatile: the old claim that two reads were never merged held only at MLIR level; ELF merged them** | Twice-load and once-load ELF both had six loads; ObjectEmitter CO-RE load | **Always once**, syntax unchanged |
| `global.load` | volatile (equivalent to once) | Global-load implementation | Unchanged; documentation only |
| `ref.atomic_add` and related operations | Monotonic atomicrmw; non-FETCH `lock *(u32 …) +=` / `lock *(u64 …) +=` | Atomic disassembly, instructions 9 / 18 | Unchanged |
| `ref.field.atomic_add` | Same, after GEP to the field offset | Development test `test/Target/EBPF/field-atomic-add.test`; concurrent multi-CPU test runs on three targets did not lose counts, whereas field.load/store `+=` on the same record did | Introduced after the baseline |
| `ref.field.atomic_or` / `global.atomic_or` | — | 64 bit: monotonic `atomicrmw or` → `lock *(u64 …) \|=`. 32 bit: inline asm `lock *(u32 *)($0 + 0) \|= w2` (`r,{r2},~{memory}`) — LLVM rejects a 32-bit atomicrmw or below CPU v3 and ObjectEmitter targets v1. **The `~{memory}` clobber is a compiler barrier only** (LLVM does not move memory accesses across it); the CPU contract is the instruction's, non-FETCH or. Evidence: `test/Target/EBPF/e630-cmpxchg-or.test`, `kernel/atomicmatch` (opcode / imm against clang -mcpu=v3) | Introduced after the baseline |
| `ref.field.cmpxchg` / `global.cmpxchg` | — | 64 bit: `cmpxchg … seq_cst seq_cst` → `r0 = cmpxchg_64`. 32 bit: inline asm `w0 = cmpxchg32_32($1 + 0, w0, w2)` (`={r0},r,{r0},{r2},~{memory}` — this form; r0 holds expected in and the old value out, r2 new). The order is the instruction's full barrier; the clobber is again a compiler barrier. Evidence: as above plus the value paths and mutants in `kernel/atomicmatch`; values and multi-CPU atomicity are | Introduced after the baseline |
| `spin.region` | call 0x5d → body loads/stores → call 0x5e | Spin disassembly, instructions 10–18 | Unchanged |
| Ringbuf reserve → store → submit | call 0x83 → store → call 0x84 | Ringbuf disassembly, instructions 52–57 | Unchanged; once is not accepted because the program exclusively owns the reservation until submit |
| `packet.load` / `window_load` / `packet.store` | normal | — | Outside once support |

## 3. Verification and limits of kernel observations

- Guarantees are supported by **volatile in LLVM IR** (`ebpf-compile --dump-llvm-ir`) and **ELF access counts and widths**. Robustness against future middle-level optimization can be examined by applying `opt -passes='default<O2>'` to dumped IR (development script `kernel/memsem/probe.sh`).
- Single-thread execution gives the same values for normal and once: **kernel execution checks acceptance and value agreement only**. Concurrent-writer tests are weak observations; observing no difference does not disprove once.
- Verifier acceptance is not evidence for once semantics.

## 4. Future design (not implemented)

- If helper memory-effect attributes are added, spin_lock / spin_unlock, map helpers and ringbuf submit must retain memory-clobber declarations. spin.region and ownership rely on helper-call opacity. The normative ordering of once accesses and helpers must then be revisited.
- Extending once to packet accesses requires removing once operations from the C1 sink whitelist and reviewing the W1 assumptions together.

## 5. Packet neutrality and memory effects

- **Packet-neutral query (`PacketNeutral`)**: shared by C1 / W1 consumers. Only operations listed in the classification table are neutral. Unlisted operations, helpers missing from the UAPI table, and pktinval helpers (the union of packet-pointer-invalidating helpers from three kernel sources) stop the transformation. Classification must have a per-helper justification that it does not write the packet.
- **MemoryEffectOpInterface**: packet.load / window_load Read(`ebpf.packet`); packet.store Write(`ebpf.packet`); ringbuf.store_field / store_record only Write(`ebpf.reservation`).
  ref.* / ref.field.* / elem.* (normal and once), helper-calling operations, spin and tail_call have unknown effects at this boundary. Helper calls also have no LLVM memory attributes (the development lit check uses NOATTR).
- The first addition of a packet-pointer-invalidating operation requires an actual negative control placing it inside in_range: C1 must not move across it and W1 must not substitute across it.

## 6. Packet ranges and pointer invalidation

- **The ebpf.packet resource represents packet bytes and ctx data / data_end (the packet bounds).** packet.load / window_load / packet.check read this resource; packet.store writes packet bytes.
- **ebpf.xdp.adjust_head** changes ctx data and the packet start; **ebpf.xdp.adjust_tail** changes ctx data_end. **Both invalidate packet pointers on success and failure**, as recorded by pktinval in the UAPI table. As helpers, they retain unknown MLIR effects, acting as barriers for all resources.
- Earlier windows cannot be reused. The structured-stage exit may-invalidate check rejects a use if any path contains the helper. Reload through a fresh packet.check window, or use packet.load, which reloads ctx data / data_end each time.
- `clone_redirect`, `skb.store_bytes` and `l3_csum_replace` also invalidate windows on success and failure. Store sources are initialized scalar bytes copied to stack immediately before the helper, never a retained packet pointer. A raw helper status does not imply delivery or terminate the original packet's processing. `redirect` remains a terminator and has no pktinval entry.
- C1 / W1 and entry-block substitutions do not cross operations that are not packet-neutral, including adjust_head and adjust_tail; actual-operation negative controls cover both.
