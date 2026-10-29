<!-- Generated from descriptions in include/bpf-mlir/Dialect/EBPF/IR/EBPFOps.td. Do not edit; regenerate with scripts/gen-reference. -->

# ebpf dialect operation reference

Each operation documents **Stage** (① Input = source-writable / ② Internal = created only by ebpf-expand-regions), **Meaning**, **Constraints**, **Lowering**, **Evidence** (feature IDs in [release_scope](../release_scope.md)), and **Unsupported**.
See also [types](ebpf_types.md).

- ① Input operations (143): `ebpf.bloom.peek` `ebpf.break` `ebpf.byteorder.from_be` `ebpf.byteorder.to_be` `ebpf.call` `ebpf.continue` `ebpf.ctx.arg` `ebpf.ctx.field` `ebpf.ctx.field.store` `ebpf.ctx.load` `ebpf.ctx.retval` `ebpf.devmap.lookup` `ebpf.dynptr.read` `ebpf.dynptr.write` `ebpf.elem.load` `ebpf.elem.store` `ebpf.ext.arg` `ebpf.flow_keys.load` `ebpf.flow_keys.store` `ebpf.func` `ebpf.global.atomic_add` `ebpf.global.load` `ebpf.if` `ebpf.if.yield` `ebpf.kernel.read_scalar` `ebpf.kernel.read_str` `ebpf.kfield.copy` `ebpf.kfield.load` `ebpf.kfield.ptr` `ebpf.kfield.store` `ebpf.kfunc.call` `ebpf.kprobe.arg` `ebpf.kptr.addr` `ebpf.kptr.check` `ebpf.kptr.xchg` `ebpf.kref.check` `ebpf.ksyscall.arg` `ebpf.ktime.ns` `ebpf.lirc.sample` `ebpf.loop` `ebpf.loop.yield` `ebpf.lwt.seg6_action` `ebpf.lwt.seg6_adjust_srh` `ebpf.lwt.seg6_store_bytes` `ebpf.map.atomic_add` `ebpf.map.delete` `ebpf.map.for_each` `ebpf.map.for_each.yield` `ebpf.map.inner` `ebpf.map.lookup` `ebpf.map.lookup_percpu` `ebpf.map.peek` `ebpf.map.pop` `ebpf.map.push` `ebpf.map.try_delete` `ebpf.map.try_update` `ebpf.map.update` `ebpf.msg.apply_bytes` `ebpf.msg.cork_bytes` `ebpf.msg.pop_data` `ebpf.msg.pull_data` `ebpf.msg.redirect` `ebpf.packet.check` `ebpf.packet.load` `ebpf.packet.store` `ebpf.packet.window_load` `ebpf.perf.output` `ebpf.probe.retval` `ebpf.probe.target_arg` `ebpf.probe.target_index` `ebpf.program` `ebpf.record.make` `ebpf.redirect` `ebpf.redirect_map` `ebpf.ref.atomic_add` `ebpf.ref.check` `ebpf.ref.field.atomic_add` `ebpf.ref.field.load` `ebpf.ref.field.store` `ebpf.ref.index` `ebpf.ref.load` `ebpf.ref.store` `ebpf.return` `ebpf.ringbuf.discard` `ebpf.ringbuf.discard_dynptr` `ebpf.ringbuf.if_reserved` `ebpf.ringbuf.output` `ebpf.ringbuf.reserve` `ebpf.ringbuf.reserve_dynptr` `ebpf.ringbuf.store_field` `ebpf.ringbuf.store_record` `ebpf.ringbuf.submit` `ebpf.ringbuf.submit_dynptr` `ebpf.seq.write` `ebpf.session.cookie.load` `ebpf.session.cookie.store` `ebpf.session.is_return` `ebpf.sk.assign` `ebpf.sk.redirect` `ebpf.sk.reuseport_cookie` `ebpf.sk.select_reuseport` `ebpf.skb.under_cgroup` `ebpf.sock.map_lookup` `ebpf.sock.map_update` `ebpf.sock.ref_check` `ebpf.sock.release` `ebpf.sock_addr.set_sun_path` `ebpf.spin.region` `ebpf.stack.kernel_id` `ebpf.stack.user_id` `ebpf.storage.delete` `ebpf.storage.get` `ebpf.sys.bpf` `ebpf.sys.close` `ebpf.sysctl.set_new_value` `ebpf.tail_call` `ebpf.task.cgroup_id` `ebpf.task.comm` `ebpf.task.pid_tgid` `ebpf.task.under_cgroup` `ebpf.timer.callback` `ebpf.timer.done` `ebpf.timer.init` `ebpf.timer.set_callback` `ebpf.timer.start` `ebpf.tp.buffer.load` `ebpf.tp.buffer.store` `ebpf.tp.field` `ebpf.tp.field.copy` `ebpf.uprobe.arg` `ebpf.usdt.arg` `ebpf.user.read` `ebpf.user.read_str` `ebpf.user.str_at` `ebpf.user_ringbuf.callback` `ebpf.user_ringbuf.done` `ebpf.user_ringbuf.drain` `ebpf.verdict` `ebpf.verdict.if` `ebpf.xdp.adjust_head` `ebpf.xdp.adjust_tail` `ebpf.xsk.lookup` `ebpf.yield`
- ② Internal operations (14): `ebpf.assume_present` `ebpf.bpf_loop` `ebpf.callback.return` `ebpf.elem.at` `ebpf.elem.in_range` `ebpf.elem.mask` `ebpf.for_each_map_elem` `ebpf.is_present` `ebpf.loop.spill` `ebpf.loop_callback` `ebpf.pkt.check_br` `ebpf.spin.lock` `ebpf.spin.unlock` `ebpf.tail_call.try`

## ① Input operations

### `ebpf.bloom.peek` (ebpf::BloomPeekOp)

_Query possible bloom_filter membership and return raw status (zero or -ENOENT)_

Syntax:

```
operation ::= `ebpf.bloom.peek` $map `,` $value attr-dict `:` type($map) `,` type($value) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Returns 0 if every hash bit is set (possibly present: **false positives are possible**), or -ENOENT if any bit is unset (absent: no false negatives). Result is **raw** i64 helper status.

**Constraints**: bloom_filter only, none key parameter, value matching its integer value type. No loop bodies (compiler restriction).

**Lowering**: Unchanged in ②. Stage ③ stores value in a stack slot and calls map_peek_elem(map, &value). Kernel resolve_map_arg_type changes bloom peek's value parameter to a read argument.

**Evidence**: F59. Inserted / absent values in a zero_seed bloom_filter match C in 7.1.8 XDP test runs.

**Unsupported**: False-positive rate depends on map size / hash count (kernel default 5), not checked at compile time. 6.12 / 6.6 are unverified.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | a BPF map handle with kind, key type and value type |
| `value` | any non-token type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.break` (ebpf::BreakOp)

_Exit the nearest ebpf.loop with an explicit carried-value tuple_

Syntax:

```
operation ::= `ebpf.break` ($values^ `:` type($values))? attr-dict
```

**Stage**: ① Input

**Meaning**: Exits the nearest ebpf.loop; the explicit carried-value tuple becomes loop results.

**Constraints**: Parent is an ebpf.if or ebpf.ref.check arm. Between it and the nearest loop, only ebpf.if / ebpf.ref.check / scf.if may be crossed. Rejected outside loops. Types must match nearest-loop iter_args. Reservation-region exits cannot arise because ring-buffer operations are forbidden in loops.

**Lowering**: Stage ② branches to the exit: after the loop for B, after all copies for U, or callback.return 1 for H (write context and stop).

**Evidence**: F07. Expansion tests, three targets, and H break.

**Unsupported**: Labeled breaks to outer loops; target is always the nearest loop.

Traits: `HasParent<IfOp, RefCheckOp>`, `Terminator`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `values` | variadic of signless integer |



### `ebpf.byteorder.from_be` (ebpf::ByteorderFromBeOp)

_Convert a big-endian integer byte sequence to CPU-order little endian_

Syntax:

```
operation ::= `ebpf.byteorder.from_be` $value attr-dict `:` type($value)
```

**Stage**: ① Input

**Meaning**: Explicitly swaps a network-order value, such as one read by packet.load, into CPU little-endian order.

**Constraints**: Width i16 / i32 / i64; matching input / result types. Allowed in loops.

**Lowering**: Stage ③ llvm.intr.bswap, same as to_be for bpfel; BPF backend emits BPF_END.

**Evidence**: F19. packet→key agrees with C bpf_ntohs / ntohl; removing conversion gives wrong key; three targets.

**Unsupported**: i8 and widths outside 16 / 32 / 64; big-endian target.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `value` | signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | signless integer |



### `ebpf.byteorder.to_be` (ebpf::ByteorderToBeOp)

_Convert a CPU-order little-endian integer to big-endian byte order_

Syntax:

```
operation ::= `ebpf.byteorder.to_be` $value attr-dict `:` type($value)
```

**Stage**: ① Input

**Meaning**: Explicit byte swap to big-endian order. Schema integers are little-endian; network order is explicit through this op, not an implicit type-name rule.

**Constraints**: Width i16 / i32 / i64 (BPF_END widths); input / result types match (AllTypesMatch). Allowed in loops.

**Lowering**: bpfel only; stage ③ llvm.intr.bswap becomes BPF_END be16 / be32 / be64. Same instruction as from_be.

**Evidence**: F19. C bpf_htons / htonl value agreement, packet→key differential tests, three targets.

**Unsupported**: i8 and widths outside 16 / 32 / 64, including i1 / i24 / i128; big-endian target.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `value` | signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | signless integer |



### `ebpf.call` (ebpf::CallOp)

_Direct BPF-to-BPF call to an ebpf.func in the same module_

Syntax:

```
operation ::= `ebpf.call` $callee `(` $args `)` attr-dict `:` functional-type($args, $results)
```

**Stage**: ① Input

**Meaning**: Directly calls an ebpf.func in the same module and returns the callee's integer result.

**Constraints**: Symbol-use checking rejects absent callees, ebpf.program entries, non-functions, and argument / result type mismatches. ebpf-verify-call-graph rejects cycles and depth > 8 frames including entry (a conservative compiler limit), and rejects loop calls whose callee reaches ring-buffer operations. After stage ②, ebpf-verify-structured rechecks recursion and ≤ 8 frames across both calls and bpf_loop callback edges. Checked borrowed references may be passed only within ref.check present regions.

**Lowering**: Unchanged in ②. Stage ③ emits llvm.call, distinct from helper bpfabi.helper_call. Requirements record each program's call-graph reachability set.

**Evidence**: F08, F09. Direct calls, calls inside loops, three-target loop / function tests, cross-function loops on three targets, and callback calls.

**Unsupported**: Indirect calls, function pointers, helper names as callees, and out-of-module functions including kfuncs. The eight-frame compiler limit does not guarantee kernel acceptance.

Interfaces: `SymbolUserOpInterface`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>callee</code></td><td>::mlir::FlatSymbolRefAttr</td><td>flat symbol reference attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `args` | variadic of any non-token type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `results` | variadic of any non-token type |



### `ebpf.continue` (ebpf::ContinueOp)

_Continue the nearest ebpf.loop with explicit carried values, incrementing IV once and rechecking bounds_

Syntax:

```
operation ::= `ebpf.continue` ($values^ `:` type($values))? attr-dict
```

**Stage**: ① Input

**Meaning**: Continues the nearest loop with the explicit carried-value tuple. B increments IV once and rechecks count / bound at the header.

**Constraints**: Same as ebpf.break: parent if / ref.check arm, inside nearest loop, types matching iter_args.

**Lowering**: Stage ② branches to latch (B), current copy's join / next guard (U), or callback.return 0 (H).

**Evidence**: F07. B with continue has two back edges; three-target tests.

**Unsupported**: Labeled continues to outer loops.

Traits: `HasParent<IfOp, RefCheckOp>`, `Terminator`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `values` | variadic of signless integer |



### `ebpf.ctx.arg` (ebpf::CtxArgOp)

_Read a tracing context argument as a kernel-struct pointer or integer_

Syntax:

```
operation ::= `ebpf.ctx.arg` $ctx `[` $index `]` attr-dict `:` type($ctx) `->` type($result)
```

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

Traits: `AlwaysSpeculatableImplTrait`

Interfaces: `ConditionallySpeculatable`, `NoMemoryEffect (MemoryEffectOpInterface)`

Effects: `MemoryEffects::Effect{}`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>index</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | a pointer to an internal kernel struct obtained from tracing arguments or a nullable pointer to an internal kernel struct or 8-bit signless integer or 16-bit signless integer or 32-bit signless integer or 64-bit signless integer |



### `ebpf.ctx.field` (ebpf::CtxFieldOp)

_Read a named context integer field or trusted BTF-struct pointer field_

Syntax:

```
operation ::= `ebpf.ctx.field` $ctx $field (`[` $index^ `]`)? attr-dict `:` type($ctx) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Reads a named field of the kind's CTX struct and returns its declared integer width: xdp_md for XDP, __sk_buff for sched_cls, bpf_sk_lookup, bpf_nf_ctx, bpf_raw_tracepoint_args, or bpf_perf_event_data. perf_event offsets depend on arch pt_regs size, requiring program arch x86_64, UAPI values, and trace_perf arch requirements. Reads after ctx.field.store observe the stored value; not Pure and cannot be reordered / merged.
**Pointer fields** marked btf in capability-table column 8 (e.g. netfilter state → nf_hook_state, skb → sk_buff) return non-NULL !ebpf.kptr<"S">, kernel type PTR_TO_BTF_ID | PTR_TRUSTED. Use CO-RE kfield.load for pointee fields. Flexible arrays with UAPI count 0, such as raw_tp args, require a constant element index: `ebpf.ctx.field %ctx "args"[1] : !ebpf.ctx<"raw_tp"> -> i64`.

**Constraints**: Context must be an ebpf.program entry argument, not static-function context, because attach type matters. Kind must have CTX; field must exist in UAPI ctxfield and abi/ctxaccess.tsv for program type / expected_attach_type / struct / field / r / width. Result width must match. Packet pointer fields data / data_end / data_meta are absent: use packet ops. A btf-marked field permits only the corresponding kptr type, rejecting integer address exposure / another struct name. Non-btf fields cannot yield kptr. S must exist in btf.scope @kernel / schema core.kernel_types. Flexible arrays require index 0..11 (bpf_tracing_ctx_access 8 × MAX_BPF_FUNC_ARGS; KernelABI.h kMaxFlexCtxIndex); scalar indices and fixed-length arrays are rejected.

**Lowering**: Stage ③ bpfabi.ctx_field_load uses UAPI offset + index × element width and capability-table width (eight-byte pointer result for kptr). Exit checks both tables. Stage ④ emits one load at the declared width; verifier ctx access depends on exact offset / width, so it is neither split nor combined. No helper.

**Evidence**: F36, F37. UAPI-header offsetof agreement and all capability rows accepted by 7.1.8 load probes; XDP ingress_ifindex / sched_cls len / mark C differential test runs; raw_tp indexed args test-run / sys_enter attach; sk_lookup five reads and netns attach; netfilter state / skb pointers plus CO-RE reads; child-cgroup bpf_sock / bpf_sock_addr / bpf_sock_ops reads and mark / user_port stores; netns sk_skb len / local_port and sk_msg size / family; reuseport len / eth_protocol / ip_protocol / bind_inany / hash; sk_msg addresses / ports and reuseport migration len; own-thread cpu-clock perf_event sample_period, all compared with C.

**Unsupported**: Type / attach / field / width absent from the table, fixed arrays, struct-valued fields, and narrow loads. Pointee struct names are hand-maintained is_valid_access facts, not checked at load; ctxaccess asks only whether reads are accepted. Compile time does not check raw_tp index against tracepoint argument count; attach rejects excessive max_ctx_offset with -EINVAL in bpf_probe_register.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>index</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | signless integer or a pointer to an internal kernel struct obtained from tracing arguments |



### `ebpf.ctx.field.store` (ebpf::CtxFieldStoreOp)

_Write a writable integer field of a struct context_

Syntax:

```
operation ::= `ebpf.ctx.field.store` $ctx $field `,` $value attr-dict `:` type($ctx) `,` type($value)
```

**Stage**: ① Input

**Meaning**: Writes a context integer field, such as sched_cls __sk_buff.mark. Kernel converts it into a store on the underlying object (e.g. skb).

**Constraints**: Follows ctx.field entry context / CTX / UAPI integer-field rules, requiring a capability-table w row and exact value width. Missing w rows are rejected with a diagnostic listing writable fields.

**Lowering**: Stage ③ bpfabi.ctx_field_store, checked against the table at exit. Stage ④ emits one store at the declared width / offset.

**Evidence**: F36. Writable-row probes and negative controls for read-only fields; sched_cls mark matches C test-run ctx_out.

**Unsupported**: Fields without w rows. Table does not describe value-range restrictions imposed by the kernel; each added capability row needs those checked.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `value` | signless integer |



### `ebpf.ctx.load` (ebpf::CtxLoadOp)

_Read an integer at a fixed byte offset of a user-supplied syscall-program context_

Syntax:

```
operation ::= `ebpf.ctx.load` $ctx `[` $offset `]` attr-dict `:` type($ctx) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Reads a little-endian declared-width integer from syscall BPF_PROG_TEST_RUN ctx_in, an untyped user-supplied byte sequence. Not Pure; reads are not reordered / merged.

**Constraints**: Own syscall entry context with OPS ctx.load. Width i8 / i16 / i32 / i64; offset ≥ 0 and aligned to width (compiler restriction; kernel syscall_prog_is_valid_access does not check alignment). Offset + width ≤ 65535; kernel requires offset < U16_MAX and ctx_size_in ≤ U16_MAX. Test run rejects ctx_in smaller than max accessed offset + width with -EINVAL (max_ctx_offset).

**Lowering**: Stage ③ emits one volatile declared-width load at ctx + offset, not split / merged because verifier checks exact ctx offset / width. No helper.

**Evidence**: F40. Syscall test-run retval and maps match C.

**Unsupported**: Context stores (kernel accepts them and test run writes back to ctx_in) are not exposed. Neither compiler nor requirements describes context layout; byte meanings are a caller / author contract.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>offset</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | signless integer |



### `ebpf.ctx.retval` (ebpf::CtxRetvalOp)

_Read a kernel-function return value from fexit context_

Syntax:

```
operation ::= `ebpf.ctx.retval` $ctx `after` $nargs attr-dict `:` type($ctx) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Reads target return slot N (`after N`, target argument count) after the argument slots, truncating its u64 value to iW. Pure.

**Constraints**: fexit context only; N 0..12; result i8 / i16 / i32 / i64. ebpf-verify-schema checks N / width against required fexit nargs / ret signature. Allowed in loop bodies. Load-time retsig rows check target FUNC_PROTO; mismatch and unknown caps (retsig_unknown) both block.

**Lowering**: Stage ③ truncates bpfabi.ctx_arg's u64 at offset 8 × N. No helper.

**Evidence**: F22. C oracle, retsig, three-target / non-root tests. Too many declared arguments fail verifier doesn't have N-th argument; too few or wrong return width / sign can pass verifier and silently change values, so retsig precheck is the only guard (three targets).

**Unsupported**: Non-fexit, pointer / void results, and fexit argument-reading operations.

Traits: `AlwaysSpeculatableImplTrait`

Interfaces: `ConditionallySpeculatable`, `NoMemoryEffect (MemoryEffectOpInterface)`

Effects: `MemoryEffects::Effect{}`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>nargs</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | signless integer |



### `ebpf.devmap.lookup` (ebpf::DevmapLookupOp)

_Read devmap_hash ifindex and presence_

Syntax:

```
operation ::= `ebpf.devmap.lookup` $map `[` $key `]` attr-dict `:` type($map) `,` type($key) `->` type($ifindex) `,` type($present)
```

**Stage**: ① Input
**Meaning**: Present key yields (ifindex, true); NULL yields (0, false).
**Constraints**: XDP program body; devmap_hash with i32 key / value. No pointer result.
**Lowering**: Unchanged in ②; ③ calls map_lookup_elem and branches on NULL, reading u32 ifindex only when non-NULL.
**Evidence**: F60. 7.1.8 child-netns veth ifindex / missing results match C.
**Unsupported**: devmap, eight-byte values, and entry write / atomic / delete.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | a BPF map handle with kind, key type and value type |
| `key` | any non-token type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `ifindex` | 32-bit signless integer |
| `present` | 1-bit signless integer |



### `ebpf.dynptr.read` (ebpf::DynptrReadOp)

_Bpf_dynptr_read: read an integer and raw status from dynptr offset, returning zero value on failure_

Syntax:

```
operation ::= `ebpf.dynptr.read` $dynptr `[` $offset `]` attr-dict `:` type($dynptr) `->` type($value) `,` type($status)
```

**Stage**: ① Input

**Meaning**: dynptr_read(&v,N/8,&dynptr,offset,0) reads little-endian bytes at runtime i32 offset. Returns iN and **raw** i64 status:0, −E2BIG for out-of-bounds, −EINVAL for null. **Failure value is0**: helper does not write on failure, so stage ③ zeros destination first.

**Constraints**: Direct ringbuf.reserve_dynptr result or user_ringbuf callback argument. Width8 /16 /32 /64. Post-consumption use rejected.

**Lowering**: Stage ③ zeros N/8-byte scratch, calls dynptr_read(slot,N/8,slot_d,zext(offset),0), then loads it.

**Evidence**: F02. Dynptr differential tests.

**Unsupported**: Record / array reads and bpf_dynptr_data direct pointers.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `dynptr` | a kernel dynptr, an opaque 16-byte stack object describing a runtime-sized memory window |
| `offset` | 32-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `value` | signless integer |
| `status` | 64-bit signless integer |



### `ebpf.dynptr.write` (ebpf::DynptrWriteOp)

_Bpf_dynptr_write: write an integer at dynptr offset and return raw status_

Syntax:

```
operation ::= `ebpf.dynptr.write` $dynptr `[` $offset `]` `,` $value attr-dict `:` type($dynptr) `,` type($value) `->` type($status)
```

**Stage**: ① Input

**Meaning**: dynptr_write(&dynptr,offset,&v,N/8,0) writes little-endian i8 /i16 /i32 /i64 at runtime i32 offset as u32. **Raw** i64 status:0, −E2BIG if offset+N/8 exceeds dynptr size, −EINVAL for null failed reservation or read-only dynptr.

**Constraints**: Direct ringbuf.reserve_dynptr result; read-only user_ringbuf rejected. Integer widths8 /16 /32 /64. No post-consumption use.

**Lowering**: Stage ③ stores v in scratch and calls dynptr_write(slot_d,zext(offset),&v,N/8,0).

**Evidence**: F02. Dynptr differential tests.

**Unsupported**: Records / arrays, variable lengths, or flags.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `dynptr` | a kernel dynptr, an opaque 16-byte stack object describing a runtime-sized memory window |
| `offset` | 32-bit signless integer |
| `value` | signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.elem.load` (ebpf::ElemLoadOp)

_Load a checked array element_

Syntax:

```
operation ::= `ebpf.elem.load` (`once` $once^)? $elem attr-dict `:` type($elem) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Reads !ebpf.elem<iN> validated by ref.index in_range. once follows ref.load (volatile at ③).

**Constraints**: Result matches iN. Elements exist only as ref.index in_range block arguments, so uses are confined there. once requires 8–64 bits and natural alignment provable at ③ from offset / dimension strides.

**Lowering**: Stage ③ loads elem.at address with alignment proven from constant offset / strides.

**Evidence**: F06, F29. Variable / multidimensional array tests, three targets, once.

**Unsupported**: Uses outside in_range or inside out_of_range.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>once</code></td><td>::mlir::UnitAttr</td><td>unit attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `elem` | a bounds-checked array-element reference |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | signless integer |



### `ebpf.elem.store` (ebpf::ElemStoreOp)

_Store to a checked array element_

Syntax:

```
operation ::= `ebpf.elem.store` (`once` $once^)? $elem `,` $value attr-dict `:` type($elem) `,` type($value)
```

**Stage**: ① Input

**Meaning**: Writes an integer to an element checked by ref.index in_range. once follows ref.store.

**Constraints**: Value type equals element iN; in_range only. Callees cannot use this documented form because ref.index excludes subprogram-argument borrows. once restrictions follow elem.load.

**Lowering**: Stage ③ stores to elem.at address with provable alignment; once adds volatile.

**Evidence**: F06, F29. Variable / multidimensional array tests, three targets, once.

**Unsupported**: Uses outside in_range.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>once</code></td><td>::mlir::UnitAttr</td><td>unit attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `elem` | a bounds-checked array-element reference |
| `value` | signless integer |



### `ebpf.ext.arg` (ebpf::ExtArgOp)

_Read an argument of the function replaced by an ext/freplace program_

Syntax:

```
operation ::= `ebpf.ext.arg` $ctx `[` $index `]` attr-dict `:` type($ctx) `->` type($result)
```

**Stage**: ① Input

**Meaning**: ext replaces another BPF program's global function and receives its arguments rather than a context pointer. Reads argument index from a 64-bit BPF register, truncated to result integer width. Pure.

**Constraints**: Context kind must have OPS ext.arg (ext). Index 0..4 (five BPF function arguments); result i8 / i16 / i32 / i64. ebpf-verify-schema requires index < schema nargs and width matching args[index]. ProgramOp permits only ext.arg to use ext entry ctx.
Load-time attach freplace / extret nargs ret / extarg rows (format 11) check the loader-supplied target program BTF FUNC for global linkage, argument count, and integer width / sign of arguments / return. ebpf-precheck --ext-target is required; absence blocks with ext_target_unknown. **Kernel btf_check_func_type_match checks only argument size and return BTF kind**, so wrong argument sign or return width can pass the kernel and silently corrupt values; precheck is the guard.

**Lowering**: Stage ③ emits entry llvm.func `@p(i64 × (highest used index + 1)) -> i32|i64` and truncates the selected argument. ebpf-build-btf constructs FUNC_PROTO from schema (`u<ret> (u<a0> arg0, …)`, unsigned).

**Evidence**: F47. On 7.1.8, four C/ebpf combinations replacing one-argument g agree in test runs; i64-returning replong passes kernel but fails ext_target precheck.

**Unsupported**: Pointer arguments (context structs / memory); omitted unread-argument declarations (BTF needs all widths, so schema args declares all integers). 6.12 / 6.6 are unverified.

Traits: `AlwaysSpeculatableImplTrait`

Interfaces: `ConditionallySpeculatable`, `NoMemoryEffect (MemoryEffectOpInterface)`

Effects: `MemoryEffects::Effect{}`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>index</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | 8-bit signless integer or 16-bit signless integer or 32-bit signless integer or 64-bit signless integer |



### `ebpf.flow_keys.load` (ebpf::FlowKeysLoadOp)

_Read a named integer field of flow_dissector's bpf_flow_keys_

Syntax:

```
operation ::= `ebpf.flow_keys.load` $ctx $field (`[` $index^ `]`)? attr-dict `:` type($ctx) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Reads through ctx flow_keys (PTR_TO_FLOW_KEYS) into UAPI struct bpf_flow_keys, returning raw declared-width bits. Kernel zeros it before execution and initializes nhoff, thoff (= nhoff), n_proto (Ethernet h_proto, network order), and flags (BPF_FLOW_DISSECTOR_F_*). Reads observe these inputs and earlier program stores; not Pure. Four-element ipv6_src / ipv6_dst require constant indices, e.g. ipv6_src[2] -> i32. Network-order n_proto / sport / dport / addresses / flow_label preserve byte order as raw integers; use ebpf.byteorder to convert.

**Constraints**: Own program entry context with OPS flow_keys (flow_dissector), not static functions. Field is a UAPI ctxfield bpf_flow_keys row; result width matches (i8 / i16 / i32). Four-element fields require index 0..3; scalar fields reject indices.

**Lowering**: Stage ③ performs one volatile eight-byte pointer load at UAPI __sk_buff.flow_keys offset, then one volatile declared-width load at field offset + index × width. Kernel check_flow_keys_access checks only off + size ≤ sizeof(struct bpf_flow_keys). No helper or requirements row.

**Evidence**: F50. IPv4 / IPv6 TCP / UDP dissectors match equivalent C test-run data_out (flow_keys) and retval on 7.1.8.

**Unsupported**: Not an abi/ctxaccess.tsv capability row: this is not a ctx access, so ctxprobe does not cover it. Fields beyond an older kernel's struct end (e.g. flags / flow_label) fail verifier at load; compiler does not inspect kernel versions.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>index</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | signless integer |



### `ebpf.flow_keys.store` (ebpf::FlowKeysStoreOp)

_Write a named bpf_flow_keys integer field as flow_dissector output_

Syntax:

```
operation ::= `ebpf.flow_keys.store` $ctx $field (`[` $index^ `]`)? `,` $value attr-dict `:` type($ctx) `,` type($value)
```

**Stage**: ① Input

**Meaning**: Writes raw integer bits to flow_keys fields: nhoff / thoff / addr_proto / is_frag / is_first_frag / is_encap / ip_proto / n_proto / sport / dport / ipv4_src / ipv4_dst / ipv6_src / ipv6_dst elements / flags / flow_label. For BPF_OK or other verdicts except flow_dissector_continue, kernel __skb_flow_bpf_to_target copies them into flow keys. Kernel then clamps nhoff to [original nhoff, hlen] and thoff to [nhoff, hlen]. flow_dissector_continue (129) resumes the kernel dissector and ignores stores, though test-run data_out retains them.

**Constraints**: Same as flow_keys.load: flow_dissector entry ctx, UAPI field, matching width, index 0..3 for four-element fields. Integer values only; the type system excludes pointers, which the kernel rejects as leaks addr into flow keys.

**Lowering**: Stage ③ performs one volatile ctx pointer load, then one volatile declared-width store at field offset + index × width. No helper or requirements row.

**Evidence**: F50. 7.1.8 test-run complete data_out fields and ok / drop / flow_dissector_continue verdict combinations match C, including thoff clamping.

**Unsupported**: No actual netns flow-dissector-link / traffic hash / RPS observation (test runs only). Compile time does not enforce meanings such as thoff ≥ nhoff; kernel clamps them.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>index</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `value` | signless integer |



### `ebpf.func` (ebpf::SubprogramOp)

_Directly called BPF subprogram (static or global)_

Syntax:

```
operation ::= `ebpf.func` $sym_name $linkage $function_type (`maps` $map_symbols^)? attr-dict-with-keyword $body
```

**Stage**: ① Input

**Meaning**: A BPF-to-BPF call target with static or global linkage. The kernel verifies static functions in caller context, but global functions independently from argument BTF types.
At most five arguments: i8 / i16 / i32 / i64 or !ebpf.maybe_ref / !ebpf.borrowed pointing to such integers or records. **Static functions may also take !ebpf.pkt_window<N>**, passed from a caller's packet.check in_range region. Three-kernel verifier observations preserve packet pointers / bounds across static calls. A callee window may be used only by packet.window_load, packet.store (only if all reaching programs are XDP; stage ③ checks), or calls to other static functions. Global-window arguments are verifier-rejected: the kernel treats global pointer arguments as non-packet memory.
**Static functions may take caller context !ebpf.ctx<"K">**. Three-kernel observations over seven kinds preserve PTR_TO_CTX. Context type fixes one callee kind. Permitted uses are packet.load / packet.check / stack.kernel_id / stack.user_id / perf.output and calls to other static functions. Attach-dependent ctx.arg / ctx.retval / kprobe.arg / uprobe.arg are explicitly rejected: checking one caller's schema would not cover callers attached elsewhere. Invalidating xdp.adjust_head / adjust_tail / tail_call are also rejected, as are global context arguments.
Exactly one integer result is required. Entry arguments are followed by map handles corresponding by position to `maps [...]`.

**Constraints**: The op verifier rejects unknown linkage, six or more arguments, i1 / kptr or other unsupported argument types, non-single-integer results, global contexts, context after map handles, and exits other than ebpf.return. Reference arguments support ref.check / ref.load / ref.field.load / ref.store / ref.field.store / ref.atomic_add / ref.field.atomic_add and forwarding through ebpf.call. Passing an lpm_trie value to a writing callee, including transitively, is rejected; these values remain read-only in programs. Lock / timer fields follow program rules.
ebpf-verify-call-graph requires no recursion, reachability from a program, and ≤ 8 frames. Loops in callees have path depth ≤ 2 and product ≤ 64 from the program entry.

**Lowering**: Stage ② expands bodies like programs and removes functions made unreachable by expansion. Stage ③ emits noinline .text llvm.func: internal for static, external for global. Global borrowed arguments carry arg:nonnull through BTF DECL_TAG and requirements argtag.

**Evidence**: F08. Three-target C noinline oracle; op / call graph / reference arguments; three-target arg:nonnull; record borrows; callee / callback loops; lit for static context arguments.

**Unsupported**: Reservation, kptr, and pointer arguments except the static window / context cases; attach-dependent and invalidating callee operations; pointer returns; functions without results. spin.region and timer operations require program bodies. A function called from a loop cannot reach ring-buffer operations.

Traits: `IsolatedFromAbove`

Interfaces: `Symbol`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>sym_name</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>linkage</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>function_type</code></td><td>::mlir::TypeAttr</td><td>type attribute of function type</td></tr>
<tr><td><code>map_symbols</code></td><td>::mlir::ArrayAttr</td><td>symbol ref array attribute</td></tr>
</table>



### `ebpf.global.atomic_add` (ebpf::GlobalAtomicAddOp)

_Atomically add to a schema core.globals bss variable_

Syntax:

```
operation ::= `ebpf.global.atomic_add` $name `,` $delta attr-dict `:` type($delta)
```

**Stage**: ① Input

**Meaning**: Adds delta atomically to a .bss global without returning a value (non-FETCH).

**Constraints**: Delta i32 / i64 only (BPF atomics). Schema checks declared name / width and bss section in both program / function bodies; rodata is frozen after load. Older behavior missed function-body rodata writes / width mismatches. No timer.callback; loops allowed.

**Lowering**: Stage ③ addressof placeholder global plus monotonic llvm.atomicrmw add, like ref.atomic_add. No helper.

**Evidence**: F26. Four-thread concurrent counts match C; rodata additions fail compile, post-load updates fail kernel EPERM; three-target / non-root and function-body checks.

**Unsupported**: 8 / 16-bit additions, FETCH, other atomics (and / or / xchg / cmpxchg), and rodata additions.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>name</code></td><td>::mlir::FlatSymbolRefAttr</td><td>flat symbol reference attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `delta` | signless integer |



### `ebpf.global.load` (ebpf::GlobalLoadOp)

_Read a schema core.globals variable_

Syntax:

```
operation ::= `ebpf.global.load` $name attr-dict `:` type($result)
```

**Stage**: ① Input

**Meaning**: Reads a named integer global in rodata or bss. Volatile, like C const volatile, prevents assuming its value. ELF symbols determine byte positions; compiler does not calculate layout. Loader sets / freezes rodata before load; verifier tracks the configured value as constant.

**Constraints**: No op verifier. ebpf-verify-schema checks declared name / width in **both program and function bodies**; older behavior missed functions. No timer.callback; allowed in loops. Schema rejects map / program name collisions; stage ③ rejects other symbol collisions.

**Lowering**: Stage ③ emits addressof of a placeholder llvm.mlir.global marked ebpf.global and a volatile load aligned to width/8. BuildBTF creates btf.var in .rodata / .bss DATASEC. No helper.

**Evidence**: F26. C oracle; rodata configuration; three-target DATASEC / CheckGlobals (cilium replaces zero-size DATASEC offsets from symbols and does not inspect VAR type); function-body validation.

**Unsupported**: Non-integer globals (arrays / records), .data, and post-load rodata updates. Go LoadObjectsWithRodata configures before load.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>name</code></td><td>::mlir::FlatSymbolRefAttr</td><td>flat symbol reference attribute</td></tr>
</table>

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | signless integer |



### `ebpf.if` (ebpf::IfOp)

_Conditional regions joining with if.yield or exiting a loop with break / continue_

Syntax:

```
operation ::= `ebpf.if` $cond (`->` type($results)^)? $thenRegion `else` $elseRegion attr-dict
```

**Stage**: ① Input

**Meaning**: An i1 selects then / else regions, returning integers only. Each arm joins via ebpf.if.yield or exits the nearest ebpf.loop via ebpf.break / continue. Also usable outside loops.

**Constraints**: Arms take no arguments and end in if.yield / break / continue. If both exit, no results are permitted. Allowed in loops; stage-② expansion estimate counts it as four operations.

**Lowering**: Stage ② creates cf.cond_br, then / else blocks, and a merge block with result block arguments. Unreachable blocks after two exiting arms are removed so requirements match ELF instructions. Absent at ③.

**Evidence**: F07. break / continue, nesting, three-target tests, and result-width / i1 differential tests.

**Unsupported**: Non-integer results (references / reservations / records) and missing else; express an empty else with valueless if.yield. Result widths are i1 or 8 / 16 / 32 / 64 only; other widths are verifier-rejected (older behavior accepted i1–i128). i1 has three-target differential evidence in kernel/cmd/i1check. Loop-carried values remain i8 / i16 / i32 / i64.

Traits: `RecursiveMemoryEffects`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `cond` | 1-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `results` | variadic of signless integer |



### `ebpf.if.yield` (ebpf::IfYieldOp)

_Join an ebpf.if arm normally_

Syntax:

```
operation ::= `ebpf.if.yield` ($values^ `:` type($values))? attr-dict
```

**Stage**: ① Input

**Meaning**: Normal ebpf.if arm join; operands become parent results.

**Constraints**: Parent is ebpf.if only; operand types must match its result types.

**Lowering**: Stage ② emits cf.br to the merge block with values as block arguments.

**Evidence**: F07. Conditional-region expansion tests.

**Unsupported**: Non-integer values.

Traits: `HasParent<IfOp>`, `Terminator`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `values` | variadic of signless integer |



### `ebpf.kernel.read_scalar` (ebpf::KernelReadScalarOp)

_Read a fixed-width scalar from a ptr kprobe argument, returning value and raw helper status_

Syntax:

```
operation ::= `ebpf.kernel.read_scalar` $addr `offset` $offset attr-dict `:` type($addr) `->` type($value) `,` type($status)
```

**Stage**: ① Input

**Meaning**: Reads a fixed-width scalar through a ptr-declared kprobe argument and returns raw helper status.

**Constraints**: Ordinary x86_64 kprobe only. Address is the direct i64 result of entry-context kprobe.arg, declared ptr in schema params. Constant offset0..4095; width8 /16 /32 /64.

**Lowering**: Compiler-owned aligned eight-byte scratch is zeroed before probe_read_kernel. Failure returns value0 / raw negative i64 status; success status0. ptr declaration implies neither pointee layout nor address space. Ignoring status conflates a failed read with successful zero. Effectful memory read, not Pure; scratch cannot escape.

**Evidence**: F24. On7.1.8 /6.12.111 /6.6.157, 45 C/compiler pairs (nine public,36 private) match value / raw status / hit. Host-status and7.1.8-VM value mutations produce distinct differences. Close / FD / bounded disappearance match for own599 IDs. Private arms are VM-only with FixtureCaps auxiliary oracle, not public-module support. ABI matches kernel/ksyscall helper113 scratch.

**Unsupported**: Public module caps, pointee-layout checking, uprobe fixed-length reads, variable widths / offsets, and memory stores.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>offset</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `addr` | 64-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `value` | signless integer |
| `status` | 64-bit signless integer |



### `ebpf.kernel.read_str` (ebpf::KernelReadStrOp)

_Read a kernel-struct char-pointer string into a reserved byte array, returning raw helper status_

Syntax:

```
operation ::= `ebpf.kernel.read_str` $reservation $path `,` $ptr $field attr-dict `:` type($reservation) `,` type($ptr) `->` type($status)
```

**Stage**: ① Input

**Meaning**: CO-RE reads a kptr<S> field declared kind strptr, then probe_read_kernel_str copies its kernel string into a checked ring reservation byte array. **Raw** i64 status is length including NUL on success, or array count when truncated (last byte NUL); disallowed NULL / user addresses give -ERANGE, read faults -EFAULT. Negative status zeros the entire field. **Empty string returns1**, same implementation on all three kernels, without user.read_str's version difference. Success leaves bytes after NUL unchanged, so initialize all bytes first with record.make → store_record. Nonconsuming.

**Constraints**: Nonempty field / destination paths, record reservation. kptr verification requires strptr (BTF PTR → eight-bit INT). Destination is one-dimensional eight-bit integer array of1..64 elements. Placement follows task.comm / user.read_str: present only, not absent / post-consumption / scf.if / loop-called subprogram. No compile-time kind restriction; load checks helper, which kernel withholds without CAP_PERFMON. Requirements kfield strptr minimum format15 checks target pointer whose qualifier / typedef-stripped pointee is a one-byte integer.

**Lowering**: Stage ③ core_field_load eight-byte pointer; ④ __ebpf_core.S.field becomes preserve.struct.access.index plus volatile load. Then probe_read_kernel_str(reservation + path offset, count, pointer).
**Embedded paths** (F76): At most three a.b.c levels, intermediate embedded structs only (no pointer / union / array), existing leaf rules. Chained CO-RE and format17 path / all-prefix struct:T rows check target names. Unknown blocks load.

**Evidence**: F23. Kernel-string field tests.

**Unsupported**: Pointer traversal in intermediate paths, chained char pointers, non-reservation destinations, and non-x86_64 address rules (copy_from_kernel_nofault_allowed is architecture-specific). Status is not normalized.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>path</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `reservation` | a successful ring-buffer reservation, linearly consumed exactly once |
| `ptr` | a pointer to an internal kernel struct obtained from tracing arguments |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.kfield.copy` (ebpf::KFieldCopyOp)

_Copy fixed N bytes from a kernel-struct array field into a borrowed record or ring reservation array (CO-RE)_

Syntax:

```
operation ::= `ebpf.kfield.copy` $ptr $field `,` $dst $path attr-dict `:` type($ptr) `,` type($dst)
```

**Stage**: ① Input

**Meaning**: Copies all N bytes from a kptr<"S"> struct's declared eight-bit-integer array to an equal-length eight-bit record array. **Fixed N bytes**: neither NUL nor trailing bytes are interpreted; no string truncation. Destination is !ebpf.borrowed<!ebpf.record<…>> or checked !ebpf.reservation<!ebpf.record<…>>. No result; copying does not consume the reservation.

**Constraints**: Nonempty source field / destination path, borrowed record or record reservation. ebpf-verify-kptr requires an N-element eight-bit source array and equal-N one-dimensional destination array. Reservation placement follows task.comm: present region only, not absent, after consumption, inside scf.if, or in loop-called subprograms, checked by if_reserved / ownership / call graph. Requirements kfield [N]i8 checks target BTF element width / count; cilium alone does not check array length.

**Lowering**: Stage ③ core_field_addr locates the field through CO-RE; stage ④ __ebpf_core_addr.<S>.<field> is expanded by ObjectEmitter into llvm.preserve.struct.access.index. Emit N volatile byte loads and byte stores to destination pointer + record-field offset, without helper calls (direct comm-read shape).
**Embedded paths** (F76): Up to a.b.c, at most three levels, intermediate embedded structs only (no pointer / union / array); leaf retains this op's type rules. Chained CO-RE intrinsics plus format17 path / all-prefix struct:T rows also check intermediate target type names. Unknown blocks load.

**Evidence**: F23. task->comm 16 bytes match C on three kernels × root / {bpf, perfmon}; reservation destination tests.

**Unsupported**: Non-record destinations (stack / packet / untyped reservation). N outside 1..64. NUL-terminated probe_read_kernel_str semantics are separate work. Wrong N can silently copy only a prefix or bytes of subsequent fields; only kfield [N]i8 precheck prevents it.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>path</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ptr` | a pointer to an internal kernel struct obtained from tracing arguments |
| `dst` | a checked borrowed reference without ownership or a successful ring-buffer reservation, linearly consumed exactly once |



### `ebpf.kfield.load` (ebpf::KFieldLoadOp)

_Read a kernel-struct field with CO-RE_

Syntax:

```
operation ::= `ebpf.kfield.load` $ptr $field attr-dict `:` type($ptr) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Reads named field through kptr<S> or checked kfunc-acquired kref<S>. Borrowed read does not consume the reference. Field-byte-offset relocation is resolved against target BTF at load. **Always once**: one volatile load per occurrence, never merged. Treated as effectful.

**Constraints**: Nonempty field; result i8 / i16 / i32 / i64. S is btf.scope @kernel struct from schema core.kernel_types. Local fields are little-endian integers with naturally aligned placeholder offsets in declaration order. ebpf-verify-kptr checks member presence / width. Load-time kfield iN|uN checks target BTF. kfield_unknown also blocks (policy2); caps lacking KernelTypes, e.g. bpftool-recorded ebpf-target, stop CO-RE ELF loads.

**Lowering**: Stage ③ core_field_load has no offset and is Conditional. Stage-④ marker __ebpf_core.S.field becomes preserve.struct.access.index plus volatile declared-width B / H / W / DW load. Only CO-RE modules run the BPF backend PipelineStartEP pass.
**Embedded paths** (F76): Up to three a.b.c levels; intermediate embedded structs only, no pointer / union / array. Leaf retains existing type rules. Chained CO-RE plus format17 path / prefix struct:T rows check intermediate names. Unknown blocks load.

**Evidence**: F23, F49, F56. CO-RE relocation / offline oracle; load checks; @kernel validation; always-once correction after merged loads; 8 / 16 / 64-bit C agreement per fork on three kernels × root / {bpf, perfmon} with kernel/cmd/kfieldcheck; kref pid / tgid; 6.12.111 VM sched_ext_ops.tick task_struct.tgid with a compiler callback composed into a C donor (composition only in runner).

**Unsupported**: Bitfields / unions. Pointer fields use kfield.ptr; eight-bit arrays use kfield.copy; neither accepts kref in the original acquired-reference extension. No loop bodies. cilium CO-RE poisons missing fields instead of reporting errors, and **does not rewrite load width or check width / sign**. Narrow declarations such as u32 for target u64 can pass verifier and silently read low bits; wider reads fail access beyond the end of member. Only kfield precheck guards correct width / sign.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ptr` | a pointer to an internal kernel struct obtained from tracing arguments or a checked owned kernel-struct reference, consumed exactly once by release or map transfer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | signless integer |



### `ebpf.kfield.ptr` (ebpf::KFieldPtrOp)

_Read a nullable kernel-struct pointer field using CO-RE_

Syntax:

```
operation ::= `ebpf.kfield.ptr` $ptr $field attr-dict `:` type($ptr) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Reads named field declared {kind:kptr,struct:T} from !ebpf.kptr<"S">, yielding !ebpf.kptr_or_null<"T">. Uses an eight-byte CO-RE field-offset read, always once. **Result is always nullable**; pointee reads require kptr.check present.

**Constraints**: Nonempty field name. ebpf-verify-kptr checks S member points to T; load-time kfield ptr:T checks target BTF pointer-to-struct T.

**Lowering**: Stage ③ core_field_load yields pointer; ④ marker __ebpf_core.<S>.<field> becomes preserve.struct.access.index plus an eight-byte volatile load. Local member BTF is PTR → struct T.
**Embedded paths** (F76): Up to three a.b.c levels; intermediate embedded structs only, not pointer / union / array; leaf retains this op's rules. Chained CO-RE and format17 path / all-prefix struct:T rows check intermediate target names. Unknown blocks load.

**Evidence**: F23. task->real_parent->tgid, task->mm->total_vm, and task->vfork_done (NULL / absent in ordinary fork) match C.

**Unsupported**: Kernel verifier determines traversed pointer type from base / field: trusted-base __safe_rcu fields can be non-NULL RCU pointers, while unlisted fields use PROBE_MEM (NULL silently reads zero). Compiler does not know that list and always requires a nullable check. No RCU lifetime guarantee or non-struct pointer such as char*.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ptr` | a pointer to an internal kernel struct obtained from tracing arguments |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | a nullable pointer to an internal kernel struct |



### `ebpf.kfield.store` (ebpf::KFieldStoreOp)

_Store a kernel-struct integer field with CO-RE (struct_ops only)_

Syntax:

```
operation ::= `ebpf.kfield.store` $ptr $field `,` $value attr-dict `:` type($ptr) `,` type($value)
```

**Stage**: ① Input

**Meaning**: The write counterpart of kfield.load: one volatile declared-width store at the relocated field address through kptr<S>. No result.

**Constraints**: Nonempty field, i8 / i16 / i32 / i64 value, enclosing kind with OPS kfield.store (struct_ops only). Kernel allows BTF-pointer writes only where program-type btf_struct_access permits; tracing is rejected. kptr checking requires @kernel S with a matching-width integer member, not array / pointer. Requirements kfield iN|uN check target BTF as for reads. **Kernel decides writable fields**: tcp_congestion_ops bpf_tcp_ca_btf_struct_access permits selected tcp_sock fields such as snd_cwnd / snd_cwnd_cnt / snd_cwnd_stamp / snd_ssthresh / ecn_flags; others fail verifier. Compiler has no list.

**Lowering**: Stage ③ core_field_addr, stage-④ __ebpf_core_addr.S.field expanded by ObjectEmitter to preserve.struct.access.index, then a volatile declared-width store. Integer-field kfield requirements match reads.

**Evidence**: F49. 7.1.8 Reno-style tcp_congestion_ops cong_avoid writes snd_cwnd / snd_cwnd_cnt; netns client cwnd grows as with C.

**Unsupported**: Non-struct_ops (tracing BTF pointers read-only), bitfields / arrays / pointer fields. 6.12 / 6.6 unverified.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ptr` | a pointer to an internal kernel struct obtained from tracing arguments |
| `value` | 8-bit signless integer or 16-bit signless integer or 32-bit signless integer or 64-bit signless integer |



### `ebpf.kfunc.call` (ebpf::KfuncCallOp)

_Call a named kfunc using UAPI-declared types, flags, and program types_

Syntax:

```
operation ::= `ebpf.kfunc.call` $callee `(` $args `)` attr-dict `:` functional-type($args, $results)
```

**Stage**: ① Input

**Meaning**: Calls a kernel BTF-published function, e.g. bpf_task_from_pid(i32) -> kref_or_null<task_struct>. UAPI kfunc rows define name, signature, flags (KF_ACQUIRE / KF_RELEASE / KF_RET_NULL), and allowed program types. ebpf-abigen generates them from vmlinux FUNC_PROTO and kernel BTF_ID_FLAGS / register_btf_kfunc_id_set, not manual edits. Integer table types match widths. *S arguments accept kref<S> or kptr<S>, except release requires kref and **consumes it**. acquire + ret_null returns kref_or_null checked by kref.check; acquire alone returns kref. void has no result.

**Constraints**: Name must exist; flags must be known (acquire / release / ret_null / rcu); argument count / types / result must match. Release requires exactly one *S argument. Pointer results without acquire are rejected (unowned returns unsupported). Enclosing program type must be listed. Only program bodies: no func / callback / loop / map.for_each / scf.if / spin.region, which ownership checking does not traverse. Every kref path must release exactly once; every kref_or_null path must check exactly once. Ownership diagnostics identify missing release / double release / use after release.

**Lowering**: Stage ③ emits bpfabi.kfunc_call; exit checking validates table and leaves availability as Unknown for load-time loader / verifier. Stage ④ emits llvm.call to extern .ksyms llvm.func. ObjectEmitter attaches DISubprogram declaration with signature and local CO-RE structs for *S; BPF backend emits extern BTF FUNC / FUNC_PROTO / .ksyms DATASEC, call -1 (src_reg1), and R_BPF_64_32 relocation like clang __ksym. Loader resolves kernel BTF ID and rewrites src_reg2. Format13 requirements record each program / reachable subprogram kfunc signature (`*S` becomes ptr:S). Missing or differing target FUNC_PROTO blocks with kfunc_sig, guarding integer width / sign mismatches that loader / verifier may silently accept.

**Evidence**: F56. Root-stage 7.1.8 syscall test-run retval / maps match C for bpf_task_from_pid / bpf_task_acquire / bpf_task_release.

**Unsupported**: The table covers only bpf_task_from_pid / bpf_task_acquire / bpf_task_release; later groups add rows. Unowned pointer returns, unknown flags such as KF_SLEEPABLE, dynptr / iter / variable-length parameters, and ebpf.func calls are excluded. Availability / flags / signatures vary by kernel; original evidence is 7.1.8 only, not 6.12 / 6.6. Passing kptr such as fentry arguments to KF_RCU is unmeasured.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>callee</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `args` | variadic of any non-token type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `results` | variadic of any non-token type |



### `ebpf.kprobe.arg` (ebpf::KprobeArgOp)

_Read function argument register n from kprobe pt_regs_

Syntax:

```
operation ::= `ebpf.kprobe.arg` $ctx $n attr-dict `:` type($ctx) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Reads one-based argument n from pt_regs. Returns **raw register bits** (eight bytes) truncated to iW, without type semantics. Pure.

**Constraints**: Context is kprobe only, n ≥ 1, width i8 / i16 / i32 / i64. Program requires arch; schema accepts x86_64 only. n must fit the UAPI register count (six on x86_64) and match declared schema params width.
For **pointer arguments**, schema kind ptr requires result i64: an eight-byte raw address used as identity / correlation key, **without dereference**. Requirements kprobearg ptr checks that the target parameter is a pointer.
Load gates check arch / ctxfield pt_regs offset-size / kprobearg type and attach target against BTF; mismatch and Unknown both block. Because cilium can silently retry failed X attach as __x64_X, precheck also requires that alias to be absent (attach_alias).

**Lowering**: Stage ③ emits bpfabi.kprobe_arg using fixed eight-byte UAPI kprobearg offset, not CO-RE, then truncates. Stage-③ exit verification is Conditional: offset correctness depends on target pt_regs. No helper.

**Evidence**: F24. C oracle; load-time checking preventing silent wrong values; three targets / non-root and discovered __x64_ fallback; pointer values match runner buffer addresses and C.

**Unsupported**: Non-x86_64 (schema rejection), other contexts (uprobe uses uprobe.arg), and stack-passed argument 7 onward. External unchecked loaders can use __x64_ fallback. kernel.read_scalar reads a fixed-width value via helper only from this op's direct ptr-declared result. Pointer checking verifies pointer-ness, not pointee type or address space. No generic probe_read_user op.

Traits: `AlwaysSpeculatableImplTrait`

Interfaces: `ConditionallySpeculatable`, `NoMemoryEffect (MemoryEffectOpInterface)`

Effects: `MemoryEffects::Effect{}`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>n</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | signless integer |



### `ebpf.kptr.addr` (ebpf::KPtrAddrOp)

_Expose all 64 address bits of a checked kernel pointer as an integer_

Syntax:

```
operation ::= `ebpf.kptr.addr` $ptr attr-dict `:` type($ptr) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Converts checked kptr<"S"> or nonnull kref<"S"> address bits to i64 without reading pointee, acquiring, or consuming a reference. Result is an ordinary integer usable in map keys / values, events, arithmetic, or yield. kref release obligations remain.

**Constraints**: Only program bodies of tp_btf / fentry / fexit / iter / fmod_ret / fsession. Rejects function / callback / loop placement, direct nullable input, and non-i64 result. S must be declared in schema core.kernel_types (ebpf-verify-kptr).

**Lowering**: Stage ③ LLVM ptrtoint i64. No helper / new requirement row; format17 / policy15 / caps9 unchanged. Tracing load's CAP_PERFMON requirement and actual verifier enforce pointer-value use with map helpers.

**Evidence**: F77. Type / placement / ownership controls and request C differential tests.

**Unsupported**: Integer-to-pointer conversion or direct typed-pointer storage. Addresses correlate live objects but provide no generation identity across free / reuse or ownership. Actual kernel evidence covers fentry kptr only; other five kinds and kref have static controls.

Traits: `AlwaysSpeculatableImplTrait`

Interfaces: `ConditionallySpeculatable`, `NoMemoryEffect (MemoryEffectOpInterface)`

Effects: `MemoryEffects::Effect{}`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ptr` | a pointer to an internal kernel struct obtained from tracing arguments or a checked owned kernel-struct reference, consumed exactly once by release or map transfer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | 64-bit signless integer |



### `ebpf.kptr.check` (ebpf::KPtrCheckOp)

_Check a nullable kernel pointer and introduce kptr only in the present region_

Syntax:

```
operation ::= `ebpf.kptr.check` $ptr attr-dict `:` type($ptr) (`->` type($results)^)?
              `present` $presentRegion `absent` $absentRegion
```

**Stage**: ① Input

**Meaning**: Executes present with kptr<"S"> argument for non-NULL kptr_or_null<"S">, absent otherwise. Results come from both arms' yields, like ref.check.

**Constraints**: Present has one kptr with identical S; absent no arguments; both yields match result types.

**Lowering**: Stage ② emits is_present cf.cond_br and true-edge assume_present with merge-block results. Stage ③ compares != NULL and preserves the pointer.

**Evidence**: F23. 7.1.8 / 6.12.111 × root / {bpf, perfmon, sys_nice}: sched_pi_setprio pi_task present / absent counts and PID match C.

**Unsupported**: On 6.6.157, and arguments absent from 7.1 / 6.12 raw_tp_null_args tables, verifier may treat arguments as non-NULL and remove the comparison as dead (source-only, runtime unconfirmed). Thus checking does not guarantee runtime safety. arg_nullable gate blocks 6.6.

Traits: `RecursiveMemoryEffects`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ptr` | a nullable pointer to an internal kernel struct |

#### Results:

| Result | Description |
| :----: | ----------- |
| `results` | variadic of any non-token type |



### `ebpf.kptr.xchg` (ebpf::KPtrXchgOp)

_Exchange an owned reference with a map-record kptr field (bpf_kptr_xchg helper194)_

Syntax:

```
operation ::= `ebpf.kptr.xchg` $ref $field `,` ($newRef^):(`null`)? attr-dict `:` type($ref) (`,` type($newRef)^)? `->` type($old)
```

**Stage**: ① Input

**Meaning**: Installs a new reference into a schema kptr field (BTF PTR → TYPE_TAG kptr → STRUCT T), returning the old reference as kref_or_null<T>. The null form empties the field and returns its reference. **New-reference ownership transfers to the map**, consuming it like release; later use is rejected. The program owns the returned reference and must check it exactly once, then release or transfer its present kref exactly once. Kernel dtors release references left in maps on element deletion, userspace update, or map destruction.

**Constraints**: Destination is checked borrowed record; new value is acquired kref<T> or null, not kptr / unchecked kref_or_null. Result is kref_or_null<T> with exactly one kref.check use. Program-body placement only, as with kfunc.call: no func / callback / loop / map.for_each / scf.if / spin.region. Record checking requires nonempty dotted record_ref path of depth ≤ 3 (e.g. in.t), no array indices, matching kptr leaf T, and each / cumulative offset divisible by8. T must be @kernel struct / schema core.kernel_types. Ownership checks every-path new-reference consumption and one result check. Direct kptr-field ref.field.load / store / atomic_add / ref.index are rejected, as is record.make of kptr-bearing records or nested parents; kernel forbids direct stores.

**Lowering**: Unchanged in ②. Stage ③ calls UAPI kptr_xchg (194) with field pointer + @records offset and new pointer (null is0). Nullable result is checked by kref.check expansion. Requirements include helper kptr_xchg, btf type_tag (format13), and map value record:S.

**Evidence**: F69. kptr exchange and ownership tests.

**Unsupported**: kptr_untrusted, direct RCU field reads, percpu_kptr, and arrays of kptr / kptr-bearing records. Ordinary kptr compiles in ten hash / array / per-CPU / LRU / local-storage value kinds and nested record_ref; runtime evidence for extended placement belongs to its dedicated experiment. 6.6 source does not search nested fields: successful map creation alone cannot establish xchg acceptance. Compiler does not check a type has a dtor; kernel rejects map creation otherwise, and cilium may retry without BTF, after which xchg program load fails explicitly.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ref` | any non-token type |
| `newRef` | a checked owned kernel-struct reference, consumed exactly once by release or map transfer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `old` | an owned nullable kernel-struct reference acquired by a kfunc, with linear checking |



### `ebpf.kref.check` (ebpf::KRefCheckOp)

_Check a nullable kfunc-acquired reference and introduce an owned kref in present_

Syntax:

```
operation ::= `ebpf.kref.check` $ptr attr-dict `:` type($ptr) (`->` type($results)^)?
              `present` $presentRegion `absent` $absentRegion
```

**Stage**: ① Input

**Meaning**: Non-NULL kref_or_null<S> executes present with owned kref<S>; NULL executes absent. Results come from both arm yields, like kptr.check. Each present path must transfer the reference exactly once to a release kfunc or kptr.xchg (map ownership). Absent holds no reference; NULL is not released.

**Constraints**: Present has one kref with identical S; absent none; yields match result types without kref escape. kref uses are kfunc.call, kfield.load, and the new-reference operand of kptr.xchg.

**Lowering**: Stage ② emits is_present cf.cond_br / true-edge assume_present and merge arguments. Stage ③ compares != NULL and preserves the pointer.

**Evidence**: F56. Acquired-reference ownership tests.

**Unsupported**: Reference transport outside the region, into functions or loops; ownership checking is region-local.

Traits: `RecursiveMemoryEffects`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ptr` | an owned nullable kernel-struct reference acquired by a kfunc, with linear checking |

#### Results:

| Result | Description |
| :----: | ----------- |
| `results` | variadic of any non-token type |



### `ebpf.ksyscall.arg` (ebpf::KsyscallArgOp)

_Read syscall argument n through the wrapper's saved user pt_regs (two-stage load)_

Syntax:

```
operation ::= `ebpf.ksyscall.arg` $ctx $n attr-dict `:` type($ctx) `->` type($result)
```

**Stage**: ① Input

**Meaning**: ksyscall attaches a kprobe to __<pfx>_sys_<name>. Wrapper argument1 points to saved user pt_regs; syscall argument n (1..6) is read from that struct using the **syscall convention**, x86_64 di / si / dx / **r10** / r8 / r9. Function argument4 cx instead holds the user return address after syscall. Raw bits truncate to iW. A kernel-memory read failure (not expected) returns zero because the helper zeros its destination.

**Constraints**: Own context with OPS ksyscall.arg; n 1..6; result i8 / i16 / i32 / i64 or user_str. Schema n must fit arch UAPI ksyscallarg and match ksyscall params width; ptr declarations require i64 and expose the address without dereference. Load checks attach ksyscall name, arch, ctxfield for wrapper di and syscall registers, and sysarg type against tracefs syscalls/sys_enter_<name>/format, falling back to __do_sys_<name> BTF only when format is absent. Mismatch or unknown blocks with sysarg / sysarg_unknown (§4).

**Lowering**: Stage ③ reads wrapper argument1 via bpfabi.kprobe_arg, adds UAPI ksyscallarg offset, then probe_read_kernel (113) copies eight bytes into a zeroed stack slot and truncates. Same two-stage shape as BPF_KSYSCALL / PT_REGS_PARMn_CORE_SYSCALL, but fixed offsets rather than CO-RE.

**user_str**: Requires matching schema kind user_str; cannot substitute i64 / ptr despite equal width. Preserves raw 64-bit pointer from the two-stage read; separate user.read_str (helper114) reads bytes. sysarg strptr minimum format16 matches one-level tracefs char pointers or BTF char pointers after qualifier / typedef removal. Both mismatch and Unknown block. char** / void* / unsigned char* / arrays are not strptr. Three-kernel helper114 runtime evidence belongs to the dedicated syscall-string experiment.

**Evidence**: F67. 7.1.8 root prctl five arguments compared with equivalent C. The C-only two-stage measurement establishes cx is the return address.

**Unsupported**: Other architectures (UAPI ksyscallarg supports x86_64 only), compat ia32 entries, and generic user-memory dereference. kprobe.arg remains rejected for ksyscall because wrapper registers are not syscall arguments. No loop bodies or static-function context arguments.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>n</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | 8-bit signless integer or 16-bit signless integer or 32-bit signless integer or 64-bit signless integer or a user-string pointer from a typed source, read only by ebpf.user.read_str or an array of user character pointers from a typed source, read only by fixed-index user.str_at |



### `ebpf.ktime.ns` (ebpf::KtimeOp)

_Raw bpf_ktime_get_ns() value_

Syntax:

```
operation ::= `ebpf.ktime.ns` attr-dict `:` type($result)
```

**Stage**: ① Input

**Meaning**: Returns raw i64 monotonic-clock nanoseconds from ktime_get_ns.

**Constraints**: No op verifier or compile-time kind restriction; requirements helper checks determine availability at load. Allowed in loops / subprograms / timer.callback, whose ordinary helper set is limited to this op. Packet-neutral for C1 / W1.

**Lowering**: Stage ③ calls UAPI ktime_get_ns.

**Evidence**: F30. Kernel op acceptance, requirements helper rows, and timer callback time reads.

**Unsupported**: Other clocks (boot / tai / coarse).

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | 64-bit signless integer |



### `ebpf.lirc.sample` (ebpf::LircSampleOp)

_Read a lirc_mode2 context sample as u32 (mode << 24 | value)_

Syntax:

```
operation ::= `ebpf.lirc.sample` $ctx attr-dict `:` type($ctx) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Reads one raw-IR device sample from rc-core. UAPI linux/lirc.h uses high eight bits for LIRC_MODE2_SPACE0 / PULSE1 / FREQUENCY2 / TIMEOUT3 / OVERFLOW4 shifted by24, low24 for microseconds or Hz. Result i32. Not Pure; reads are not reordered / merged. Decompose mode / value with arith and input-defined masks.

**Constraints**: Own lirc_mode2 entry context with OPS lirc.sample, not static functions; result i32. This is exactly the sole access permitted by 7.1.8 drivers/media/rc/bpf-lirc.c lirc_mode2_is_valid_access: offset0, four-byte read.

**Lowering**: Stage ③ emits one volatile four-byte load at ctx + 0, like ctx.load. No helper.

**Evidence**: F48. BPF_PROG_ATTACH to rc-loopback LIRC device: pulse / space / timeout counts and value sums match C.

**Unsupported**: No ctxaccess requirement row: context is not a struct, and its single offset0 u32 read is kernel-version invariant. No input-event helpers rc_keydown / rc_repeat / rc_pointer_rel.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | 32-bit signless integer |



### `ebpf.loop` (ebpf::LoopOp)

_Bounded loop with constant count or runtime count clamped to it (integer carried values only)_

Syntax:

```
operation ::= `ebpf.loop` $count (`unroll` $unroll^)? (`callback` $callback^)? (`bound` `(` $bound^ `)`)? `(` $inits `)` attr-dict `:` functional-type($inits, $results) $body
```

**Stage**: ① Input

**Meaning**: Bounded loop with constant attribute N, i32 IV starting at 0 with step 1 and unsigned comparison. Integer iter_args carry values across iterations; results are final values. Optional i32 `bound(%n)` is evaluated once at entry; iteration count is unsigned min(n, N). Strategies are default (B) bounded back edge, (U) unroll, and (H) callback via bpf_loop.

**Constraints**: 0 ≤ N ≤ 64; one body block ending in ebpf.loop.yield; carried types i8 / i16 / i32 / i64; nesting depth ≤ 2 and product ≤ 64; estimated unrolled size ≤ 4096 ops. unroll and callback are mutually exclusive. Body ops come only from the allowlist, including arith, scf.if, map lookup / update / atomic_add / try_*, ref.*, packet.load, ktime, if / break / continue, loop, call, and record.make. Captures are integers, context, and map handles; (H) allows only integers and map handles. ebpf-verify-call-graph checks depth / product across callee paths. ebpf-verify-ownership rejects a live reservation crossing a loop. Limits are conservative compiler restrictions.

**Lowering**: Stage ② expands (B), N ≥ 2, into header (i < N plus bound comparison), body, and latch (i + 1); N = 0 / 1 degenerate. (U) copies the body N times into straight-line code. (H) moves the body into module-level ebpf.loop_callback and replaces the loop with ebpf.bpf_loop, lowered in ③ to helper loop and a static LLVM callback. Remaining loops at ③ are rejected.

**Evidence**: F07, F09. B / U on three targets; bound / stop, control flow, nesting, calls and callbacks across three targets; cross-function loops; callback extensions. Loaders without CAP_PERFMON reject (B) on 6.12 / 6.6.

**Unsupported**: N > 64, depth 3, product > 64; ring-buffer operations, packet.store, adjust_head / adjust_tail, tail_call, and map.delete in bodies. **packet.check / packet.window_load are accepted only within (U)**: all enclosing loops must be unrolled, because stage-② (U) has no cycle. Any enclosing B / H, including nesting, is explicitly rejected. References, reservations, and records cannot cross loops. There is no automatic fallback between U / B / H. A non-root loader's rejection of B is reported at load time without changing lowering.

Traits: `AttrSizedOperandSegments`, `RecursiveMemoryEffects`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>count</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
<tr><td><code>unroll</code></td><td>::mlir::UnitAttr</td><td>unit attribute</td></tr>
<tr><td><code>callback</code></td><td>::mlir::UnitAttr</td><td>unit attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `bound` | 32-bit signless integer |
| `inits` | variadic of signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `results` | variadic of signless integer |



### `ebpf.loop.yield` (ebpf::LoopYieldOp)

_End a loop iteration with carried values and an optional stop condition_

Syntax:

```
operation ::= `ebpf.loop.yield` $values (`stop` $stop^)? attr-dict (`:` type($values)^)?
```

**Stage**: ① Input

**Meaning**: Ends an ebpf.loop body, passing values to the next iteration. Optional i1 `stop %c` is tested at the iteration end. If true, this iteration's values become loop results; its effects remain and no next iteration executes.

**Constraints**: HasParent permits only ebpf.loop; types / count must match parent iter_args, checked by the loop verifier.

**Lowering**: Stage ②: B branches to latch, or conditionally exits for stop; U joins the current copy or exits past all copies for stop; H writes carried values to context and emits ebpf.callback.return 0 (continue) / 1 (stop). Absent at ③.

**Evidence**: F07, F09. B expansion, stop on three targets, H callback.return.

**Unsupported**: Not an arbitrary-position break: only tested at the body end. Use ebpf.if and ebpf.break to exit earlier.

Traits: `AttrSizedOperandSegments`, `HasParent<LoopOp>`, `Terminator`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `values` | variadic of signless integer |
| `stop` | 1-bit signless integer |



### `ebpf.lwt.seg6_action` (ebpf::LwtSeg6ActionOp)

_Bpf_lwt_seg6_action: perform End.X, End.T, or End.DT6 and return status (lwt_seg6local only; invalidates packet pointers)_

Syntax:

```
operation ::= `ebpf.lwt.seg6_action` $ctx $action `,` $param attr-dict `:` type($ctx) `,` type($param) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Calls `lwt_seg6_action(ctx, action, &param, sizeof param)` and returns **raw** i64 status. Action spellings come from UAPI `seg6action` rows (`SEG6_LOCAL_ACTION_*`). The compiler accepts:
- `end_x`: a 16-byte next-hop IPv6 address. The kernel looks up its route and sets skb dst.
- `end_t` / `end_dt6`: a 4-byte int route table number. end_dt6 removes the outer IPv6 header and SRH.
The program must return `redirect` to use the selected dst. With `ok`, the kernel looks up the next segment and discards the action's dst (net/ipv6/seg6_local.c input_action_end_bpf). Packet pointers are invalidated on success and failure (`pktinval`).

**Constraints**: Only lwt_seg6local programs and their entry context (OPS `lwt.seg6`); loop bodies and static-function contexts are rejected. Param must be an `ebpf.record.make` result of the action's exact size: 16 for end_x, 4 for end_t / end_dt6. `end_b6` / `end_b6_encap` exist in UAPI but are explicitly rejected: constructing SRH parameters is outside compiler scope.

**Lowering**: Stage ③ obtains the action value from UAPI (absence is an error) and calls `lwt_seg6_action`, with record.make's stack storage as param and record size as len.

**Evidence**: F57. Actual 7.1.8 attach with End.X plus redirect and End.X plus ok.

**Unsupported**: end_t / end_dt6 are unmeasured (no route-table observation). end_b6 / end_b6_encap, other program kinds, and 6.12 / 6.6 are unverified.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>action</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `param` | a schema record identified by symbol and byte size for maps, reservations, perf output and subprogram arguments |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.lwt.seg6_adjust_srh` (ebpf::LwtSeg6AdjustSrhOp)

_Bpf_lwt_seg6_adjust_srh: insert or remove delta bytes in the SRH TLV area and return status (lwt_seg6local only; invalidates packet pointers)_

Syntax:

```
operation ::= `ebpf.lwt.seg6_adjust_srh` $ctx `[` $offset `]` `,` $delta attr-dict `:` type($ctx) `,` type($offset) `,` type($delta) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Calls `lwt_seg6_adjust_srh(ctx, offset, delta)` to insert (positive delta) or remove (negative delta) bytes at an offset between the TLV area start and the SRH end, returning **raw** i64 status. Inserted bytes must not be assumed zero; the caller writes TLVs with `ebpf.lwt.seg6_store_bytes`. After the program, the kernel revalidates SRH, updates hdrlen, and drops malformed packets. It also updates IPv6 payload_len.
Packet pointers are invalidated on success and failure (`pktinval`).

**Constraints**: Only lwt_seg6local programs and their entry context (OPS `lwt.seg6`). Delta is signed i32 and need not be constant; the kernel checks bounds. Loop bodies and static-function contexts are rejected. Old-window rejection follows store_bytes.

**Lowering**: Stage ③ zero-extends offset, sign-extends delta, and calls `lwt_seg6_adjust_srh`, returning status.

**Evidence**: F57. Actual 7.1.8 attach with +8 bytes and a PadN TLV at the SRH end.

**Unsupported**: Other program kinds and loop bodies. 6.12 / 6.6 and removal (negative delta) are unmeasured.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `offset` | 32-bit signless integer |
| `delta` | 32-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.lwt.seg6_store_bytes` (ebpf::LwtSeg6StoreBytesOp)

_Bpf_lwt_seg6_store_bytes: write a complete record to SRH flags, tag, or TLVs and return status (lwt_seg6local only; invalidates packet pointers)_

Syntax:

```
operation ::= `ebpf.lwt.seg6_store_bytes` $ctx `[` $offset `]` `,` $record attr-dict `:` type($ctx) `,` type($offset) `,` type($record) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Calls `lwt_seg6_store_bytes(ctx, offset, &rec, sizeof rec)` to write every record byte at the packet's byte offset from data (the IPv6 header start), returning **raw** i64 status. The kernel permits only SRH flags / tag (bytes 5–7 from the SRH start) and the TLV area; other locations return −EFAULT (net/core/filter.c). TLV writes cause post-program SRH revalidation; malformed packets are dropped (`seg6_bpf_has_valid_srh`).
Packet pointers are invalidated on success and failure (UAPI `pktinval`).

**Constraints**: Only lwt_seg6local programs (OPS marker `lwt.seg6`) and their entry context are accepted; static-function context arguments are not accepted by this invalidating operation. Data must be an `ebpf.record.make` result (all bytes, zero padding). Not allowed in `ebpf.loop`. The stage-② may-invalidate check rejects `packet.window_load` if any path from window definition to use crosses this operation. Packet-neutral C1 / W1 / packet-check rewrites do not cross it, as with adjust_head.

**Lowering**: Stage ③ zero-extends offset to i64 and calls `lwt_seg6_store_bytes`, with record.make's stack storage as data and the record size as len. The result is status.

**Evidence**: F57. Actual 7.1.8 netns seg6local route attach and differential measurement against equivalent C.

**Unsupported**: Other program kinds, variable-length data, and loop bodies. 6.12 / 6.6 are unverified.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `offset` | 32-bit signless integer |
| `record` | a schema record identified by symbol and byte size for maps, reservations, perf output and subprogram arguments |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.map.atomic_add` (ebpf::MapAtomicAddOp)

_Atomically add to a map value_

Syntax:

```
operation ::= `ebpf.map.atomic_add` $map `[` $key `]` `,` $delta attr-dict `:` type($map) `,` type($key) `,` type($delta)
```

**Stage**: ① Input

**Meaning**: Atomically adds delta to the keyed value. Missing elements are unchanged and not created. No result.

**Constraints**: Rejects read-only lpm_trie, devmap / prog_array / stack_trace / perf_event_array, and unknown kinds. Delta matches value type, which must be signless integer, not record, and **32 or 64 bits only** (BPF atomics; i8 / i16 previously aborted in the LLVM BPF backend). record.make rejects use as atomic_add key. Allowed in loop bodies.

**Lowering**: Stage ② expands to map.lookup → is_present branch → assume_present plus ref.atomic_add on the true edge, making the NULL check explicit. Stage ③ uses map_lookup_elem and a result-unused monotonic atomicrmw add (BPF non-FETCH lock +=).

**Evidence**: F01. Stage-② expansion; array / hash / percpu_array acceptance on 7.1.8; ELF non-FETCH lock +=; width rules.

**Unsupported**: Upsert, FETCH returning the old value, and atomic operations other than add.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | a BPF map handle with kind, key type and value type |
| `key` | any non-token type |
| `delta` | any non-token type |



### `ebpf.map.delete` (ebpf::MapDeleteOp)

_Delete a keyed map element (hash family or XDP socket maps)_

Syntax:

```
operation ::= `ebpf.map.delete` $map `[` $key `]` attr-dict `:` type($map) `,` type($key)
```

**Stage**: ① Input

**Meaning**: Deletes key's element without exposing helper status. Use ebpf.map.try_delete for status.

**Constraints**: sockmap / sockhash are accepted only in XDP program bodies and if / sock.ref_check arms (measured on 7.1.8 against C and full manifest acceptance). Otherwise only hash / percpu_hash / lru_hash / lru_percpu_hash. array / percpu_array are rejected because the kernel would return -EINVAL without a change. lpm_trie / devmap follow map.update exclusions. Key type matches; record keys must be record.make results. **Not allowed in loop bodies**; try_delete is allowed there.

**Lowering**: Unchanged in ②. Stage ③ calls map_delete_elem(map, &key), discarding status. Integer key / value stack-slot lifetime and cost follow map.lookup; --tune-spill-lifetime=false restores v0.15.0 output.

**Evidence**: F04. C oracle for array delete -EINVAL without changes; op tests; three targets.

**Unsupported**: Array-family delete is rejected at compile time. Use try_delete inside loops.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | a BPF map handle with kind, key type and value type |
| `key` | any non-token type |



### `ebpf.map.for_each` (ebpf::MapForEachOp)

_Run a callback for each map element (bpf_for_each_map_elem; invocation count and carried results)_

Syntax:

```
operation ::= `ebpf.map.for_each` $map `(` $inits `)` attr-dict `:` type($map) `,` functional-type($inits, results) $body
```

**Stage**: ① Input

**Meaning**: Runs a body per map element via bpf_for_each_map_elem. Block arguments are key value, writable borrowed value !ebpf.borrowed<V> (current CPU slot for per-CPU maps), and carried values. ebpf.map.for_each.yield passes values onward; true stop ends at that element. Results are **invoked element count** as i64, including the stopping element (helper result), followed by final carried values. Arrays iterate in index order; hash-family order is unspecified.

**Constraints**: Map kind is array / percpu_array / hash / percpu_hash / lru_hash / lru_percpu_hash. Integer key only, integer or record value, carried i8 / i16 / i32 / i64 as in bpf_loop callbacks. Body allowlist follows loops minus ebpf.loop / call / break / continue (no callback nesting / calls). Value borrow is used only by ref.load / store / atomic_add / field.*. Captures are integers and program / func map handles, passed to the stage-② callback; inner-map handles are rejected. Not allowed in loop bodies.

**Lowering**: Stage ② moves the body into module-level ebpf.loop_callback with for_each attribute (entry key / value / carried / captures / maps), replacing it by ebpf.for_each_map_elem. Terminator is callback.return 0 / 1. Stage ③ emits a static `(ptr map, ptr key, ptr value, ptr ctx) -> i64` callback, helper for_each_map_elem(map, &callback, ctx, 0), and carried reloads from ctx. Frame / recursion checks and requirement reachability follow bpf_loop callbacks.

**Evidence**: F53. Array stop / writeback and hash sum match equivalent C in 7.1.8 XDP test runs.

**Unsupported**: Callback loops / calls / nested for_each and record keys. Semantics of modifying the iterated map with update / delete depend on the kernel; the compiler does not prevent it. 6.12 / 6.6 are unverified.

Traits: `RecursiveMemoryEffects`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | a BPF map handle with kind, key type and value type |
| `inits` | variadic of signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `count` | 64-bit signless integer |
| `results` | variadic of signless integer |



### `ebpf.map.for_each.yield` (ebpf::MapForEachYieldOp)

_End a map.for_each callback with carried values and an optional stop condition_

Syntax:

```
operation ::= `ebpf.map.for_each.yield` $values (`stop` $stop^)? attr-dict (`:` type($values)^)?
```

**Stage**: ① Input

**Meaning**: Ends ebpf.map.for_each body. Values carry to the next element; true i1 stop makes this element's values final and returns callback status 1.

**Constraints**: Parent is ebpf.map.for_each only. Value types / count match the parent's carried values, checked by the parent verifier.

**Lowering**: Stage ② writes carried values to context and emits callback.return 0 (continue) / 1 (stop). Absent at ③.

**Evidence**: F53. Stopping at array key 2 reports invocation count 3.

**Unsupported**: Not arbitrary-position break; evaluated only at the body end.

Traits: `AttrSizedOperandSegments`, `HasParent<MapForEachOp>`, `Terminator`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `values` | variadic of signless integer |
| `stop` | 1-bit signless integer |



### `ebpf.map.inner` (ebpf::MapInnerOp)

_Convert a checked outer map-in-map borrow to an inner map handle_

Syntax:

```
operation ::= `ebpf.map.inner` $ref attr-dict `:` type($ref) `->` type($inner)
```

**Stage**: ① Input

**Meaning**: Converts a ref.check-validated outer array_of_maps / hash_of_maps lookup borrow !ebpf.borrowed<!ebpf.map<"…", K, V>> to inner !ebpf.map<"…", K, V>. The handle works with map.lookup / update / delete / atomic_add / try_update / try_delete. Pure.

**Constraints**: Operand is borrowed map and result equals its pointee. Result cannot escape via yield / call argument / loop-carried value: validity is confined to the checked region's present path. A borrowed map can be used only by map.inner; ref.check and stage-② exit verification reject ref.load and other uses. ebpf-verify-schema checks inner kind / key / value against the outer schema inner template.

**Lowering**: Unchanged in ②; ref.check emits a NULL branch and assume_present borrow. Stage ③ preserves the pointer. After NULL checking, the kernel treats the outer lookup result as CONST_PTR_TO_MAP with template metadata and accepts it as the inner helper's map argument.

**Evidence**: F52. array_of_maps with inner hash and hash_of_maps with inner array match C for lookup / update / atomic_add in 7.1.8 XDP test runs.

**Unsupported**: Program-side inner-map insertion / outer-map update (kernel rejection; userspace inserts). Schema permits only hash / array families inside, rejecting lpm_trie / ringbuf / local storage / two-level map-in-map. 6.12 / 6.6 are unverified.

Traits: `AlwaysSpeculatableImplTrait`

Interfaces: `ConditionallySpeculatable`, `NoMemoryEffect (MemoryEffectOpInterface)`

Effects: `MemoryEffects::Effect{}`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ref` | a checked borrowed reference without ownership |

#### Results:

| Result | Description |
| :----: | ----------- |
| `inner` | a BPF map handle with kind, key type and value type |



### `ebpf.map.lookup` (ebpf::MapLookupOp)

_Look up a map, returning an unchecked nullable reference_

Syntax:

```
operation ::= `ebpf.map.lookup` $map `[` $key `]` attr-dict `:` type($map) `,` type($key) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Looks up key and returns an **unchecked** !ebpf.maybe_ref<V>, where V is map value type. The helper can return NULL: ebpf.ref.check is required before use, and access goes through present-region !ebpf.borrowed<V>.

**Constraints**: The op verifier rejects devmap (redirect_map only), prog_array (tail_call only), stack_trace (stack.kernel_id only), perf_event_array (perf.output only), and unknown kinds (including ringbuf here). Key type matches the map key; result pointee matches its value. Record keys are accepted only for hash / percpu_hash / lru_hash / lru_percpu_hash and lpm_trie, and must be record.make results. ebpf-verify-schema checks map kind / key / value; ebpf-verify-records checks record-value depth / dimensions.

**Lowering**: Unchanged in ②; ref.check expansion supplies the NULL branch. Stage ③ calls map_lookup_elem(map, &key): integer keys use stack slots; record keys reuse record.make stack pointers. Integer key / value slots have store-to-helper lifetime.start / end markers (enabled by default), allowing LLVM to overlap per-op slots: stack use no longer scales with op count; without markers, 32 sixteen-byte operations hit the BPF stack limit. Measured processed-instruction counts mostly stay equal or decrease but sometimes increase: repository maximum is sdiv_i32_floordivsi on 6.6.157, 1057 → 1251 (+18%). **Downstream maximum on 7.1.8 is +145%, mojo-bpf-mlir testdata pkt 185 → 454**; constant-key NULL elision likely marks shared slots precise and weakens pruning. 6.x and acceptance are unchanged. `ebpf-compile --tune-spill-lifetime=false` restores v0.15.0 output.

**Evidence**: F01, F04, F16. 7.1.8 acceptance and NULL-check-removal mutation rejected as map_value_or_null; record keys; hash-family records; three-target lpm_trie lookup / map-kind tests.

**Unsupported**: The four dedicated map kinds cannot use this program-side lookup. lpm_trie keys are limited by schema to eight-byte IPv4 records. To avoid lookup on out-of-bounds packets, enclose it in packet.check: packet.load otherwise returns 0 out of bounds and still performs the lookup.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | a BPF map handle with kind, key type and value type |
| `key` | any non-token type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | an unchecked nullable reference |



### `ebpf.map.lookup_percpu` (ebpf::MapLookupPercpuOp)

_Look up a specified CPU's per-CPU map slot (unchecked nullable reference)_

Syntax:

```
operation ::= `ebpf.map.lookup_percpu` $map `[` $key `]` `,` $cpu attr-dict `:` type($map) `,` type($key) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Looks up key in percpu_array / percpu_hash / lru_percpu_hash and returns the **specified CPU's** slot (%cpu, i32), unlike map.lookup's current-CPU slot. Result is unchecked !ebpf.maybe_ref<V>; absent key or cpu ≥ kernel nr_cpu_ids gives NULL. Access uses ref.check borrows as with map.lookup.

**Constraints**: Only these three per-CPU kinds, matching kernel check_map_func_compatibility. Key matches map type; record keys follow hash-family record.make rules. Result pointee equals map value. No loop bodies. Writes to another CPU's slot are unsynchronized; races are the caller's responsibility.

**Lowering**: Unchanged in ②. Stage ③ calls map_lookup_percpu_elem(map, &key, zext(cpu)); integer keys use stack storage as in map.lookup.

**Evidence**: F53. CPU 0 / 1 percpu_array slots and out-of-range CPU NULL match C in 7.1.8 XDP test runs.

**Unsupported**: 6.12 / 6.6 are unverified.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | a BPF map handle with kind, key type and value type |
| `key` | any non-token type |
| `cpu` | 32-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | an unchecked nullable reference |



### `ebpf.map.peek` (ebpf::MapPeekOp)

_Read the next queue or stack element without removing it, returning status and value_

Syntax:

```
operation ::= `ebpf.map.peek` $map attr-dict `:` type($map) `->` type($status) `,` type($value)
```

**Stage**: ① Input

**Meaning**: Reads the same element as map.pop without removal. Status / value follow pop: nonzero status yields value 0. Bloom uses separate ebpf.bloom.peek.

**Constraints**: Queue / stack only, none key parameter, integer result matching map value. No loop bodies (compiler restriction).

**Lowering**: Unchanged in ②. Stage ③ zeros a stack slot, calls map_peek_elem(map, &slot), then loads it as with pop.

**Evidence**: F59. Queue / stack peek match C in 7.1.8 XDP test runs.

**Unsupported**: Record values. 6.12 / 6.6 are unverified.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | a BPF map handle with kind, key type and value type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |
| `value` | integer |



### `ebpf.map.pop` (ebpf::MapPopOp)

_Remove a queue or stack element and return status and value_

Syntax:

```
operation ::= `ebpf.map.pop` $map attr-dict `:` type($map) `->` type($status) `,` type($value)
```

**Stage**: ① Input

**Meaning**: Removes the oldest queue element (FIFO) or newest stack element (LIFO). Returns **raw** helper status (0 / negative errno; empty -ENOENT) and value. **Nonzero status yields value 0**: kernel zeros empty results but does not write on lock-failure -EBUSY, so the compiler zeros the slot before calling.

**Constraints**: Queue / stack only, with none key parameter and integer result matching map value. bloom_filter is rejected (kernel -EOPNOTSUPP). No loop bodies (compiler restriction).

**Lowering**: Unchanged in ②. Stage ③ zeros a stack slot, calls map_pop_elem(map, &slot), and loads the value width afterward. Lifetime ends after the load.

**Evidence**: F59. Queue FIFO, stack LIFO, empty -ENOENT / value 0 match C in 7.1.8 XDP test runs.

**Unsupported**: Record values. 6.12 / 6.6 are unverified.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | a BPF map handle with kind, key type and value type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |
| `value` | integer |



### `ebpf.map.push` (ebpf::MapPushOp)

_Push a value to queue, stack, or bloom_filter and return helper status_

Syntax:

```
operation ::= `ebpf.map.push` $map `,` $value `flags` $flags attr-dict `:` type($map) `,` type($value) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Inserts a value into a keyless map and returns **raw** i64 status (0 / negative errno). Full queue / stack gives -E2BIG; exist (BPF_EXIST) drops the oldest element and inserts, returning 0. bloom_filter sets the value's hash bits and returns 0.

**Constraints**: Map is queue / stack / bloom_filter with none key parameter; value matches its integer value type. Queue / stack allow any / exist; bloom_filter only any. noexist and bloom exist are rejected because the kernel would only return -EINVAL. No loop bodies (compiler restriction).

**Lowering**: Unchanged in ②. Stage ③ stores value in a stack slot and calls map_push_elem(map, &value, flags), with UAPI updateflag values. Slot lifetime follows map.lookup keys.

**Evidence**: F59. Queue full -E2BIG / exist overwrite, stack, and bloom push match C in 7.1.8 XDP test runs.

**Unsupported**: Record values (schema rejection); NUMA_NODE / RDONLY / WRONLY map flags; configurable bloom hash count (map_extra 0 uses kernel default 5). 6.12 / 6.6 are unverified.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>flags</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | a BPF map handle with kind, key type and value type |
| `value` | any non-token type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.map.try_delete` (ebpf::MapTryDeleteOp)

_Delete a keyed map element and return raw helper status_

Syntax:

```
operation ::= `ebpf.map.try_delete` $map `[` $key `]` attr-dict `:` type($map) `,` type($key) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Deletes key's element and returns **raw** i64 status (0 / negative errno), dependent on kind / previous state. Missing hash keys give -ENOENT. On 7.1.8, C comparisons show sockmap empty / out-of-range -EINVAL and sockhash missing key -ENOENT.

**Constraints**: Same as map.delete: XDP sockmap / sockhash or hash family; no array family / lpm_trie / devmap; matching key type; record keys only from record.make. Hash-family operations are allowed in loop bodies; socket maps are rejected in loops / calls / callbacks. Socket-map XDP acceptance was measured on 7.1.8, not 6.12 / 6.6.

**Lowering**: Unchanged in ②. Stage ③ calls map_delete_elem(map, &key) and exposes status. Stack-slot lifetime / cost follow map.lookup; --tune-spill-lifetime=false restores v0.15.0 output.

**Evidence**: F05. C oracle and three-target status tests.

**Unsupported**: Array-family delete is rejected at compile time.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | a BPF map handle with kind, key type and value type |
| `key` | any non-token type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.map.try_update` (ebpf::MapTryUpdateOp)

_Update a map and return raw helper status (zero or negative errno)_

Syntax:

```
operation ::= `ebpf.map.try_update` $map `[` $key `]` `,` $value `flags` $flags attr-dict `:` type($map) `,` type($key) `,` type($value) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Updates a map and returns **raw** i64 status (0 / negative errno). Errno semantics depend on map kind, flags, and prior state; do not generalize them. Flags are any / noexist / exist.

**Constraints**: Kind / key / value rules follow map.update. Only those three flag names. noexist on array / percpu_array is accepted: in-range gives -EEXIST and out-of-range gives -E2BIG. Allowed in loop bodies.

**Lowering**: Unchanged in ②. Stage ③ calls map_update_elem(map, &key, &value, flags), with numeric UAPI updateflag values; unknown names also fail explicitly at ③. Stack lifetime / cost follow map.lookup; --tune-spill-lifetime=false restores v0.15.0 output.

**Evidence**: F05. C oracle; flag checks and correction allowing array NOEXIST; matching C status / map state on three targets.

**Unsupported**: Other flags. Interpreting status is the caller's responsibility; compile time does not predict it.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>flags</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | a BPF map handle with kind, key type and value type |
| `key` | any non-token type |
| `value` | any non-token type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.map.update` (ebpf::MapUpdateOp)

_Update a map_

Syntax:

```
operation ::= `ebpf.map.update` $map `[` $key `]` `,` $value attr-dict `:` type($map) `,` type($key) `,` type($value)
```

**Stage**: ① Input

**Meaning**: Replaces the keyed element with value using any flags (0). Helper status is not exposed; use ebpf.map.try_update when status is needed.

**Constraints**: lpm_trie is compiler-restricted to read-only program access. Other kind rules follow map.lookup. Key / value types match map parameters. Record keys require hash-family maps; record keys / values must be record.make results, including all bytes and zero padding. Allowed in loop bodies.

**Lowering**: Unchanged in ②. Stage ③ calls map_update_elem(map, &key, &value, 0). Integers use stack slots; records reuse record.make pointers. Integer key / value lifetime markers, stack-slot overlap, processed-instruction costs, and --tune-spill-lifetime=false behavior follow ebpf.map.lookup: observed repository maximum +18% on 6.6.157 and downstream maximum +145% on 7.1.8, with unchanged acceptance.

**Evidence**: F01, F03, F04. 7.1.8 acceptance; record values / keys and three-target byte agreement with C; map-kind tests.

**Unsupported**: Configurable flags (noexist / exist use try_update). Program-side lpm_trie / devmap updates are rejected; userspace supplies them.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | a BPF map handle with kind, key type and value type |
| `key` | any non-token type |
| `value` | any non-token type |



### `ebpf.msg.apply_bytes` (ebpf::MsgApplyBytesOp)

_Bpf_msg_apply_bytes: apply the sk_msg verdict to the next n bytes (raw status; always zero on 7.1.8)_

Syntax:

```
operation ::= `ebpf.msg.apply_bytes` $ctx `,` $bytes attr-dict `:` type($ctx) `,` type($bytes) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Calls `msg_apply_bytes(msg, n)` to apply this run's pass / redirect / drop verdict to the first n bytes (u32), returning **raw** i64 status (always 0 in 7.1.8 / 6.12 / 6.6 source). Kernel tcp_bpf_send_verdict sends min(size, n) bytes and reruns the program for any remainder. If n exceeds the message, the verdict and destination carry into later writes until n bytes are consumed, without running the program; the kernel holds the destination socket reference. **The apply value persists across runs within one write**, because msg is cleared only per write chunk, even if later runs do not call apply. **Combined with drop, sendmsg returns `size − n` but delivers nothing** (`*copied -= tosend`); the caller must not interpret that return as delivered bytes.

**Constraints**: Requires a program body with OPS msg.apply_bytes (sk_msg) and that program's entry context; static functions / callbacks are rejected. n is i32 (zero-extended as u32); result is i64. No ebpf.loop bodies. It does not invalidate packet pointers, but is not packet-neutral; C1 / W1 cannot cross it.

**Lowering**: Stage ③ zero-extends n to i64 and calls msg_apply_bytes(ctx, n) using the UAPI helper number, returning status.

**Evidence**: F61. On 7.1.8 child-netns TCP sockmap links, C matches: a 10-byte write with apply 4 runs three times at sizes 10 / 6 / 2; apply 100 preserves verdict / destination into the next write; apply 4 with drop returns 6 and delivers nothing.

**Unsupported**: Non-sk_msg, loop bodies, combinations with cork or egress redirect. 6.12 / 6.6 have source-only evidence.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `bytes` | 32-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.msg.cork_bytes` (ebpf::MsgCorkBytesOp)

_Bpf_msg_cork_bytes: buffer an sk_msg message until n bytes accumulate (raw status; always zero on 7.1.8)_

Syntax:

```
operation ::= `ebpf.msg.cork_bytes` $ctx `,` $bytes attr-dict `:` type($ctx) `,` type($bytes) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Calls `msg_cork_bytes(msg, n)`. If message size is below n (u32), the kernel buffers it without sending or applying a verdict; sendmsg returns accepted bytes. A later write reaching n reruns the program on the complete buffered message. Returns **raw** i64 status, always 0 in source for all three versions. **Removing the socket from sockmap / sockhash discards buffered bytes**, without delivery (net/core/skmsg.c sk_psock_stop).

**Constraints**: Same as ebpf.msg.apply_bytes: OPS msg.cork_bytes, entry context only, no loop bodies, i32 n and i64 result. Neither pktinval nor packet-neutral.

**Lowering**: Stage ③ zero-extends n to i64, calls msg_cork_bytes(ctx, n), and returns status.

**Evidence**: F61. C matches on 7.1.8: cork 8 buffers a 3-byte write returning 3; the next 5 bytes cause one 8-byte delivery; removing the socket from the map discards buffered bytes.

**Unsupported**: Non-sk_msg and loop bodies. ENOSPC termination, combinations with apply, and buffered scatterlist element count / window length are unmeasured. 6.12 / 6.6 have source-only evidence.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `bytes` | 32-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.msg.pop_data` (ebpf::MsgPopDataOp)

_Bpf_msg_pop_data: remove message bytes [start, start + len) and return status (sk_msg; invalidates packet pointers)_

Syntax:

```
operation ::= `ebpf.msg.pop_data` $ctx `,` $start `,` $len attr-dict `:` type($ctx) `,` type($start) `,` type($len) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Calls `msg_pop_data(msg, start, len, 0)` to remove the u32 byte range from both delivered data and message size, returning 0. Length 0 is a no-op returning 0. Failures return **raw** negative i64 errno: −EINVAL for start outside the message or start + len exceeding size; −ENOMEM when an interior removal has neither a free slot nor a page. After success, the direct window returns to **the entire first element**, not start. An interior pop splits an element, so the window may contain only its prefix (start minus element start bytes). Subsequent drop / redirect applies to the modified message. Flags are fixed at 0.
Packet pointers are invalidated on success and failure (pktinval).

**Constraints**: Same as ebpf.msg.pull_data: OPS msg.pop_data, entry context only, no loop bodies, i32 start / len, i64 result, old-window rejection, and packet-neutral C1 / W1 / packet-check rewrite barriers.

**Lowering**: Stage ③ zero-extends start / len to i64, calls msg_pop_data(ctx, start, len, 0), and returns status.

**Evidence**: F61. Actual 7.1.8 attach matches C: an interior pop leaves a one-byte prefix window, a leading pop exposes the entire remainder, −EINVAL, and post-pop drop (EACCES) / redirect affects the modified message.

**Unsupported**: Non-sk_msg, loop bodies, cross-element pop, copy paths without a free slot, and −ENOMEM. No push operation: inserted bytes are not kernel-zeroed. 6.12 / 6.6 have source-only evidence.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `start` | 32-bit signless integer |
| `len` | 32-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.msg.pull_data` (ebpf::MsgPullDataOp)

_Bpf_msg_pull_data: replace the direct sk_msg window with message range [start, end), returning status (invalidates packet pointers)_

Syntax:

```
operation ::= `ebpf.msg.pull_data` $ctx `,` $start `,` $end attr-dict `:` type($ctx) `,` type($start) `,` type($end) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Calls `msg_pull_data(msg, start, end, 0)` to make the u32 range [start, end) contiguous. A single scatterlist element needs no copy; a range crossing elements is copied into a new page. Success sets the direct packet.check data / data_end window to **exactly [start, end)** and returns 0, without changing message contents. Failures return **raw** negative i64 errno: −EINVAL for end ≤ start or start / end outside the message, −ENOMEM for page allocation failure. Failure leaves the window unchanged. Flags are fixed at 0; the kernel rejects other values with −EINVAL.
On success and failure the compiler invalidates packet pointers (UAPI pktinval; kernel verifier clears them after the helper). Re-read with a new packet.check / packet.load, which reloads ctx data / data_end.

**Constraints**: Program body must have OPS msg.pull_data (sk_msg), and context must be its entry context; static-function context arguments are rejected. start / end are i32, zero-extended; they need not be constant because the kernel checks bounds and returns errno. Result is i64. No ebpf.loop bodies. At the stage-② exit, may-invalidate checking rejects packet.window_load and window-passing calls across this op. Packet-neutral C1 / W1 / packet-check rewrites cannot cross it, as with adjust_head / seg6 operations.

**Lowering**: Stage ③ zero-extends start / end to i64 and calls msg_pull_data(ctx, start, end, 0) using the UAPI helper number. Status is returned. Later packet reads reload ctx data / data_end; packet.check lowering always reloads them.

**Evidence**: F61. Actual 7.1.8 attach matches C: pull [2, 6) gives exactly four bytes starting at start; end ≤ start and out-of-message bounds give −EINVAL with the original window unchanged. Swapping operands changes only predicted cases.

**Unsupported**: Non-sk_msg, loop bodies, cross-element copy paths, −ENOMEM, and copy-marked windows with NULL data (kTLS / splice). 6.12 / 6.6 have source-only evidence.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `start` | 32-bit signless integer |
| `end` | 32-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.msg.redirect` (ebpf::MsgRedirectOp)

_Terminate with bpf_msg_redirect_map or bpf_msg_redirect_hash (sk_msg with sockmap or sockhash)_

Syntax:

```
operation ::= `ebpf.msg.redirect` $ctx `,` $map `[` $key `]` (`ingress` $ingress^)? `:` type($ctx) `,` type($map) `,` type($key) (`when` $cond^ `else` $else_action)? attr-dict
```

**Stage**: ① Input

**Meaning**: An sk_msg terminator returning `msg_redirect_map(msg, sockmap, key, flags)` or `msg_redirect_hash(msg, sockhash, &key, flags)` unchanged. A present socket sets the message destination and yields SK_PASS. ingress queues to that socket's receive path; otherwise egress sends from it (TCP destinations only). Absent or LISTEN TCP sockets yield SK_DROP (sendmsg returns EACCES). A conditional `when %c else "<verdict>"` form is available.
**The destination persists within one write**: msg->sk_redir is cleared only per write chunk by sk_msg_init. After ebpf.msg.apply_bytes limits a verdict, a subsequent run for the same write still redirects to the previous destination even if it returns pass (net/core/skmsg.c sk_psock_map_verd). Split writes to send the remainder through the original socket.

**Constraints**: Same form as ebpf.sk.redirect, for program / context kind with OPS msg.redirect (sk_msg).

**Lowering**: Stage ② follows ebpf.sk.redirect. Stage ③ calls msg_redirect_map with a zero-extended key or msg_redirect_hash with a stack key, uses UAPI redirflag flags, truncates to i32, and returns.

**Evidence**: F61. Actual 7.1.8 netns TCP pairs match C for ingress / egress and empty-slot EACCES. Further C comparisons cover pass after apply retaining the previous destination within a write; apply extending beyond a write carries the destination into a later write without running the program; redirect / drop after pop.

**Unsupported**: Non-sk_msg (sk_skb uses ebpf.sk.redirect), nested redirects, flags other than BPF_F_INGRESS, and msg_push_data (inserted bytes are not kernel-zeroed). apply / cork / pull / pop have separate ebpf.msg.* operations.

Traits: `HasParent<ProgramOp>`, `Terminator`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>ingress</code></td><td>::mlir::UnitAttr</td><td>unit attribute</td></tr>
<tr><td><code>else_action</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `map` | any non-token type |
| `key` | any non-token type |
| `cond` | 1-bit signless integer |



### `ebpf.packet.check` (ebpf::PacketCheckOp)

_Check a packet range and introduce a scoped window (stores only for XDP or cgroup_sockopt entry; window_load reads)_

Syntax:

```
operation ::= `ebpf.packet.check` $ctx `[` $offset `]` `len` $len attr-dict `:` type($ctx) `,` type($offset) (`->` type($results)^)?
              `in_range` $inRange `out_of_range` $outOfRange
```

**Stage**: ① Input

**Meaning**: Checks [offset, offset + len) against data_end. Success executes in_range with its sole block argument !ebpf.pkt_window<len>; failure executes explicit out_of_range. Both arms may return values via ebpf.yield (`-> T…`).

**Constraints**: Context kind must have PACKET range: XDP / __sk_buff, cgroup_sockopt optval / optval_end, sk_msg, or sk_reuseport. Only XDP and cgroup_sockopt own-entry programs support writes. Constant len is 1..65535 (MAX_PACKET_OFF). Constant offsets use subtraction-form offset ≤ 65535 − len. in_range has exactly one matching window argument; out_of_range has none. Window uses are packet.store / packet.window_load within in_range, or an operand to a **static ebpf.func call** with exactly the same pkt_window<len> (no shrinking). No yield escape or block-argument transport.
packet.store accepts XDP and cgroup_sockopt own-entry windows only. cgroup_sockopt requires a direct checked window built from entry ctx; stores to static-function windows are rejected. sched_cls and other read-only kinds reject stores. Stores are packet-write barriers (MemWrite<packet>) for C1 / W1. Actual 7.1.8 own-child-cgroup / fresh-netns / own-socket SET / GET measurements cover 40 normal cases, two distinct mutations, and zero cleanup residue, with no C difference; older kernels and actual non-root are unmeasured.
Inside ebpf.loop, **all enclosing loops must be U / unroll**. Variable offsets such as iter_args-driven walks are allowed; B / H bodies are rejected. To stop a walk out of bounds, test the i1 result with ebpf.if then ebpf.break (break parents remain if / ref.check only). Offset widths are i8 / i16 / i32 / i64.

**Lowering**: Stage ② ebpf-expand-regions first replaces constant-offset packet.load directly in the in_range entry block with window_load, sinks rewritten reads to first use (C1), zero-extends offset to i64, then emits pkt.check_br and ^in(%w) / ^out blocks.
Stage ③ reads the kind's PACKET pair using UAPI offsets: xdp_md data / data_end 0 / 4, __sk_buff 76 / 80 (four-byte fields), bpf_sockopt optval / optval_end 8 / 16 (eight-byte fields). It branches on data + off + len ≤ data_end, preserving the comparison's pointer register as the window.

**Evidence**: F10, F11, F20. Subtraction-form bounds; three-target tests and removed-boundary mutation; sched_cls read-only; window_load / C1 / W1; rejection of input pkt.check_br. Integer result widths are i1 / 8 / 16 / 32 / 64; others are rejected. Three-target i1 differential tests use kernel/cmd/i1check.

**Unsupported**: B / H body checks (future B work needs DominatedBackward structured verification; H needs context capture). Windows cannot escape regions or cross iterations. No writes for read-only kinds. Loop-carried values and function arguments remain i8 / i16 / i32 / i64, excluding i1 even though checked-region results allow it.

Traits: `RecursiveMemoryEffects`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>len</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `offset` | signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `results` | variadic of signless integer |



### `ebpf.packet.load` (ebpf::PacketLoadOp)

_Load an integer from the context packet_

Syntax:

```
operation ::= `ebpf.packet.load` $ctx `[` $offset `]` attr-dict `:` type($ctx) `,` type($offset) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Reads little-endian integer bytes at unsigned zero-extended offset. Returns 0 if data + offset + width exceeds data_end, or a variable offset exceeds its limit. Interpreting an out-of-range zero is the caller's responsibility.

**Constraints**: Context kind must have a PACKET range pair: XDP / __sk_buff data / data_end, cgroup_sockopt optval / optval_end, sk_msg_md data / data_end, or sk_reuseport_md data / data_end. For reuseport, UDP selection starts at UDP header, TCP SYN at TCP header, migration has length 0. **Result and offset widths are i8 / i16 / i32 / i64**; previous unsupported widths caused crashes, silent 3/16-byte reads, or internal errors. Stage ③ rejects constant offset > 65535 − width. Allowed in loops except callbacks, which cannot capture context.

**Lowering**: Stage ③ reads the kind's range pair with UAPI widths via bpfabi.ctx_packet (cgroup_sockopt uses eight-byte optval / optval_end). For variable offsets, first branches to zero if off > MAX_PACKET_OFF − width, also catching high bits of i64 offsets. Then checks at + width ≤ data_end and loads bytes individually for strict alignment, except that a constant offset off with (2 + off) mod width = 0 (the strict-alignment verifier's NET_IP_ALIGN = 2 rule) is one width-aligned load (--tune-aligned-packet-load, enabled by default; =false keeps bytewise reads). i64 offsets are not zero-extended. Stage ② replaces provably in-range constant-offset reads with packet.window_load via W1.

**Evidence**: F10, F20. Kernel op checks exposed variable-offset rejection; explicit offset bound; byte loads; one wide load at strict-aligned constant offsets (three targets, normal and BPF_F_STRICT_ALIGNMENT, misaligned mutant rejected); window_load rewrites; width checks and three-target i64 offsets 2^32 + 12 / 2^63 returning 0.

**Unsupported**: Contexts whose PACKET entry is -, and widths outside 8 / 16 / 32 / 64 bits.

Interfaces: `MemoryEffectOpInterface (MemoryEffectOpInterface)`

Effects: `MemoryEffects::Effect{MemoryEffects::Read on ::mlir::ebpf::PacketResource}`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `offset` | signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | signless integer |



### `ebpf.packet.store` (ebpf::PacketStoreOp)

_Store an integer to a checked packet window_

Syntax:

```
operation ::= `ebpf.packet.store` $window `[` $index `]` `,` $value attr-dict `:` type($window) `,` type($value)
```

**Stage**: ① Input

**Meaning**: Writes a little-endian integer at constant index in a checked window, for XDP or a cgroup_sockopt own-entry window.

**Constraints**: Value is i8 / i16 / i32 / i64. [index, index + width) must fit the window, checked by subtraction to avoid overflow such as index −1. Window is a packet.check in_range argument. cgroup_sockopt stores require the own-entry checked optval window, not a static function. packet.check rejects read-only kinds such as sched_cls. Stage-② may-invalidate checking rejects uses if any path from definition crosses xdp.adjust_head / adjust_tail.

**Lowering**: Stage ③ extracts bytes with lshr / trunc and stores each at window + index + k, alignment 1. Memory effect is packet write.

**Evidence**: F11, F10. Three-target bounds / removed-check mutation / non-root variable offsets; rewrite and receiver checksum; post-helper-use rejection; closed sched_cls bypass.

**Unsupported**: Read-only kinds, static-function cgroup_sockopt windows, variable indices, and out-of-window stores.

Interfaces: `MemoryEffectOpInterface (MemoryEffectOpInterface)`

Effects: `MemoryEffects::Effect{MemoryEffects::Write on ::mlir::ebpf::PacketResource}`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>index</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `window` | a bounds-checked packet window of len bytes |
| `value` | signless integer |



### `ebpf.packet.window_load` (ebpf::PacketWindowLoadOp)

_Load an integer from a checked packet window_

Syntax:

```
operation ::= `ebpf.packet.window_load` $window `[` $index `]` attr-dict `:` type($window) `->` type($result)
```

**Stage**: ① Input (packet.check in_range window), also generated at ② by packet.load rewrites

**Meaning**: Reads at a constant index without another range check.

**Constraints**: Bytes must fit the window; out-of-range indices are rejected. Window is a packet.check in_range argument. Stage-② may-invalidate checking rejects any definition-to-use path crossing packet-pointer invalidation such as adjust_head / adjust_tail.

**Lowering**: Stage ③ loads bytes individually at window + constant, with strict alignment; when the window's pkt.check_br offset c is constant and (2 + c + index) mod width = 0 it is one width-aligned load (--tune-aligned-packet-load, enabled by default). Stage ② rewrites constant-offset packet.load directly in in_range entry (initial rewrite), sinks it before first use (C1), and also rewrites loads in blocks dominated by in_range (W1).

**Evidence**: F10, aligned wide reads. Initial rewrite / C1 / W1, non-neutral rewrite barriers, and the decision to retain this as a source-writable op rather than stage-②-only.

**Unsupported**: Variable indices (use packet.load). In loops, only windows from packet.check inside U loops are allowed; windows cannot cross iterations.

Interfaces: `MemoryEffectOpInterface (MemoryEffectOpInterface)`

Effects: `MemoryEffects::Effect{MemoryEffects::Read on ::mlir::ebpf::PacketResource}`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>index</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `window` | a bounds-checked packet window of len bytes |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | signless integer |



### `ebpf.perf.output` (ebpf::PerfOutputOp)

_Bpf_perf_event_output: zero or negative errno (fentry with perf_event_array and a fixed record)_

Syntax:

```
operation ::= `ebpf.perf.output` $ctx `,` $map `,` $record attr-dict `:` type($ctx) `,` type($map) `,` type($record) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Calls `perf_event_output(ctx, perf_event_array, current_cpu, &rec, sizeof rec)` to output a record to a perf ring. Returns **raw** i64 status: 0 on success, −ENOENT for an empty slot, −ENOSPC for ring overflow (observed).

**Constraints**: Only fentry program / context, including a static function's fentry context argument. Map is `!ebpf.map<"perf_event_array", i32, i32>`. Data is an ebpf.record.make result (all bytes, zero padding). Its record name / size must equal schema's map `record` nominal payload declaration (ebpf-verify-schema). Schema requires max_entries 0 (loader substitutes possible CPU count) and flags 0. Other program-side uses of perf_event_array are rejected.

**Lowering**: Stage ③ calls perf_event_output with UAPI `perfflag current_cpu`, record.make stack storage, and record size.

**Evidence**: F28. C oracle; success / −ENOENT / overflow tests and correction of BuildBTF's max_entries 0 → 1 handling; three targets and non-root.

**Unsupported**: Non-fentry kinds, explicit output CPU, and variable-length data. Compare lost / −ENOSPC counts only after draining and a successful flush on the same CPU.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `map` | any non-token type |
| `record` | a schema record identified by symbol and byte size for maps, reservations, perf output and subprogram arguments |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.probe.retval` (ebpf::ProbeRetvalOp)

_Read a function return register from kretprobe or uretprobe pt_regs_

Syntax:

```
operation ::= `ebpf.probe.retval` $ctx attr-dict `:` type($ctx) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Reads the return register (x86_64 rax, UAPI kproberet) as **raw eight-byte register bits**, truncated to iW with no type interpretation, like kprobe.arg. Pure.

**Constraints**: Context kind must have OPS probe.retval (kretprobe / uretprobe); width i8 / i16 / i32 / i64. Program requires arch; schema accepts x86_64 only and no params. Load-time attach companion arch / ctxfield pt_regs ax 80 8 rows check target BTF. attach_alias blocks cilium Kretprobe __x64_ fallback. uretprobe also checks binary hash / symbol and **target CU DW_AT_language C / C++**: Go gives uretprobe_abi; unknown language gives uretprobe_abi_unknown (policy8).

**Lowering**: Stage ③ uses bpfabi.kprobe_arg n = 0 for the fixed UAPI return-register offset / eight bytes, not CO-RE, then truncates. Exit checks UAPI with Conditional outcome because correctness depends on target pt_regs. No helper.

**Evidence**: F38. kretprobe bpf_fentry_test1 and uretprobe fixture probe_target return the same values as C; precheck blocks Go-function uretprobe.

**Unsupported**: Return type width / sign / pointer-ness is not checked: format9 companion rows contain only arch / ctxfield. rax has no defined meaning for void / struct-by-value returns. No other arch or argument reads (argument registers are clobbered at return).

Traits: `AlwaysSpeculatableImplTrait`

Interfaces: `ConditionallySpeculatable`, `NoMemoryEffect (MemoryEffectOpInterface)`

Effects: `MemoryEffects::Effect{}`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | signless integer |



### `ebpf.probe.target_arg` (ebpf::ProbeTargetArgOp)

_Read argument n for multi-probe target i only when it is the current target; otherwise return zero_

Syntax:

```
operation ::= `ebpf.probe.target_arg` $ctx `target` $target `arg` $n attr-dict `:` type($ctx) `->` type($value) `,` type($hit)
```

**Stage**: ① Input

**Meaning**: For entry kprobe_multi / uprobe_multi, when attach cookie equals i (%hit), reads one-based argument n (%v) at target_params[i]'s width. **Other targets produce value 0**, not another function's register interpreted with target i's type. This supports different signatures (e.g. int / int / char) while common kprobe.arg / uprobe.arg params describe a shared type. Cookie contract follows target_index: attach item i gets cookie i (§8).

**Constraints**: Own context with OPS probe.target_arg (kprobe_multi / uprobe_multi), i < attach-list length, n ≥ 1. Value i8 / i16 / i32 / i64 or, for uprobe_multi, user_str / user_buf; hit i1. Schema must have target_params[i][n] with matching width / type: ptr only i64; user_str / user_buf only their matching types. user_buf may escape only to user.read. Raw ptr / user_buf emit format18 mtargetarg ptr and require one-level eight-byte DWARF pointers (F78).

**Lowering**: Stage ③ compares get_attach_cookie to i, reads fixed UAPI kprobearg register n, truncates, and selects hit ? value : 0. user_str preserves raw i64 and false address0; it cannot convert to integer. user.read_str reports raw read status.

**Requirements**: With target_params, emit mtargetarg rows after mtarget in (i, n) order (format13), replacing kprobearg / uprobearg. ctxfield appears once for the union of all register n values. Load checks each target's parameter using existing argument rules. Wrong target_params count or n without an arch register fails explicitly without writing ELF.

**Evidence**: F68. Stage-③ lit shape; 7.1.8 root reads bpf_fentry_test1–3 parameter1 as int / int / char and compares to C. Per-target uprobe_multi user_str has compile checks; its runtime differential evidence belongs to its dedicated experiment.

**Unsupported**: Return-probe families and usdt.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>target</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
<tr><td><code>n</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `value` | 8-bit signless integer or 16-bit signless integer or 32-bit signless integer or 64-bit signless integer or a user-string pointer from a typed source, read only by ebpf.user.read_str or a typed uprobe user-buffer address |
| `hit` | 1-bit signless integer |



### `ebpf.probe.target_index` (ebpf::ProbeTargetIndexOp)

_Attach-list index of the current multi-probe function or symbol (attach cookie)_

Syntax:

```
operation ::= `ebpf.probe.target_index` $ctx attr-dict `:` type($ctx) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Returns zero-based attach-list index i as i64 for kprobe_multi / kretprobe_multi / uprobe_multi / uretprobe_multi. It is raw get_attach_cookie(ctx), meaningful as an index only under the **loader contract of attaching name i with cookie i** (requirements mtarget, requirements_format.md §8). Without cookies, all functions return 0 and are indistinguishable (7.1.8 source-only, unmeasured). Neither compiler nor verifier enforces bounds; callers must bound map keys / array indices, e.g. with arith.minui.
USDT also uses it: loader attaches note point i with cookie i and writes that point's spec at map index i (§8).

**Constraints**: Own program context of OPS probe.target_index kinds: the four multi probes and usdt. Single k/u probes and return probes are rejected: one attach, no cookie contract. Result i64; no static-function context because semantics depend on attach.

**Lowering**: Stage ③ calls UAPI get_attach_cookie using kmulti / umulti prototypes when expected_attach_type is trace_kprobe_multi / trace_uprobe_multi; requirements include helper row. Not pktinval, but deliberately absent from PacketNeutral because these kinds have no packets; C1 / W1 conservatively do not cross absent entries.

**Evidence**: F54. 7.1.8 root cilium KprobeMulti / KretprobeMulti / UprobeMulti / UretprobeMulti with Symbols in mtarget order and Cookies i; per-function counts compared to equivalent C using bpf_get_attach_cookie.

**Unsupported**: Arbitrary-u64 cookie API, single-probe / fentry / perf_event cookies, and kprobe.session bpf_session_cookie.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | 64-bit signless integer |



### `ebpf.program` (ebpf::ProgramOp)

_EBPF program with an attach kind_

Syntax:

```
operation ::= `ebpf.program` $sym_name $kind custom<ProgramAttach>($attach, $attach_list) (`arch` $arch^)? (`maps` $map_symbols^)? attr-dict-with-keyword $body
```

**Stage**: ① Input

**Meaning**: An attach unit, represented by a top-level module symbol. Kinds are defined in ProgramKinds.def, including xdp / tp_btf / fentry / fexit / kprobe / uprobe / sched_cls / raw_tp / kretprobe / uretprobe / iter / syscall / fmod_ret. The entry block takes one context (`!ebpf.ctx<kind>`) followed by zero or more map handles. Handles correspond **by position** to symbols in `maps [...]`; schema declares their capacity, flags, and BTF.
Exits use `ebpf.verdict`, `verdict.if`, `return` (kinds marked `|int` in VERDICTS), `redirect`, `redirect_map`, or `tail_call`.

**Constraints**: The op verifier rejects unknown kinds, mismatched context/program kinds, mismatched or duplicate map arguments/symbols, and a second context.
For ext (freplace), `attach` names the global BPF function being replaced (section `freplace/<function>`); the loader supplies the target program. Only `ebpf.ext.arg` may use the entry context. Stage ③ produces `llvm.func @name(i64 × (highest used index + 1)) -> i32|i64`; schema supplies the unsigned FUNC_PROTO signature (nargs / args / ret). Requirements carry family `freplace` and extret / extarg (format 11). All ebpf.return operations in a program must have the same type.
`attach` is required for tp_btf / raw_tp (tracepoint); fentry / fexit / kprobe / kretprobe / fmod_ret (kernel function); uprobe / uretprobe (symbol); sched_cls (`ingress` / `egress`); iter (target); and sk_skb / sk_msg (a sockmap / sockhash symbol present in program maps). The latter have no map value in the section name; requirements use the schema attach_target `map:<symbol>`. sk_skb stream_parser uses `attach "stream_parser:<map>"` and `ebpf.return` for the integer message length. sk_reuseport optionally accepts `attach "migrate"` (select_or_migrate); absence means select. `arch` is required for kprobe / uprobe / kretprobe / uretprobe and is not accepted by other kinds, except the multi-probe forms below.
Multi probes (kprobe_multi / kretprobe_multi / uprobe_multi / uretprobe_multi) require `arch` and an enumerated name list, e.g. `attach ["f1", "f2"]`. The verifier rejects an empty list, empty or duplicate names, and glob characters `*`, `?`, `[`. Other kinds cannot use a list. Item i becomes `mtarget <p> <i> <name>`; the loader attaches in list order and supplies cookie i, read by `ebpf.probe.target_index` (requirements_format.md §8). Schema attach_target must contain the identical ordered JSON string array, checked by ebpf-verify-schema.
A GCC-suffixed kprobe name such as `__do_pipe_flags.part.0` may exist only in kallsyms, while BTF FUNC has the unsuffixed name. A program that reads no arguments can pass precheck, attach, and fire, but **does not observe the original function's semantics**: `.part` is an outlined remainder and omits calls returning in the inlined prefix. Argument readers stop with `kprobearg_unknown` when BTF FUNC is absent. An unsuffixed name absent from kallsyms fails attach; no other function is substituted. Downstream measurements cover three kernels.
Schema checking requires declarations when coverage.programs = complete and checks kind / attach_target. fentry / fexit / sched_cls / kprobe / uprobe require declarations regardless of coverage. ebpf-compile accepts only program / func / timer.callback / user_ringbuf.callback directly under the module, and only `ebpf` / `arith` / `scf` operations in their bodies.

**Lowering**: Stage ② (ebpf-expand-regions) expands checked regions into cf branches and multiple blocks. Stage ③ normally creates `llvm.func @name(ptr) -> i32`, with kind-derived sections: `xdp`, `tp_btf/<tp>`, `fentry/<fn>`, `fexit/<fn>`, `kprobe/<fn>`, `uprobe/<sym>`, `tcx/<direction>`, `raw_tp/<tp>`, `kretprobe/<fn>`, `uretprobe/<sym>`, `iter/<target>`, `syscall`, `fmod_ret/<fn>`, or suffix-free `kprobe.multi` / `kretprobe.multi` / `uprobe.multi` / `uretprobe.multi`. It attaches `bpfabi.prog_type`, consumed by bpfabi-requirements.

**Evidence**: F01, F20, F21, F23, F24, F25, F54. Staged lowering; identical XDP ELF on two targets; tp_btf / fentry / fexit / kprobe / uprobe / sched_cls fixtures; kind × target legality; enumerated multi-probe targets.

**Unsupported**: Kinds outside the supported kind table are rejected. Non-context arguments other than map handles are not accepted. Stage ① does not accept a multi-block body mixed with cf operations. ebpf-verify-target-legality and load-time gates enforce kind × target restrictions for maps with timers / spin locks.

Traits: `IsolatedFromAbove`

Interfaces: `Symbol`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>sym_name</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>kind</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>attach</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>attach_list</code></td><td>::mlir::ArrayAttr</td><td>string array attribute</td></tr>
<tr><td><code>arch</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>map_symbols</code></td><td>::mlir::ArrayAttr</td><td>symbol ref array attribute</td></tr>
</table>



### `ebpf.record.make` (ebpf::RecordMakeOp)

_Construct a record from every field, with zero padding_

Syntax:

```
operation ::= `ebpf.record.make` $fields `(` $values `)` attr-dict `:` functional-type($values, $result)
```

**Stage**: ① Input

**Meaning**: Constructs all bytes of a schema record from every field, stored at declared offsets / widths with remaining padding zeroed. Fields are leaf paths (`x`, `x.y`, `x[i]`) in any order.

**Constraints**: Name / value counts match; names are unique. Result uses are limited to map.update / try_update values; map.lookup / update / delete / try_update / try_delete keys; ringbuf.store_record values; and perf.output records. No yield / call / block-crossing / loop-carried / atomic_add-key uses. ebpf-verify-records requires each @records leaf exactly once with matching width. Records with spin_lock / timer cannot be constructed. Allowed inside loop / callback bodies if the result does not cross the loop.

**Lowering**: Stage ③ normally allocates record-sized stack storage with alignment 8, zeros it via memset, and stores each field at @records offsets; the value is its pointer. When stores cover every byte, memset is omitted (C2). When the sole use is store_record and every byte is covered, D2 stores directly into the reservation without a stack record.

**Evidence**: F03, F02. C byte oracle; record values / keys on three targets; nested and array leaves; loops; non-root tests establishing that zero padding is the compiler's responsibility.

**Unsupported**: Partial construction, modifying an existing record, and spin_lock / timer records.

Traits: `AlwaysSpeculatableImplTrait`

Interfaces: `ConditionallySpeculatable`, `NoMemoryEffect (MemoryEffectOpInterface)`

Effects: `MemoryEffects::Effect{}`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>fields</code></td><td>::mlir::ArrayAttr</td><td>string array attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `values` | variadic of signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | a schema record identified by symbol and byte size for maps, reservations, perf output and subprogram arguments |



### `ebpf.redirect` (ebpf::RedirectOp)

_Terminate with the bpf_redirect result (sched_cls or lwt_xmit)_

Syntax:

```
operation ::= `ebpf.redirect` $ifindex `:` type($ifindex) (`when` $cond^ `else` $else_action)? attr-dict
```

**Stage**: ① Input

**Meaning**: A sched_cls / lwt_xmit terminator returning the unmodified result of `redirect(ifindex, 0)`. This requests an action; it does not report delivery. Even a nonexistent ifindex returns REDIRECT while the packet is not delivered.
In lwt_xmit, 7 (TC_ACT_REDIRECT) equals BPF_REDIRECT and causes post-program forwarding to the ifindex device. Its skb lacks an L2 header, so **redirect to a device with a MAC header (veth, dummy, etc.) is silently dropped by the kernel**, via −ERANGE in `__bpf_redirect_common`, despite appearing successful to the sender. Only headerless devices such as tun receive it.
With `when %c else "<verdict>"`, false returns the verdict. Ifindex belongs to the program's netns.

**Constraints**: HasParent<"ProgramOp"> restricts this terminator to the program's top-level body. The kind must have OPS marker `redirect` (sched_cls / lwt_xmit). `when` requires `else`, whose verdict must be valid for that kind (sched_cls pass / drop; lwt_xmit ok / drop).

**Lowering**: Stage ② expands the conditional form into `cf.cond_br` and unconditional `ebpf.redirect` / `ebpf.verdict`. Stage ③ zero-extends ifindex, calls `redirect` with flags 0, truncates the result to i32, and returns. A conditional form remaining at ③ is rejected.

**Evidence**: F20. C oracle; program-kind checks; three-target and non-root measurements with nonexistent ifindex returning REDIRECT without delivery. F57: lwt_xmit test run and actual 7.1.8 netns route attach.

**Unsupported**: XDP (use `ebpf.redirect_map`), lwt_in / lwt_out (kernel warns and converts BPF_REDIRECT to OK), redirect inside regions, configurable flags (always 0), and delivery-status observation. lwt_xmit cannot prepend L2 for MAC-header devices: no head-growth helper op exists.

Traits: `HasParent<ProgramOp>`, `Terminator`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>else_action</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ifindex` | 32-bit signless integer |
| `cond` | 1-bit signless integer |



### `ebpf.redirect_map` (ebpf::RedirectMapOp)

_Terminate with bpf_redirect_map (XDP with devmap, devmap_hash, cpumap, or xskmap)_

Syntax:

```
operation ::= `ebpf.redirect_map` $map `[` $key `]` `:` type($map) `,` type($key) `fallback` $fallback (`when` $cond^ `else` $else_action)? attr-dict
```

**Stage**: ① Input

**Meaning**: An XDP terminator returning the unmodified result of `redirect_map(map, key, flags)`. Without flags, a present entry yields REDIRECT and an absent entry yields the fallback verdict. For devmap / devmap_hash, `redirect_flags = "broadcast"` selects all entries regardless of key; `"broadcast_exclude_ingress"` excludes ingress. Even an empty map returns REDIRECT for broadcast; this is distinct from delivery. Userspace supplies devmap ifindices; updating a nonexistent ifindex fails with **-EINVAL** on all three measured targets. A `when %c else "<verdict>"` form is also available.

**Constraints**: A top-level terminator (HasParent<"ProgramOp">), only in XDP. Map kind must be devmap / devmap_hash / cpumap / xskmap, with matching i32 key and i32 value (ifindex / ifindex / qsize / AF_XDP socket fd respectively, supplied by userspace). Fallback is aborted / drop / pass / tx. redirect_flags is absent, broadcast, or broadcast_exclude_ingress, and may be set only for devmap / devmap_hash. Standalone exclude_ingress, unknown names, and broadcast on cpumap / xskmap are rejected. `when` requires `else` with an XDP verdict.
checkMapKind rejects generic lookup / update / try_update / delete / try_delete / atomic_add on these four map kinds. Dedicated scalar lookups exist for devmap_hash / xskmap. A cpumap key is a CPU number: that CPU's kthread turns the redirected frame into an skb and passes it to the original device's stack. A devmap_hash key is a hash key rather than an index. An xskmap key is an RX queue number; delivery requires the socket to be bound to the frame's device and queue.

**Lowering**: Stage ② expands `when` into cf.cond_br and unconditional redirect / verdict operations, preserving redirect_flags. Stage ③ ORs the UAPI fallback verdict with optional broadcast / exclude flags, zero-extends key, calls redirect_map, truncates to i32, and returns. Instructions without redirect_flags remain unchanged.

**Evidence**: F14, F60. C oracle; three-target and non-root tests for present / unset / nonexistent-ifindex / GRO-off paths. Actual 7.1.8 netns veth packets match C for cpumap / devmap_hash / xskmap. Non-root checks cover broadcast / conditional lowering / ABI, 4-byte MapSpec and existing requirements, and wide / signed / record rejection. On 7.1.8 own-netns veth native XDP, 24 four-byte C/ebpf arms match; six eight-byte arms are C-oracle only. Removing exclude_ingress is caught by ingress receive 1 versus expected 0. Requested flags 0 and actual RDONLY_PROG are distinguished.

**Unsupported**: Non-XDP kinds; fallback redirect; generic map operations. Program lookups are limited to the dedicated devmap_hash / xskmap scalar ops. Eight-byte cpumap / devmap / devmap_hash values and compiler-side second-program attachment remain separate work; C-only measurements cover PASS / DROP and ordinary-XDP-fd rejection. Broadcast evidence is limited to 7.1.8 own-netns veth native XDP; 6.12 / 6.6, generic XDP, physical NICs, and hotplug are unmeasured. The cpumap / devmap_hash / xskmap extension is unverified on 6.12 / 6.6. cilium v0.22 reduces cpumap max_entries to the possible CPU count.

Traits: `HasParent<ProgramOp>`, `Terminator`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>fallback</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>else_action</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>redirect_flags</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | any non-token type |
| `key` | 32-bit signless integer |
| `cond` | 1-bit signless integer |



### `ebpf.ref.atomic_add` (ebpf::RefAtomicAddOp)

_Atomically add to an integer through a borrowed reference (unchecked references are rejected)_

Syntax:

```
operation ::= `ebpf.ref.atomic_add` $ref `,` $delta attr-dict `:` type($ref) `,` type($delta)
```

**Stage**: ① Input

**Meaning**: Result-unused monotonic atomic add through a borrow. Also produced by stage-② map.atomic_add expansion, but directly writable in stage ①.

**Constraints**: Operand !ebpf.borrowed<T>, delta T; unchecked refs are rejected with a note. No lpm_trie addition or subprogram-argument borrows. **Only 32 / 64-bit widths**, as with map.atomic_add.

**Lowering**: Unchanged in ②. Stage ③ emits result-unused monotonic LLVM atomicrmw add (BPF non-FETCH lock +=), with explicit defensive rejection of unexpected widths.

**Evidence**: F01. Stage-② expansion; direct and expanded forms accepted on 7.1.8; ELF lock *(u32|u64) +=; width rules.

**Unsupported**: FETCH and non-add atomics.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ref` | any non-token type |
| `delta` | signless integer |



### `ebpf.ref.check` (ebpf::RefCheckOp)

_Check a nullable reference, introducing a borrow only inside the present region_

Syntax:

```
operation ::= `ebpf.ref.check` $ref attr-dict `:` type($ref) (`->` type($results)^)?
              `present` $presentRegion `absent` $absentRegion
```

**Stage**: ① Input

**Meaning**: Checks unchecked !ebpf.maybe_ref<T>: non-NULL executes present, NULL executes absent. In stage ① the checked !ebpf.borrowed<T> exists as a present-region block argument; syntax provides no unchecked dereference path. Both regions may return values with ebpf.yield.

**Constraints**: Both regions have bodies; present has one borrowed argument preserving T, absent none. The borrow is used only within present by ref.load / store / atomic_add / field.load / field.store, call arguments, ref.index, spin.region, or timer.init / set_callback / start. If T is a map handle (outer map-in-map element), only map.inner is permitted. Integer results are i1 / i8 / i16 / i32 / i64; other widths are rejected (older behavior accepted i1–i128). i1 is tested across three targets by kernel/cmd/i1check. Borrows cannot be yielded or transported via block arguments. If both arms break / continue, no results are permitted.

**Lowering**: Stage ② creates is_present cf.cond_br and true-edge assume_present; results become merge-block arguments. Stage ③ compares pointer against NULL (icmp ne) and branches, preserving the pointer for the borrow.

**Evidence**: F01. NULL-check-removal mutation rejected by kernel as map_value_or_null; stage-② expansion / exit checks; borrowed subprogram arguments; break / continue; result widths.

**Unsupported**: Borrow storage in maps / aggregates or escape outside the region. No unchecked unwrap.

Traits: `RecursiveMemoryEffects`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ref` | an unchecked nullable reference |

#### Results:

| Result | Description |
| :----: | ----------- |
| `results` | variadic of any non-token type |



### `ebpf.ref.field.atomic_add` (ebpf::RefFieldAtomicAddOp)

_Atomically add to a named field of a borrowed record, without a result_

Syntax:

```
operation ::= `ebpf.ref.field.atomic_add` $ref $field `,` $delta attr-dict `:` type($ref) `,` type($delta)
```

**Stage**: ① Input

**Meaning**: Atomically adds delta to a field using ref.field.load path rules. No FETCH of the old value, like ref.atomic_add. Shared-map counters do not lose multi-CPU updates; field.load / add / field.store does lose them.

**Constraints**: Checked record borrow only (unchecked rejection includes a note); no lpm_trie; **delta width 32 / 64 only**. ebpf-verify-records checks path / width, rejects spin_lock / timer fields, and requires field offset divisible by access byte width, together with map-value alignment 8 proving natural alignment. Rejected inside spin.region / timer.callback; accepted inside loops and per-CPU record fields (safe, allowing a common frontend form).

**Lowering**: Unchanged in ②. Stage ③ emits result-unused monotonic atomicrmw add at pointer + @records offset (BPF non-FETCH lock *(u32|u64) +=). Insufficient alignment / unexpected widths also fail explicitly at ③ as defense in depth.

**Evidence**: F03. Three-target root / non-root concurrent multi-CPU fieldatomic test runs preserve counts, while the same-record load / store += control loses them. ELF has non-FETCH lock +=.

**Unsupported**: FETCH, non-add atomics, and elem.atomic_add for ref.index elements. No acquire / release ordering semantics (docs/memory_semantics.md).

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ref` | any non-token type |
| `delta` | signless integer |



### `ebpf.ref.field.load` (ebpf::RefFieldLoadOp)

_Load a named field from a borrowed record_

Syntax:

```
operation ::= `ebpf.ref.field.load` (`once` $once^)? $ref $field attr-dict `:` type($ref) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Reads a named path in !ebpf.borrowed<!ebpf.record<"S", N>>. Paths are x / x.y / x[i] with constant indices. Schema determines offsets / widths, read from @records BTF declarations; the compiler does not compute layout. once follows ref.load.

**Constraints**: Operand must be a record borrow; unchecked refs are rejected with a note. ebpf-verify-records checks field presence, path form (≤ 3 components, integer arrays ≤ 2 dimensions, record arrays one dimension, constant in-range indices), and result width. spin_lock / timer field reads, including lock.val paths, are rejected. Subprogram-argument borrows can be read. once needs 8–64-bit width and naturally aligned access provable at ③.

**Lowering**: Stage ③ loads borrowed pointer + @records offset with alignment proved from map-value alignment 8 and offset; once adds volatile.

**Evidence**: F03, F29. @records checks on three targets; nested / array elements; depth 3 / two dimensions; borrowed record subprogram arguments; rejection of once without provable alignment.

**Unsupported**: Variable indices (use ref.index) and non-leaf paths.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>once</code></td><td>::mlir::UnitAttr</td><td>unit attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ref` | any non-token type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | signless integer |



### `ebpf.ref.field.store` (ebpf::RefFieldStoreOp)

_Store a named field of a borrowed record_

Syntax:

```
operation ::= `ebpf.ref.field.store` (`once` $once^)? $ref $field `,` $value attr-dict `:` type($ref) `,` type($value)
```

**Stage**: ① Input

**Meaning**: Writes an integer by path, following ref.field.load's offset / path rules. once follows ref.store.

**Constraints**: Operand is a record borrow; lpm_trie writes are rejected. ebpf-verify-records checks path / width and rejects spin_lock / timer field writes. Subprogram-argument borrows cannot be used (callees read only). Within spin.region, only non-lock fields of that same borrow can be written.

**Lowering**: Stage ③ stores at borrowed pointer + @records offset with provable alignment; once adds volatile.

**Evidence**: F03, F29. Three-target record / nested / array tests and borrowed-record subprogram arguments. Subsequent callee-write support permits these writes in callees.

**Unsupported**: Variable indices use ref.index / elem.store; whole-record replacement uses map.update / record.make.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>once</code></td><td>::mlir::UnitAttr</td><td>unit attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ref` | any non-token type |
| `value` | signless integer |



### `ebpf.ref.index` (ebpf::RefIndexOp)

_Check variable indices into a record array field and execute in-range or out-of-range regions_

Syntax:

```
operation ::= `ebpf.ref.index` $ref $field `[` $indices `]` attr-dict `:` type($ref) `,` type($indices) (`->` type($results)^)?
              `in_range` $inRange `out_of_range` $outOfRange
```

**Stage**: ① Input

**Meaning**: Indexes a borrowed record's array field with variable i32 indices. Each [] in a field template represents one variable index: arr equals arr[], and ins[].addr / m[][] are supported. For every dimension, checks unsigned index < element count. All checks passing executes in_range with a checked !ebpf.elem<iN> block argument; any failure executes out_of_range. The program explicitly defines out-of-range behavior: no implicit zero / clamp / mask result.

**Constraints**: Operand is a record borrow, with at least one index. in_range has one elem argument; out_of_range has none. Only elem.load / elem.store inside in_range may use it; no yield / block-argument transport. ebpf-verify-records checks template, [] / index count, and width against @records. Subprogram-argument borrows are excluded. Integer result widths are i1 / 8 / 16 / 32 / 64 only (other widths rejected; older behavior allowed i1–i128). i1 is differentially tested on three targets with kernel/cmd/i1check.

**Lowering**: Stage ② zero-extends each index once, then emits per-dimension elem.in_range cf.cond_br checks and true-edge elem.at. Stage ③ uses icmp ult and base + field offset + index × stride with the same compared / addressed value. **A loop IV may cause codegen to form the address using a different induction variable**; inspect ELF.

**Evidence**: F06. Variable indices, multidimensional / record arrays, C agreement on three targets, and loop-IV indexing rejected on all three targets without CAP_PERFMON. Result-width checks.

**M1 (default)**: On each true checked edge, stage ② passes the index through elem.mask (③ inline-asm barrier plus and 2^k − 1), rechecks elem.in_range (same out_of_range on false), and uses that value in elem.at. Values are unchanged. This removes non-root 6.12 / 6.6 speculative-path rejection at a repeated index comparison. **The guarantee requires the masked address range to fit the value**: field offset + (2^k − 1) × stride + element size ≤ record size. Non-fitting arrays, such as a trailing non-power-of-two array, produce a warning, disabled by --warn-index-mask-fit=false without ELF changes. If spilling loses the recheck's narrowing, 6.6 may reject; padding after the array through the next power of two brings it within the guarantee. For nonconstant indices, cost is +2 instructions per dimension (and / recheck; barrier emits no instruction), with measured processed change −7 to +6. **Direct constant dimensions, including unrolled IVs, omit M1 by default**: the verifier knows them exactly. --tune-mask-skip-constant-index=false restores the earlier form. Previously each unrolled copy cost +5–6 instructions because the barrier obscured constants and retained register load / and / recheck / shift / add; eight copies cost +40–48 instructions and +8–84 processed. --tune-mask-checked-index=false restores pre-M1 output.

**Diagnostics**: ebpf-compile warns, without stopping or changing ELF, when constant and unknown values reach the same index on different paths (e.g. a lookup-failure default) or when a non-unrolled loop carries it. --warn-nonroot-index=false disables this. Such shapes were rejected by some kernels without CAP_PERFMON. Conditions of enclosing ebpf.if are evaluated with arm constants to exclude unreachable defaults. **An unflagged rejection shape** remains: a user if compares the index with a threshold below element count, and arm helpers preserve the branch through LLVM. Different index ranges then reach the same addition, causing non-root REASON_PATHS rejection on three kernels. M1 does not unify those ranges. Stage ① cannot know whether optimization retains the branch; warning would falsely flag variants with empty arms or thresholds ≥ count. Move ref.index inside the user-if arms or use CAP_PERFMON.

**Unsupported**: CAP_PERFMON-less loop-IV indexing can fail at load; lowering / requirements are not changed for it. No implicit out-of-range value.

Traits: `RecursiveMemoryEffects`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ref` | a checked borrowed reference without ownership |
| `indices` | variadic of 32-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `results` | variadic of any non-token type |



### `ebpf.ref.load` (ebpf::RefLoadOp)

_Load through a borrowed reference (unchecked references are rejected)_

Syntax:

```
operation ::= `ebpf.ref.load` (`once` $once^)? $ref attr-dict `:` type($ref) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Reads the integer pointed to by a borrow. once emits each access exactly once at its declared width (volatile at ③), not acquire / release or atomicity; see docs/memory_semantics.md.

**Constraints**: Operand !ebpf.borrowed<T>, result T. An unchecked maybe_ref is rejected with a note to use ref.check first. No whole-record reads (use ref.field.load). Subprogram-argument borrows are accepted for callee reads. once supports 8 / 16 / 32 / 64-bit integers only, checked at ③.

**Lowering**: Stage ③ loads from the pointer with alignment provable from map-value alignment 8; once adds volatile.

**Evidence**: F01, F29. 7.1.8 acceptance; subprogram arguments; once width checks and normal / once paired tests.

**Unsupported**: Whole-record reads; once i1 / i24 and other unsupported widths fail at ③.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>once</code></td><td>::mlir::UnitAttr</td><td>unit attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ref` | any non-token type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | any non-token type |



### `ebpf.ref.store` (ebpf::RefStoreOp)

_Store through a borrowed reference (unchecked references are rejected)_

Syntax:

```
operation ::= `ebpf.ref.store` (`once` $once^)? $ref `,` $value attr-dict `:` type($ref) `,` type($value)
```

**Stage**: ① Input

**Meaning**: Writes the integer pointed to by a borrow. once follows ref.load and becomes a volatile store at ③.

**Constraints**: Operand is !ebpf.borrowed<T> and value type is T; unchecked references are rejected with a note. No whole-record stores (use ref.field.store). lpm_trie lookup borrows are read-only by compiler restriction. Subprogram-argument borrows are excluded by this documented constraint (read-only callee). once uses ref.load width limits.

**Lowering**: Stage ③ stores to the borrowed pointer, with alignment derived from map-value alignment 8; once makes it volatile.

**Evidence**: F01, F29. 7.1.8 acceptance; lpm_trie-write rejection; once tests. Borrowed writes originate in the predecessor compiler's borrowed-reference implementation.

**Unsupported**: Whole-record stores and lpm_trie value writes.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>once</code></td><td>::mlir::UnitAttr</td><td>unit attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ref` | any non-token type |
| `value` | any non-token type |



### `ebpf.return` (ebpf::ReturnOp)

_Terminate by returning one integer from a subprogram or program_

Syntax:

```
operation ::= `ebpf.return` $value attr-dict `:` type($value)
```

**Stage**: ① Input

**Meaning**: Returns one integer from ebpf.func. Also terminates ebpf.program by returning a raw i32 for unnamed-verdict kinds: socket_filter retains that many bytes (0 drops, ≥ len retains all); syscall exposes BPF_PROG_TEST_RUN retval; fmod_ret calls the original function only for 0, otherwise substitutes the returned value; ext returns from the replacement function.

**Constraints**: ParentOneOf accepts ebpf.func or ebpf.program, not a tail-call fallback. In a function, operand type must match the result type. In a program, kind must have VERDICTS `|int` (including socket_filter / syscall / fmod_ret, whose verifier does not impose a return range). Operand is i32, or i32 / i64 for ext as checked against schema ret. struct_ops members with schema ret void cannot contain ebpf.return. Out-of-range **constants** for `|int:<range>` are rejected: u32 means all 32 bits; lo..hi is signed. Nonconstant values are not range-checked here.

**Lowering**: Unchanged in ②; stage ③ emits llvm.return, not a UAPI verdict. For kinds with negative range lower bounds (currently lsm), constant arms of a defining arith.select, recursively through arm selects, pass through an instruction-free inline-asm barrier (`"=r,0"`). This prevents the BPF backend folding `select c, -1, 0` to sign extension / BPF_NEG (`r = -r`), whose range the 6.12 verifier cannot track. The select becomes branches with constant R0 on each path.

**Evidence**: F08, F40, F41, F47. Direct function return; syscall retval; fmod_ret replacement; socket_filter truncation matching C test-run retval; ext replacement return measured through its target XDP program's test run; LSM select returns matching C on actual 7.1.8 / 6.12.111 / 6.6.157 attach.

**Unsupported**: Multiple or zero results. Kinds whose verifier enforces verdict ranges (XDP / cgroup family / iter / fentry etc.) use named ebpf.verdict instead.

Traits: `HasParent<SubprogramOp, ProgramOp>`, `Terminator`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `value` | any non-token type |



### `ebpf.ringbuf.discard` (ebpf::RingbufDiscardOp)

_Discard a reservation (consumes it)_

Syntax:

```
operation ::= `ebpf.ringbuf.discard` $reservation attr-dict `:` type($reservation)
```

**Stage**: ① Input

**Meaning**: Discards it without reader visibility. **Consumes** reservation; no later use.

**Constraints**: Same as submit: exactly one consumption per present path; post-consumption use rejected.

**Lowering**: Stage ③ ringbuf_discard(ptr, flags0).

**Evidence**: F02. Ownership and three-target tests.

**Unsupported**: Flags other than0.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `reservation` | a successful ring-buffer reservation, linearly consumed exactly once |



### `ebpf.ringbuf.discard_dynptr` (ebpf::RingbufDiscardDynptrOp)

_Discard and consume a dynptr reservation; failed reservations are no-ops_

Syntax:

```
operation ::= `ebpf.ringbuf.discard_dynptr` $dynptr attr-dict `:` type($dynptr)
```

**Stage**: ① Input

**Meaning**: ringbuf_discard_dynptr(&dynptr,0) hides the event from readers; storage remains until consumer passes it. **Consumes** dynptr. Failed reservations do nothing.

**Constraints**: Same as submit_dynptr.

**Lowering**: Stage ③ ringbuf_discard_dynptr(slot_d,0).

**Evidence**: F02. Dynptr differential tests.

**Unsupported**: Flags other than0.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `dynptr` | a kernel dynptr, an opaque 16-byte stack object describing a runtime-sized memory window |



### `ebpf.ringbuf.if_reserved` (ebpf::RingbufIfReservedOp)

_Execute present only when ring-buffer reservation succeeded_

Syntax:

```
operation ::= `ebpf.ringbuf.if_reserved` $reservation attr-dict `:` type($reservation) (`->` type($results)^)?
              `present` $presentRegion `absent` $absentRegion
```

**Stage**: ① Input

**Meaning**: Checks an unchecked reserve result and selects present / absent. A valid reservation<R> exists **only as a present-region block argument**; no op returns it in stage ①, so unchecked use has no syntactic path, like ref.check. Both regions can yield results (-> T…), e.g. submit then true / absent false.

**Constraints**: Both regions have bodies; present has one reservation preserving record type, absent no arguments. Absent cannot store / submit / discard / task.comm / user.read_str. Integer result widths are i1 / 8 / 16 / 32 / 64; others rejected (older behavior accepted i1–i128). Three-target i1 evidence uses kernel/cmd/i1check. Reservation uses are store_field / store_record / submit / discard / task.comm / user.read_str, confined to present without block-argument transport.
**Exactly one consumption on every path**: branch-wise submit / discard is allowed through ebpf.if, ref.check, packet.check, nesting, and result yields. Op verifier requires at least one submit / discard syntactically. Every-path single consumption, missing / double consumption, and nonconsuming use after consumption are checked by ebpf-verify-ownership, unconditionally first in ebpf-compile, and stage-② checkLinear. **Standalone ebpf-opt op verification does not inspect paths**; contract applies to ebpf-compile input. Yield types must match parent results and cannot carry reservation. Yield neither consumes nor uses it; results do not change ownership rules.

**Lowering**: Stage ② is_present branch plus true-edge assume_present; results become merge-block arguments. Stage ③ NULL compare / branch, results as phi.

**Evidence**: F02. Post-consumption-use rejection; three targets; ringresult runner compares success / event counts and absent-status-selected verdicts, with inverted-result mutation failing. Width checks. Branch-wise consumption C/ebpf ELF accepted on three kernels × root / non-root.

**Unsupported**: Reservation subprogram arguments and cross-block transport.

Traits: `RecursiveMemoryEffects`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `reservation` | an unchecked reservation that may have failed |

#### Results:

| Result | Description |
| :----: | ----------- |
| `results` | variadic of any non-token type |



### `ebpf.ringbuf.output` (ebpf::RingbufOutputOp)

_Bpf_ringbuf_output: copy and commit a record.make result without exposed reservation, returning status_

Syntax:

```
operation ::= `ebpf.ringbuf.output` $ringbuf `,` $record (`flags` $flags^)? attr-dict `:` type($record) `->` type($status)
```

**Stage**: ① Input

**Meaning**: ringbuf_output(&ringbuf, &rec, sizeof rec, flags) copies every record byte and commits it. **Raw** i64 status is0 or −EAGAIN for insufficient ring space (7.1.8 kernel/bpf/ringbuf.c; same internal __bpf_ringbuf_reserve). No ownership tracking is exposed, unlike reserve / if_reserved / store / submit: helper closes the lifecycle. Absent flags mean0, waking readers only when the consumer has caught up. no_wakeup suppresses notification; force_wakeup always notifies (UAPI ringbufconst).

**Constraints**: Data is record.make (all bytes, zero padding); named flags limited to no_wakeup / force_wakeup. Schema map kind ringbuf and nominal record name / size must match. Size bound follows reserve: round_up(N + hdr_sz,8) > max_entries−1 fails schema checking, otherwise every call would give −EAGAIN. No kind restriction (base helper prototype). No loop bodies.

**Lowering**: Stage ③ calls UAPI ringbuf_output with record.make stack data, record size, and UAPI flags.

**Evidence**: F02. 7.1.8 XDP test runs match C for success / −EAGAIN counts, event bytes, and wakeup notifications.

**Unsupported**: Variable lengths (use dynptr), non-record data, loop bodies. 6.12 /6.6 unmeasured.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>ringbuf</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>flags</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `record` | a schema record identified by symbol and byte size for maps, reservations, perf output and subprogram arguments |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.ringbuf.reserve` (ebpf::RingbufReserveOp)

_Attempt to reserve ring-buffer storage_

Syntax:

```
operation ::= `ebpf.ringbuf.reserve` $ringbuf attr-dict `:` type($result)
```

**Stage**: ① Input

**Meaning**: Reserves the result record's size from the schema ringbuf map named by attribute. Returns **unchecked** maybe_reservation<record<S,N>>; helper may return NULL. Must pass ringbuf.if_reserved before use; a valid reservation exists only as its present-region argument.

**Constraints**: Schema map kind ringbuf and record name / size must match. Ringbuf schema requires a nominal record, so integer reservations are unsupported. Every path consumes a valid reservation exactly once by submit or discard (ownership checking). No scf.if or loop-called subprogram placement. No kind restriction.
**Reservation size ≤ max_entries − 16** (schema verifier): kernel requires round_up(size + BPF_RINGBUF_HDR_SZ, 8) ≤ max_entries − 1 even for an empty ring (three-kernel __bpf_ringbuf_reserve; UAPI ringbufconst hdr_sz). Oversized requests would load but always return absent, so compile rejects them: a4096 ring allows4080.

**Lowering**: Stage ③ ringbuf_reserve(map, record size, flags0); stage ② expands if_reserved to a NULL branch.

**Evidence**: F02. Identical-ELF two-target differential tests; record flow on three targets; C ring-event oracle and three targets. Record/schema matching descends from the predecessor compiler. Three kernels reserve4080 but always reject4088 at runtime.

**Unsupported**: Flags other than0, dynamic sizes, and dynptr reserve (reservation-free copy uses ringbuf.output). **Ring size ≤ 2^29 bytes (512 MiB)**: btf-verify K9 rejects max_entries >1073741823, including 2^30 rings, because BTF int (*max_entries)[N] exceeds U32_MAX bytes. All three kernels reject that BTF; libbpf silently drops it. Clang C emits the same BTF.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>ringbuf</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | an unchecked reservation that may have failed |



### `ebpf.ringbuf.reserve_dynptr` (ebpf::RingbufReserveDynptrOp)

_Reserve a runtime-sized ring-buffer dynptr, returning status (consumption required even on failure)_

Syntax:

```
operation ::= `ebpf.ringbuf.reserve_dynptr` $ringbuf `,` $size attr-dict `:` type($size) `->` type($dynptr) `,` type($status)
```

**Stage**: ① Input

**Meaning**: ringbuf_reserve_dynptr(&ringbuf, size,0,&dynptr) reserves runtime i32 size interpreted u32. Returns stack dynptr<ringbuf> and **raw** i64 status:0, −EINVAL for full ring (unlike output −EAGAIN on7.1.8), −E2BIG beyond dynptr limit2^24−1. **Failed dynptrs must still be consumed**, as kernel verifier requires. They are null; read / write gives −EINVAL, submit / discard does nothing. No NULL-check region; inspect status.

**Constraints**: Dynptr uses only write / read / submit_dynptr / discard_dynptr, no yield / call / loop capture. No scf.if / loop bodies. Every path from definition through region exit consumes exactly once; later use, crossing loops while live, or reaching tail_call while live is rejected. Schema requires ringbuf map; direct constant size uses reserve's size bound. **No match against map record declaration**: event size / layout are author's responsibility. No loop-called subprograms.

**Lowering**: Stage ③ allocates16 entry-stack bytes aligned8, used only as helper argument, then calls ringbuf_reserve_dynptr(&map,zext(size),0,slot).

**Evidence**: F02. 7.1.8 XDP test-run success / status / event bytes match C.

**Unsupported**: Flags other than0; 6.12 /6.6 unmeasured.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>ringbuf</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `size` | 32-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `dynptr` | a kernel dynptr, an opaque 16-byte stack object describing a runtime-sized memory window |
| `status` | 64-bit signless integer |



### `ebpf.ringbuf.store_field` (ebpf::RingbufStoreFieldOp)

_Store an integer at a reserved record's byte offset_

Syntax:

```
operation ::= `ebpf.ringbuf.store_field` $reservation `[` $offset `]` `,` $value attr-dict `:` type($reservation) `,` type($value)
```

**Stage**: ① Input

**Meaning**: Writes one integer's bytes at [offset] of a valid reserved record. Does not consume it.

**Constraints**: Op verifier requires record reservation and in-record offset / width. Schema verifier additionally requires that range to match an integer record field. No absent / scf.if / post-consumption placement. Only written bytes are defined; compiler does not initialize unwritten bytes or padding. To define all bytes use record.make / store_record.

**Lowering**: Stage ③ stores at reservation pointer + offset with alignment provable from reservation alignment8 / offset.

**Evidence**: F02. Field-based stores replace the removed whole-scalar ringbuf.store; one integer uses a one-field record. Record-flow tests and schema-offset validation inherited from the predecessor compiler.

**Unsupported**: Named fields (use record.make names); this op uses byte offsets.

Interfaces: `MemoryEffectOpInterface (MemoryEffectOpInterface)`

Effects: `MemoryEffects::Effect{MemoryEffects::Write on ::mlir::ebpf::ReservationResource}`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>offset</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `reservation` | a successful ring-buffer reservation, linearly consumed exactly once |
| `value` | signless integer |



### `ebpf.ringbuf.store_record` (ebpf::RingbufStoreRecordOp)

_Copy every byte of a record.make result into a reserved record_

Syntax:

```
operation ::= `ebpf.ringbuf.store_record` $reservation `,` $value attr-dict `:` type($reservation) `,` type($value)
```

**Stage**: ① Input

**Meaning**: Copies all declared record bytes, including zero padding, into a valid reservation. Does not consume it; submit / discard is still required.

**Constraints**: Record reservation and value must have identical nominal name / size. Value must come directly from record.make, not block arguments / other ops. Placement follows store_field: no absent / scf.if / post-consumption use.

**Lowering**: Stage ③ normally copies record.make stack storage into reservation with explicit source / destination alignment. If this is the sole use and field stores cover every byte, D2 avoids stack storage and stores fields directly, merging adjacent constants at provable widths. --tune-store-record-merge=false restores pre-D2 output.

**Evidence**: F02. Copy / alignment tests; D1 rejected because constant stores did not merge into wide stores; D2 adoption / regression checks.

**Unsupported**: Integer values (not restoration of removed scalar ringbuf.store) and partial-record copy.

Interfaces: `MemoryEffectOpInterface (MemoryEffectOpInterface)`

Effects: `MemoryEffects::Effect{MemoryEffects::Write on ::mlir::ebpf::ReservationResource}`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `reservation` | a successful ring-buffer reservation, linearly consumed exactly once |
| `value` | a schema record identified by symbol and byte size for maps, reservations, perf output and subprogram arguments |



### `ebpf.ringbuf.submit` (ebpf::RingbufSubmitOp)

_Commit a reservation (consumes it)_

Syntax:

```
operation ::= `ebpf.ringbuf.submit` $reservation attr-dict `:` type($reservation)
```

**Stage**: ① Input

**Meaning**: Makes a valid reservation visible to userspace readers. **Consumes** it; no subsequent use.

**Constraints**: Reservation is if_reserved present block argument. Every CFG path submits or discards exactly once: double consumption is kernel use-after-free, omission leaks ring space. Ownership checking rejects later nonconsuming store_field / task.comm etc.

**Lowering**: Stage ③ ringbuf_submit(ptr, flags0).

**Evidence**: F02. Ownership rejection and three-target observations / negative controls.

**Unsupported**: NO_WAKEUP / FORCE_WAKEUP flags; only0.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `reservation` | a successful ring-buffer reservation, linearly consumed exactly once |



### `ebpf.ringbuf.submit_dynptr` (ebpf::RingbufSubmitDynptrOp)

_Commit and consume a dynptr reservation; failed reservations are no-ops_

Syntax:

```
operation ::= `ebpf.ringbuf.submit_dynptr` $dynptr attr-dict `:` type($dynptr)
```

**Stage**: ① Input

**Meaning**: ringbuf_submit_dynptr(&dynptr,0) commits to the reader and **consumes** dynptr, forbidding later use. Failed/null reservations do nothing.

**Constraints**: Direct reserve_dynptr result; exactly one submit / discard per path. No scf.if / loop bodies.

**Lowering**: Stage ③ ringbuf_submit_dynptr(slot_d,0).

**Evidence**: F02. Dynptr differential tests.

**Unsupported**: Wakeup flags other than0.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `dynptr` | a kernel dynptr, an opaque 16-byte stack object describing a runtime-sized memory window |



### `ebpf.seq.write` (ebpf::SeqWriteOp)

_Bpf_seq_write: write complete record bytes to an iterator seq_file and return status_

Syntax:

```
operation ::= `ebpf.seq.write` $seq `,` $record attr-dict `:` type($seq) `,` type($record) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Calls seq_write(seq, &rec, sizeof rec), returning **raw** i64 status: 0 on success, −E2BIG for seq_file-buffer overflow. Bytes become read(2) output from the iterator fd.

**Constraints**: iter programs only (OPS seq.write). seq is !ebpf.kptr<"seq_file"> read from bpf_iter_meta.seq with kfield.ptr and validated by kptr.check. Data is record.make (all bytes, zero padding). Kernel tracing_prog_func_proto permits this GPL helper only with expected_attach_type BPF_TRACE_ITER.

**Lowering**: Stage ③ calls UAPI seq_write with record.make stack storage and record size.

**Evidence**: F39. iter/bpf_map_elem read output is byte-identical to equivalent C.

**Unsupported**: seq_printf / seq_printf_btf and variable-length data.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `seq` | a pointer to an internal kernel struct obtained from tracing arguments |
| `record` | a schema record identified by symbol and byte size for maps, reservations, perf output and subprogram arguments |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.session.cookie.load` (ebpf::SessionCookieLoadOp)

_Read the eight-byte cookie shared between session entry and return_

Syntax:

```
operation ::= `ebpf.session.cookie.load` $ctx attr-dict `:` type($ctx) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Reads the i64 cookie shared by entry / return for one invocation of the link's function (kernel session run-context data). Typically store at entry and load at return. Initial entry value is expected zero from 7.1.8 source reading only, not measured.

**Constraints**: Follows session.is_return: own session-kind context and kfunc-table program type.

**Lowering**: Stage ③ calls bpf_session_cookie(ctx) -> ptr, then loads eight bytes. No ret_null in the table: kernel type is non-null PTR_TO_MEM of size8.

**Evidence**: F66. Entry stores 0xE473 and return sums it, compared with C.

**Unsupported**: Kernel signature differences follow session.is_return. No op exposes the cookie pointer itself; load / store only.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | 64-bit signless integer |



### `ebpf.session.cookie.store` (ebpf::SessionCookieStoreOp)

_Write the eight-byte cookie shared between session entry and return_

Syntax:

```
operation ::= `ebpf.session.cookie.store` $ctx `,` $value attr-dict `:` type($ctx) `,` type($value)
```

**Stage**: ① Input

**Meaning**: Writes i64 to the cookie described by session.cookie.load.

**Constraints**: Same as session.is_return; value i64.

**Lowering**: Stage ③ calls bpf_session_cookie(ctx) -> ptr and stores eight bytes.

**Evidence**: F66. Session cookie differential tests.

**Unsupported**: Same as session.cookie.load.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `value` | 64-bit signless integer |



### `ebpf.session.is_return` (ebpf::SessionIsReturnOp)

_Test whether a session program is executing at function return (bpf_session_is_return kfunc)_

Syntax:

```
operation ::= `ebpf.session.is_return` $ctx attr-dict `:` type($ctx) `->` type($result)
```

**Stage**: ① Input

**Meaning**: kprobe_session / fsession run the same program at entry and return. Returns i1 true at return, interpreting nonzero bpf_session_is_return(ctx) bool as true.

**Constraints**: Own context with OPS session, not static-function context. Program type must occur in the UAPI kfunc table generated from kernel source / vmlinux BTF.

**Lowering**: Stage ③ calls bpfabi.kfunc_call bpf_session_is_return(ctx) -> i8 and compares != 0. Stage ④ calls an extern .ksyms function; BTF FUNC_PROTO follows table bool(void *ctx). The 7.1.8 verifier inlines fsession calls.

**Evidence**: F66. 7.1.8 root kprobe-session / fsession entry / return counts compared with C.

**Unsupported**: **Signature varies by kernel**: 7.1.8 bool(void *ctx), 6.12 bool(void), absent on 6.6. Format13 kfunc requirement rows check target FUNC_PROTO before load; 6.12's void signature and 6.6 absence stop with kfunc_sig. Handwritten-requirement checks exist, but generated-ELF checking on 6.12 / 6.6 was not measured in the original extension. No uprobe session.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | 1-bit signless integer |



### `ebpf.sk.assign` (ebpf::SkAssignOp)

_Select a checked socket as an sk_lookup result, returning raw bpf_sk_assign status_

Syntax:

```
operation ::= `ebpf.sk.assign` $ctx `,` $sock (`replace` $replace^)? (`no_reuseport` $no_reuseport^)? attr-dict `:` type($ctx) `,` type($sock) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Calls sk_assign(ctx, sk, flags) using the sk_lookup bpf_sk_lookup_assign prototype to select a sock.map_lookup-acquired socket. Raw status 0 selects it; negative errno leaves previous selection unchanged: invalid flags −EINVAL; refcounted sockets, non-LISTEN TCP, or non-CLOSE UDP −ESOCKTNOSUPPORT; protocol mismatch −EPROTOTYPE; family mismatch −EAFNOSUPPORT; already selected without replace −EEXIST (net/core/filter.c, same on three kernels). Selection becomes the lookup result only for SK_PASS; destination address / port are unchanged. replace replaces earlier selection; no_reuseport skips reselecting within the chosen socket's reuseport group.

**Constraints**: Own sk_lookup body entry context with OPS sk.assign. Socket is sock.ref_check present sock_ref (assume_present at ②). **Nonconsuming use**, permitted only before release; ownership checking rejects post-release use and separately requires exactly one release on every path. No NULL deselection form.

**Lowering**: Unchanged in ②; stage ③ calls sk_assign(ctx, sock, flags), ORing UAPI sklookupflag replace / no_reuseport, or 0 if absent. i64 result.

**Evidence**: F61. Three-kernel test-run ctx_out cookies / status for eight arms compared to C, plus actual netns-link dispatch.

**Unsupported**: NULL deselection, ctx sk reads, and other kinds (TC bpf_sk_assign has another prototype).

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>replace</code></td><td>::mlir::UnitAttr</td><td>unit attribute</td></tr>
<tr><td><code>no_reuseport</code></td><td>::mlir::UnitAttr</td><td>unit attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `sock` | a checked non-NULL owned socket reference with linear release |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.sk.redirect` (ebpf::SkRedirectOp)

_Terminate with bpf_sk_redirect_map or bpf_sk_redirect_hash (sk_skb with sockmap or sockhash)_

Syntax:

```
operation ::= `ebpf.sk.redirect` $ctx `,` $map `[` $key `]` (`ingress` $ingress^)? `:` type($ctx) `,` type($map) `,` type($key) (`when` $cond^ `else` $else_action)? attr-dict
```

**Stage**: ① Input

**Meaning**: An sk_skb terminator returning the unmodified result of `sk_redirect_map(skb, sockmap, key, flags)` or `sk_redirect_hash(skb, sockhash, &key, flags)`. A present socket sets skb's destination and returns SK_PASS; the kernel redirects to it. An absent socket or LISTEN TCP socket yields SK_DROP. `ingress` (BPF_F_INGRESS) queues to the destination socket's receive path; otherwise egress sends from it. Redirection is asynchronous on a workqueue: status accepts the request, not delivery. With `when %c else "<verdict>"`, false returns the verdict.

**Constraints**: HasParent<"ProgramOp"> allows only the top-level body. Program / context kind must have OPS sk.redirect (sk_skb). Map is sockmap (i32 key) or sockhash (matching map key type); key type must match. `when` requires `else` with a kind-valid verdict.

**Lowering**: Stage ② expands `when` into cf.cond_br, unconditional redirect, and verdict. Stage ③ passes a zero-extended key for sockmap or stack key slot for sockhash, with UAPI redirflag ingress or flags 0; it truncates helper result to i32 and returns.

**Evidence**: F61. Actual 7.1.8 netns TCP pairs match C: ingress / egress reach different receivers and an empty slot yields SK_DROP without delivery.

**Unsupported**: Non-sk_skb (sk_msg uses ebpf.msg.redirect), nested redirects, flags other than BPF_F_INGRESS, and vsock destinations.

Traits: `HasParent<ProgramOp>`, `Terminator`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>ingress</code></td><td>::mlir::UnitAttr</td><td>unit attribute</td></tr>
<tr><td><code>else_action</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `map` | any non-token type |
| `key` | any non-token type |
| `cond` | 1-bit signless integer |



### `ebpf.sk.reuseport_cookie` (ebpf::SkReuseportCookieOp)

_Raw get_socket_cookie u64 for sk_reuseport ctx sk or migrating_sk (NULL yields zero)_

Syntax:

```
operation ::= `ebpf.sk.reuseport_cookie` $ctx $field attr-dict `:` type($ctx) `->` type($cookie)
```

**Stage**: ① Input

**Meaning**: Reads context pointer field `sk` (PTR_TO_SOCKET: the group lookup's socket, or closing listener during migration) or `migrating_sk` (PTR_TO_SOCK_COMMON_OR_NULL: migrating child, NULL during SYN selection), passes it directly to get_socket_cookie, and returns its **raw** i64 cookie, or 0 for NULL. The value uses the same sock_gen_cookie as userspace getsockopt(SO_COOKIE): 7.1.8 bpf_get_socket_ptr_cookie returns `sk ? sock_gen_cookie(sk) : 0`. Pointers never appear in IR, nor create ownership / borrows; the context-read socket pointer has no reference count and needs no release. A nonzero migrating_sk cookie directly identifies listener-close migration.

**Constraints**: Context kind must have OPS marker sk.reuseport_cookie (sk_reuseport), including static-function context arguments. Field is exactly sk or migrating_sk; other fields are explicitly rejected (use ebpf.ctx.field for integer fields). Result is i64. Not allowed in loop bodies or the packet-neutral table: it calls get_socket_cookie, whose effects do not include pktinval.

**Lowering**: Stage ③ performs one volatile eight-byte pointer load at ctx plus UAPI `ctxfield sk_reuseport_md <field>` offset, then calls get_socket_cookie using the UAPI number. The kernel's ARG_PTR_TO_BTF_ID_SOCK_COMMON | PTR_MAYBE_NULL accepts PTR_TO_SOCKET and nullable PTR_TO_SOCK_COMMON, so no NULL check is emitted. Requirements include only the helper row, not ctxaccess for pointer fields (capability tables omit pointer fields).

**Evidence**: F63. In 7.1.8 child-netns own socket groups, C and ebpf match SO_COOKIE identities: selection sk belongs to the group and migrating_sk is 0; migration sk is the closed listener and migrating_sk is the accepted child. Swapping fields changes only predicted cases. 6.12 / 6.6 were not measured in this experiment.

**Unsupported**: Pointee fields such as state / family (bpf_sock reads) and socket reference types. Cookies vary by run and serve as identity tokens.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `cookie` | 64-bit signless integer |



### `ebpf.sk.select_reuseport` (ebpf::SkSelectReuseportOp)

_Bpf_sk_select_reuseport: select a reuseport_sockarray, sockmap, or sockhash socket by key and return status (sk_reuseport only)_

Syntax:

```
operation ::= `ebpf.sk.select_reuseport` $ctx `,` $map `[` $key `]` attr-dict `:` type($ctx) `,` type($map) `,` type($key) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Calls `sk_select_reuseport(ctx, map, &key, 0)` to select the keyed socket for SO_REUSEPORT group lookup, returning **raw** i64 status. Success is 0; out-of-range / empty slots give −ENOENT; sockets in another group give −EPROTOTYPE / −EAFNOSUPPORT / −EBADFD (7.1.8 net/core/filter.c). Selection takes effect only when the program returns `pass`. Without selection, pass uses the kernel hash. Regardless of selection, `drop` discards UDP datagrams and treats TCP SYN as having no listener (ECONNREFUSED).

**Constraints**: Context kind must have OPS marker sk.select_reuseport (sk_reuseport), including static-function context arguments. Map is `!ebpf.map<"reuseport_sockarray", i32, i32|i64>` with matching i32 key, or sockmap (i32 key) / sockhash (matching map key type). For the latter, the kernel returns −EINVAL for a socket outside the group. Flags are fixed at 0 and cannot be supplied. Other reuseport_sockarray lookup / update / delete / atomic_add uses are rejected, matching kernel check_map_func_compatibility. Not allowed in loop bodies.

**Lowering**: Stage ③ stores key on the stack and calls sk_select_reuseport using the UAPI helper number and flags 0.

**Evidence**: F43. Actual 7.1.8 netns UDP / TCP SO_ATTACH_REUSEPORT_EBPF matches C: selected receiver, empty-slot −ENOENT hash fallback, and drop. Listener-close migration moves accept-queue children to the selected listener; sockmap / sockhash selection is measured. Dedicated tests cover −ENOENT (empty / out-of-range / closed), −EINVAL (sockmap socket outside the group), −EPROTOTYPE / −EAFNOSUPPORT / −EBADFD; no-selection / errno pass uses hashing, drop ignores selection, and SO_DETACH_REUSEPORT_BPF prevents further execution.

**Unsupported**: Reading ctx migrating_sk to distinguish migration from SYN selection (the migration measurement does not read ctx), and configurable flags.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `map` | any non-token type |
| `key` | any non-token type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.skb.under_cgroup` (ebpf::SkbUnderCgroupOp)

_Compare skb socket ancestry to a cgroup_array slot (sched_cls; raw status)_

Syntax:

```
operation ::= `ebpf.skb.under_cgroup` $ctx `,` $map `[` $index `]` attr-dict `:` type($ctx) `,` type($map) `,` type($index) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Raw i64 skb_under_cgroup(ctx, map, index): 1 if full-socket owner belongs to the slot cgroup or descendant, 0 otherwise. No full socket gives -ENOENT before index -E2BIG / empty -EAGAIN checks. This concerns socket owner, not current-task cgroup.

**Constraints**: Own sched_cls entry ctx, cgroup_array i32 / i32, i32 index as u32. Callee context rejected.

**Lowering**: Unchanged in ②; ③ zero-extends index and calls UAPI helper, retaining i64.

**Evidence**: F70. 7.1.8 root child-netns loopback egress matches C for ancestry1 / 0, including different sender / owner. Empty -EAGAIN, out-of-range / negative -E2BIG; synthetic TEST_RUN dummy full socket checked. Untyped map / program BTF accepted; net/core/filter.c source.

**Unsupported**: Other kinds such as LWT_OUT, cgroup-v1, timer.callback, 6.12 / 6.6, actual non-root. True NULL / non-full-socket -ENOENT unmeasured: initial TEST_RUN no-full prediction was unsupported. Do not reinterpret missing full socket as false. Generic cgroup_array map.* rejected.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `map` | a BPF map handle with kind, key type and value type |
| `index` | 32-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.sock.map_lookup` (ebpf::SockMapLookupOp)

_Acquire an owned socket reference from sockmap or sockhash_

Syntax:

```
operation ::= `ebpf.sock.map_lookup` $map `[` $key `]` attr-dict `:` type($map) `,` type($key) `->` type($result)
```

**Stage**: ① Input
**Meaning**: Returns a socket reference acquired by map_lookup_elem; even NULL must pass through sock.ref_check.
**Constraints**: Only XDP program bodies and ebpf.if / sock.ref_check arms. Key matches map; sockmap key i32, value i32 / i64. Only sock.ref_check may use the unchecked result.
**Lowering**: Unchanged in ②; ③ calls existing map_lookup_elem(map, &key). Key spill lifetime ends after helper.
**Evidence**: F61. Type / all-path ownership checks; lookup / release / delete match C in 7.1.8 child-netns TCP pairs.
**Unsupported**: Field reads, kref conversion, and function / loop / callback placement.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | a BPF map handle with kind, key type and value type |
| `key` | any non-token type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | an owned nullable socket reference acquired from a socket map |



### `ebpf.sock.map_update` (ebpf::SockMapUpdateOp)

_Bpf_sock_map_update or bpf_sock_hash_update: insert the sock_ops socket by key and return status (sock_ops only)_

Syntax:

```
operation ::= `ebpf.sock.map_update` $ctx `,` $map `[` $key `]` `flags` $flags attr-dict `:` type($ctx) `,` type($map) `,` type($key) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Calls `sock_map_update(skops, sockmap, &key, flags)` or sock_hash_update to insert the callback socket at key, returning **raw** i64 status (0 or negative errno). Errno depends on callback, map kind, flags, and previous state. In 7.1.8 net/core/sock_map.c, callbacks other than PASSIVE_ESTABLISHED / ACTIVE_ESTABLISHED / TCP_LISTEN give −EOPNOTSUPP; sockmap key ≥ max_entries gives −E2BIG; noexist with an existing key gives −EEXIST. Flags are any / noexist / exist. Closing a socket makes the kernel remove it from the map.

**Constraints**: Context kind must have OPS sock.map_update (sock_ops), including static-function context arguments. Map is sockmap (i32 key) or sockhash (matching map key type). Key must match map key type; flags must be one of the three names. No loop bodies.

**Lowering**: Stage ③ stores key on the stack and calls sock_map_update / sock_hash_update using UAPI helper numbers and updateflag values.

**Evidence**: F61. Actual 7.1.8 child-cgroup sock_ops on child-process netns TCP pairs matches C for TCP_CONNECT_CB −EOPNOTSUPP, ESTABLISHED 0, −E2BIG, and noexist −EEXIST.

**Unsupported**: Non-sock_ops and socket-field reads. XDP lookup / delete use dedicated types, with C agreement on 7.1.8 child-netns TCP pairs; 6.12 / 6.6 are unmeasured.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>flags</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `map` | any non-token type |
| `key` | any non-token type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.sock.ref_check` (ebpf::SockRefCheckOp)

_Check a nullable socket and pass an owned reference to the present region_

Syntax:

```
operation ::= `ebpf.sock.ref_check` $ptr attr-dict `:` type($ptr) (`->` type($results)^)?
              `present` $presentRegion `absent` $absentRegion
```

**Stage**: ① Input
**Meaning**: NULL executes absent; non-NULL executes present. Both arms may yield scalars. NULL is not released.
**Constraints**: Single-block regions; present has one sock_ref argument, absent none. Ownership checking requires exactly one release on every present path. Reference cannot escape.
**Lowering**: Stage ② is_present plus true-edge assume_present; ③ same pointer and NULL branch.
**Evidence**: F61. NULL / present all-path ownership checks and C agreement in 7.1.8 child netns.
**Unsupported**: Reference yield / call / loop capture.

Traits: `RecursiveMemoryEffects`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ptr` | an owned nullable socket reference acquired from a socket map |

#### Results:

| Result | Description |
| :----: | ----------- |
| `results` | variadic of any non-token type |



### `ebpf.sock.release` (ebpf::SockReleaseOp)

_Return an acquired socket reference with sk_release_

Syntax:

```
operation ::= `ebpf.sock.release` $ptr attr-dict `:` type($ptr)
```

**Stage**: ① Input
**Meaning**: Releases a checked socket exactly once on every path; later use is rejected.
**Constraints**: Only sock_ref from sock.ref_check present.
**Lowering**: Unchanged in ②; ③ calls sk_release(socket), ignoring return.
**Evidence**: F61. Present-path single-release checks and C agreement in 7.1.8 child netns; no release on NULL paths.
**Unsupported**: NULL / kref / kptr inputs.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ptr` | a checked non-NULL owned socket reference with linear release |



### `ebpf.sock_addr.set_sun_path` (ebpf::SockAddrSetSunPathOp)

_Replace an own Unix-connect entry's sun_path with fixed bytes_

Syntax:

```
operation ::= `ebpf.sock_addr.set_sun_path` $ctx $literal attr-dict `:` type($ctx) `->` type($status)
```

**Stage**: ① Input

**Meaning**: bpf_sock_addr_set_sun_path synchronously copies a literal. i32 status is 0 on success or negative errno. No NUL append or strlen.

**Constraints**: Own entry ctx of cgroup_sock_addr / connect_unix, literal 1..108 bytes only. Rejects static functions / loops / callbacks, variable buffers / lengths, and pointer escape. Permission verdict and status are independent.

**Lowering**: Initializes entry-stack bytes, then calls internal bpf_cast_to_kern_ctx and extern kfunc bpf_sock_addr_set_sun_path. Borrowed kernel ctx stays inside the op; no public pointer type. Prototype / program type come from generated UAPI; requirements use existing kfunc signature rows. Unix profile remains Unknown.

**Evidence**: F73. 7.1.8 root, own AF_UNIX/SOCK_DGRAM connect_unix: 20 normal C/compiler arms match, including 1 / 108 bytes, abstract paths, embedded NUL; two distinct mutations (destination / deny→allow), zero cleanup residue. Older kernels / actual non-root are unmeasured.

**Unsupported**: Other Unix attach types, SOCK_STREAM, dynamic buffers, existing host paths / sockets, older kernels. Experiment pathnames are relative to own private tmpfs; abstract names use own fresh netns.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>literal</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 32-bit signless integer |



### `ebpf.spin.region` (ebpf::SpinRegionOp)

_Acquire a map value's bpf_spin_lock, execute a closed critical region, and release it_

Syntax:

```
operation ::= `ebpf.spin.region` $ref $lock `:` type($ref) $body attr-dict
```

**Stage**: ① Input

**Meaning**: Locks field $lock of a borrowed record map value, executes the region, and unlocks. There is one exit path, so forgetting unlock is structurally impossible. Concurrent updates preserve both fields (a == b == total count).

**Constraints**: Only inside an ebpf.program body, not ebpf.func. %ref is a record borrow. Region has one block ending in valueless ebpf.yield. Only arith and ref.field.load / store on **the same %ref** are accepted. Helpers (including ktime), map ops, loops, nested spin.region, and other borrows are rejected.
ebpf-verify-records requires $lock to name a spin_lock field, rejects direct lock-field access (including lock.val), and rejects record.make of lock-bearing records. Kinds are xdp / fentry / fexit / tp_btf; other kinds are compiler unsupported in ebpf-verify-target-legality. A profile fact `map-with-spin-lock kprobe rejected` also adds a target-unsupported note. Schema permits only array values, one lock per record, and 4-byte-aligned lock offsets.

**Lowering**: Stage ② expands to internal ebpf.spin.lock, body, ebpf.spin.unlock. Stage ③ calls spin_lock / spin_unlock on the value pointer plus @records lock-field offset. BTF uses `struct bpf_spin_lock { u32 val }`, sized by UAPI.
On 7.1.8 fentry / fexit / tp_btf, own-child-cgroup / netns measurements filtered to own tgid give a=b=128 for parallel k=4 / N=32 and no C/ebpf difference. Missing-unlock C is verifier-rejected; omitting b causes mismatch. Actual 6.x ops are unmeasured.

**Evidence**: F17, F31. C oracle rejects helpers under lock and missing unlock; host observations; three-target root / non-root tests; kprobe-family lock maps rejected on all three targets; target-legality and load gates; Go binding access holes.

**Unsupported**: Other kinds (kprobe family also target-rejected), non-array maps, multiple locks per record, and coexistence with timer (schema rejection). No BPF_F_LOCK userspace updates; unflagged updates do not acquire the lock. Go bindgen exposes lock fields as inaccessible holes.

Traits: `NoRegionArguments`, `RecursiveMemoryEffects`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>lock</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ref` | a checked borrowed reference without ownership |



### `ebpf.stack.kernel_id` (ebpf::StackKernelIdOp)

_Bpf_get_stackid: kernel stack ID or negative errno (fentry with stack_trace)_

Syntax:

```
operation ::= `ebpf.stack.kernel_id` $ctx `,` $map `skip` $skip (`reuse` $reuse^)? attr-dict `:` type($ctx) `,` type($map) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Calls `get_stackid(ctx, stack_trace, skip | reuse)` to record a kernel stack and return **raw** i64 status: ID ≥ 0 on success, negative errno otherwise. Depth ≤ skip gives −EFAULT (observed with skip 255). A different stack in the same hash bucket gives −EEXIST without reuse. **Even with reuse, the kernel allocates a new freelist element before releasing the old one**, so no free entry gives −ENOMEM (collision in a one-entry map; stackmap.c on 6.6.157 / 6.12.111 / 7.1.8). **Reuse silently reassigns the old ID to the later stack**: looking up an earlier event's ID returns the new stack. Without reuse, −EEXIST leaves the bucket unchanged. Collisions depend on stackmap.c jhash2, bucket count, and IPs including program addresses, so they vary by load. A downstream model matches three-kernel root measurements; those measurements were not run here. **Avoid reuse when looking up stacks later**: use a larger map and count −EEXIST. With skip 0, frame 0 is the helper return address and varies by call site. Userspace looks up the IP sequence by ID.

**Constraints**: Only fentry program / context, including a static function's fentry context argument. Map type is `!ebpf.map<"stack_trace", i32, !ebpf.stack<D>>`, D ≥ 1; skip ≥ 0. D must equal schema's u64 value-array length (ebpf-verify-schema). Schema requires u32 key and flags 0. Other program-side uses of stack_trace are rejected, as are loop bodies.

**Lowering**: Stage ③ calls get_stackid with skip and optional reuse_stackid. UAPI stackflag rows supply skip limits and reuse values; excessive skip is rejected at ③.

**Evidence**: F27. C oracle; map / op tests; skip 255 −EFAULT; three targets and non-root.

**Unsupported**: Use ebpf.stack.user_id for user stacks. No build-ID kernel stacks or non-fentry kinds. `D × 8 ≤ perf_event_max_stack` depends on the environment and is not checked at compile time.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>skip</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
<tr><td><code>reuse</code></td><td>::mlir::UnitAttr</td><td>unit attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `map` | any non-token type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.stack.user_id` (ebpf::StackUserIdOp)

_Bpf_get_stackid with BPF_F_USER_STACK: user stack ID or negative errno (uprobe, kprobe, or fentry with stack_trace)_

Syntax:

```
operation ::= `ebpf.stack.user_id` $ctx `,` $map `skip` $skip (`reuse` $reuse^)? attr-dict `:` type($ctx) `,` type($map) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Calls `get_stackid(ctx, stack_trace, skip | user_stack | reuse)` to record the current task's **user stack**, returning **raw** i64 status: ID ≥ 0 on success, negative errno otherwise. Collision / reuse behavior follows stack.kernel_id: reuse silently reassigns an old ID to the later stack. Frame 0 is the current user IP (the probed function's entry for uprobes), followed by caller return addresses.
**x86_64 user unwinding uses frame pointers only**. For a binary without frame pointers, the kernel follows rbp as a frame chain. An unreadable value silently truncates the stack to the probed function; a readable value can produce **false frames** from writable data or heap addresses. Even build-ID maps report status valid for false frames in file mappings. **Depth 1 or a frame outside an executable (r-x) mapping can indicate missing frame pointers**; status valid does not establish correctness. Precheck cannot decide this because the target binary is loader input.
**Build IDs**: The kernel reads build-ID notes only from ELF PT_NOTE segments. Go's internal linker places .note.gnu.build-id outside PT_NOTE, so all frames have status ip on three measured kernels. External linking (`-ldflags=-linkmode=external` or cgo) places it inside PT_NOTE and all measured frames have status valid on three kernels.

**Constraints**: Matching program / context kind must be uprobe, kprobe, or fentry, including static-function context arguments. Map is `!ebpf.map<"stack_trace", i32, !ebpf.stack<D>>` or `!ebpf.stack_build_id<D>` (schema element `{"kind": "stack_build_id"}` paired with flags 32). D ≥ 1, skip ≥ 0, and D equals schema's value element count (ebpf-verify-schema). Not allowed in loop bodies.

**Lowering**: Stage ③ calls get_stackid with skip, user_stack, and optional reuse_stackid. UAPI stackflag rows supply flag values and the skip limit; excessive skip is rejected at ③.

**Evidence**: F27. Source / C oracle with frame-pointer and no-frame-pointer fixtures on three kernels; uprobe / fentry / kprobe differential tests on three kernels × two privilege levels; build-ID maps match C on three kernels × three privilege levels; IP fallback and false-frame / Go-build-ID measurements on three kernels.

**Unsupported**: DWARF unwinding and frames beyond D. Non-root uprobe attachment requires CAP_SYS_ADMIN (loader condition).

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>skip</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
<tr><td><code>reuse</code></td><td>::mlir::UnitAttr</td><td>unit attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `map` | any non-token type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.storage.delete` (ebpf::StorageDeleteOp)

_Delete an owner's local storage and return raw helper status_

Syntax:

```
operation ::= `ebpf.storage.delete` $map `,` $owner attr-dict `:` type($map) `,` type($owner) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Deletes the owner's local-storage value and returns **raw** i64 status (0 / negative errno; -ENOENT if absent).

**Constraints**: Map / owner rules follow storage.get. Do not use borrows of the deleted value afterward: kernel frees it after RCU; the compiler does not track this, so it is the caller's responsibility. No loop bodies.

**Lowering**: Unchanged in ②; ③ exposes <kind>_delete(map, owner) status.

**Evidence**: F51. First delete 0 and second -ENOENT match equivalent C on actual 7.1.8 attach.

**Unsupported**: No post-delete borrow-use checking. 6.12 / 6.6 are unverified.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | a BPF map handle with kind, key type and value type |
| `owner` | a pointer to an internal kernel struct obtained from tracing arguments |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.storage.get` (ebpf::StorageGetOp)

_Look up an owner's local storage, optionally creating a zeroed value (unchecked nullable reference)_

Syntax:

```
operation ::= `ebpf.storage.get` $map `,` $owner (`create` $createIfMissing^)? attr-dict `:` type($map) `,` type($owner) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Looks up local-storage map value attached to a kernel owner object: socket / task / inode / cgroup for sk_storage / task_storage / inode_storage / cgrp_storage. create allocates a missing zero-filled value. Returns **unchecked** !ebpf.maybe_ref<V>, possibly NULL even with create if allocation fails. Access through ref.check present !ebpf.borrowed<V> and existing ref.* operations, like map.lookup.

**Constraints**: Only the four local-storage map kinds. Owner is !ebpf.kptr<"S"> for sock / task_struct / inode / cgroup respectively (Support/LocalStorage.h), obtained from kptr.check present, LSM / tracing ctx.arg, or kfield.ptr traversal. Result pointee equals map value. No loop bodies. ebpf-verify-schema checks map kind / key / value; schema requires 32-bit integer key, max_entries 0, flags no_prealloc.
Kernel program-type compatibility is not decided by the compiler. In 7.1.8 func_proto, task / cgrp storage support all types, inode storage only LSM, sk storage LSM / tracing / network types. Requirements helper rows check at load time; otherwise the verifier explicitly rejects unsupported combinations.

**Lowering**: Unchanged in ② (ref.check supplies the NULL branch). Stage ③ calls <kind>_get(map, owner, NULL, flags), using UAPI helper numbers and storageflag create or 0.

**Evidence**: F51. Actual 7.1.8 LSM task_getioprio / file_ioctl / socket_getsockopt owners match C for all four kinds.

**Unsupported**: Supplied initial values (only zero-filled creation). Owner must be kptr, not cgroup_sock context (ARG_PTR_TO_CTX), a network context sk field, or other sock_common-derived structs such as tcp_sock. Schema rejects BPF_F_CLONE. 6.12 / 6.6 are unverified.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>createIfMissing</code></td><td>::mlir::UnitAttr</td><td>unit attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | a BPF map handle with kind, key type and value type |
| `owner` | a pointer to an internal kernel struct obtained from tracing arguments |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | an unchecked nullable reference |



### `ebpf.sys.bpf` (ebpf::SysBpfOp)

_Invoke a pointer-free bpf() command from a syscall program (raw fd or negative errno)_

Syntax:

```
operation ::= `ebpf.sys.bpf` $ctx `,` $cmd `,` $attr attr-dict `:` type($ctx) `,` type($attr) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Calls sys_bpf(cmd, &attr, sizeof attr) in the kernel. map_create / map_get_fd_by_id return a new fd installed O_CLOEXEC in **the test-run caller's fd table**; map_freeze returns 0; failure returns negative errno. Early kernel/bpf/syscall.c paths include map_create CHECK_ATTR / map_alloc_check −EINVAL, freeze missing-fd −EBADF / already-frozen −EBUSY, get_fd_by_id without CAP_SYS_ADMIN −EPERM / missing-ID −ENOENT. Attr record byte meanings are the author's contract; compiler does not interpret field names.

**Constraints**: Own syscall program-body entry context with OPS sys.bpf, not subprogram / loop callback. Cmd is UAPI bpfcmd map_create / map_freeze / map_get_fd_by_id, the three pointer-free commands among nine accepted by bpf_sys_bpf. Attr is record.make and **size must not exceed the command's pointer boundary** (SysBpfAttr.def): map_create80 (7.1.8 excl_prog_hash), map_freeze8 (key), map_get_fd_by_id16 (struct end, no pointer). Kernel reads KERNEL_BPFPTR and treats pointer fields as kernel pointers, so these limits keep integer record bytes away from pointer fields. go/internal/abigen checks boundaries against three-kernel BTF. Kernel exposes the helper only to CAP_PERFMON loaders; otherwise load gives −EINVAL. Compiler does not inspect privilege; requirements helper rows support precheck.

**Lowering**: Stage ③ calls sys_bpf with UAPI command number, record.make stack pointer, and record size; i64 result.

**Evidence**: F40. Three-kernel test-run differential measurement against equivalent C.

**Unsupported**: Pointer-bearing MAP_UPDATE / DELETE_ELEM / PROG_LOAD / BTF_LOAD / LINK_CREATE / RAW_TRACEPOINT_OPEN (no way to write pointers into records), btf_find_by_name_kind / kallsyms_lookup_name, and semantic fd checks (fds remain integers).

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>cmd</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `attr` | a schema record identified by symbol and byte size for maps, reservations, perf output and subprogram arguments |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.sys.close` (ebpf::SysCloseOp)

_Close a file descriptor from a syscall program, returning raw bpf_sys_close status_

Syntax:

```
operation ::= `ebpf.sys.close` $ctx `,` $fd attr-dict `:` type($ctx) `->` type($status)
```

**Stage**: ① Input

**Meaning**: sys_close(fd) closes a descriptor in the test-run caller's fd table. Raw status is 0 or −EBADF for an absent fd (fs/file.c close_fd).

**Constraints**: Own syscall program-body entry context with OPS sys.close. fd is i32 (truncate sys.bpf status with arith.trunci).

**Lowering**: Stage ③ calls sys_close with zero-extended u32 fd; result i64.

**Evidence**: F40. Syscall helper differential tests.

**Unsupported**: No check that sys.bpf created the fd; any descriptor of the test-run caller can be closed.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `fd` | 32-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.sysctl.set_new_value` (ebpf::SysctlSetNewValueOp)

_Replace a cgroup_sysctl new value with fixed literal bytes and return raw status_

Syntax:

```
operation ::= `ebpf.sysctl.set_new_value` $ctx $literal attr-dict `:` type($ctx) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Passes fixed bytes to bpf_sysctl_set_new_value. Raw i64 status is 0 or negative errno. Even successful replacement never reaches the handler if verdict denies; handler rejection after allow is a separate outcome.

**Constraints**: Own entry ctx of a kind whose OPS permits sysctl.set. Literal is 1–64 raw bytes, counting embedded NUL; no implicit trailing NUL. No callee / loop / callback / generic pointer.

**Lowering**: Allocates N entry-stack bytes and initializes every byte. Stage-③ bpfabi.helper_call sysctl_set_new_value takes ctx / read-only buffer / constant N; stage ④ uses UAPI helper104. No Pure / readnone attributes; even unused status preserves the call.

**Evidence**: F71. 7.1.8 root own-child-cgroup / netns: 14 independent normal C/compiler arms match. Helper 0 with handler EINVAL, deny EPERM, and read helper EINVAL are checked separately from actual TTL. Two complete semantic mutations; host / sibling TTL unchanged; 32 own map / program IDs ENOENT; 16-arm cleanup zero. Compiler boundaries have non-root lit evidence.

**Unsupported**: get_name / current / new helpers, dynamic buffers, PAGE_SIZE boundary, and file_pos changes. Actual writes are confined to own cgroup / netns and explicitly named paths. Older-kernel and attach evidence retain the measurement's limits.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>literal</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.tail_call` (ebpf::TailCallOp)

_Bpf_tail_call: transfer without return on success, execute fallback only on failure (XDP with prog_array)_

Syntax:

```
operation ::= `ebpf.tail_call` $ctx `,` $map `[` $index `]` `:` type($ctx) `,` type($map) `,` type($index) (`when` $cond^ `else` $else_action)? `fallback` $fallback attr-dict
```

**Stage**: ① Input

**Meaning**: An XDP terminator tail-calling the program in prog_array slot `index`. Success does not return; only failure executes the fallback region. The program cannot distinguish out-of-range, limit, or empty-slot failures.
With `when %c else "<verdict>"`, false returns the verdict without attempting a tail call or executing fallback. Schema prog_array `slots` declares slots; the loader installs them (requirements `tailslot`).

**Constraints**: HasParent<"ProgramOp"> restricts it to the top-level body: loops, packet.check, ref.check, and reservation regions are rejected. Requires XDP program / context and prog_array with i32 key / value. Fallback is one block ending in ebpf.verdict / ebpf.verdict.if and cannot contain tail_call. `when` requires `else` with an XDP verdict. checkMapKind rejects program-side prog_array lookup / update. Failed calls invalidate packet pointers; fallback packet reads must re-read ctx with packet.load.

**Lowering**: Stage ② creates `ebpf.tail_call.try` followed by the fallback contents; `when` adds cond_br and a false-edge verdict. Stage ③ zero-extends index and calls tail_call, ignoring its return value.

**Evidence**: F15. C oracle; fallback re-reads; three-target / non-root tests including version differences in counting the limit 33; binding slot contract; checks preventing stage-② tail_call.try bypasses.

**Unsupported**: Non-XDP, nested region / fallback tail calls, multiple attempts in one program, and program-side prog_array reads / writes.

Traits: `HasParent<ProgramOp>`, `NoRegionArguments`, `Terminator`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>else_action</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `map` | any non-token type |
| `index` | 32-bit signless integer |
| `cond` | 1-bit signless integer |



### `ebpf.task.cgroup_id` (ebpf::TaskCgroupIdOp)

_Raw bpf_get_current_cgroup_id() value for the current task's cgroup v2_

Syntax:

```
operation ::= `ebpf.task.cgroup_id` attr-dict `:` type($result)
```

**Stage**: ① Input

**Meaning**: Returns i64 current-task default-hierarchy cgroup ID (directory inode number; cgroup_id(task_dfl_cgroup(current))).

**Constraints**: No op verifier. Like task.pid_tgid, compile time does not restrict kinds; requirements helper rows check availability at load. CONFIG_CGROUPS absence removes the helper. Allowed in loops / subprograms.

**Lowering**: Stage ③ calls UAPI get_current_cgroup_id.

**Evidence**: F42. Actual 7.1.8 LSM attach matches C, rejecting socket(2) only in own child cgroup with matching ID; outside / different / unset IDs do not reject.

**Unsupported**: Ancestor-cgroup ID helper, cgroup-v1 IDs, and timer callbacks (ordinary helper set limited to ktime.ns).

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | 64-bit signless integer |



### `ebpf.task.comm` (ebpf::TaskCommOp)

_Write current-task comm into a reservation's byte-array field and return raw helper status_

Syntax:

```
operation ::= `ebpf.task.comm` $reservation $field attr-dict `:` type($reservation) `->` type($status)
```

**Stage**: ① Input

**Meaning**: get_current_comm writes task name into a checked ring reservation byte-array field, returning **raw** i64 helper status. Does not consume it.

**Constraints**: Record reservation; one-dimensional eight-bit integer array field (record checking). Present only, not absent / post-consumption; also excluded from loop-called subprograms. Compiler does not restrict kinds; load gates check helper availability.

**Lowering**: Stage ③ get_current_comm(reservation + field offset, element count), with constant size from @records.

**Evidence**: F21. C oracle; record.make → store_record → task.comm → status defines all bytes; three-target / non-root; post-consumption rejection.

**Unsupported**: Map / stack / packet writes (reservation only; no generic helper memory writer), multidimensional / non-eight-bit arrays. Nonzero status paths are unmeasured.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `reservation` | a successful ring-buffer reservation, linearly consumed exactly once |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.task.pid_tgid` (ebpf::TaskPidTgidOp)

_Raw bpf_get_current_pid_tgid() value (tgid << 32 | pid)_

Syntax:

```
operation ::= `ebpf.task.pid_tgid` attr-dict `:` type($result)
```

**Stage**: ① Input

**Meaning**: Returns raw i64 helper value: high32 tgid (process), low32 pid (thread).

**Constraints**: No op verifier. Compile time does not restrict kinds; load-time requirements helper checks determine availability for program type. Allowed in loops / subprograms.

**Lowering**: Stage ③ calls UAPI get_current_pid_tgid.

**Evidence**: F21. C oracle; per-tgid count agreement; three-target / non-root; ring events.

**Unsupported**: Separate PID / TGID operations (caller shifts / truncates). Timer callbacks permit only ktime.ns among ordinary helpers.

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | 64-bit signless integer |



### `ebpf.task.under_cgroup` (ebpf::TaskUnderCgroupOp)

_Compare current-task ancestry to a cgroup_array slot, returning raw status_

Syntax:

```
operation ::= `ebpf.task.under_cgroup` $map `[` $index `]` attr-dict `:` type($map) `,` type($index) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Raw i64 current_task_under_cgroup(map, index): 1 for current task cgroup-v2 membership / descendant, 0 otherwise, -EAGAIN for empty slot, -E2BIG for out-of-range index. Not reduced to bool.

**Constraints**: cgroup_array i32 / i32, i32 index interpreted u32. Userspace supplies cgroup fds. Helper availability follows requirements / load verifier. Allowed in loops / static subprograms.

**Lowering**: Unchanged in ②; ③ zero-extends index and calls UAPI helper, retaining i64 result.

**Evidence**: F70. 7.1.8 root C/ebpf: same / descendant1, sibling0, deleted / empty -EAGAIN, out-of-range / negative index -E2BIG. Untyped map BTF and program BTF accepted. Non-root compile / precheck and mutation controls; kernel helpers.c source.

**Unsupported**: cgroup-v1, timer.callback, other-kind helper runtime acceptance, non-root runtime, and 6.12 / 6.6 measurements. Generic cgroup_array map.* rejected.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | a BPF map handle with kind, key type and value type |
| `index` | 32-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.timer.callback` (ebpf::TimerCallbackOp)

_Timer callback with restricted map-value access and arithmetic_

Syntax:

```
operation ::= `ebpf.timer.callback` $sym_name `map` $map `:` $record attr-dict-with-keyword $body
```

**Stage**: ① Input

**Meaning**: A timer-specific callback symbol at module top level, separate from a bpf_loop callback. `map @m : !ebpf.record<…>` declares its map and record. Its single block argument borrows the value; the kernel calls it when the timer fires. Terminates with ebpf.timer.done.

**Constraints**: One block, exactly one !ebpf.borrowed<record> argument, and timer.done terminator. Only arith, ref.field.load / store on that argument, ebpf.ktime.ns, **ebpf.timer.start on that argument's own timer**, and wrapping ebpf.if are accepted; nested regions use the same allowed set. Other helpers, timer.init / set_callback, map operations, and loops are rejected. timer.start explicitly rejects a ref other than the callback block argument. ebpf-verify-records rejects direct timer / spin_lock field accesses. Stage ③ rejects callbacks unused by any program's set_callback. This is a permitted top-level ebpf-compile input.

**Lowering**: Stage ③ emits an internal/static .text llvm.func `(ptr map, ptr key, ptr value) -> i32`; the body uses the third argument. BTF is static FUNC `cb(void *map, <key type> *key, struct <R> *value) -> int`, matching C rather than the bpf_loop callback shape.
On 7.1.8 fentry / fexit / tp_btf, callback count1 and fired_ns within the MONOTONIC range match C. Helper set is not broadened; actual 6.x operations are unmeasured.

**Evidence**: F18. Callback ELF / BTF shape and return-type correction; three-target tests; C callback ktime oracle; ktime.ns permission and requirement reachability; own-timer start and ebpf.if.

**Unsupported**: Map and key arguments cannot be used. Helpers other than ktime (and the explicitly allowed own timer restart) are rejected. Callbacks of programs outside xdp / fentry / fexit / tp_btf are compiler unsupported.

Traits: `IsolatedFromAbove`

Interfaces: `Symbol`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>sym_name</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>map</code></td><td>::mlir::FlatSymbolRefAttr</td><td>flat symbol reference attribute</td></tr>
<tr><td><code>record</code></td><td>::mlir::TypeAttr</td><td>any type attribute</td></tr>
</table>



### `ebpf.timer.done` (ebpf::TimerDoneOp)

_End a timer callback by returning zero_

Syntax:

```
operation ::= `ebpf.timer.done` attr-dict
```

**Stage**: ① Input

**Meaning**: Terminates ebpf.timer.callback, returning 0 as required by the verifier contract.

**Constraints**: HasParent permits only ebpf.timer.callback. It must be the callback block's last operation, checked by the callback verifier. No operands.

**Lowering**: Stage ③ emits llvm.return with i32 constant 0.

**Evidence**: F18. Return type corrected to C's int; corrected ELF rerun on three targets.

**Unsupported**: Nonzero return values.

Traits: `HasParent<TimerCallbackOp>`, `Terminator`



### `ebpf.timer.init` (ebpf::TimerInitOp)

_Raw bpf_timer_init(&value->field, map, clock) status_

Syntax:

```
operation ::= `ebpf.timer.init` $ref $field `,` $map `clock` $clock attr-dict `:` type($ref) `,` type($map) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Initializes a borrowed record map value's timer field with `bpf_timer_init(&value->field, map, clock)`, returning **raw** i64 status (0 / negative errno). A second init returns −EBUSY and leaves the timer initialized. The caller must check init == 0 before set_callback / start; ignoring status rearms the timer (C and ebpf mutations demonstrate this).

**Constraints**: Only in ebpf.program bodies, not ebpf.func. %ref is a record borrow directly from map.lookup → ref.check present; $map is that same lookup map value. Clock is monotonic only. ebpf-verify-records checks the timer field. No loop bodies. Kinds are xdp / fentry / fexit / tp_btf; other kinds are compiler unsupported in target legality. Target-profile fact `map-with-timer <type> rejected` adds a target-unsupported note. Schema permits array values only, one timer per record, 8-byte-aligned offset, and no lock in the same record.

**Lowering**: Stage ③ calls timer_init(value pointer + @records timer offset, &map, clock), with UAPI clockid monotonic.
On 7.1.8 fentry / fexit / tp_btf in own child cgroup / netns filtered to own tgid, first init / callback / start status is 0, second init is −EBUSY, and C/ebpf agree. Actual 6.x ops are unmeasured.

**Evidence**: F18, F31. C oracle for −EBUSY, unstarted / no-callback / invalid-clock statuses; ELF shape and host observations; three-target root / non-root; kprobe timer maps rejected on 6.x but accepted on 7.1.8; target-legality and load gates.

**Unsupported**: Other clocks, non-array maps, other program kinds, and direct measurement of callback contents after last uref close (own IDs disappear within five seconds). Go bindgen exposes timer fields as inaccessible holes; userspace updates stop running timers.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>clock</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ref` | a checked borrowed reference without ownership |
| `map` | a BPF map handle with kind, key type and value type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | 64-bit signless integer |



### `ebpf.timer.set_callback` (ebpf::TimerSetCallbackOp)

_Raw bpf_timer_set_callback(&value->field, callback) status_

Syntax:

```
operation ::= `ebpf.timer.set_callback` $ref $field `,` $callback attr-dict `:` type($ref) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Binds callback @cb (ebpf.timer.callback) to a borrowed record's timer via bpf_timer_set_callback, returning **raw** i64 status (0 / negative errno). Repeating set_callback / start without checking init status succeeds even after −EBUSY and fires the timer again, as shown by C / ebpf mutations.

**Constraints**: Shares timer.init checks: program body, record borrow directly from map.lookup. $callback names an ebpf.timer.callback whose record equals %ref's record and whose map @m equals the originating lookup map. Field checking, loop exclusion, and target-legality kind restrictions follow timer.init.

**Lowering**: Stage ③ calls timer_set_callback(value pointer + timer offset, &callback). Callback address relocates into .text. Requirements traverse the set_callback addressof edge to include callback-only helpers in the program's rows.
On 7.1.8 fentry / fexit / tp_btf, callback fires with count1 and fired_ns inside the MONOTONIC range; C/ebpf agree. Callback helper set is unchanged; actual 6.x ops are unmeasured.

**Evidence**: F18, F31. C no-callback start −EINVAL; callback relocation / BTF shape; three targets; callback-only helper requirement reachability.

**Unsupported**: Callback must be an ebpf.timer.callback in the same ELF, not a subprogram or bpf_loop callback. Kinds other than xdp / fentry / fexit / tp_btf are compiler unsupported.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>callback</code></td><td>::mlir::FlatSymbolRefAttr</td><td>flat symbol reference attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ref` | a checked borrowed reference without ownership |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | 64-bit signless integer |



### `ebpf.timer.start` (ebpf::TimerStartOp)

_Raw bpf_timer_start(&value->field, nsecs, 0) status_

Syntax:

```
operation ::= `ebpf.timer.start` $ref $field `,` $nsecs attr-dict `:` type($ref) `,` type($nsecs) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Starts a borrowed record's timer one-shot after relative nsecs via timer_start(&value->field, nsecs, 0). Returns **raw** i64 status (0 / negative errno). Without start it does not fire; without a callback, start gives −EINVAL.

**Constraints**: Shares timer.init checks; nsecs is i64. Field checking, loop exclusion, and kind restrictions follow timer.init. Inside ebpf.timer.callback, only the **callback block argument's own map value timer** may be started (periodic timer, with an ebpf.if bound); program behavior is unchanged.

**Lowering**: Stage ③ calls timer_start(value pointer + timer offset, nsecs, 0). Flags are constant 0.
On 7.1.8 fentry / fexit / tp_btf, one-shot count1 / armed1 stays stable for 200 ms; firing after detach and ID disappearance after last own uref close were observed with C/ebpf agreement. Direct callback observation after close and actual 6.x ops are outside that measurement.

**Evidence**: F18, F31. C one-shot persistence and unstarted / no-callback status; host C agreement; three-target root / non-root; callback timestamp inequalities; own-timer callback restart with bounded N and an unbounded mutation stopped by last uref close, measured on XDP on three kernels.

**Unsupported**: Flags other than 0 (no ABS / CPU_PIN), and timer_cancel. A second program-side start (rearm) is a negative control. Periodic own-timer restart has three-kernel evidence only for XDP. Other than xdp / fentry / fexit / tp_btf, kinds are compiler unsupported.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ref` | a checked borrowed reference without ownership |
| `nsecs` | 64-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | 64-bit signless integer |



### `ebpf.tp.buffer.load` (ebpf::TpBufferLoadOp)

_Read i32 once from the raw_tp_writable args[0] buffer_

Syntax:

```
operation ::= `ebpf.tp.buffer.load` $ctx `[` $offset `]` attr-dict `:` type($ctx) `->` type($result)
```

**Stage**: ① Input

**Meaning**: One volatile signless-i32 read at byte offset 0 of the buffer pointed to by args[0]. Raw i32 result. DefaultResource Read + Write preserves even unused reads. Volatile is neither thread synchronization nor a full memory barrier.

**Constraints**: Own raw_tp_writable entry context with tp.buffer capability, constant offset 0 / i32 only. No static functions, other contexts / offsets / widths, or exposed private pointer.

**Lowering**: Stage ③ bpfabi.tp_buffer_load; stage ④ one UAPI args[0] DW volatile pointer load, then one buffer W volatile load. Strict exit checks width / order / pointer escape. Requirements tpbuf i32 (format14) immediately after attach checks target signed-i32 pointer before load.

**Evidence**: F46. On 7.1.8 bpf_test_finish filtered to own TGID, 14 normal C/ebpf arms / 72 calls match; complete observations detect store-omission / -12 mutations (two arms / ten calls). BTF / load / attach, C7 Close / ENOENT, and zero remaining own 76 IDs are checked. Separate checks cover stage-①②③ CSE, stage-④ strict exit, and LLVM / ELF R2/W1 order. Earlier C-only evidence is preserved.

**Unsupported**: Other offsets / widths / arguments, context transport to subprograms, and exposed private pointers. Matching target BTF alone does not guarantee writable_size or attach acceptance.

Interfaces: `MemoryEffectOpInterface (MemoryEffectOpInterface)`

Effects: `MemoryEffects::Effect{MemoryEffects::Read on ::mlir::SideEffects::DefaultResource, MemoryEffects::Write on ::mlir::SideEffects::DefaultResource}`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>offset</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | 32-bit signless integer |



### `ebpf.tp.buffer.store` (ebpf::TpBufferStoreOp)

_Write i32 once to the raw_tp_writable args[0] buffer_

Syntax:

```
operation ::= `ebpf.tp.buffer.store` $ctx `[` $offset `]` `,` $value attr-dict `:` type($ctx) `,` type($value)
```

**Stage**: ① Input

**Meaning**: One volatile i32 store at buffer offset 0. Read + Write effects prevent merging surrounding loads / stores.

**Constraints**: Same own raw_tp_writable entry context / constant offset0 / signless i32 as tp.buffer.load. No result or public pointer.

**Lowering**: Stage ③ bpfabi.tp_buffer_store; ④ one UAPI args[0] DW volatile pointer load, then one buffer W volatile store. Strict exit checks value / width / order / pointer escape; emits tpbuf i32 requirements.

**Evidence**: F46. 7.1.8 bpf_test_finish / own TGID: 14 normal C/ebpf arms / 72 calls match. Store omission gives before/after0 / errno0; -12 gives after-12 / errno12, each detected in five calls. Preserves one Close per own 76 IDs and absence checks, independent C7 detach evidence, and earlier C-only evidence.

**Unsupported**: Other offsets / widths / arguments, static functions, pointer exposure, and nonvolatile access.

Interfaces: `MemoryEffectOpInterface (MemoryEffectOpInterface)`

Effects: `MemoryEffects::Effect{MemoryEffects::Read on ::mlir::SideEffects::DefaultResource, MemoryEffects::Write on ::mlir::SideEffects::DefaultResource}`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>offset</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `value` | 32-bit signless integer |



### `ebpf.tp.field` (ebpf::TpFieldOp)

_Read a tracepoint event field at its schema-declared offset and width_

Syntax:

```
operation ::= `ebpf.tp.field` $ctx $field `[` $offset `]` attr-dict `:` type($ctx) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Reads a named context field from a tracefs event record. TRACE_EVENT uses the perf record; syscall events use local syscall_tp_t. In both, the first eight bytes are replaced by struct pt_regs*. Integer example: `ebpf.tp.field %ctx "fd" [16] : !ebpf.ctx<"tracepoint"> -> i64`. Returns raw bits without signed interpretation; schema declares sign and arith controls extension. Not Pure; reads are not reordered / merged.

**Constraints**: Own tracepoint program entry context with OPS tp.field, not static functions. Integer widths i8 / i16 / i32 / i64; offset ≥ 8, aligned to width; offset + width ≤ 8192 (7.1.8 tp_prog_is_valid_access / PERF_MAX_TRACE_SIZE). Schema fields must contain the name with identical offset / width; the op copies the declaration, while schema is the checking authority.
Load gates use attach trace_tp category/event plus tpfield name offset byte-count i|u for **all schema fields, including unread declarations**. Compare target events/category/event/format. Mismatch tpfield and unknown tpfield_unknown block load; tracefs is root-readable, so non-root can use root-recorded caps (format11 / policy9).

**Lowering**: Stage ③ emits one volatile load at ctx + offset with declared width, like ctx.load. No split / combined access or helper.

**user_str**: Also accepts !ebpf.user_str, strictly matching schema kind user_str, eight-byte size / alignment. Format16 tpfield strptr checks tracefs char* before load. char** / embedded arrays / data_loc do not match. Unknown types or unreadable formats are blocking Unknown. user.read_str exposes raw helper status; no integer cast or direct dereference.

**Evidence**: F44. Actual C comparisons for syscall sys_enter_getppid __syscall_nr and sys_enter_write __syscall_nr / fd / count, plus TRACE_EVENT task_rename pid / oom_score_adj. Tracefs offsets equal BPF ctx offsets; wrong-offset declarations fail tpfield before load.

**Unsupported**: __data_loc pointees, array scalar results, and scalars wider than eight bytes. Fixed-byte-array copying uses tp.field.copy (F75). Schema / requirements reject syscall fields outside the special BPF context.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>offset</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | signless integer or a user-string pointer from a typed source, read only by ebpf.user.read_str or an array of user character pointers from a typed source, read only by fixed-index user.str_at |



### `ebpf.tp.field.copy` (ebpf::TpFieldCopyOp)

_Copy a fixed tracepoint byte array to an equal-length checked record array_

Syntax:

```
operation ::= `ebpf.tp.field.copy` $dst $path `,` $ctx $field `[` $offset `]` attr-dict `:` type($dst) `,` type($ctx)
```

**Stage**: ① Input

**Meaning**: Copies fixed N bytes from an entry-context tracepoint field to a borrowed map record or checked ring reservation array. No result, NUL interpretation, or reservation consumption.

**Constraints**: Schema type {kind:array,elem:u8|i8,n:N}, N 1..64. Name / offset must match; offset ≥ 8; offset + N ≤ 8192. Destination RecordPath is a one-dimensional eight-bit array of the same N. Own tracepoint entry context only; no static functions / loops / callbacks. Reservation present / consumption rules follow kfield.copy.

**Lowering**: Stage ③ emits N volatile i8 loads at ctx + offset and i8 destination stores, alignment1. No helper / CO-RE.

**Evidence**: F75. Format17 tpfield [N]u8/i8 checks tracefs fixed-array declaration, element width / count / sign / offset / size. Mismatch and Unknown block load.

**Unsupported**: Dynamic / data_loc / multidimensional / non-eight-bit arrays, arbitrary pointers, and string semantics. Existing same-size scalar reinterpretation contracts remain unchanged.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>path</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>offset</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `dst` | a checked borrowed reference without ownership or a successful ring-buffer reservation, linearly consumed exactly once |
| `ctx` | an eBPF program context carrying its attach kind |



### `ebpf.uprobe.arg` (ebpf::UprobeArgOp)

_Read a user-function argument register from uprobe pt_regs (integer or typed user string)_

Syntax:

```
operation ::= `ebpf.uprobe.arg` $ctx $n attr-dict `:` type($ctx) `->` type($result)
```

**Stage**: ① Input

**Meaning**: Reads one-based user-function argument n from pt_regs, using raw bits like kprobe.arg. Integer results truncate to iW; !ebpf.user_str preserves 64 raw bits as a user string pointer, usable only by user.read_str. Pure.

**Constraints**: Context is uprobe only; n ≥ 1; result i8 / i16 / i32 / i64 or user_str. Schema params must declare matching width or kind user_str paired with that result.
Load gates check binary sha256 / symbol / uprobearg iN|uN|strptr against the loader-supplied binary's hashed fd and DWARF. strptr requires one pointer level to eight-bit char; Unknown also blocks. Policy 16 reads a unique non-declaration definition whose direct low_pc equals the main binary symbol address. If main DWARF info is absent, separate DWARF is used only after GNU build-ID and optional debuglink CRC matching (F25 / F54; requirements_format.md). Attach stays on the main binary; no unknown-type fallback.

**Lowering**: Stage ③ uses bpfabi.kprobe_arg and UAPI offsets, like kprobe.arg. Integers truncate; user_str remains 64 bits. No helper.

**Buffer / raw pointer**: Schema user_buf returns !ebpf.user_buf, consumed for reads only by user.read; schema ptr returns raw i64. Both emit requirements ptr, minimum format 18, matched against a one-level, eight-byte DWARF pointer. No integer-to-readable-buffer cast.

**Evidence**: F25, F78. C oracle / fixture and binary identity; three targets (non-root attach needs CAP_SYS_ADMIN); user_str; buffer / ptr declarations and static checks, whose runtime evidence is owned by the user.read experiment.

**Unsupported**: user_str cannot feed integer ops; no kprobe context. Missing DWARF in both main / matched separate files and char** stop before load. void* must use ptr / user_buf declarations. Placement path and PID are loader inputs, not compiler inputs.

Traits: `AlwaysSpeculatableImplTrait`

Interfaces: `ConditionallySpeculatable`, `NoMemoryEffect (MemoryEffectOpInterface)`

Effects: `MemoryEffects::Effect{}`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>n</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | signless integer or a user-string pointer from a typed source, read only by ebpf.user.read_str or a typed uprobe user-buffer address |



### `ebpf.usdt.arg` (ebpf::UsdtArgOp)

_Read a USDT argument using the cookie-indexed loader-written note specification, returning value and status_

Syntax:

```
operation ::= `ebpf.usdt.arg` $ctx $n attr-dict `:` type($ctx) `->` type($value) `,` type($status)
```

**Stage**: ① Input

**Meaning**: Reads one-based argument n of the current USDT point, returning value iW (schema params width) and i64 status. Compiler cannot know each point's register / memory / constant placement. **Loader writes note-derived specifications** into __ebpf_usdt_spec_<program>; keys are point indices and layout is in requirements_format.md §8. Attach cookies index this map. const uses spec off, reg uses register bits, deref reads W/8 user bytes at register + off. Result retains low bits of declared width; usdtarg checks width / sign against note <±size>@, and the caller uses extsi / extui to widen.
Status is 0 for successful const / reg / deref, **raw probe_read_user negative errno** on deref failure (value 0), −ENOENT (-2) with value 0 for cookie outside map max_entries / NULL lookup, or −EINVAL (-22) with value 0 for kind 0 (unwritten array slot / unreadable location), unknown kind, or invalid register. −2 / −22 are compiler-defined statuses, not kernel helper returns. **Using value without checking status is allowed**, as with user.read_str; caller distinguishes failure.

**Constraints**: Own program context with OPS usdt.arg; n 1..12; value i8 / i16 / i32 / i64; status i64. No static-function context. n must exist in schema params at matching width. Load gates check attach usdt provider:name plus arch / ctxfield rows for every read register / binary / usdtsem / usdtarg, and loader usdt_attach declaration against binary notes. Missing points, semaphore disagreement, argument count / size / sign mismatch, unreadable placement, or point count > max_points all block.

**Lowering**: Stage ③ truncates get_attach_cookie to u32 key, then map_lookup_elem on compiler-placeholder __ebpf_usdt_spec_<program> (one added map / ebpf_usdt_spec record per schema USDT program). NULL yields (0, −ENOENT). Reads argument kind at +16(n−1), reg at +16(n−1)+1, off at +16(n−1)+8. **All UAPI usdtreg registers are read once, volatile, at fixed pt_regs offsets**; register numbers select values rather than variable-offset context pointers, preventing LLVM pointer selection. Invalid numbers yield (0, −EINVAL). Kind1 returns off; kind2 returns register; kind3 calls probe_read_user(&tmp, W/8, reg + off) with a zeroed eight-byte temporary, preserving raw status and zero failure value. Others yield (0, −EINVAL). Value truncates to iW.

**Evidence**: F55. On 7.1.8 root, all points in clang -O0 / -O2 and gcc -O2 fixtures match stdout values with status 0. Loader-filled maps match note parsing. Semaphore-point ref_ctr_offset has a zero-event control when omitted.

**Unsupported**: SIB off(base,index,scale), RIP-relative placement, and non-x86_64 are precheck-rejected (no spec kinds). Deref-failure status is unmeasured. Two programs at one point are outside scope (spec map is per program). Without loader cookies all points read spec0; precheck does not observe cookies, so §8's contract is essential.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>n</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |

#### Results:

| Result | Description |
| :----: | ----------- |
| `value` | 8-bit signless integer or 16-bit signless integer or 32-bit signless integer or 64-bit signless integer |
| `status` | 64-bit signless integer |



### `ebpf.user.read` (ebpf::UserReadOp)

_Read a signed-clamped length from a typed user buffer and initialize the entire destination_

Syntax:

```
operation ::= `ebpf.user.read` $reservation $field `,` $ptr `,` $len attr-dict `:` type($reservation) `,` type($ptr) `,` type($len) `->` type($status) `,` type($count)
```

**Stage**: ① Input

**Meaning**: Computes signed n=max(0,min(len,N)), zeros all N bytes of the reservation's direct byte-array field, then always calls probe_read_user(dst,n,ptr) once. Returns raw i64 status and i32 clamped requested count, **not successfully read bytes**. NUL has no significance. Failure zeros the whole field including suffix.

**Constraints**: uprobe / uprobe_multi only. Pointer is a direct same-program uprobe.arg / probe.target_arg user_buf result. len i8 / i16 / i32 / i64; direct one-dimensional u8 / i8 field, N1..8192. Inside reservation present, before submit / discard. Caller initializes other fields / padding.

**Lowering**: Sign-extends len to i64, applies register barrier, compares lower / upper bounds. Volatile constant8 /4 /2 /1-byte stores honoring reservation alignment initialize the field, followed by probe_read_user. No large stack allocation, memset libcall, or new loop.

**Evidence**: F78. Source / ptr checks and boundary / three-kernel differential tests. Uses existing helper / ptr requirement rows.

**Unsupported**: Pointers from arbitrary integers / casts / select, slices, map borrows, or arbitrary kinds. Does not establish complete TLS tools or successful reads from arbitrary addresses.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `reservation` | a successful ring-buffer reservation, linearly consumed exactly once |
| `ptr` | a typed uprobe user-buffer address |
| `len` | any non-token type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |
| `count` | 32-bit signless integer |



### `ebpf.user.read_str` (ebpf::UserReadStrOp)

_Read a typed user string into a reservation byte array, returning raw helper status_

Syntax:

```
operation ::= `ebpf.user.read_str` $reservation $field `,` $ptr attr-dict `:` type($reservation) `,` type($ptr) `->` type($status)
```

**Stage**: ① Input

**Meaning**: probe_read_user_str reads user_str into a reservation byte-array field, returning **raw** i64 status: length including NUL on success, element count on truncation, negative errno on failure. **Empty-string status varies by kernel**: 1 on7.1.8, 0 on6.12 /6.6. Detect empty via signed status ≥0 && field[0]==0; status ≤1 would also include failures. Successful reads leave bytes after NUL unchanged; initialize all record bytes with record.make → store_record first.

**Constraints**: Program kind must have user.read_str: uprobe / uprobe_multi / tracepoint / ksyscall. Nonempty field; one-dimensional eight-bit integer array with count ≥1. Placement follows store_field: no absent / post-consumption use. ksyscall pointers originate from typed ksyscall.arg.

**Lowering**: Stage ③ probe_read_user_str(reservation + field offset, count, raw64 user_str).

**Evidence**: F25. C oracle; user_str and post-consumption rejection; three-target / non-root measurements including empty-string status differences.

**Unsupported**: Runtime-length user buffers use user.read (F78). Other kind families rejected. Status is not normalized; compiler does not know kernel versions. TP-derived three-kernel empty / errno evidence belongs to the dedicated differential experiment. Kernel strings use kernel.read_str.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `reservation` | a successful ring-buffer reservation, linearly consumed exactly once |
| `ptr` | a user-string pointer from a typed source, read only by ebpf.user.read_str |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.user.str_at` (ebpf::UserStrAtOp)

_Read string pointer, raw status, and presence at a fixed user char** index (0..19)_

Syntax:

```
operation ::= `ebpf.user.str_at` $array `[` $index `]` attr-dict `:` type($array) `->` `(` type($ptr) `,` type($status) `,` type($present) `)`
```

**Stage**: ① Input
**Meaning**: Reads eight bytes at source raw address +8*index with probe_read_user(112). Results are user_str, raw i64 status, and present = status==0 && pointer!=0. A select guarantees pointer0 on failure. NULL terminator gives status0 / present=false; fault gives negative status / present=false; empty string is non-NULL and present=true.
**Constraints**: Integer attribute index0..19 only. Source must be a same-program direct tp.field / ksyscall.arg user_str_array result, in tracepoint / ksyscall kinds with user.str_at. No loop / static function / SSA index / escape. Caller stops on present=false. Twenty non-NULL entries mean first20 truncation, not complete argv.
**Lowering**: Zero eight-byte scratch → helper112 → load → status-based pointer select → presence comparison. Spill lifetime ends after load. Separate user.read_str reads string contents.
**Evidence**: F74. Static controls and B0 opcheck ref-p128-str-at acceptance. Three-kernel C differential checks value / errno / NULL / empty for root TP / ksyscall and non-root ksyscall. Non-root TP fails reading tracefs ID. Failure-pointer-zero evidence inherits structural ABI-select verification, not an exposed raw-pointer observation.
**Unsupported**: Arbitrary-integer pointers, uprobe-derived arrays, dynamic indices / variable buffers / other architectures / compat.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>index</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `array` | an array of user character pointers from a typed source, read only by fixed-index user.str_at |

#### Results:

| Result | Description |
| :----: | ----------- |
| `ptr` | a user-string pointer from a typed source, read only by ebpf.user.read_str |
| `status` | 64-bit signless integer |
| `present` | 1-bit signless integer |



### `ebpf.user_ringbuf.callback` (ebpf::UserRingbufCallbackOp)

_User_ringbuf drain callback, restricted to sample reads, arithmetic, globals, and time_

Syntax:

```
operation ::= `ebpf.user_ringbuf.callback` $sym_name attr-dict-with-keyword $body
```

**Stage**: ① Input

**Meaning**: Module-level callback invoked for each sample by user_ringbuf.drain, like timer.callback. Sole block argument is dynptr<user_ringbuf> (kernel BPF_DYNPTR_TYPE_LOCAL), read with dynptr.read. Terminates with user_ringbuf.done (continue0) or done stop %c (true stops1). Kernel releases the sample afterward, including the stopping sample.

**Constraints**: One block, exactly one matching dynptr argument, done terminator. Only arith, dynptr.read of that argument, global.load / global.atomic_add, and ktime.ns; no map ops / other helpers / regions / calls. Stage ③ rejects callbacks unused by any program drain. Allowed as ebpf-compile top-level input.

**Lowering**: Stage ③ internal/static .text llvm.func(ptr dynptr,ptr ctx)->i64; ctx unused because drain passes NULL. BTF static FUNC long cb(void *dynptr,void *ctx). Requirement reachability follows callback address.

**Evidence**: F02. 7.1.8 XDP test-run drain results / callback global sums match C.

**Unsupported**: Map ops, callback ctx (drain third argument), and dynptr writes.

Traits: `IsolatedFromAbove`

Interfaces: `Symbol`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>sym_name</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>



### `ebpf.user_ringbuf.done` (ebpf::UserRingbufDoneOp)

_End a user_ringbuf callback with continue zero or stop one_

Syntax:

```
operation ::= `ebpf.user_ringbuf.done` (`stop` $stop^)? attr-dict
```

**Stage**: ① Input

**Meaning**: Terminates user_ringbuf.callback. No operand returns0 and advances to next sample; stop %c returns1 if true, ending after this sample. Verifier callback range is0..1.

**Constraints**: Parent user_ringbuf.callback only; stop i1.

**Lowering**: Stage ③ i64 llvm.return select(c,1,0), or constant0 without operand.

**Evidence**: F02. User-ring-buffer callback tests.

**Unsupported**: Other return values.

Traits: `HasParent<UserRingbufCallbackOp>`, `Terminator`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `stop` | 1-bit signless integer |



### `ebpf.user_ringbuf.drain` (ebpf::UserRingbufDrainOp)

_Bpf_user_ringbuf_drain: process userspace samples with a callback, returning count or negative errno_

Syntax:

```
operation ::= `ebpf.user_ringbuf.drain` $ringbuf `,` $callback attr-dict `->` type($status)
```

**Stage**: ① Input

**Meaning**: user_ringbuf_drain(&map,callback,NULL,0) passes samples in order. **Raw** i64 result is consumed sample count excluding userspace-DISCARD samples; −EBUSY if another consumer is draining; −EINVAL / −E2BIG for corrupt userspace headers (7.1.8 kernel/bpf/ringbuf.c). Callback stop1 ends after that sample.

**Constraints**: Program bodies only, no function / callback / loop bodies. Callback names user_ringbuf.callback; schema map kind user_ringbuf.

**Lowering**: Stage ③ UAPI helper with callback address (pseudo-function ld_imm64), NULL ctx, flags0.

**Evidence**: F02. User-ring-buffer differential tests.

**Unsupported**: Wakeup flags other than0, callback context, and measurements on6.12 /6.6.

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>ringbuf</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>callback</code></td><td>::mlir::FlatSymbolRefAttr</td><td>flat symbol reference attribute</td></tr>
</table>

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.verdict` (ebpf::VerdictOp)

_Terminate by returning a program verdict_

Syntax:

```
operation ::= `ebpf.verdict` $action attr-dict
```

**Stage**: ① Input

**Meaning**: A terminator returning a kind-specific verdict. xdp accepts `aborted` / `drop` / `pass` / `tx` / `redirect`; sched_cls accepts `pass` / `drop`; tp_btf / fentry / fexit / kprobe / uprobe accept only `done` (return value 0, not a verdict).
For sock_ops in the `cgroup` verdict family (deny 0 / allow 1), deny does not block a connection: kernel tcp_call_bpf discards the reply and returns -1, and callers of callbacks such as ESTABLISHED ignore that return value.

**Constraints**: ParentOneOf permits only `ebpf.program` or a `ebpf.tail_call` fallback region. The func verifier rejects it inside `ebpf.func`, which terminates with ebpf.return. The op verifier rejects verdicts absent from the kind table, such as sched_cls `redirect` or kprobe `pass`.

**Lowering**: Unchanged in ②. Stage ③ creates `bpfabi.return` using UAPI `verdict` rows (xdp_action / tcx_action_base), or KernelABI.h's 0 for `done`. bpfabi-verify checks the table at the ③ exit; ④ emits a constant `llvm.return`.

**Evidence**: F01. UAPI verdict values; tp_btf and fentry done; sched_cls pass / drop; fallback terminators.

**Unsupported**: Use `ebpf.verdict.if` to select by value. sched_cls `redirect` / `next` are not accepted; use `ebpf.redirect`. xdp `redirect` only returns a constant and does not call a helper; use `ebpf.redirect_map` for forwarding.

Traits: `HasParent<ProgramOp, TailCallOp>`, `Terminator`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>action</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>



### `ebpf.verdict.if` (ebpf::VerdictIfOp)

_Terminate by selecting between two verdicts_

Syntax:

```
operation ::= `ebpf.verdict.if` $cond $then_action `else` $else_action attr-dict
```

**Stage**: ① Input

**Meaning**: An i1 condition selects one of two verdicts: `ebpf.verdict.if %c "pass" else "drop"` returns the first when true and the second when false.

**Constraints**: ParentOneOf permits only `ebpf.program` or a `ebpf.tail_call` fallback. The op verifier checks both verdicts against the program kind's table.

**Lowering**: Stage ② (ebpf-expand-regions) creates `cf.cond_br` and two blocks ending in `ebpf.verdict`. Later stages follow `ebpf.verdict`; remaining occurrences at ③ are rejected as stage-① operations.

**Evidence**: F11. pass / drop selected by packet.check's range i1; three-target measurements; fallback terminators.

**Unsupported**: Exactly two verdicts, with no multi-way selection.

Traits: `HasParent<ProgramOp, TailCallOp>`, `Terminator`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>then_action</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>else_action</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `cond` | 1-bit signless integer |



### `ebpf.xdp.adjust_head` (ebpf::XdpAdjustHeadOp)

_Bpf_xdp_adjust_head: move the packet start by delta bytes and return status (XDP only; invalidates packet pointers)_

Syntax:

```
operation ::= `ebpf.xdp.adjust_head` $ctx `,` $delta attr-dict `:` type($ctx) `->` type($status)
```

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

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `delta` | 32-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.xdp.adjust_tail` (ebpf::XdpAdjustTailOp)

_Bpf_xdp_adjust_tail: move the packet end by delta bytes and return status (XDP only; invalidates packet pointers)_

Syntax:

```
operation ::= `ebpf.xdp.adjust_tail` $ctx `,` $delta attr-dict `:` type($ctx) `->` type($status)
```

**Stage**: ① Input

**Meaning**: Calls `xdp_adjust_tail(ctx, delta)` and returns raw status (0 or negative errno) as i64. The compiler accepts shrinking only. Like adjust_head, the helper invalidates packet pointers on both success and failure (`pktinval`).

**Constraints**: The op verifier requires an XDP program and context, and **delta must be a direct i32 `arith.constant` whose signed value is ≤ 0**. Positive constants and nonconstant values are rejected.
Even delta 0 calls the helper and participates in may-invalidate checking. It is not allowed in loop bodies. Old-window rejection and packet-neutral C1 / W1 / packet-check rewrite barriers follow adjust_head.

**Lowering**: Stage ③ sign-extends delta to i64 and calls `xdp_adjust_tail`, returning status. No memory effects are declared.

**Evidence**: F13. C oracle (failure −22 leaves the packet unchanged); may-invalidate checking; trailer stripping on three targets with root / non-root; actual veth attach; restriction to constant delta ≤ 0.

**Unsupported**: Growth (positive delta; driver tailroom is unmeasured), nonconstant delta even if provably negative at runtime, non-XDP programs, and loop bodies. Physical NICs are unmeasured.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `delta` | 32-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `status` | 64-bit signless integer |



### `ebpf.xsk.lookup` (ebpf::XskLookupOp)

_Test socket presence in xskmap_

Syntax:

```
operation ::= `ebpf.xsk.lookup` $map `[` $key `]` attr-dict `:` type($map) `,` type($key) `->` type($present)
```

**Stage**: ① Input
**Meaning**: True for non-NULL lookup. Does not read fd or an ordinary map value.
**Constraints**: XDP program body, xskmap with i32 key / value.
**Lowering**: Unchanged in ②; ③ compares map_lookup_elem result against NULL without dereferencing PTR_TO_XDP_SOCK.
**Evidence**: F60. 7.1.8 child-netns AF_XDP present / missing / out-of-range match C.
**Unsupported**: queue_id reads and entry write / atomic / delete.

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | a BPF map handle with kind, key type and value type |
| `key` | any non-token type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `present` | 1-bit signless integer |



### `ebpf.yield` (ebpf::YieldOp)

_Close a checked region and return its values_

Syntax:

```
operation ::= `ebpf.yield` ($results^ `:` type($results))? attr-dict
```

**Stage**: ① Input

**Meaning**: Terminates checked regions: ref.check / ringbuf.if_reserved / ref.index / packet.check / spin.region, returning values if the parent has results. kptr.check and kref.check are also supported parents.

**Constraints**: ParentOneOf restricts parents to these operations. ref.check forbids borrowed escape and requires result-type agreement. ref.index forbids elem / borrowed escape. packet.check forbids pkt_window escape. ringbuf.if_reserved forbids reservation escape and requires matching results. spin.region returns no values. kptr.check / kref.check forbid kptr / kref escape and require matching results. Within loops, ref.check arms may also end with break / continue.

**Lowering**: Stage ② branches to the merge block with result block arguments. In spin.region it disappears into lock / body / unlock. Absent at ③; ebpf-verify-structured rejects leftovers as stage-① ops.

**Evidence**: F01, F02, F06, F10, F17. Region expansion, ref.index, packet.check, and spin.region tests.

**Unsupported**: Borrow / reservation / window / element escape. ebpf.if uses if.yield; ebpf.loop uses loop.yield.

Traits: `HasParent<RefCheckOp, RingbufIfReservedOp, RefIndexOp, PacketCheckOp, SpinRegionOp, KPtrCheckOp, KRefCheckOp, SockRefCheckOp>`, `Terminator`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `results` | variadic of any non-token type |



## ② Internal operations

### `ebpf.assume_present` (ebpf::AssumePresentOp)

_Obtain a checked reference or reservation on an is_present true edge (stage ② internal)_

Syntax:

```
operation ::= `ebpf.assume_present` $value attr-dict `:` type($value) `->` type($result)
```

**Stage**: ② Internal

**Meaning**: Uses an unchecked value as !ebpf.borrowed / !ebpf.reservation / !ebpf.sock_ref on an is_present true edge.

**Constraints**: Op verifier checks only type conversion (maybe_ref → borrowed, maybe_reservation → reservation, sock_ref_or_null → sock_ref). Placement is checked at stage-② exit (ebpf-verify-structured 1): block must have a single incoming true edge from cf.cond_br conditioned on is_present of the same value. A false edge into the same block is rejected, preventing unchecked borrows. CheckedEdge defines the condition and is shared with diagnostic passes. Packet-neutral.

**Lowering**: Stage ③ preserves the pointer; is_present supplies the comparison.

**Evidence**: Internal — generated from ref.check / ringbuf.if_reserved present regions. Source input is rejected to prevent stage-① bypass. Input ops own feature evidence; tests cover PacketNeutral and both edges targeting the same block.

**Unsupported**: Not writable in input.

Interfaces: `EBPF_Stage2InternalOpInterface`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `value` | any non-token type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | any non-token type |



### `ebpf.bpf_loop` (ebpf::BpfLoopOp)

_Bpf_loop(count, callback, &context, 0), returning carried values reloaded from context_

Syntax:

```
operation ::= `ebpf.bpf_loop` $callback `count` `(` $count `)` `(` $inits `)` `captures` `(` $captures `)` attr-dict `:` functional-type(operands, results)
```

**Stage**: ② Internal

**Meaning**: Helper call invoking ebpf.loop_callback count times, with runtime count, initial carried values, and captures. Results are final carried values.

**Constraints**: Callback must name an ebpf.loop_callback.

**Lowering**: Stage ③ calls loop(count, callback address, ctx, flags = 0). Requirements and HelperCalls treat function addresses as reachability edges.

**Evidence**: Internal — ebpf-expand-regions creates it from stage-① ebpf.loop N callback. ebpf-compile rejects it in source input, preventing stage-① bypasses. The input op owns feature-path evidence, including callback calls.

**Unsupported**: Not writable in input; use stage-① ebpf.loop ... callback.

Traits: `AttrSizedOperandSegments`

Interfaces: `EBPF_Stage2InternalOpInterface`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>callback</code></td><td>::mlir::FlatSymbolRefAttr</td><td>flat symbol reference attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `count` | 32-bit signless integer |
| `inits` | variadic of signless integer |
| `captures` | variadic of signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `results` | variadic of signless integer |



### `ebpf.callback.return` (ebpf::CallbackReturnOp)

_Write carried values to context and return constant zero (continue) or one (stop)_

Syntax:

```
operation ::= `ebpf.callback.return` $stop ($values^ `:` type($values))? attr-dict
```

**Stage**: ② Internal

**Meaning**: Terminates ebpf.loop_callback by writing carried values to context and returning stop: 0 continues, 1 stops. The same contract applies to for_each callbacks (next element / stop).

**Constraints**: Parent is ebpf.loop_callback only.

**Lowering**: Stage ③ writes carried values to context and returns constant 0 / 1 from the callback function.

**Evidence**: Internal — ebpf-expand-regions creates it from loop.yield inside stage-① callback loops. ebpf-compile rejects it in source input, preventing stage-① bypasses. The input op owns feature-path evidence.

**Unsupported**: Not writable in input; use stage-① ebpf.loop.yield.

Traits: `HasParent<LoopCallbackOp>`, `Terminator`

Interfaces: `EBPF_Stage2InternalOpInterface`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>stop</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `values` | variadic of signless integer |



### `ebpf.elem.at` (ebpf::ElemAtOp)

_Form a checked element on elem.in_range true edges (stage ② internal)_

Syntax:

```
operation ::= `ebpf.elem.at` $ref $field `[` $indices `]` attr-dict `:` type($ref) `->` type($result)
```

**Stage**: ② Internal

**Meaning**: Refers to a record array element as !ebpf.elem<iN> after range-check true edges.

**Constraints**: Stage-② exit verification (ebpf-verify-structured 1b) walks backward from the last dimension. Each block must have exactly one incoming true edge from cf.cond_br whose elem.in_range condition has the same ref / field / dimension index / dim (CheckedEdge defines the checked-edge condition). Elem uses are limited to elem.load / elem.store.

**Lowering**: Stage ③ forms record field offset (@records) + index × stride. Loop-IV indexing can cause codegen to form the address with another induction variable; inspect ELF.

**Evidence**: Internal — ebpf-expand-regions creates it from ref.index in_range. Source input is rejected to prevent stage-① bypass. ref.index owns feature evidence; checked-edge placement is shared.

**Unsupported**: Not writable in input; use ref.index.

Interfaces: `EBPF_Stage2InternalOpInterface`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ref` | any non-token type |
| `indices` | variadic of 64-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | a bounds-checked array-element reference |



### `ebpf.elem.in_range` (ebpf::ElemInRangeOp)

_Test unsigned index against array element count (stage ② internal)_

Syntax:

```
operation ::= `ebpf.elem.in_range` $ref $field `[` $index `]` attr-dict `:` type($ref)
```

**Stage**: ② Internal

**Meaning**: Returns i1 indicating whether a variable index is within the record array field's dimension, selected by dim.

**Constraints**: Only within stage-② ref.index expansion, using the single zero-extended index value.

**Lowering**: Stage ③ emits icmp ult against element count.

**Evidence**: Internal — ebpf-expand-regions creates it from ref.index. ebpf-compile rejects source-input occurrences to prevent bypassing stage-① restrictions. Feature-path evidence belongs to ref.index, including multidimensional arrays.

**Unsupported**: Not writable in input; use ref.index.

Interfaces: `EBPF_Stage2InternalOpInterface`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>dim</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ref` | any non-token type |
| `index` | 64-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | 1-bit signless integer |



### `ebpf.elem.mask` (ebpf::ElemMaskOp)

_Obscure and mask a checked index (stage ② internal M1)_

Syntax:

```
operation ::= `ebpf.elem.mask` $ref $field `[` $index `]` attr-dict `:` type($ref)
```

**Stage**: ② Internal

**Meaning**: On an elem.in_range true edge, obscures the index from the compiler and masks with 2^k − 1, using the smallest 2^k ≥ dimension count. Since the checked index is smaller, this is an identity. Stage ② rechecks elem.in_range on the result (same out_of_range on false), then uses it in elem.at. This reestablishes a range immediately before addition, independent of register history such as speculative unknown values or narrowing lost after spill.

**Constraints**: Only inside stage-② ref.index expansion with --tune-mask-checked-index.

**Lowering**: Stage ③ uses an instruction-free inline-asm barrier (`"=r,0"`, like libbpf barrier_var) to prevent known-bits mask elimination, then and.

**Evidence**: Internal — speculative index probes and M1 implementation tests.

**Unsupported**: Not writable in input. Does not solve constant / unknown indices reaching the same addition (REASON_PATHS).

Interfaces: `EBPF_Stage2InternalOpInterface`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>field</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>dim</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ref` | any non-token type |
| `index` | 64-bit signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | 64-bit signless integer |



### `ebpf.for_each_map_elem` (ebpf::ForEachMapElemOp)

_Bpf_for_each_map_elem(map, callback, &context, 0), returning invocation count and reloaded carried values_

Syntax:

```
operation ::= `ebpf.for_each_map_elem` $callback `map` `(` $map `)` `(` $inits `)` `captures` `(` $captures `)` attr-dict `:` functional-type(operands, results)
```

**Stage**: ② Internal

**Meaning**: Calls an ebpf.loop_callback with for_each attribute for each map element. Passes initial carried values and captures, returning invoked element count (helper result) and final carried values.

**Constraints**: Callback names an ebpf.loop_callback with for_each attribute; key / value block argument types match the map.

**Lowering**: Stage ③ calls for_each_map_elem(map, callback address, ctx, flags = 0). Requirements and HelperCalls follow function-address reachability edges, as with bpf_loop.

**Evidence**: Internal — ebpf-expand-regions creates it from stage-① ebpf.map.for_each; ebpf-compile rejects it in input. The input op owns feature-path evidence.

**Unsupported**: Not writable in input; use ebpf.map.for_each.

Traits: `AttrSizedOperandSegments`

Interfaces: `EBPF_Stage2InternalOpInterface`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>callback</code></td><td>::mlir::FlatSymbolRefAttr</td><td>flat symbol reference attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `map` | a BPF map handle with kind, key type and value type |
| `inits` | variadic of signless integer |
| `captures` | variadic of signless integer |

#### Results:

| Result | Description |
| :----: | ----------- |
| `count` | 64-bit signless integer |
| `results` | variadic of signless integer |



### `ebpf.is_present` (ebpf::IsPresentOp)

_Test an unchecked reference or reservation for non-NULL (stage ② internal)_

Syntax:

```
operation ::= `ebpf.is_present` $value attr-dict `:` type($value)
```

**Stage**: ② Internal

**Meaning**: Returns i1 for non-NULL !ebpf.maybe_ref / !ebpf.maybe_reservation / !ebpf.sock_ref_or_null.

**Constraints**: Checked by ebpf-verify-structured at the stage-② exit. Paired with assume_present so only true edges can use contents. Packet-neutral (isPacketNeutral table): W1 and diagnostic passes may cross it between window definition / use.

**Lowering**: Stage ③ emits icmp ne against NULL.

**Evidence**: Internal — generated from ref.check / ringbuf.if_reserved by ebpf-expand-regions. Source input is rejected to prevent stage-① bypass. Input ops own feature evidence; adding it to PacketNeutral preserves existing ELF, with W1-changing synthetic inputs gated on three targets.

**Unsupported**: Not writable in input; use ref.check / ringbuf.if_reserved / sock.ref_check.

Traits: `AlwaysSpeculatableImplTrait`

Interfaces: `ConditionallySpeculatable`, `EBPF_Stage2InternalOpInterface`, `NoMemoryEffect (MemoryEffectOpInterface)`

Effects: `MemoryEffects::Effect{}`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `value` | any non-token type |

#### Results:

| Result | Description |
| :----: | ----------- |
| `result` | 1-bit signless integer |



### `ebpf.loop.spill` (ebpf::LoopSpillOp)

_Volatile IV store to a dedicated stack slot per bounded-loop iteration (stage ② internal speculative-path barrier)_

Syntax:

```
operation ::= `ebpf.loop.spill` $iv attr-dict `:` type($iv)
```

**Stage**: ② Internal

**Meaning**: With --tune-backedge-spill (enabled by default; =false disables it), ebpf-expand-regions inserts this at the header start of B back-edge loops with N ≥ 2, or body start with --tune-backedge-rotate. Not inserted for unroll / callback. No operation reads the dead store; program semantics are unchanged.

**Constraints**: Not writable in input (Stage2InternalOp; ebpf-compile explicitly rejects it). One per loop; i32 IV.

**Lowering**: Stage ③ emits `llvm.store volatile (zext i64 %iv)` into a dedicated entry alloca i64, one unread eight-byte stack slot per loop. BPF uses one `*(u64 *)(r10 - X) = rN`. The slot starts STACK_INVALID then becomes STACK_SPILL. For loaders without CAP_PERFMON (!bypass_spec_v4), the 7.1.8 verifier marks the store nospec_result (kernel/bpf/verifier.c Spectre-v4 sanitization), ending speculative paths at that instruction. This breaks the B-loop bound failure chain `The sequence of 8193 jumps` / `infinite loop detected`, where final-iteration speculative re-entry narrows IV across generations.

**Evidence**: F07. Stage-③ b8cf1 / c4cf1 / c64cf1 with the store alone are accepted on 7.1.8 with {bpf, net_admin}; lowering incorporates that behavior.

**Unsupported**: Does not help CAP_PERFMON-less 6.12 / 6.6: sanitize_stack_spill fixup inserts BPF_ST_NOSPEC but does not terminate speculative paths at the store. Not inserted for U / H. Does not change main-path speculative push count for constant loops (8192 boundary); --tune-backedge-rotate addresses that.

Interfaces: `EBPF_Stage2InternalOpInterface`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `iv` | 32-bit signless integer |



### `ebpf.loop_callback` (ebpf::LoopCallbackOp)

_Bpf_loop callback body with IV, carried integers, captured integers, and maps_

Syntax:

```
operation ::= `ebpf.loop_callback` $sym_name attr-dict-with-keyword $body
```

**Stage**: ② Internal

**Meaning**: Module-level callback symbol for ebpf.bpf_loop. Block arguments are IV, carried values, captured integers, and maps. Context is a sequence of eight-byte caller-stack slots: num_carried values, then num_captured integers. With for_each attribute, it is a for_each_map_elem callback and replaces IV with key value and borrowed value arguments.

**Constraints**: IsolatedFromAbove. IV is i32; for_each has integer key and !ebpf.borrowed value. Attributes record carried / captured counts and map_symbols.

**Lowering**: Stage ③ emits a static llvm.func: `(u64 index, ptr ctx)` for bpf_loop, `(ptr map, ptr key, ptr value, ptr ctx)` for for_each. Key is loaded through its pointer; value preserves its pointer. Map arguments follow map_symbols order and become symbol addressof, not stack captures.

**Evidence**: Internal — ebpf-expand-regions creates it from stage-① ebpf.loop N callback / ebpf.map.for_each. ebpf-compile rejects it in input to prevent bypassing stage-① restrictions. Feature-path evidence belongs to those input ops, including callback calls / nesting and for_each.

**Unsupported**: Not writable in input; permitted top-level inputs are program / func / timer.callback / user_ringbuf.callback only.

Traits: `IsolatedFromAbove`

Interfaces: `EBPF_Stage2InternalOpInterface`, `Symbol`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>sym_name</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
<tr><td><code>num_carried</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
<tr><td><code>num_captured</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
<tr><td><code>map_symbols</code></td><td>::mlir::ArrayAttr</td><td>array attribute</td></tr>
<tr><td><code>for_each</code></td><td>::mlir::UnitAttr</td><td>unit attribute</td></tr>
</table>



### `ebpf.pkt.check_br` (ebpf::PktCheckBrOp)

_Branch on packet bounds, passing a window to the true successor (stage ② internal)_

Syntax:

```
operation ::= `ebpf.pkt.check_br` $ctx `[` $offset `]` `len` $len `,` $inRange `,` $outOfRange attr-dict `:` type($ctx)
```

**Stage**: ② Internal

**Meaning**: Terminates with a branch testing [offset, offset + len). The in-range successor ^in has a sole !ebpf.pkt_window<len> argument.

**Constraints**: Op verifier checks successor count / arguments. Offset is one zero-extended i64 value. ebpf-verify-structured checks invalidating helpers before window uses.

**Lowering**: Stage ③ preserves the pointer register used for data + offset + len versus data_end comparison (ugt / ule). Constant-offset checking uses subtraction to avoid overflow.

**Evidence**: Internal — expanded from packet.check; source input is rejected to prevent bypassing stage-① restrictions, including read-only sched_cls windows. packet.check owns feature evidence.

**Unsupported**: Not writable in input; use packet.check (window stores are XDP-only).

Traits: `Terminator`

Interfaces: `EBPF_Stage2InternalOpInterface`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>len</code></td><td>::mlir::IntegerAttr</td><td>64-bit signless integer attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `offset` | 64-bit signless integer |

#### Successors:

| Successor | Description |
| :-------: | ----------- |
| `inRange` | any successor |
| `outOfRange` | any successor |



### `ebpf.spin.lock` (ebpf::SpinLockOp)

_Bpf_spin_lock (stage ② internal)_

Syntax:

```
operation ::= `ebpf.spin.lock` $ref $lock `:` type($ref) attr-dict
```

**Stage**: ② Internal

**Meaning**: Acquires a borrowed record's spin-lock field.

**Constraints**: Only at the start of stage-② spin.region expansion, paired with ebpf.spin.unlock around the body.

**Lowering**: Stage ③ calls spin_lock with the lock field address.

**Evidence**: Internal — generated by ebpf-expand-regions from stage-① ebpf.spin.region. ebpf-compile rejects it in source input, preventing bypass of stage-① restrictions. The input op owns feature-path evidence.

**Unsupported**: Not writable in input; use stage-① ebpf.spin.region for a closed critical region.

Interfaces: `EBPF_Stage2InternalOpInterface`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>lock</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ref` | a checked borrowed reference without ownership |



### `ebpf.spin.unlock` (ebpf::SpinUnlockOp)

_Bpf_spin_unlock (stage ② internal)_

Syntax:

```
operation ::= `ebpf.spin.unlock` $ref $lock `:` type($ref) attr-dict
```

**Stage**: ② Internal

**Meaning**: Releases a borrowed record's spin-lock field.

**Constraints**: Only at the end of stage-② spin.region expansion.

**Lowering**: Stage ③ calls spin_unlock with the lock field address.

**Evidence**: Internal — generated by ebpf-expand-regions from stage-① ebpf.spin.region. ebpf-compile rejects it in source input, preventing bypass of stage-① restrictions. The input op owns feature-path evidence.

**Unsupported**: Not writable in input; use stage-① ebpf.spin.region.

Interfaces: `EBPF_Stage2InternalOpInterface`

#### Attributes:

<table>
<tr><th>Attribute</th><th>MLIR Type</th><th>Description</th></tr>
<tr><td><code>lock</code></td><td>::mlir::StringAttr</td><td>string attribute</td></tr>
</table>

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ref` | a checked borrowed reference without ownership |



### `ebpf.tail_call.try` (ebpf::TailCallTryOp)

_Bpf_tail_call attempt (stage ②; only failure continues)_

Syntax:

```
operation ::= `ebpf.tail_call.try` $ctx `,` $map `[` $index `]` `:` type($ctx) `,` type($map) `,` type($index) attr-dict
```

**Stage**: ② Internal

**Meaning**: A nonterminal tail-call attempt. Success never returns; failure (out-of-range / limit / empty slot, indistinguishable to the program) continues into the original fallback contents.

**Constraints**: In stage ②, the fallback contents immediately follow the original tail_call expansion. Failure invalidates packet pointers.

**Lowering**: Stage ③ calls tail_call(ctx, prog_array, index).

**Evidence**: Internal — generated by ebpf-expand-regions from `ebpf.tail_call ... fallback { ... }`. ebpf-compile rejects it as input; allowing it in regions would bypass stage-① restrictions. The input op owns feature-path evidence.

**Unsupported**: Not writable in input; use stage-① ebpf.tail_call, a top-level program terminator.

Interfaces: `EBPF_Stage2InternalOpInterface`

#### Operands:

| Operand | Description |
| :-----: | ----------- |
| `ctx` | an eBPF program context carrying its attach kind |
| `map` | any non-token type |
| `index` | 32-bit signless integer |



