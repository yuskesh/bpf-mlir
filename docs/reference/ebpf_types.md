<!-- Generated from descriptions in include/bpf-mlir/Dialect/EBPF/IR/EBPFTypes.td. Do not edit; regenerate with scripts/gen-reference. -->

# ebpf dialect type reference

Each type documents **Meaning**, **Where it appears**, and **Evidence**. See [operations](ebpf_ops.md).


## Documented types

### BorrowedType

_A checked borrowed reference without ownership_

Syntax:

```
!ebpf.borrowed<
  ::mlir::Type   # pointee
>
```

**Meaning**: `!ebpf.borrowed<T>` borrows a map value, either an integer or a record. It owns nothing. Non-NULL is guaranteed by the ref.check present region at stage 1 or the true is_present edge at stage 2.

**Where it appears**: the block argument of a ref.check present region, without escape or block-argument transport, and a subprogram parameter whose callee only reads it. At stage 2 it is produced by assume_present. Uses include ref.load/store/atomic_add/field.load/field.store, ref.index, spin.region, timer.init/set_callback/start and ebpf.call arguments.

**Evidence**: F01, F03. Map reference, subprogram and record-field fixtures cover these uses.

#### Parameters:

| Parameter | C++ type | Description |
| :-------: | :-------: | ----------- |
| pointee | `::mlir::Type` |  |

### ContextType

_An eBPF program context carrying its attach kind_

Syntax:

```
!ebpf.ctx<
  ::llvm::StringRef   # kind
>
```

**Meaning**: `!ebpf.ctx<"kind">` identifies the program context and its attach kind. The kind selects available operations, including packet access, tracing arguments, pt_regs and return values. Kinds include xdp, tp_btf, fentry, fexit, kprobe, uprobe and sched_cls. The type itself does not validate the kind; the program and operation verifiers do.

**Where it appears**: only as the first entry-block argument of `ebpf.program`, with the matching program kind. It cannot be another program argument or an `ebpf.func` parameter. It may be captured by a loop. Operations check the kind: ctx.arg (tp_btf), ctx.retval (fexit), kprobe.arg (kprobe), uprobe.arg (uprobe), stack.kernel_id/perf.output (fentry), packet.load/packet.check (xdp/sched_cls), and XDP operations such as adjust_head, adjust_tail and tail_call.

**Evidence**: F01, F20, F21, F22, F23, F24, F25. Tracing, entry/exit and probe argument fixtures cover the corresponding context forms.

#### Parameters:

| Parameter | C++ type | Description |
| :-------: | :-------: | ----------- |
| kind | `::llvm::StringRef` | program kind |

### DynptrType

_A kernel dynptr, an opaque 16-byte stack object describing a runtime-sized memory window_

Syntax:

```
!ebpf.dynptr<
  ::llvm::StringRef   # kind
>
```

**Meaning**: `!ebpf.dynptr<"K">` represents struct bpf_dynptr, an opaque 16-byte stack object. K = "ringbuf" denotes a runtime-sized reservation initialized by ringbuf.reserve_dynptr. It is linear: submit_dynptr or discard_dynptr consumes it exactly once, even after failed reservation. A failed dynptr is null, reads/writes return -EINVAL and consumption does nothing; the kernel verifier enforces the lifetime.

**Where it appears**: ringbuf.reserve_dynptr results, used only by dynptr.write/read and ringbuf.submit_dynptr/discard_dynptr. Yield/call/loop capture is rejected. ebpf-verify-ownership checks exactly one consumption on every path. At stage 3 it points to a 16-byte entry-block alloca aligned to 8.

**Evidence**: F02. Root 7.1.8 XDP test runs match C for reserve success/failure, read/write status and event bytes.

**Unsupported**: skb/xdp/local dynptr and bpf_dynptr_from_mem, or passing a dynptr to a subprogram.

#### Parameters:

| Parameter | C++ type | Description |
| :-------: | :-------: | ----------- |
| kind | `::llvm::StringRef` | dynptr kind |

### ElemType

_A bounds-checked array-element reference_

Syntax:

```
!ebpf.elem<
  ::mlir::Type   # element
>
```

**Meaning**: `!ebpf.elem<iN>` is a checked dynamically indexed record-array element with a signless integer element type.

**Where it appears**: at stage 1 only the in_range block argument of ref.index, without yield or block-argument transport. At stage 2 it is produced by elem.at under true elem.in_range edges for every dimension. Only elem.load/store may use it.

**Evidence**: F06. Record array indexing and multidimensional bounds fixtures cover this reference.

#### Parameters:

| Parameter | C++ type | Description |
| :-------: | :-------: | ----------- |
| element | `::mlir::Type` |  |

### KPtrOrNullType

_A nullable pointer to an internal kernel struct_

Syntax:

```
!ebpf.kptr_or_null<
  ::llvm::StringRef   # structName
>
```

**Meaning**: `!ebpf.kptr_or_null<"S">` cannot be read directly; field reads require the checked !ebpf.kptr<S> present-region argument of kptr.check.

**Where it appears**: ctx.arg results when a tp_btf args element is {"kind":"struct", "name":"S", "nullable":true}. Only kptr.check may use it. Loop capture is rejected.

**Evidence**: F23. sched_pi_setprio pi_task tests on 7.1.8/6.12 reject unchecked reads of marked arguments and accept checked reads.

**Unsupported**: 6.6.157 does not mark nullable tp_btf arguments and removes the check. Writing a check therefore does not establish runtime safety on that kernel; the load-time arg_nullable requirement blocks it.

#### Parameters:

| Parameter | C++ type | Description |
| :-------: | :-------: | ----------- |
| structName | `::llvm::StringRef` | kernel struct name |

### KPtrType

_A pointer to an internal kernel struct obtained from tracing arguments_

Syntax:

```
!ebpf.kptr<
  ::llvm::StringRef   # structName
>
```

**Meaning**: `!ebpf.kptr<"S">` represents a kernel-supplied pointer with a BTF type. S names a @kernel struct, the schema core.kernel_types local type. Only declared fields can be read, using CO-RE relocations.

**Where it appears**: ctx.arg results and the present block argument of kptr.check after checking kptr_or_null. No operation constructs it from an integer. Its field-read consumer is kfield.load; loop capture is rejected. ebpf-verify-kptr checks S's declaration and ebpf-verify-schema checks the ctx.arg type name.

**Evidence**: F23. CO-RE field fixtures check the local @kernel declaration and tracing argument origin.

#### Parameters:

| Parameter | C++ type | Description |
| :-------: | :-------: | ----------- |
| structName | `::llvm::StringRef` | kernel struct name |

### KRefOrNullType

_An owned nullable kernel-struct reference acquired by a kfunc, with linear checking_

Syntax:

```
!ebpf.kref_or_null<
  ::llvm::StringRef   # structName
>
```

**Meaning**: `!ebpf.kref_or_null<"S">` is an owned nullable reference returned by a KF_ACQUIRE | KF_RET_NULL kfunc. Direct field reads are disallowed; kref.check's present !ebpf.kref<S> argument is required. Every path must check it exactly once. Failing to check leaks a reference, which the kernel rejects as Unreleased reference.

**Where it appears**: kfunc.call results whose table flags are acquire/ret_null and return type is *S, and kptr.xchg results transferring a map value's old reference out. It may occur only as the operand of one kref.check, not yield/call/loop capture. ebpf-verify-ownership checks every path. S is a @kernel struct checked by ebpf-verify-kptr. At stage 3 it is a pointer.

**Evidence**: F56, F69. Root 7.1.8 syscall test runs compare acquired references with C; kptr.xchg tests cover map ownership transfers.

#### Parameters:

| Parameter | C++ type | Description |
| :-------: | :-------: | ----------- |
| structName | `::llvm::StringRef` | kernel struct name |

### KRefType

_A checked owned kernel-struct reference, consumed exactly once by release or map transfer_

Syntax:

```
!ebpf.kref<
  ::llvm::StringRef   # structName
>
```

**Meaning**: `!ebpf.kref<"S">` owns a checked non-NULL kernel reference, a trusted PTR_TO_BTF_ID. Every CFG path must consume it once through a KF_RELEASE kfunc argument or transfer ownership to a map via kptr.xchg. Use after release or transfer is rejected.

**Where it appears**: only kref.check's present-region block argument, without escaping the region. Uses are kfunc.call arguments (release consumes, other kfuncs borrow), kfield.load pointers and the consuming new-reference operand of kptr.xchg. Yield/call transport/loop capture is rejected. ebpf-verify-ownership checks every path, as for dynptr. At stage 3 it is a pointer.

**Evidence**: F56, F69. Kfunc ownership and map-kptr exchange fixtures cover the transfers.

#### Parameters:

| Parameter | C++ type | Description |
| :-------: | :-------: | ----------- |
| structName | `::llvm::StringRef` | kernel struct name |

### MapType

_A BPF map handle with kind, key type and value type_

Syntax:

```
!ebpf.map<
  ::llvm::StringRef,   # kind
  ::mlir::Type,   # keyType
  ::mlir::Type   # valueType
>
```

**Meaning**: `!ebpf.map<"kind", K, V>` carries the map kind and key/value types. Operation verifiers use these parameters to check keys and values. Capacity, flags and BTF declarations belong to the schema; the IR carries a handle.

**Where it appears**: program entry arguments after the context, and function entry arguments after typed parameters. They correspond positionally to `maps [@...]`; ebpf-verify-schema checks kind/key/value. For array_of_maps/hash_of_maps, the value parameter is the inner map handle type and must match the schema's `inner` template. `ebpf.map.inner` produces the inner handle only inside its checked region.

Uses include map operations, redirect_map, tail_call, stack.kernel_id, perf.output, timer.init and storage.get/delete. Handles can be captured by loops and passed to bpf_loop callbacks. Kinds include hash, array, percpu_array, percpu_hash, lru_hash, lru_percpu_hash, devmap, lpm_trie, prog_array, stack_trace, perf_event_array, sockmap, sockhash, reuseport_sockarray, sk_storage, task_storage, inode_storage, cgrp_storage, array_of_maps, hash_of_maps, queue, stack, bloom_filter, cpumap, xskmap, devmap_hash and cgroup_array. cgroup_array is restricted to task.under_cgroup/skb.under_cgroup; cpumap to redirect_map. xskmap/devmap_hash support redirect_map and dedicated scalar XDP lookup. sockmap/sockhash support sk_skb/sk_msg attach, dedicated redirect/sock_ops update, and XDP socket lookup/delete; generic lookup/update/atomic are rejected. The four local-storage kinds support only storage.get/delete. ringbuf is addressed by name in ringbuf.reserve rather than a handle.

Keyless queue/stack/bloom_filter maps use MLIR `none` as their key type, for example `!ebpf.map<"queue", none, i32>`, and support only map.push/pop/peek and bloom.peek.

**Unsupported**: deprecated cgroup_storage/percpu_cgroup_storage and their *_deprecated aliases are deliberately rejected with a diagnostic suggesting cgrp_storage. The kernel alternative for per-CPU storage uses a local per-CPU kptr, which this compiler does not support. insn_array is not a user-declared map: libbpf creates it from ELF .jumptables for a program. It has no ordinary-array replacement. Schema and map/storage operations reject it as loader-generated. RejectedMapKinds.def records these reasons and optional replacements.

**Evidence**: F01, F04, F51, F52, F59, F60. The map, storage, map-in-map and keyless-map fixtures cover these declarations, including three-target map-kind tests.

#### Parameters:

| Parameter | C++ type | Description |
| :-------: | :-------: | ----------- |
| kind | `::llvm::StringRef` | map kind |
| keyType | `::mlir::Type` |  |
| valueType | `::mlir::Type` |  |

### MaybeRefType

_An unchecked nullable reference_

Syntax:

```
!ebpf.maybe_ref<
  ::mlir::Type   # pointee
>
```

**Meaning**: `!ebpf.maybe_ref<T>` is an unchecked nullable reference: map_lookup_elem can return NULL. The IR requires a NULL check before obtaining `!ebpf.borrowed<T>`. An unchecked dereference is rejected by the operation verifier with a note, before kernel verification.

**Where it appears**: the result of map.lookup and the operand of ref.check. It can be a subprogram argument, where the callee may only check it or forward it through ebpf.call. At stage 2 it is an operand of is_present/assume_present. Loop capture is rejected.

**Evidence**: F01. Removing the NULL check in the kernel operation fixture is rejected by the kernel; staged lowering and subprogram tests check the IR boundary.

#### Parameters:

| Parameter | C++ type | Description |
| :-------: | :-------: | ----------- |
| pointee | `::mlir::Type` |  |

### MaybeReservationType

_An unchecked reservation that may have failed_

Syntax:

```
!ebpf.maybe_reservation<
  ::mlir::Type   # recordType
>
```

**Meaning**: an unchecked ring-buffer reservation; bpf_ringbuf_reserve can return NULL. As with maybe_ref/ref.check, the IR represents the check explicitly instead of hiding separate NULL branches in every lowered store/submit.

**Where it appears**: ringbuf.reserve results and ringbuf.if_reserved operands. At stage 2 it is an is_present/assume_present operand.

**Evidence**: F02. Checked ring reservation and event fixtures cover this form.

#### Parameters:

| Parameter | C++ type | Description |
| :-------: | :-------: | ----------- |
| recordType | `::mlir::Type` |  |

### PktWindowType

_A bounds-checked packet window of len bytes_

Syntax:

```
!ebpf.pkt_window<
  int64_t   # len
>
```

**Meaning**: `!ebpf.pkt_window<len>` represents a checked len-byte packet range. It retains the pointer register used for the check, so accesses within the window need no second range check. Only constant indices inside the window are valid.

**Where it appears**: at stage 1, only the sole block argument of packet.check's in_range region; at stage 2, only the sole argument of pkt.check_br's ^in block. Uses are packet.store (XDP only) and packet.window_load. Yield outside the region and block-argument transport are rejected. Use after xdp.adjust_head/adjust_tail is rejected at the stage-2 exit. At stage 3 the window becomes an !llvm.ptr register.

**Evidence**: F10, F11. Packet-check/window-load fixtures, read-only sched_cls windows and helper invalidation tests cover the boundary.

#### Parameters:

| Parameter | C++ type | Description |
| :-------: | :-------: | ----------- |
| len | `int64_t` |  |

### RecordType

_A schema record identified by symbol and byte size for maps, reservations, perf output and subprogram arguments_

Syntax:

```
!ebpf.record<
  ::llvm::StringRef,   # symbol
  int64_t   # size
>
```

**Meaning**: `!ebpf.record<"S", N>` identifies a schema record by name and byte size. Field order/offsets are defined by core.records and the @records BTF declarations. This type stores identity and size only. ebpf-verify-schema checks map keys/values and ring reservations, and ebpf-verify-records checks @records.

**Where it appears**: as a map key/value type, maybe_ref/borrowed pointee accessed by field name or ref.index, and reservation/maybe_reservation record type. Its only SSA producer is record.make, used for map.update/try_update values, hash/lpm_trie keys, ringbuf.store_record and perf.output. Whole-record ref.load/store is rejected.

**Evidence**: F02, F03. Map value, record.make, record-key, reservation/schema and whole-record ring-store fixtures cover these contracts.

#### Parameters:

| Parameter | C++ type | Description |
| :-------: | :-------: | ----------- |
| symbol | `::llvm::StringRef` | record symbol |
| size | `int64_t` |  |

### ReservationType

_A successful ring-buffer reservation, linearly consumed exactly once_

Syntax:

```
!ebpf.reservation<
  ::mlir::Type   # recordType
>
```

**Meaning**: `!ebpf.reservation<!ebpf.record<"S", N>>` is a successful, non-NULL ring-buffer reservation. It is linear: submit or discard consumes it exactly once. The dialect type and ebpf-verify-ownership express the consumption count, which standard dialect types/traits do not.

**Where it appears**: only the present-region block argument of ringbuf.if_reserved; no operation produces it as a result. Uses include ringbuf.store_field/store_record/submit/discard and task.comm/user.read_str. Its parameter is the schema ringbuf map's declared record. An integer parameter is syntactically possible but rejected by schema verification because ringbuf must declare a record.

**Evidence**: F02. Reservation tests reject use after consumption and check event output.

#### Parameters:

| Parameter | C++ type | Description |
| :-------: | :-------: | ----------- |
| recordType | `::mlir::Type` |  |

### SockRefOrNullType

_An owned nullable socket reference acquired from a socket map_

Syntax: `!ebpf.sock_ref_or_null`

**Meaning**: sockmap/sockhash lookup returns an owned PTR_TO_SOCKET_OR_NULL, not a userspace map-value fd. Every path must pass it to sock.ref_check exactly once.
**Where it appears**: sock.map_lookup results and sock.ref_check operands; at stage 2 only is_present/assume_present. Call/yield/loop capture is rejected.
**Evidence**: F61. Ownership tests check single consumption on every path; child-netns tests on 7.1.8 match C for NULL and present results.


### SockRefType

_A checked non-NULL owned socket reference with linear release_

Syntax: `!ebpf.sock_ref`

**Meaning**: a checked PTR_TO_SOCKET, passed exactly once to sock.release on every CFG path. It is not converted to kref/PTR_TO_BTF_ID.
**Where it appears**: only sock.ref_check's present-region block argument, used only by sock.release without region escape. At stage 2 it is an assume_present result.
**Evidence**: F61. Tests check one release on all paths and match C in a 7.1.8 child netns. The original ownership tests did not measure runtime on 6.12/6.6.


### StackBuildIdType

_A build-ID stack_trace map value containing depth bpf_stack_build_id entries_

Syntax:

```
!ebpf.stack_build_id<
  int64_t   # depth
>
```

**Meaning**: `!ebpf.stack_build_id<D>` is D >= 1 entries of the 32-byte `struct bpf_stack_build_id { s32 status; u8 build_id[20]; u64 offset | ip }`. Userspace looks up stack.user_id's ID and reads each entry's status: 1 is a valid build ID/file offset, 2 is an IP fallback when the build ID cannot be read, and 0 ends the stack. It is not an in-program value.

**Where it appears**: only the value type of a stack_trace map used by stack.user_id. stack.kernel_id is rejected because kernel stacks would silently fall back to IP status for every entry. The schema needs both value element {"kind":"stack_build_id"} and BPF_F_STACK_BUILD_ID; verification checks D. BTF carries key_size, value_size = 32 * D and map_flags.

**Evidence**: F27. Source/C-oracle and differential stack-build-ID tests cover the format.

#### Parameters:

| Parameter | C++ type | Description |
| :-------: | :-------: | ----------- |
| depth | `int64_t` |  |

### StackType

_A stack_trace map value containing depth u64 instruction pointers_

Syntax:

```
!ebpf.stack<
  int64_t   # depth
>
```

**Meaning**: `!ebpf.stack<D>` is a depth-D (D >= 1) sequence of u64 instruction pointers. Userspace looks it up by stack.kernel_id's ID; it is not an in-program value.

**Where it appears**: only the value type of `!ebpf.map<"stack_trace", i32, !ebpf.stack<D>>`, the map operand of stack.kernel_id. D must match the schema's D-element u64 array. BTF map declarations use key_size/value_size rather than typed definitions.

**Evidence**: F27. Stack introduction/BTF fixtures and three-target tests cover the representation.

#### Parameters:

| Parameter | C++ type | Description |
| :-------: | :-------: | ----------- |
| depth | `int64_t` |  |

### UserBufType

_A typed uprobe user-buffer address_

Syntax: `!ebpf.user_buf`

**Meaning**: a user-memory buffer address, distinct from a raw integer and a NUL-terminated string. It has no parameters.
**Where it appears**: only uprobe.arg and uprobe_multi probe.target_arg results. It matches a schema user_buf parameter, while uprobearg/mtargetarg ptr (minimum format 18) is checked against a depth-one, eight-byte DWARF pointer.
**Constraints**: casts, select, storage, function arguments and returns cannot construct or escape this type. Its only read consumer is ebpf.user.read. Raw identity uses the schema ptr form as i64.
**Evidence**: F78. The type/declaration checks do not themselves establish memory-read behavior; user-read fixtures provide the memory and three-kernel differential checks separately.


### UserStrArrayType

_An array of user character pointers from a typed source, read only by fixed-index user.str_at_

Syntax: `!ebpf.user_str_array`

**Meaning**: user char**, constructed only from a schema user_str_array tp.field/ksyscall.arg. Integers, generic pointers and char* are not substitutes.
**Where it appears**: tp.field/ksyscall.arg results matching that schema kind; only as a user.str_at operand.
**Constraints**: only user.str_at in the same program may use it. Cast/select/store/function argument/return/yield escape is rejected. Loops and dynamic indices are unsupported.
**Evidence**: F74. A depth-two tracefs/BTF strarray type check is required before loading. Three-kernel C differential tests compare values, status and NULL for root tracepoint/ksyscall and non-root ksyscall. Non-root tracepoint loading succeeds, but tracefs ID reading rejects attach, so no runtime values were observed there.


### UserStrType

_A user-string pointer from a typed source, read only by ebpf.user.read_str_

Syntax: `!ebpf.user_str`

**Meaning**: `!ebpf.user_str` is a user-string pointer (const char*) with no parameters, separate from integers so arbitrary integers cannot serve as pointers.

**Where it appears**: uprobe.arg or uprobe_multi probe.target_arg results, used only as user.read_str operands, never integer operands. It pairs with a schema parameter {"kind": "user_str"}. At load time, uprobearg strptr or the per-target mtargetarg strptr is checked against a depth-one pointer to an eight-bit char in the binary's DWARF.

**Evidence**: F25. Typed string/probe fixtures cover strptr checks and three targets.

**Tracepoint**: tp.field may also produce this type when fields[].type is {"kind":"user_str"}. It performs one volatile eight-byte pointer read. tpfield strptr (minimum format 16) checks a depth-one char pointer declaration in tracefs; Unknown blocks loading. Arrays, char**, data_loc and arbitrary integers cannot construct it. The initial declaration extension alone did not test user helpers across three kernels.

**Ksyscall**: ksyscall.arg may produce it when the same-numbered schema parameter is user_str. It obtains 64 bits through the wrapper-to-syscall-pt_regs two-level read. sysarg strptr (minimum format 16) checks the target depth-one char pointer. Casts from ptr/i64 and char** are not allowed.

