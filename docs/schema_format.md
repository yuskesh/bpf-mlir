# Schema JSON format (normative)

- **Purpose**: the normative format of schema JSON, one of bpf-mlir's inputs (`ebpf-compile --schema`). Frontends such as go-bpf-mlir and mojo-bpf-mlir generate schemas; this document defines the reader's contract.
- **Implementation**: `lib/Target/EBPF/Schema.cpp` (`ebpf::Schema::parseJSON`). `lib/Target/EBPF/SchemaKeys.inc` lists permitted keys per object. **The gate compares each object's documented key set against this table in both directions** (`go/internal/schemaspec`). Add keys to the table and document in the same commit.
- **Validation tool**: `build/bin/ebpf-schema-check <schema.json>…` reads schemas without a compilation input.
- **Corpus**: development data in `conformance/schema/` includes positive repository/downstream schemas and negative unknown-key / missing-required-key cases per object. Other implementations can use the same data.

## 1. General rules

- **No silent acceptance**: unknown keys, missing required keys, wrong versions, duplicates, overlaps, non-power-of-two values and unresolved references are errors. **Only `extensions` permits uninterpreted keys and values**, which are preserved.
- Parsing stops at the first error rather than listing every error.
- **JSON reading**: duplicate keys, differently cased unknown keys, invalid UTF-8 and trailing bytes are errors (the latter two checked by llvm::json). **String `\u0000` is accepted**: valid in a note, but later reference checking rejects it in a record symbol. **Unpaired surrogate escapes are accepted after replacement by U+FFFD** and may subsequently fail semantic checks. **There is no nesting-depth limit**: nesting 10,000 levels is syntactically accepted, then rejected for an unknown key. Aligning these rules with requirements JSON is a separate decision. **Schema JSON parsing differs from the stricter requirements-side rules in [§13](requirements_format.md#13-json-reading)**: schemas are compile-time inputs read only by the C++ compiler through llvm::json. Unlike caps / maps / loader declarations, they are not checking inputs shared with a C loader, so this difference does not create two implementations' competing verdicts.
- After parsing, collections (records, maps, programs, …) are sorted by name / id. Input array order has no meaning.
- Required column: `yes` means always required; `no` means optional with the documented default; `conditional:` means the kind determines whether the key is required or forbidden.
- Type objects (`type(...)`) are selected by `kind`; an unknown kind is an error.
- Uniqueness applies to record symbols; nonzero record ids; field names within records / kernel types; kernel-type names; map symbols; program names; global names; maps within programs; slot and parameter indices; clock / value_map / bounds_set ids; values within value_maps; signal names; and attribute keys within signals. A global cannot share a name with a map or program.
- Record layout: every field has a known, nonzero size; int / record_ref offsets satisfy alignment; `offset + size ≤ record size`; fields do not overlap. Record-reference cycles are errors.
- spin_lock / timer: at most one lock and one timer per record, and they cannot coexist. Neither may be an array element. Records containing them cannot be nested in other records. In maps, such a record is allowed only as an array value, not a key or map `record`.

## 2. Version and extensions

- `version` must be `1`, with no compatibility window. Serialization always writes `1`.
- `extensions` is an optional object. Each key is a dotted namespace such as `io.example.foo`; leading/trailing dots and `..` are forbidden. Values are uninterpreted. Serialization sorts object keys.

## 3. Tables by object

### `schema`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `version` | yes | Integer, only `1` (`kSchemaVersion`); `1.0` is also accepted as an integer | — | Format version |
| `coverage` | yes | Object (`coverage`) | — | Scope for which this schema is authoritative |
| `core` | yes | Object (`core`) | — | Core layer |
| `telemetry` | yes | Object (`telemetry`) | — | Telemetry layer |
| `extensions` | no | Object; each key is a dotted namespace, without leading/trailing dots or `..`; values are arbitrary uninterpreted JSON | Absent | Opaque payload under reverse-DNS namespaces |

### `coverage`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `programs` | yes | `"complete"` or `"omitted"` | — | Whether programs are authoritative |
| `maps` | yes | `"complete"` or `"omitted"` | — | Whether maps are authoritative |
| `records` | yes | `"complete"` or `"omitted"` | — | Whether records are authoritative |
| `telemetry` | yes | `"complete"` or `"omitted"` | — | Whether telemetry is authoritative |

### `core`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `records` | yes | Array of `core.records[]` | — | Record (struct) declarations |
| `kernel_types` | no | Array of `core.kernel_types[]` | `[]` | Local CO-RE types |
| `maps` | yes | Array of `core.maps[]` | — | Map declarations |
| `programs` | yes | Array of `core.programs[]` | — | Program declarations |
| `globals` | no | Array of `core.globals[]` | `[]` | Global variables |
| `ksyms` | no | Array of `core.ksyms[]` | `[]` | Per-CPU typed kernel variables |
| `kconfig` | no | Array of `core.kconfig[]` | `[]` | Kernel config options read by the program |

### `core.records[]`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `symbol` | yes | String, unique among records; not `bpf_spin_lock` / `bpf_timer` | — | Record name (BTF struct name) |
| `id` | yes | Integer 0–4294967295 (uint32; larger values are errors); nonzero ids are unique | — | Ring-buffer record identifier (0 means none) |
| `size` | yes | Integer ≥ 0; `size % alignment == 0`, at least `min_size` | — | Size, or upper bound for variable-length records |
| `min_size` | yes | Integer ≥ 0, at most `size` | — | Minimum size; equal to size for fixed-length records |
| `alignment` | yes | Integer fitting uint32, power of two | — | Alignment |
| `required_through` | yes | String: `""` or a field name in this record | — | Fields through this field are always present (`""` means all) |
| `fields` | yes | Array of `core.records[].fields[]`, possibly empty | — | Fields |
| `note` | no | String | `""` | Description |

### `core.records[].fields[]`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `name` | yes | String, unique within the record | — | Field name |
| `type` | yes | Type object: `type(int)` / `type(array)` / `type(record_ref)` / `type(spin_lock)` / `type(timer)` / `type(kptr)` / `type(cpumask)` | — | Field type |
| `offset` | yes | Integer ≥ 0; int / record_ref alignment; `offset + size ≤ record size`; no overlap. spin_lock requires a multiple of 4; timer and kptr require a multiple of 8 | — | Byte offset within the record |
| `expose` | no | String; its value set is not checked | `""` | Presentation to readers (`int` / `str` / …) |
| `note` | no | String | `""` | Description |

### `type(int)`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"int"` | — | Type kind |
| `bits` | yes | Integer 8 / 16 / 32 / 64; values exceeding uint32 are errors | — | Width |
| `signed` | yes | Bool | — | Signedness |
| `endianness` | yes | `"little"` or `"big"` | — | Byte order, not represented in BTF |
| `alignment` | yes | Integer fitting uint32, power of two, at most `bits / 8` | — | Alignment |

### `type(array)`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"array"` | — | Type kind |
| `count` | yes | Integer ≥ 1 | — | Element count |
| `element` | yes | Recursive type object; spin_lock / timer / kptr forbidden | — | Element type |

### `type(record_ref)`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"record_ref"` | — | Type kind |
| `symbol` | yes | String naming a declared record, both in record fields and map key/value types | — | Referenced record |

### `type(spin_lock)`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"spin_lock"`; no other keys | — | `struct bpf_spin_lock` field |

### `type(timer)`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"timer"`; no other keys | — | `struct bpf_timer` field |

### `type(kptr)`

A record-field type for a referenced kptr in a map value. BTF is `PTR → TYPE_TAG "kptr" → STRUCT <struct>`, 8 bytes; the kernel resolves the vmlinux struct by name. **Fields may be reached through record_ref chains of depth at most 3, with each offset a multiple of 8.** Array elements, direct map key/value kptr types, and arrays of records containing kptr are forbidden. A kptr-containing record and its parents are allowed **only as values of hash / percpu_hash / lru_hash / lru_percpu_hash / array / percpu_array / sk_storage / inode_storage / task_storage / cgrp_storage maps**; map keys and ringbuf / perf payloads are forbidden. An ordinary kptr in a per-CPU map differs from the unsupported `percpu_kptr` tag. Access is only through `ebpf.kptr.xchg`; ref.field.load/store, atomic_add and record.make are rejected. Requirements include `btf type_tag` (format 13). This object differs from `{"kind": "kptr", "struct": T}` in kernel_types fields, which describes a local type's pointer field: placement determines meaning despite identical spelling.

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"kptr"` | — | Type kind |
| `struct` | yes | Nonempty string naming a `core.kernel_types` entry | — | Referenced kernel struct with a destructor, e.g. task_struct. Compilation does not check destructor availability; the kernel rejects map creation if it is absent |

### `type(cpumask)`

A record-field type for an embedded `struct bpf_cpumask` of `size` bytes. BTF is a local `struct __ebpf_cpumask_<size> { u8 __opaque[<size>]; }` (record names starting with `__ebpf_cpumask_` are reserved). The bytes are written in place by the cpumask kfuncs: the only access is `ebpf.ref.field.addr`, whose `!ebpf.cpumask_mem<size>` result is a `*bpf_cpumask` / `*cpumask` argument of a non-acquire / non-release kfunc call; ref.field.load/store, atomics, record.make and ref.index of the field are rejected. **The field offset is a multiple of 8, and so is the offset of every enclosing record field; a record holding a cpumask (directly or nested) has alignment 8.** A cpumask cannot be an array element (use an array of records), a map key or value by itself, or part of a map key. A cpumask-holding record is allowed only as the value of array / percpu_array / hash / percpu_hash / lru_hash / lru_percpu_hash maps or as the type of a bss global (rodata is frozen after load); ringbuf / perf payloads are forbidden. Requirements include `kstructsize bpf_cpumask <size>` (format 28 — one row per distinct size): the loader blocks a target whose `sizeof(struct bpf_cpumask)` is larger than `size`, since the kfuncs would overwrite the bytes after the field.

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"cpumask"` | — | Type kind |
| `size` | yes | Positive multiple of 8, at most 1048576 | — (no default) | Bytes reserved for the kernel's struct bpf_cpumask: 16 with CONFIG_NR_CPUS ≤ 64 (the 7.3.1 / 6.12 / 6.6 pins), 1032 with NR_CPUS 8192 (the 7.1.8 host) |

### `core.kernel_types[]`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `name` | yes | Nonempty unique string; `bpf_arena` is reserved (the compiler declares `bpf_arena { user_vm_start: u64 }` for an arena map) | — | Kernel struct name for CO-RE |
| `fields` | yes | Nonempty array of `core.kernel_types[].fields[]` | — | Fields to read |
| `note` | no | String | `""` | Description |

### `core.kernel_types[].fields[]`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `name` | yes | String, unique within the type | — | Kernel field name |
| `type` | yes | `type(int)` of 8 / 16 / 32 / 64 bits, little endian, any signedness/alignment; `{"kind": "kptr", "struct": <kernel_types name>}` for a struct-pointer field traversed by `ebpf.kfield.ptr`; `type(array)` of 1–64 8-bit integers, copied as fixed N bytes by `ebpf.kfield.copy`; or `{"kind": "strptr"}` for char *, an 8-byte pointer to a 1-byte integer read with probe_read_kernel_str by `ebpf.kernel.read_str`, accepting only the kind key; `{"kind": "ptr"}` for void *, an 8-byte untrusted pointer read only by `ebpf.kaddr.read` as `!ebpf.kaddr<"">` (compare / NULL test only — requirements kfield `ptr:void`, format 25), accepting only the kind key; or `type(enum)` for a kernel ENUM field | — | Field type. No offset is specified: CO-RE resolves it. Local placeholder offsets use natural alignment in declaration order; pointers align to 8 |
| `note` | no | String | `""` | Description |

### `core.kernel_types[].fields[].type(struct)`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"struct"` | — | Embedded local kernel type by value, not a pointer |
| `struct` | yes | Declared kernel_types name | — | Forward references and sharing allowed. Value cycles and layout overflow rejected. Child types determine local offset/size/alignment naturally; CO-RE resolves actual offsets |

### `core.kernel_types[].fields[].type(enum)`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"enum"` | — | A kernel ENUM field. The local CO-RE type is an anonymous enum without enumerators (cilium matches it with any target enum), so an int local type would make the relocation impossible |
| `bits` | yes | 8 / 16 / 32 / 64 | — | Field width. `ebpf.kfield.load` reads it as iN of this width; `ebpf.scx.exit_info` reads `scx_exit_info.kind` as one (no other op takes it). The contract is the width only, not the sign; requirements kfield `enum:<bits>` (format 22) checks a target ENUM (ENUM or ENUM64 for 64) of bits/8 bytes that is not a bitfield |

This type is allowed only in kernel_types fields. The four field-reading forms accept paths of at most three components, `a.b.c`: intermediate components are embedded structs, the final component has an existing leaf type. Multilevel stores into kernel memory are rejected.

### `core.maps[]`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `symbol` | yes | String, unique among maps | — | Map name (ELF symbol) |
| `kind` | yes | `hash` / `array` / `ringbuf` / `percpu_array` / `percpu_hash` / `lru_hash` / `lru_percpu_hash` / `devmap` / `lpm_trie` / `prog_array` / `stack_trace` / `perf_event_array` / `sockmap` / `sockhash` (sk_skb / sk_msg attach targets; in-program operations rejected) / `reuseport_sockarray` / `struct_ops` (operation table in `.struct_ops.link`, not accessed by programs) / `sk_storage` / `task_storage` / `inode_storage` / `cgrp_storage` (local storage: only `ebpf.storage.get` / `delete`) / `array_of_maps` / `hash_of_maps` (map-in-map: `inner` required, only lookup → `ebpf.map.inner`) / `user_ringbuf` (userspace-to-kernel ring: only `ebpf.user_ringbuf.drain`) / `queue` / `stack` / `bloom_filter` (keyless maps: only `ebpf.map.push` / `pop` / `peek`, `ebpf.bloom.peek`) / `cpumap` / `xskmap` / `devmap_hash` (`ebpf.redirect_map` targets; other in-program operations rejected) / `cgroup_array` (dedicated task / skb cgroup-ancestry helpers only; userspace supplies cgroup fds) / `arena` (shared memory of `max_entries` pages at the user address `map_extra`, no key / value; the handle is `!ebpf.map<"arena", none, none>` and ordinary `ebpf.map.*` operations are rejected; at most one arena per schema). Deprecated kernel `cgroup_storage` / `percpu_cgroup_storage` and `*_deprecated` aliases are rejected by name, suggesting `cgrp_storage` (`RejectedMapKinds.def`) | — | Map kind |
| `key` | conditional: forbidden for ringbuf, user_ringbuf, queue / stack / bloom_filter (kernel key_size 0) and arena; required otherwise | Type object. devmap / prog_array / perf_event_array / stack_trace / sockmap / reuseport_sockarray / struct_ops / cpumap (CPU) / xskmap (rx queue) / devmap_hash / cgroup_array (index) require u32; sockhash requires an integer, not a record; lpm_trie requires the 8-byte record `{prefixlen u32 @0, addr u8[4] @4}`; local storage requires a 32-bit integer (userspace owner fd); array_of_maps requires u32, hash_of_maps an integer. spin_lock / timer and records containing them are forbidden | Absent for ringbuf | Key type |
| `value` | conditional: forbidden for ringbuf, user_ringbuf, struct_ops (whose value is its operation table) and arena; required otherwise | Type object. devmap / prog_array / perf_event_array require u32; cpumap (qsize), xskmap (AF_XDP socket fd), devmap_hash (ifindex), cgroup_array (cgroup fd) require u32; stack_trace requires an array of u64 or `type(stack_build_id)`; lpm_trie requires int; sockmap / sockhash / reuseport_sockarray require u32 or u64 (socket fd supplied by userspace); local storage requires integer or record; array_of_maps / hash_of_maps require u32 (inner map fd); queue / stack / bloom_filter require 8 / 16 / 32 / 64 bit integers, not records. Records containing lock / timer are allowed only in array maps. Records containing kptr, including enclosing parents, are allowed only in the ten hash / array / per-CPU / LRU / local-storage kinds listed above | Absent for ringbuf | Value type |
| `max_entries` | yes | Integer ≥ 0. perf_event_array and local storage require 0; struct_ops requires 1; others require > 0. ringbuf / user_ringbuf require a power of two (bytes); devmap_hash permits at most 2^31. arena counts 4096-byte pages and requires 1 to 1048576 (pages × 4096 ≤ 4 GiB). cpumap emits the declared value into ELF, but **max_entries above the possible-CPU count has no useful meaning; loaders may reduce it (cilium v0.22 reduces it to possible CPUs; requirements_format.md §8)**. **Compilation rejects values above 1073741823** (btf-verify K9: the map-definition BTF array would exceed U32_MAX bytes and the kernel rejects BTF; this also excludes a 2^30-byte ringbuf) | — | Entry count |
| `flags` | yes | Integer ≥ 0. lpm_trie requires bit 0 (NO_PREALLOC). prog_array / perf_event_array / sockmap / sockhash / reuseport_sockarray / cgroup_array / struct_ops require 0 (the loader derives struct_ops BPF_F_LINK from the section). stack_trace requires 0 for u64 values, BPF_F_STACK_BUILD_ID (32, UAPI `mapflag`) for stack_build_id; either one alone is rejected. Local storage requires exactly BPF_F_NO_PREALLOC (1, UAPI `mapflag no_prealloc`). array_of_maps / hash_of_maps / cpumap / xskmap / devmap_hash require 0. queue / stack require 0; bloom_filter allows 0 or BPF_F_ZERO_SEED (64, UAPI `mapflag zero_seed`). arena requires BPF_F_MMAPABLE (1024, UAPI `mapflag mmapable`), optionally combined with BPF_F_SEGV_ON_FAULT (`mapflag segv_on_fault`): window access then requires its own live arena.alloc success proof. BPF_F_NO_USER_CONV (`mapflag no_user_conv`) and other flags remain rejected | — | map_flags |
| `record` | conditional: nonempty and required for ringbuf, user_ringbuf (userspace-written sample identity), perf_event_array; must be empty for reuseport_sockarray, struct_ops, local storage, map-in-map, queue / stack / bloom_filter, cpumap / xskmap / devmap_hash, cgroup_array, arena; optional otherwise | String; if nonempty, a declared record without lock / timer | `""` | Transported payload record |
| `note` | no | String | `""` | Description |
| `slots` | conditional: optional only for prog_array, forbidden otherwise | Array of `core.maps[].slots[]` | `[]` | Tail-call slots |
| `struct_ops` | conditional: required for struct_ops, forbidden otherwise | `core.maps[].struct_ops` | — | Local `.struct_ops.link` operation table; at most one struct_ops map per type in a schema |
| `inner` | conditional: required for array_of_maps / hash_of_maps, forbidden otherwise | String naming another core.maps symbol in the same schema. Inner template kind must be hash / array / percpu_array / percpu_hash / lru_hash / lru_percpu_hash; not map-in-map; no lock / timer; absent from every program's `maps` | — | Inner-map type, represented by BTF `values` template rather than an ELF `.maps` map |
| `map_extra` | conditional: required for arena, forbidden otherwise | JSON unsigned integer < 2^64, read exactly (no decimal, no rounding). Checked in order: `map_extra mod 4096 = 0`; `map_extra + pages × 4096` fits in u64 (no overflow); `map_extra >> 32 = (map_extra + pages × 4096 − 1) >> 32` (no 4 GiB boundary crossing); `map_extra & 0xffffffff ≥ 4096` (the first page does not overlap a program NULL). Each failure names its check | — | Arena user address (BPF_MAP_CREATE `map_extra`); BTF carries it as a one-enumerator anonymous ENUM64 member `map_extra` (libbpf `__ulong`) |

`insn_array` is not accepted as a user-declared map. libbpf creates this program-specific map from ELF `.jumptables`; there is no replacement by an ordinary array. Schema and map / storage operations explicitly reject this loader-generated kind (`RejectedMapKinds.def` reason / optional replacement). This does not change the set of accepted kinds.

### `core.maps[].slots[]`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `index` | yes | Unique integer ≥ 0 and less than `max_entries` | — | Slot index |
| `program` | yes | Nonempty string; emission checks program existence | — | Program placed in the slot |

### `core.maps[].struct_ops`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `type` | yes | Type in `include/bpf-mlir/Support/StructOpsTypes.def`: tcp_congestion_ops / bpf_dummy_ops / sched_ext_ops. Unlisted types such as hid_bpf_ops are rejected by name | — | Kernel struct name; the loader finds `bpf_struct_ops_<type>` in kernel BTF and copies members by name |
| `name` | conditional: required when the type has a DATA `name` row (tcp_congestion_ops / sched_ext_ops), forbidden otherwise | 1–BYTES−1 alphanumeric / `_` / `.` characters: tcp allows 15 of 16 bytes; sched_ext allows 127 of SCX_OPS_NAME_LEN 128 bytes (`bpf_obj_name_cpy`) | — | Struct name field. Registered tcp names are selectable by sockets across the host; sched_ext registration has only been demonstrated in a VM |
| `ops` | yes | Nonempty array of `core.maps[].struct_ops.ops[]`; no duplicate members or programs | — | Function-pointer members and implementing programs |
| `dispatch_max_batch` | conditional: optional for sched_ext_ops, forbidden otherwise | JSON unsigned integer ≤ 2147483647 (INT_MAX — `bpf_scx_init_member` returns -E2BIG above it) | absent (the kernel's 0) | u32 data member |
| `flags` | conditional: optional for sched_ext_ops, forbidden otherwise | JSON unsigned integer < 2^64 with bits 56–63 clear (`__SCX_OPS_INTERNAL_MASK`, outside `SCX_OPS_ALL_FLAGS` on every kernel). The accepted lower bits differ by kernel (6.12.111 / 7.1.8 / 7.3.1) and are not checked at compile time — the kernel rejects others with EINVAL at registration | absent (0) | u64 data member; for example `SCX_OPS_SWITCH_PARTIAL` (8) |
| `timeout_ms` | conditional: optional for sched_ext_ops, forbidden otherwise | JSON unsigned integer ≤ 30000 (`SCX_WATCHDOG_MAX_TIMEOUT` is 30 × HZ jiffies and ms are rounded up, so 30000 is the bound for HZ 250 and 1000) | absent (0 — the kernel's 30 s watchdog) | u32 watchdog timeout |
| `exit_dump_len` | conditional: optional for sched_ext_ops, forbidden otherwise | JSON unsigned integer ≤ 4294967295 | absent (0 — the kernel uses 32768) | u32 data member |
| `hotplug_seq` | conditional: optional for sched_ext_ops, forbidden otherwise | JSON unsigned integer < 2^64 | absent (0) | u64 data member |
| `sub_cgroup_id` | conditional: optional for sched_ext_ops, forbidden otherwise | JSON unsigned integer < 2^64. 6.12.111 has no such member; cilium then rejects a non-zero value by name | absent (0) | u64 data member (7.1.8 / 7.3.1 with CONFIG_EXT_SUB_SCHED) |

The integer keys accept only JSON integers: strings, negative numbers, decimals (including `3000.0`) and values beyond the member width are rejected by name. They are emitted into the local BTF and `.struct_ops.link` only when present; a type without such a DATA row (tcp_congestion_ops / bpf_dummy_ops) rejects them. `priv` is not writable (the kernel rejects non-zero non-function members) and is rejected by name. Members only in 7.3.1 (`cid_shard_size` and others) and the 7.3.1 type `sched_ext_ops_cid` are not in the 7.1.8-based table and are rejected as unknown keys / types.

sched_ext_ops support covers callback compilation and the integer data members above. scx dispatch kfuncs are not provided. The 6.12.111 VM demonstration explicitly combined a compiler-produced tick with a C enqueue / timeout_ms 3000 donor inside an experimental runner, excluding the compiler's ops map from the load set. maps.json struct_ops checks compare names and function-pointer members only; integer data is not part of that spelling.

### `core.maps[].struct_ops.ops[]`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `member` | yes | Member of an fptr row in the UAPI structopsmember table, based on 7.1.8 vmlinux BTF. Misspellings and data members are rejected at compile time | — | Struct function-pointer member name; load-time structop checking compares against the target kernel type |
| `program` | yes | Nonempty string naming a struct_ops program in the same schema whose attach_target is this map | — | Implementing program |

### `core.programs[]`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `name` | yes | String, unique among programs | — | Program name |
| `kind` | yes | `xdp` / `tp_btf` / `fentry` / `fexit` / `kprobe` / `uprobe` / `sched_cls` / `raw_tp` / `kretprobe` / `uretprobe` / `iter` / `syscall` / `fmod_ret` / `lsm` / `sk_skb` / `sk_msg` / `tracepoint` / `perf_event` / `raw_tp_writable` / `ext` / `lirc_mode2` / `struct_ops` / `kprobe_multi` / `kretprobe_multi` / `uprobe_multi` / `uretprobe_multi` / `usdt` / `lsm_s` / `lsm_cgroup` / `ksyscall` / `kprobe_session` / `fsession` | — | Program kind |
| `attach_target` | yes | String. Nonempty for tp_btf / fentry / fexit / kprobe / uprobe / raw_tp / kretprobe / uretprobe / iter / fmod_ret / lsm / lsm_s / lsm_cgroup (LSM hook names), ksyscall (syscall name: C identifier without an architecture prefix, not beginning `sys_` / `__`), kprobe_session / fsession (one kernel function), raw_tp_writable. tracepoint uses tracefs `<category>/<event>` with exactly one `/`. sk_skb / sk_msg use a core.maps sockmap / sockhash symbol (sk_skb stream_parser uses `stream_parser:<symbol>`). sk_reuseport uses `""` (select) or `migrate`. ext uses a nonempty global function name in the BPF program to replace. struct_ops names a core.maps struct_ops map whose ops include this program; do not put that map in `maps`. sched_cls uses `ingress` / `egress`; xdp / syscall / perf_event accept any string including empty. **The four multi-probe kinds instead use a nonempty JSON string array of nonempty, unique names without glob characters `*` `?` `[`, in the same order as program `attach [...]`; index i is requirements mtarget index i.** **usdt uses `<provider>:<name>`, both C identifiers, with the same spelling in program `attach` and requirements usdt target** | — | Tracepoint / kernel function / user symbol / tcx direction / iterator target |
| `maps` | yes | Array of declared map names, unique, possibly empty | — | Maps bound positionally to `ebpf.program` maps |
| `args` | conditional: required nonempty for tp_btf; optional nonempty for fentry (struct names, nullable objects, integers, null; fentry kptr is always nullable), fmod_ret (integers / null only), lsm / lsm_s / lsm_cgroup (mixed struct / nullable / integer / null; struct ctx.arg yields only `!ebpf.kptr_or_null`; lsm / lsm_s emit trace_lsm and farg; lsm_cgroup emits trace_lsm_cgroup and farg, format 13); ext requires it when nargs > 0, length exactly nargs, integers only, no null, with widths carried by BTF FUNC_PROTO; struct_ops optionally uses the lsm value domain and length ≤ nargs, with verifier-visible struct types (tcp_congestion_ops sock uses tcp_sock), and additionally accepts enum entries (other kinds reject them by name). Forbidden for other kinds, even an empty array | Array of strings naming core.kernel_types; `{"kind": "struct", "name": <kernel_types name>, "nullable": bool}` for nullable struct pointers read through `!ebpf.kptr_or_null` / `ebpf.kptr.check` (false / absent nullable equals the string form); `type(int)` with bits 8 / 16 / 32 / 64, little endian and natural alignment; or `null` for unread arguments; struct_ops only: `{"kind": "enum", "bits": 8 / 16 / 32 / 64}` for a BTF ENUM / ENUM64 argument of that size (no other key — the contract is the width only, the sign is not checked; ctx.arg reads it as iN; requirements farg `enum:<bits>`, format 19) | `[]` | Positional tp_btf arguments. Integer / null entries allow reading later arguments after non-struct arguments, such as sched_switch bool preempt. Do not use `i8`…`u64`, `-` or `enum:8`…`enum:64` as kernel_types names (reserved) |
| `nargs` | conditional: required for fmod_ret, ext (replacement function, 0–5), struct_ops (member argument count); optional for fexit (with it the return value is `ctx.retval after nargs` and requirements carry retsig; without it only `ctx.func_ret` (bpf_get_func_ret) reads the return value and requirements carry funcret); forbidden for others, including null | Integer 0–12, restricted to 0–5 for ext | — | Target argument count |
| `ret` | conditional: required for fexit, fmod_ret, ext (32 / 64 bit, matching ebpf.return width), struct_ops (member return type, `"void"` for void members; ebpf.return is i32, or i64 for a 64-bit ret such as size_t get_info); forbidden otherwise | `type(int)` or `"void"` (struct_ops only) | — | Target return type |
| `arch` | conditional: required for kprobe / uprobe / kretprobe / uretprobe / perf_event, all four multi-probe kinds, usdt, ksyscall; forbidden otherwise | `"x86_64"` | — | pt_regs calling convention / return register; perf_event assumes fixed bpf_perf_event_data offsets and regs size. ksyscall uses wrapper-name prefix / pt_regs, with params describing syscall arguments |
| `params` | conditional: optional for kprobe / uprobe, kprobe_multi / uprobe_multi (same for every function), usdt (n 1–12, type(int) only, same at every point, checked against note `<±size>@` through usdtarg), ksyscall (n 1–6; type(int), ptr, user_str; ksyscall.arg reads them and sysarg checks tracefs sys_enter_<name> format; empty params omitted from canonical serialization). Forbidden for other kinds including kretprobe / uretprobe and perf_event | Array of `core.programs[].params[]` | `[]` | Declared argument types |
| `target_params` | conditional: optional for kprobe_multi / uprobe_multi, mutually exclusive with params, length equal to attach_target, item i describes target i using params form; forbidden otherwise | Array of arrays of `core.programs[].params[]` | `[]` | Per-target declarations read by `ebpf.probe.target_arg`. Requirements mtargetarg `<p> <i> <n> <type>` follows mtarget, checks function i, format 13; the initial implementation lacked this row and could not emit ELF |
| `binary_sha256` | conditional: required for uprobe / uretprobe, uprobe_multi / uretprobe_multi and usdt (binary containing notes); forbidden otherwise | 64 lowercase hexadecimal characters | — | User binary SHA-256 |
| `semaphore` | conditional: required for usdt, forbidden otherwise | `"required"` / `"none"` | — | Semaphore declaration checked by usdtsem against every note point and combined with loader usdt_attach (requirements_format.md §8) |
| `max_points` | conditional: required for usdt, forbidden otherwise | Integer 1–65536 | — | max_entries of compiler-generated USDT spec map `__ebpf_usdt_spec_<program>`; excess note points block through usdt_probe. Compiler-generated spec map and `ebpf_usdt_spec` record are omitted from canonical schema. core.maps prefix `__ebpf_usdt_spec_` and record name `ebpf_usdt_spec` are reserved |
| `sleepable` | conditional: optional for struct_ops and fentry, forbidden otherwise | Boolean | `false` | Sleepable program: section `struct_ops.s` (the loader sets BPF_F_SLEEPABLE). **fentry**: section `fentry.s/<function>`; the program op must carry the `sleepable` keyword exactly when the schema sets this (ebpf-verify-schema rejects a mismatch either way); the matching requirements row is `sleepable <prog>` (requirements_format.md). Only members in the compiler's table `ScxContract.def`, keyed by (ops type, member), accept it — sched_ext_ops init_task / cpu_online / cpu_offline / init / exit / sub_attach / sub_detach; another ops type's member of the same name (tcp_congestion_ops init) is rejected. `ebpf.scx.create_dsq` (KF_SLEEPABLE) requires it. `false` is omitted from canonical serialization |
| `fields` | conditional: optional nonempty for tracepoint, forbidden otherwise | Array of `core.programs[].fields[]`, without duplicate names or overlapping offsets | — | Event-field declarations. ebpf.tp.field offset/width must match; tpfield rows sorted by offset are checked against target tracefs format before load |
| `note` | no | String | `""` | Description |

### `core.programs[].fields[]`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `name` | yes | C identifier, unique among fields | — | tracefs format field name |
| `offset` | yes | Integer ≥ 8; scalar offset is a multiple of type width, array alignment is 1; offset + width (N for arrays) ≤ 8192; unique among fields | — | Byte offset from record start; the first 8 bytes cannot be read by BPF |
| `type` | yes | `type(int)` of 8 / 16 / 32 / 64 bits, little endian, naturally aligned; `core.programs[].fields[].type(user_str)` / `type(user_str_array)` / `type(array)` | — | Integer, char pointer, pointer to char-pointer array, or fixed byte array |

### `core.programs[].fields[].type(array)`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"array"` | — | Inline fixed byte array in a tracepoint; forbidden in the special syscalls BPF context |
| `elem` | yes | `"u8"` / `"i8"` | — | Byte signedness, checked against tracefs element type and Signed |
| `n` | yes | Integer 1..64 | — | Element count / total bytes. tp.field.copy destination must be a one-dimensional 8-bit array of the same N. tpfield `[N]u8/i8` requires format 17 |

### `core.programs[].fields[].type(user_str)`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"user_str"`; no other keys | — | User char pointer, matching tp.field user_str result, size/alignment 8. Format-16 tpfield strptr checks tracefs type. char**, data_loc, arrays and integers are different types. Unknown blocks load |

### `core.programs[].params[]`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `n` | yes | Unique integer ≥ 1 | — | One-based argument index |
| `type` | yes | `type(int)`; user_str for uprobe / uprobe_multi / ksyscall; user_buf for uprobe / uprobe_multi; user_str_array for ksyscall only; ptr for kprobe / kprobe_multi / uprobe / uprobe_multi / ksyscall. These use the corresponding `core.programs[].params[].type(...)` objects. usdt permits only type(int) | — | Argument type. ksyscall user_str / array must match ksyscall.arg of the same index; format-16 sysarg strptr / strarray checks char-pointer depth 1 / 2 |

### `type(stack_build_id)`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"stack_build_id"`; no other keys | — | Stack-trace build-id element (`struct bpf_stack_build_id`, 32 bytes, UAPI table). **Allowed only as an array element of stack_trace map values**, requiring BPF_F_STACK_BUILD_ID (32) flags; either type or flag alone is rejected. Forbidden as a record field or other map key/value |

### `core.programs[].params[].type(user_str)`

Also allowed in ksyscall params, n 1–6, whose corresponding ksyscall.arg must return user_str. Two-stage register access through the syscall wrapper obtains the pointer value; only a separate user.read_str reads user memory. ptr / i64 declarations are not substitutes even though they are also 64 bits wide.

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"user_str"`; no other keys | — | User-string pointer |

### `core.programs[].params[].type(ptr)`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"ptr"`; no other keys | — | kprobe / ksyscall / uprobe pointer argument. arg reads only a raw i64 value without dereferencing. uprobe / uprobe_multi ptr requires format 18 and checks a depth-1, 8-byte DWARF pointer. Existing kprobe / ksyscall rules are unchanged |

### `core.programs[].params[].type(user_buf)`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"user_buf"`; no other keys | — | uprobe / uprobe_multi buffer address. Result is only user_buf, not interchangeable with integers / strings / casts. Format-18 ptr requirements check DWARF pointer depth 1 and size 8. Only ebpf.user.read consumes it for reading |

### `core.programs[].params[].type(user_str_array)`

ksyscall only, indices 1–6, not interchangeable with user_str / ptr / integer. Twenty elements is not a schema attribute: it is the compiler's user.str_at index limit.

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"user_str_array"`; no other keys | — | ksyscall char** argument, used only by user.str_at. sysarg strarray requires format 16 |

### `core.programs[].fields[].type(user_str_array)`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"user_str_array"`; no other keys | — | Tracepoint char** field, size/alignment 8; tpfield strarray requires format 16 |

### `core.globals[]`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `name` | yes | Unique string, C identifier; cannot share a map/program name, equal `_license`, or begin `__ebpf` | — | Global ELF symbol |
| `section` | yes | `"rodata"`, `"bss"`, `"data"` or `"data:<name>"` (`<name>` of letters, digits and `_`) | — | ELF section. `data` globals are records, written only by `ebpf.scx.exit_info`. `data:<name>` is the dedicated section `.data.<name>` of kptr globals (the scx `private(name)` form): hidden 8-byte symbols, read and written only by `ebpf.global.kptr_xchg` / `ebpf.global.kptr_load_rcu`; the ELF carries the requirements row `datakptr .data.<name>` (the loader must not mmap the section — `docs/requirements_format.md` §3 / §8 `hidden_data_vars`) |
| `type` | conditional: required for data:<name> and for rodata / bss integer globals; forbidden for data and for rodata / bss record globals (exactly one of `type` and `record` in rodata / bss) | rodata / bss: `type(int)`, any width / endianness; bss only: `core.globals[].type(kaddr)`; data:<name>: `type(kptr)` to `bpf_cpumask` (declared in `core.kernel_types`) | — | Integer type, the kaddr type of a bss global, or the kptr type of a data:<name> global. A kptr type in rodata / bss / data, an integer in data:<name>, a kptr to another struct and a kaddr in rodata are errors |
| `record` | conditional: required for data, forbidden for data:<name>; in rodata / bss instead of `type` | Name of a `core.records[]` symbol. data: without a kptr field (at any depth); rodata / bss: without kptr, spin_lock, timer or stack_build_id fields at any depth, through nested records and arrays | — | Record type of the global, zero-initialized; BTF is a VAR of the record struct in the section's DATASEC. A data record is written only by `ebpf.scx.exit_info`; a rodata / bss record is borrowed with `ebpf.global.ref` and read / written with the ref ops — a rodata borrow is read-only |
| `note` | no | String | `""` | Description |

### `core.globals[].type(kaddr)`

a bss global caching an untrusted kernel address — C's `static struct S *g` (BTF VAR → PTR → STRUCT, no type tag; the verifier treats the loaded value as a scalar). Read with `ebpf.global.load @g : !ebpf.kaddr<"S">` and written with `ebpf.global.store`; the value is only compared (`ebpf.kaddr.eq`) or read through (`ebpf.kaddr.read`), never dereferenced.

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"kaddr"` | — | The global holds an 8-byte kernel address |
| `struct` | yes | Name of a `core.kernel_types[]` struct | — | The struct the address points to (BTF PTR → the local struct, as in clang's output). A void address is an error |

### `core.ksyms[]`

a per-CPU typed kernel variable — C's `extern T name __ksym [__weak]` — read through `bpf_per_cpu_ptr` (`ebpf.ksym.per_cpu_load`). The ELF holds an undefined symbol in `.ksyms` with a BTF VAR, and the requirements row `ksymvar` (`docs/requirements_format.md` §3).

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `name` | yes | Unique string, C identifier; cannot share a map/program/global/kconfig name, equal `_license`, or begin `__ebpf` | — | Kernel variable name (target BTF VAR) |
| `per_cpu` | yes | `true` only | — | A per-CPU variable. Plain typed variables are errors (their direct load has another verifier contract, and cilium's kallsyms address would load from a number) |
| `slot` | yes | `type(int)` (little endian, i8..u64), or `core.ksyms[].slot(ptr)` | — | What each CPU's copy holds. A pointer slot is read as an untrusted `!ebpf.kaddr<"S">` (the verifier makes it a scalar). Struct slots and pointers to pointers are errors |
| `weak` | no | Boolean | `false` | `__weak`: the variable may be absent; every read must be under `ebpf.ksym.exists` (the requirements row is guarded) |
| `note` | no | String | `""` | Description |

### `core.ksyms[].slot(ptr)`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"ptr"` | — | The slot is a pointer to a struct (one level) |
| `struct` | yes | Name of a `core.kernel_types[]` struct | — | The pointee, matched as `ptr:<struct>` against the target BTF |

### `core.kconfig[]`

a kernel config option — C's `extern T CONFIG_X __kconfig [__weak]` — read by `ebpf.kconfig.load`. The loader fills the value from the target's kconfig file at load time; the compiler never knows it.

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `name` | yes | Unique string `CONFIG_<letters, digits, _>`; cannot share another ELF symbol's name | — | Option name. libbpf's virtual `LINUX_*` values are errors (loader-made, and a program comparing them would replace requirements) |
| `type` | yes | `"bool"`, `"tristate"`, `"char"` or `"i16"`..`"u64"` | — | Value type (tristate is libbpf's `enum libbpf_tristate`, 4 bytes). `"i8"` / `"u8"` are errors: libbpf treats every one-byte integer as char (it accepts y / n / m), so write `"char"`. String options are errors |
| `weak` | no | Boolean | `false` | `__weak`: an absent option reads 0 (loader-dependent — `docs/requirements_format.md` §8 `kconfig`) |
| `note` | no | String | `""` | Description |

### `telemetry`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `signals` | yes | Array of `telemetry.signals[]` | — | OTel signals |
| `clocks` | yes | Array of `telemetry.clocks[]` | — | Clock definitions |
| `value_maps` | yes | Array of `telemetry.value_maps[]` | — | Value-to-name tables |
| `bounds_sets` | yes | Array of `telemetry.bounds_sets[]` | — | Histogram boundary sets |

### `telemetry.clocks[]`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `id` | yes | Unique string | — | Clock id |
| `kernel_source` | yes | String | — | E.g. `bpf_ktime_get_ns()` |
| `posix_clock` | yes | String | — | E.g. `CLOCK_MONOTONIC` |
| `to_wall` | yes | String | — | Conversion to wall time |
| `note` | no | String | `""` | Description |

### `telemetry.value_maps[]`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `id` | yes | Unique string | — | Table id |
| `unknown` | no | String | `""` | Spelling for an unlisted value, e.g. `unnamed(%ld)` |
| `arch_invariant` | no | Bool | `false` | Whether values are architecture-independent |
| `btf_mode` | no | String; nonempty requires btf_anchor | `""` | BTF checking mode, e.g. `names` |
| `btf_anchor` | conditional: required if btf_mode is nonempty | String | `""` | Anchor enumerator for BTF checking |
| `btf_prefix` | no | String | `""` | Namespace prefix to remove |
| `btf_omit` | no | String | `""` | Enumerators excluded from checking |
| `authority` | no | String | `""` | Value provenance |
| `note` | no | String | `""` | Description |
| `entries` | yes | Possibly empty array of `telemetry.value_maps[].entries[]` | — | Value-to-name mapping |

### `telemetry.value_maps[].entries[]`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `value` | yes | Integer, possibly negative, unique within the table | — | Value |
| `name` | yes | String | — | Name |

### `telemetry.bounds_sets[]`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `id` | yes | Unique string | — | Boundary-set id |
| `bounds` | yes | Nonempty, strictly increasing numeric array | — | Histogram boundaries |
| `unit` | yes | String | — | Unit |
| `authority` | no | String | `""` | Provenance |
| `note` | no | String | `""` | Description |

### `telemetry.signals[]`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `name` | yes | Unique string | — | Signal name |
| `signal` | yes | `"traces"` / `"metrics"` / `"logs"` | — | Signal kind |
| `record` | yes | String naming core.records | — | Source record |
| `span_name` | conditional: required nonempty for traces, must be empty for logs / metrics | String | `""` | Span-name template |
| `span_kind` | conditional: required nonempty for traces, must be empty for logs / metrics | String | `""` | Span kind, e.g. INTERNAL / CLIENT |
| `timing` | yes | `telemetry.signals[].timing` | — | start / clock / end |
| `drop_when` | yes | `predicate` | — | Condition for omitting a signal |
| `attributes` | yes | Possibly empty array of `telemetry.signals[].attributes[]` | — | Attributes |
| `body` | conditional: required for logs, forbidden for metrics / traces | `source` | — | LogRecord body |
| `value` | conditional: required for metrics, forbidden for logs / traces | `source`; if kind is constant, name is an integer string | — | Metric observation |
| `metric` | conditional: required for metrics, forbidden otherwise; if present, must be an object | `telemetry.signals[].metric` | — | Metric description |
| `note` | no | String | `""` | Description |

### `telemetry.signals[].timing`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `start` | yes | Free-form string | — | E.g. `record_ktime:hdr.timestamp` |
| `clock` | yes | String: empty or a telemetry.clocks id | — | Clock |
| `end` | yes | Free-form string | — | E.g. `start_plus:duration_ns` |

### `telemetry.signals[].metric`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"sum"` or `"exponential_histogram"` | — | Metric kind |
| `unit` | yes | String, UCUM, not validated | — | Unit |
| `temporality` | yes | `"delta"` or `"cumulative"` | — | Temporality |
| `monotonic` | conditional: required for sum, forbidden for exponential_histogram | Bool | — | Whether sum is monotonic |
| `scale` | conditional: required for exponential_histogram, forbidden for sum | Integer | — | Scale |
| `zero_threshold` | conditional: required for exponential_histogram, forbidden for sum | Number ≥ 0 | — | Zero-bucket threshold |
| `bucket_rule` | conditional: required for exponential_histogram, forbidden for sum | `"otlp_lower_exclusive"` | — | Value-to-bucket rule |

### `telemetry.signals[].attributes[]`

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `key` | yes | String, unique within the signal | — | semconv key |
| `stability` | yes | String | — | `semconv` / `spinel` / … |
| `source` | yes | `source` | — | Value source |
| `presence` | yes | `predicate` | — | Attribute-presence condition |
| `note` | no | String | `""` | Description |

### `predicate`

Used in `telemetry.signals[].drop_when`, `attributes[].presence`, and predicate `args[]`.

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `op` | yes | `always` / `never` / `empty` / `nonempty` / `zero` / `nonzero` / `byte_eq` / `any` / `all` / `not` / `unexpressible` | — | Operator |
| `operand` | conditional: required for empty / nonempty / zero / nonzero / byte_eq, forbidden otherwise | `predicate.operand`; must be an object if present | — | Operand |
| `index` | conditional: nonzero allowed only for byte_eq | Integer ≥ 0; must be integer if present | `0` | byte_eq byte index |
| `bytes` | conditional: required nonempty for byte_eq, must be empty otherwise | Array of integers 0–255; must be array if present | `[]` | byte_eq bytes |
| `args` | conditional: required for any / all / not (exactly one for not), forbidden otherwise | Array of predicate; must be array if present | `[]` | Subpredicates |
| `detail` | conditional: required nonempty for unexpressible, must be empty otherwise | String | `""` | Description of the unexpressible condition |

### `predicate.operand`

Used in predicate `operand`.

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"field"` / `"derived"` / `"constant"` | — | Operand kind |
| `name` | yes | String, not resolved against a record | — | Operand name |

### `source`

Used in `attributes[].source`, `signals[].body`, `signals[].value`.

| Key | Required | Value | Default | Meaning |
|---|---|---|---|---|
| `kind` | yes | `"field"` / `"derived"` / `"constant"` / `"runtime_extension"` | — | Source kind |
| `name` | yes | String; for field, a dot-separated path through record_ref within the signal's record | — | Field / derived / constant name |
| `from` | no | String; if nonempty for derived, a field path within the record | `""` | Original field |
| `detail` | conditional: required nonempty for runtime_extension, optional otherwise | String | `""` | Description of the unexpressible content |

## 4. Previously silently accepted forms now rejected

Parser inspection found seven forms that were silently accepted. All now produce errors; 135 repository and downstream-generated inputs remained accepted because none used these forms. Frontend compatibility changes:

1. Wrong types for optional string keys (`note`, `expose`, maps[].record, span_name / span_kind, source.from / detail, predicate.detail, value_maps string keys, bounds_sets authority) previously silently became `""`. Non-bool arch_invariant previously became false.
2. Non-object telemetry.signals[].metric previously disappeared silently for traces / logs.
3. Wrong types for predicate operand / index / bytes / args were previously ignored when unused by that operator.
4. Undeclared record_ref names in map key/value types, including array elements, were previously checked only within record fields.
5. **Duplicate keys within the same JSON object**: llvm::json silently retains the later value. A pre-parse scan rejects duplicates, comparing decoded key strings after unescaping.
6. Values exceeding uint32 in int bits / alignment and record id / alignment were previously truncated before checking: `bits: 4294967360` was accepted as 64.
7. args on programs other than tp_btf, even empty arrays, were previously rejected only when nonempty. Later supported kinds have the explicit permissions listed in §3.

Development corpus `conformance/schema/cases/silent*` (15), `cond_*` (12 conditional-required cases) and `range_*` (18 range cases) contains negative controls.
