# `.ebpf_requirements` format and pre-load checking (normative)

An ebpf-compile ELF's `.ebpf_requirements` section records the kernel capabilities required by its programs and the schema used to produce the ELF. A loader reads it, checks target capabilities (caps), and decides whether to block loading.
This document is **normative for both format and verdicts**. The rules are independent of implementation language. Reference implementations and their test harnesses live in the private development checkout; the tables below are machine-read and must stay aligned with the conformance data.

## 1. Section

- The section name is `.ebpf_requirements`. Contents are UTF-8 text with `\n`-terminated lines and no terminating NUL.
- Line 1 is `ebpf-requirements <N>`. Subsequent rows contain tab-separated fields.
- It changes neither instructions nor BTF. libbpf / cilium ignore it as an unknown section.
- **Identical input produces identical bytes**, with ordering defined per row below.
- Readers remove exactly one trailing `\r` from a line: CRLF is accepted, but `\r\r\n` leaves a CR in a field and fails. Numeric fields accept a leading `+`, as a signed prefix before the decimal digits. Parse corpus cases fix these rules.
- The ELF header e_version must equal 1 across all four bytes. ELF-based readers must check all four bytes, even when their ELF library checks only the low byte.

## 2. Versions

- Header `<N>` is the format version. Historical emitters wrote versions 5–10, later 5–13, and current feature-dependent additions extend this through 18. Versions 1–4 from older compilers remain readable. Version-11 parser/checking support preceded emission: tracepoint emits trace_tp + tpfield; perf_event emits trace_perf + arch; lsm with schema args emits trace_lsm + farg; every ext emits freplace + extret / extarg; every struct_ops emits trace_struct_ops + structop / retsig / farg. Only ELF using those rows needs version 11.
- **Version 15 adds no row kind; it is the minimum version of kfield type value `strptr`** (char * field read by ebpf.kernel.read_str). Only ELF containing that value becomes 15; other ELF versions/bytes do not change. strptr below version 15 fails min_version; an older MaxFormatVersion-14 reader rejects the header. Earlier kfield value extensions did not raise the format version because older readers loudly rejected them by the value rule; strptr follows the later value-minimum-version rule, as does btf type_tag at 13.
- Version 14 adds only `tpbuf <program> i32`, physically immediately after a generic raw_tp_writable attach. Parser/BTF checking preceded compiler emission. Existing ELF without the row is unchanged. kfunc permission profiles derive from actual ELF and add no row.
- Version 12 adds multi-probe families kprobe_multi / kretprobe_multi / uprobe_multi / uretprobe_multi with mtarget; usdt with usdtsem / usdtarg; and map-in-map innermap. Parser/checking preceded emission. innermap follows the outer array_of_maps / hash_of_maps map row using its schema inner template. Multi-probe emission is `attach <p> <family> <N>` → arch → ctxfield → (binary) → N mtarget rows in attach-array order → kprobearg / uprobearg. Only affected ELF becomes 12.
- Version 13 adds kfunc / sysarg / mtargetarg, companion families trace_lsm_cgroup / ksyscall, and BTF feature type_tag. Emission includes: each used kfunc reachable from a program or subprogram, `kfunc <p> <name> <ret> <arg>…`, using UAPI signature types (`*S` becomes ptr:S), sorted by name after all other rows including ctxaccess; every ksyscall program's ksyscall family; multi-entry target_params as mtargetarg after mtarget, sorted by (i,n), without kprobearg / uprobearg, and ctxfield once for each n in the union of all targets. Incorrect target_params count or an n without an architecture register stops ELF emission by name. lsm_cgroup with args emits trace_lsm_cgroup + farg. A map-value kptr record field (`PTR → TYPE_TAG "kptr" → STRUCT`) emits btf type_tag; this is a value extension, not a new row kind.
- **ELF version is the maximum minimum version required by any row kind or versioned value present in it.** Historically: kfield strptr requires 15; tpbuf 14; kfunc / sysarg / mtargetarg, trace_lsm_cgroup / ksyscall, or btf type_tag require 13; multi-probe / usdt attach or mtarget / usdtsem / usdtarg / innermap require 12; trace_lsm / trace_tp / trace_perf / freplace / trace_struct_ops or tpfield / extret / extarg / structop require 11; trace_fmod_ret requires 10; ctxaccess, generic attach, kretprobe / uretprobe require 9; farg 8; tailslot 7; argtag 6; otherwise 5 (all emitted ELF has BTF and btf rows). New values requiring 16–18 are specified below. Adding a format version does not raise the version of ELF that uses none of its additions; those objects remain readable by older loaders.
- **Attach types are versioned like row kinds.** Generic attach types (§4, UAPI and mechanism names), kretprobe / uretprobe require 9; trace_fmod_ret 10; trace_lsm / trace_tp / trace_perf / freplace / trace_struct_ops 11; four multi families / usdt 12; trace_lsm_cgroup / ksyscall 13. Multi families in versions 9–11 and ≤8 fail min_version. **BTF feature values follow the same rule**: type_tag requires 13 (≤12 fails min_version; the preceding reader rejected it as unknown BTF feature under value). Unknown attach types in older documents fail value, as with readers through version 8; kretprobe / uretprobe and companion families with too-old versions fail min_version. A historical version-9/10 `trace_perf perf` could be treated as generic attach with a non-UAPI type lacking an attach_type answer; it now fails min_version. No repository ELF used that form. **Mechanism-name and target-kind tables are fixed at version 9; adding entries requires a version bump.**
- **Future row-kind additions must raise the format version.** retsig / arch / ctxfield / kprobearg / binary / uprobearg historically did not; they appear only immediately after version-4-or-newer attach rows, so their minimum is 4.
- Readers **reject unknown header versions and row kinds**, never silently skip them. The maximum supported requirements format is 18.

## 3. Row kinds

**Format 17** is the minimum for tpfield values `[N]u8` / `[N]i8`, where N is canonical decimal 1..64 and the byte-count column equals N. Only ELF declaring an array becomes 17; existing bytes/versions are unchanged. Checking strictly requires a single fixed tracefs array with 1-byte elements, matching count / total size / offset / Signed. Scalars, pointers, multidimensional arrays, 2-byte elements and data_loc mismatch; uninterpretable typedefs and unreadable formats yield blocking Unknown. tpfield's row minimum remains 11; policy 15 / caps 9 were unchanged by this extension. Keys are `<event>/<field>/<offset>/<N>/[N]u8` or the signed counterpart; missing answers are Unknown and i/u answers cannot substitute. Existing scalar i/u checking is unchanged: interpreting a same-size array as an integer, including endianness, is the reader's responsibility.

**Format 18** is the minimum for uprobearg ptr and uprobe_multi mtargetarg ptr. Only affected ELF becomes 18; old bytes/versions are unchanged. Row minima 4 / 13 and kprobe ptr are unchanged. Typed user_buf and raw-i64 identity use the same depth-1 / 8-byte DWARF pointer requirement. There is no new query, Unmet kind or loader declaration; policy 16 / caps 10 are unchanged. New ptr below format 18 fails min_version; older readers reject header 18.

The new ptr check walks DIEs directly without decoding pointee members or materializing the pointee type. Two typedef / const / volatile / restrict chains (outer and pointee) each permit at most 64 DIEs including the endpoint; a shared offset set makes revisits Unknown. Atomic / unknown tags, broken references and a 65th DIE are Unknown. Pointer width is a positive DW_AT_byte_size, or, if absent, the address_size of **the unit owning that pointer DIE**, including cross-unit ref_addr. Unknown width takes precedence over depth mismatch. The pointee pointer's width/content is not inspected; depth ≥2 mismatches. Known non-pointer pointees (base / struct / union / array / enum / subroutine / reference / …) give depth 1 without decoding contents. Missing DW_AT_type on the pointer itself, or on const / volatile / restrict, means void (outer qualified void is non-pointer; pointee qualified void gives depth 1). A missing typedef reference is Unknown. Existing i/u/strptr and kernel ptr checks are unchanged.

Known non-pointer actual type is `non-pointer`. Wrong width/depth is `ptr(depth=1,width=<decimal>)` or `ptr(depth>=2,width=<decimal>)`, using the outer width and the latter when both differ. Mismatch uses existing blocking uprobearg, Name `<n> of <target> (ptr)`, Detail `argument <n> (<ArgName>) of <target> is <actual> in the binary's DWARF, but the object reads it as ptr`. Unknown uses blocking uprobearg_unknown with the same Name and Detail `argument <raw DWARF name> has a type this check cannot read`. Unknown width produces Unknown, not an actual-type string. No new query/reason turns missing evidence into success.

**Format 16** is the minimum for tpfield strptr (8-byte user char pointer). Header ≤15 with strptr fails min_version; an older reader rejects header 16. Existing i/u rows and ELF remain unchanged. In addition to offset/size, checking requires depth-1 char pointer: `const char * filename` / `char * dev_name` match; `const char *const * argv`, data_loc, arrays and integers do not. Unknown aliases/tokens or unreadable data yield blocking tpfield_unknown. The compiler has no kernel-version branch.

The same verdict family/blocking rules kept policy 15; independent query key `<event>/<field>/<offset>/8/strptr` kept caps 9. u/i answers do not supply type evidence; a missing strptr key is Unknown. The v1.14.0 reader control retained the unknown key, but u/i queries failed fatally with no answer; it did not silently reinterpret it. That reader rejects new ELF at the header before any strptr query.

`Minimum version` is the earliest format in which a row may occur; its presence in an older-format ELF is an error. `Fields` counts tab-separated fields including the row-kind name.

| Row | Fields | Minimum version | Ordering | Binding | Meaning | Origin |
|---|---|---|---|---|---|---|---|
| `schema` | 3 | 2 | Exactly once immediately after header | — | `schema sha256 <64 hex digits>`: SHA-256 of the schema file used for ELF generation; compared with generated bindings | Schema boundary |
| `program` | 4 | 1 | Program-symbol order | Name (definition) | `program <symbol> <program type name> <enum bpf_prog_type value>` | Capability requirements |
| `helper` | 4 | 1 | Program order, then helper number | Name (program) | `helper <program> <helper name without bpf_ prefix> <enum bpf_func_id value>`: helpers reachable through subprogram and callback addresses | Reachability analysis |
| `map` | 8 | 1 | Map-symbol order | Name (definition) | `map <symbol> <map type name> <enum bpf_map_type value> <key> <value> <max_entries> <flags>`. Key/value use schema spelling: u32, i64, [16]i8, record:<name>, [D]stack_build_id for build-id stack traces, suffix be for big endian, or - if absent. **Version 1 has only 4 fields**, without key onward | Schema/map boundary |
| `kfield` | 5 | 3 | (program, struct, field, type), unique | Name (program) | `kfield <program> <kernel struct> <field> <type>`: CO-RE read. Types i8/u8/i16/u16/i32/u32/i64/u64; ptr:<struct> for struct pointers; [N]i8 / [N]u8, N 1–64, checked as N one-byte integer elements; strptr, checked as pointer through const / volatile / typedef to a one-byte integer, **minimum version 15**. Initially only i32/u32; earlier value extensions did not raise the format, since readers through v0.16.0 reject unknown values loudly under value | CO-RE fields |
| `attach` | 4 | 4 | Program order, immediately followed by type-specific companion rows (§4) | Name (one per program) | `attach <program> <attach type> <target>`; generic types without companions and kretprobe / uretprobe require version 9 | Attach requirements |
| `arg` | 4 | 4 | Immediately after trace_raw_tp attach; contiguous index from 0 | **Position** (preceding attach) | `arg <program> <index> <type>`: kernel struct name for struct pointer; integer i8…u64 (bool u8); - for unread, unchecked argument. Integer/- extension did not raise format: readers through v0.16.0 treat u8/- as struct names and stop loudly with attach Unmet | Typed tracepoint arguments |
| `retsig` | 4 | 4 | Immediately after trace_fexit attach; also trace_fmod_ret at version 10; after trace_struct_ops structop and before farg at version 11 | **Position** (preceding attach) | `retsig <program> <argument count> <i\|u><width>`. trace_struct_ops additionally allows void for void members, only after its version-11 family. Wrongly small argument counts and wrong return width/sign can pass the verifier but silently misread values; this check protects them. Too-large counts are also rejected by the verifier | Return-signature checking |
| `arch` | 3 | 4 | Once immediately after kprobe/uprobe attach; also once after trace_perf attach, whose only companion is arch | **Position** (preceding attach) | `arch <program> <arch>`, e.g. x86_64: architecture assumed by fixed-offset reads | Register ABI |
| `ctxfield` | 6 | 4 | After arch, in argument-number order | **Position** (preceding attach) | `ctxfield <program> pt_regs <register field> <offset> <bytes>`: pt_regs field used to read arguments | Register ABI |
| `kprobearg` | 4 | 4 | After kprobe attach companions, increasing number | **Position** (preceding attach) | `kprobearg <program> <one-based number> <i\|u><width>\|ptr`. ptr reads an 8-byte raw value without dereferencing and checks that the target argument is a pointer; this value extension did not raise format | Kernel argument types |
| `binary` | 4 | 4 | Once after uprobe ctxfield | **Position** (preceding attach) | `binary <program> sha256 <64 hex digits>`: attach binary SHA-256 | User-binary identity |
| `uprobearg` | 4 | 4 | After uprobe binary, increasing number | **Position** (preceding attach) | `uprobearg <program> <number> <i\|u><width \| strptr \| ptr>`. strptr is a depth-1 pointer to 8-bit char; ptr, from format 18, is depth-1 / 8-byte pointer for user_buf or raw-i64 identity. Older type checks are unchanged | User argument types |
| `btf` | 2 | 5 | Name order | — | `btf <feature>`: int / ptr / const / array / struct / var / datasec / func / func_proto / func_global / decl_tag / type_tag. type_tag requires version 13, for map-value kptr PTR → TYPE_TAG → STRUCT | BTF features |
| `argtag` | 4 | 6 | Program order, then tag | Name (program) | `argtag <program> <tag> <pointer class>`; currently only arg:nonnull mem, requiring verifier interpretation of argument tags | Argument tags |
| `tailslot` | 4 | 7 | Schema map order, increasing slot | Name (map and program) | `tailslot <map> <slot> <program>`: prog_array slot set by loader after load. Map must have a prog_array row, slots unique and below max_entries, program in the same ELF | Tail-call setup |
| `farg` | 4 | 8 | Immediately after trace_fentry attach, contiguous indices from 0. At version 10, also after trace_fmod_ret retsig: integer i8…u64 or -, checked against FUNC_PROTO argument i+1 width/sign. At version 11, also immediately after trace_lsm attach (struct / integer / -, checked against bpf_lsm_<hook> FUNC_PROTO) and after trace_struct_ops structop / optional retsig (same domain, checked against member FUNC_PROTO) | **Position** (preceding attach) | `farg <program> <index> <struct\|->`: fentry argument index is a struct pointer; - means unread/unchecked. Checks target FUNC_PROTO before load: fentry pointers are plain, and a wrong struct can silently read different data | Fentry argument types |
| `ctxaccess` | 7 | 9 | Program order, then strictly (struct, field, mode), unique | Name (program) | `ctxaccess <program> <attach type\|-> <struct> <field> <r\|w> <bytes>`: ctx field read/write width. Attach type is expected_attach_type UAPI name or -; bytes 1/2/4/8. Verifier permission changes as kernels add fields; load-time ctx_access answers it | Context-field access |
| `tpfield` | 6 | 11 | Immediately after trace_tp attach; strictly increasing offset | **Position** (preceding attach) | `tpfield <program> <field> <offset> <bytes> <i\|u\|strptr\|strarray\|[N]u8\|[N]i8>`. Integers use width 1/2/4/8 and sign; strptr/strarray require format 16 and width 8; fixed byte arrays require format 17, N 1..64. tracefs layout/type mismatch and Unknown block load | Tracepoint fields |
| `extret` | 4 | 11 | Once immediately after freplace attach | **Position** (preceding attach) | `extret <program> <argument count> <i\|u><width>\|void`: replaced function argument count/return type. The kernel does not compare argument sign and return width; ext_targets checks target BTF before load | Replacement signature |
| `extarg` | 4 | 11 | After extret; contiguous indices from 0, below extret argument count | **Position** (preceding attach) | `extarg <program> <index> <i\|u><width>\|-`: replaced function's integer argument type, or - for unread/unchecked | Replacement arguments |
| `structop` | 4 | 11 | Once immediately after trace_struct_ops attach, before retsig/farg | **Position** (preceding attach) | `structop <program> <struct> <member>`: implemented function-pointer member, e.g. tcp_congestion_ops. struct_ops_members checks kernel BTF bpf_struct_ops_<struct> and member FUNC_PROTO together with retsig/farg | Struct-ops checking |
| `mtarget` | 4 | 12 | Multi companions: kprobe_multi arch → ctxfield → mtarget → kprobearg; kretprobe_multi arch → ctxfield → mtarget; uprobe_multi arch → ctxfield → binary → mtarget → uprobearg; uretprobe_multi arch → ctxfield → binary → mtarget. Exactly N contiguous indices from 0; N is attach target | **Position** (preceding attach) | `mtarget <program> <i> <function \| symbol>`: kernel function for kprobe family, binary symbol for uprobe family. Loader attaches in i order with cookie i (§8); each target uses single-family checking (§4) | Multi-probe targets |
| `usdtsem` | 3 | 12 | Once after usdt binary, before usdtarg | **Position** (preceding attach) | `usdtsem <program> <required\|none>`: semaphore declaration, checked against every note point by usdt_probe and loader usdt_attach (§8). A required point silently produces no events without a loader passing ref_ctr_offset | USDT semaphore |
| `usdtarg` | 4 | 12 | After usdtsem; strictly increasing n 1–12 | **Position** (preceding attach) | `usdtarg <program> <n> <i\|u><width>`: argument size/sign, authoritative in note `<[-]size>@`; loader supplies its location from the note. Checks size/sign at every point and whether the loader can parse each location spelling | USDT arguments |
| `innermap` | 8 | 12 | Once immediately after array_of_maps / hash_of_maps map. **Required for of_maps rows in format ≥12**; ≤11 retains old behavior without it | **Position** (preceding map) | `innermap <outer map> <map type name> <enum bpf_map_type value> <key> <value> <max_entries> <flags>`: inner template; kernel permits only matching inserted maps. Fields match map-row spelling. Nested map-in-map is a value error. HasMapType checks inner kind (§5). Compiler emission followed initial reader support | Inner-map template |
| `kfunc` | 4–9 | 13 | Program order, then name, unique | Name (program) | `kfunc <program> <name> <ret> <arg0> … <argN-1>`, 0–5 arguments. Types i8…u64 / bool / ptr:<struct> / ptr:void / ptr:<integer type> (e.g. ptr:u64); return also allows void. kfunc_protos checks target BTF FUNC/FUNC_PROTO and existence before load: verifier can silently accept integer argument width/sign mismatches | kfunc signature |
| `sysarg` | 4 | 13 | After ksyscall arch → ctxfield; strictly increasing n 1–6 | **Position** (preceding attach) | `sysarg <program> <n> <i\|u><width>\|ptr\|strptr`: syscall argument read from syscall pt_regs reached through wrapper pt_regs; fourth uses r10. strptr requires format 16 and depth-1 char pointer, distinct from ptr/i64 or char**. tracefs preferred, BTF fallback; mismatch and Unknown block. Independent caps-9 key syscall/n/strptr; missing answer is Unknown | Syscall argument types |
| `mtargetarg` | 5 | 13 | After N mtarget rows for kprobe_multi / uprobe_multi; strictly lexicographic (i,n), i < N; mutually exclusive with kprobearg / uprobearg | **Position** (preceding attach) | `mtargetarg <program> <i> <n> <type>`: target-i argument n; same domain/check as kprobearg (including ptr) / uprobearg (including strptr), applied to target i (§4) | Per-target argument types |
| `tpbuf` | 3 | 14 | At most once, physically immediately after same-program generic raw_tp_writable attach | **Position** (preceding attach) | `tpbuf <program> i32`: checks before load that rawtp target argument 0 points to signed 32-bit integer. Only i32 permitted | Writable raw tracepoint buffer |

Outside the reader's ordering checks: duplicate map rows and agreement between numeric ids and names. Numeric ids come from UAPI tables, while capability checking uses names.

**Reader-enforced ordering**, divided by binding type (negative parse cases cover these rules):

- **Name-bound rows**: helper / kfield / attach / argtag / ctxaccess / kfunc bind a program; tailslot binds map and program; generic map:<symbol> attach targets bind a map. Readers check prior definitions and duplicates: schema, program, tailslot slots, one attach per program, ctxaccess (program,struct,field,mode), and kfunc (program,name), whose duplicates fail order. Name/number sorting of program / map / btf and similar rows is an **emitter rule**, not a reader requirement (`accept_rows_unsorted` is accepted).
- **Position-bound rows**: arg / farg / retsig / arch / ctxfield / kprobearg / binary / uprobearg; version-11 tpfield / extret / extarg / structop; version-12 mtarget / usdtsem / usdtarg and innermap. Companions bind the preceding attach; innermap binds the preceding map. A program symbol is also carried, but position defines meaning, so the reader checks all ordering:
  - Program and attach type must match the preceding attach.
  - retsig / arch / binary occur once per attach.
  - Order is arch → ctxfield → kprobearg for kprobe; arch → ctxfield → binary → uprobearg for uprobe.
  - arg / farg indices are contiguous from 0; kprobearg / uprobearg numbers strictly increase.
  - Version 11: trace_perf has exactly one arch; trace_tp tpfield offsets strictly increase; freplace has one extret then extarg contiguous from 0 below extret count; trace_struct_ops has one structop → optional single retsig → farg.
  - Version 12: multi families insert mtarget into the single-family ordering shown above. Indices must be contiguous from 0 (gaps/backtracking fail order; i ≥ N fails value). **Before N targets are complete, any row outside arch / ctxfield / binary / mtarget fails order**, naming that row; EOF uses line 0, row mtarget. Argument rows follow all N targets. usdt uses arch → ctxfield → binary → exactly one usdtsem → usdtarg with strictly increasing n 1–12. **innermap must immediately follow an array_of_maps / hash_of_maps row with the same symbol**; otherwise order. In version ≥12, an of_maps row not immediately followed by innermap fails order at the following row, or line 0 / row innermap at EOF.
  - Version 13: ksyscall uses arch → ctxfield → sysarg, n strictly increasing in 1–6, with no kprobearg/binary; arch/ctxfield after sysarg fails order. mtargetarg follows all N targets with strictly lexicographic (i,n); i ≥ N fails value. **It is mutually exclusive with kprobearg/uprobearg**, failing order whichever appears first. trace_lsm_cgroup farg has the same ordering and domain as trace_lsm.
  - Version 14: tpbuf is physically immediately after `attach <program> raw_tp_writable rawtp:<C identifier>`, without even a blank line. Program type/id must be raw_tracepoint_writable / 24. Duplicate/wrong-position rows fail order; a type other than i32 fails value.

An earlier reference reader checked only program/type agreement, arg indices and duplicate arch/binary, accepting duplicate attach/retsig and other companion-order violations. Tightening the checks did not change parsing for any of 694 repository ELF objects; their results remained byte-identical.

**Every row's minimum version is checked directly at that row**, rather than relying on an attach row to guard companion rows indirectly.

## 4. Attach types

| Attach type | Target | Companion rows (in order) | Origin |
|---|---|---|---|---|
| `trace_raw_tp` | Tracepoint name | `arg` by index | Typed tracepoint |
| `trace_fentry` | Kernel function name | Optional `farg` by index | Function entry |
| `trace_fexit` | Kernel function name | `retsig` | Function exit |
| `kprobe` | Kernel function name | `arch`, `ctxfield` by number, `kprobearg` by number | Kernel probe |
| `uprobe` | Binary symbol name | `arch`, `ctxfield`, `binary`, `uprobearg` by number | User probe |
| `tcx` | `ingress` or `egress` | None | tcx |
| `kretprobe` | Kernel function name | `arch`, `ctxfield` for return register by number (version 9) | Kernel return probe |
| `uretprobe` | Binary symbol name | `arch`, `ctxfield`, `binary` (version 9) | User return probe |
| `trace_fmod_ret` | Kernel function with ALLOW_ERROR_INJECTION | `retsig`, `farg` integer or - by index (version 10) | Return modification |
| `trace_lsm` | LSM hook C identifier; BTF FUNC bpf_lsm_<hook> | `farg` struct/integer/- by index (version 11) | LSM signature |
| `trace_tp` | Tracepoint event `<category>/<event>`, both C identifiers | `tpfield` by offset (version 11) | Tracepoint layout |
| `trace_perf` | `perf`; loader supplies perf-event fd | `arch` (version 11) | Perf context |
| `freplace` | Global function name to replace; loader supplies target program | `extret`, `extarg` by index (version 11) | Replacement signature |
| `trace_struct_ops` | Operation-table struct_ops map symbol, defined earlier or order error | `structop`, optional `retsig`, `farg` by index (version 11) | Struct-ops signature |
| `kprobe_multi` | Function count N ≥1, functions in mtarget | `arch`, `ctxfield` by number, N `mtarget` by i, `kprobearg` by number (version 12) | Multi kernel probe |
| `kretprobe_multi` | Function count N | `arch`, return-register `ctxfield`, N `mtarget` (version 12) | Multi kernel return probe |
| `uprobe_multi` | Symbol count N, symbols in mtarget | `arch`, `ctxfield`, `binary`, N `mtarget`, `uprobearg` by number (version 12) | Multi user probe |
| `uretprobe_multi` | Symbol count N | `arch`, `ctxfield`, `binary`, N `mtarget` (version 12) | Multi user return probe |
| `usdt` | `<provider>:<name>`, both C identifiers | `arch`, `ctxfield` by number, `binary`, `usdtsem`, `usdtarg` by number (version 12) | USDT |
| `trace_lsm_cgroup` | LSM hook C identifier, BTF FUNC bpf_lsm_<hook>; loader supplies cgroup fd | `farg` struct/integer/- by index (version 13) | Cgroup LSM |
| `ksyscall` | Prefix-free syscall C identifier; wrapper `<prefix>sys_<name>`, architecture-specific prefix (`__x64_` on x86_64) | `arch`, `ctxfield` by number, `sysarg` by number (version 13) | Syscall wrapper |

**Version-11 companion families retain version-9 generic checks**: trace_lsm asks the same attach_type/attach_target as `lsm_mac lsm:<hook>`; trace_tp as `tracepoint tp:<cat>/<event>`; trace_perf as `perf_event perf`; trace_struct_ops as `struct_ops map:<symbol>`, with identical Unmet kinds/verdicts, before checking companions. freplace had no generic attach row, so checks only its companions. lsm farg checks bpf_lsm_<hook> using func_args for struct arguments (as fentry) and func_param for integer argument i+1 (as fmod_ret), producing farg / farg_unknown. trace_perf arch uses arch / arch_unknown like kprobe, since bpf_perf_event_data regs size depends on architecture. tpfield, extret/extarg and structop with retsig/farg use §5 queries.

kretprobe / uretprobe use kprobe / uprobe family checking without argument rows. kretprobe checks kallsyms and loader aliases: cilium v0.22 link.Kretprobe and Kprobe share kprobe(), which retries failed X as __x64_X (`link/kprobe.go`); attach_alias prevents silent retargeting. uretprobe checks binary/symbol.

**Multi families (format 12)** attach one program through one link to multiple functions/symbols using BPF_TRACE_KPROBE_MULTI / BPF_TRACE_UPROBE_MULTI and program type kprobe. The single attach per program rule remains, with targets in mtarget:

- Ask attach_type with (program,trace_kprobe_multi) or (program,trace_uprobe_multi), available from kernels 5.18 and 6.6 respectively. LiveCaps probes link creation as well as load: without CONFIG_FPROBE, kprobe.multi load can succeed while link creation returns -EOPNOTSUPP (§5).
- Check arch/ctxfield once, as for single families.
- **Check each mtarget as a single-family target**: kernel symbols through HasKernelSymbol (attach if absent, attach_symbol_unknown if undecidable), and each kprobearg × target FUNC_PROTO through CheckFuncParam (kprobearg / kprobearg_unknown). User families check binary once (binary / binary_unknown), symbols (uprobe_symbol), arguments (uprobearg*), calling convention (uprobearg_abi*, or uretprobe_abi* for uretprobe_multi). **Mismatches name the function**: attach Name is the function; argument Name is `<n> of <function> (<type>)`.
- **Do not query attach_alias**: cilium v0.22 KprobeMulti and libbpf multi do not retarget aliases. Missing names fail link creation loudly without partial attachment (§8 L2).
- No new Unmet kinds are introduced.

**USDT (format 12)** points are systemtap sys/sdt.h `.note.stapsdt` notes (owner stapsdt, type 3), not symbols. The binary compiler chooses argument locations per point; for the same probe, clang may use memory and gcc registers. Programs do not know locations: loaders derive a spec from notes (§8). Checking reads the notes from the already hash-checked uprobe binary:

1. arch / ctxfield as for single probes.
2. Loader usdt_attach (§8): none gives usdt_loader; plain with usdtsem required gives usdt_loader because without ref_ctr_offset semaphore points silently emit nothing; no declaration gives usdt_loader_unknown. All block load.
3. Binary SHA-256, as uprobe (binary / binary_unknown).
4. At least one provider:name point or usdt_probe; **every point's** semaphore presence must match usdtsem, otherwise usdt_probe names its pc.
5. Every point must have enough arguments for the largest usdtarg n, with matching size/sign in `<±size>`; usdtarg names the failing pc.
6. **Read arguments only** must have loader-readable locations. x86_64 permits %reg, off(%reg) with optional off, and $imm, using 64 / 32 / 16 / 8 bit general registers. SIB off(%base,%index,scale), %rip, unknown registers and old spellings without @ give usdtarg_unknown. Unread locations are not checked because they cannot alter values. Malformed notes also give usdtarg_unknown.

**Version-13 families**:

- **trace_lsm_cgroup** preserves generic `lsm_cgroup lsm:<hook>` attach_type/attach_target checking. farg checks bpf_lsm_<hook> like trace_lsm (func_args for structs, func_param for integers; farg / farg_unknown). Also check loader lsm_cgroup_load (§8, lsm_cgroup_loader*). **That loader check also applies to version-9 generic lsm_cgroup rows**; fsession_load applies to generic `trace_fsession func:<function>`.
- **ksyscall** checks arch/ctxfield as kprobe, and existence of wrapper `<prefix>sys_<name>` in kallsyms (attach / attach_symbol_unknown). **No alias query**: loader ksyscall_attach:prefix attaches to the prefixed name; unknown architecture prefix gives attach_symbol_unknown. Check sysarg through syscall_args (sysarg / sysarg_unknown, Name `<n> of syscall <name> (<type>)`) and loader ksyscall_attach (§8, ksyscall_loader*). Older format-5 `kprobe __x64_sys_<name>` ELF is indistinguishable from ordinary kprobe and retains its verdicts.
- **mtargetarg** applies CheckFuncParam to kprobe_multi target i like kprobearg, or DWARF and calling-convention checks to uprobe_multi symbol i like uprobearg. Existing kprobearg* / uprobearg* / uprobearg_abi* kinds name the function.
- **Static map-target answers (policy 12)**: generic/family map:<symbol> targets for sk_skb_stream_parser / sk_skb_stream_verdict / sk_skb_verdict / sk_msg_verdict are satisfied by sockmap/sockhash map rows in the same ELF; struct_ops / trace_struct_ops are satisfied by struct_ops maps. Do not query attach_targets, eliminating the previous attach_target_unknown map:… result. Wrong map kind gives attach_target naming the mismatch; other map-target attach types still query attach_targets.

### Generic attach rows (version 9)

Attach types absent from the table above have **no companion rows**. The type is one of:

- **UAPI enum bpf_attach_type names**, lowercase without BPF_, from abi/uapi.tsv attachtype: e.g. cgroup_inet_ingress / sk_lookup / trace_iter / lsm_mac / netfilter. Programs load with that expected_attach_type; checking asks attach_type (§5).
  - **Link-only types**, not load expected_attach_type: perf_event (kind perf_event, row `perf_event perf`) is used for BPF_LINK_CREATE, while load uses expected_attach_type 0. The kernel ignores PERF_EVENT expected_attach_type and cilium loads with 0. AttachTypeCaps.HasAttachType checks enum availability plus load acceptance with expected_attach_type 0; **it does not probe load using the link-only type** (LiveCaps linkOnlyAttachType, TestLinkOnlyAttachType).
- **Mechanism names**, without expected_attach_type: load uses 0 and no attach_type query. **The following table is fixed at version 9; additions require a format bump.**

| Mechanism | Loader attach method |
|---|---|
| `raw_tp` | BPF_RAW_TRACEPOINT_OPEN, without BTF |
| `raw_tp_writable` | Same, for writable tracepoints |
| `tracepoint` | perf_event_open tracepoint event + PERF_EVENT_IOC_SET_BPF / link |
| `socket_filter` | setsockopt SO_ATTACH_BPF |
| `sched_act` | tc act_bpf through netlink |
| `lwt_in` / `lwt_out` / `lwt_xmit` / `lwt_seg6local` | Route encap bpf through netlink |
| `syscall` | No attach; invoked with BPF_PROG_TEST_RUN |

target is `<kind>` or `<kind>:<value>` without tabs/spaces. **Target kinds are fixed at version 9; additions require a bump.**

| Kind | Value | Meaning | Check |
|---|---|---|---|
| `func` | Required | Kernel function | `attach_target` |
| `tp` | Required | Tracepoint `<cat>/<name>` | `attach_target` |
| `rawtp` | Required | Raw tracepoint name | `attach_target` |
| `iter` | Required | Iterator target name | `attach_target` |
| `lsm` | Required | LSM hook name | `attach_target` |
| `sym` | Required | User-binary symbol | `attach_target` |
| `map` | Required | Same-ELF map symbol, whose map row must precede it or order error | `attach_target` |
| `prog` | Required | Replaced program function name; loader supplies the program | `attach_target` |
| `cgroup` | None | Cgroup; loader supplies path | Not queried |
| `netns` | None | Network namespace | Not queried |
| `socket` | None | Socket fd | Not queried |
| `netlink` | None | tc / route configured through netlink | Not queried |
| `perf` | None | Perf-event fd | Not queried |
| `device` | None | Device fd for lirc | Not queried |
| `none` | None | No attachment | Not queried |

Missing required value, unexpected value, and unknown kind fail value. Generic rows retain the one-attach-per-program rule.

The emitter uses ProgramAttaches.def REQATTACH rows for kinds without a companion family (historically stored in ProgramKinds.def). Examples include sk_lookup `attach <p> sk_lookup netns` and netfilter `attach <p> netfilter netns`. Netfilter links attach to the hook in the BPF_LINK_CREATE caller's netns; pf / hook / priority are loader inputs.

Emission by kind:

- raw_tp: `raw_tp rawtp:<tp>`; iter: `trace_iter iter:<target>`; syscall: `syscall none`. fmod_ret initially used `modify_return func:<function>`, later replaced by trace_fmod_ret companions.
- lsm without args: `lsm_mac lsm:<hook>`; **with schema args, trace_lsm <hook> followed by farg per struct / integer / - element, version 11**. lsm_s (`lsm.s/<hook>`) uses the same rows/lsm_mac type. Sleepability is not in the row; the kernel rejects non-sleepable hooks or maps forbidden to sleepable programs at load.
- lsm_cgroup without args: `lsm_cgroup lsm:<hook>`, attaching to loader-supplied cgroup fd through BPF_LINK_CREATE. **With args, trace_lsm_cgroup <hook> plus farg per element, version 13.**
- ksyscall (`ksyscall/<name>`) initially emitted kprobe-family `kprobe __<pfx>_sys_<name>` plus arch, using UAPI syscallpfx (`__x64_sys_` on x86_64). **Current emission is family `ksyscall <name>` (version 13) → arch → optional ctxfield for schema params → sysarg sorted by n.** ctxfield includes wrapper argument-1 di and each read syscall pt_regs field from UAPI ksyscallarg, deduplicated. Loader ksyscall_attach:prefix targets the wrapper; cilium v0.22's plain section-suffix <name> attachment fails.
- kprobe_session: `trace_kprobe_session func:<function>`; fsession: `trace_fsession func:<function>`, without companions. Session kfunc signatures (bpf_session_is_return / bpf_session_cookie) vary by kernel and are checked through kfunc rows. **cilium v0.22 cannot load fsession**, although attachment uses AttachTracing's raw-tracepoint open. Loader declaration fsession_attach records that distinction.
- sk_skb / sk_msg: `sk_skb_stream_verdict map:<symbol>` / `sk_msg_verdict map:<symbol>`, using the schema attach_target sockmap/sockhash, defined before attach. Attach is BPF_LINK_CREATE to sockmap; LiveCaps attach_types also probes link creation.
- tracepoint originally emitted `tracepoint tp:<category>/<event>` and perf_event `perf_event perf` (link-only UAPI type; load uses 0). raw_tp_writable uses `raw_tp_writable rawtp:<tp>`. These initial generic forms had no companions and did not read tracepoint fields or architecture-dependent perf context offsets; those reads require the later companion forms.
- struct_ops originally used `struct_ops map:<symbol>`: BPF_STRUCT_OPS is the link type for registering the table map, but loader sets program load expected_attach_type to the member index. Map row is `map <symbol> struct_ops 26 u32 - 1 0`. This generic form does not check member argument/return types; companions provide that check.
- kretprobe / uretprobe use the table's families: arch → ctxfield for the return register (UAPI kproberet) → binary for uretprobe.

Current struct_ops emission is `attach <p> trace_struct_ops <map>`, `structop <p> <struct> <member>` from schema map type/ops, `retsig <p> <nargs> <void|i|u><width>`, then farg per schema args, version 11, replacing the older version-9 generic form. farg struct names are the pre-promotion BTF FUNC_PROTO names from KernelABI.h promotion tables: tcp_congestion_ops schema tcp_sock becomes sock, before verifier bpf_tcp_ca_is_valid_access promotion.

Current ext emission is `attach <p> freplace <function>` plus `extret <p> <nargs> <i|u><width>` and `extarg <p> <i> <i|u><width>` for all schema arguments, version 11. Older ext ELF had no attach row and used version 5. Signedness remains the schema declaration: ebpf-compile's replacement-target BTF is unsigned, so targeting a C int function can produce an ext_target sign mismatch.

## 5. Checking — caps queries

Checking queries capabilities for each requirements row and returns an ordered list of unmet requirements. Answers are true / false / **Unknown**. A missing interface means Unknown except where the table requires a checking error.

**Unknown handling is query-specific.** A checking error is distinct from a definite mismatch and blocks load (fail closed).

| Query | Rows | Meaning | Unknown answer | Other error | Caps without query | Load on Unknown |
|---|---|---|---|---|---|---|---|
| HasProgType | program | Program type exists | Checking error | Checking error | Required basic interface | Blocked by checking error |
| HasHelper | helper | Helper usable by this program type | `helper_unknown` | Checking error | Required basic interface | Continues |
| HasMapType | map / innermap inner kind | Map type exists | Checking error | Checking error | Required basic interface | Blocked by checking error |
| HasTCX | attach tcx | tcx link available | `attach_tcx_unknown` | Checking error | `attach_tcx_unknown` | Continues |
| CheckFuncSig | retsig | fexit target FUNC_PROTO argument count and return type | —; errors are checking errors | Checking error | `retsig_unknown` | Blocked |
| CheckFunc | attach trace_fentry / trace_fexit | FUNC exists in target BTF | — | Checking error | `attach_func_unknown` | Continues |
| CheckFuncArgs | farg | fentry argument i is a struct pointer; - is unchecked | —; errors are checking errors | Checking error | `farg_unknown` | Blocked since policy 5 |
| CheckTracepoint | attach trace_raw_tp + arg | btf_trace_<tp> argument types | — | Checking error | `attach_unknown` | Blocked since policy 2 |
| CheckKFields | kfield | CO-RE field exists, is not a bitfield, matches width/sign | — | Checking error | `kfield_unknown` | Blocked since policy 2 |
| HasBTFFeature | btf | Kernel accepts BTF feature | `btf_feature_unknown` | `btf_feature_unknown` | `btf_feature_unknown` | Blocked |
| Loader `btf_rewrite` declaration (§8) | btf | Whether loader rewrites unsupported features; not a query: since policy 3, combine declaration with HasBTFFeature | — | — | Combined with BTF checking | Unsupported feature declared rewrite blocks as btf_rewrite; absent declaration gives btf_feature_unknown (loader rewrites) |
| HasArgTagSemantics | argtag | Verifier interprets argument tag | `arg_tag_unknown` | `arg_tag_unknown` | `arg_tag_unknown` | Blocked |
| Arch | arch | Target architecture (uname) | `arch_unknown` | Checking error | `arch_unknown` | Blocked |
| CheckStructField | ctxfield | pt_regs field offset/size | `ctxfield_unknown` | Checking error | `ctxfield_unknown` | Blocked |
| HasKernelSymbol | attach kprobe / kernel-family mtarget, no aliases for multi | Target and loader alias availability in kallsyms | `attach_symbol_unknown` / `attach_alias_unknown` | Checking error | `attach_symbol_unknown` | Blocked |
| CheckFuncParam | kprobearg, multiplied by mtarget for multi | Target argument n type | `kprobearg_unknown` | Checking error | `kprobearg_unknown` | Blocked |
| UprobeBinary | binary / uprobearg / user-family mtarget / usdtsem / usdtarg notes | Loader's attach binary: hash, symbols, DWARF | `binary_unknown` | `binary_unknown` | `binary_unknown` | Blocked |
| MarksNullableTPArgs | attach trace_raw_tp + struct-pointer arg; since policy 6, not queried for only integer / - args | Whether verifier marks nullable tp_btf arguments and rejects unchecked reads | `arg_nullable_mark_unknown` | Checking error | `arg_nullable_mark_unknown` | Blocked |
| HasTracingHelper | helper for Tracing programs: trace_fentry / trace_fexit / trace_raw_tp; since policy 12 also generic trace_iter (key trace_iter), trace_fmod_ret / generic modify_return (key modify_return). LiveCaps loads call-helper probes on bpf_map_elem / bpf_modify_return_test | Helper usable for this attach type; kernel tracing_prog_func_proto varies with expected_attach_type | `helper_unknown` | Checking error | Optional; fall back to HasHelper with the same verdict rule | Continues |
| AllowsMapField | MapFields (§7) | Program type may use maps with bpf_timer / bpf_spin_lock in values | `map_field_unknown` | Checking error | `map_field_unknown` | Continues |
| HasAttachType | Generic UAPI attach, multi trace_kprobe_multi / trace_uprobe_multi, and non-- ctxaccess attach type; once per (program,attach type) | Kernel accepts expected_attach_type for this program type. For sockmap sk_skb/sk_msg, also creates/closes a link to an empty sockmap; EINVAL means false (links require ≥6.10: 6.6 accepted load but failed attach loudly); BPF_PROG_ATTACH is not queried. Multi also probes link creation: kprobe.multi to bpf_fentry_test1; uprobe.multi to an uncalled function in the probe process's executable, PID-filtered to self, then closes. EOPNOTSUPP / missing mechanism means false: without CONFIG_FPROBE load may pass but link fail. Other errors (missing bpf_fentry_test1, insufficient link privileges) are Unknown, permitting later loud attach failure | `attach_type_unknown` | Checking error | `attach_type_unknown` | Continues. With loader sockmap_attach:prog_attach (§8), false for sk_skb/sk_msg does not produce attach_type because BPF_PROG_ATTACH needs no sockmap link |
| HasAttachTarget | Generic valued targets, except static sk_skb/sk_msg/struct_ops map: answers (§4) | Function / tracepoint / iterator / LSM hook / symbol / map / program exists | `attach_target_unknown` | Checking error | `attach_target_unknown` | Continues |
| AllowsCtxAccess | ctxaccess | Verifier accepts field access (read/write, width) for program/attach type | `ctx_access_unknown` | Checking error | `ctx_access_unknown` | Continues |
| CheckTracepointField | tpfield / trace_tp | Offset, size and signedness in target tracefs events/<cat>/<event>/format | `tpfield_unknown` | Checking error | `tpfield_unknown` | Blocked since policy 9. **tracefs requires root on measured 7.1.8 (mode 700)**; non-root loaders use root-recorded caps, tracepoint_fields from ebpf-caps 5 (§11) |
| CheckStructOpsMember | structop + retsig + farg / trace_struct_ops | Target BTF bpf_struct_ops_<struct> exists, member is a function pointer, matching FUNC_PROTO argument count / return (including void) / argument types | `structop_unknown` | Checking error | `structop_unknown` | Blocked since policy 9 |
| CheckExtTarget | extret + extarg / freplace | Loader-supplied replacement-target program has global-linkage BTF FUNC with matching count / argument / return types; target is a loader input, like uprobe binary | `ext_target_unknown` | Checking error | `ext_target_unknown` | Blocked since policy 9; recorded caps has no replacement target (§11) |
| CheckKfunc | kfunc | Target BTF FUNC/FUNC_PROTO matches return/count/types, including integer width/sign, bool and pointee after typedef/qualifier stripping. No bpf_kfunc DECL_TAG required; vmlinux only, module kfuncs absent | `kfunc_sig_unknown` | Checking error | `kfunc_sig_unknown` | Blocked since policy 12 |
| HasKfuncLoad | kfunc with matching prototype | Verifier acceptance of that kfunc in a finite canonical profile of actual-ELF section / flags / attach / context. Load-only, no attach or test run | `kfunc_allowed_unknown` | Checking error | `kfunc_allowed_unknown` | Continues on Unknown; definitive target-kfunc refusal blocks as kfunc_allowed (policy 13; profile table covers ten program types as of policy 14) |
| CheckTracepointBuffer | tpbuf | Target BTF btf_trace_<name> FUNC_PROTO has void return, data void pointer and argument 0 pointing to signed INT size 4. Qualifiers identified through depth 32; later unused arguments not compared | `attach_unknown` | Checking error | `attach_unknown` | Both Unknown and mismatch block. Identifying const type does not prove writable capacity; writable_size remains a kernel attach boundary |
| CheckSyscallArg | sysarg / ksyscall | sys_enter tracefs declaration, or BTF __do_sys FUNC_PROTO when event absent. Existing integer/ptr queries unchanged. strptr requires depth-1 char pointer through typedef/qualifiers; char** / void* / unsigned char* / array mismatch, unknown alias is Unknown. unsigned-long size/signed appearance is not type evidence | `sysarg_unknown` | Checking error | `sysarg_unknown` | Blocked, including unreadable tracefs. Non-root loaders use independent root-recorded caps-9 strptr answers; ptr/i64 answers cannot substitute |

Requirements.KfuncProfile(program,name) returns an immutable value after matching the unique kfunc row against the actual-ELF private snapshot. Hand-parsed, missing, duplicate, modified or unsupported profiles give ErrUnknown. This API prevents guessing caps keys from public Program/Attach values; it does not authenticate compiler output or protect later caller changes to ProgramSpec.

## 6. Unmet kinds and BlocksLoad

Unknown kinds end in `_unknown`. BlocksLoad means loading must stop.
**Every definite mismatch blocks. Unknown blocks when unchecked loading could silently misread values or allow silent loader rewriting.** Reasons for continuing Unknown are explicit: verifier / loader rejection must be loud. If that cannot be justified, classify it as a **fail-open candidate** for a policy decision.

| Kind | Unknown | BlocksLoad | Unmet condition | Reason |
|---|---|---|---|---|---|
| `program_type` | no | yes | Program type absent; skip that program's helper checks | Definite mismatch |
| `helper` | no | yes | Helper unavailable | Definite mismatch |
| `helper_unknown` | yes | no | Helper availability undecidable; cilium v0.22 cannot probe Extension / LSM / StructOps / Tracing helpers, while LiveCaps tracing_helpers gives definite Tracing answers | May continue: unusable helpers are loudly rejected by the verifier, measured on three targets: cannot use helper / unknown func on 6.6, or invalid func for nonexistent numbers |
| `attach` | no | yes | Attach target absent or wrong: tcx unavailable, fexit signature, fentry FUNC, tracepoint type, kprobe symbol | Definite mismatch |
| `attach_tcx_unknown` | yes | no | tcx link availability undecidable | May continue, **not measured**, based only on cilium v0.22 source: link.AttachTCX in link/tcx.go:29 only creates a tcx link and has no legacy-tc fallback. All three targets had tcx, so failure on a kernel without it was not observed |
| `retsig_unknown` | yes | yes | fexit signature undecidable | Wrong signatures can pass the verifier and silently misread values |
| `farg` | no | yes | fentry argument is not a struct pointer or points to a different struct | Definite mismatch: a plain fentry pointer can silently read another struct's layout |
| `farg_unknown` | yes | yes | fentry argument type undecidable | Wrong types can pass the verifier and silently read another struct; blocked since policy 5, like retsig_unknown |
| `attach_func_unknown` | yes | no | fentry / fexit FUNC undecidable | May continue: cilium loudly rejects fentry to nonexistent functions at load, measured on three targets as fentry … not supported |
| `arg_nullable_unknown` | yes | no | Tracepoint argument nullability undecidable | Per struct-pointer argument index since policy 6. Emitted **only on targets that mark nullable arguments (nullable_args true)**: 7.1.8 / 6.12.111 reject unchecked reads. Non-marking 6.6.157 blocks as arg_nullable; undecidable marking blocks as arg_nullable_mark_unknown |
| `arg_nullable` | no | yes | Verifier does not mark nullable tp_btf arguments (6.6 lacks raw_tp_null_args); per struct-pointer argument index, not attaches containing only unread - / integer arguments since policy 6, which have no references requiring protection and were accepted on three kernels | The verifier accepts unchecked reads and may remove even program-written NULL checks as dead branches. Runtime outcome of reading a NULL argument (zero or kernel NULL dereference) is **unverified**. An earlier silent-zero claim was only a prediction; its attempted runtime experiment was cancelled. The diagnostic states only the established verifier behavior |
| `arg_nullable_mark_unknown` | yes | yes | Cannot determine whether verifier marks nullable arguments; per struct-pointer argument index since policy 6 | Cannot exclude a non-marking target; same risk as arg_nullable |
| `kfield` | no | yes | CO-RE field missing or wrong width/sign | Definite mismatch |
| `attach_unknown` | yes | yes | Tracepoint argument types undecidable | Cannot rely on verifier rejection of wrong types; blocked since policy 2 |
| `kfield_unknown` | yes | yes | CO-RE field undecidable | cilium represents missing fields with a poison result and nil error, and does not compare width/sign. An unchecked width mismatch can survive load; blocked since policy 2 |
| `btf_feature` | no | yes | Kernel rejects BTF feature | Definite mismatch |
| `btf_feature_unknown` | yes | yes | BTF feature undecidable | A loader can silently rewrite BTF and succeed, so load acceptance is not evidence |
| `btf_rewrite` | no | yes | Loader rewrites a BTF feature used by this ELF | Definite mismatch |
| `arg_tag` | no | yes | Verifier does not interpret argument tag | Definite mismatch |
| `arg_tag_unknown` | yes | yes | Tag semantics undecidable | If tags are ignored, unchecked dereferences can pass |
| `map_type` | no | yes | Map type absent; includes innermap inner kind, with Program naming outer map and Name the inner type | Definite mismatch |
| `arch` | no | yes | Architecture differs | Definite mismatch |
| `arch_unknown` | yes | yes | Architecture undecidable | Fixed offsets can read a different register |
| `ctxfield` | no | yes | pt_regs offset/size differs | Definite mismatch |
| `ctxfield_unknown` | yes | yes | pt_regs field undecidable | Fixed offsets can read a different register |
| `attach_symbol_unknown` | yes | yes | kprobe target symbol undecidable | Cannot exclude loader retargeting to an alias |
| `attach_alias` | no | yes | Loader alias such as __x64_X exists; failed X attach may silently retry it | Definite mismatch |
| `attach_alias_unknown` | yes | yes | Alias undecidable, e.g. unknown target-architecture alias rule | Cannot exclude silent retargeting |
| `kprobearg` | no | yes | kprobe argument type differs | Definite mismatch |
| `kprobearg_unknown` | yes | yes | kprobe argument type undecidable | Wrong types silently misread values |
| `binary` | no | yes | uprobe binary SHA-256 differs | Definite mismatch |
| `binary_unknown` | yes | yes | Binary undecidable | All Unknown uprobe checks block |
| `uprobe_symbol` | no | yes | Binary symbol absent or not unique | Definite mismatch |
| `uprobe_debug_build_id` | no | yes | Separate DWARF GNU build ID differs from main binary | Do not authorize reads using types from another build |
| `uprobe_debug_crc` | no | yes | Separate DWARF CRC32 differs from main binary debuglink | Do not use corrupt type evidence even with a matching build ID |
| `uprobearg` | no | yes | uprobe argument type differs | Definite mismatch |
| `uprobearg_unknown` | yes | yes | uprobe argument type undecidable | Same type-mismatch risk |
| `uprobearg_abi` | no | yes | Target is not SysV: CU DW_AT_language is Go (ABIInternal) or subprogram DW_AT_calling_convention is not DW_CC_normal | uprobe.arg reads SysV registers; a Go function previously passed checking and returned a different value. Target a cgo //export C entry instead |
| `uprobearg_abi_unknown` | yes | yes | CU DW_AT_language missing or not in the C-family table, e.g. Rust / Objective-C | Calling convention cannot be established; block |
| `map_field` | no | yes | Program type cannot use a map with bpf_timer / bpf_spin_lock value fields | Definite mismatch |
| `map_field_unknown` | yes | no | Map-field policy undecidable | May continue: forbidden combinations are loudly rejected by the verifier, measured on three targets for timers and spin locks |
| `attach_type` | no | yes | Kernel rejects expected_attach_type for the program type, including inability to create sockmap links for sk_skb/sk_msg | Definite mismatch named before load. Loader-dependent since policy 12: not emitted for sk_skb/sk_msg under sockmap_attach:prog_attach (§8) |
| `attach_type_unknown` | yes | no | expected_attach_type undecidable, e.g. missing query or BTF-dependent attach type | May continue: unsupported expected_attach_type is loudly rejected with -EINVAL by BPF_PROG_LOAD bpf_prog_load_check_attach, not silent value corruption. **Not measured**; based on kernel 7.1.8 kernel/bpf/syscall.c source |
| `attach_target` | no | yes | Valued target absent from target kernel | Definite mismatch |
| `attach_target_unknown` | yes | no | Target undecidable. LiveCaps answers iter / rawtp / func / lsm using vmlinux BTF and tp using tracefs event directories; missing/unreadable directories are Unknown. rawtp/func absent from vmlinux remain Unknown because they may be in modules; other kinds Unknown | May continue: missing functions / tracepoints / hooks fail attach loudly **only for loaders without retargeting**. cilium v0.22 retargets only kprobe/kretprobe, which use §4 families and attach_alias, not generic rows. **Attach-failure behavior not measured** in this policy definition |
| `ctx_access` | no | yes | Verifier rejects context-field access | Definite mismatch |
| `ctx_access_unknown` | yes | no | Context-field access undecidable | May continue: verifier loudly rejects invalid bpf_context access. Measured on 7.1.8: ctxprobe negative controls 23 / 24 rejected; one accepted control exposed an omission from the writable-field table |
| `uretprobe_abi` | no | yes | Return-probe target is not SysV: Go CU language or non-DW_CC_normal convention | probe.retval reads SysV rax; Go ABIInternal uses RBX and other registers for multiple results, creating the same silent-value risk as uprobe. Target a cgo //export C entry |
| `uretprobe_abi_unknown` | yes | yes | Target CU language missing/non-C-family, or target subprogram absent from DWARF | Calling convention undecidable; block |
| `tpfield` | no | yes | Tracepoint event field absent from target tracefs format, or wrong offset/size/sign | Definite mismatch: fixed-offset reads can pass the verifier and silently read a different field |
| `tpfield_unknown` | yes | yes | Field undecidable: unreadable tracefs (non-root / absent / module event), or missing tracepoint_fields recording | Same risk as kfield_unknown; **non-root loaders use root-recorded caps** (§11) |
| `ext_target` | no | yes | Replacement target function not global, or mismatched argument count/types/return | Definite mismatch: kernel can accept wrong argument signedness / return width and silently misread values |
| `ext_target_unknown` | yes | yes | Target undecidable: missing supplied program / BTF / function, or recorded caps which does not record replacement programs | Block like uprobearg_unknown; ext requires live checking with the replacement-target program (§11) |
| `structop` | no | yes | struct_ops member absent, not a function pointer, or mismatched count/types/return | Definite mismatch: returning a value from a void member or reading wrongly typed arguments can pass the verifier |
| `structop_unknown` | yes | yes | Member undecidable: no BTF or struct absent from vmlinux, e.g. module struct_ops | Block like farg_unknown |
| `usdt_probe` | no | yes | No provider:name point in notes (Name is point), semaphore mismatch (Name <provider>:<name> at pc 0x…), or point count exceeds compiler spec-map __ebpf_usdt_spec_<program> max_entries / schema max_points (Name point, detail count/limit, added within policy 11). Count check applies only when the program has the spec map, i.e. uses ebpf.usdt.arg | Definite mismatch: absent points or missing ref_ctr_offset can attach successfully but silently produce no events. A point outside spec-map capacity cannot fetch its arguments, silently dropping with st = −ENOENT |
| `usdtarg` | no | yes | Point has fewer arguments than requested n, or argument n size/sign differs; names point pc | Definite mismatch: wrong width/sign silently misreads values, like uprobearg |
| `usdtarg_unknown` | yes | yes | Unreadable point argument description: SIB / %rip / unknown register / missing @ / malformed note | Loader-written specs may silently supply wrong values if the location is unreadable; block like uprobearg_unknown |
| `usdt_loader` | no | yes | Loader declares no USDT attach (usdt_attach:none, cilium v0.22) or cannot pass ref_ctr_offset for required semaphore points (plain) | Definite mismatch: **silently zero events**; kernel does not raise the semaphore without ref_ctr_offset, so the point does not execute |
| `usdt_loader_unknown` | yes | yes | No usdt_attach declaration: bml-libbpf-v1.7 preset, older recordings, or undeclared loader file | Unknown attachment behavior can silently produce zero events; fail closed |
| `kfunc_sig` | no | yes | kfunc missing from target BTF (message not found in the target BTF), or mismatched FUNC_PROTO return/count/types | Definite mismatch: **integer width/sign-only differences can silently pass the verifier**. Missing functions and pointer/integer mismatch also fail verifier loudly, but checking names them before load, as required since v1.8.0 |
| `kfunc_sig_unknown` | yes | yes | Signature undecidable: unreadable BTF or missing kfunc_protos recording | Could silently accept a wrong-width declaration |
| `kfunc_allowed` | no | yes | Prototype-matching kfunc definitively rejected by name in its exact profile | Name missing permission before load |
| `kfunc_allowed_unknown` | yes | no | Missing recipe/query/actual-ELF profile, or undecidable probe dependency/environment | Kernel rejects this class loudly at load. fsession and struct_ops have no recipe and do not check permission |
| `sysarg` | no | yes | Syscall argument n missing or width/sign/pointer differs | Definite mismatch: wrong reads can pass the verifier and silently read another value; the ordinary function calling convention's fourth argument position is the user's return address |
| `sysarg_unknown` | yes | yes | Argument undecidable: unreadable tracefs (non-root), neither event nor __do_sys_<name> exists, unresolved BTF type name, or missing syscall_args recording | Block like tpfield_unknown; **non-root loaders use root-recorded caps** (§11) |
| `lsm_cgroup_loader` | no | yes | Loader cannot load lsm_cgroup (lsm_cgroup_load:none; cilium v0.22 loads attach_btf_id 0 without resolving hook BTF id and kernel rejects) | Definite mismatch: stop before load rather than report precheck success followed by loud load failure |
| `lsm_cgroup_loader_unknown` | yes | yes | No lsm_cgroup_load declaration, including bml-libbpf-v1.7 preset or ebpf-caps ≤7 recordings | Same boundary; fail closed like usdt_loader_unknown |
| `fsession_loader` | no | yes | Loader cannot load fsession (fsession_load:none; cilium v0.22 says Tracing programs must provide btf_id, though attach uses raw-tracepoint open) | Definite mismatch; same pre-load boundary |
| `fsession_loader_unknown` | yes | yes | No fsession_load declaration | Same boundary |
| `ksyscall_loader` | no | yes | Loader does not attach to prefixed wrapper (ksyscall_attach:none; cilium v0.22 attaches the plain section suffix and fails loudly) | Definite mismatch; same pre-load boundary |
| `ksyscall_loader_unknown` | yes | yes | No ksyscall_attach declaration | Same boundary |

**Uprobe calling convention (policy 4)**: before argument checking, inspect DW_AT_language of the compilation unit containing the target DWARF subprogram. Use standardized DWARF values, not the producer string; producer text is diagnostic context only.

| DW_AT_language | Verdict |
|---|---|
| C89 (0x01), C (0x02), C99 (0x0c), C11 (0x1d), C17 (0x2c), C++ (0x04), C++03 (0x19), C++11 (0x1a), C++14 (0x21), C++17 (0x2a), C++20 (0x2b) | SysV: continue to argument count/type checking |
| Go (0x16) | `uprobearg_abi` (ABIInternal) |
| Missing / other | `uprobearg_abi_unknown` |

- A present subprogram DW_AT_calling_convention other than DW_CC_normal (1) gives uprobearg_abi.
- Count and position exclude formal_parameter entries with true DW_AT_variable_parameter, such as Go results ~r0.
- **uretprobe (policy 8)** uses the same table for each attach row even without argument rows, including childless/zero-argument subprograms. Go gives uretprobe_abi; missing/other language or absent DWARF subprogram gives uretprobe_abi_unknown.
- C++ artificial this counts as a real argument (RDI under SysV). Selection uses the main symbol address, not DWARF name, so mangled-name differences alone do not block. **Actual C++ member-function attach is unmeasured**; extern "C" functions were accepted in the calling-convention fixture.

## 7. MapFields (map-field usage)

Besides rows, checking validates per-program use of maps whose values contain bpf_timer / bpf_spin_lock, derived from ELF instructions/BTF, **not section-only parsing**.

- For each program FUNC, collect `.maps` maps referenced by ld_imm64 relocations, following subprogram pseudo calls and function addresses. From `.BTF` `.maps` DATASEC VAR, follow the map-definition struct's pointer value member, recording direct value-struct members whose type names are bpf_timer / bpf_spin_lock.
- States: derived, not_derived (Parse without ELF), failed. Failure includes map references without relocation, `.maps` offsets not beginning at a map symbol, missing/corrupt BTF, unknown BTF kinds, map without VAR, non-struct map definitions, and non-pointer value members. **Failure is not an empty table.**
- If derived, ask AllowsMapField for each usage: false gives map_field, Unknown map_field_unknown. Otherwise emit map_field_unknown for each potentially record-valued map row: value begins record: and kind is not ringbuf / perf_event_array / user_ringbuf. user_ringbuf exclusion dates to policy 11: its record identifies samples rather than stored map values.

## 8. Loader rules

Caps has two parts:

- **Kernel facts**: §5 answers, independent of loader for the same kernel and privileges.
- **Loader declarations**: library behavior, which can differ on the same kernel. Loaders supply an explicit declaration of their behavior; legacy callers with no declaration use the cilium v0.22 defaults below.

Checking requires these properties. Where a loader lacks a property, checking compensates for declared behavior (L2) or fails closed (L4).

| Rule | Required loader property | Use in checking |
|---|---|---|
| L1 Preserve BTF | Do not rewrite/drop features in btf rows | **Kernel BTF-feature support × loader btf_rewrite declaration**, rewrite vs keep: rewrite silently replaces unsupported features; keep passes them unchanged for loud kernel rejection. If a used feature is unsupported and declared rewrite, block as btf_rewrite (since policy 3; previously one btf_rewrites query). **The declaration covers only four intentional rewrites used by verdict policy.** Other libbpf rewrites (FUNC→TYPEDEF, FLOAT→empty STRUCT, VAR/DATASEC, ? DATASEC names, ENUM kflag) occur when the kernel lacks the corresponding feature, blocked by btf_feature. A loader probe falsely reporting absence, including libbpf's process-wide caching of unprivileged probe failures as MISSING, is a **loader-guard obligation**, not a declaration field. The cilium-backed reference loader compares its four probes with its actual BTF marshaling options; disagreement becomes blocking Unknown |
| L2 Do not retarget | Attach only to the required name | Retargeting loaders declare per-architecture kprobe_alias_prefix. Check proves alias absence (attach_alias); missing architecture gives blocking attach_alias_unknown; empty prefix means no retargeting. **Multi kernel families require no retargeting** and never query aliases: cilium v0.22 KprobeMulti and libbpf multi do not retry aliases. A multi-retargeting loader cannot claim L2; the prefix declaration applies only to single kprobe/kretprobe |
| L3 Uprobe binary | Attach to the same inode whose hash was checked | Check reads caller-supplied uprobe_binary. With uprobe_reopens_path, the caller must ensure reopened paths identify that file; this declaration is informational, not checking input |
| L4 Missing CO-RE field | Do not silently poison missing-field relocations | For core_poisons_missing_field loaders, kfield checking is the sole guard. kfield_unknown blocks since policy 2; policy 1 allowed it |
| L5 Map BTF | Do not recreate maps without their BTF | Not a checking input. **Compiler output alone cannot ensure this**: cilium strips/retries after ENOTSUPP/EINVAL; libbpf v1.7.0 strips without attempting 12 map types (perf_event_array, cgroup_array, stack_trace, *_of_maps, devmap/devmap_hash, cpumap, xskmap, sockmap/sockhash, queue, stack, arena) and retries without BTF after any creation error. At the original audit, three supported kinds overlapped that list: stack_trace/perf_event_array already used untyped key_size/value_size, but devmap was typed. Kernel devmap map_check_no_btf rejected typed BTF with ENOTSUPP on three targets; cilium silently stripped/retried and libbpf stripped without trying. devmap was therefore changed to untyped definitions. prog_array is also untyped because 6.x rejects its typed definition |

**Per-loader declarations**: values describe the loader, not the implementation language. The legacy default is cilium v0.22.

| Declaration | cilium v0.22 | Evidence (cilium v0.22.0 source / measurements) | Raw libbpf v1.7.0 (source and 7.1.8, not a preset) | bml-libbpf-v1.7 (guarded bpf-mlir-loader) | aya | cilium-v0.22-usdt (explicit USDT glue) | cilium-v0.22-progattach (explicit BPF_PROG_ATTACH glue) | cilium-v0.22-ksyscall (explicit syscall-wrapper glue) | cilium-v0.22-usdt-ksyscall (existing glue combined) |
|---|---|---|---|---|---|---|---|---|---|
| `btf_rewrite` (L1, feature → rewrite / keep) | All four `rewrite`: unsupported func_global linkage, decl_tag, type_tag, enum64; fixed by tests | btf/marshal.go:32-40 KernelMarshalOptions flags become true on failed kernel probes; all four false on measured 7.1.8 | Raw loader is nonconforming: whole-BTF discard and undeclared rewrites below. All four are rewrite | All four `keep`: guard stops before loading predicted rewrites; it never installs rewritten BTF. Whole-BTF discard is caught after load. Guard predict / sanitize / btf_dropped measured across 3 kernels × 4 privilege modes | Unverified | Same as cilium: all four rewrite | Same as cilium: all four rewrite | Same as cilium: all four rewrite | Same as cilium: all four rewrite |
| `kprobe_alias_prefix` (L2) | `x86_64` → `__x64_`; only measured architectures declared; others unknown/blocking | link/kprobe.go:178-181 / 194-197 retry PMU and tracefs ENOENT/EINVAL with PlatformPrefix()+symbol; internal/linux/platform.go:12 has GOARCH prefixes including unmeasured arm64 | No retargeting; predicted x86_64 → empty string | `x86_64` → `""`, no retargeting, from source/host 7.1.8. Three-kernel attachment unmeasured | Unverified | Same as cilium, `x86_64` → `__x64_` | Same as cilium, `x86_64` → `__x64_` | Same as cilium, `x86_64` → `__x64_`; AttachKsyscall verifies attached name afterward | Same as cilium, `x86_64` → `__x64_` |
| `uprobe_reopens_path` (L3) | true | link/uprobe.go:176 OpenSafeELFFile(ex.path) resolves symbols; :363 passes path to tracefs. Replacement of a 9p file was observed | true | true | Unverified | true | true | true | true |
| `core_poisons_missing_field` (L4) | true | btf/core.go:367-371 returns poison:true rather than error for missing non-existence-check relocations; INT width/sign not checked | true; also silently adjusts unsigned load width | true | Unverified | true | true | true | true |
| `usdt_attach` (USDT) | `none` | elf_sections.go recognizes usdt+ as kprobe type only; link has no USDT note/spec-map/ref_ctr_offset attach support | Unverified: bpf_program__attach_usdt reads notes and supplies semaphore ref_ctr_offset, but libbpf's internal spec layout is not this document's contract | Not declared: unknown, blocks as usdt_loader_unknown until bml measures and declares it | Unverified | `ref_ctr`: AttachUSDT writes each note point's spec to compiler map index i and passes Executable.Uprobe options Address=file offset, Cookie=i, RefCtrOffset=semaphore file offset when present; see contract below, measured on 7.1.8 as root | `none`, Same as cilium | `none`, Same as cilium | `ref_ctr`, retaining AttachUSDT obligations |
| `sockmap_attach` (loader mechanism) | `link` | link.AttachRawLink uses BPF_LINK_CREATE; sockmap links require ≥6.10, while 6.6 loads but fails attach | Unverified: bpf_program__attach_sockmap uses links, version not measured | Not declared, same verdict as link; bml must measure | Unverified | `link` | `prog_attach`: caller uses AttachSockmapProgAttach / link.RawAttachProgram / BPF_PROG_ATTACH (since 4.17). **Explicit preset selection, not automatic fallback** | `link` | `link` |
| `lsm_cgroup_load` (loader mechanism) | `none` | findProgramTargetInKernel does not recognize (LSM,AttachLSMCgroup), loading attach_btf_id 0; kernel rejects | Unverified | Not declared, blocking lsm_cgroup_loader_unknown | Unverified | `none` | `none` | `none` | `none` |
| `fsession_load` (loader mechanism) | `none` | Cannot load: Tracing programs must provide btf_id; attachment itself uses link.AttachTracing raw-tracepoint open | Unverified | Not declared, unknown | Unverified | `none` | `none` | `none` | `none` |
| `ksyscall_attach` (loader mechanism) | `none` | Attaches kprobe to plain ksyscall/<name> suffix such as getppid, failing loudly, rather than __x64_sys_<name> wrapper | Unverified; bpf_program__attach_ksyscall prefixes names, suggesting prefix if declared | Not declared, unknown | Unverified | `none` | `none` | `prefix`: caller uses AttachKsyscall. The loader maps kernel uname through the syscall-prefix table used by checking. After attach, link-info kprobe function name must match wrapper; otherwise close/error. **Explicit selection, not automatic fallback** | `prefix`, retaining wrapper/attached-name checks |
| BTF type_tag rewrite (L1 consequence) | `rewrite`: on kernels without type_tag (<5.17), removes TYPE_TAG and creates a map without a kptr-marked value field; kptr.xchg program then fails verifier load loudly | btf/marshal.go ReplaceTypeTags. Format-13 btf type_tag checking blocks first through btf_feature / btf_rewrite, including Unknown | Unverified | `keep`: kernel rejects loudly | Unverified | Same as cilium | Same as cilium | Same as cilium | Same as cilium |
| Map BTF (L5 observation, not declaration) | Strip BTF and retry creation on ENOTSUPP / EINVAL | map.go:647-651; 6.x rejects typed prog_array key/value, followed by silent BTF stripping | Strip without trying for 12 map types; retry without BTF on any creation errno | Guard checks map BTF ids against predictions, blocking as map_btf | Unverified | Same as cilium | Same as cilium | Same as cilium | Same as cilium |
| Map max_entries rewrite (informational, not declaration) | **cpumap max_entries 0 or above possible CPUs is replaced by possible-CPU count**, like perf_event_array 0→CPU count. No Unmet: updates for impossible CPU keys fail under any loader (-E2BIG / -ENODEV), without changing redirect semantics | map.go:174-183 fixupMagicFields CPUMap; schema 64 became 20 on a host with 20 possible CPUs, observed as root | Unverified | Unverified; loader-specific behavior to be measured | Unverified | Same as cilium | Same as cilium | Same as cilium | Same as cilium |

aya has neither been inspected nor measured. Any loader using checking must supply declarations matching its actual behavior; a checking process requires an explicit declaration input.

cilium-v0.22-usdt-ksyscall combines the existing USDT and ksyscall presets. Relative to cilium v0.22, only usdt_attach:ref_ctr and ksyscall_attach:prefix change. Callers must satisfy both existing AttachUSDT and AttachKsyscall obligations. This introduces neither new glue nor automatic fallback. Do not silently reinterpret a recording carrying another loader declaration as this preset.

**Raw libbpf v1.7.0 does not satisfy §8**, based on source inspection and host 7.1.8 measurements:

- L1: if the kernel rejects BTF for any reason, it **discards all BTF and continues loading** (`BTF is optional, ignoring`, pr_info), even when all feature answers say supported. It also rewrites outside the four declared features and process-caches every probe failure as MISSING; an unprivileged process observed all 14 features as MISSING.
- L2: attach_kprobe / bpf_program__attach_kprobe_opts preserve the name; only attach_ksyscall adds a prefix. A declaration should therefore use an empty kprobe_alias_prefix for the architecture.
- L3: reopens binary_path using elf_open; names without `/` are searched in PATH, so uprobe_reopens_path=true.
- L4: poisons missing fields and silently changes load width when both INT types are unsigned but widths differ. Policy-2 kfield checking blocks first.
- L5: strips BTF without trying the 12 map types listed above.
- Other potential content changes: replacing probe_read_{kernel,user} with probe_read when FEAT_PROBE_READ_KERN is MISSING (invalidating the rationale for permitting helper_unknown), removing expected_attach_type, removing internal-map MMAPABLE or omitting internal-map creation on MISSING features.

**Conformance conditions**: a libbpf loader may claim its declaration only with fixed options and pre/post-load guards. The versioned bml-libbpf-v1.7 preset describes guarded bpf-mlir-loader, not raw libbpf; its values were measured across three kernels and four privilege modes.

- Before load: ELF BTF kinds must be within btf-row features, all ELF symbols have DEFAULT visibility, and no externs exist. Stop if libbpf feat_supported differs from checking answers, including cached unprivileged MISSING results.
- After load: a kernel-loaded BTF fd must exist (no whole-BTF discard); readback must match prediction; func_info / line_info counts, map BTF ids and internal-map flags must match.
- Fix memlock, print, BPF token, pin and automatic-attach options.

**MUST — compare prediction with actual behavior**: declarations predict loader behavior. **Every loader must compare declared and actual behavior and stop on disagreement**, fail closed. The cilium-backed reference loader compares BTF rewrite predictions with actual marshaling options; libbpf uses the guards above.

**usdt_attach declaration and USDT contract**: these are loader obligations outside checking; checking uses usdt_loader* and §4's USDT checks.

- Values: none (no USDT attachment), plain (uprobe attachment without semaphore ref_ctr_offset), ref_ctr (supplies semaphore ref_ctr_offset). **Absent means unknown**, blocking USDT ELF through usdt_loader_unknown. **bml-libbpf-v1.7 does not declare usdt_attach** and blocks USDT until bml measures and declares support.
- A ref_ctr loader must, for each note point: (1) correct pc using actual `.stapsdt.base` section address minus note base (prelink), then translate through PT_LOAD to file offset; (2) write argument-location spec at point index i in the program's spec map; (3) attach the hashed file's point as a uprobe with cookie i (L3); (4) pass semaphore file offset as ref_ctr_offset where present. Layout/name contract is below; these clarifications do not change format-12 rows.
- plain may attach only usdtsem none points. Without ref_ctr_offset a semaphore point's counter is not raised and the point never runs: **silently zero events**.
- i is **note order** of matching provider:name points across `.note.stapsdt` sections, starting at 0. More points than spec-map max_entries / schema max_points blocks as usdt_probe (§6).

**USDT spec map is a bpf-mlir contract**, distinct from libbpf's unstable internal __bpf_usdt_specs / struct __bpf_usdt_spec in usdt.bpf.h. bml must populate this spec rather than use libbpf's USDT layout.

- Compiler emits an array map per usdt program using ebpf.usdt.arg, named `__ebpf_usdt_spec_<program>`, with ELF `.maps` symbol and requirements row `map __ebpf_usdt_spec_<p> array 2 u32 record:ebpf_usdt_spec <max_points> 0`, not written in schema. Key is u32 point index i; max_entries is schema max_points. BTF value struct ebpf_usdt_spec is 192 bytes. A program without ebpf.usdt.arg emits no spec map and needs no spec writes.
- Before attach, write point i's spec at key i through BPF_MAP_UPDATE_ELEM; pass **cookie i** to that point's uprobe. Program uses bpf_get_attach_cookie to look up the spec. Unwritten array slots are zero (kind 0, st=−EINVAL); out-of-range cookies yield NULL lookup and st=−ENOENT.
- Each little-endian 192-byte value contains twelve 16-byte argument specs at offset 16×(n−1), n 1–12:

  | Offset within spec | Width | Name | Value |
  |---|---|---|---|
  | +0 | u8 | `kind` | 0 absent/unreadable note argument (read gives st=−EINVAL), 1 const ($imm), 2 reg (%reg), 3 deref (off(%reg), off optional) |
  | +1 | u8 | `reg` | reg/deref register index from usdtreg table below; 0 for const |
  | +2 | 6 bytes | — | 0 |
  | +8 | i64 | `off` | Constant $imm, dereference offset, or 0 for reg |

  Program reads const from off, reg from the register value, deref from W/8 bytes of user memory at register+off via probe_read_user. W is schema params width, matched by usdtarg to note `<±size>@`. The result uses low W bits with declared signedness. Note size is not in the spec because checking establishes agreement. Arguments above 12 and unread argument locations may use kind 0.
- **usdtreg table**: abi/uapi.tsv row kind usdtreg is generated by ebpf-abigen extract from libbpf tools/lib/bpf/usdt.c x86_64 reg_map order, excluding rip. Offsets come from UAPI struct pt_regs; kernel names come from vmlinux BTF pt_regs fields at those offsets. **Do not hand-edit it.** Width aliases share an index; declared width/sign determine truncation. High-byte names such as %ah and %rip are absent and block as usdtarg_unknown.

  | Index | UAPI pt_regs | Kernel pt_regs (ctxfield) | Offset | Note names |
  |---|---|---|---|---|
  | 0 | rax | ax | 80 | rax, eax, ax, al |
  | 1 | rbx | bx | 40 | rbx, ebx, bx, bl |
  | 2 | rcx | cx | 88 | rcx, ecx, cx, cl |
  | 3 | rdx | dx | 96 | rdx, edx, dx, dl |
  | 4 | rsi | si | 104 | rsi, esi, si, sil |
  | 5 | rdi | di | 112 | rdi, edi, di, dil |
  | 6 | rbp | bp | 32 | rbp, ebp, bp, bpl |
  | 7 | rsp | sp | 152 | rsp, esp, sp, spl |
  | 8–15 | r8–r15 | r8–r15 | 72, 64, 56, 48, 24, 16, 8, 0 | rN, rNd, rNw, rNb |

  ebpf.usdt.arg lowering reads all table registers at fixed pt_regs offsets and selects by index. Requirements therefore include sixteen `ctxfield <p> pt_regs <kernel name> <offset> 8` rows, checked against target BTF. Reference loaders encode note arguments into this 192-byte layout before attachment.

**Four additional loader declaration fields**, checked through attach_type / lsm_cgroup_loader* / fsession_loader* / ksyscall_loader*:

- sockmap_attach is link (BPF_LINK_CREATE; sk_skb/sk_msg block as attach_type on kernels without sockmap links, e.g. 6.6) or prog_attach (BPF_PROG_ATTACH since 4.17; suppress false attach_type for these program kinds). **Absent is checked like link**, the stricter default, with no Unknown kind. A prog_attach loader must attach to the declared sockmap/sockhash fd using the requirements expected_attach_type and detach with BPF_PROG_DETACH; unlike links, process exit does not detach. The cilium-v0.22-progattach preset requires this explicit attachment and detach behavior.
- lsm_cgroup_load / fsession_load are btf_id (resolve target vmlinux BTF id, bpf_lsm_<hook> / function, and load as attach_btf_id) or none. Absent is unknown/blocking. Development raw-load runners LoadLSMCgroup / LoadFsession implement btf_id; generated default cilium bindings use none.
- **bml-libbpf-v1.7 declares none of these four fields** until measured: lsm_cgroup/fsession/ksyscall block as *_loader_unknown, like undeclared USDT, while sk_skb/sk_msg are checked like link.
- ksyscall_attach is prefix (attach to checked `<prefix>sys_<name>` wrapper) or none; absent is unknown/blocking. **A prefix loader must use checking's naming rule**, the syscall-prefix mapping, based on **kernel machine**, not process architecture (e.g. a 32-bit binary on x86_64 kernel). Unknown machine prefix means no attach, never plain-name fallback. With a retargeting loader (L2), verify attached target name afterward; detach/error on mismatch. The cilium-v0.22-ksyscall preset checks the attached function name through link info after creating the kprobe.

**Multi-probe loader obligation — order and cookies**: each multi family uses one link with Symbols in mtarget i order and **cookie i for name i**. cilium v0.22 uses KprobeMulti/KretprobeMulti KprobeMultiOptions{Symbols,Cookies} or Executable.UprobeMulti/UretprobeMulti UprobeMultiOptions.Cookies. ebpf.probe.target_index reads bpf_get_attach_cookie directly as i. Omitted cookies or reordered targets yield wrong indices or all zero; **checking does not detect this**, since cookies are neither input nor declaration fields. Uprobe multi also retains L3's hashed-binary obligation.

**Loader obligation — .rodata configuration**: set schema .rodata globals before load. Missing-setting detection is loader state outside ELF/declaration checking (§12 globals); checked loaders validate configuration before loading.

**Outside checking** (loader responsibility, explicitly listed rather than silently omitted): kern_version settings, reloads for failed-load logs, func_info record repacking, .rodata BIND_MAP, verifier-log CO-RE-poison explanations, RLIMIT_MEMLOCK, print callbacks, automatic BPF tokens, feature-probe caches, fd duplication, placeholder memfds, internal-map mmap replacement, files read (vmlinux/module BTF, kprobe PMU/tracefs, possible CPUs), map pin/reuse, and automatic attach. **Behavior that can silently change loaded program/map contents must not be left outside checking**: handle it through L1–L5 or conformance guards.

fentry farg accepts struct / i8…u64 / -. For count/struct checking through func_args, replace integers with - in an equal-length list; each integer separately uses func_param index+1 width/sign checking. Mismatch is blocking farg; missing query / Unknown is blocking farg_unknown. Existing format-14/caps-9 queries/keys are retained; older readers treat new integers as struct names and reject by name.

## 9. Policy versions

Verdict policy (Unmet kinds, BlocksLoad, Unknown handling) has its own numeric version. conformance/requirements/VERSION records both format and policy versions. A verdict change raises policy and adds a row below. Other loaders pin the policy version; group related changes rather than fragmenting versions.

| Policy | Change | Impact | Origin |
|---|---|---|---|---|
| 15 | Check integer fentry farg using func_args for structure/count and func_param for width/sign. farg / farg_unknown still block; struct/skip-only inputs unchanged | Correct integer signatures become accepted instead of misidentified as struct names. Wrong width/sign/excess count and missing queries block. Format 14 / caps 9 unchanged; other loaders must copy the same division of checks | Integer fentry arguments |
| 16 | Select exactly one non-declaration subprogram across all CUs whose direct low_pc matches the main binary's unique FUNC/executable-PT_LOAD address; no name/ranges/entry_pc/specification fallback. Separate DWARF is used only without an embedded info section, after GNU build-ID and optional debuglink-CRC checks. New uprobe_debug_build_id / uprobe_debug_crc both block | Prevents declaration types being selected; accepts same-address aliases and correct separate DWARF. The development address-selection survey enumerates all changed inputs. Unknown blocks through existing uprobearg_unknown / uretprobe_abi_unknown. Requirements format 17 unchanged; caps 10 adds uprobe_debug. Existing compressed embedded-DWARF acceptance is not narrowed | Address-based and separate-DWARF checking |
| 1 | Original verdicts before policy versioning, corresponding to the initial §6 table | Baseline | Initial specification |
| 2 | Block kfield_unknown / attach_unknown. For tp_btf, non-marking verifier gives arg_nullable; unknown marking gives arg_nullable_mark_unknown; only marking targets may emit nonblocking arg_nullable_unknown | Blocks tp_btf / CO-RE where KernelTypes or recorded kfields/tracepoint evidence is absent, and where nullable marking is unanswered. Reference live queries answer these on 7.1.8 / 6.12.111, keeping that checked path unchanged. **6.6.157 blocks programs reading tp_btf pointer arguments**. Corpus rawtp_no_btf changes ok→target_rejected | Fail-closed type and nullable checking |
| 3 | Derive L1 rewrites from kernel btf_feature × loader btf_rewrite declaration, replacing btf_rewrites query. Newly permitted: supported kernel feature despite recorded rewrite answer, and absent rewrite query with feature answer (Unknown feature still blocks). Unsupported rewritten features now produce both btf_feature and btf_rewrite, still blocking. Missing loader rule gives btf_feature_unknown (loader rewrites) | Caps format becomes ebpf-caps 2; 1 / btf_rewrites recordings are unreadable and must be regenerated. Other implementations must align with policy 3 | Kernel facts versus loader declarations |
| 4 | Before uprobe argument checking, require C-family CU DW_AT_language: Go ABIInternal / non-normal convention gives uprobearg_abi; missing/other language gives uprobearg_abi_unknown. Do not count formal_parameter entries marked DW_AT_variable_parameter | Newly blocks Go, missing-language and non-C-family targets that previously passed matching type names but could silently read wrong registers. C/C++ targets unchanged | Uprobe calling convention |
| 5 | Check format-8 farg against target FUNC_PROTO; mismatch farg and undecidable farg_unknown both block | New Unmet kinds; ELF without farg unchanged. Missing func_args (e.g. ebpf-caps 2 or bpftool ebpf-target recordings) blocks ELF with farg | Fentry signature checking |
| 6 | Query nullable_args only for attaches with struct-pointer arg rows, and emit arg_nullable / arg_nullable_mark_unknown / arg_nullable_unknown per struct index, saying reads pointer argument <i> | Relaxation: unread - / integer-only tp_btf no longer blocks on non-marking 6.6 or missing/undecidable query. Existing loadable ELF remains loadable. Pointer-containing tp_btf still blocks as before; multiple pointer args can emit the same kind at several indices | Nullable-query scope |
| 7 | Check format-9 generic attach and ctxaccess through attach_types / attach_targets / ctx_access. Definite attach_type / attach_target / ctx_access block; Unknown does not because unsupported types fail BPF_PROG_LOAD with EINVAL, absent targets fail attach, and bad ctx access fails verifier loudly. Retargetable cilium kprobe/kretprobe retain §4 families and attach_alias; return probes use entry-family verdict rules | New kinds; ELF without version-9 rows unchanged. Caps format 4 reads 3/2 with missing new queries as Unknown | Generic attach/context checking |
| 8 | Check each uretprobe target CU language, including when no argument rows exist. Non-SysV Go/non-normal convention gives uretprobe_abi; absent/other language or absent DWARF subprogram gives uretprobe_abi_unknown; both block | Newly blocks Go/non-C/missing-language/missing-DWARF return targets that policy 7 allowed with matching binary hash/symbol. Other ELF and uprobe unchanged | Return-probe calling convention |
| 9 | Format-11 companions: tpfield/tpfield_unknown via tracepoint_fields; ext_target/ext_target_unknown via loader-supplied ext_targets; structop/structop_unknown via struct_ops_members. **All block**, including Unknown, for silent-value risks. trace_lsm farg / trace_perf arch reuse existing rules; families retain generic attach_type/attach_target checks | New kinds; ELF without version-11 rows unchanged. trace_tp blocks with unreadable tracefs (non-root live, missing recording); use root-recorded caps 5 (§11). freplace blocks without target program, including recorded caps. Caps 5 reads 4/3/2, whose missing queries block as Unknown | Field and target-signature checking |
| 10 | Split recorded queries into privilege-dependent load probes and independent BTF/tracefs/kallsyms/uname/file evidence (§10). If load CapEff (run_as or --load-as) differs from probed_as, including absent probed_as, never use dependent recorded answers: --caps --live reprobes as the loader, --caps alone uses Unknown. Independent queries remain recorded. Unmet/BlocksLoad rules unchanged | Newly blocks other-privilege/root recordings used with --caps alone, typically precheck_failed for prog_type Unknown. Non-root tracepoint path uses --caps <root recording> --live: recorded fields plus non-root load probes; CAP_BPF-only reprobe EPERM gives precheck_failed instead of old ok. Same-privilege, --live and direct RecordedCaps without ForLoad unchanged. Caps 6 adds privileged_queries and reads 5–2 | Recorded privilege separation |
| 11 | Format-12 USDT adds five blocking kinds usdt_probe / usdtarg / usdtarg_unknown / usdt_loader / usdt_loader_unknown for silent wrong values or zero events. Multi/innermap reuse existing rules: per-target single-family checks without attach_alias; inner map_type named. mayHoldField excludes user_ringbuf | Parse-only user_ringbuf loses nonblocking map_field_unknown, leaving acceptance unchanged. USDT blocks with cilium usdt_attach:none or undeclared loaders such as bml preset. Other ELF unchanged. Initially caps 6 had optional usdt_attach, then caps 7 made it versioned (6 with the key is error), without changing policy. Before release, same policy 11 added point-count>spec-map-capacity usdt_probe and cilium-v0.22-usdt ref_ctr preset | Multi-probe and USDT checking |
| 12 | Format-13 adds ten blocking kinds kfunc_sig/kfunc_sig_unknown, sysarg/sysarg_unknown, lsm_cgroup_loader*, fsession_loader*, ksyscall_loader*. trace_lsm_cgroup/mtargetarg reuse existing kinds. Changes also affect older ELF: (a) sockmap_attach:prog_attach suppresses sk_skb/sk_msg attach_type; (b) tracing_helpers queried for trace_iter/modify_return; (c) static same-ELF map target answers for sk_skb/sk_msg/struct_ops remove unknown or reject wrong map type; (d) loader checks apply to version-9 generic lsm_cgroup/fsession | Newly blocks unsupported cilium/undeclared lsm_cgroup/fsession before loud load failure, unusable iter/fmod_ret helpers previously Unknown, and missing kfunc_protos/syscall_args for new rows. Newly permits sk_skb/sk_msg on 6.6 without sockmap links under explicit progattach preset. Nonblocking target Unknown disappears for static map answers. Caps 8 adds four loader keys/two queries; reads 7–2: absent sockmap field means link, other absent loader fields unknown/blocking | Extended signatures and loader mechanisms |
| 13 | Separate kfunc prototype from permission: kfunc_sig* still block; only after prototype agreement query privileged kfunc_loads for exact profile. Definite false blocks as kfunc_allowed; Unknown does not block as kfunc_allowed_unknown. tpbuf reuses blocking attach/attach_unknown | No acceptance reduction through Unknown for recipe-less ksess/fsess/TRACING. 6.6 SYSCALL/XDP task kfuncs are definite false before load. Caps 9 adds two queries; format 14 adds tpbuf; changes grouped in one policy version | kfunc permission profiles |
| 14 | Add ten canonical program types: tracepoint, raw_tracepoint, perf_event, lsm, cgroup_sock(sock_create), cgroup_device, cgroup_sock_addr(connect4), cgroup_sockopt(getsockopt), cgroup_sysctl, sock_ops; 30 load-only recipes. After prototype agreement, query kfunc_loads with policy-13 false/Unknown rules. fsession/struct_ops remain recipe-less Unknown | Newly blocks hook-table rejection on 6.12 raw_tracepoint/sock_ops and nine non-lsm types on 6.6 (six C control cells); previously precheck ok then loud load failure. Accepted targets such as 7.1.8 10/10 lose nonblocking Unknown. A missing profile key in recorded kfunc_loads is a checking error: rerecord. Format/caps format/Unmet kinds unchanged. Other implementations copy profile table/recipes and pin policy 14 | Expanded permission recipes |

**Format 15 does not raise policy** (policy remains 15): new kfield strptr uses existing kfield / kfield_unknown and CheckKFields member rules, with kfields keys distinguished by type spelling. Existing rows/verdicts are unchanged. The format bump makes older readers reject the new header. Prior caps-9 recordings lack strptr keys and yield blocking kfield_unknown.

**Format 10 does not raise policy**: trace_fmod_ret with retsig / integer farg reuses attach / retsig_unknown / farg / farg_unknown / attach_func_unknown and existing fexit signature / FUNC_PROTO parameter / fentry function-presence rules. ELF without those rows is unchanged; version-9 generic modify_return func:<function> remains readable/checkable.

**Format-12 ordering rules** (mtarget count, required innermap) belong to format; policy 11 covers USDT Unmet and user_ringbuf changes.

**Multi-link probe clarification does not raise policy 11**: Unmet kinds, query names and Check rules are unchanged; attach_types answers become closer to actual behavior by probing link creation (§5), following the sockmap precedent. Without CONFIG_FPROBE, kprobe.multi previously checked ok then failed attach loudly; now it gives attach_type. **If probe links cannot be created because bpf_fentry_test1 is absent or privileges are insufficient, answer Unknown**; attach_type_unknown is nonblocking and later attach may still fail loudly. Recording format is unchanged and cannot distinguish older load-only answers. **Rerecord caps for kprobe.multi on kernels without FPROBE**; stale true still ends in loud attach failure.

**Policy-12 clarifications**:

- **kfunc checking uses vmlinux BTF only**. Module kfuncs absent there block as kfunc_sig not found; module-BTF checking is not implemented.
- **sockmap_attach:prog_attach suppresses false attach_type for sk_skb/sk_msg even when the false came from load rejection**, since LiveCaps combines load and link results in one boolean. It relies on loud BPF_PROG_LOAD failure, as with nonblocking attach_type_unknown.

**Format-13 ordering rules** (kfunc field count, sysarg/mtargetarg position, btf type_tag minimum) belong to format; policy 12 covers new Unmet and changes (a)–(d). These were grouped into one coordinated version change.

**Tightening format rules does not raise policy**: direct row-minimum checks and position-bound ordering retained acceptance of all repository ELF, while handwritten or corrupt objects can be rejected.

## 10. Conformance corpus and recorded caps

Development data in conformance/requirements tests equivalent checking implementations. Implementations in any language can run against the same inputs and expected results.

- cases/<name>/ contains object.bpf.o (a fixed ELF fixture) or handwritten requirements.txt (no derived MapFields), caps.json, want.json and case.json with optional descriptive metadata. Optional load_as.json (`{"uid", "cap_eff"}`) enables privilege separation by selecting answers for the loading process; absent means no separation. Optional reprobe.json contains only load-process privilege-dependent query answers; absent means Unknown.
- parse/<name>/ contains requirements.txt and want.json.
- json/<name>/ contains JSON-input parsing cases (§13).
- bin/ contains uprobe binaries also used by go/requirements/testdata fixtures.

**caps.json**:

```json
{
  "format": "ebpf-caps 10",
  "probed_as": {"uid": 1000, "cap_eff": "000000c000000000"},
  "loader": {"name": "cilium-v0.22", "kprobe_alias_prefix": {"x86_64": "__x64_"}, "uprobe_reopens_path": true, "core_poisons_missing_field": true, "btf_rewrite": {"func_global": "rewrite", "decl_tag": "rewrite", "type_tag": "rewrite", "enum64": "rewrite"}, "usdt_attach": "none", "sockmap_attach": "link", "lsm_cgroup_load": "none", "fsession_load": "none", "ksyscall_attach": "none"},
  "queries": {"arch": {"": {"text": "x86_64"}}, "...": {}},
  "privileged_queries": {"prog_type": {"xdp": {"value": true}}, "helper": {"xdp/map_lookup_elem": {"unknown": "probe failed"}}, "map_type": {}, "...": {}}
}
```

- probed_as records effective uid and hexadecimal CapEff from /proc/self/status. **Probe answers depend on privileges** (nonroot.md). Handwritten corpus caps use root `{"uid": 0, "cap_eff": "000001ffffffffff"}`, except priv_no_probed_as.
- **Privilege separation, introduced in caps 6 and retained thereafter**: dependent queries are program/map/BTF load probes; independent queries read vmlinux BTF, tracefs formats, kallsyms names, uname or binary files. Format ≥6 places dependent queries in privileged_queries and independent ones in queries; wrong placement is an error naming the format. privileged_queries in ≤5 is an error; older recordings are partitioned by query name. **When load CapEff differs from probed_as (uid is not compared), or probed_as is absent, never use dependent recorded answers**. Use load-process reprobes (--caps --live, §11) or Unknown under §5; prog_type/map_type Unknown is a checking error. Independent answers remain recorded regardless of privileges; an Unknown recorded without enough read privilege remains Unknown. The same query-privilege classification applies in any implementation.
- **Caps 8** introduces optional sockmap_attach (link/prog_attach), lsm_cgroup_load/fsession_load (none/btf_id), ksyscall_attach (none/prefix), and kfunc_protos/syscall_args queries. Presence in ≤7 fails caps_key_newer_format, naming key and format, e.g. `caps: loader key "ksyscall_attach" is new in "ebpf-caps 8", but the format is "ebpf-caps 7"`. The writer then wrote 8. Reading caps 7 defaults absent sockmap_attach to link; other absent fields are unknown, blocking the relevant families until rerecorded. Older readers reject format 8 with new keys as unknown_key (strict JSON precedes format checking), or reject the format name if no new keys exist.
- **Caps 9** writer emits 9 and reads 8–2. New kfunc_loads belongs in privileged_queries; tracepoint_buffer in queries. In ≤8, caps_key_newer_format precedes placement checks. Do not raise minima for existing queries/keys; no new loader key is added.
- loader is required (§8), including btf_rewrite feature→rewrite/keep. Optional usdt_attach is none/plain/ref_ctr; other values error, absence unknown. **usdt_attach requires caps 7**: earlier-format recordings containing it fail with e.g. `caps: loader key "usdt_attach" is new in "ebpf-caps 7", but the format is "ebpf-caps 6"`. A short-lived writer emitted that invalid combination; rerecord it. Older caps 6 without the field remains readable but USDT blocks as usdt_loader_unknown. Pre-caps-7 readers such as v1.6.0 reject format 7 by name rather than unknown key. **Caps 1 with btf_rewrites is not read**; rerecord. Formats 6/5/4/3/2 remain readable: ≤5 put all queries in queries; caps 2 cannot contain func_args; caps ≤3 cannot contain attach_types/attach_targets/ctx_access; caps ≤4 cannot contain tracepoint_fields/struct_ops_members/ext_targets. **ext_targets is not recorded**: replacement program is a loader input; --record writes unknown, not an answer. Only handwritten caps, such as corpus fixtures, hold these answers.
- queries / privileged_queries map query name → argument key → answer. **Missing query name means the interface is absent** (§5). A present query with a missing argument key is a checking error, never silent success. prog_type / helper / map_type are required.
- Exactly one answer form is allowed: `{"value": true|false}`, `{"unknown": "<reason>"}`, `{"error": "<message>"}`, `{"diffs": ["<difference>", …]}` (empty means match), `{"text": "<value>"}`, `{"rewrites": {…}}`, or `{"file": "<path relative to caps.json directory>"}`.

| Query | §5 | Argument key | Answer | Privilege |
|---|---|---|---|---|
| `prog_type` | HasProgType | Program type name | value | dependent |
| `helper` | HasHelper | `<program type>/<helper>` | value | dependent |
| `map_type` | HasMapType | Map type name | value | dependent |
| `tcx` | HasTCX | `""` | value | dependent |
| `func_sig` | CheckFuncSig | `<function>/<argument count>/<type>` | diffs | independent |
| `func` | CheckFunc | Function name | diffs | independent |
| `tracepoint` | CheckTracepoint | `<tracepoint>(<struct>,…)` | diffs | independent |
| `kfields` | CheckKFields | Per kfield: `<program> <struct>.<field> <type>` | diffs | independent |
| `btf_feature` | HasBTFFeature | Feature name | value; raw BTF load probe, CAP_BPF | dependent |
| `arg_tag` | HasArgTagSemantics | `<program type>/<tag>/<class>` | value | dependent |
| `arch` | Arch | `""` | text | independent |
| `struct_field` | CheckStructField | `<struct>.<field>/<offset>/<size>` | diffs | independent |
| `kernel_symbol` | HasKernelSymbol | Symbol name, including aliases | value; kallsyms names readable without root | independent |
| `func_param` | CheckFuncParam | `<function>/<n>/<type>` | diffs | independent |
| `uprobe_binary` | UprobeBinary | Program symbol | file | independent |
| `uprobe_debug` | UprobeDebugFile | `<program>/<lowercase even-length hex GNU build ID>`, ID 1..64 bytes | file / unknown / error, since caps 10 | independent |
| `map_field` | AllowsMapField | `<program type>/<field struct>` | value | dependent |
| `nullable_args` | MarksNullableTPArgs | `""` | value | dependent |
| `func_args` | CheckFuncArgs | `<function>(<struct\|->,…)` | diffs since caps 3; absent from caps 2, yielding farg_unknown for farg rows | independent |
| `tracing_helpers` | HasTracingHelper | `<attach type>/<helper>`, e.g. trace_fentry/ktime_get_ns | value; absent query falls back to HasHelper | dependent |
| `attach_types` | HasAttachType | `<program type>/<attach type>` | value, since caps 4 | dependent |
| `attach_targets` | HasAttachTarget | `<attach type>/<kind>:<value>` | value, since caps 4; current BTF names / tracefs ids. Revisit privilege classification before adding a privilege-dependent target kind | independent |
| `ctx_access` | AllowsCtxAccess | `<program type>/<attach type>/<struct>.<field>/<r\|w>/<bytes>` | value, since caps 4 | dependent |
| `tracepoint_fields` | CheckTracepointField | `<cat>/<event>/<field>/<offset>/<bytes>/<i\|u>` | diffs, since caps 5; reading requires root but contents are privilege-independent | independent |
| `struct_ops_members` | CheckStructOpsMember | `<struct>.<member>/<argument count>/<return>(<farg>,…)`, or -1/- without retsig | diffs, since caps 5 | independent |
| `ext_targets` | CheckExtTarget | `<program>/<function>/<argument count>/<return>(<extarg>,…)` | diffs, since caps 5; --record writes unknown | independent |
| `kfunc_protos` | CheckKfunc | `<name>/<ret>(<arg>,…)`, row spelling, e.g. bpf_task_from_pid/ptr:task_struct(i32) | diffs, since caps 8 | independent |
| `syscall_args` | CheckSyscallArg | `<syscall>/<n>/<type>`, e.g. prctl/1/i32 | diffs, since caps 8; tracefs read requires root, contents independent, like tracepoint_fields | independent |
| `kfunc_loads` | HasKfuncLoad | Fixed-order JSON array `[recipe,name,ret,args,type,typeID,kind,section,flags,attach,targetKind,target,context]`; args is a type array; excludes raw BTF ids and program symbol | value, since caps 9 | dependent |
| `tracepoint_buffer` | CheckTracepointBuffer | `<target>/0/<pointee>`, e.g. bpf_test_finish/0/i32 | diffs, since caps 9 | independent |

**Case want.json**: `{"result": "ok" | "target_rejected" | "precheck_failed", "unmet": [{"kind", "program", "name", "id", "blocks_load"}, …]}`. List every Unmet, including nonblocking ones, in checking order. precheck_failed, a checking error, has an empty list. detail text is not compared. Name uses the reference spelling, e.g. pt_regs.dx (offset 96, 8 bytes). Other implementations may reproduce it or explicitly document narrowing comparison to kind/program/blocks_load.

**Parse want.json**: `{"accept": true, "version": N}` or `{"accept": false, "line": L, "row": "<kind>", "rule": "<rule>"}` . line is one-based, header 1; document-end checks (no program, or missing schema at version ≥2) use 0. row is the row kind, omitted for header / unknown kinds / document rules. Rules are header (missing/unknown header), fields (field count), min_version, order (§3 dependencies/duplicates/positional sequence), value, unknown_kind, document (missing program/schema). If several rules fail, report the first rejected line and its first rule, in order: fields → unknown kind → minimum version → order → value.

**VERSION** contains tab-separated `format <maximum format version>` and `policy <policy version>`; wants belong to that policy.

**Coverage gate (TestConformanceCoverage)**: every §6 Unmet kind occurs in a want. Every §3 row has a wrong-field-count case, a too-old-version case if minimum >1, and ordering negatives if the reader enforces ordering. Unknown-kind / header / document negatives and accepting cases must exist. **Loader axis**: LoaderDependentKinds appear in a cilium-declaration case or its preset pair. This includes usdt_loader/usdt_loader_unknown (the latter appears only in undeclared bml pairs, because cilium declares none), and attach_type(sockmap_attach), lsm_cgroup_loader*, fsession_loader*, ksyscall_loader*. Every such cilium case has a `<name>__<preset>` pair for every other preset, differing only in loader declaration. Adding a preset without pairs fails the gate; UPDATE_CONFORMANCE=1 generates pairs.

**Wants fix the reference verdicts.** Regeneration belongs to the development checkout; users of this data need no Go toolchain. On a policy change, inspect each want difference and raise policy as specified in §9.

## 11. Pre-load checking process interface

A separate checking process can implement this JSON protocol for loaders in any language. The private development command ebpf-precheck is a reference implementation, not a tool included in this source package.

```
ebpf-precheck (--loader=<preset> | --loader-file=<decl.json>) (--live | --caps=<caps.json> [--load-as=<uid>:<cap_eff>] | --caps=<caps.json> --live)
              [--schema-sha256=<hex> [--hint=<message>]] [--maps=<maps.json>] [--binary=<program>=<path> …] [--ext-target=<program>=<target> …] [--record=<caps.json>]
              (<object.bpf.o> | --requirements=<section-content-file>)
```

Rules:

- **Recorded privilege separation (policy 10)**: --caps compares load privileges (default run_as; --load-as for another process, reported as load_as) with recorded probed_as CapEff. If different or absent, do not use dependent recorded answers: **--caps alone uses Unknown**, giving precheck_failed for prog_type; **--caps --live reprobes in this process**, reporting reprobed:true. --live declares execution on the load target with load-equivalent privileges; combined --load-as must equal run_as or usage_error. --binary / --ext-target require --live alone. Independent answers such as tracepoint_fields stay recorded. --record with --caps records load privileges as probed_as.
- **Library callers must select load privileges explicitly**: supplied capabilities are used unchanged unless the caller requests adaptation to the loading process. A library that cannot probe must not invent live answers. Callers loading with recorded capabilities must supply the load privileges and live reprobe answers, equivalent to --caps --live.
- **Loader declaration required**: missing/unknown preset, two declarations, neither --live nor --caps, invalid --load-as, or disagreement with recording loader gives usage_error without checking. Exception: absent usdt_attach in older recordings is not compared; use that recorded unknown declaration, so USDT blocks as usdt_loader_unknown. Unknown --loader-file usdt_attach values also give usage_error. No declaration-free checking, because verdicts depend on loader behavior (§8).
- **Run with the loading process's uid/capabilities**. Live probe answers vary with privilege: XDP needs CAP_NET_ADMIN or precheck_failed. Verify run_as / probed_as.
- --live probes raw BTF loads for kernel feature facts, comparing with cilium KernelMarshalOptions; disagreement gives Unknown independently of declared loader (only stricter for non-cilium). Derive rewrites from btf_rewrite. Comparing libbpf feature answers is the guarded loader's obligation (§8 MUST); live checking is not unconditionally Unknown merely because the loader is not cilium.
- --binary=<program>=<path> supplies uprobe / multi / USDT binaries for --live alone; notes are read there. Check reads the open fd; attach must use the same inode (L3).
- --debug-root=<dir> defaults to /usr/lib/debug; explicit empty disables lookup. --debug=<program>=<path> overrides per program without fallback on failure. Both require --live alone. CLI records absolute explicit paths. Separate files are opened, snapshotted and closed, never attached. ReaderAt must stay alive/immutable during Check. See separate-DWARF rules below.
- **Tracepoint fields**: --live reads tracefs events/<cat>/<event>/format. On measured 7.1.8, /sys/kernel/tracing mode 700 makes non-root live checking block as tpfield_unknown. Supply a root --live --record recording as **--caps <recording> --live**: independent format answers stay recorded while dependent program/helper probes rerun as non-root. The historical --caps-only path reused root answers; since policy 10 it gives precheck_failed.
- **Syscall arguments**: similarly read events/syscalls/sys_enter_<name>/format; non-root unreadability blocks as sysarg_unknown. Use root-recorded syscall_args with --caps <recording> --live. If no event exists, use BTF __do_sys_<name>, readable without root; absent both gives sysarg_unknown.
- **kfunc signatures** use readable vmlinux BTF /sys/kernel/btf/vmlinux FUNC_PROTO through independent kfunc_protos.
- **Tracepoint live privileges** require CAP_PERFMON or root / {bpf,perfmon}; non-root with both still cannot read mode-700 tracefs. **CAP_BPF-only fails earlier with EPERM probing tracepoint program type**, yielding precheck_failed, and the same-privilege load also fails EPERM. Root recordings do not waive this: --caps alone fails through Unknown since policy 10, --caps --live through reprobe EPERM.
- **freplace targets**: --ext-target=<program>=<target>, with --live alone, names target object ELF `.BTF` or prog-id:<id> for a loaded program's kernel BTF (requiring privileges). Check global FUNC linkage, count/types/return. **ext requires live checking with the replacement program**: absent target or recorded caps gives ext_target_unknown because target programs are not recorded.
- Order: parse → optional schema hash → optional --maps declaration check (§12) → target checking. --record writes queried answers with probed_as identifying the answering process.

**Output** is one JSON object on stdout:

| Field | Meaning |
|---|---|
| `format` | `"ebpf-precheck 1"` |
| `result` | ok / target_rejected / precheck_failed / schema_mismatch / map_mismatch / requirements_invalid / usage_error; --version uses version |
| `unmet` | All Unmet in checking order: kind, program, name, id, blocks_load, detail (message, not compared) |
| `error` | Message for results other than ok / target_rejected |
| `parse_error` | requirements_invalid: {line,row,rule}, like §10 parse wants |
| `map_problems` | map_mismatch: §12 problem list |
| `versions` | format_max, policy (§9), object_format (ELF header), bpf_mlir (build module version/commit) |
| `run_as` | Effective uid / cap_eff from this process's /proc/self/status |
| `probed_as` | Answering process: run_as for --live, recording value for --caps; omitted if unavailable |
| `load_as` | --caps load privilege: run_as or --load-as; omitted for --live alone |
| `reprobed` | --caps --live dependent queries rerun because recorded/load privileges differ; omitted if false |
| `loader` | Declaration used for checking |

**Exit codes**: 0 ok, 3 target_rejected, 4 schema_mismatch, 5 requirements_invalid, 6 precheck_failed, 7 map_mismatch, 2 usage_error. Load **only when result is ok**; permitted Unknown remains in unmet with blocks_load:false.

**Warnings on stderr**: stdout/exit remain as above. Only the following warning is written; otherwise stderr is empty. Warnings are not verdicts and change neither result/exit/JSON format nor recordings. They are human diagnostics, not a caller parsing contract, though command tests fix their wording.

- **Recorded versus live disagreement**, only with --caps --live regardless of reprobed: for independent queries actually asked of recorded caps, excluding uprobe_binary / uprobe_debug / ext_targets, ask live with identical arguments. Compare only definitive value/text/diffs answers; warn on verdict-relevant differences in booleans/text/diffs emptiness, one line per (query,key) in byte order. Do not compare unknown/error; do not live-probe dependent queries through this comparison, which makes no bpf() calls. Warnings appear only after checking runs (ok / target_rejected / precheck_failed). Verdicts still use recorded answers: rerecord for a different kernel or use --live alone.

```
ebpf-precheck: warning: recorded answer differs from the live probe: query=<query> key=<key (quoted string)> declared=<recorded answer JSON> observed=<live answer JSON> recorded_as=<uid>:<cap_eff>|none run_as=<uid>:<cap_eff> — the check used the recorded answer (record again on this kernel, or check with --live)
```

No kernel-change warning is available for --caps alone (no live observation), or same-privilege --caps --live dependent queries (comparison would need load probes). Recordings do not identify the kernel.

## 12. Map declaration checking

Compare caller declarations from generated bindings/frontends with ELF requirements map rows (or the checking-process --maps input). This stops stale generated builds when only caller declarations change. Callers convert language types to schema spelling; the checker does not infer caller-language types.

**maps.json** for corpus / --maps:

```json
{
  "allow_undeclared": false,
  "maps": [
    {"name": "counts", "kind": "array", "key": "u32", "value": "u64", "max_entries": 3, "flags": 0}
  ]
}
```

- **kind is required**, matching the map row type name, e.g. array/percpu_array/hash. Key/value spelling alone cannot distinguish ordinary/per-CPU arrays; a downstream mix-up previously passed checking and failed only at read time.
- key/value use §3 map spelling: u32, i64, record:<S>, [N]iW, or - if absent.
- Record members can declare kptr:<T>. Only direct BTF PTR → TYPE_TAG kptr → modifiers → named STRUCT T receives that spelling. Other leading tags, untagged pointers and anonymous structs remain ?pointer and are rejected. Arrays use [N]kptr:<T>. Do not add kernel T to local-record declaration closure. Opaque bindings and integer/big-endian spellings are unchanged.
- Omitted flags means **flags 0**; nonzero ELF flags give flags_undeclared. Previously omission skipped checking, silently accepting missing lpm_trie BPF_F_NO_PREALLOC declarations.
- Default checking is **bidirectional**: undeclared ELF maps also mismatch. allow_undeclared:true permits checking a caller-selected subset.
- **Internal USDT maps**: ebpf.usdt.arg causes __ebpf_usdt_spec_<program> (§8). It is absent from canonical schema core.maps but present in requirements; declaring only schema maps therefore gives undeclared. For bidirectional checking, declare every emitted spec map with kind array, key u32, value record:ebpf_usdt_spec, max_entries equal to program max_points, flags 0. Alternatively allow_undeclared:true permits **all** undeclared maps, not just USDT internals. Reserved names are not automatically exempted. Internal-record layout is in §8 and is also absent from schema-generated record tables.
- **Optional inner** describes a map-in-map inner template with kind/key/value/max_entries/flags, using map spellings; flags cannot be omitted. **Only maps with this field are checked** against format-12 innermap. Difference or absent innermap (old ELF / non-outer map) gives inner, with declared/elf `kind=<type> key=<key> value=<value> max_entries=<N> flags=<F>`; absent side is -. **Absent inner skips checking**, preserving compatibility like globals/records. Do not check inner if kind already differs.
  - **One-way checking**: an ELF innermap with no declared inner is allowed (corpus maps/inner_not_declared). Older maps.json remains usable with format-12 of_maps, like absence of globals. Callers requiring template checking must declare inner. Unlike globals, there is no inner-absent assertion form: an *_of_maps kind necessarily has an inner template.

```json
{"name": "outer", "kind": "array_of_maps", "key": "u32", "value": "u32", "max_entries": 3,
 "inner": {"kind": "hash", "key": "u32", "value": "u64", "max_entries": 4, "flags": 0}}
```

- **Optional struct_ops** contains `{"type", "name" (only if type has a name member, e.g. tcp_congestion_ops), "ops": [{"member", "program"}]}`, matching schema spelling. **Only maps declaring it are checked** against ELF global variables in `.struct_ops.link` / `.struct_ops`: BTF DATASEC VAR local STRUCT name for type, char-array bytes before NUL for name, function-member relocation symbol for program. Difference gives struct_ops with declared/elf `type=<T>;name=<N>;<member>=<program>;…`, omitting absent name and sorting members by name; missing ELF table is -. Section-only checking without ELF gives format. **Omission skips checking** for compatibility. Requirements flags are 0; loader adds BPF_F_LINK from `.struct_ops.link`, so omit flags or write 0. **Older readers (v1.8.x Go / bml copy) reject struct_ops as unknown_key** under §13; maps.json has no numeric version.

```json
{"name": "g13cc", "kind": "struct_ops", "key": "u32", "value": "-", "max_entries": 1,
 "struct_ops": {"type": "tcp_congestion_ops", "name": "g13cc", "ops": [{"member": "init", "program": "g13_init"}]}}
```

**Optional records** declares record members. **Every declared record** is checked against the same-name BTF STRUCT for size and member name/byte offset/type spelling. This rejects same-name/same-size records with different members, whether key/value or nested. Undeclared records retain name-only key/value comparison for compatibility.

```json
"records": {
  "outer": {"size": 40, "members": [
    {"name": "id", "offset": 0, "type": "u8"},
    {"name": "in", "offset": 4, "type": "record:inner"},
    {"name": "arr", "offset": 12, "type": "[3]u16"}
  ]},
  "inner": {"size": 8, "members": [ … ]}
}
```

- Member types use §3 spelling: u8…i64, arrays [N]T (two dimensions [N][M]T), record:<T>, special bpf_spin_lock / bpf_timer.
- Do not declare padding: BTF has no padding members, checked across all repository ELF by go/layout TestRecordShapesMatchSchema. Input member order does not matter; comparison sorts by offset.
- **Endianness is not checked**: BTF INT lacks it, so u16be matches BTF u16. Schema-hash checking through CheckSchema protects endianness.
- **Nested-record closure**: any declared member record:<T>, including [N]record:<T>, requires T also in records; otherwise decl. Checking is per declaration, not recursive traversal, but closure ensures every referenced record is checked.
- declared/elf table spelling: `size=40;id:0:u8;in:4:record:inner;arr:12:[3]u16;…` in offset order. Unrepresentable BTF members (union/pointer/bitfield/…) use ?<reason>.
- Declaring records for section-only checking without ELF gives format.

**Problems** are MapDeclProblem{map,field,declared,elf}, ordered by declarations, then undeclared ELF maps, then record names:

| Field | Meaning |
|---|---|
| `missing_in_elf` | Declared map absent from ELF |
| `undeclared` | ELF map absent from declarations, only for bidirectional checking |
| `kind` | Kind differs; **do not compare other fields of that map** |
| `key` / `value` | Type spelling differs: width/sign/record name |
| `max_entries` / `flags` | Value differs; flags compared when declared |
| `decl` | Invalid declaration: missing/duplicate map name, missing kind; records with absent name, duplicate member name/offset, unreadable type spelling or undeclared nested record |
| `format` | Requirements version 1 lacks map definitions and must be regenerated; declared records without readable ELF BTF |
| `record` | Declared record size/member differs from BTF STRUCT; map is record:<S>, declared/elf use table spelling |
| `record_missing` | Declared record absent from ELF BTF |
| `global` | Global mismatch: GLOBAL OBJECT symbol section/size; BTF DATASEC VAR offset (after .rel.BTF relocations)/size; VAR INT width/sign. elf joins layout.CheckGlobals messages with semicolon-space |
| `global_missing_in_elf` | Declared global absent from ELF .rodata / .bss |
| `global_undeclared` | ELF .rodata / .bss global undeclared, unless allow_undeclared_globals |
| `inner` | Declared inner template differs from innermap or innermap absent |
| `struct_ops` | Declared table type/name/member programs differ from ELF .struct_ops.link global or table absent |

**Optional globals** declares schema core.globals:

```json
"globals": [
  {"name": "target_tgid", "section": "rodata", "type": "u32"},
  {"name": "hits", "section": "bss", "type": "u64"}
],
"allow_undeclared_globals": false
```

- **Omitted globals means no global checking**. **globals:[] asserts no globals**: every ELF global gives global_undeclared. Preserve empty arrays on read/write (corpus globals_empty). If present, check each declaration's symbol/DATASEC VAR/type under the global-layout rules and **all undeclared .rodata/.bss GLOBAL OBJECT symbols**, bidirectionally.
- allow_undeclared_globals:true permits undeclared globals. **It is separate from map allow_undeclared**: map allowances, e.g. loader-internal maps, must not silently weaken global checking.
- section is rodata/bss; type is u8…i64, optionally be suffix, which is not checked because BTF lacks endianness, as for records.
- Compare in name order. Invalid/missing/duplicate names, section or type give decl. globals with section-only checking gives format.
- Whether .rodata settings were Set before load is loader state, outside ELF/declaration checking (§8).

Corpus maps/<name>/ contains object.bpf.o or requirements.txt, maps.json, want.json and case.json. Want is `{"result": "ok" | "map_mismatch", "problems": [...]}`. Every problem field value is part of the expected result.

## 13. JSON reading

Checking-input JSON (caps.json, maps.json, --loader-file) follows these rules so implementations do not disagree merely because of their JSON library's input handling. This stricter reading does not change format/policy versions: field sets are unchanged.

| Rule | Rejected form | Common permissive JSON behavior |
|---|---|---|
| `duplicate_key` | Byte-identical keys after unescaping within one object | Accepts, later wins |
| `key_case` | Key differs only by case from a typed field name; map keys are unrestricted | Binds case-insensitively |
| `invalid_utf8` | Invalid raw UTF-8 in strings/keys, including overlong or surrogate encodings | Replaces with U+FFFD |
| `unpaired_surrogate` | Unpaired escape in \uD800–\uDFFF | Replaces with U+FFFD |
| `trailing_data` | Non-whitespace after first value (whitespace is space/tab/LF/CR) | Decoder.Decode reads only first value |
| `nul` | String/key \u0000; raw 0x00 is instead syntax as a control character | Accepts NUL string |
| `nesting_too_deep` | More than **128** open braces/brackets, counting top object as 1 (JSONMaxDepth) | Accepts through 10,000 |
| `unknown_key` | Key absent from typed fields | Same error with DisallowUnknownFields |
| `type` | Value type differs from field type | Same error |
| `syntax` | Other RFC 8259 errors, e.g. numeric leading + / unclosed object | Same error |

- **Loader-declaration keys**: required name; kprobe_alias_prefix, uprobe_reopens_path, core_poisons_missing_field, btf_rewrite; optional usdt_attach none/plain/ref_ctr. Unknown values fail post-read value validation, not a JSON rule. Pre-USDT readers reject the key as unknown_key. In caps loader, usdt_attach requires caps 7; older presence gives caps_key_newer_format. --loader-file has no format and may always declare it. Optional sockmap_attach link/prog_attach, lsm_cgroup_load / fsession_load none/btf_id, ksyscall_attach none/prefix similarly validate values after reading; caps loader requires format 8, older readers reject unknown keys.
- **Caps-only rules** (CapsRules): caps_key_newer_format rejects keys newer than the declared format: usdt_attach 7; privileged_queries 6; func_args 3; attach_types/attach_targets/ctx_access 4; tracepoint_fields/struct_ops_members/ext_targets 5; four new loader keys plus kfunc_protos/syscall_args 8; kfunc_loads/tracepoint_buffer 9. caps_format_unknown rejects an unknown, newer, empty or absent format name. It runs **after byte checks but before typed decoding**, so unknown keys in newer formats are rejected by format rather than unknown_key. The historical next-format example was caps 10 when the reader supported 9; current caps 10 is supported. Non-string format fails type during decoding. Corpus JSON wants use named rules, never other:<message>.
- Order: byte rules duplicate_key through nesting_too_deep, first encountered from input start → caps_format_unknown for caps → typed unknown_key/type → caps_key_newer_format for caps. Implementations may differ in messages; corpus compares rule names.
- Corpus json/<name>/ has input.json, case.json (kind caps/maps/loader and why), want.json (`{"result":"ok"}` or `{"result":"invalid","rule":…}`). TestConformanceJSON requires success and all rules for each kind. *_nesting_128 confirms depth 128 does not fail depth checking, though unknown keys still reject.
- Schema parsing is separate (llvm::json plus duplicate checking); its behavior is in [schema §1](schema_format.md#1-general-rules).

### Typed argv value strarray (format 16)

sysarg also accepts strarray, while the row minimum remains 13. tpfield/sysarg check char** depth 2, using independent caps-9 /strarray keys, not strptr/ptr/i/u answers. Missing answers give blocking *_unknown. char*/char***/void**/unsigned char**/data_loc/inline arrays mismatch; unknown aliases/unreadable data give Unknown. BTF fallback resolving typedef/qualifiers is ksyscall-only; tracefs retains priority. No compiler kernel-version branches.

### Embedded kernel-field paths (format 17)

kfield row minimum stays 3; multicomponent field values a.b / a.b.c and struct:T require format 17. Segments match `[A-Za-z_][A-Za-z0-9_]*`, maximum three. Every intermediate prefix requires `kfield p S prefix struct:T` for the same program/root struct; parse completion rejects missing/conflicting prefix types independent of row order. Example: `kfield p sock __sk_common struct:sock_common` plus `kfield p sock __sk_common.skc_daddr u32`. Prefixes must be embedded value structs, not pointers/unions/arrays, with matching names. Leaves use existing width/sign/array-length/pointee/strptr checks. Each step preserves existing breadth-first anonymous struct/union search.

Old single-component fields and old ELF versions are unchanged. No new Unmet kinds: kfield/kfield_unknown block load. Policy 15/caps 9 were retained. Recorded kfields keys contain full rows; absent new-path answers give Unknown, never substitute flat answers.

### Separate DWARF (policy 16, caps 10; requirements format 17 unchanged)

The main binary SHA-256, unique STT_FUNC and executable PT_LOAD determine the attach target. Select type evidence using that main-symbol address, never a separate file's symbol. Exactly one non-declaration DW_TAG_subprogram across all CUs must have a direct DW_AT_low_pc equal to that address. No name/ranges/entry_pc/specification fallback. Existing argument/language/calling-convention checks remain.

New independent query uprobe_debug uses UprobeDebugFiles.UprobeDebugFile(program,buildID), key program/ plus lowercase hex build ID of 1..64 bytes, and File/Unknown/Error answers. Presence in caps ≤9 gives caps_key_newer_format. Relative File paths are based on **caps.json's directory**, not cwd. Byte-only ParseRecordedCaps retains caller-cwd behavior; ReadRecordedCaps supplies file location.

LiveCaps nil root defaults to /usr/lib/debug; explicit empty disables lookup. Per-program overrides work even with empty root and never fall back on failure. Implicit lookup is only `.build-id/<first2hex>/<remaininghex>.debug`; no debuglink filename, debuginfod or remote search. Recorder.SetUprobeDebugPath preserves the supplied spelling; callers choose output caps directory for relative paths. Otherwise use reader Name (live uses absolute path); absent Name makes only the recording Unknown, while live bytes remain usable. Multi resolves once per attach/program and shares the result, without global caching.

For compound failures, stop at the first following condition, shared by the reference implementations. Existing main SHA/symbol/address check order is unchanged.

1. Main `.gnu_debugaltlink` gives Unknown. Otherwise any `.debug_info` / `.zdebug_info`, even zero-size/NOBITS, selects only the existing embedded reader. Corruption never falls back to separate files. Remaining steps apply only without info.
2. Read main `.note.gnu.build-id`: absence before malformed. No PT_NOTE fallback. Exactly one uncompressed SHT_NOTE section, ≤4096 bytes. Parse ELF-endian u32 namesz/descsz/type, 4-byte alignment, full bounds/overflow checks. Exactly one note with owner exactly `GNU\0` (namesz 4), type 3, descriptor length 1..64. Missing/duplicate/malformed is Unknown; unrelated valid notes ignored; all-zero ids not separately forbidden.
3. Optional `.gnu_debuglink`: exactly one uncompressed PROGBITS section ≤4096 bytes, nonempty name + NUL, 4-byte aligned, followed by exactly four ELF-endian CRC bytes. Padding contents unrestricted; trailing bytes rejected.
4. Check absent capability, override/root lookup, then query Error/Unknown/unreadability in order. Malformed main ID/debuglink precedes disabled-root reporting. Never fall back to another file after failure.
5. Open/fstat: reject size >268435456 before reading; read at most limit+1 through EOF; check actual limit then original-size equality. Length changes give Unknown; same-length mutation detection is not promised, since input must be immutable. Close fd before returning. Arbitrary ReaderAt is snapshotted through EOF up to limit+1 without claiming fstat checks.
6. Open ELF and compare class/data/machine with main.
7. Read separate GNU build ID under step-2 rules and require byte equality with main.
8. If main has debuglink, compare IEEE CRC32 of the entire separate snapshot.
9. Reject separate .gnu_debugaltlink, then SHT_REL/SHT_RELA targeting .debug_* / .zdebug_* via sh_info (even empty), then presence of .debug_types / .zdebug_types (even empty).
10. Read debug sections in section-table order: reject NOBITS → validate compression header → reject zstd → sum expanded lengths with overflow checking, rejecting >536870912. Ordinary sections use size; GNU .zdebug_* requires ZLIB + 8-byte big-endian length (missing/short is Unknown); SHF_COMPRESSED uses ELF32/64 compression-header length. Separate files support only uncompressed/zlib. Existing embedded zstd acceptance is not narrowed; its older difference from bml remains separate.
11. Require info section → parse DWARF → existing address/ABI checks. Backend parse/embedded-reader error text remains backend-specific; new source-selection reasons below are fixed ASCII.

New definite-mismatch Detail templates, both blocking; Program/Name identify program/target, including each multi target:

```text
separate DWARF build ID is <got-lower-hex>, want <body-lower-hex>
separate DWARF CRC32 is <got-8-lower-hex>, want <link-8-lower-hex>
```

Selection Unknown uses these strings in uprobearg_unknown Detail or uretprobe_abi_unknown cause, without OS/backend suffixes. Open/stat/read failure means unavailable; query Error or other callback failure means query failed. Explicit Unknown matching a listed string is preserved; other caller-provided messages are caller evidence outside reference byte-equality guarantees.

```text
no separate DWARF capability
separate DWARF lookup is disabled
separate DWARF file is unavailable
separate DWARF query failed
separate DWARF file exceeds 268435456 bytes
separate DWARF file changed while reading
separate DWARF expanded sections exceed 536870912 bytes
separate DWARF ELF is unreadable
separate DWARF ELF class, data or machine differs from the binary
separate DWARF contains unsupported zstd compression
separate DWARF contains unsupported relocations
separate DWARF contains unsupported type units
separate DWARF has a NOBITS debug section
separate DWARF has an invalid compression header
the binary has no GNU build ID
the binary has an invalid GNU build ID note
separate DWARF has no GNU build ID
separate DWARF has an invalid GNU build ID note
the binary has an invalid GNU debuglink
separate DWARF has no debug information
separate DWARF contains unsupported .gnu_debugaltlink
the binary contains unsupported .gnu_debugaltlink
```

Build IDs identify linked builds, not cryptographic authenticity; CRC checks corruption. Together they bind type evidence to the ELF selected by main SHA. Old recordings without a separate file stop with Unknown rather than guessing types.
