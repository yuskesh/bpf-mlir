// Canonical three-layer schema: core owns BPF ABI/layout, telemetry owns
// language-independent OTel semantics, and extensions retain opaque
// implementation wiring without interpreting or dropping it. Do not flatten
// frontend-specific producers/consumers/enrichers into generic C++ types.
// Integer width/sign/offset/alignment/endianness are explicit. Reject unknown
// top-level keys; extensibility belongs only under dot-containing stable
// extension namespaces. Schema version is exactly 1. See docs/schema_format.md.
#ifndef BPF_MLIR_TARGET_EBPF_SCHEMA_H
#define BPF_MLIR_TARGET_EBPF_SCHEMA_H

#include "bpf-mlir/Support/Usdt.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/JSON.h"

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace ebpf {

inline constexpr uint32_t kSchemaVersion = 1;

enum class Endianness { Little, Big };

// Coverage distinguishes complete bidirectional declarations from omitted
// categories whose checks are explicitly skipped. An empty list must not
// silently mean both. Coverage itself is mandatory; there is no implicit
// default or ambiguous partial mode.
enum class Coverage { Complete, Omitted };

struct CoverageDecl {
  Coverage programs = Coverage::Complete;
  Coverage maps = Coverage::Complete;
  Coverage records = Coverage::Complete;
  Coverage telemetry = Coverage::Complete;
  bool operator==(const CoverageDecl &o) const {
    return programs == o.programs && maps == o.maps && records == o.records &&
           telemetry == o.telemetry;
  }
};

// Core types.
struct Type;

struct IntType {
  uint32_t bits = 0;      // 8 / 16 / 32 / 64
  bool isSigned = false;
  Endianness endianness = Endianness::Little;
  uint32_t alignment = 0; // Power of two.
  bool operator==(const IntType &o) const;
};

// References retain nominal record identity, matching BTF and Go named
// structs rather than anonymous duplicated layouts.
struct RecordRefType {
  std::string symbol;
  bool operator==(const RecordRefType &o) const { return symbol == o.symbol; }
};

struct ArrayType {
  std::unique_ptr<Type> element;
  uint64_t count = 0;
  ArrayType() = default;
  ArrayType(const ArrayType &o);
  ArrayType &operator=(const ArrayType &o);
  bool operator==(const ArrayType &o) const;
};

// Direct map-value lock field; BTF bpf_spin_lock size comes from UAPI.
struct SpinLockType {
  bool operator==(const SpinLockType &) const { return true; }
};

// Map-value timer field uses UAPI bpf_timer {u64 __opaque[2]}, with the same
// placement restrictions as locks.
struct TimerType {
  bool operator==(const TimerType &) const { return true; }
};

// UAPI bpf_stack_build_id element, only for stack_trace value arrays paired
// with BPF_F_STACK_BUILD_ID.
struct StackBuildIdType {
  bool operator==(const StackBuildIdType &) const { return true; }
};

// Referenced map-value kptr targets name core.kernel_types. BTF is eight-byte
// PTR -> TYPE_TAG kptr -> STRUCT T. record_ref chains are allowed, arrays are not.
struct KptrType {
  std::string structName;
  bool operator==(const KptrType &o) const { return structName == o.structName; }
};

struct Type {
  std::variant<IntType, ArrayType, RecordRefType, SpinLockType, TimerType, StackBuildIdType, KptrType> v;
  bool operator==(const Type &o) const { return v == o.v; }
  bool operator!=(const Type &o) const { return !(*this == o); }
};

// Core records, maps and programs.
struct Field {
  std::string name;
  Type type;
  uint64_t offset = 0;
  std::string expose;  // Reader-facing shape: empty, int, str, etc.
  std::string note;    // Optional documentation, unused by code generation.
  bool operator==(const Field &o) const {
    return name == o.name && type == o.type && offset == o.offset &&
           expose == o.expose && note == o.note;
  }
};

struct Record {
  std::string symbol;
  uint32_t id = 0;            // Ring identifier; zero means absent.
  uint64_t size = 0;          // Fixed size or variable-record maximum.
  uint64_t minSize = 0;       // record_min_bytes; equal to size for fixed records.
  uint32_t alignment = 0;
  std::string requiredThrough; // Fields through this name are always present; empty means all.
  std::vector<Field> fields;
  std::string note;
  bool synthesized = false; // Compiler-added record (e.g. USDT spec), omitted from canonical serialization.
  bool isVariableLength() const { return minSize != size; }
  bool operator==(const Record &o) const {
    return symbol == o.symbol && id == o.id && size == o.size &&
           minSize == o.minSize && alignment == o.alignment &&
           requiredThrough == o.requiredThrough && fields == o.fields &&
           note == o.note;
  }
};

// Canonical map-kind spellings: bpf-mlir/Support/MapKinds.def.
enum class MapKind {
#define EBPF_MAP_KIND(ENUM, NAME, MAPTYPE) ENUM,
#include "bpf-mlir/Support/MapKinds.def"
};

// Header-only NAME lookup shared by schema, map types and UAPI maptype names,
// without a BuildBTF/ObjectEmitter link dependency.
inline const char *mapKindSpelling(MapKind k) {
  switch (k) {
#define EBPF_MAP_KIND(ENUM, NAME, MAPTYPE)                                                                                     \
  case MapKind::ENUM:                                                                                                          \
    return NAME;
#include "bpf-mlir/Support/MapKinds.def"
  }
  return "";
}

// Shared spelling source for serialization and schema verification.
const char *mapKindName(MapKind k);

// Ring buffers remain MapKind::RingBuf despite having no key/value. Do not
// require key/value for every map kind.
struct Map {
  std::string symbol;
  MapKind kind = MapKind::Hash;
  std::optional<Type> key;
  std::optional<Type> value;
  uint64_t maxEntries = 0;  // Bytes for ring buffers.
  uint64_t flags = 0;
  std::string record;       // Transported ring record symbol, or empty.
  std::string note;
  // prog_array index -> same-ELF program declaration, populated by the loader
// from tailslot requirements.
  struct Slot {
    uint64_t index = 0;
    std::string program;
    bool operator==(const Slot &o) const { return index == o.index && program == o.program; }
  };
  std::vector<Slot> slots;
  // Local .struct_ops.link table. type names a StructOpsTypes.def kernel struct;
  // name is its DATA name member (empty if absent). Each function-pointer
  // member maps to an implementing struct_ops program in the same ELF.
  struct StructOps {
    std::string type, name;
    struct Op {
      std::string member, program;
      bool operator==(const Op &o) const { return member == o.member && program == o.program; }
    };
    std::vector<Op> ops;
    bool operator==(const StructOps &o) const { return type == o.type && name == o.name && ops == o.ops; }
  };
  std::optional<StructOps> structOps;
  // array_of_maps/hash_of_maps inner template names another core.maps symbol.
  // It supplies BTF values, not a separate ELF .maps entry. Other kinds are empty.
  std::string inner;
  bool synthesized = false; // Compiler-added USDT spec map, omitted from canonical serialization.
  bool operator==(const Map &o) const {
    return symbol == o.symbol && kind == o.kind && key == o.key &&
           value == o.value && maxEntries == o.maxEntries &&
           flags == o.flags && record == o.record && note == o.note && slots == o.slots && structOps == o.structOps &&
           inner == o.inner;
  }
};

struct Program {
  std::string name;
  std::string kind;              // Program kind, e.g. xdp or tp_btf.
  std::string attachTarget;      // tp_btf tracepoint name, e.g. sched_process_fork.
  std::vector<std::string> attachTargets; // Multi-probe target name array; attachTarget is empty.
  std::vector<std::string> maps; // Positional correspondence with ebpf.program maps [...].
  // tp_btf argument local types match context positions and are checked against
  // the actual target signature at load time. xdp has no such arguments.
  std::vector<std::string> args; // kernel_types names, integer i8..u64 or unread '-'.
  // fexit signature includes target count and integer return type; the return
  // slot is nargs, -1 denotes absence. retsig checks the target at load time.
  int64_t nargs = -1;
  IntType ret;
  bool retVoid = false; // struct_ops void return is represented by retsig void.
  // Probe architecture defines calling convention/pt_regs (x86_64 only).
  // Argument n is one-based and checked against target kprobearg at load time.
  std::string arch;
  struct Param {
    int64_t n;
    IntType type;       // For user_str, unused u64 reflects register width.
    bool userStr = false; // User string pointer, checked against one pointer to 8-bit character DWARF.
    bool ptr = false;     // Raw eight-byte pointer identity without dereference; type is u64.
    bool userStrArray = false;
    bool userBuf = false; // typed user buffer address, not an integer.
    bool operator==(const Param &o) const { return n == o.n && type == o.type && userStr == o.userStr && ptr == o.ptr && userStrArray == o.userStrArray && userBuf == o.userBuf; }
  };
  std::vector<Param> params;
  // Per-target entry parameters follow attach_target order (mtarget i).
  // Mutually exclusive with the shared params declaration.
  std::vector<std::vector<Param>> targetParams;
  const Param *targetParam(size_t i, int64_t n) const {
    if (i >= targetParams.size())
      return nullptr;
    for (const Param &q : targetParams[i])
      if (q.n == n)
        return &q;
    return nullptr;
  }
  // User binary content SHA-256: 64 lowercase hexadecimal digits. Placement
// paths and PIDs are loader inputs, never schema fields.
  std::string binarySHA256;
  // TracefsEvent-only field declarations: name, record byte offset and type.
  // Offsets are claims, not target layout evidence; tpfield checks target
  // tracefs format at load time.
  struct TpField {
    std::string name;
    uint64_t offset = 0;
    IntType type;
    bool userStr = false; // raw char pointer, distinct from an integer of the same width.
    bool userStrArray = false;
    uint64_t arrayCount = 0; // fixed byte array, zero means a scalar/pointer.
    bool operator==(const TpField &o) const { return name == o.name && offset == o.offset && type == o.type && userStr == o.userStr && userStrArray == o.userStrArray && arrayCount == o.arrayCount; }
  };
  std::vector<TpField> fields;
  // USDT-only semaphore requirement (required/none, usdtsem) and spec map
  // max_entries bound on point count.
  std::string usdtSemaphore;
  uint64_t usdtMaxPoints = 0;
  std::string note;
  bool operator==(const Program &o) const {
    return name == o.name && kind == o.kind && attachTarget == o.attachTarget && attachTargets == o.attachTargets &&
           maps == o.maps && args == o.args && nargs == o.nargs && (nargs < 0 || (ret == o.ret && retVoid == o.retVoid)) && arch == o.arch &&
           params == o.params && targetParams == o.targetParams && binarySHA256 == o.binarySHA256 && fields == o.fields && usdtSemaphore == o.usdtSemaphore &&
           usdtMaxPoints == o.usdtMaxPoints && note == o.note;
  }
  const TpField *field(llvm::StringRef n) const {
    for (const TpField &f : fields)
      if (f.name == n)
        return &f;
    return nullptr;
  }
  const Param *param(int64_t n) const {
    for (const Param &q : params)
      if (q.n == n)
        return &q;
    return nullptr;
  }
};

// Globals declare name, section and integer type, never byte offsets; ELF
// section/symbol information owns placement.
struct Global {
  std::string name;
  std::string section; // "rodata" / "bss"
  IntType type;
  std::string note;
  bool operator==(const Global &o) const {
    return name == o.name && section == o.section && type == o.type && note == o.note;
  }
};

// Partial local kernel types declare only accessed CO-RE fields, not the
// actual kernel layout. Declaration-order natural offsets/sizes are local
// DWARF placeholders; target BTF relocates actual offsets at load time.
// Supported field forms are explicit below; bitfields and unions are unsupported.
struct KernelField {
  std::string name;
  std::string embedded; // embedded value of another kernel type (not a pointer).
  IntType type;         // Integer bits 8/16/32/64; unused for a nonempty ptrTo.
  std::string ptrTo;    // Nonempty names the pointed-to kernel_types struct.
  uint64_t arrayCount = 0; // Nonzero count describes an array of one-byte integers; type is the element.
  bool strPtr = false;  // Character pointer read only by kernel.read_str; type is unused.
  uint64_t offset = 0;  // Parse-computed natural local offset, not the target offset.
  std::string note;
  bool operator==(const KernelField &o) const {
    return name == o.name && embedded == o.embedded && type == o.type && ptrTo == o.ptrTo && arrayCount == o.arrayCount && strPtr == o.strPtr &&
           offset == o.offset && note == o.note;
  }
};

struct KernelType {
  std::string name;     // Kernel struct name used for CO-RE target lookup.
  std::vector<KernelField> fields;
  uint64_t size = 0;    // Local placeholder size used for DWARF.
  uint64_t alignment = 4; // Natural local layout, resolved after all declarations.
  std::string note;
  const KernelField *field(llvm::StringRef n) const {
    for (const KernelField &f : fields)
      if (f.name == n)
        return &f;
    return nullptr;
  }
  bool operator==(const KernelType &o) const {
    return name == o.name && fields == o.fields && size == o.size &&
           note == o.note;
  }
};

// Structured telemetry predicate/source AST, not prose or C/Ruby expressions.
// Preserve unrepresentable inputs explicitly at the runtime_extension boundary;
// never silently drop them.
struct Operand {
  std::string kind;  // "field" / "derived" / "constant"
  std::string name;
  bool operator==(const Operand &o) const {
    return kind == o.kind && name == o.name;
  }
};

struct Predicate {
  // always/never/empty/nonempty/zero/nonzero/byte_eq/any/all/not/unexpressible.
  // unexpressible explicitly retains a condition that the AST cannot encode,
  // with the original condition text in detail rather than silently dropping it.
  std::string op;
  std::optional<Operand> operand;
  uint64_t index = 0;              // byte_eq byte index.
  std::vector<uint8_t> bytes;      // byte_eq
  std::vector<Predicate> args;     // any / all / not
  std::string detail;              // Original unrepresentable condition.
  bool operator==(const Predicate &o) const {
    return op == o.op && operand == o.operand && index == o.index &&
           bytes == o.bytes && args == o.args && detail == o.detail;
  }
};

struct Source {
  // field / derived / constant / runtime_extension
  std::string kind;
  std::string name;
  std::string from;   // Source field, possibly empty.
  std::string detail; // Retain unrepresentable prose explicitly.
  bool operator==(const Source &o) const {
    return kind == o.kind && name == o.name && from == o.from &&
           detail == o.detail;
  }
};

struct Attribute {
  std::string key;        // semconv key
  std::string stability;  // "semconv" / "spinel" / ...
  Source source;
  Predicate presence;
  std::string note;
  bool operator==(const Attribute &o) const {
    return key == o.key && stability == o.stability && source == o.source &&
           presence == o.presence && note == o.note;
  }
};

struct Timing {
  std::string start;  // Example: record_ktime:hdr.timestamp.
  std::string clock;  // References clocks[].id.
  std::string end;    // Example: start_plus:duration_ns.
  bool operator==(const Timing &o) const {
    return start == o.start && clock == o.clock && end == o.end;
  }
};

// Metric kinds are closed: sum requires monotonic and forbids scale,
// zero_threshold and bucket_rule; exponential_histogram requires those three
// and forbids monotonic. Unknown kinds are errors. otlp_lower_exclusive is the
// closed bucket rule: at scale zero, v>zero_threshold belongs to index i with
// 2^i < v <= 2^(i+1); v<=zero_threshold contributes to zero_count. Declaring
// boundaries avoids disagreement between language implementations.
struct Metric {
  std::string kind;         // Closed sum/exponential_histogram kind.
  std::string unit;         // UCUM
  std::string temporality;  // "delta" / "cumulative"
  std::optional<bool> monotonic;       // Sum only.
  std::optional<int64_t> scale;        // Exponential histogram only.
  std::optional<double> zeroThreshold; // Exponential histogram only.
  std::string bucketRule;              // Exponential histogram only.
  bool operator==(const Metric &o) const {
    return kind == o.kind && unit == o.unit && temporality == o.temporality &&
           monotonic == o.monotonic && scale == o.scale &&
           zeroThreshold == o.zeroThreshold && bucketRule == o.bucketRule;
  }
};

// Traces require span_name/span_kind and forbid body/value. Logs require
// body Source and forbid value/metric/span fields. Metrics require value Source
// plus metric and forbid body/span fields. Generic Source avoids embedding
// C/Ruby expressions or exporter names; implementation wiring stays in extensions.
struct Signal {
  std::string name;
  std::string signal;   // "traces" / "metrics" / "logs"
  std::string record;   // Origin record symbol.
  std::string spanName; // Template may contain {attr.key}.
  std::string spanKind; // "INTERNAL" / "CLIENT" / ...
  Timing timing;
  Predicate dropWhen;
  std::vector<Attribute> attributes;
  std::optional<Source> body;   // Logs: source of the LogRecord body/main value.
  std::optional<Source> value;  // Metrics: observation-value source.
  std::optional<Metric> metric;
  std::string note;
  bool operator==(const Signal &o) const {
    return name == o.name && signal == o.signal && record == o.record &&
           spanName == o.spanName && spanKind == o.spanKind &&
           timing == o.timing && dropWhen == o.dropWhen &&
           attributes == o.attributes && body == o.body && value == o.value &&
           metric == o.metric && note == o.note;
  }
};

struct Clock {
  std::string id;
  std::string kernelSource; // "bpf_ktime_get_ns()"
  std::string posixClock;   // "CLOCK_MONOTONIC"
  std::string toWall;       // Conversion to wall-clock time.
  std::string note;
  bool operator==(const Clock &o) const {
    return id == o.id && kernelSource == o.kernelSource &&
           posixClock == o.posixClock && toWall == o.toWall && note == o.note;
  }
};

struct ValueMapEntry {
  int64_t value = 0;
  std::string name;
  bool operator==(const ValueMapEntry &o) const {
    return value == o.value && name == o.name;
  }
};

// Value-to-name mappings retain BTF validation instructions so declarations
// can be checked against the running target instead of simply trusted.
struct ValueMap {
  std::string id;
  std::string unknown;        // Fallback for unmapped values, e.g. unnamed(%ld).
  bool archInvariant = false; // Whether values are architecture-independent.
  std::string btfMode;        // Validation mode such as names; empty skips BTF checking.
  std::string btfAnchor;      // Enumerator anchoring BTF validation.
  std::string btfPrefix;      // Namespace prefix to strip.
  std::string btfOmit;        // Enumerators excluded from validation.
  std::string authority;      // Value provenance.
  std::string note;
  std::vector<ValueMapEntry> entries;
  bool operator==(const ValueMap &o) const {
    return id == o.id && unknown == o.unknown &&
           archInvariant == o.archInvariant && btfMode == o.btfMode &&
           btfAnchor == o.btfAnchor && btfPrefix == o.btfPrefix &&
           btfOmit == o.btfOmit && authority == o.authority &&
           note == o.note && entries == o.entries;
  }
};

struct BoundsSet {
  std::string id;
  std::string unit;
  std::string authority;
  std::string note;
  std::vector<double> bounds;
  bool operator==(const BoundsSet &o) const {
    return id == o.id && unit == o.unit && authority == o.authority &&
           note == o.note && bounds == o.bounds;
  }
};

//===----------------------------------------------------------------------===//
// Schema
//===----------------------------------------------------------------------===//
class Schema {
public:
  static llvm::Expected<Schema> parseJSON(llvm::StringRef json);

  // Canonical bytes are deterministic for a Schema, including opaque
  // extensions that core does not interpret.
  std::string serializeJSON() const;

  const CoverageDecl &coverage() const { return coverage_; }

  // core
  const std::vector<Program> &programs() const { return programs_; }
  const std::vector<Map> &maps() const { return maps_; }
  const std::vector<Record> &records() const { return records_; }
  const std::vector<KernelType> &kernelTypes() const { return kernelTypes_; }
  const KernelType *kernelType(llvm::StringRef name) const {
    for (const KernelType &k : kernelTypes_)
      if (k.name == name)
        return &k;
    return nullptr;
  }
  const Program *program(llvm::StringRef name) const {
    for (const Program &p : programs_)
      if (p.name == name)
        return &p;
    return nullptr;
  }
  // core.globals declarations, empty when absent.
  const std::vector<Global> &globals() const { return globals_; }
  const Global *global(llvm::StringRef name) const {
    for (const Global &g : globals_)
      if (g.name == name)
        return &g;
    return nullptr;
  }
  // telemetry
  const std::vector<Signal> &signals() const { return signals_; }
  const std::vector<Clock> &clocks() const { return clocks_; }
  const std::vector<ValueMap> &valueMaps() const { return valueMaps_; }
  const std::vector<BoundsSet> &boundsSets() const { return boundsSets_; }
  // Extension namespace -> uninterpreted payload.
  const std::map<std::string, llvm::json::Value> &extensions() const {
    return extensions_;
  }

  // Type byte size; resolve record_ref through records().
  llvm::Expected<uint64_t> sizeOf(const Type &t) const;

  bool operator==(const Schema &o) const;

private:
  Schema() = default;
  CoverageDecl coverage_;
  std::vector<Program> programs_;
  std::vector<Map> maps_;
  std::vector<Record> records_;
  std::vector<KernelType> kernelTypes_;
  std::vector<Global> globals_;
  std::vector<Signal> signals_;
  std::vector<Clock> clocks_;
  std::vector<ValueMap> valueMaps_;
  std::vector<BoundsSet> boundsSets_;
  std::map<std::string, llvm::json::Value> extensions_;
};

// tp_btf argument integers i8..u64 and unread '-', shared by ProgramDecl::args
// and requirements arg rows.
inline bool isTPArgScalarSpelling(llvm::StringRef s) {
  return s == "-" || s == "i8" || s == "u8" || s == "i16" || s == "u16" || s == "i32" || s == "u32" || s == "i64" ||
         s == "u64";
}

} // namespace ebpf

#endif // BPF_MLIR_TARGET_EBPF_SCHEMA_H
