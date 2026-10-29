ebpf.program @partial "xdp" maps [@m] {
^bb0(%ctx: !ebpf.ctx<"xdp">, %m: !ebpf.map<"hash", i32, i64>):
  %k = arith.constant 0 : i32
  %maybe = ebpf.map.lookup %m[%k]
      : !ebpf.map<"hash", i32, i64>, i32 -> !ebpf.maybe_ref<i64>
  %res = ebpf.ringbuf.reserve "events" : !ebpf.maybe_reservation<i64>
  ebpf.ringbuf.if_reserved %res : !ebpf.maybe_reservation<i64> present {
  ^present(%r: !ebpf.reservation<i64>):
    ebpf.ref.check %maybe : !ebpf.maybe_ref<i64> present {
    ^present(%ref: !ebpf.borrowed<i64>):
      ebpf.ringbuf.submit %r : !ebpf.reservation<i64>
      ebpf.yield
    } absent {
      ebpf.yield
    }
    ebpf.yield
  } absent {
    ebpf.yield
  }
  ebpf.verdict "pass"
}
