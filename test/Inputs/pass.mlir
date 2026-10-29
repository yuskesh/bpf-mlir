ebpf.program @pass "xdp" {
^bb0(%ctx: !ebpf.ctx<"xdp">):
  ebpf.verdict "pass"
}
