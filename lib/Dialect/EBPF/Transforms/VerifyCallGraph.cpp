//===- VerifyCallGraph.cpp - module-wide call graph checks ------------------===//
//
// After ownership verification, check acyclicity, reachability of every func
// from a program, and maximum entry-inclusive call depth. Calls inside loops
// must not reach ring-buffer operations. Count nested loop depth/product across
// calls from each program entry using strategy-specific conservative budgets.
// Call verifiers already own target existence, non-program targets and types.
//===----------------------------------------------------------------------===//
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h"

#include "bpf-mlir/Dialect/EBPF/IR/EBPFDialect.h"
#include "bpf-mlir/Support/LoopBudget.h"

#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringExtras.h"

namespace mlir {
namespace ebpf {
#define GEN_PASS_DEF_EBPFVERIFYCALLGRAPH
#include "bpf-mlir/Dialect/EBPF/Transforms/Passes.h.inc"
} // namespace ebpf
} // namespace mlir

using namespace mlir;
using namespace mlir::ebpf;

namespace {

// Compiler support limit, not a kernel contract. MAX_CALL_FRAMES is internal,
// not UAPI; observing eight in three kernels does not establish invariance.
// Kernel depth counting can reset at global subprograms (7.1.8 verifier.c:5463),
// unlike this conservative longest entry-inclusive chain. Limiting it to eight
// does not guarantee acceptance: kernel verification owns final depth/stack checks.
constexpr unsigned kMaxCallFrames = 8;

struct EBPFVerifyCallGraphPass
    : public mlir::ebpf::impl::EBPFVerifyCallGraphBase<EBPFVerifyCallGraphPass> {
  void runOnOperation() override {
    ModuleOp module = getOperation();
    bool bad = false;

    // Edges go from program/func callers to func callees, already resolved by op verifiers.
    llvm::StringMap<SubprogramOp> funcs;
    for (auto fn : module.getOps<SubprogramOp>())
      funcs[fn.getSymName()] = fn;
    auto calleesOf = [&](Operation *owner) {
      SmallVector<std::pair<CallOp, SubprogramOp>> out;
      owner->walk([&](CallOp call) {
        auto it = funcs.find(call.getCallee());
        if (it != funcs.end())
          out.push_back({call, it->second});
      });
      return out;
    };

    // DFS colors detect cycles: an edge to a gray function closes a cycle.
    enum class Mark { White, Grey, Black };
    llvm::StringMap<Mark> mark;
    std::function<void(SubprogramOp, SmallVector<StringRef> &)> dfs =
        [&](SubprogramOp fn, SmallVector<StringRef> &path) {
          mark[fn.getSymName()] = Mark::Grey;
          path.push_back(fn.getSymName());
          for (auto [call, callee] : calleesOf(fn)) {
            Mark m = mark.lookup(callee.getSymName());
            if (m == Mark::Grey) {
              bad = true;
              std::string cycle;
              bool on = false;
              for (StringRef p : path) {
                on |= p == callee.getSymName();
                if (on)
                  cycle += "@" + p.str() + " -> ";
              }
              cycle += "@" + callee.getSymName().str();
              call.emitOpError() << "makes the call graph recursive (" << cycle
                                 << "); BPF subprograms may not recurse";
            } else if (m == Mark::White) {
              dfs(callee, path);
            }
          }
          path.pop_back();
          mark[fn.getSymName()] = Mark::Black;
        };
    for (auto fn : module.getOps<SubprogramOp>())
      if (mark.lookup(fn.getSymName()) == Mark::White) {
        SmallVector<StringRef> path;
        dfs(fn, path);
      }
    if (bad)
      return signalPassFailure(); // Cycles make depth undefined.

    // For each program, compute reachability and the longest frame chain to each func.
    llvm::StringMap<unsigned> depth; // func -> longest frame chain ending there, including entry.
    llvm::StringMap<bool> reached;
    std::function<void(SubprogramOp, unsigned, CallOp)> visit =
        [&](SubprogramOp fn, unsigned frames, CallOp site) {
          reached[fn.getSymName()] = true;
          if (frames > kMaxCallFrames) {
            if (!bad)
              site.emitOpError() << "reaches a call depth of " << frames
                                 << " frames (entry included); this compiler supports at most "
                                 << kMaxCallFrames
                                 << " (a conservative limit of its own; the kernel verifier "
                                    "has the final say on call depth and stack)";
            bad = true;
            return;
          }
          if (depth.lookup(fn.getSymName()) >= frames)
            return; // Already visited through an equally deep or deeper chain.
          depth[fn.getSymName()] = frames;
          for (auto [call, callee] : calleesOf(fn))
            visit(callee, frames + 1, call);
        };
    for (auto prog : module.getOps<ProgramOp>())
      for (auto [call, callee] : calleesOf(prog))
        visit(callee, 2, call);
    // a timer.callback (sched_ext_ops owners — the op verifier) is its
    // own entry frame; its requirements reach the owners through set_callback.
    for (auto cb : module.getOps<TimerCallbackOp>())
      for (auto [call, callee] : calleesOf(cb))
        visit(callee, 2, call);
    for (auto fn : module.getOps<SubprogramOp>())
      if (!reached.lookup(fn.getSymName())) {
        bad = true;
        fn.emitOpError() << "is not reachable from any ebpf.program; an unreachable "
                            "subprogram would be emitted without a program to "
                            "attribute its requirements to";
      }
    if (bad)
      return signalPassFailure();

    // Reject loop calls reaching any ring-buffer operation, including within
    // the immediate callee. DFS terminates because cycles were rejected above.
    auto forbiddenIn = [](SubprogramOp fn) -> Operation * {
      Operation *found = nullptr;
      fn.walk([&](Operation *op) {
        auto kc = dyn_cast<KFieldCopyOp>(op); // Reservation-targeted kfield.copy counts like task.comm; borrowed targets are allowed.
        if (isa<RingbufReserveOp, RingbufIfReservedOp, RingbufStoreFieldOp, RingbufStoreRecordOp, TaskCommOp, CtxStackOp, KernelDPathOp, StrSnprintfOp, UserReadStrOp, UserCopyOp, UserCopyTaskOp, UserReadOp, KernelReadStrOp,
                RingbufSubmitOp, // Include kernel.read_str.
                RingbufDiscardOp, RingbufReserveDynptrOp, RingbufSubmitDynptrOp, RingbufDiscardDynptrOp>(op) || // Include dynptr reservations.
            (kc && kc.writesReservation())) {

          found = op;
          return WalkResult::interrupt();
        }
        return WalkResult::advance();
      });
      return found;
    };
    std::function<bool(SubprogramOp, std::string &)> reachesForbidden =
        [&](SubprogramOp fn, std::string &path) {
          path += " -> @" + fn.getSymName().str();
          if (Operation *op = forbiddenIn(fn)) {
            path += " (which contains '" + op->getName().getStringRef().str() + "')";
            return true;
          }
          for (auto [call, callee] : calleesOf(fn))
            if (reachesForbidden(callee, path))
              return true;
          path.resize(path.rfind(" -> @"));
          return false;
        };
    module.walk([&](CallOp call) {
      if (!call->getParentOfType<LoopOp>() && !call->getParentOfType<IterNumOp>() && !call->getParentOfType<IterScxDsqOp>()) // an iterator body too (the DSQ iterator)
        return;
      auto it = funcs.find(call.getCallee());
      if (it == funcs.end())
        return;
      std::string path;
      if (reachesForbidden(it->second, path)) {
        bad = true;
        call.emitOpError() << "is inside ebpf.loop but reaches" << path
                           << "; a subprogram called from a loop may not contain a ring buffer "
                              "op";
      }
    });
    if (bad)
      return signalPassFailure();

    // Start at (depth,product)=(0,1). Entering a loop adds one depth and multiplies
    // by max(N,1); calls pass that context to callees. Return restores the
    // caller context, so sibling loops do not multiply. Skip a context only if
    // previously visited in the same strategy category with both depth and
    // product at least as large. These
    // conservative compiler limits prove neither kernel limits nor workload.
    llvm::StringMap<SmallVector<LoopBudget>> visited;
    std::function<void(Region &, LoopBudget, SmallVector<std::string> &)> scan;
    auto enterFunc = [&](SubprogramOp fn, LoopBudget budget, SmallVector<std::string> &path) {
      auto &seen = visited[fn.getSymName()];
      for (const auto &prior : seen)
        if (prior.dominates(budget))
          return;
      seen.push_back(budget);
      path.push_back("@" + fn.getSymName().str());
      scan(fn.getBody(), budget, path);
      path.pop_back();
    };
    scan = [&](Region &r, LoopBudget budget, SmallVector<std::string> &path) {
      for (Block &blk : r)
        for (Operation &op : blk) {
          if (bad)
            return;
          if (auto loop = dyn_cast<LoopOp>(op)) {
            auto next = budget.enter(loop.getCount(), loop.getUnroll(), loop.getCallback());
            path.push_back("loop " + std::to_string(loop.getCount()));
            std::string along = llvm::join(path, " -> ");
            if (next.depth > LoopBudget::maxDepth) {
              bad = true;
              loop.emitOpError() << "is nested " << next.depth << " deep along " << along
                                 << " (loops reached through calls count the loops of every caller "
                                    "on the path); this compiler supports "
                                 << LoopBudget::maxDepth;
            } else if (next.product > next.productLimit()) {
              bad = true;
              loop.emitOpError() << "the counts along " << along << " multiply to " << next.product
                                 << ", over the limit of " << next.productLimit()
                                 << " this compiler supports (a count of 0 is taken as 1)";
            } else {
              scan(loop.getBody(), next, path);
            }
            path.pop_back();
            continue;
          }
          // an iterator adds one depth and no count factor (LoopBudget::enterIter).
          if (auto it = dyn_cast<IterNumOp>(op)) {
            auto next = budget.enterIter();
            path.push_back("iter.num");
            std::string along = llvm::join(path, " -> ");
            if (next.depth > LoopBudget::maxDepth) {
              bad = true;
              it.emitOpError() << "is nested " << next.depth << " deep along " << along
                               << " (loops and iterators reached through calls count those of every caller on the path); "
                                  "this compiler supports "
                               << LoopBudget::maxDepth;
            } else {
              scan(it.getBody(), next, path);
            }
            path.pop_back();
            continue;
          }
          // the DSQ iterator counts like ebpf.iter.num (one depth, no count factor).
          if (auto it = dyn_cast<IterScxDsqOp>(op)) {
            auto next = budget.enterIter();
            path.push_back("iter.scx_dsq");
            std::string along = llvm::join(path, " -> ");
            if (next.depth > LoopBudget::maxDepth) {
              bad = true;
              it.emitOpError() << "is nested " << next.depth << " deep along " << along
                               << " (loops and iterators reached through calls count those of every caller on the path); "
                                  "this compiler supports "
                               << LoopBudget::maxDepth;
            } else {
              scan(it.getBody(), next, path);
            }
            path.pop_back();
            continue;
          }
          if (auto call = dyn_cast<CallOp>(op)) {
            auto it = funcs.find(call.getCallee());
            if (it != funcs.end())
              enterFunc(it->second, budget, path);
            continue;
          }
          for (Region &inner : op.getRegions())
            scan(inner, budget, path);
        }
    };
    for (auto prog : module.getOps<ProgramOp>()) {
      SmallVector<std::string> path{"@" + prog.getSymName().str()};
      scan(prog.getBody(), LoopBudget{}, path);
    }
    for (auto cb : module.getOps<TimerCallbackOp>()) { // callees of a callback.
      SmallVector<std::string> path{"@" + cb.getSymName().str()};
      scan(cb.getBody(), LoopBudget{}, path);
    }
    if (bad)
      signalPassFailure();
  }
};

} // namespace
