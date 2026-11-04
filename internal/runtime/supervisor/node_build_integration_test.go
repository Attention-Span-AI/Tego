// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const modeNodePoolBench = "node-pool-bench"

// The target carries the TSYNC filter on every thread, so all four execs
// actually notify the parent's production supervisor pool, including Node's
// own startup syscalls. Each batch joins all four real Node processes.
func targetNodePoolLoop() (int, int64, error) {
	n, err := strconv.Atoi(os.Getenv(helperLoops))
	if err != nil || n <= 0 {
		return 0, 0, fmt.Errorf("invalid node batch count: %q", os.Getenv(helperLoops))
	}
	nodePath := os.Getenv("TEGO_NODE22_BIN")
	start := time.Now()
	for range n {
		var wg sync.WaitGroup
		errs := make(chan error, 4)
		for range 4 {
			wg.Go(func() { errs <- exec.Command(nodePath, "-e", "0").Run() })
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				return 0, time.Since(start).Nanoseconds(), fmt.Errorf("node exec: %w", err)
			}
		}
	}
	return n, time.Since(start).Nanoseconds(), nil
}

// An op is four parallel, real Node execs through a real seccomp listener and
// the four-worker pool. Timing includes process launch, Node startup and exit;
// it excludes harness/filter setup and listener handoff, as the other real
// notification benchmarks do. Every benchmark repetition creates a fresh Loop.
func BenchmarkNodeSeccompPool4(b *testing.B) {
	nodePath := nodeBenchPath(b)
	b.ReportAllocs()
	b.StopTimer()
	h := startHarnessWith(b, harnessOpts{
		loops: b.N, mode: modeNodePoolBench, workers: 4,
		env: []string{"TEGO_NODE22_BIN=" + nodePath},
		rules: func(rt *agent.RuleTable, _ string) {
			*rt = *commandPolicy(b, "deny: b.js").Rules
		},
		acked: b.StartTimer, reported: b.StopTimer,
	})
	m := h.stop(b)
	if h.report.LoopOps != b.N || len(h.report.Checks) != 1 || h.report.Checks[0].Err != "" || m.Notifications < int64(4*b.N) {
		b.Fatalf("four-node batch failed or escaped notifications: %+v, %+v", h.report, m)
	}
	execs := 0
	for _, ev := range h.sink.all() {
		if ev.Kind == record.KindExec {
			if ev.Verdict != record.VerdictAllow {
				b.Fatalf("Node exec was not allowed: %+v", ev)
			}
			execs++
		}
	}
	if execs != 4*b.N {
		b.Fatalf("recorded %d execs, want %d; all four target threads must notify", execs, 4*b.N)
	}
	b.ReportMetric(float64(h.report.LoopNS)/float64(b.N), "target-ns/op")
}
