// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"os"
	"path/filepath"
	"testing"
)

// modeBench is a target that makes only targetLoop's notified mkdirat calls: no checks, so the harness's
// report is the loop and nothing else.
const modeBench = "bench"

// BenchmarkSeccompNotifyRoundTrip measures one notified syscall over a real seccomp listener, which
// BenchmarkNotificationRoundTrip fakes: the target's mkdirat blocks in the kernel, a real Loop receives the
// notification, reads the path out of the target, decides it against the contract, records it and answers
// CONTINUE, and the kernel runs the syscall (EEXIST: the directory is made before the target starts). That
// is the record-and-continue fast path P0-DESIGN §9 budgets at under 10 µs, whose soft ceiling
// TestIntegrationFastPath asserts.
//
// The loop runs in the target process, b.N calls of it per target: the timer runs from the ack that releases
// the target to its report, so the target's start, the filter's install and the listener's hand-over stay out
// of ns/op and -benchtime settles b.N as it would for an in-process loop. Allocations are this process's over
// the same span: the loop's per-notification cost plus a report decode per target. target-ns/op is the
// target's own reading of its loop, the round trip as the agent sees it.
//
// It needs no privilege: the target sets no_new_privs before installing the filter, and pidfd_getfd of one's
// own child passes the ptrace check under yama's ptrace_scope 1. A kernel without seccomp user notification
// skips it, naming why (startHarnessWith).
func BenchmarkSeccompNotifyRoundTrip(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	h := startHarnessWith(b, harnessOpts{
		loops: b.N,
		mode:  modeBench,
		prepare: func(dir string) {
			if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
				b.Fatal(err)
			}
		},
		acked:    b.StartTimer,
		reported: b.StopTimer,
	})
	m := h.stop(b)
	if h.report.LoopOps != b.N {
		b.Fatalf("the target reported %d operations, want %d", h.report.LoopOps, b.N)
	}
	if m.Notifications < int64(b.N) {
		b.Fatalf("the loop received %d notifications for %d notified calls", m.Notifications, b.N)
	}
	b.ReportMetric(float64(h.report.LoopNS)/float64(b.N), "target-ns/op")
}
