// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Targets that send addressed UDP datagrams with sendto under the real filter (DGRAM-VERDICT): modeBenchDgram under
// the declared-net harness's contract, modeBenchDgramGuard under modeGuard's models[] guard, where an admitted
// datagram is relayed (relayDatagram).
const (
	modeBenchDgram      = "bench-dgram"
	modeBenchDgramGuard = "bench-dgram-guard"
	// helperDgramTo is where each datagram goes: "allowed" (the declared port), "denied" (the undeclared one) or
	// "mixed" (every tenth to the undeclared one).
	helperDgramTo = "TEGO_SUPERVISOR_DGRAM_TO"
	// helperDgramRate paces the sends at this many a second; unset or 0 sends as fast as the answers come.
	helperDgramRate = "TEGO_SUPERVISOR_DGRAM_RATE"
)

// targetDgramLoop sends helperLoops one-byte datagrams on one unconnected UDP socket to 127.0.0.1, at helperDgramTo's
// ports and helperDgramRate's pace, and times the whole loop. A send's result is not checked: a refusal is the
// answer under test, and the loop's lines say which it was.
func targetDgramLoop() (int, int64) {
	n, err := strconv.Atoi(os.Getenv(helperLoops))
	if err != nil || n <= 0 {
		return 0, 0
	}
	ports := splitPorts(os.Getenv(helperPorts))
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return 0, 0
	}
	defer unix.Close(fd) //nolint:errcheck // the target's own socket
	allowed := &unix.SockaddrInet4{Port: ports[0], Addr: [4]byte{127, 0, 0, 1}}
	denied := &unix.SockaddrInet4{Port: ports[1], Addr: [4]byte{127, 0, 0, 1}}
	to := os.Getenv(helperDgramTo)
	var interval time.Duration
	if rate, err := strconv.Atoi(os.Getenv(helperDgramRate)); err == nil && rate > 0 {
		interval = time.Second / time.Duration(rate)
	}
	msg := []byte{'x'}
	start := time.Now()
	for i := 0; i < n; i++ {
		if interval > 0 {
			due := time.Duration(i) * interval
			if ahead := due - time.Since(start); ahead > time.Millisecond {
				time.Sleep(ahead - time.Millisecond)
			}
			for time.Since(start) < due {
			}
		}
		dst := allowed
		if to == "denied" || (to == "mixed" && i%10 == 9) {
			dst = denied
		}
		_ = unix.Sendto(fd, msg, 0, dst)
	}
	return n, time.Since(start).Nanoseconds()
}

// BenchmarkRelayDatagram measures one addressed UDP datagram over a real seccomp listener, as the agent sees it
// (target-ns/op), on each path R13b gives one (DGRAM-VERDICT's budget: at most 20 µs per datagram on 6.17):
//
//   - continue: an admitted destination, recorded best effort and continued, as every datagram was before;
//   - kernel-refused: an undeclared destination where the run's cgroup/sendmsg4 decides UDP
//     (Options.KernelDatagrams): refused here with its EPERM, one line, nothing sent from here;
//   - refused: an undeclared destination no kernel program decides (tier landlock): refused here with R10's errno,
//     one line, nothing sent (R13b as amended 2026-10-16; before, it was continued under a best-effort refused line);
//   - relay: an admitted destination under the models[] guard, sent on the duplicate (relayDatagram): the path
//     proposed for every datagram a kernel program decides, measured for the record of why it was
//     not taken (ADR 0016's 2026-10-05 note).
//
// Like BenchmarkSeccompNotifyRoundTrip it needs no privilege, and the timer runs only across the target's loop.
func BenchmarkRelayDatagram(b *testing.B) {
	for _, bc := range []struct {
		name, mode, to string
		kernel         KernelDatagrams
	}{
		{"continue", modeBenchDgram, "allowed", KernelDatagrams{}},
		{"kernel-refused", modeBenchDgram, "denied", KernelDatagrams{UDP: unix.EPERM}},
		{"refused", modeBenchDgram, "denied", KernelDatagrams{}},
		{"relay", modeBenchDgramGuard, "allowed", KernelDatagrams{}},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.StopTimer()
			h := startHarnessWith(b, harnessOpts{
				loops: b.N, mode: bc.mode, env: []string{helperDgramTo + "=" + bc.to}, kernel: bc.kernel,
				acked: b.StartTimer, reported: b.StopTimer,
			})
			m := h.stop(b)
			if h.report.LoopOps != b.N {
				b.Fatalf("the target reported %d datagrams, want %d", h.report.LoopOps, b.N)
			}
			if m.Notifications < int64(b.N) {
				b.Fatalf("the loop received %d notifications for %d datagrams", m.Notifications, b.N)
			}
			b.ReportMetric(float64(h.report.LoopNS)/float64(b.N), "target-ns/op")
		})
	}
}

// TestIntegrationUDPFlood is DGRAM-VERDICT's flood cell: 10,000 addressed UDP datagrams a second for 10 s, every tenth
// to an undeclared destination the run's kernel program decides (Options.KernelDatagrams), keep pace with no
// notification backlog over R22's soft budget. The target falls no more than a tenth behind its schedule, the loop
// holds a notification for less than SoftCeiling on average, every datagram is answered and has its one line, and
// every refused one is refused here, with the kernel program's errno, without best_effort. The two budgets are a
// pace and a latency on the wall clock, which the machine's scheduler is part of: budget mode
// (testutil.BudgetsEnv, set by scripts/timing-budgets.sh) holds them to their limits, the unit gate to
// testutil.CeilingFactor times them (docs/BENCHMARKS.md, "Timing budgets in the test suites"). The target may run
// for helperTimeout past the pace's ceiling before it is killed, so a flood that finishes past the ceiling is judged
// on its own figure, and one still sending when it is killed is judged on the time it had run, which is past both the
// Limit and the ceiling: either way the failure is the pace budget's own. The count, line and refusal checks hold in
// both modes.
func TestIntegrationUDPFlood(t *testing.T) {
	mode := testutil.TimingMode(t)
	const rate, seconds = 10000, 10
	const total = rate * seconds
	pace := testutil.Budget{Name: "the target's time for " + strconv.Itoa(total) + " datagrams scheduled over " +
		strconv.Itoa(seconds) + "s", Limit: seconds * time.Second * 11 / 10, Spec: "DGRAM-VERDICT: the loop keeps pace"}
	h := startHarnessWith(t, harnessOpts{
		loops: total, mode: modeBenchDgram, kernel: KernelDatagrams{UDP: unix.EPERM},
		env:     []string{helperDgramTo + "=mixed", helperDgramRate + "=" + strconv.Itoa(rate)},
		timeout: pace.Ceiling() + helperTimeout,
		outOfTime: func(t testing.TB, ran time.Duration) {
			t.Logf("FLOOD: the target was still sending %v after it started, and was killed", ran)
			mode.Judge(t, pace, testutil.Figure{Wall: ran})
		},
	})
	m := h.stop(t)
	if h.report.LoopOps != total {
		t.Fatalf("the target reported %d datagrams, want %d", h.report.LoopOps, total)
	}
	took := time.Duration(h.report.LoopNS)
	held := time.Duration(m.HeldMS) * time.Millisecond / time.Duration(max(m.Notifications, 1))
	t.Logf("FLOOD %d datagrams in %v (scheduled %ds): %d notifications, %v held on average, %d over %v", total, took,
		seconds, m.Notifications, held, m.Anomalies, SoftCeiling)
	mode.Judge(t, pace, testutil.Figure{Wall: took})
	if m.Notifications < total {
		t.Errorf("%d notifications for %d datagrams", m.Notifications, total)
	}
	mode.Judge(t, testutil.Budget{Name: "a notification's mean hold", Limit: SoftCeiling, Spec: "R22's soft budget"},
		testutil.Figure{Wall: held})
	allowed := h.netEvents(t, "127.0.0.1:"+strconv.Itoa(h.allowedPort))
	denied := h.netEvents(t, "127.0.0.1:"+strconv.Itoa(h.deniedPort))
	if len(allowed) != total-total/10 || len(denied) != total/10 {
		t.Fatalf("%d lines for the declared port and %d for the undeclared one, want %d and %d", len(allowed), len(denied),
			total-total/10, total/10)
	}
	for _, ev := range denied {
		var p netPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if ev.Verdict != record.VerdictRefused || p.BestEffort {
			t.Fatalf("an undeclared datagram's line is %s best_effort=%t, want the refusal made here", ev.Verdict, p.BestEffort)
		}
	}
}
