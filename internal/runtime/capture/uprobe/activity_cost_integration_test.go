// SPDX-License-Identifier: Apache-2.0

//go:build integration

package uprobe

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// The record-off plan's two budgets for the TLS half of the activity stamp (§5): what a run process's TLS call costs
// under record: off once the shared probes are placed for its stall check (the probe programs' own run time, over
// the trap ADR 0026 (9) prices), and what placing them adds to such a run's start.

// echoClient is a CPython client that makes argv[2] 16-byte round trips over one TLS connection through the host's
// libssl: each is one SSL_write and at least one SSL_read.
const echoClient = `import socket, ssl, sys
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
n = int(sys.argv[2])
with socket.create_connection(("127.0.0.1", int(sys.argv[1]))) as raw:
    with ctx.wrap_socket(raw, server_hostname="api.anthropic.com") as s:
        for _ in range(n):
            s.sendall(b"0123456789abcdef")
            got = b""
            while len(got) < 16:
                got += s.recv(16 - len(got))
print("DONE", flush=True)
`

// tlsEcho echoes what each TLS connection sends until the test ends.
func tlsEcho(t *testing.T) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
}

// probePrograms opens the program behind every probe pinned for the build, once each, and reports whether the probes
// are uprobe_multi links.
func probePrograms(t *testing.T, buildRoot string) ([]*ebpf.Program, bool) {
	t.Helper()
	var progs []*ebpf.Program
	var seen []ebpf.ProgramID
	multi := false
	libs, err := os.ReadDir(filepath.Join(buildRoot, UprobePinDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, lib := range libs {
		dir := filepath.Join(buildRoot, UprobePinDir, lib.Name())
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			l, err := link.LoadPinnedLink(filepath.Join(dir, e.Name()), nil)
			if err != nil {
				t.Fatalf("pinned probe %s/%s: %v", dir, e.Name(), err)
			}
			info, err := l.Info()
			_ = l.Close()
			if err != nil {
				t.Fatal(err)
			}
			multi = multi || info.Type == link.UprobeMultiType
			if slices.Contains(seen, info.Program) {
				continue
			}
			seen = append(seen, info.Program)
			p, err := ebpf.NewProgramFromID(info.Program)
			if err != nil {
				t.Fatalf("program %d of probe %s/%s: %v", info.Program, dir, e.Name(), err)
			}
			t.Cleanup(func() { _ = p.Close() })
			progs = append(progs, p)
		}
	}
	if len(progs) == 0 {
		t.Fatal("no probe program is pinned for the build")
	}
	return progs, multi
}

// TestIntegrationRecordOffTLSCallCost is the record-off plan's budget for a run process's TLS call under record: off
// (§5: at most +50 ns over the shared probe's trap): the probe programs' own run time, from the kernel's BPF run-time
// statistics, per TLS call its client makes (a 16-byte SSL_write and the SSL_read of the echo, so three program runs:
// the write's entry, the read's entry and its return). Three rows are alternated over 9 rounds, each read as its best
// round: the record: off run whose row carries RunActivity, the same row without the flag, and no row at all, the
// client outside every run. That last is the shared probe's trap: what every host process's TLS call pays while the
// probes are placed (ADR 0026 (9)), the trap and the run-set miss; the budget is what the flagged run pays over it.
// The stamp's own work is the flagged row over the unflagged one. TARGET-MISS above 50 ns; the test fails past 500 ns
// of program time a call, a probe that does more under off than its source says (a register test, a run-set lookup
// and the stamp), and when the flagged rounds stamp nothing.
func TestIntegrationRecordOffTLSCallCost(t *testing.T) {
	requireObjects(t)
	requireRoot(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	if len(systemLibraries("/", nil)) == 0 {
		t.Skip("this host has no libssl for pre-attach to find")
	}
	stats, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		t.Skipf("BPF run-time statistics are not available here: %v", err)
	}
	defer stats.Close()
	const hash, slot, trips, rounds = "integration", 2, 3000, 9
	root, maps := bpffsPinRoot(t, hash)
	_, fd, cg := childCgroupOf(t, "cost")
	pinned := seedActivityRuns(t, maps, map[uint64]bpf.Run{cg: activityRow(slot, bpf.RecordOff)}, nil)
	port := tlsEcho(t)
	u, err := New(Options{Kernel: true, PinRoot: root, StateDir: t.TempDir(), Logger: testLogger(t), Detach: func(detachJob) {},
		Rules: &agent.RuleTable{Record: agent.RecordOff, Limits: agent.ResolvedLimits{StallAfter: 3 * time.Second, Set: agent.BudgetStallAfter}}})
	if err != nil {
		t.Fatal(err)
	}
	u.FollowKernel(hash)
	if err := u.Start(context.Background(), source.RunRef{ID: "r-int-cost", Agent: "a", CgroupID: cg}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = u.Stop() })
	progs, multi := probePrograms(t, filepath.Join(root, hash))
	runtimeOf := func() (time.Duration, uint64) {
		t.Helper()
		var rt time.Duration
		var n uint64
		for _, p := range progs {
			s, err := p.Stats()
			if err != nil {
				t.Fatalf("program statistics: %v", err)
			}
			rt += s.Runtime
			n += s.RunCount
		}
		return rt, n
	}
	// outside is the row of a client in no run: its cgroup has no run-set entry, so the probes miss and return.
	const outside = 0xff
	perCall := func(flags uint8) float64 {
		t.Helper()
		if flags == outside {
			if err := pinned[bpf.MapRunSet].Delete(&cg); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatal(err)
			}
		} else {
			row := activityRow(slot, bpf.RecordOff)
			row.Flags = flags
			if err := pinned[bpf.MapRunSet].Update(&cg, &row, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
		}
		rt0, n0 := runtimeOf()
		cmd := exec.Command(python, "-c", echoClient, port, strconv.Itoa(trips))
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("python3: %v: %s", err, out)
		}
		rt1, n1 := runtimeOf()
		if n1-n0 < 3*trips {
			t.Fatalf("the probes ran %d times for %d round trips: they are not on the client's libssl", n1-n0, trips)
		}
		return float64(rt1-rt0) / float64(2*trips)
	}
	best := map[uint8]float64{}
	arms := []uint8{outside, 0, bpf.RunActivity}
	for round := range rounds {
		order := slices.Clone(arms)
		if round%2 == 1 {
			slices.Reverse(order)
		}
		for _, flags := range order {
			if ns := perCall(flags); best[flags] == 0 || ns < best[flags] {
				best[flags] = ns
			}
		}
	}
	if v, _ := bpf.ActivityAt(pinned[bpf.MapActivity], slot); v == 0 {
		t.Fatal("the flagged rounds stamped nothing at the run's slot")
	}
	const target = 50.0
	got := best[bpf.RunActivity]
	over := got - best[outside]
	t.Logf("TLS probes under record: off on %s (multi %v), program time a call: %.1f ns for a run with the stamp, %.1f ns "+
		"without it, %.1f ns for a process outside every run: %+.1f ns over the shared probe (target %.0f ns), %+.1f ns "+
		"the stamp (best of %d rounds of %d round trips)", kernelRelease(t), multi, got, best[0], best[outside], over,
		target, got-best[0], rounds, trips)
	if over > target {
		t.Logf("TARGET-MISS tls.activity_call_ns %.1f over its target %.0f on %s", over, target, kernelRelease(t))
	}
	if got > 500 {
		t.Errorf("a record: off run's TLS call costs %.1f ns of probe program time, over the 500 ns limit", got)
	}
}

// TestIntegrationRecordOffActivityStartCost is the record-off plan's budget for what placing the shared probes adds to
// the start of a record: off run with a stall budget (§5: a median of at most 30 ms where the kernel has
// uprobe_multi, 6.6 and RHEL 9's 5.14, and 150 ms on 6.1, whose probes are placed one perf event each), against the
// same run without a stall budget, which places none. Each round starts from no probe at all (the previous holder's
// detach has run), the cold start a solo run pays; the two kinds alternate over 7 rounds. TARGET-MISS above the
// target; the test fails past the pre-attach budget, which bounds what Start may spend placing.
func TestIntegrationRecordOffActivityStartCost(t *testing.T) {
	requireObjects(t)
	requireRoot(t)
	if len(systemLibraries("/", nil)) == 0 {
		t.Skip("this host has no libssl for pre-attach to find")
	}
	const hash, slot, rounds = "integration", 2, 7
	root, maps := bpffsPinRoot(t, hash)
	_, _, cg := childCgroupOf(t, "start")
	seedActivityRuns(t, maps, map[uint64]bpf.Run{cg: activityRow(slot, bpf.RecordOff)}, nil)
	state := t.TempDir()
	multi := false
	start := func(stall bool) time.Duration {
		t.Helper()
		rules := &agent.RuleTable{Record: agent.RecordOff}
		if stall {
			rules.Limits = agent.ResolvedLimits{StallAfter: 3 * time.Second, Set: agent.BudgetStallAfter}
		}
		var mu sync.Mutex
		var jobs []detachJob
		u, err := New(Options{Kernel: true, PinRoot: root, StateDir: state, Logger: testLogger(t), Rules: rules,
			Detach: func(j detachJob) { mu.Lock(); jobs = append(jobs, j); mu.Unlock() }})
		if err != nil {
			t.Fatal(err)
		}
		u.FollowKernel(hash)
		began := time.Now()
		if err := u.Start(context.Background(), source.RunRef{ID: "r-int-start", Agent: "a", CgroupID: cg}, &fakeSink{}); err != nil {
			t.Fatal(err)
		}
		took := time.Since(began)
		placed := len(pinnedLinkIDs(t, filepath.Join(root, hash))) > 0
		if placed != stall {
			t.Fatalf("a record: off run with a stall budget %v placed probes %v", stall, placed)
		}
		if placed && !multi {
			_, multi = probePrograms(t, filepath.Join(root, hash))
		}
		if err := u.Stop(); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		for _, j := range jobs {
			if err := detachAfter(j, 0); err != nil {
				t.Fatal(err)
			}
		}
		if left, _ := os.ReadDir(filepath.Join(root, hash, UprobePinDir)); len(left) != 0 {
			t.Fatalf("probes left after the last holder's detach: %v", left)
		}
		return took
	}
	// load is the capture object's load alone (LoadCollection, the verifier's work on uprobe_ssl), which an
	// activity-only Start pays as a capture run's does before it places a probe: the part of the added time that is
	// not placement.
	load := func() time.Duration {
		t.Helper()
		began := time.Now()
		coll, err := LoadCollection(root, hash)
		took := time.Since(began)
		if err != nil {
			t.Fatalf("load the capture object: %v", err)
		}
		coll.Close()
		return took
	}
	var with, without, loads []time.Duration
	for round := range rounds {
		for _, stall := range []bool{round%2 == 0, round%2 == 1} {
			if d := start(stall); stall {
				with = append(with, d)
			} else {
				without = append(without, d)
			}
		}
		loads = append(loads, load())
	}
	slices.Sort(with)
	slices.Sort(without)
	slices.Sort(loads)
	added := with[rounds/2] - without[rounds/2]
	target := 150 * time.Millisecond
	if multi {
		target = 30 * time.Millisecond
	}
	t.Logf("record: off Start on %s (multi %v): median %s with a stall budget (probes placed), %s without: %s added "+
		"(target %s; %d rounds each, cold), of which the capture object's load is a median %s", kernelRelease(t), multi,
		with[rounds/2], without[rounds/2], added, target, rounds, loads[rounds/2])
	if added > target {
		t.Logf("TARGET-MISS start.activity_probes_ms %.1f over its target %.0f on %s", float64(added)/1e6,
			float64(target)/1e6, kernelRelease(t))
	}
	if with[rounds/2] > DefaultPreattachBudget {
		t.Errorf("a record: off run's Start took %s to place its probes, past the pre-attach budget %s",
			with[rounds/2], DefaultPreattachBudget)
	}
}

// kernelRelease is uname -r.
func kernelRelease(t *testing.T) string {
	t.Helper()
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Fatal(err)
	}
	return unix.ByteSliceToString(uts.Release[:])
}
