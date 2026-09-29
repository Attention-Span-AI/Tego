// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestTwoBuildsCoexistWithoutInterference is §6 E22 and E29 (and capture-derive.md E27, whose capture code only
// ever sees its own bpf_hash's pins, so an upgrade mid-run leaves both builds' runs whole) against the running kernel: a binary upgrade leaves a
// run of the old build live while a run of the new one starts, so two bpf_hash builds' objects are pinned, their
// tracing programs attached host-wide, and their cgroup programs attached to their own runs' cgroups, side by side.
// The two builds here are the same objects under two build identities (Options.Hash), which is what the kernel
// sees of an upgrade: separate pin directories, maps, run_idx spaces and links. Each run's contract allows the
// port the other refuses, so any cross-build interference shows as a wrong verdict:
//
//   - each run's connects are decided by its own contract, and its breadcrumb is in its own build's reason map;
//   - each build's run set holds its own run's cgroup and not the other's;
//   - when the old build's last run ends and its pins go, the new build's run still decides as before and its
//     pins stay.
//
// It also measures E29's coexistence cost: the per-open cost to a process outside every run, with no build
// attached, one and two. Each build's tracing programs run for every open on the host and filter by their own run
// set, so the second build adds one more miss per hook; the numbers are logged, and E29 states them.
func TestTwoBuildsCoexistWithoutInterference(t *testing.T) {
	if !ebpfbindings.Available() {
		t.Skip("built without the compiled objects; add -tags tegobpf")
	}
	if err := checkBPFFS(DefaultBPFFS); err != nil {
		t.Skipf("%v", err)
	}
	requireBPFCaps(t)
	real, err := bpfHash()
	if err != nil {
		t.Fatal(err)
	}

	portA, portB := listenLoopback(t, "tcp4", "127.0.0.1"), listenLoopback(t, "tcp4", "127.0.0.1")
	allow := func(port int) []agent.NetRule {
		return []agent.NetRule{{Raw: "127.0.0.1:" + strconv.Itoa(port), Port: port, Proto: agent.ProtoInet,
			Verdict: agent.VerdictAllow, IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Static: true}}
	}
	type build struct {
		name    string
		hash    string
		allowed int
		refused int
		rel     string
		id      uint64
		dir     *os.File
		h       *Handle
	}
	// Distinct identities of the same length as a real bpf_hash, so no pin path is shorter than production's.
	builds := []*build{
		{name: "old", hash: fmt.Sprintf("%.8s%08x", real, os.Getpid()), allowed: portA, refused: portB},
		{name: "new", hash: fmt.Sprintf("%.8s%08x", real, os.Getpid()+1), allowed: portB, refused: portA},
	}
	const opens = 20000
	perOpen := []time.Duration{openCost(t, opens)}
	for _, bd := range builds {
		bd.rel = fmt.Sprintf("/tego-it-upgrade-%s-%d", bd.name, os.Getpid())
		full := filepath.Join("/sys/fs/cgroup", bd.rel)
		if err := os.Mkdir(full, 0o755); err != nil {
			t.Skipf("cannot create a cgroup for the run at %s: %v", full, err)
		}
		t.Cleanup(func() { _ = os.Remove(full) })
		if bd.id, err = cgroupIDOfPath("/sys/fs/cgroup", bd.rel); err != nil {
			t.Fatal(err)
		}
		b := New(Options{Machine: machineLinger(0), StateDir: pinState(t), Events: &sink{}, Hash: bd.hash})
		rt := &agent.RuleTable{Net: allow(bd.allowed), Tier: backend.TierCgroup, Record: agent.RecordFull}
		if bd.h, err = b.Prepare(context.Background(), rt, Run{ID: "it-upgrade-" + bd.name, Agent: "a", CgroupID: bd.id,
			CgroupPath: bd.rel}); err != nil {
			t.Fatalf("Prepare, %s build: %v", bd.name, err)
		}
		h := bd.h
		t.Cleanup(func() { _ = h.Close() })
		if err := bd.h.Attach(bd.id); err != nil {
			t.Fatalf("Attach, %s build: %v", bd.name, err)
		}
		if err := bd.h.Arm(); err != nil { // the run-set row is Arm's (ADR 0021 (2))
			t.Fatalf("Arm, %s build: %v", bd.name, err)
		}
		if bd.dir, err = os.Open(full); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = bd.dir.Close() })
		perOpen = append(perOpen, openCost(t, opens))
	}
	t.Logf("per open(2) of a process outside every run, %d opens: no build %v, one build %v, two builds %v",
		opens, perOpen[0], perOpen[1], perOpen[2])

	check := func(what string, bd *build) {
		t.Helper()
		targets := []string{"tcp4 127.0.0.1:" + strconv.Itoa(bd.refused), "tcp4 127.0.0.1:" + strconv.Itoa(bd.allowed)}
		got := runNetHelper(t, bd.dir, "connect", targets)
		if !errors.Is(got[0], unix.EPERM) || got[1] != nil {
			t.Fatalf("%s: the %s build's run: %s = %v, %s = %v; want EPERM and success, as its own contract says",
				what, bd.name, targets[0], got[0], targets[1], got[1])
		}
		reasons := bd.h.kern.(*bpfKernel).maps[ebpfbindings.MapReason]
		var br ebpfbindings.Breadcrumb
		if err := reasons.Lookup(&bd.id, &br); err != nil || int(br.Port) != bd.allowed ||
			ebpfbindings.Verdict(br.Verdict) != ebpfbindings.VerdictAllow || br.RunIdx != bd.h.Slot() {
			t.Fatalf("%s: the %s build's breadcrumb %+v (%v); want allow on %d under its slot %d", what, bd.name, br,
				err, bd.allowed, bd.h.Slot())
		}
	}
	membership := func(what string, bd, other *build) {
		t.Helper()
		runSet := bd.h.kern.(*bpfKernel).maps[ebpfbindings.MapRunSet]
		var row ebpfbindings.Run
		if err := runSet.Lookup(&bd.id, &row); err != nil {
			t.Fatalf("%s: the %s build's run set has no row for its own run: %v", what, bd.name, err)
		}
		if other != nil {
			if err := runSet.Lookup(&other.id, &row); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("%s: the %s build's run set has the %s build's run (%+v, %v)", what, bd.name, other.name, row, err)
			}
		}
	}
	for _, bd := range builds {
		check("both builds live", bd)
	}
	membership("both builds live", builds[0], builds[1])
	membership("both builds live", builds[1], builds[0])

	// The old build's last run ends: its pins go, the new build's stay and its run decides as before.
	oldPins := filepath.Join(DefaultBPFFS, "tego", builds[0].hash)
	newPins := filepath.Join(DefaultBPFFS, "tego", builds[1].hash)
	if err := builds[0].h.Close(); err != nil {
		t.Fatalf("Close, old build: %v", err)
	}
	if _, err := os.Stat(oldPins); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the old build's last run ended and its pins stayed at %s (%v)", oldPins, err)
	}
	if _, err := os.Stat(newPins); err != nil {
		t.Fatalf("the old build's teardown took the new build's pins at %s: %v", newPins, err)
	}
	check("after the old build's teardown", builds[1])
	membership("after the old build's teardown", builds[1], nil)
}

// openCost is the mean wall time of one open(2)+close(2) of a file on the root mount by this process, which is in
// no run: what every build's host-wide tracing programs cost a process they do not record.
func openCost(t *testing.T, n int) time.Duration {
	t.Helper()
	start := time.Now()
	for range n {
		fd, err := unix.Open("/etc/hostname", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			fd, err = unix.Open("/proc/self/stat", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		}
		if err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(fd)
	}
	return time.Since(start) / time.Duration(n)
}
