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

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestEveryNestedCgroupIsInTheRunSetBeforeATaskCanJoinIt is enforce-cgroup-observe.md §8 I6: a cgroup a task can join already has a run_set
// row when it belongs to a live run (R11). cgroup_track's tp_btf/cgroup_mkdir runs inside mkdir(2), before the
// new cgroup's directory exists for anyone to write a pid into, so the row is there by the time mkdir returns.
// The test makes a chain of 500 cgroups, each inside the one before, under a live run's cgroup, and reads each
// one's row the moment its mkdir returns: every one must be the run's, with the run's slot, and not one may be
// missing (an "unmatched" cgroup, whose tasks the tracing programs would not record as the run's). A process
// placed at the bottom of the chain, and one half way down, then connect: the run's programs decide both
// (a destination the contract names is reached, one it does not is refused), and the breadcrumb says so.
func TestEveryNestedCgroupIsInTheRunSetBeforeATaskCanJoinIt(t *testing.T) {
	if !ebpfbindings.Available() {
		t.Skip("built without the compiled objects; add -tags tegobpf")
	}
	if err := checkBPFFS(DefaultBPFFS); err != nil {
		t.Skipf("%v", err)
	}
	requireBPFCaps(t)
	const depth = 500

	rel := fmt.Sprintf("/tego-it-nested-%d", os.Getpid())
	full := filepath.Join("/sys/fs/cgroup", rel)
	if err := os.Mkdir(full, 0o755); err != nil {
		t.Skipf("cannot create a cgroup for the run at %s: %v", full, err)
	}
	var chain []string // every nested cgroup's full path, outermost first
	t.Cleanup(func() {
		for i := len(chain) - 1; i >= 0; i-- {
			_ = os.Remove(chain[i])
		}
		_ = os.Remove(full)
	})
	id, err := cgroupIDOfPath("/sys/fs/cgroup", rel)
	if err != nil {
		t.Fatalf("cgroup id: %v", err)
	}
	allowedPort, refusedPort := listenLoopback(t, "tcp4", "127.0.0.1"), listenLoopback(t, "tcp4", "127.0.0.1")
	rt := &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordFull, Net: []agent.NetRule{{
		Raw: "127.0.0.1:" + strconv.Itoa(allowedPort), Port: allowedPort, Proto: agent.ProtoInet,
		Verdict: agent.VerdictAllow, IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Static: true}}}
	b := New(Options{Machine: machineLinger(0), StateDir: pinState(t), Events: &sink{}})
	h, err := b.Prepare(context.Background(), rt, Run{ID: "it-nested", Agent: "a", CgroupID: id, CgroupPath: rel})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if err := h.Attach(id); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := h.Arm(); err != nil { // the run-set row is Arm's (ADR 0021 (2))
		t.Fatalf("Arm: %v", err)
	}
	runSet := h.kern.(*bpfKernel).maps[ebpfbindings.MapRunSet]
	if runSet == nil {
		t.Fatal("the run set is not loaded")
	}
	var own ebpfbindings.Run
	if err := runSet.Lookup(&id, &own); err != nil {
		t.Fatalf("the run's own cgroup %d has no run-set row after Attach: %v", id, err)
	}

	unmatched, foreign := 0, 0
	dir, relDir := full, rel
	for i := range depth {
		dir, relDir = filepath.Join(dir, "n"), relDir+"/n"
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir level %d (%s): %v", i+1, dir, err)
		}
		chain = append(chain, dir)
		cid, err := cgroupIDOfPath("/sys/fs/cgroup", relDir)
		if err != nil {
			t.Fatalf("cgroup id of level %d: %v", i+1, err)
		}
		var row ebpfbindings.Run
		switch err := runSet.Lookup(&cid, &row); {
		case errors.Is(err, ebpf.ErrKeyNotExist):
			unmatched++
			if unmatched <= 3 {
				t.Errorf("level %d (cgroup %d): no run-set row when its mkdir returned: %v", i+1, cid, err)
			}
		case err != nil:
			t.Fatalf("level %d: read the run set: %v", i+1, err)
		case row.RunIdx != own.RunIdx || row.Record != own.Record:
			foreign++
			t.Errorf("level %d (cgroup %d): row slot %d record %d, want the run's slot %d record %d", i+1, cid,
				row.RunIdx, row.Record, own.RunIdx, own.Record)
		}
	}
	if unmatched != 0 || foreign != 0 {
		t.Fatalf("of %d nested cgroups, %d had no run-set row and %d another's", depth, unmatched, foreign)
	}
	t.Logf("all %d nested cgroups carried the run's row (slot %d) when their mkdir returned", depth, own.RunIdx)

	reasons := h.kern.(*bpfKernel).maps[ebpfbindings.MapReason]
	for _, level := range []int{depth / 2, depth} {
		cdir, err := os.Open(chain[level-1])
		if err != nil {
			t.Fatal(err)
		}
		targets := []string{"tcp4 127.0.0.1:" + strconv.Itoa(refusedPort), "tcp4 127.0.0.1:" + strconv.Itoa(allowedPort)}
		got := runNetHelper(t, cdir, "connect", targets)
		_ = cdir.Close()
		if !errors.Is(got[0], unix.EPERM) || got[1] != nil {
			t.Fatalf("from nesting level %d: %s = %v, %s = %v; want EPERM and success", level, targets[0], got[0],
				targets[1], got[1])
		}
		var br ebpfbindings.Breadcrumb
		if err := reasons.Lookup(&id, &br); err != nil || int(br.Port) != allowedPort ||
			ebpfbindings.Verdict(br.Verdict) != ebpfbindings.VerdictAllow || br.RunIdx != h.Slot() {
			t.Fatalf("from nesting level %d the breadcrumb is %+v (%v); want the allowed port %d under slot %d", level,
				br, err, allowedPort, h.Slot())
		}
	}
}
