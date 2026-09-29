// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestRmdirOfANestedCgroupDeletesItsRunSetRow is docs/p0/enforce-cgroup-observe.md §6 E6 and E26 against the
// running kernel: a cgroup made inside a live run's cgroup gets its run_set row inside mkdir (R11), and its
// rmdir, from anyone (here, this process, outside tego), deletes that row and only that row: the create-then-
// immediate-rmdir of E6 nets to zero, and the run's own row, keyed by another cgroup id, is untouched.
func TestRmdirOfANestedCgroupDeletesItsRunSetRow(t *testing.T) {
	if !ebpfbindings.Available() {
		t.Skip("built without the compiled objects; add -tags tegobpf")
	}
	if err := checkBPFFS(DefaultBPFFS); err != nil {
		t.Skipf("%v", err)
	}
	requireBPFCaps(t)

	rel := fmt.Sprintf("/tego-it-rmdir-%d", os.Getpid())
	full := filepath.Join("/sys/fs/cgroup", rel)
	if err := os.Mkdir(full, 0o755); err != nil {
		t.Skipf("cannot create a cgroup for the run at %s: %v", full, err)
	}
	child := filepath.Join(full, "child")
	t.Cleanup(func() {
		_ = os.Remove(child)
		_ = os.Remove(full)
	})
	id, err := cgroupIDOfPath("/sys/fs/cgroup", rel)
	if err != nil {
		t.Fatalf("cgroup id: %v", err)
	}
	rt := &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordFull}
	b := New(Options{Machine: machineLinger(0), StateDir: pinState(t), Events: &sink{}})
	h, err := b.Prepare(context.Background(), rt, Run{ID: "it-rmdir", Agent: "a", CgroupID: id, CgroupPath: rel})
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
	// A prepared capability is part of immutable membership, not reconstructed
	// from a descendant's cgroup or a recorder's mode-specific slot maps.
	want := h.runRow()
	want.Flags = ebpfbindings.RunListenerResults
	if err := runSet.Put(&id, &want); err != nil {
		t.Fatal(err)
	}

	for round := range 3 { // E6: create then immediately remove, repeatedly
		if err := os.Mkdir(child, 0o755); err != nil {
			t.Fatalf("round %d: mkdir: %v", round, err)
		}
		cid, err := cgroupIDOfPath("/sys/fs/cgroup", rel+"/child")
		if err != nil {
			t.Fatalf("round %d: cgroup id: %v", round, err)
		}
		var row ebpfbindings.Run
		if err := runSet.Lookup(&cid, &row); err != nil {
			t.Fatalf("round %d: the new cgroup %d has no run-set row when mkdir returned: %v", round, cid, err)
		}
		if row != want {
			t.Fatalf("round %d: descendant lost membership flags/generation: got %+v, want %+v", round, row, want)
		}
		if err := os.Remove(child); err != nil {
			t.Fatalf("round %d: rmdir: %v", round, err)
		}
		if err := runSet.Lookup(&cid, &row); !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("round %d: after rmdir the row for cgroup %d is still there (%v); cgroup_rmdir must delete it", round, cid, err)
		}
		var own ebpfbindings.Run
		if err := runSet.Lookup(&id, &own); err != nil {
			t.Fatalf("round %d: the run's own row went with its child's: %v", round, err)
		}
		if own != want {
			t.Fatalf("round %d: rmdir changed the parent's membership: %+v", round, own)
		}
	}
}
