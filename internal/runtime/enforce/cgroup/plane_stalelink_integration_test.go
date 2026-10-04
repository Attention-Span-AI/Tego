// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestPlaneStaleLinkOverARecreatedBuildIsNotAdopted is enforce-plane R20 against the running kernel, as root: a
// plane whose pins outlived the build's maps (a removal that failed between the two) is not adopted by its links.
// Its programs read the dead run set, which names no run, so every hook allows: a run that adopted its link was
// enforced by nothing. The next launcher loads the plane over the new maps, unpins the stale link and attaches its
// own, and the run's deny_read is refused.
func TestPlaneStaleLinkOverARecreatedBuildIsNotAdopted(t *testing.T) {
	requireBPFCaps(t)
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects: %v", err)
	}
	mode, build := hostPlane(t)
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.MkdirAll(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secret, "k"), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("t6stlnk%09d", os.Getpid())
	b := New(Options{Machine: machineLinger(time.Hour), BPFFS: DefaultBPFFS, StateDir: pinState(t), Hash: hash,
		Plane: PlaneSetup{Mode: mode, Build: build}})
	pins, err := newPinLayout(DefaultBPFFS, hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pins.remove() })

	run := func(name string, fs []agent.FSRule) (*Handle, int) {
		t.Helper()
		rel, fd, id := runCgroupUnderSelf(t, name)
		rt := &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordFull, Contract: &agent.Contract{}, FS: fs}
		rows, err := decide.CompilePlane(rt)
		if err != nil {
			t.Fatal(err)
		}
		b.opts.planeHeld = holdPaths(t, rows.Keyed...).held
		h, err := b.Prepare(context.Background(), rt, Run{ID: "t6-stlnk-" + name, CgroupID: id, CgroupPath: rel,
			CgroupMount: "/sys/fs/cgroup", PlaneRows: rows})
		if err != nil {
			t.Fatalf("Prepare %s: %v", name, err)
		}
		if err := h.Arm(); err != nil {
			_ = h.Close()
			t.Fatalf("Arm %s: %v", name, err)
		}
		return h, fd
	}
	a, _ := run("a", nil)
	if err := a.Close(); err != nil {
		t.Fatalf("close A: %v", err)
	}
	// The build's own pins go, its plane's stay: what a removal whose plane directory could not be removed left
	// before pins.remove stopped there. The build directory itself is kept, so no orphan sweep takes the plane.
	for _, d := range []string{pins.Maps, pins.Progs, pins.Links} {
		entries, err := os.ReadDir(d)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if err := os.RemoveAll(filepath.Join(d, e.Name())); err != nil {
				t.Fatalf("unpin %s/%s: %v", d, e.Name(), err)
			}
		}
	}
	lay := newPlaneLayout(pins, hash, mode)
	if entries, err := os.ReadDir(lay.Links); err != nil || len(entries) == 0 {
		t.Fatalf("the plane's links are not pinned after run A (%d, %v): the test needs them left", len(entries), err)
	}
	bh, fdB := run("b", []agent.FSRule{{Path: secret, Kind: agent.FSDenyRead}})
	defer func() { _ = bh.Close() }()
	if errno := openInCgroup(t, fdB, filepath.Join(secret, "k")); errno != int(unix.EACCES) {
		t.Errorf("run B's read of secret/k under a plane pinned over the build's old maps: errno %d, want EACCES "+
			"(the stale link was adopted and decides over a run set that names no run)", errno)
	}
}
