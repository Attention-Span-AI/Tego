// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestPlaneRemovalReleasesLinksBeforeReturn is TestBuildRemovalReleasesLinksBeforeReturn for a build with its
// decision plane, in the mode this kernel runs: the plane's links are on trampolines too (fmod_ret or lsm, 27 or 37
// functions a mode on 6.17, enforce-plane §10.1), and the build's removal takes the plane's directory first
// (removePlaneDirs, R20). Right after pins.remove returns, none of the build's or the plane's links and programs is
// still enumerable.
func TestPlaneRemovalReleasesLinksBeforeReturn(t *testing.T) {
	requireBPFCaps(t)
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects: %v", err)
	}
	mode, build := hostPlane(t)
	hash := fmt.Sprintf("teardown-plane-%d", os.Getpid())
	pins, err := newPinLayout(DefaultBPFFS, hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pins.remove() })
	b := New(Options{Machine: machineLinger(time.Hour), BPFFS: DefaultBPFFS, StateDir: pinState(t), Hash: hash,
		Events: &sink{}, Plane: PlaneSetup{Mode: mode, Build: build}, startTimer: func(string) error { return nil }})
	rel, _, id := runCgroupUnderSelf(t, "teardown")
	rt := &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordSummary, Contract: &agent.Contract{},
		FS: []agent.FSRule{{Path: t.TempDir(), Kind: agent.FSDenyRead}}}
	rows, err := decide.CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	b.opts.planeHeld = holdPaths(t, rows.Keyed...).held
	h, err := b.Prepare(context.Background(), rt, Run{ID: "teardown-plane", CgroupID: id, CgroupPath: rel,
		CgroupMount: "/sys/fs/cgroup", PlaneRows: rows})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := h.Arm(); err != nil {
		_ = h.Close()
		t.Fatalf("Arm: %v", err)
	}
	if h.PlaneMode() != mode {
		_ = h.Close()
		t.Fatalf("the run decides in plane mode %q, want %q", h.PlaneMode(), mode)
	}
	links, progs := buildObjectIDs(t, pins)
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	start := time.Now()
	if err := pins.remove(); err != nil {
		t.Fatalf("remove: %v", err)
	}
	t.Logf("removal of %d links and %d programs (plane %s) returned in %v", len(links), len(progs), mode,
		time.Since(start))
	for _, dir := range []string{pins.Root, newPlaneLayout(pins, hash, mode).Root} {
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the removal left %s (%v)", dir, err)
		}
	}
	requireReleased(t, links, progs)
}
