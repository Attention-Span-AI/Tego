// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestPlaneRunKeyedFilesAreTheInodesItDecides is what an adoption reads of a filled plane (Handle.PlaneKeyed, ADR 0055
// Decisions 3 and 5) against the running kernel, as root: each fs row is reported at its path with the device and
// inode a stat of that path gives, the identity an adoption compares the agent owner's ~/.tego and the agent's held
// files with. And the premise of both: a row keys an inode, so the plane refuses a read of a deny_read file by a hard
// link of it no rule names, and a deny_read directory renamed after the fill stays
// denied under its new name, while a file of neither is read.
func TestPlaneRunKeyedFilesAreTheInodesItDecides(t *testing.T) {
	requireBPFCaps(t)
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects: %v", err)
	}
	mode, build := hostPlane(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	records := filepath.Join(dir, "records")
	netrc := filepath.Join(dir, "netrc")
	work := filepath.Join(dir, "work")
	for _, d := range []string{records, work} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(records, "events.jsonl"), netrc, filepath.Join(work, "plain")} {
		if err := os.WriteFile(f, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(work, "n")
	if err := os.Link(netrc, link); err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("t6keyed%09d", os.Getpid())
	b := New(Options{Machine: machineLinger(time.Hour), BPFFS: DefaultBPFFS, StateDir: pinState(t), Hash: hash,
		Plane: PlaneSetup{Mode: mode, Build: build}})
	t.Cleanup(func() {
		if pins, err := newPinLayout(DefaultBPFFS, hash); err == nil {
			_ = pins.remove()
		}
	})
	rel, fd, id := runCgroupUnderSelf(t, "keyed")
	rt := &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordFull, Contract: &agent.Contract{},
		FS: []agent.FSRule{{Path: records, Kind: agent.FSDenyRead}, {Path: netrc, Kind: agent.FSDenyRead}}}
	rows, err := decide.CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	b.opts.planeHeld = holdPaths(t, rows.Keyed...).held
	h, err := b.Prepare(context.Background(), rt, Run{ID: "t6-keyed", CgroupID: id, CgroupPath: rel,
		CgroupMount: "/sys/fs/cgroup", PlaneRows: rows})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	keyed, ok := h.PlaneKeyed()
	if !ok {
		t.Fatal("a filled plane says it keys nothing")
	}
	for _, p := range []string{records, netrc} {
		var st unix.Stat_t
		if err := unix.Stat(p, &st); err != nil {
			t.Fatal(err)
		}
		want := PlaneKeyed{Path: p, Dev: st.Dev, Ino: st.Ino} //nolint:unconvert // Dev is uint64 on amd64 and arm64, not everywhere
		if !slices.Contains(keyed, want) {
			t.Errorf("keyed %+v has no %+v", keyed, want)
		}
	}
	if err := h.Arm(); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if errno := openInCgroup(t, fd, link); errno != int(unix.EACCES) {
		t.Errorf("a read of %s, a hard link of the deny_read file %s: errno %d, want EACCES", link, netrc, errno)
	}
	if errno := openInCgroup(t, fd, filepath.Join(work, "plain")); errno != 0 {
		t.Errorf("a read of a file no rule covers: errno %d, want it to go ahead", errno)
	}
	moved := filepath.Join(dir, "moved")
	if err := os.Rename(records, moved); err != nil {
		t.Fatal(err)
	}
	if errno := openInCgroup(t, fd, filepath.Join(moved, "events.jsonl")); errno != int(unix.EACCES) {
		t.Errorf("a read under the deny_read directory renamed after the fill: errno %d, want EACCES", errno)
	}
}
