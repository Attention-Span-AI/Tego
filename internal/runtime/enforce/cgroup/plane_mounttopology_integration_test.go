// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// planeWriteEnv makes this test binary, re-executed into a run's cgroup, open one file for writing and exit with the
// errno (0 for an open that went ahead), as planeOpenEnv does for a read.
const planeWriteEnv = "TEGO_CGROUP_PLANE_WRITE"

func init() {
	p := os.Getenv(planeWriteEnv)
	if p == "" {
		return
	}
	fd, err := unix.Open(p, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(fd)
		os.Exit(0)
	}
	var en syscall.Errno
	if errors.As(err, &en) {
		os.Exit(int(en))
	}
	os.Exit(255)
}

// writeInCgroup runs the write agent in the cgroup fd names and returns the errno its open for writing got.
func writeInCgroup(t *testing.T, cgroupFD int, path string) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), planeWriteEnv+"="+path)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cgroupFD}
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		return ee.ExitCode()
	}
	t.Fatalf("run the write agent: %v", err)
	return -1
}

// TestPlaneRunWalksTheMountTreeAsItStands demonstrates topology changes made
// by root OUTSIDE the governed scope (ADR 0055 NET09). The capable hook refuses
// the governed task's mount operations, but cannot prevent an outside process
// from changing a shared namespace. Such a bind can move an outside directory
// beneath a write entry, and an overlay can expose a deny_read layer through the
// merged path. Keyed deny targets themselves remain refused through a bind.
func TestPlaneRunWalksTheMountTreeAsItStands(t *testing.T) {
	requireBPFCaps(t)
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects: %v", err)
	}
	mode, build := hostPlane(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	work, outside, keys, hooks := filepath.Join(dir, "work"), filepath.Join(dir, "outside"), filepath.Join(dir, "keys"),
		filepath.Join(dir, "repo", ".git", "hooks")
	for _, d := range []string{work, outside, keys, hooks, filepath.Join(work, "m"), filepath.Join(work, "k"), filepath.Join(work, "h")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(outside, "f"), filepath.Join(keys, "id"), filepath.Join(hooks, "pre-commit")} {
		if err := os.WriteFile(f, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	hash := fmt.Sprintf("t6mtree%09d", os.Getpid())
	b := New(Options{Machine: machineLinger(time.Hour), BPFFS: DefaultBPFFS, StateDir: pinState(t), Hash: hash,
		Plane: PlaneSetup{Mode: mode, Build: build}})
	t.Cleanup(func() {
		if pins, err := newPinLayout(DefaultBPFFS, hash); err == nil {
			_ = pins.remove()
		}
	})
	rel, fd, id := runCgroupUnderSelf(t, "mtree")
	rt := &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordFull, Contract: &agent.Contract{},
		FS: []agent.FSRule{{Path: work, Kind: agent.FSWrite}, {Path: filepath.Join(dir, "repo"), Kind: agent.FSWrite},
			{Path: keys, Kind: agent.FSDenyRead}},
		DenyWrite: []agent.FSRule{{Kind: agent.FSDenyWrite, Path: hooks, Resolved: hooks, BuiltIn: true}}}
	rows, err := decide.CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	b.opts.planeHeld = holdPaths(t, rows.Keyed...).held
	h, err := b.Prepare(context.Background(), rt, Run{ID: "t6-mtree", CgroupID: id, CgroupPath: rel,
		CgroupMount: "/sys/fs/cgroup", PlaneRows: rows})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	if err := h.Arm(); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if errno := writeInCgroup(t, fd, filepath.Join(outside, "f")); errno != int(unix.EACCES) {
		t.Fatalf("a write of %s, outside every write entry: errno %d, want EACCES", filepath.Join(outside, "f"), errno)
	}
	if errno := writeInCgroup(t, fd, filepath.Join(hooks, "pre-commit")); errno != int(unix.EACCES) {
		t.Fatalf("a write beneath the deny_write target %s: errno %d, want EACCES", hooks, errno)
	}
	// Outside root makes these mounts after the fill in a namespace shared with the run.
	for _, m := range [][2]string{{outside, filepath.Join(work, "m")}, {keys, filepath.Join(work, "k")}, {hooks, filepath.Join(work, "h")}} {
		if err := unix.Mount(m[0], m[1], "", unix.MS_BIND, ""); err != nil {
			t.Fatalf("bind %s on %s: %v", m[0], m[1], err)
		}
		t.Cleanup(func() { _ = unix.Unmount(m[1], unix.MNT_DETACH) })
	}
	if errno := writeInCgroup(t, fd, filepath.Join(work, "m", "f")); errno != 0 {
		t.Errorf("a write of the file outside every write entry, bound beneath one after the fill: errno %d, want it "+
			"to go ahead after the outside-root mount (the walk follows the mount tree as it stands)", errno)
	}
	if errno := openInCgroup(t, fd, filepath.Join(work, "k", "id")); errno != int(unix.EACCES) {
		t.Errorf("a read of the deny_read directory's file, bound beneath the write entry: errno %d, want EACCES "+
			"(its row keys the inode)", errno)
	}
	if errno := writeInCgroup(t, fd, filepath.Join(work, "h", "pre-commit")); errno != int(unix.EACCES) {
		t.Errorf("a write of the deny_write target's file, bound beneath the write entry: errno %d, want EACCES "+
			"(its row keys the inode)", errno)
	}
	t.Run("overlay", func(t *testing.T) {
		upper, wd, merged := filepath.Join(dir, "upper"), filepath.Join(dir, "ovlwork"), filepath.Join(work, "o")
		for _, d := range []string{upper, wd, merged} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := unix.Mount("overlay", merged, "overlay", 0, "lowerdir="+keys+",upperdir="+upper+",workdir="+wd); err != nil {
			t.Skipf("a kernel with no overlayfs (the guest loads it by default, VM_MODULES=overlay): %v", err)
		}
		t.Cleanup(func() { _ = unix.Unmount(merged, unix.MNT_DETACH) })
		if errno := openInCgroup(t, fd, filepath.Join(merged, "id")); errno != 0 {
			t.Errorf("a read of the deny_read directory's file through an overlay mounted on it after the fill: errno "+
				"%d, want it to go ahead after the outside-root mount (the plane decides the merged file)", errno)
		}
	})
}
