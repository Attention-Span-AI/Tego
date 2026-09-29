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
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// planeOpenEnv makes this test binary, re-executed into a run's cgroup, open one file read-only and exit with the
// errno (0 for an open that went ahead): the smallest agent a Handle-level plane test needs.
const planeOpenEnv = "TEGO_CGROUP_PLANE_OPEN"

func init() {
	p := os.Getenv(planeOpenEnv)
	if p == "" {
		return
	}
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
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

// openInCgroup runs the open agent in the cgroup fd names and returns the errno its open got.
func openInCgroup(t *testing.T, cgroupFD int, path string) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), planeOpenEnv+"="+path)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cgroupFD}
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		return ee.ExitCode()
	}
	t.Fatalf("run the open agent: %v", err)
	return -1
}

// runCgroupUnderSelf makes a cgroup under this process's own for one run: its path relative to the mount, an
// O_PATH descriptor for CLONE_INTO_CGROUP and its id.
func runCgroupUnderSelf(t *testing.T, name string) (string, int, uint64) {
	t.Helper()
	rel, err := cgroupPathOfPID(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	rel = filepath.Join(rel, fmt.Sprintf("tego-plane-%d-%s", os.Getpid(), name))
	dir := filepath.Join("/sys/fs/cgroup", rel)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("make the run's cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	return rel, fd, st.Ino
}

// keepRows is a plane whose clears do nothing: the slot keeps a run's rows past its end, as it does when the
// launcher died before its Detach and no reaper or Prepare has cleared them yet.
type keepRows struct{ planeKernel }

func (keepRows) clearSlot(uint32) error { return nil }

// hostPlane is a plane mode and build this kernel runs: LSM mode where bpf is an active LSM, else fmod_ret; the
// rdonly build where BTF has bpf_rdonly_cast.
func hostPlane(t *testing.T) (ebpfbindings.PlaneMode, ebpfbindings.Object) {
	t.Helper()
	mode := ebpfbindings.PlaneFmodRet
	if b, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil && strings.Contains(","+string(b)+",", ",bpf,") {
		mode = ebpfbindings.PlaneLSM
	}
	build := ebpfbindings.ObjectPlaneProbe
	if kernelHasFunc("bpf_rdonly_cast") {
		build = ebpfbindings.ObjectPlaneRdonly
	}
	if !kernelHasFunc("bpf_loop") {
		t.Skip("no bpf_loop in this kernel's BTF: no plane mode")
	}
	return mode, build
}

// TestPlaneStaleRowsOfTheSlotsLastRunAreAbsent is enforce-plane R6 and §6 E2 through the backend: a slot's rows are
// kept across its runs (no inner map is created or dropped on a run's path) and each carries its run's gen, so a
// run in a reused slot whose previous run's rows were never cleared walks past them. Run A, whose contract denies
// secret/, is refused a read of secret/k; its rows are left in the slot (the clear suppressed, as a launcher dead
// before its Detach leaves them); run B in the same slot, whose contract denies nothing there, reads secret/k while
// A's row for it is still in the map.
func TestPlaneStaleRowsOfTheSlotsLastRunAreAbsent(t *testing.T) {
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
	hash := fmt.Sprintf("t6stale%09d", os.Getpid())
	state := pinState(t)
	// A linger keeps the build, and its plane with A's rows, pinned between the two runs, as a build a run left does;
	// the test removes it at the end.
	b := New(Options{Machine: machineLinger(time.Hour), BPFFS: DefaultBPFFS, StateDir: state, Hash: hash,
		Plane: PlaneSetup{Mode: mode, Build: build}, planeWrap: func(p planeKernel) planeKernel { return keepRows{p} }})
	t.Cleanup(func() {
		if pins, err := newPinLayout(DefaultBPFFS, hash); err == nil {
			_ = pins.remove()
		}
	})

	run := func(name string, fs []agent.FSRule) (*Handle, int) {
		t.Helper()
		rel, fd, id := runCgroupUnderSelf(t, name)
		rt := &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordFull, Contract: &agent.Contract{}, FS: fs}
		rows, err := decide.CompilePlane(rt)
		if err != nil {
			t.Fatal(err)
		}
		held := holdPaths(t, rows.Keyed...)
		b.opts.planeHeld = held.held
		h, err := b.Prepare(context.Background(), rt, Run{ID: "t6-" + name, CgroupID: id, CgroupPath: rel,
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
	a, fdA := run("a", []agent.FSRule{{Path: secret, Kind: agent.FSDenyRead}})
	if errno := openInCgroup(t, fdA, filepath.Join(secret, "k")); errno != int(unix.EACCES) {
		t.Errorf("run A's read of secret/k: errno %d, want EACCES", errno)
	}
	slot := a.Slot()
	if err := a.Close(); err != nil {
		t.Fatalf("close A: %v", err)
	}
	stale := slotRows(t, hash, mode, slot)
	if stale == 0 {
		t.Fatal("run A's rows are gone: the test needs them left in the slot")
	}
	bh, fdB := run("b", nil)
	defer func() { _ = bh.Close() }()
	if bh.Slot() != slot {
		t.Fatalf("run B took slot %d, A had %d: the test needs the slot reused", bh.Slot(), slot)
	}
	if n := slotRows(t, hash, mode, slot); n < stale {
		t.Fatalf("the slot holds %d rows once B is filled, A left %d: they were cleared", n, stale)
	}
	if errno := openInCgroup(t, fdB, filepath.Join(secret, "k")); errno != 0 {
		t.Errorf("run B's read of secret/k with A's stale row still in its slot: errno %d, want it to go ahead", errno)
	}
}

// slotRows counts the rows of one slot of a build's plane, fs and exec.
func slotRows(t *testing.T, hash string, mode ebpfbindings.PlaneMode, slot uint32) int {
	t.Helper()
	lay := newPlaneLayout(pinLayout{Base: filepath.Join(DefaultBPFFS, pinRoot)}, hash, mode)
	n := 0
	for _, name := range []string{ebpfbindings.MapPlaneRows, ebpfbindings.MapPlaneExecRows} {
		outer, err := loadPinnedMap(lay.Maps, name)
		if err != nil || outer == nil {
			t.Fatalf("open %s: %v", name, err)
		}
		inner, err := innerOf(outer, slot, name)
		_ = outer.Close()
		if err != nil {
			t.Fatal(err)
		}
		var k, next uint64
		for err := inner.NextKey(nil, &next); err == nil; err = inner.NextKey(&k, &next) {
			k = next
			n++
		}
		_ = inner.Close()
	}
	return n
}
