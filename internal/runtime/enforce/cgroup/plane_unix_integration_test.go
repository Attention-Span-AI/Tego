// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestPlaneUnixVerdictOnRealKernel is enforce-plane R14 through the backend (TIER3-PLAN T15): a tier-cgroup run in a
// plane mode on a kernel without cgroup/connect_unix (below 6.7) has its unix names decided by the plane's
// socket_connect and socket_sendmsg, from the rows and by the rule connect_unix uses on 6.7+, so
// TestUnixVerdictOnRealKernel's cells hold with EACCES where they hold with EPERM there: the agent's own connects and
// datagrams, the supervisor's /proc/self/fd relay from this launcher's cgroup, and the same name from any other.
// On 6.7+ the test answers the load's probe of BPF_CGROUP_UNIX_CONNECT as a kernel below 6.7 does, so the cells
// run the plane's hooks on every kernel; where the probe really answers so, the backend chose them unaided.
func TestPlaneUnixVerdictOnRealKernel(t *testing.T) {
	_, dir, u := planeUnixRun(t, "plane")
	unixKernelCells(t, dir, u, unix.EACCES)
}

// planeUnixRun is a prepared, attached and armed tier-cgroup run in the host's plane mode whose unix names the
// plane's socket_connect and socket_sendmsg decide (connect_unix withheld on 6.7+), over newUnixFixture(tag)'s
// table, with its cgroup directory open.
func planeUnixRun(t *testing.T, tag string) (*Handle, *os.File, *unixFixture) {
	t.Helper()
	requireBPFCaps(t)
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects: %v", err)
	}
	mode, build := hostPlane(t)
	if ok, err := unixConnectSupported(); err == nil && ok {
		was := unixConnectSupported
		unixConnectSupported = func() (bool, error) { return false, nil }
		t.Cleanup(func() { unixConnectSupported = was })
		t.Logf("this kernel has cgroup/connect_unix; the build is loaded as below 6.7, without it")
	}
	u := newUnixFixture(t, tag)
	rt := u.table()
	rt.Contract = &agent.Contract{Net: &agent.NetSection{}} // a net: section, and no exec: section
	rows, err := decide.CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("t15%s%09d", tag, os.Getpid())
	b := New(Options{Machine: machineLinger(0), BPFFS: DefaultBPFFS, StateDir: pinState(t), Hash: hash,
		Events: &sink{}, Plane: PlaneSetup{Mode: mode, Build: build}})
	b.opts.planeHeld = holdPaths(t, rows.Keyed...).held
	t.Cleanup(func() {
		if pins, err := newPinLayout(DefaultBPFFS, hash); err == nil {
			_ = pins.remove()
		}
	})
	rel, _, id := runCgroupUnderSelf(t, "unix"+tag)
	h, err := b.Prepare(context.Background(), rt, Run{ID: "t15-unix-" + tag, Agent: "a", CgroupID: id, CgroupPath: rel,
		CgroupMount: "/sys/fs/cgroup", PlaneRows: rows})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if dp, why := h.PlaneChoice(); dp != string(mode) {
		t.Fatalf("the run decides in %s (%v), want the plane's %s mode", dp, why, mode)
	}
	if _, ok := h.kern.(*bpfKernel).progs[ebpfbindings.ProgConnectUnix]; ok {
		t.Fatal("connect_unix was loaded: the plane's unix hooks would decide every name a second time")
	}
	if !h.plane.decidesUnix() {
		t.Fatal("the plane did not load its unix hooks where connect_unix is absent")
	}
	if err := h.Attach(id); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := h.Arm(); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	dir, err := os.Open(filepath.Join("/sys/fs/cgroup", rel))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	return h, dir, u
}
