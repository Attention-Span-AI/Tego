// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestMountPointsReadsMountinfo reads mountinfo's fifth field, escapes undone, and skips a line too short to have
// one. A mount point holding \v, \r or U+00A0, which the kernel prints unescaped, stays one field: the fields are
// split on spaces alone.
func TestMountPointsReadsMountinfo(t *testing.T) {
	if points, err := MountPoints(); err != nil || points == nil {
		t.Errorf("this process's own mount table read as %q, %v", points, err)
	}
	info := "22 1 0:21 / /proc rw,nosuid shared:5 - proc proc rw\n" +
		"36 25 0:32 / /w/.git/my\\040tmp rw - tmpfs tmpfs rw\n" +
		"37 25 8:1 /src /w/.git/bind rw - ext4 /dev/sda1 rw\n" +
		"38 25 98:0 / /w/a\u00a0b rw - ext4 /dev/x rw\n" +
		"39 25 98:1 / /w/c\vd\re rw - ext4 /dev/y rw\n" +
		"broken line\n"
	path := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(path, []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := mountInfoPath
	mountInfoPath = path
	t.Cleanup(func() { mountInfoPath = saved })
	got, err := MountPoints()
	want := []string{"/proc", "/w/.git/my tmp", "/w/.git/bind", "/w/a\u00a0b", "/w/c\vd\re"}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("mount points %q, %v; want %q", got, err, want)
	}

	// A table that cannot be read is an error, never an empty list that keys no mount row (R12).
	mountInfoPath = filepath.Join(t.TempDir(), "absent")
	if got, err := MountPoints(); !errors.Is(err, ErrMountTable) || got != nil {
		t.Errorf("an unreadable mount table read as %q, %v; want ErrMountTable", got, err)
	}
}

// TestPlanPlaneFillMountRows is enforce-plane R12's fill half: a mount row is an fs row at the mounted root's held
// descriptor, carrying its nearest row's kind with PlaneMountOnly and that row's position as rule_idx; a mounted
// root that is a keyed row's inode already (one descriptor) keeps that row; and the mount rows count against the
// slot's cap.
func TestPlanPlaneFillMountRows(t *testing.T) {
	rows, held, id := fillFixture()
	rows.FS[1].Kind |= decide.PlaneProtected
	rows.Mounts = []decide.PlaneMountRow{{Path: "/w/secret/tmp", Row: 1}, {Path: "/w/secret/bind", Row: 1}}
	held["/w/secret/tmp"], held["/w/secret/bind"] = 13, 10 // bind: the same inode as /w/secret, one descriptor
	id.fds[13] = [3]uint64{31, 9, 2}
	id.paths["/w/secret/tmp"] = [2]uint64{9, 2}
	plan, err := planPlaneFill(rows, 5, 77, heldOf(held), id)
	if err != nil {
		t.Fatal(err)
	}
	var mount *planeFillEntry
	for i := range plan.Entries {
		if plan.Entries[i].Path == "/w/secret/bind" {
			t.Error("a mounted root held under a keyed row's descriptor got a second row")
		}
		if plan.Entries[i].Path == "/w/secret/tmp" {
			mount = &plan.Entries[i]
		}
	}
	want := planeFillEntry{FD: 13, Path: "/w/secret/tmp", What: ebpfbindings.PlaneFillFS,
		Kind: uint8(decide.PlaneReadDeny | decide.PlaneProtected | decide.PlaneMountOnly), RuleIdx: 1, MntID: 31, Ino: 2, Dev: 9}
	if mount == nil || *mount != want {
		t.Fatalf("mount entry %+v, want %+v", mount, want)
	}
	rows.Mounts = append(rows.Mounts, decide.PlaneMountRow{Path: "/w/x", Row: 7})
	if _, err := planPlaneFill(rows, 5, 77, heldOf(held), id); err == nil || !strings.Contains(err.Error(), "names no fs row") {
		t.Errorf("a mount row naming no fs row: %v", err)
	}
	rows.Mounts = make([]decide.PlaneMountRow, decide.PlaneRowsMax)
	var capErr *decide.ErrPlaneCap
	if _, err := planPlaneFill(rows, 5, 77, heldOf(held), id); !errors.As(err, &capErr) {
		t.Errorf("mount rows past the cap: %v", err)
	}
}

// TestNetPolicyRow is ADR 0018 (5)'s half of the slot header: no net flag without a net: section (socket_create
// decides nothing), else PlaneSlotNetDecides, with PlaneSlotNetICMP for a port-0 entry.
func TestNetPolicyRow(t *testing.T) {
	net := ebpfbindings.PlaneSlotNetDecides | ebpfbindings.PlaneSlotNetICMP
	if h := slotHeader(planeFillRequest{Gen: 9}, false, 0, 0); h.Flags&net != 0 || h.Gen != 9 {
		t.Errorf("a contract with no net: section: header %+v", h)
	}
	if h := slotHeader(planeFillRequest{Gen: 9, Net: planeNetPolicy{Restricted: true}}, false, 0, 0); h.Flags&net != ebpfbindings.PlaneSlotNetDecides {
		t.Errorf("net: section without ICMP: header %+v", h)
	}
	if h := slotHeader(planeFillRequest{Gen: 9, Net: planeNetPolicy{Restricted: true, ICMP: true}}, false, 0, 0); h.Flags&net != net {
		t.Errorf("net: section with an ICMP entry: header %+v", h)
	}
	for _, tc := range []struct {
		rt   *agent.RuleTable
		want planeNetPolicy
	}{
		{&agent.RuleTable{Contract: &agent.Contract{}}, planeNetPolicy{}},
		{&agent.RuleTable{Contract: &agent.Contract{Net: &agent.NetSection{}}}, planeNetPolicy{Restricted: true}},
		{&agent.RuleTable{Contract: &agent.Contract{Net: &agent.NetSection{}}, Net: []agent.NetRule{{Proto: agent.ProtoInet, Port: 443}}},
			planeNetPolicy{Restricted: true}},
		{&agent.RuleTable{Contract: &agent.Contract{Net: &agent.NetSection{}}, Net: []agent.NetRule{{Proto: agent.ProtoInet}}},
			planeNetPolicy{Restricted: true, ICMP: true}},
		{&agent.RuleTable{Contract: &agent.Contract{Net: &agent.NetSection{}}, Net: []agent.NetRule{{Proto: agent.ProtoUnix}}},
			planeNetPolicy{Restricted: true}},
		{&agent.RuleTable{}, planeNetPolicy{Restricted: true}}, // a table without its contract fails closed
	} {
		if got := netPolicyOf(tc.rt); got != tc.want {
			t.Errorf("netPolicyOf(%+v) = %+v, want %+v", tc.rt, got, tc.want)
		}
	}
}

// TestChoosePlaneTakesTheCallersError: a table the caller could not compile with its mount rows (over the cap)
// runs on the listener, with the caller's reason, rather than compiled again without them.
func TestChoosePlaneTakesTheCallersError(t *testing.T) {
	h := &Handle{opts: Options{Plane: PlaneSetup{Mode: ebpfbindings.PlaneLSM}},
		run: Run{PlaneErr: &decide.ErrPlaneCap{FSRows: decide.PlaneRowsMax + 1}}}
	if err := h.choosePlane(&agent.RuleTable{}); err != nil {
		t.Fatalf("choosePlane at tier cgroup = %v, want the fallback", err)
	}
	if plane, why := h.PlaneChoice(); plane != PlaneFanotify || why == nil || !strings.Contains(why.Error(), "inodes") {
		t.Errorf("DecisionPlane %q %v, want the listener with the caller's reason", plane, why)
	}
}

// TestTier3PlaneTakesTheCallersError: at tier bpflsm, a table the caller could not compile with its mount rows is
// refused with ErrPlaneCannotHold and the caller's reason, not compiled again without the mounted roots (which fits
// and fails later at the fill with a reason that names no cap).
func TestTier3PlaneTakesTheCallersError(t *testing.T) {
	capErr := &decide.ErrPlaneCap{FSRows: decide.PlaneRowsMax + 1}
	run := &Run{PlaneErr: capErr}
	err := tier3Plane(PlaneSetup{Mode: ebpfbindings.PlaneLSM}, &agent.RuleTable{}, run)
	var got *decide.ErrPlaneCap
	if !errors.Is(err, ErrPlaneCannotHold) || !errors.As(err, &got) || got != capErr {
		t.Errorf("tier3Plane = %v; want ErrPlaneCannotHold wrapping the caller's ErrPlaneCap", err)
	}
	if run.PlaneRows != nil {
		t.Errorf("tier3Plane set PlaneRows %+v after the caller's compile failed", run.PlaneRows)
	}
}

// TestChoosePlaneRefusesHandedRowsThatNoLongerHold: rows the caller handed over were checked before tier 1 was
// composed from them, so a tier cgroup run whose rows fail sharedInode now (a hard link made in between) is
// ErrPlaneRowsChanged, not the listener fallback, which would keep the filter's plane-only relaxations. Rows the
// caller did not hand over, its error instead, still fall back.
func TestChoosePlaneRefusesHandedRowsThatNoLongerHold(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(a, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	rows := &decide.PlaneRows{FS: []decide.PlaneRow{{Path: a}, {Path: b}}}
	h := &Handle{opts: Options{Plane: PlaneSetup{Mode: ebpfbindings.PlaneFmodRet}}, run: Run{PlaneRows: rows}}
	err := h.choosePlane(&agent.RuleTable{})
	if !errors.Is(err, ErrPlaneRowsChanged) || !errors.Is(err, ErrPlaneSharedInode) {
		t.Fatalf("choosePlane over handed rows now on one inode = %v; want ErrPlaneRowsChanged", err)
	}
	h = &Handle{opts: Options{Plane: PlaneSetup{Mode: ebpfbindings.PlaneFmodRet}}, run: Run{PlaneErr: err}}
	if err := h.choosePlane(&agent.RuleTable{}); err != nil {
		t.Fatalf("choosePlane with the caller's error = %v, want the fallback", err)
	}
	if plane, why := h.PlaneChoice(); plane != PlaneFanotify || !errors.Is(why, ErrPlaneSharedInode) {
		t.Errorf("DecisionPlane %q %v, want the listener with the shared-inode reason", plane, why)
	}
}
