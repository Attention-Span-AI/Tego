// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// tier3Fixture is a plane fixture configured as tier bpflsm (Options.Tier), with a table compiled for it.
func tier3Fixture(t *testing.T, mode ebpfbindings.PlaneMode, opts ...func(*Options)) (*fixture, *fakePlane) {
	t.Helper()
	f, p := planeFixture(t, mode, append([]func(*Options){func(o *Options) { o.Tier = backend.TierBPFLSM }}, opts...)...)
	f.table.Tier = backend.TierBPFLSM
	return f, p
}

// TestTierBPFLSMIsThePlaneInLSMMode is tier bpflsm's run (enforce-plane R19; TIER3-PLAN T7): the tier-2 backend with
// the plane in LSM mode, reporting itself as tier bpflsm, taking a table compiled for tier bpflsm (and no other), its
// run-set row carrying tier 3, its capability set within tier 3's column and without what the plane does not decide
// yet (chmod is step B).
func TestTierBPFLSMIsThePlaneInLSMMode(t *testing.T) {
	t.Parallel()
	f, plane := tier3Fixture(t, ebpfbindings.PlaneLSM)
	if f.backend.Tier() != backend.TierBPFLSM {
		t.Errorf("Tier() = %s, want bpflsm", f.backend.Tier())
	}
	h := f.prepareArmed(t)
	defer h.Close()
	if h.fan != nil {
		t.Error("a tier-3 run has a fanotify listener")
	}
	if dp, why := h.PlaneChoice(); dp != string(ebpfbindings.PlaneLSM) || why != nil {
		t.Errorf("DecisionPlane = %s, %v; want lsm", dp, why)
	}
	if len(plane.fills) != 1 {
		t.Errorf("%d fills, want 1", len(plane.fills))
	}
	row := f.kernel.runs[f.run.CgroupID]
	if row.Tier != 3 || row.Plane != ebpfbindings.RunPlaneOf(ebpfbindings.PlaneLSM) {
		t.Errorf("run-set row %+v, want tier 3 in LSM mode", row)
	}
	caps, col := h.Capabilities(), backend.Matrix(backend.TierBPFLSM)
	for c := range caps {
		if caps.Has(c) && !col.Has(c) {
			t.Errorf("capability %s is not in tier bpflsm's column", c)
		}
	}
	if !caps.Has(backend.CapReadDeny) || !caps.Has(backend.CapExecDeny) || !caps.Has(backend.CapFileWriteDeny) {
		t.Errorf("capabilities %v: the plane decides read, exec and write denial", caps)
	}
	if !caps.Has(backend.CapProtectedWriteTargets) {
		t.Error("the plane in LSM mode decides the built-in deny_write targets by inode, and the run does not say so (ADR 0041 D7)")
	}
	if caps.Has(backend.CapChmodDeny) {
		t.Error("the run claims chmod denial under the write rules; path_chmod protects deny_write targets only (step B)")
	}

	// A table compiled for another tier answers in that tier's terms, so each backend takes only its own.
	g, _ := tier3Fixture(t, ebpfbindings.PlaneLSM)
	g.table.Tier = backend.TierCgroup
	if _, err := g.backend.Prepare(context.Background(), g.table, g.run); !errors.Is(err, ErrTier) {
		t.Errorf("tier bpflsm prepared a table compiled for cgroup: %v", err)
	}
	c, _ := planeFixture(t, ebpfbindings.PlaneLSM)
	c.table.Tier = backend.TierBPFLSM
	if _, err := c.backend.Prepare(context.Background(), c.table, c.run); !errors.Is(err, ErrTier) {
		t.Errorf("tier cgroup prepared a table compiled for bpflsm: %v", err)
	}
}

// TestTierBPFLSMReadsNoMountTableForAListener: the fanotify policy, and the mount table its submount marks come
// from, is the listener's alone (R8), and a tier-3 run never has a listener. A tier-3 run whose contract has a
// deny_read entry and no deny_write target was refused ErrMountTable when mountinfo could not be read, though
// nothing in it needs the table (enforce-plane R12). A tier-2 run over the same table is still refused. Not
// parallel: it points the package's mount table at a missing file.
func TestTierBPFLSMReadsNoMountTableForAListener(t *testing.T) {
	saved := mountInfoPath
	mountInfoPath = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { mountInfoPath = saved })

	c := newFixture(t)
	if _, err := c.backend.Prepare(context.Background(), c.table, c.run); !errors.Is(err, ErrMountTable) {
		t.Fatalf("tier cgroup over an unreadable mount table with a deny_read entry: %v; want ErrMountTable", err)
	}

	f, _ := tier3Fixture(t, ebpfbindings.PlaneLSM)
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("tier bpflsm with a deny_read-only contract over an unreadable mount table: %v; want prepared", err)
	}
	defer h.Close()
	if len(h.policy.mounts) != 0 || len(h.policy.denyRead.entries) != 0 {
		t.Errorf("a tier-3 run built a listener policy: %d mounts, %d deny_read entries",
			len(h.policy.mounts), len(h.policy.denyRead.entries))
	}
}

// TestTierBPFLSMRefusesATableThePlaneCannotHold: where tier cgroup runs such a table on the fanotify listener
// (TestPlaneFallsBackToTheListenerForATableItCannotHold), tier bpflsm has no listener to fall to, and refuses it at
// Prepare, fail closed, with the reason and the way out (enforce-plane §6 E13, I7): nothing is loaded and the slot
// is released.
func TestTierBPFLSMRefusesATableThePlaneCannotHold(t *testing.T) {
	t.Parallel()
	for name, edit := range map[string]func(rt *agent.RuleTable){
		"an exec entry that does not allow": func(rt *agent.RuleTable) {
			rt.Exec = []agent.ExecRule{{Path: "/usr/bin/true", Verdict: agent.VerdictAsk}}
		},
		"more rows than a slot holds": func(rt *agent.RuleTable) {
			for i := range decide.PlaneRowsMax + 1 {
				p := "/d/" + strconv.Itoa(i)
				rt.Exec = append(rt.Exec, agent.ExecRule{Path: p, Resolved: p, IsDir: true, Verdict: agent.VerdictAllow})
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f, plane := tier3Fixture(t, ebpfbindings.PlaneLSM, func(o *Options) {
				o.newListener = func(*Handle) (*fanotifyListener, error) {
					t.Error("tier bpflsm made a fanotify group for a table its plane cannot hold")
					return nil, errors.New("no listener at tier bpflsm")
				}
			})
			edit(f.table)
			_, err := f.backend.Prepare(context.Background(), f.table, f.run)
			if !errors.Is(err, ErrPlaneCannotHold) {
				t.Fatalf("Prepare = %v, want ErrPlaneCannotHold", err)
			}
			for _, want := range []string{"tier bpflsm", "--tier cgroup"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q does not say %q", err, want)
				}
			}
			if len(plane.fills) != 0 || slices.Contains(f.kernel.calls, "plane.prepareSlot") || slices.Contains(f.kernel.calls, "populate") {
				t.Errorf("the refused run touched the kernel: %v", f.kernel.calls)
			}
			st, err := openSlotTable(t, f.dir, "testhash")
			if err != nil {
				t.Fatal(err)
			}
			defer st.close()
			if held, _ := st.heldBy(0); held {
				t.Error("slot 0 stays held after the refusal")
			}
		})
	}
}

// TestTierBPFLSMRefusesALateSharedInode: two fs entries made one file under two names after tier3Plane's check (a
// hard link made during the build lock and the slot acquire) are refused by choosePlane's second look with
// ErrPlaneCannotHold, and Prepare unwinds: never the tier-2 fallback, a tier-3 run on the fanotify listener with an
// empty plane mode (enforce-plane R19, §6 E13, I7).
func TestTierBPFLSMRefusesALateSharedInode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f, plane := tier3Fixture(t, ebpfbindings.PlaneLSM, func(o *Options) {
		o.newListener = func(*Handle) (*fanotifyListener, error) {
			t.Error("tier bpflsm made a fanotify group")
			return nil, errors.New("no listener at tier bpflsm")
		}
		// Runs under the slot table's lock, after tier3Plane stated both paths as two files.
		o.carriedSlots = func(string) (map[uint32]bool, error) {
			if err := os.Remove(b); err != nil {
				return nil, err
			}
			return map[uint32]bool{}, os.Link(a, b)
		}
	})
	f.table.FS = append(f.table.FS, agent.FSRule{Path: a, Resolved: a, Kind: agent.FSDenyRead},
		agent.FSRule{Path: b, Resolved: b, Kind: agent.FSDenyRead})
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if !errors.Is(err, ErrPlaneCannotHold) || !errors.Is(err, ErrPlaneSharedInode) {
		if h != nil {
			dp, why := h.PlaneChoice()
			t.Errorf("the run was prepared on plane %q (%v)", dp, why)
			_ = h.Close()
		}
		t.Fatalf("Prepare = %v, want ErrPlaneCannotHold for the shared inode", err)
	}
	if len(plane.fills) != 0 || slices.Contains(f.kernel.calls, "plane.prepareSlot") {
		t.Errorf("the refused run touched the plane: %v", f.kernel.calls)
	}
	st, err := openSlotTable(t, f.dir, "testhash")
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	if held, _ := st.heldBy(0); held {
		t.Error("slot 0 stays held after the refusal")
	}
}

// TestTierBPFLSMNeedsLSMMode: tier bpflsm is the plane in LSM mode, so a backend handed fmod_ret or no mode at all
// refuses at Prepare before anything exists, never deciding the run another way (R19).
func TestTierBPFLSMNeedsLSMMode(t *testing.T) {
	t.Parallel()
	for _, mode := range []ebpfbindings.PlaneMode{ebpfbindings.PlaneFmodRet, ""} {
		f, _ := tier3Fixture(t, mode, func(o *Options) {
			o.newListener = func(*Handle) (*fanotifyListener, error) {
				t.Error("tier bpflsm made a fanotify group")
				return nil, errors.New("no listener at tier bpflsm")
			}
		})
		_, err := f.backend.Prepare(context.Background(), f.table, f.run)
		if !errors.Is(err, ErrNeedsLSMMode) {
			t.Errorf("mode %q: Prepare = %v, want ErrNeedsLSMMode", mode, err)
		}
		if len(f.kernel.calls) != 0 {
			t.Errorf("mode %q: the refused run touched the kernel: %v", mode, f.kernel.calls)
		}
	}
}
