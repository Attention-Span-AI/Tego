// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil/contracttest"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

var standardDevicePaths = []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom"}

func stdContract(t *testing.T, fsBody string) *agent.RuleTable {
	t.Helper()
	f := contracttest.Build(t, "version: 0\nname: std\ncommand: [fixture]\ncapture: off\nfs:\n"+fsBody, contracttest.Tree{"out/": ""})
	return f.Rules
}

// withoutDeviceRows is the table the compiler would have made before ADR 0158: the same rows less the device rows.
func withoutDeviceRows(rt *agent.RuleTable) *agent.RuleTable {
	cp := *rt
	cp.FS = slices.DeleteFunc(slices.Clone(rt.FS), func(r agent.FSRule) bool { return r.StdDevice })
	return &cp
}

// TestStandardDevicesAtEveryTier is ADR 0158's decision for the model every tier is held to: with an fs: section
// and no entry for them, a write to each of the five devices is allowed by the product's own rule at tiers landlock,
// cgroup and bpflsm, and a write to anything else under /dev, or beside it, is refused as it was.
func TestStandardDevicesAtEveryTier(t *testing.T) {
	rt := stdContract(t, "  write: [out]\n")
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		t.Run(string(tier), func(t *testing.T) {
			for _, p := range standardDevicePaths {
				for _, kind := range []agent.ActionKind{agent.ActionFSWrite, agent.ActionFSRead} {
					r := Evaluate(rt, agent.Action{Kind: kind, Path: p}, tier)
					if r.Verdict != agent.VerdictAllow {
						t.Errorf("%s %s = %+v, want allow", kind, p, r)
					}
					if kind == agent.ActionFSWrite && r.Rule != agent.BuiltinStandardDevices {
						t.Errorf("write %s is named %q, want %q", p, r.Rule, agent.BuiltinStandardDevices)
					}
				}
			}
			for _, p := range []string{"/dev/tty", "/dev/ptmx", "/dev/console", "/dev/pts/0", "/dev/pts/ptmx", "/dev/shm/x", "/dev/shm",
				"/dev/stdout", "/dev/stderr", "/dev/fd/1", "/dev/sda", "/dev/mem", "/dev/kmsg", "/dev/nullx", "/dev/null.d/x", "/dev/mqueue/q", "/dev/hugepages/f"} {
				if r := Evaluate(rt, agent.Action{Kind: agent.ActionFSWrite, Path: p}, tier); r.Verdict == agent.VerdictAllow {
					t.Errorf("write %s = %+v: nothing else under /dev is granted", p, r)
				}
			}
			// What a device row does not grant: a create, a delete or a rename in /dev, and another file's name.
			for _, a := range []agent.Action{
				{Kind: agent.ActionFSDelete, Path: "/dev/null"}, {Kind: agent.ActionFSRename, Path: "/dev/null", DestPath: "/dev/null2"},
				{Kind: agent.ActionFSMkdir, Path: "/dev/newdir"}, {Kind: agent.ActionFSWrite, Path: "/dev/newfile"},
				{Kind: agent.ActionFSLink, Path: "/dev/null", DestPath: "/dev/nlink"},
			} {
				if r := Evaluate(rt, a, tier); r.Verdict == agent.VerdictAllow {
					t.Errorf("%+v at %s = %+v, want refused: the row grants no right on /dev itself, only the device's own contents", a, tier, r)
				}
			}
		})
	}
	// Without the rows the same table refuses all five: the rows are what grants.
	bare := withoutDeviceRows(rt)
	for _, p := range standardDevicePaths {
		if r := Evaluate(bare, agent.Action{Kind: agent.ActionFSWrite, Path: p}, backend.TierLandlock); r.Verdict != agent.VerdictRefused {
			t.Errorf("without device rows write %s = %+v, want refused (the default deny)", p, r)
		}
	}
}

// TestAnExplicitDenyBeatsTheStandardDevices: a contract's fs.deny_write is the author's word. The device it names (or
// one beneath a directory it names) has no default row, and the write is refused with the author's rule at every
// tier; the other devices keep theirs.
func TestAnExplicitDenyBeatsTheStandardDevices(t *testing.T) {
	rt := stdContract(t, "  write: [out]\n  deny_write: [/dev/null]\n")
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		r := Evaluate(rt, agent.Action{Kind: agent.ActionFSWrite, Path: "/dev/null"}, tier)
		if r.Verdict != agent.VerdictRefused || r.Rule == agent.BuiltinStandardDevices {
			t.Errorf("%s: write /dev/null under deny_write = %+v, want refused by something other than the default", tier, r)
		}
		if r := Evaluate(rt, agent.Action{Kind: agent.ActionFSWrite, Path: "/dev/zero"}, tier); r.Verdict != agent.VerdictAllow {
			t.Errorf("%s: write /dev/zero = %+v, want allow", tier, r)
		}
	}
}

// TestPlaneRowsOfTheStandardDevices is the decision plane's table: compiled with the device rows it differs from the
// table without them by five rows that allow a modification, one per device and nothing else under /dev, and every
// row the table had keeps its kind.
func TestPlaneRowsOfTheStandardDevices(t *testing.T) {
	rt := stdContract(t, "  write: [out]\n")
	with, err := CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	base, err := CompilePlane(withoutDeviceRows(rt))
	if err != nil {
		t.Fatal(err)
	}
	baseKinds := map[string]PlaneKind{}
	for _, r := range base.FS {
		baseKinds[r.Path] = r.Kind
	}
	var added []string
	for _, r := range with.FS {
		was, had := baseKinds[r.Path]
		if had {
			if r.Kind != was {
				t.Errorf("row %s changed kind from %04b to %04b", r.Path, was, r.Kind)
			}
			continue
		}
		added = append(added, r.Path)
		if r.Kind&PlaneModifyAllow == 0 || r.Kind&(PlaneReadDeny|PlaneRenameRefused|PlaneProtected) != 0 {
			t.Errorf("device row %s kind %04b, want a plain modify-allow", r.Path, r.Kind)
		}
		if r.Modify.Section != PlaneFSRule || rt.FS[r.Modify.Index].RuleName() != agent.BuiltinStandardDevices || !rt.FS[r.Modify.Index].StdDevice {
			t.Errorf("device row %s is decided by %+v, want the product's device entry", r.Path, r.Modify)
		}
	}
	slices.Sort(added)
	want := slices.Clone(standardDevicePaths)
	slices.Sort(want)
	if !slices.Equal(added, want) {
		t.Fatalf("rows added under the device rule = %v, want %v", added, want)
	}
	for _, r := range with.FS {
		if strings.HasPrefix(r.Path, "/dev") && !slices.Contains(want, r.Path) {
			t.Errorf("a row at %s: nothing else under /dev is keyed", r.Path)
		}
	}
	for _, p := range standardDevicePaths {
		if v := with.Decide(p, PlaneModify); !v.Allow {
			t.Errorf("plane: modify %s = %+v, want allow", p, v)
		}
	}
	for _, p := range []string{"/dev/tty", "/dev/shm/x", "/dev/pts/0", "/dev/sda", "/dev/newfile"} {
		if v := with.Decide(p, PlaneModify); v.Allow {
			t.Errorf("plane: modify %s = %+v, want refused", p, v)
		}
	}
}
