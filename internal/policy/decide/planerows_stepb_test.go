// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"errors"
	"slices"
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestPlaneRowsProtectDenyWriteTargets is enforce-plane R12 on the rows: for every generated table, with and
// without deny_write targets, the attribute question (PlaneProtect: chmod, chown, xattr, ACL) is refused on exactly
// the paths a deny_write target covers (agent.RuleTable.DenyWriteTarget, the predicate supervisor R15c and Evaluate
// ask), named by that target, and allowed everywhere else, whatever the fs entries say: Landlock governs none of
// these calls, and the plane protects the targets only.
func TestPlaneRowsProtectDenyWriteTargets(t *testing.T) {
	bad, protected := 0, 0
	fail := func(format string, args ...any) {
		bad++
		if bad < 20 {
			t.Errorf(format, args...)
		}
	}
	genPlaneTables(func(desc string, rt *agent.RuleTable) {
		s, err := CompilePlane(rt)
		if err != nil {
			fail("%s: %v", desc, err)
			return
		}
		for _, r := range s.FS {
			if _, ok := rt.DenyWriteTarget(r.Path, false); ok != (r.Kind&PlaneProtected != 0) {
				fail("%s: row %s kind %08b, a deny_write target covers it: %v", desc, r.Path, r.Kind, ok)
			}
			if r.Kind&PlaneMountOnly != 0 {
				fail("%s: row %s carries PlaneMountOnly, which only a mount row has", desc, r.Path)
			}
		}
		for _, p := range planeProbes {
			v := s.Decide(p, PlaneProtect)
			target, covered := rt.DenyWriteTarget(p, false)
			if v.Allow == covered {
				fail("%s chmod %s: plane %+v, a deny_write target covers it: %v", desc, p, v, covered)
				continue
			}
			if covered {
				protected++
				if name := v.Rule.Name(rt); name != target.RuleName() {
					fail("%s chmod %s: plane names %s, the target is %s", desc, p, name, target.RuleName())
				}
				if s.RuleAt(v.Row, PlaneProtect, 1) != v.Rule {
					fail("%s chmod %s: RuleAt names another rule than Decide", desc, p)
				}
			}
		}
	})
	if protected == 0 {
		t.Fatal("no generated table protected any probe path")
	}
}

// TestPlaneRowsWithMounts is enforce-plane R12's mounted-root rows: WithMounts keys a mountpoint strictly below a
// deny_write target at the nearest row above it (no entry lies between, so that row's answer is the path model's
// there), leaves out a mountpoint elsewhere, at a target, at a row's path or relative, keys and pins each one with
// the Landlock grant the domain already has there, leaves CompilePlane's rows and positions as they were, and counts
// the mount rows against the slot's cap.
func TestPlaneRowsWithMounts(t *testing.T) {
	rt := &agent.RuleTable{
		Tier: backend.TierBPFLSM,
		FS: []agent.FSRule{
			{Kind: agent.FSWrite, Path: "/w", Access: agent.AccessWriteFile | agent.AccessMakeDir},
			{Kind: agent.FSDenyRead, Path: "/w/.git/secret"},
		},
		DenyWrite: []agent.FSRule{{Kind: agent.FSDenyWrite, Path: "/w/.git", Resolved: "/w/.git", BuiltIn: true, Unenforced: true}},
	}
	s, err := CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	fs := slices.Clone(s.FS)
	points := []string{"/w/.git/tmp", "/w/.git/secret/cache", "/w/.git", "/w/.git/secret", "/w/other", "/proc", "rel",
		"/w/.git/tmp/../tmp"}
	m, err := s.WithMounts(rt, points)
	if err != nil {
		t.Fatal(err)
	}
	gitRow, secretRow := s.fsByPath["/w/.git"], s.fsByPath["/w/.git/secret"]
	want := []PlaneMountRow{{Path: "/w/.git/secret/cache", Row: secretRow}, {Path: "/w/.git/tmp", Row: gitRow}}
	if !slices.Equal(m.Mounts, want) {
		t.Fatalf("mount rows %+v, want %+v", m.Mounts, want)
	}
	if !slices.EqualFunc(s.FS, fs, func(a, b PlaneRow) bool { return a == b }) || len(s.Mounts) != 0 || &m.FS[0] != &s.FS[0] {
		t.Error("WithMounts changed the compiled rows, or did not keep their positions")
	}
	for _, mr := range m.Mounts {
		if !slices.Contains(m.Keyed, mr.Path) || slices.Contains(s.Keyed, mr.Path) {
			t.Errorf("%s: not keyed by the mounted table alone", mr.Path)
		}
		if m.FS[mr.Row].Kind&PlaneProtected == 0 {
			t.Errorf("%s: its row %s protects nothing", mr.Path, m.FS[mr.Row].Path)
		}
	}
	if !slices.IsSorted(m.Keyed) {
		t.Error("Keyed is not sorted")
	}
	// /w/.git/tmp lies under the write entry, whose grant includes the read set; the neutral rule carries it.
	var tmp *NeutralRule
	for i := range m.Neutral {
		if m.Neutral[i].Path == "/w/.git/tmp" {
			tmp = &m.Neutral[i]
		}
	}
	if tmp == nil || tmp.Access&(agent.AccessReadFile|agent.AccessReadDir) == 0 || tmp.Access&^(agent.AccessReadFile|agent.AccessReadDir) != 0 {
		t.Errorf("/w/.git/tmp's neutral rule is %+v, want the read rights the write entry grants and nothing else", tmp)
	}
	if same, err := s.WithMounts(rt, []string{"/w/other", "/"}); err != nil || same != s {
		t.Errorf("no mountpoint below a target: %v, %v", same, err)
	}
	if same, err := s.WithMounts(&agent.RuleTable{FS: rt.FS}, points); err != nil || same != s {
		t.Errorf("a table with no deny_write target keys no mount: %v", err)
	}
	many := make([]string, PlaneRowsMax)
	for i := range many {
		many[i] = "/w/.git/m" + strconv.Itoa(i)
	}
	var capErr *ErrPlaneCap
	if _, err := s.WithMounts(rt, many); !errors.As(err, &capErr) {
		t.Errorf("mount rows past the cap: %v, want ErrPlaneCap", err)
	}
}
