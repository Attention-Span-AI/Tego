// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRootWalkMatchesEvaluate is TIER3-PLAN §5's parity on the model: the walk over RootRows alone, the one the
// plane makes in the kernel, answers every fs action on every canonical path of every generated table as
// Evaluate's bpflsm column does — the verdict, and for a refusal the rule and reason the line carries.
func TestRootWalkMatchesEvaluate(t *testing.T) {
	kinds := []agent.ActionKind{agent.ActionFSRead, agent.ActionFSWrite, agent.ActionFSDelete, agent.ActionFSMkdir}
	bad := 0
	tables := genTables(backend.TierBPFLSM, func(desc string, rt *agent.RuleTable) {
		x := NewRootIndex(RootRows(rt))
		for _, p := range genPaths {
			for _, k := range kinds {
				read := k == agent.ActionFSRead
				got := x.Walk(p, read)
				ev := Evaluate(rt, agent.Action{Kind: k, Path: p}, backend.TierBPFLSM)
				want, reason := RootDecide(rt, k, p)
				if got.Allow && got == want && k == agent.ActionFSDelete {
					// The Landlock floor the run keeps under the walk asks an unlink of its directory.
					if l, refused := (&Evaluator{rt: rt}).landlockDelete(p); refused {
						if ev != l {
							bad++
							t.Errorf("%s %s %s: the walk allows, the Landlock floor refuses %+v, Evaluate %+v", desc, k, p, l, ev)
						}
						continue
					}
				}
				if got.Allow != (ev.Verdict == agent.VerdictAllow) || got != want {
					bad++
					if bad < 20 {
						t.Errorf("%s %s %s: walk %+v, RootDecide %+v, Evaluate %+v", desc, k, p, got, want, ev)
					}
					continue
				}
				if ev.Verdict == agent.VerdictAllow {
					continue
				}
				// A refusal names the entry that decided it, or the nearest entry, or unmatched.
				name := agent.UnmatchedRule
				switch {
				case got.Rule >= 0:
					name = rt.FS[got.Rule].RuleName()
				case got.Named >= 0:
					name = rt.FS[got.Named].RuleName()
				}
				if ev.Rule != name || ev.Reason != reason {
					bad++
					if bad < 20 {
						t.Errorf("%s %s %s: walk names %s/%s, Evaluate %+v", desc, k, p, name, reason, ev)
					}
				}
			}
		}
	})
	if tables < 1000 {
		t.Fatalf("only %d tables generated", tables)
	}
}

// TestRootWalkBound: the walk stops at agent.MaxWalk steps, as the kernel's does: a path deeper than that with
// no entry within the bound is refused path-unresolved, and an entry within it decides as usual.
func TestRootWalkBound(t *testing.T) {
	deep := "/d" + strings.Repeat("/n", agent.MaxWalk+2)
	for _, tc := range []struct {
		name string
		fs   []agent.FSRule
		path string
	}{
		{"no entry", nil, deep},
		{"write at the top", []agent.FSRule{{Kind: agent.FSWrite, Path: "/d", Access: agent.AccessWriteSet}}, deep},
		{"write within the bound", []agent.FSRule{{Kind: agent.FSWrite, Path: "/d" + strings.Repeat("/n", 10), Access: agent.AccessWriteSet}}, deep},
		{"shallow", []agent.FSRule{{Kind: agent.FSDenyRead, Path: "/d"}}, "/d/n/f"},
	} {
		rt := &agent.RuleTable{FS: tc.fs, Tier: backend.TierBPFLSM}
		x := NewRootIndex(RootRows(rt))
		for _, k := range []agent.ActionKind{agent.ActionFSRead, agent.ActionFSWrite} {
			got := x.Walk(tc.path, k == agent.ActionFSRead)
			want, reason := RootDecide(rt, k, tc.path)
			ev := Evaluate(rt, agent.Action{Kind: k, Path: tc.path}, backend.TierBPFLSM)
			if got != want || got.Allow != (ev.Verdict == agent.VerdictAllow) || got.Unresolved != (ev.Reason == record.ReasonPathUnresolved) {
				t.Errorf("%s %s: walk %+v, RootDecide %+v (%s), Evaluate %+v", tc.name, k, got, want, reason, ev)
			}
		}
	}
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM}
	x := NewRootIndex(RootRows(rt))
	if v := x.Walk(deep, true); !v.Unresolved || v.Allow {
		t.Errorf("a path deeper than the bound with no entry: %+v, want refused path-unresolved", v)
	}
}

// TestRootRowsOnePerCanonicalPath: rows key the spelling the kernel meets, so a symlinked entry is one row at
// its resolved path, and entries sharing a path share its row, the first of them naming it.
func TestRootRowsOnePerCanonicalPath(t *testing.T) {
	rt := &agent.RuleTable{FS: []agent.FSRule{
		{Kind: agent.FSWrite, Path: "/w", Raw: "/w", Access: agent.AccessWriteSet},
		{Kind: agent.FSDenyRead, Path: "/l", Raw: "/l", Resolved: "/w/a", Unenforced: true},
		{Kind: agent.FSWatch, Path: "/w/a", Raw: "/w/a"},
		{Kind: agent.FSImplicit, Path: "/r", Raw: "/r"},
	}}
	rows := RootRows(rt)
	var paths []string
	for _, r := range rows {
		paths = append(paths, r.Path)
	}
	if got := strings.Join(paths, " "); got != "/r /w /w/a" {
		t.Fatalf("rows at %s, want /r /w /w/a", got)
	}
	a := rows[2]
	if a.Named != 1 || a.Read.Rule != 1 || a.Read.Allow || a.Modify.Rule != 1 || a.Modify.Allow {
		t.Errorf("/w/a row = %+v, want named, read-refused and modify-refused by the deny_read (entry 1)", a)
	}
	if r := rows[0]; r.Read.Decides() || r.Modify.Rule != 3 || r.Modify.Allow {
		t.Errorf("/r row = %+v, want an implicit entry deciding modifications only", r)
	}
}

// TestRootExecRowsMatchMatchExec: the exec rows answer every path as matchExec does at tier 3, where an entry
// written as a bare name matches by its final component and one written as a path does not.
func TestRootExecRowsMatchMatchExec(t *testing.T) {
	rt := &agent.RuleTable{Exec: []agent.ExecRule{
		{Path: "/usr/bin/python3", Resolved: "/usr/bin/python3.12", Basename: "python3", Raw: "python3", ByName: true, Verdict: agent.VerdictAllow},
		{Path: "/opt/tools", IsDir: true, Raw: "/opt/tools", Verdict: agent.VerdictAllow},
		{Path: "/bin/sh", Resolved: "/usr/bin/dash", Basename: "sh", Raw: "/bin/sh", Verdict: agent.VerdictAllow},
		{Path: "/usr/bin/curl", Basename: "curl", Raw: "/usr/bin/curl", Verdict: agent.VerdictRefused},
		{Path: "/l/tools", Resolved: "/opt/other", IsDir: true, Raw: "/l/tools", Verdict: agent.VerdictAllow},
		// The shape Compile gives every entry that is no link: Resolved equal to Path.
		{Path: "/usr/bin/git", Resolved: "/usr/bin/git", Basename: "git", Raw: "/usr/bin/git", Verdict: agent.VerdictAllow},
		{Path: "/srv/bin", Resolved: "/srv/bin", IsDir: true, Raw: "/srv/bin", Verdict: agent.VerdictAllow},
	}, Tier: backend.TierBPFLSM}
	rows := RootExecRows(rt)
	for _, p := range []string{"/usr/bin/python3", "/usr/bin/python3.12", "/home/u/.venv/bin/python3", "/opt/tools",
		"/opt/tools/rg", "/opt/tools/sub/fd", "/opt/toolsx/rg", "/bin/sh", "/usr/bin/dash", "/tmp/sh", "/usr/bin/curl",
		"/tmp/curl", "/opt/other/x", "/l/tools/x", "/usr/bin/python", "/usr/bin/git", "/tmp/git", "/srv/bin/x",
		"/srv/bin/sub/y", "/srv/binx"} {
		wantRule, wantOK := matchExec(rt, p, backend.TierBPFLSM)
		rule, allow, ok := RootExecMatch(rows, p)
		if ok != wantOK || rule != wantRule {
			t.Errorf("%s: rows match entry %d (%v), matchExec %d (%v)", p, rule, ok, wantRule, wantOK)
			continue
		}
		if ok && allow != (rt.Exec[rule].Verdict == agent.VerdictAllow) {
			t.Errorf("%s: rows allow=%v for entry %d", p, allow, rule)
		}
	}
}
