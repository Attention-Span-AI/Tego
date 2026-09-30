// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestPlaneEvaluatorMatchesEvaluate is T10's parity property: the bpflsm column read out of the plane rows
// answers every fs action, on every generated table with and without deny_write targets, exactly as the root
// model does (Evaluate at bpflsm): verdict, rule and reason. The one stated difference is a rename end that lies
// above every write entry and above a deny_write target, where the plane names the row's nearest entry
// (checkPlaneRename).
func TestPlaneEvaluatorMatchesEvaluate(t *testing.T) {
	bad := 0
	fail := func(format string, args ...any) {
		bad++
		if bad < 20 {
			t.Errorf(format, args...)
		}
	}
	tables := genPlaneTables(func(desc string, rt *agent.RuleTable) {
		checkPlaneEvaluator(desc, rt, planeProbes, renameDests, false, fail)
	})
	if tables < 1000 {
		t.Fatalf("only %d tables", tables)
	}
	// ADR 0043's name dimensions: the column read out of the rows and the name rows answers as the root model,
	// files and directories alike.
	named := genNameTables(func(desc string, rt, _ *agent.RuleTable) {
		checkPlaneEvaluator(desc, rt, nameProbes, nameRenameDests, true, fail)
	})
	if named < 1000 {
		t.Fatalf("only %d tables with name entries", named)
	}
}

// checkPlaneEvaluator is TestPlaneEvaluatorMatchesEvaluate's question of one table; dirs asks each probe as a
// directory too.
func checkPlaneEvaluator(desc string, rt *agent.RuleTable, probes, dests []string, dirs bool, fail func(string, ...any)) {
	kinds := []agent.ActionKind{agent.ActionFSRead, agent.ActionFSWrite, agent.ActionFSDelete, agent.ActionFSMkdir}
	pe := NewPlaneEvaluator(rt)
	if pe.Err() != nil {
		fail("%s: %v", desc, pe.Err())
		return
	}
	objects := []bool{false}
	if dirs {
		objects = append(objects, true)
	}
	for _, p := range probes {
		for _, dir := range objects {
			for _, k := range kinds {
				a := agent.Action{Kind: k, Path: p, Dir: dir}
				if got, want := pe.Evaluate(a, Env{}), Evaluate(rt, a, backend.TierBPFLSM); got != want {
					fail("%s %s %s dir=%v: plane %+v, Evaluate %+v", desc, k, p, dir, got, want)
				}
			}
			if !dir {
				// An attribute change: path_chmod and the attribute hooks against the root model's deny_write
				// refusal, verdict, rule and reason (enforce-plane R12).
				a := agent.Action{Kind: agent.ActionFSAttr, Path: p}
				if got, want := pe.Evaluate(a, Env{}), Evaluate(rt, a, backend.TierBPFLSM); got != want {
					fail("%s attr %s: plane %+v, Evaluate %+v", desc, p, got, want)
				}
				// A hard link: path_link (the new name a modification, then REFER) against the root model's two ends
				// and no-gain rule. Verdict and reason always agree; the rule may differ where the root model names a
				// deny_write target first, as for a rename, or where REFER refuses a source the root model refuses at
				// itself (the plane names the source's nearest entry, enforce-plane R10).
				for _, dst := range dests {
					a := agent.Action{Kind: agent.ActionFSLink, Path: p, DestPath: dst}
					got, want := pe.Evaluate(a, Env{}), Evaluate(rt, a, backend.TierBPFLSM)
					if got.Verdict != want.Verdict || got.Reason != want.Reason {
						fail("%s link %s -> %s: plane %+v, Evaluate %+v", desc, p, dst, got, want)
						continue
					}
					if got.Rule != want.Rule && got.Verdict == agent.VerdictAllow {
						fail("%s link %s -> %s: plane names %s, Evaluate %+v", desc, p, dst, got.Rule, want)
					}
				}
			}
			for _, dst := range dests {
				a := agent.Action{Kind: agent.ActionFSRename, Path: p, DestPath: dst, Dir: dir}
				got, want := pe.Evaluate(a, Env{}), Evaluate(rt, a, backend.TierBPFLSM)
				if got.Verdict != want.Verdict || got.Reason != want.Reason {
					fail("%s rename %s -> %s dir=%v: plane %+v, Evaluate %+v", desc, p, dst, dir, got, want)
					continue
				}
				if got.Rule != want.Rule {
					if _, dw := denyWriteIdx(rt, p, true); !dw {
						if _, dw = denyWriteIdx(rt, dst, true); !dw {
							fail("%s rename %s -> %s dir=%v: plane names %s, Evaluate %+v", desc, p, dst, dir, got.Rule, want)
						}
					}
				}
			}
		}
	}
}

// TestPlaneEvaluatorExecMatchesEvaluate: exec answers, a script and a bare command name included, on tables of one
// or two exec entries beside a deny_read, restricted and unrestricted, equal the root model's.
func TestPlaneEvaluatorExecMatchesEvaluate(t *testing.T) {
	fs := []agent.FSRule{
		{Kind: agent.FSWrite, Path: "/opt/x", Raw: "/opt/x", Resolved: "/opt/x", Access: agent.AccessWriteSet},
		{Kind: agent.FSDenyRead, Path: "/usr/bin/secret", Raw: "/usr/bin/secret", Resolved: "/usr/bin/secret"},
		{Kind: agent.FSDenyRead, Path: "/srv/tools/sub", Raw: "/srv/tools/sub", Resolved: "/srv/tools/sub"},
	}
	probes := append(append([]string{}, execProbes...), "/usr/bin/secret", "/srv/tools/sub/fd", "a", "sh", "b", "zz")
	n, count, bad := len(genExecPool), 0, 0
	check := func(unrestricted bool, idx ...int) {
		var ex []agent.ExecRule
		for _, i := range idx {
			ex = append(ex, genExecPool[i])
		}
		ex[0].Interp = "/lib/ld.so"
		rt := &agent.RuleTable{FS: fs, Exec: ex, Tier: backend.TierBPFLSM, Contract: &agent.Contract{}}
		if !unrestricted {
			rt.Contract.Exec = &agent.ExecSection{}
		}
		pe := NewPlaneEvaluator(rt)
		if pe.Err() != nil {
			t.Fatalf("%v: %v", idx, pe.Err())
		}
		count++
		for _, p := range probes {
			for _, script := range []string{"", "/usr/bin/a", "/tmp/s"} {
				a := agent.Action{Kind: agent.ActionExec, Path: p, Script: script}
				if got, want := pe.Evaluate(a, Env{}), Evaluate(rt, a, backend.TierBPFLSM); got != want {
					if bad++; bad < 20 {
						t.Errorf("%v unrestricted=%v exec %s script %q: plane %+v, Evaluate %+v", idx, unrestricted, p, script, got, want)
					}
				}
			}
		}
	}
	for _, u := range []bool{false, true} {
		for a := 0; a < n; a++ {
			check(u, a)
			for b := a + 1; b < n; b++ {
				check(u, a, b)
			}
		}
	}
	if count < 40 {
		t.Fatalf("only %d exec tables", count)
	}
}

// TestPlaneEvaluatorUnbuildable: a table the plane cannot hold answers every fs and exec action refused, naming
// PlaneUnbuildableRule, and leaves net to the root model.
func TestPlaneEvaluatorUnbuildable(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM, Exec: []agent.ExecRule{{Path: "/b/x", Resolved: "/b/x", Verdict: agent.VerdictAsk}}}
	pe := NewPlaneEvaluator(rt)
	if pe.Err() == nil {
		t.Fatal("an ask exec entry compiles for the plane")
	}
	for _, a := range []agent.Action{
		{Kind: agent.ActionFSRead, Path: "/x"}, {Kind: agent.ActionFSRename, Path: "/x", DestPath: "/y"}, {Kind: agent.ActionExec, Path: "/b/x"},
		{Kind: agent.ActionFSLink, Path: "/x", DestPath: "/y"}, {Kind: agent.ActionFSAttr, Path: "/x"},
		{Kind: agent.ActionExecAnon}, // an exec row too (correctness F2)
	} {
		if got := pe.Evaluate(a, Env{}); got.Verdict != agent.VerdictRefused || got.Rule != PlaneUnbuildableRule || got.Reason == "" {
			t.Errorf("%+v: %+v", a, got)
		}
	}
	// A malformed action is invalid before the table's compile error is asked, for exec as for fs.
	for _, a := range []agent.Action{
		{Kind: agent.ActionFSRead}, {Kind: agent.ActionFSRename, Path: "/x"}, {Kind: agent.ActionExec, Argv: []string{""}},
		{Kind: agent.ActionFSLink, Path: "/x"}, {Kind: agent.ActionFSAttr},
		{Kind: agent.ActionExec},
	} {
		if got, want := pe.Evaluate(a, Env{}), Evaluate(rt, a, backend.TierBPFLSM); got != want || got.Rule == PlaneUnbuildableRule {
			t.Errorf("malformed %+v: %+v, want Evaluate's %+v", a, got, want)
		}
	}
}

// TestPlaneEvaluatorScriptMeetsTheLandlockFloor: the bpflsm column is the plane intersected with the Landlock domain
// the child stage installs (ADR 0019's one column, ADR 0028), so a #! script with no exec grant of its own is
// refused, unmatched, although the plane passes its stage and would allow the interpreter (Landlock's EXECUTE on
// the script, enforce-plane R9's composition, SEMANTICS §4's 2026-09-29 note). A script an entry grants by path or
// by directory runs, named by its interpreter's entry. A script matched by name alone is not granted: Landlock
// cannot match by name. The root model at bpflsm answers the same.
func TestPlaneEvaluatorScriptMeetsTheLandlockFloor(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM, Contract: &agent.Contract{Exec: &agent.ExecSection{}}, Exec: []agent.ExecRule{
		{Path: "/bin/sh", Resolved: "/bin/sh", Raw: "sh", Basename: "sh", ByName: true, Verdict: agent.VerdictAllow},
		{Path: "/w/ok.sh", Resolved: "/w/ok.sh", Raw: "/w/ok.sh", Basename: "ok.sh", Verdict: agent.VerdictAllow},
		{Path: "/w/scripts", Resolved: "/w/scripts", Raw: "/w/scripts", IsDir: true, Verdict: agent.VerdictAllow},
		{Path: "/opt/named.sh", Resolved: "/opt/named.sh", Raw: "named.sh", Basename: "named.sh", ByName: true, Verdict: agent.VerdictAllow},
	}}
	pe := NewPlaneEvaluator(rt)
	if pe.Err() != nil {
		t.Fatal(pe.Err())
	}
	for _, c := range []struct {
		path, script string
		want         agent.EvalResult
	}{
		{"/w/run.sh", "/bin/sh", agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.UnmatchedRule, Reason: record.ReasonExecNotAllowed}},
		{"/w/other/named.sh", "/bin/sh", agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.UnmatchedRule, Reason: record.ReasonExecNotAllowed}},
		{"/w/ok.sh", "/bin/sh", agent.EvalResult{Verdict: agent.VerdictAllow, Rule: "exec[sh]"}},
		{"/w/scripts/s.sh", "/bin/sh", agent.EvalResult{Verdict: agent.VerdictAllow, Rule: "exec[sh]"}},
		{"/w/ok.sh", "/usr/bin/zsh", agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.UnmatchedRule, Reason: record.ReasonExecNotAllowed}},
	} {
		a := agent.Action{Kind: agent.ActionExec, Path: c.path, Script: c.script}
		if got := pe.Evaluate(a, Env{}); got != c.want {
			t.Errorf("plane: exec %s script %s: %+v, want %+v", c.path, c.script, got, c.want)
		}
		if got := Evaluate(rt, a, backend.TierBPFLSM); got != c.want {
			t.Errorf("root model: exec %s script %s: %+v, want %+v", c.path, c.script, got, c.want)
		}
	}
}

// TestPlaneEvaluatorLinkMeetsTheLandlockFloor: the bpflsm column is the plane intersected with the Landlock domain the
// run keeps under it (as TestPlaneEvaluatorScriptMeetsTheLandlockFloor composes it for a script), so a link path_link
// allows is still refused where the ruleset refuses it (hook_path_link): a cross-directory link of a file-level write
// entry, which grants no REFER on its directory, and a link into an exec.allow directory, whose EXECUTE the file would
// gain (security F1 and F4). The root model at bpflsm answers the same.
func TestPlaneEvaluatorLinkMeetsTheLandlockFloor(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM, Contract: &agent.Contract{Exec: &agent.ExecSection{}},
		FS: []agent.FSRule{
			{Kind: agent.FSWrite, Path: "/w/out", Raw: "./out/", Resolved: "/w/out", Access: agent.AccessWriteSet},
			{Kind: agent.FSWrite, Path: "/w/a.txt", Raw: "./a.txt", Resolved: "/w/a.txt", Access: agent.AccessWriteSet, Regular: true},
		},
		Exec: []agent.ExecRule{{Path: "/w/out/bin", Resolved: "/w/out/bin", Raw: "./out/bin/", IsDir: true, Verdict: agent.VerdictAllow}},
	}
	pe := NewPlaneEvaluator(rt)
	if pe.Err() != nil {
		t.Fatal(pe.Err())
	}
	wo := record.ReasonWriteOutsideContract
	for _, c := range []struct {
		src, dst string
		want     agent.EvalResult
	}{
		{"/w/a.txt", "/w/out/a2", agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.UnmatchedRule, Reason: wo}},
		{"/w/out/a", "/w/out/bin/a2", agent.EvalResult{Verdict: agent.VerdictRefused, Rule: "fs.write[./out/]", Reason: wo}},
		{"/w/out/bin/t", "/w/out/t2", agent.EvalResult{Verdict: agent.VerdictAllow, Rule: "fs.write[./out/]"}},
		{"/w/out/a", "/w/out/b", agent.EvalResult{Verdict: agent.VerdictAllow, Rule: "fs.write[./out/]"}},
	} {
		a := agent.Action{Kind: agent.ActionFSLink, Path: c.src, DestPath: c.dst}
		if got := pe.Evaluate(a, Env{}); got != c.want {
			t.Errorf("plane: link %s -> %s: %+v, want %+v", c.src, c.dst, got, c.want)
		}
		if got := Evaluate(rt, a, backend.TierBPFLSM); got != c.want {
			t.Errorf("root model: link %s -> %s: %+v, want %+v", c.src, c.dst, got, c.want)
		}
	}
	// A rename meets the same floor: REFER's no-gain rule refuses a move into the exec.allow directory.
	ro := record.ReasonRenameOutsideContract
	for _, c := range []struct {
		src, dst string
		want     agent.EvalResult
	}{
		{"/w/out/a", "/w/out/bin/a2", agent.EvalResult{Verdict: agent.VerdictRefused, Rule: "fs.write[./out/]", Reason: ro}},
		{"/w/out/bin/t", "/w/out/t2", agent.EvalResult{Verdict: agent.VerdictAllow, Rule: "fs.write[./out/]"}},
	} {
		a := agent.Action{Kind: agent.ActionFSRename, Path: c.src, DestPath: c.dst}
		if got := pe.Evaluate(a, Env{}); got != c.want {
			t.Errorf("plane: rename %s -> %s: %+v, want %+v", c.src, c.dst, got, c.want)
		}
		if got := Evaluate(rt, a, backend.TierBPFLSM); got != c.want {
			t.Errorf("root model: rename %s -> %s: %+v, want %+v", c.src, c.dst, got, c.want)
		}
		if got := NewEvaluator(rt).Evaluate(a, backend.TierBPFLSM); got != c.want {
			t.Errorf("indexed root model: rename %s -> %s: %+v, want %+v", c.src, c.dst, got, c.want)
		}
	}
}

// TestPlaneEvaluatorLinkWalksTheSourceFirst: path_link fails on either end's walk before it asks whether the new name
// may be made (bpf/decide.bpf.c: the source's walk, the destination's, then MODIFY_ALLOW, then REFER), so a source
// the walk cannot finish is path-unresolved even where the new name lies outside every write entry (security F5).
// The root model asks the source first too.
func TestPlaneEvaluatorLinkWalksTheSourceFirst(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM, Contract: &agent.Contract{Exec: &agent.ExecSection{}},
		FS: []agent.FSRule{{Kind: agent.FSWrite, Path: "/w/out", Raw: "./out/", Resolved: "/w/out", Access: agent.AccessWriteSet}}}
	pe := NewPlaneEvaluator(rt)
	if pe.Err() != nil {
		t.Fatal(pe.Err())
	}
	deep := "/d" + strings.Repeat("/n", agent.MaxWalk+2) + "/f"
	a := agent.Action{Kind: agent.ActionFSLink, Path: deep, DestPath: "/w/elsewhere"}
	want := agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.UnmatchedRule, Reason: record.ReasonPathUnresolved}
	if got := pe.Evaluate(a, Env{}); got != want {
		t.Errorf("plane: %+v, want %+v", got, want)
	}
	if got := Evaluate(rt, a, backend.TierBPFLSM); got.Verdict != want.Verdict || got.Reason != want.Reason {
		t.Errorf("root model: %+v, want %s (%s)", got, want.Verdict, want.Reason)
	}
}

// TestPlaneEvaluatorLinkOfADenyWriteTargetUnderNotifications: a table that holds fs notifications (an fs ask entry, an
// ask_read entry, an fs gate) keeps link notified at tier 3 (landlock planeSkips), so the supervisor's R15c refuses a
// link at a deny_write end before the plane sees it, under the target's own name (recordLink's denyWrite); the bpflsm
// column names it so. Without notifications path_link's REFER refuses it, named by the source row's nearest entry, the
// plane's own line (security F6).
func TestPlaneEvaluatorLinkOfADenyWriteTargetUnderNotifications(t *testing.T) {
	table := func(ask bool) *agent.RuleTable {
		rt := &agent.RuleTable{Tier: backend.TierBPFLSM, Contract: &agent.Contract{Exec: &agent.ExecSection{}},
			FS:        []agent.FSRule{{Kind: agent.FSWrite, Path: "/w/out", Raw: "./out/", Resolved: "/w/out", Access: agent.AccessWriteSet}},
			DenyWrite: []agent.FSRule{{Kind: agent.FSDenyWrite, Path: "/w/out/.git/config", Resolved: "/w/out/.git/config", BuiltIn: true, Unenforced: true}},
		}
		if ask {
			rt.FSAsk = []agent.FSRule{{Kind: agent.FSAsk, Path: "/w/review", Raw: "./review/", Resolved: "/w/review"}}
		}
		return rt
	}
	target := (agent.FSRule{Kind: agent.FSDenyWrite, Path: "/w/out/.git/config"}).RuleName()
	wo := record.ReasonWriteOutsideContract
	for _, c := range []struct {
		ask      bool
		src, dst string
		want     agent.EvalResult
	}{
		{true, "/w/out/.git/config", "/w/out/cfg", agent.EvalResult{Verdict: agent.VerdictRefused, Rule: target, Reason: wo}},
		{true, "/w/out/a", "/w/out/.git/config", agent.EvalResult{Verdict: agent.VerdictRefused, Rule: target, Reason: wo}},
		{false, "/w/out/.git/config", "/w/out/cfg", agent.EvalResult{Verdict: agent.VerdictRefused, Rule: "fs.write[./out/]", Reason: wo}},
	} {
		rt := table(c.ask)
		if rt.HoldsFSNotifications() != c.ask {
			t.Fatalf("ask=%v: HoldsFSNotifications = %v", c.ask, rt.HoldsFSNotifications())
		}
		pe := NewPlaneEvaluator(rt)
		if pe.Err() != nil {
			t.Fatal(pe.Err())
		}
		a := agent.Action{Kind: agent.ActionFSLink, Path: c.src, DestPath: c.dst}
		if got := pe.Evaluate(a, Env{}); got != c.want {
			t.Errorf("ask=%v: link %s -> %s: %+v, want %+v", c.ask, c.src, c.dst, got, c.want)
		}
	}
}
