// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// advisoryNameOps are the supervisor's fs operations an end of which Evaluate's tier-2 column models one for one: the
// advisory verdict's op, flags and object kind, and the action kind and object Evaluate's per-end question (evalFS)
// takes, the end canonicalized as Evaluate canonicalizes it (an unlink's, a rename's and a link's end is not followed).
var advisoryNameOps = []struct {
	op     string
	flags  int
	dir    bool
	kind   agent.ActionKind
	follow bool
}{
	{record.FSOpen, unix.O_WRONLY | unix.O_CREAT, false, agent.ActionFSWrite, true},
	{record.FSOpen, unix.O_RDONLY, false, agent.ActionFSRead, true},
	{record.FSOpen, unix.O_RDONLY | unix.O_DIRECTORY, true, agent.ActionFSRead, true},
	{record.FSUnlink, 0, false, agent.ActionFSDelete, false},
	{record.FSUnlink, 0, true, agent.ActionFSDelete, false},
	{record.FSMkdir, 0, true, agent.ActionFSMkdir, true},
	{record.FSRename, 0, false, agent.ActionFSRename, false},
	{record.FSRename, 0, true, agent.ActionFSRename, false},
	{record.FSLink, 0, false, agent.ActionFSLink, false},
}

// TestAdvisoryFSNameMatchesEvaluateAtCgroup holds the supervisor's advisory verdict at tier cgroup (AdvisoryFS, which
// the listener fallback's fallbackMutation enforces) to Evaluate's tier-2 column on every generated name table (ADR
// 0043 D1, D7, D8): where a name entry changes Evaluate's answer for an end and the advisory verdict agreed with it
// without the names, the advisory verdict with them is Evaluate's, rule and reason; and every answer the names change
// in the advisory verdict is a refusal Evaluate makes with the same rule and reason. A directory is never decided by
// a name. Run on the table's index and on the scans.
func TestAdvisoryFSNameMatchesEvaluateAtCgroup(t *testing.T) {
	bad, decided := 0, 0
	genNameTables(sampledNames(func(desc string, rt, bare *agent.RuleTable) {
		rt.Tier, bare.Tier = backend.TierCgroup, backend.TierCgroup
		// The spelling against both spellings' list (the supervisor's first verdict), by index and by scan, and the end
		// where it lands against the resolved list (decideFS's verdict again at the walk's landing).
		ix, ixBare := NewAdvisoryTablesFor(rt), NewAdvisoryTablesFor(bare)
		lists := [3][2]*AdvisoryList{
			{ix.Both, ixBare.Both},
			{NewAdvisoryTables(rt.FS).Both, NewAdvisoryTables(bare.FS).Both},
			{ix.Resolved, ixBare.Resolved},
		}
		for _, p := range nameProbes {
			for _, o := range advisoryNameOps {
				obj := objFile
				if o.dir {
					obj = objDir
				}
				end := canonicalEnd(rt, cleanPath(p))
				if o.follow {
					end = Canonical(rt, cleanPath(p))
				}
				// A deny_write target's refusal is the supervisor's denyWrite, asked after the advisory verdict (R15c).
				if _, target := evalDenyWrite(rt, o.kind, end); target {
					continue
				}
				want := evalFS(rt, o.kind, end, backend.TierCgroup, obj)
				wantBare := evalFS(bare, o.kind, canonicalEnd(bare, cleanPath(p)), backend.TierCgroup, obj)
				if o.follow {
					wantBare = evalFS(bare, o.kind, Canonical(bare, cleanPath(p)), backend.TierCgroup, obj)
				}
				for i, l := range lists {
					at := p
					if i == 2 {
						at = end
					}
					got := advisoryResult(AdvisoryFS(rt, l[0], at, o.op, o.flags, o.dir))
					gotBare := advisoryResult(AdvisoryFS(bare, l[1], at, o.op, o.flags, o.dir))
					missed := want != wantBare && gotBare == wantBare && got != want
					// Where the advisory verdict disagrees with Evaluate without names (a spelling through a declared
					// link, which decideFS asks again where it lands), a name may only add a refusal Evaluate makes.
					invented := got != gotBare && (got.Verdict != agent.VerdictRefused || want.Verdict != agent.VerdictRefused ||
						(gotBare == wantBare && got != want))
					if want != wantBare && i == 0 {
						decided++
					}
					if missed || invented {
						bad++
						if bad < 20 {
							t.Errorf("%s %s %s flags %#x dir=%v (scan=%v): advisory %s (without names %s), Evaluate %s (without names %s)",
								desc, o.op, p, o.flags, o.dir, i == 1, brief(got), brief(gotBare), brief(want), brief(wantBare))
						}
					}
				}
			}
		}
	}))
	if decided == 0 {
		t.Fatal("no name entry decided any end: the property asked nothing")
	}
}

// TestAdvisoryFSNamesMutationsAtCgroup is the advisory verdict of each operation the listener fallback's supervisor
// refuses on a name (ADR 0043 D7; supervisor R15, R17) on nameTable: a creation, a write-open, a truncate, a mknod, a
// symlink, a link's new name, a rename's ends and an unlink of a covered file are refused, named per D8 (the
// expansion's own entry at an existing .env), a write-open read-denied as the listener refuses it; a read-open
// read-denied; the same operations on a directory of that name, on an exception, beneath a dependency directory and
// outside every scope are not refused by a name.
func TestAdvisoryFSNamesMutationsAtCgroup(t *testing.T) {
	rt := nameTable(backend.TierCgroup)
	tabs := NewAdvisoryTablesFor(rt)
	const create = unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL
	for _, tc := range []struct {
		op     string
		flags  int
		dir    bool
		path   string
		rule   string
		reason record.Reason
	}{
		{record.FSOpen, create, false, "/p/later/.env.local", labelEnvPfx, record.ReasonReadDenied},
		{record.FSOpen, unix.O_RDONLY, false, "/p/later/.env.local", labelEnvPfx, record.ReasonReadDenied},
		{record.FSTruncate, 0, false, "/p/src/.ENV", labelEnv, record.ReasonWriteOutsideContract},
		{OpMknod, create, false, "/p/later/.env", labelEnv, record.ReasonWriteOutsideContract},
		{record.FSSymlink, 0, false, "/p/later/.env.prod", labelEnvPfx, record.ReasonWriteOutsideContract},
		{record.FSLink, 0, false, "/p/cfg/a/token.json", ruleToken, record.ReasonWriteOutsideContract},
		{record.FSRename, 0, false, "/p/later/.env", labelEnv, record.ReasonRenameOutsideContract},
		{record.FSUnlink, 0, false, "/p/.env", "fs.deny_read[/p/.env]", record.ReasonDeleteOutsideContract},
		{record.FSUnlink, 0, false, "/p/later/.env", labelEnv, record.ReasonDeleteOutsideContract},
		{record.FSUnlink, 0, true, "/p/later/.env", "", ""},
		{record.FSMkdir, 0, true, "/p/later/.env", "", ""},
		{record.FSRename, 0, true, "/p/later/.env", "", ""},
		{record.FSOpen, create, false, "/p/x/.env.example", "", ""},
		{record.FSOpen, create, false, "/p/node_modules/m/.env", "", ""},
		{record.FSOpen, create, false, "/tmp/.env", "", ""},
		{record.FSOpen, create, false, "/p/app/.env.test", "", ""},
	} {
		rule, v, reason := AdvisoryFS(rt, tabs.Both, tc.path, tc.op, tc.flags, tc.dir)
		if tc.rule == "" {
			if v == record.VerdictRefused && (reason == record.ReasonReadDenied || rule != ruleP && rule != "fs.write[/tmp]" && rule != "fs.write[/p/app/.env.test]") {
				t.Errorf("%s %s dir=%v: %s %s %s, want no name refusal", tc.op, tc.path, tc.dir, v, rule, reason)
			}
			continue
		}
		if v != record.VerdictRefused || rule != tc.rule || reason != tc.reason {
			t.Errorf("%s %s dir=%v: %s %s %s, want refused %s %s", tc.op, tc.path, tc.dir, v, rule, reason, tc.rule, tc.reason)
		}
	}
}

// TestNameMoveRefusedMatchesEvaluate holds FSIndex.NameMoveRefused, the supervisor's D5 question at tier cgroup (ADR
// 0043 interface 1), to Evaluate's tier-2 directory rename on every generated name table: where Evaluate refuses a
// directory rename by a name entry's coverage, rename-outside-contract under the entry's rule or path-unresolved, the
// index refuses it the same way, and it refuses nothing else; a file is never asked.
func TestNameMoveRefusedMatchesEvaluate(t *testing.T) {
	asked := 0
	genNameTables(func(desc string, rt, _ *agent.RuleTable) {
		rt.Tier = backend.TierCgroup
		ix := NewFSIndex(rt)
		for p := range nameDirProbes {
			for _, dst := range nameRenameDests {
				src, end := canonicalEnd(rt, cleanPath(p)), canonicalEnd(rt, cleanPath(dst))
				rule, reason, refused := ix.NameMoveRefused(src, end, true)
				m, want := newNameIndex(rt).MoveRefused(src, end)
				if refused != want {
					t.Errorf("%s %s -> %s: NameMoveRefused %v, NameIndex.MoveRefused %v", desc, p, dst, refused, want)
					continue
				}
				if !refused {
					continue
				}
				asked++
				w := nameMoveRefusal(newNameIndex(rt), m)
				if rule != w.Rule || reason != w.Reason {
					t.Errorf("%s %s -> %s: NameMoveRefused %s %s, want %s %s", desc, p, dst, rule, reason, w.Rule, w.Reason)
				}
				// Evaluate's directory rename asks D5 after R15d's DenyReadMoveTarget, before the ends.
				ev := Evaluate(rt, agent.Action{Kind: agent.ActionFSRename, Path: p, DestPath: dst, Dir: true}, backend.TierCgroup)
				if _, dr := rt.DenyReadMoveTarget(src, true); !dr && (ev.Verdict != agent.VerdictRefused || ev.Rule != rule || ev.Reason != reason) {
					t.Errorf("%s %s -> %s: NameMoveRefused %s %s, Evaluate %+v", desc, p, dst, rule, reason, ev)
				}
				if _, _, fileRefused := ix.NameMoveRefused(src, end, false); fileRefused {
					t.Errorf("%s %s -> %s: a file's rename was asked D5", desc, p, dst)
				}
			}
		}
	})
	if asked == 0 {
		t.Fatal("no directory rename was refused: the property asked nothing")
	}
}

// advisoryResult is an advisory verdict as an EvalResult, to compare with Evaluate's.
func advisoryResult(rule string, v record.Verdict, reason record.Reason) agent.EvalResult {
	return agent.EvalResult{Verdict: agent.Verdict(v), Rule: rule, Reason: reason}
}

// brief is an fs answer's verdict, rule and reason.
func brief(r agent.EvalResult) string {
	return string(r.Verdict) + " " + r.Rule + " " + string(r.Reason)
}
