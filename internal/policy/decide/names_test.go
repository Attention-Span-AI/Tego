// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// builtInPair is the built-in .env list's two name entries over scopes, as compile makes them.
func builtInPair(scopes ...string) []agent.NameDenyRule {
	var ss []agent.NameScope
	for _, s := range scopes {
		ss = append(ss, agent.NameScope{Canonical: s, Spelling: s})
	}
	return []agent.NameDenyRule{
		{Literal: ".env", Scopes: ss, BuiltIn: true},
		{Literal: ".env.", Prefix: true, Except: []string{".env.example", ".env.sample", ".env.template", ".env.dist"}, Scopes: ss, BuiltIn: true},
	}
}

// nameTable is a project /p, writable, with a nested write entry /p/src, an existing .env with its expansion row, a
// declared `cfg/*/token.json` glob scoped to /p/cfg, the built-in pair scoped to /p, and D3's exemption of
// /p/app/.env.test, a top-level write entry at an existing file.
func nameTable(tier backend.Tier) *agent.RuleTable {
	w := func(p string) agent.FSRule {
		return agent.FSRule{Kind: agent.FSWrite, Path: p, Raw: p, Resolved: p, Access: agent.AccessWriteSet}
	}
	fs := []agent.FSRule{
		w("/p"), w("/p/src"), w("/tmp"), w("/p/app/.env.test"),
		{Kind: agent.FSDenyRead, Path: "/p/.env", Resolved: "/p/.env", BuiltIn: true, Unenforced: true, Regular: true, Nlink: 1},
	}
	names := append([]agent.NameDenyRule{{Literal: "token.json", Raw: "cfg/*/token.json",
		Scopes: []agent.NameScope{{Canonical: "/p/cfg", Spelling: "/p/cfg"}}}}, builtInPair("/p")...)
	return &agent.RuleTable{FS: fs, Tier: tier, Record: agent.RecordFull, NameDeny: names,
		NameExempt: []agent.NameExemptRule{{Parent: "/p/app", Name: ".env.test", Write: 3}}}
}

// nameCase is one action's answer in each root tier, and at landlock, which never asks a name entry.
type nameCase struct {
	kind     agent.ActionKind
	path     string
	dir      bool
	cgroup   agent.EvalResult
	bpflsm   agent.EvalResult
	landlock agent.EvalResult
}

var (
	allowBy  = func(rule string) agent.EvalResult { return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: rule} }
	refuseBy = func(rule string, reason record.Reason) agent.EvalResult {
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: rule, Reason: reason}
	}
)

const (
	labelEnv    = "fs.deny_read[/p/**/.env]"
	labelEnvPfx = "fs.deny_read[/p/**/.env.*]"
	ruleToken   = "fs.deny_read[cfg/*/token.json]"
	ruleP       = "fs.write[/p]"
)

// checkNameCases evaluates each case in the three tiers, by the reference Evaluate and by the indexed Evaluator.
func checkNameCases(t *testing.T, rt *agent.RuleTable, cases []nameCase) {
	t.Helper()
	e := NewEvaluator(rt)
	for _, c := range cases {
		a := agent.Action{Kind: c.kind, Path: c.path, Dir: c.dir}
		for tier, want := range map[backend.Tier]agent.EvalResult{backend.TierCgroup: c.cgroup, backend.TierBPFLSM: c.bpflsm, backend.TierLandlock: c.landlock} {
			if want == (agent.EvalResult{}) {
				continue
			}
			if got := Evaluate(rt, a, tier); got != want {
				t.Errorf("%s %s %s dir=%v: Evaluate %+v, want %+v", tier, c.kind, c.path, c.dir, got, want)
			}
			if got := e.Evaluate(a, tier); got != want {
				t.Errorf("%s %s %s dir=%v: Evaluator %+v, want %+v", tier, c.kind, c.path, c.dir, got, want)
			}
		}
	}
}

// TestEvaluateNameEntries is ADR 0043 D1, D2 and D7 in the root model: at tiers cgroup and bpflsm a file a name entry
// covers, existing at compile or not, is refused as a deny_read entry at its own path would refuse it: a read
// read-denied, a modification with the hook's reason (at cgroup a write-open is the listener's read-denied), named
// by the entry's rule (D8); tier landlock keeps the compile-time expansion and allows what its rules allow.
func TestEvaluateNameEntries(t *testing.T) {
	rt := nameTable(backend.TierBPFLSM)
	readDenied := func(rule string) agent.EvalResult { return refuseBy(rule, record.ReasonReadDenied) }
	checkNameCases(t, rt, []nameCase{
		{kind: agent.ActionFSRead, path: "/p/later/.env", cgroup: readDenied(labelEnv), bpflsm: readDenied(labelEnv), landlock: allowBy(ruleP)},
		{kind: agent.ActionFSRead, path: "/p/a/b/.env.local", cgroup: readDenied(labelEnvPfx), bpflsm: readDenied(labelEnvPfx), landlock: allowBy(ruleP)},
		{kind: agent.ActionFSWrite, path: "/p/later/.env.local", cgroup: readDenied(labelEnvPfx),
			bpflsm: refuseBy(labelEnvPfx, record.ReasonWriteOutsideContract), landlock: allowBy(ruleP)},
		{kind: agent.ActionFSDelete, path: "/p/later/.env.local", cgroup: refuseBy(labelEnvPfx, record.ReasonDeleteOutsideContract),
			bpflsm: refuseBy(labelEnvPfx, record.ReasonDeleteOutsideContract), landlock: allowBy(ruleP)},
		// The file's own expansion row refuses first, named by its entry, as before any name entry.
		{kind: agent.ActionFSRead, path: "/p/.env", cgroup: readDenied("fs.deny_read[/p/.env]"), bpflsm: readDenied("fs.deny_read[/p/.env]")},
		{kind: agent.ActionFSRead, path: "/p/cfg/a/b/token.json", cgroup: readDenied(ruleToken), bpflsm: readDenied(ruleToken), landlock: allowBy(ruleP)},
		{kind: agent.ActionFSRead, path: "/p/a/.env.example", cgroup: allowBy(ruleP), bpflsm: allowBy(ruleP), landlock: allowBy(ruleP)},
		{kind: agent.ActionFSWrite, path: "/p/a/.env.example", cgroup: allowBy(ruleP), bpflsm: allowBy(ruleP)},
	})
}

// TestNameEntryDecidesOnlyWhatTheWalkAllows: where the walk refuses (outside every write entry, beneath a deny_read
// directory), the walk's verdict and rule stand and no name entry renames them (ADR 0043 D1).
func TestNameEntryDecidesOnlyWhatTheWalkAllows(t *testing.T) {
	rt := nameTable(backend.TierBPFLSM)
	rt.FS = append(rt.FS, agent.FSRule{Kind: agent.FSDenyRead, Path: "/p/keys", Raw: "keys", Resolved: "/p/keys", Unenforced: true})
	checkNameCases(t, rt, []nameCase{
		{kind: agent.ActionFSRead, path: "/p/keys/.env", cgroup: refuseBy("fs.deny_read[keys]", record.ReasonReadDenied), bpflsm: refuseBy("fs.deny_read[keys]", record.ReasonReadDenied)},
		{kind: agent.ActionFSWrite, path: "/p/keys/.env", bpflsm: refuseBy("fs.deny_read[keys]", record.ReasonWriteOutsideContract)},
	})
	// Outside every write entry, a modification is the walk's refusal: unmatched, not the name entry's.
	rt = nameTable(backend.TierBPFLSM)
	rt.NameDeny = builtInPair("/")
	checkNameCases(t, rt, []nameCase{
		{kind: agent.ActionFSWrite, path: "/q/.env", bpflsm: refuseBy(agent.UnmatchedRule, record.ReasonWriteOutsideContract)},
		{kind: agent.ActionFSRead, path: "/q/.env", bpflsm: refuseBy("fs.deny_read[/**/.env]", record.ReasonReadDenied)},
	})
}

// TestNameEntryIsNearest: an ancestor write entry never reopens a covered name (ADR 0043 D3), the nested /p/src
// included.
func TestNameEntryIsNearest(t *testing.T) {
	checkNameCases(t, nameTable(backend.TierBPFLSM), []nameCase{
		{kind: agent.ActionFSRead, path: "/p/src/.env", cgroup: refuseBy(labelEnv, record.ReasonReadDenied), bpflsm: refuseBy(labelEnv, record.ReasonReadDenied),
			landlock: allowBy("fs.write[/p/src]")},
		{kind: agent.ActionFSWrite, path: "/p/src/deep/.env.prod", bpflsm: refuseBy(labelEnvPfx, record.ReasonWriteOutsideContract)},
	})
}

// TestNameEntryExemptByDeclaredWrite is D3: the top-level write entry at /p/app/.env.test exempts that name in that
// directory from every entry, the built-in prefix row included, and every ASCII spelling of it there; the same name
// elsewhere stays covered.
func TestNameEntryExemptByDeclaredWrite(t *testing.T) {
	checkNameCases(t, nameTable(backend.TierBPFLSM), []nameCase{
		{kind: agent.ActionFSRead, path: "/p/app/.env.test", cgroup: allowBy("fs.write[/p/app/.env.test]"), bpflsm: allowBy("fs.write[/p/app/.env.test]")},
		{kind: agent.ActionFSWrite, path: "/p/app/.env.test", cgroup: allowBy("fs.write[/p/app/.env.test]"), bpflsm: allowBy("fs.write[/p/app/.env.test]")},
		{kind: agent.ActionFSRead, path: "/p/app/.ENV.TEST", cgroup: allowBy(ruleP), bpflsm: allowBy(ruleP)},
		{kind: agent.ActionFSRead, path: "/p/other/.env.test", cgroup: refuseBy(labelEnvPfx, record.ReasonReadDenied), bpflsm: refuseBy(labelEnvPfx, record.ReasonReadDenied)},
	})
}

// TestAskEntryNeverExempts: an fs.ask entry at a covered file does not reopen it (D3: nearest wins at depth 0).
func TestAskEntryNeverExempts(t *testing.T) {
	rt := nameTable(backend.TierBPFLSM)
	rt.FSAsk = []agent.FSRule{{Kind: agent.FSAsk, Path: "/p/x/.env.local", Raw: "x/.env.local", Resolved: "/p/x/.env.local"}}
	checkNameCases(t, rt, []nameCase{
		{kind: agent.ActionFSRead, path: "/p/x/.env.local", cgroup: refuseBy(labelEnvPfx, record.ReasonReadDenied), bpflsm: refuseBy(labelEnvPfx, record.ReasonReadDenied)},
	})
}

// TestNameEntryOutsideScope: a name outside every scope of the entries is decided by the walk alone.
func TestNameEntryOutsideScope(t *testing.T) {
	checkNameCases(t, nameTable(backend.TierBPFLSM), []nameCase{
		{kind: agent.ActionFSRead, path: "/tmp/x/.env", cgroup: allowBy("fs.write[/tmp]"), bpflsm: allowBy("fs.write[/tmp]")},
		{kind: agent.ActionFSWrite, path: "/tmp/x/.env", cgroup: allowBy("fs.write[/tmp]"), bpflsm: allowBy("fs.write[/tmp]")},
		{kind: agent.ActionFSRead, path: "/p/token.json", cgroup: allowBy(ruleP), bpflsm: allowBy(ruleP)},
	})
}

// TestNameEntryDependencyDirectories: a dependency directory between the scope and the file takes it out of
// coverage, compared case-exactly; one that is itself a scope covers its own base (ADR 0043 D4).
func TestNameEntryDependencyDirectories(t *testing.T) {
	rt := nameTable(backend.TierBPFLSM)
	rt.NameDeny = append(rt.NameDeny, agent.NameDenyRule{Literal: "secret.json", Raw: "node_modules/*/secret.json",
		Scopes: []agent.NameScope{{Canonical: "/p/node_modules", Spelling: "/p/node_modules"}}})
	checkNameCases(t, rt, []nameCase{
		{kind: agent.ActionFSRead, path: "/p/node_modules/pkg/.env", bpflsm: allowBy(ruleP), cgroup: allowBy(ruleP)},
		{kind: agent.ActionFSWrite, path: "/p/a/.git/.env.x", bpflsm: allowBy(ruleP)},
		{kind: agent.ActionFSRead, path: "/p/Vendor/.env", bpflsm: refuseBy(labelEnv, record.ReasonReadDenied)},
		{kind: agent.ActionFSRead, path: "/p/node_modules/pkg/secret.json", bpflsm: refuseBy("fs.deny_read[node_modules/*/secret.json]", record.ReasonReadDenied)},
		{kind: agent.ActionFSRead, path: "/p/node_modules/pkg/vendor/secret.json", bpflsm: allowBy(ruleP)},
	})
}

// TestNameEntryFolding: ASCII case folds on the literal part, exceptions compare as the scan spells them (ADR 0043
// implementation note).
func TestNameEntryFolding(t *testing.T) {
	checkNameCases(t, nameTable(backend.TierBPFLSM), []nameCase{
		{kind: agent.ActionFSRead, path: "/p/a/.ENV", bpflsm: refuseBy(labelEnv, record.ReasonReadDenied)},
		{kind: agent.ActionFSRead, path: "/p/a/.Env.Local", bpflsm: refuseBy(labelEnvPfx, record.ReasonReadDenied)},
		{kind: agent.ActionFSRead, path: "/p/a/.env.EXAMPLE", bpflsm: refuseBy(labelEnvPfx, record.ReasonReadDenied)},
		{kind: agent.ActionFSRead, path: "/p/a/.ENV.example", bpflsm: allowBy(ruleP)},
		{kind: agent.ActionFSRead, path: "/p/cfg/TOKEN.JSON", bpflsm: refuseBy(ruleToken, record.ReasonReadDenied)},
	})
}

// TestNameEntryNeverDecidesADirectory: a directory named like a covered file, its creation, listing and removal are
// decided as if no name entry existed (ADR 0043 D1).
func TestNameEntryNeverDecidesADirectory(t *testing.T) {
	checkNameCases(t, nameTable(backend.TierBPFLSM), []nameCase{
		{kind: agent.ActionFSMkdir, path: "/p/a/.env", cgroup: allowBy(ruleP), bpflsm: allowBy(ruleP)},
		{kind: agent.ActionFSRead, path: "/p/a/.env", dir: true, cgroup: allowBy(ruleP), bpflsm: allowBy(ruleP)},
		{kind: agent.ActionFSDelete, path: "/p/a/.env", dir: true, cgroup: allowBy(ruleP), bpflsm: allowBy(ruleP)},
		{kind: agent.ActionFSRead, path: "/p/a/.env/bin/python", cgroup: allowBy(ruleP), bpflsm: allowBy(ruleP)},
	})
}

// TestNameEntryClimbBound: the climb is bounded at agent.MaxWalk levels counted from the file: a covered file 64
// levels below its scope is decided, one 65 below is refused path-unresolved (fail closed), while a nearer entry
// keeps the walk itself resolved (ADR 0043 D4).
func TestNameEntryClimbBound(t *testing.T) {
	rt := nameTable(backend.TierBPFLSM)
	deep := func(n int) string { return "/p/" + strings.Repeat("d/", n-1) }
	near := deep(60)
	rt.FS = append(rt.FS, agent.FSRule{Kind: agent.FSWrite, Path: strings.TrimSuffix(near, "/"), Resolved: strings.TrimSuffix(near, "/"), Raw: "near", Access: agent.AccessWriteSet})
	checkNameCases(t, rt, []nameCase{
		{kind: agent.ActionFSRead, path: deep(64) + ".env", bpflsm: refuseBy(labelEnv, record.ReasonReadDenied), cgroup: refuseBy(labelEnv, record.ReasonReadDenied)},
		{kind: agent.ActionFSRead, path: deep(65) + ".env", bpflsm: refuseBy(agent.UnmatchedRule, record.ReasonPathUnresolved), cgroup: refuseBy(agent.UnmatchedRule, record.ReasonPathUnresolved)},
		{kind: agent.ActionFSRead, path: deep(65) + "plain.txt", bpflsm: allowBy("fs.write[near]")},
	})
}

// TestRenameDirectoryCoverage is ADR 0043 D5: at tiers cgroup and bpflsm a directory rename that takes covered files
// out of coverage (out of every scope, beneath a dependency directory, or to a dependency directory's name) is
// refused, named by the entry that covered the old place; renames within a scope, into coverage, of a scope
// directory itself and of a file are allowed. Tier landlock asks no name entry.
func TestRenameDirectoryCoverage(t *testing.T) {
	rt := nameTable(backend.TierBPFLSM)
	refer := refuseBy(labelEnv, record.ReasonRenameOutsideContract)
	for _, c := range []struct {
		src, dst string
		dir      bool
		want     agent.EvalResult
	}{
		{"/p/sub", "/tmp/sub", true, refer},
		{"/p/sub", "/p/node_modules/sub", true, refer},
		{"/p/sub", "/p/vendor", true, refer},
		{"/p/cfg", "/tmp/cfg", true, refer},
		{"/p/sub", "/p/sub2", true, allowBy(ruleP)},
		{"/p/node_modules/x", "/p/x2", true, allowBy(ruleP)},
		{"/p", "/tmp/p", true, allowBy(ruleP)}, // at cgroup R15d refuses it first: /p holds the deny_read /p/.env
		{"/p/sub", "/tmp/sub", false, allowBy(ruleP)},
	} {
		a := agent.Action{Kind: agent.ActionFSRename, Path: c.src, DestPath: c.dst, Dir: c.dir}
		e := NewEvaluator(rt)
		for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
			want := c.want
			if c.src == "/p" && tier == backend.TierCgroup {
				want = refuseBy("fs.deny_read[/p/.env]", record.ReasonRenameOutsideContract)
			}
			if c.src == "/p" && tier == backend.TierBPFLSM {
				// D5 allows it, and the Landlock floor under the plane refuses it, unmatched: no write entry grants
				// "/" the REFER the rename of /p needs. D5's refusal would name the name entry.
				want = refuseBy(agent.UnmatchedRule, record.ReasonRenameOutsideContract)
			}
			if got := Evaluate(rt, a, tier); got.Verdict != want.Verdict || got.Reason != want.Reason || (got.Verdict == agent.VerdictRefused && got.Rule != want.Rule) {
				t.Errorf("%s rename %s -> %s dir=%v: Evaluate %+v, want %+v", tier, c.src, c.dst, c.dir, got, want)
			}
			if got, ref := e.Evaluate(a, tier), Evaluate(rt, a, tier); got != ref {
				t.Errorf("%s rename %s -> %s: Evaluator %+v, Evaluate %+v", tier, c.src, c.dst, got, ref)
			}
		}
		if got := Evaluate(rt, a, backend.TierLandlock); got.Verdict == agent.VerdictRefused && got.Rule == labelEnv {
			t.Errorf("landlock rename %s -> %s refused by a name entry: %+v", c.src, c.dst, got)
		}
	}
}

// TestLandlockColumnIgnoresNameEntries: tier landlock's answers, and observe's, are the same with and without name
// entries on every generated table and probe (ADR 0043 D7: Landlock cannot express a name).
func TestLandlockColumnIgnoresNameEntries(t *testing.T) {
	n := genNameTables(func(desc string, rt, bare *agent.RuleTable) {
		for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierObserve} {
			for _, p := range nameProbes {
				for _, k := range fsKinds {
					a := agent.Action{Kind: k, Path: p}
					if got, want := Evaluate(rt, a, tier), Evaluate(bare, a, tier); got != want {
						t.Fatalf("%s %s %s %s: with names %+v, without %+v", desc, tier, k, p, got, want)
					}
				}
			}
		}
	})
	if n < 1000 {
		t.Fatalf("only %d tables", n)
	}
}

// TestNameEntriesMonotonic: a name entry never turns a refusal into an allow, in any root tier, on any generated
// table, for any action and probe (ADR 0043: a strengthening).
func TestNameEntriesMonotonic(t *testing.T) {
	n := genNameTables(func(desc string, rt, bare *agent.RuleTable) {
		for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
			for _, p := range nameProbes {
				for _, a := range nameActions(p) {
					if got, was := Evaluate(rt, a, tier), Evaluate(bare, a, tier); was.Verdict == agent.VerdictRefused && got.Verdict == agent.VerdictAllow {
						t.Fatalf("%s %s %+v: a name entry allowed %+v what was refused %+v", desc, tier, a, got, was)
					}
				}
			}
		}
	})
	if n < 1000 {
		t.Fatalf("only %d tables", n)
	}
}

// TestIndexedEvaluatorMatchesReferenceWithNames is TestIndexedEvaluatorMatchesReference over the tables with name
// entries: the indexed Evaluator and the reference Evaluate give one answer, with the object a file or a directory.
func TestIndexedEvaluatorMatchesReferenceWithNames(t *testing.T) {
	// Tiers landlock and observe ask no name entry; TestLandlockColumnIgnoresNameEntries holds them.
	genNameTables(func(desc string, rt, _ *agent.RuleTable) {
		e := NewEvaluator(rt)
		for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
			for _, p := range nameProbes {
				for _, a := range nameActions(p) {
					if got, want := e.Evaluate(a, tier), Evaluate(rt, a, tier); got != want {
						t.Fatalf("%s %s %+v: indexed %+v, reference %+v", desc, tier, a, got, want)
					}
				}
			}
		}
	})
}

// TestIndexedEvaluatorAllocatesNothingWithNames is the query allocation gate with name entries: a covered file
// refused, a miss, an exempt name and a directory rename allocate nothing.
func TestIndexedEvaluatorAllocatesNothingWithNames(t *testing.T) {
	for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		e := NewEvaluator(nameTable(tier))
		for _, a := range []agent.Action{
			{Kind: agent.ActionFSRead, Path: "/p/later/.env.local"}, {Kind: agent.ActionFSWrite, Path: "/p/later/.env"},
			{Kind: agent.ActionFSRead, Path: "/p/src/main.go"}, {Kind: agent.ActionFSRead, Path: "/p/app/.env.test"},
			{Kind: agent.ActionFSRename, Path: "/p/sub", DestPath: "/tmp/sub", Dir: true},
			{Kind: agent.ActionFSRead, Path: "/p/cfg/x/token.json"},
		} {
			if n := testing.AllocsPerRun(100, func() { evaluatorSink = e.Evaluate(a, tier) }); n != 0 {
				t.Errorf("%s %+v: %g allocations", tier, a, n)
			}
		}
	}
}

// BenchmarkEvaluateName is a covered file's refusal and a miss on the indexed Evaluator (ADR 0043 C3: under 1 µs,
// no allocation).
func BenchmarkEvaluateName(b *testing.B) {
	e := NewEvaluator(nameTable(backend.TierBPFLSM))
	actions := []agent.Action{{Kind: agent.ActionFSRead, Path: "/p/later/deep/.env.local"}, {Kind: agent.ActionFSRead, Path: "/p/src/pkg/main.go"}}
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		evaluatorSink = e.Evaluate(actions[i%len(actions)], backend.TierBPFLSM)
	}
}

// fsKinds are the non-rename fs actions.
var fsKinds = []agent.ActionKind{agent.ActionFSRead, agent.ActionFSWrite, agent.ActionFSDelete, agent.ActionFSMkdir}

// nameProbes are planeProbes with the names the generated name dimensions cover, miss and exempt, one through a
// declared symlink (/l) included. The climb's bound is asked by TestPlaneNameClimbBoundMatchesEvaluate, on a table
// whose walk stays within its own bound.
var nameProbes = append(append([]string{}, planeProbes...),
	"/w/.env", "/w/a/.env", "/w/a/.ENV", "/w/a/.env.local", "/w/a/.env.example", "/w/a/.env.EXAMPLE", "/w/a/b/c/.env.test",
	"/w/node_modules/p/.env", "/w/node_modules", "/y/.env", "/x/.env", "/x/q/.env.prod", "/w/a/s.json", "/w/a/b/S.JSON",
	"/w/s.json", "/x/key.pem", "/w/keyring", "/w/a/.env.d", "/l/.env", "/l/b/.env.local")

// nameRenameDests are where a directory probe is moved to.
var nameRenameDests = []string{"/w/sub2", "/y/sub", "/w/node_modules/sub", "/w/vendor", "/w/a/b/x"}

// nameDirProbes are the probes a directory rename is asked of: directories of the generated tree, a dependency
// directory and a directory named like a covered file.
var nameDirProbes = map[string]bool{"/w": true, "/w/a": true, "/w/a/b": true, "/w/a/b/c": true, "/x": true, "/y": true,
	"/w/node_modules": true, "/w/a/.env.d": true, "/l": true}

// nameActions are the actions a name property asks of probe p: each fs kind on p as a file, a read and a delete of p
// as a directory, a file rename to each destination and, for a directory probe, a directory rename to each.
func nameActions(p string) []agent.Action {
	out := make([]agent.Action, 0, len(fsKinds)+2+2*len(nameRenameDests))
	for _, k := range fsKinds {
		out = append(out, agent.Action{Kind: k, Path: p})
	}
	out = append(out, agent.Action{Kind: agent.ActionFSRead, Path: p, Dir: true}, agent.Action{Kind: agent.ActionFSDelete, Path: p, Dir: true})
	for _, dst := range nameRenameDests {
		out = append(out, agent.Action{Kind: agent.ActionFSRename, Path: p, DestPath: dst})
		if nameDirProbes[p] {
			out = append(out, agent.Action{Kind: agent.ActionFSRename, Path: p, DestPath: dst, Dir: true})
		}
	}
	return out
}

// nameDims are the name dimensions a generated table is given: the built-in pair scoped to /w; to /w and /x; a
// declared exact entry scoped to /w/a; a declared prefix entry scoped to /; and the pair with D3's exemption of
// /w/a/.env, its write entry added to the table.
var nameDims = []struct {
	desc   string
	names  []agent.NameDenyRule
	exempt bool
}{
	{"pair:/w", builtInPair("/w"), false},
	{"pair:/w,/x", builtInPair("/w", "/x"), false},
	{"exact:s.json@/w/a", []agent.NameDenyRule{{Literal: "s.json", Raw: "a/*/s.json", Scopes: []agent.NameScope{{Canonical: "/w/a", Spelling: "/w/a"}}}}, false},
	{"prefix:key@/", []agent.NameDenyRule{{Literal: "key", Prefix: true, Raw: "/*/key*", Scopes: []agent.NameScope{{Canonical: "/", Spelling: "/"}}}}, false},
	{"pair:/w+exempt", builtInPair("/w"), true},
}

// genNameTables calls fn with every generated table of at most two fs entries, with no deny_write target and with
// the first deny_write set compile would keep, given each name dimension, and the same table without names.
func genNameTables(fn func(desc string, rt, bare *agent.RuleTable)) int {
	n := 0
	genPlaneTables(func(desc string, bare *agent.RuleTable) {
		if len(bare.FS) > 2 || (len(bare.DenyWrite) > 0 && !strings.HasSuffix(desc, "deny_write:/w/a/b")) {
			return
		}
		for _, d := range nameDims {
			rt := *bare
			rt.NameDeny = d.names
			if d.exempt {
				rt.FS = append(append([]agent.FSRule{}, bare.FS...), agent.FSRule{Kind: agent.FSWrite, Path: "/w/a/.env", Raw: "/w/a/.env", Resolved: "/w/a/.env", Access: agent.AccessWriteSet})
				rt.NameExempt = []agent.NameExemptRule{{Parent: "/w/a", Name: ".env", Write: len(rt.FS) - 1}}
				b := *bare
				b.FS = rt.FS
				n++
				fn(desc+"names:"+d.desc, &rt, &b)
				continue
			}
			n++
			fn(desc+"names:"+d.desc, &rt, bare)
		}
	})
	return n
}

// TestNameRefusalNamesAsD8 is ADR 0043 D8's naming: a refusal of a file with a deny_read entry at its canonical path
// names that entry (the expansion's, which compaction may drop from the plane); any other names the entry's own rule,
// a declared glob's name or the built-in label with the deciding scope's spelling (a scope reached through a symlink
// keeps the spelling compile used).
func TestNameRefusalNamesAsD8(t *testing.T) {
	rt := nameTable(backend.TierBPFLSM)
	rt.NameDeny = append(rt.NameDeny[:1:1], builtInPair("/p")...)
	rt.NameDeny[1].Scopes = []agent.NameScope{{Canonical: "/p", Spelling: "/home/u/link"}}
	n := NewNameIndex(rt)
	m, ok := n.Match("/p/later/.env", false)
	if !ok || m.Unresolved {
		t.Fatalf("Match: %+v %v", m, ok)
	}
	if got := n.Rule(m, -1); got != "fs.deny_read[/home/u/link/**/.env]" {
		t.Errorf("label %q", got)
	}
	if got := n.Rule(m, 4); got != "fs.deny_read[/p/.env]" {
		t.Errorf("with an entry at the path: %q", got)
	}
	if got := newNameIndex(rt).Rule(m, -1); got != "fs.deny_read[/home/u/link/**/.env]" {
		t.Errorf("the reference index names %q", got)
	}
	if m, ok := n.Match("/p/cfg/x/token.json", false); !ok || n.Rule(m, -1) != ruleToken {
		t.Errorf("declared glob: %+v %v", m, ok)
	}
}
