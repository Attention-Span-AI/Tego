// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// evalContract declares one entry of every shape the evaluator resolves: a
// write directory, a deny_read inside it (unenforceable in tier 1), a
// deny_read outside it (enforced in every tier), a watch directory outside
// every grant, a watch directory nested inside the write entry (the finer
// recording a natural contract asks for), host, cidr and unix network
// entries, and two exec entries.
const evalContract = `version: 0
name: evaluator
command: ["python", "agent.py"]
fs:
  write: ["out/"]
  deny_read: ["out/keys/", "secrets/"]
  watch: ["config/", "out/logs/"]
net:
  allow: ["mcp.internal:8080", "10.0.0.0/8:443", "unix:/run/pg.sock", "unix:@bus"]
exec:
  allow: ["python", "tool.sh"]
`

// evalFixture compiles evalContract against the shared test fixture and adds
// the paths the deny_read-inside-a-write-entry case needs.
func evalFixture(t *testing.T) (*fixture, *RuleTable) {
	t.Helper()
	f := newFixture(t)
	if err := os.MkdirAll(filepath.Join(f.project, "out", "keys"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.project, "out", "logs"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(f.project, "out", "keys", "id_ed25519"), "key", 0o600)
	f.file(filepath.Join(f.project, "script.sh"), "#!/usr/bin/env python\n", 0o755)
	rt, _ := f.compile(f.load(evalContract))
	return f, rt
}

// agent-contract.md E35: an unknown fs kind (fs_chmod) is invalid, never a refusal.
func TestEvaluateFS(t *testing.T) {
	f, rt := evalFixture(t)
	p := func(rel string) string { return filepath.Join(f.project, rel) }
	cases := []struct {
		name     string
		action   Action
		tier     backend.Tier
		verdict  Verdict
		rule     string
		reason   record.Reason
		ruleHint string
	}{
		{name: "write inside the write entry", action: Action{Kind: ActionFSWrite, Path: p("out/report.md")},
			tier: backend.TierCgroup, verdict: VerdictAllow, rule: "fs.write[out/]"},
		{name: "write inside the write entry, tier 1", action: Action{Kind: ActionFSWrite, Path: p("out/report.md")},
			tier: backend.TierLandlock, verdict: VerdictAllow, rule: "fs.write[out/]"},
		{name: "write outside every entry", action: Action{Kind: ActionFSWrite, Path: p("notes.md")},
			tier: backend.TierCgroup, verdict: VerdictRefused, rule: UnmatchedRule, reason: record.ReasonWriteOutsideContract},
		{name: "read outside every entry is allowed", action: Action{Kind: ActionFSRead, Path: p("notes.md")},
			tier: backend.TierCgroup, verdict: VerdictAllow, rule: UnmatchedRule},
		{name: "read under an enforced deny_read, root tier", action: Action{Kind: ActionFSRead, Path: p("secrets/key.pem")},
			tier: backend.TierBPFLSM, verdict: VerdictRefused, rule: "fs.deny_read[secrets/]", reason: record.ReasonReadDenied},
		{name: "read under an enforced deny_read, tier 1", action: Action{Kind: ActionFSRead, Path: p("secrets/key.pem")},
			tier: backend.TierLandlock, verdict: VerdictRefused, rule: "fs.deny_read[secrets/]", reason: record.ReasonReadDenied},
		// The root tiers' nearest-ancestor walk refuses this read; tier 1
		// cannot deny beneath an allow and says so in the rule name.
		{name: "deny_read under a write entry, root tier", action: Action{Kind: ActionFSRead, Path: p("out/keys/id_ed25519")},
			tier: backend.TierCgroup, verdict: VerdictRefused, rule: "fs.deny_read[out/keys/]", reason: record.ReasonReadDenied},
		{name: "deny_read under a write entry, tier 1", action: Action{Kind: ActionFSRead, Path: p("out/keys/id_ed25519")},
			tier: backend.TierLandlock, verdict: VerdictRefused, rule: "fs.deny_read[out/keys/]", reason: record.ReasonReadDenied}, // held reads (ADR 0069)
		// The same split for a mutation: nearest-wins refuses, the union grants.
		{name: "write under a deny_read inside a write entry, tier 3", action: Action{Kind: ActionFSWrite, Path: p("out/keys/new")},
			tier: backend.TierBPFLSM, verdict: VerdictRefused, rule: "fs.deny_read[out/keys/]", reason: record.ReasonWriteOutsideContract},
		// Tier 2's inherited Landlock ruleset grants the write, but a write is an open and its fanotify listener,
		// which cannot see the access mode, refuses every open under the deny_read.
		{name: "write under a deny_read inside a write entry, tier 2", action: Action{Kind: ActionFSWrite, Path: p("out/keys/new")},
			tier: backend.TierCgroup, verdict: VerdictRefused, rule: "fs.deny_read[out/keys/]", reason: record.ReasonReadDenied},
		// The listener fallback's supervisor applies the root mutation decision
		// even where the inherited Landlock union would grant it (ADR 0028 S3).
		{name: "mkdir under a deny_read inside a write entry, tier 2", action: Action{Kind: ActionFSMkdir, Path: p("out/keys/d")},
			tier: backend.TierCgroup, verdict: VerdictRefused, rule: "fs.deny_read[out/keys/]", reason: record.ReasonMkdirOutsideContract},
		// ...and a rename that carries a file out of that deny_read is refused, by the supervisor (R15d).
		{name: "rename out of a deny_read inside a write entry, tier 2", action: Action{Kind: ActionFSRename, Path: p("out/keys/k"), DestPath: p("out/k")},
			tier: backend.TierCgroup, verdict: VerdictRefused, rule: "fs.deny_read[out/keys/]", reason: record.ReasonRenameOutsideContract},
		{name: "rename of the directory above a deny_read, tier 2", action: Action{Kind: ActionFSRename, Path: p("out"), DestPath: p("out2")},
			tier: backend.TierCgroup, verdict: VerdictRefused, rule: "fs.deny_read[out/keys/]", reason: record.ReasonRenameOutsideContract},
		{name: "write under a deny_read inside a write entry, tier 1", action: Action{Kind: ActionFSWrite, Path: p("out/keys/new")},
			tier: backend.TierLandlock, verdict: VerdictAllow, rule: "fs.write[out/]"},
		{name: "delete outside", action: Action{Kind: ActionFSDelete, Path: p("config/app.toml")},
			tier: backend.TierCgroup, verdict: VerdictRefused, rule: "fs.watch[config/]", reason: record.ReasonDeleteOutsideContract},
		{name: "read under a watch entry", action: Action{Kind: ActionFSRead, Path: p("config/app.toml")},
			tier: backend.TierCgroup, verdict: VerdictAllow, rule: "fs.watch[config/]"},
		// SEMANTICS §7: a watch entry selects what is recorded, it grants and withholds
		// nothing. Nested inside a write entry it must not withdraw the grant — no tier
		// refuses these, and internal/runtime/supervisor drops watch entries from its own
		// nearest-wins table for exactly this reason.
		{name: "write under a watch entry nested in a write entry, root tier", action: Action{Kind: ActionFSWrite, Path: p("out/logs/app.log")},
			tier: backend.TierCgroup, verdict: VerdictAllow, rule: "fs.write[out/]"},
		{name: "write under a watch entry nested in a write entry, tier 1", action: Action{Kind: ActionFSWrite, Path: p("out/logs/app.log")},
			tier: backend.TierLandlock, verdict: VerdictAllow, rule: "fs.write[out/]"},
		{name: "mkdir under a nested watch entry, root tier", action: Action{Kind: ActionFSMkdir, Path: p("out/logs/2026")},
			tier: backend.TierBPFLSM, verdict: VerdictAllow, rule: "fs.write[out/]"},
		{name: "delete under a nested watch entry, root tier", action: Action{Kind: ActionFSDelete, Path: p("out/logs/old.log")},
			tier: backend.TierCgroup, verdict: VerdictAllow, rule: "fs.write[out/]"},
		// The watch entry still names a read, which is how §7 keeps it an individual event.
		{name: "read under a nested watch entry is attributed to it", action: Action{Kind: ActionFSRead, Path: p("out/logs/app.log")},
			tier: backend.TierCgroup, verdict: VerdictAllow, rule: "fs.watch[out/logs/]"},
		{name: "mkdir inside the write entry", action: Action{Kind: ActionFSMkdir, Path: p("out/sub")},
			tier: backend.TierCgroup, verdict: VerdictAllow, rule: "fs.write[out/]"},
		{name: "mkdir inside the write entry, tier 1", action: Action{Kind: ActionFSMkdir, Path: p("out/sub")},
			tier: backend.TierLandlock, verdict: VerdictAllow, rule: "fs.write[out/]"},
		{name: "rename within the write entry", action: Action{Kind: ActionFSRename, Path: p("out/a"), DestPath: p("out/b")},
			tier: backend.TierCgroup, verdict: VerdictAllow, rule: "fs.write[out/]"},
		{name: "rename escaping the write entry", action: Action{Kind: ActionFSRename, Path: p("out/a"), DestPath: p("notes.md")},
			tier: backend.TierCgroup, verdict: VerdictRefused, rule: UnmatchedRule, reason: record.ReasonRenameOutsideContract},
		{name: "rename into a deny_read", action: Action{Kind: ActionFSRename, Path: p("out/a"), DestPath: p("secrets/a")},
			tier: backend.TierCgroup, verdict: VerdictRefused, rule: "fs.deny_read[secrets/]", reason: record.ReasonRenameOutsideContract},
		{name: "an exhausted walk is path-unresolved", action: Action{Kind: ActionFSRead, Path: "/" + strings.Repeat("d/", MaxWalk+2) + "f"},
			tier: backend.TierCgroup, verdict: VerdictRefused, rule: UnmatchedRule, reason: record.ReasonPathUnresolved},
		{name: "observe mode enforces nothing", action: Action{Kind: ActionFSWrite, Path: p("notes.md")},
			tier: backend.TierObserve, verdict: VerdictAllow, rule: UnmatchedRule},
		{name: "an action with no path is invalid, never an error", action: Action{Kind: ActionFSWrite},
			tier: backend.TierCgroup, verdict: VerdictRefused, rule: InvalidActionRule},
		{name: "a rename with no destination is invalid", action: Action{Kind: ActionFSRename, Path: p("out/a")},
			tier: backend.TierCgroup, verdict: VerdictRefused, rule: InvalidActionRule},
		{name: "an unknown kind is invalid", action: Action{Kind: "fs_chmod", Path: p("out/a")},
			tier: backend.TierCgroup, verdict: VerdictRefused, rule: InvalidActionRule},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rt.Evaluate(tc.action, tc.tier)
			if got.Verdict != tc.verdict || got.Rule != tc.rule || got.Reason != tc.reason {
				t.Errorf("got %+v, want verdict %q rule %q reason %q", got, tc.verdict, tc.rule, tc.reason)
			}
		})
	}
}

func TestEvaluateExec(t *testing.T) {
	f, rt := evalFixture(t)
	python := filepath.Join(f.bin, "python")
	cases := []struct {
		name    string
		action  Action
		tier    backend.Tier
		verdict Verdict
		rule    string
	}{
		{name: "declared basename", action: Action{Kind: ActionExec, Path: python},
			tier: backend.TierCgroup, verdict: VerdictAllow, rule: "exec[python]"},
		{name: "declared basename by argv", action: Action{Kind: ActionExec, Argv: []string{"python", "agent.py"}},
			tier: backend.TierLandlock, verdict: VerdictAllow, rule: "exec[python]"},
		{name: "undeclared binary", action: Action{Kind: ActionExec, Path: "/usr/bin/curl"},
			tier: backend.TierCgroup, verdict: VerdictRefused, rule: UnmatchedRule},
		// SEMANTICS §4: tier 3's hook passes the #! stage and decides on the
		// interpreter; Landlock needs EXECUTE on the script itself, and tiers 2
		// and 3 install the same Landlock ruleset, so every tier refuses it
		// (the 2026-09-30 note, decide.ScriptFloor).
		{name: "unlisted script with a declared interpreter, tier 3",
			action: Action{Kind: ActionExec, Path: filepath.Join(f.project, "script.sh"), Script: python},
			tier:   backend.TierBPFLSM, verdict: VerdictRefused, rule: UnmatchedRule},
		{name: "unlisted script with a declared interpreter, tier 2",
			action: Action{Kind: ActionExec, Path: filepath.Join(f.project, "script.sh"), Script: python},
			tier:   backend.TierCgroup, verdict: VerdictRefused, rule: UnmatchedRule},
		{name: "unlisted script with a declared interpreter, tier 1",
			action: Action{Kind: ActionExec, Path: filepath.Join(f.project, "script.sh"), Script: python},
			tier:   backend.TierLandlock, verdict: VerdictRefused, rule: UnmatchedRule},
		{name: "declared script, tier 1",
			action: Action{Kind: ActionExec, Path: filepath.Join(f.bin, "tool.sh"), Script: python},
			tier:   backend.TierLandlock, verdict: VerdictAllow, rule: "exec[python]"},
		{name: "observe mode enforces nothing", action: Action{Kind: ActionExec, Path: "/usr/bin/curl"},
			tier: backend.TierObserve, verdict: VerdictAllow, rule: UnmatchedRule},
		{name: "an exec with nothing to run is invalid", action: Action{Kind: ActionExec},
			tier: backend.TierCgroup, verdict: VerdictRefused, rule: InvalidActionRule},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rt.Evaluate(tc.action, tc.tier)
			if got.Verdict != tc.verdict || got.Rule != tc.rule {
				t.Errorf("got %+v, want verdict %q rule %q", got, tc.verdict, tc.rule)
			}
			if tc.verdict == VerdictRefused && tc.rule != InvalidActionRule && got.Reason != record.ReasonExecNotAllowed {
				t.Errorf("reason %q, want exec-not-allowed", got.Reason)
			}
		})
	}
}

func TestEvaluateNet(t *testing.T) {
	_, rt := evalFixture(t)
	cases := []struct {
		name    string
		action  Action
		verdict Verdict
		rule    string
	}{
		{name: "declared host and port", action: Action{Kind: ActionNetConnect, Host: "mcp.internal", Port: 8080},
			verdict: VerdictAllow, rule: "net[mcp.internal:8080]"},
		{name: "the address the host resolved to", action: Action{Kind: ActionNetConnect, Host: "10.0.0.5", Port: 8080},
			verdict: VerdictAllow, rule: "net[mcp.internal:8080]"},
		{name: "another port on a declared host", action: Action{Kind: ActionNetConnect, Host: "mcp.internal", Port: 9090},
			verdict: VerdictRefused, rule: UnmatchedRule},
		{name: "inside a declared cidr", action: Action{Kind: ActionNetConnect, Host: "10.1.2.3", Port: 443},
			verdict: VerdictAllow, rule: "net[10.0.0.0/8:443]"},
		{name: "outside every declared cidr", action: Action{Kind: ActionNetConnect, Host: "8.8.8.8", Port: 443},
			verdict: VerdictRefused, rule: UnmatchedRule},
		{name: "undeclared host", action: Action{Kind: ActionNetConnect, Host: "api.example.com", Port: 443},
			verdict: VerdictRefused, rule: UnmatchedRule},
		{name: "declared unix socket", action: Action{Kind: ActionNetConnect, Path: "unix:/run/pg.sock"},
			verdict: VerdictAllow, rule: "net[unix:/run/pg.sock]"},
		{name: "declared abstract socket", action: Action{Kind: ActionNetConnect, Path: "@bus", Proto: "unix"},
			verdict: VerdictAllow, rule: "net[unix:@bus]"},
		{name: "undeclared unix socket", action: Action{Kind: ActionNetConnect, Path: "unix:/run/other.sock"},
			verdict: VerdictRefused, rule: UnmatchedRule},
		// A host entry compiles to ProtoInet: it covers the TCP connect and
		// the UDP destination alike (SEMANTICS §5).
		{name: "udp to a host entry", action: Action{Kind: ActionNetConnect, Host: "mcp.internal", Port: 8080, Proto: "udp"},
			verdict: VerdictAllow, rule: "net[mcp.internal:8080]"},
		{name: "a connect with no destination is invalid", action: Action{Kind: ActionNetConnect},
			verdict: VerdictRefused, rule: InvalidActionRule},
	}
	for _, tc := range cases {
		for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
			t.Run(tc.name+"/"+string(tier), func(t *testing.T) {
				// Net verdicts are the same in every enforcing tier in P0.
				got := rt.Evaluate(tc.action, tier)
				if got.Verdict != tc.verdict || got.Rule != tc.rule {
					t.Errorf("got %+v, want verdict %q rule %q", got, tc.verdict, tc.rule)
				}
			})
		}
	}
}

// TestEvaluateOfflineHost covers E18/E19: a table compiled offline carries no
// addresses, so a literal address a host entry might have covered is reported
// as unresolved rather than as a plain miss.
func TestEvaluateOfflineHost(t *testing.T) {
	f := newFixture(t)
	f.resolver.table = nil // no answers: every host is unresolvable
	rt, _ := f.compile(f.load(`version: 0
name: evaluator
command: ["python", "agent.py"]
net:
  allow: ["mcp.internal:8080"]
`), Offline())
	got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: "10.0.0.5", Port: 8080}, backend.TierCgroup)
	if got.Verdict != VerdictRefused || got.Rule != UnresolvedRule {
		t.Errorf("got %+v, want refused via %q", got, UnresolvedRule)
	}
	if got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: "mcp.internal", Port: 8080}, backend.TierCgroup); got.Verdict != VerdictAllow {
		t.Errorf("the entry itself: got %+v, want allow", got)
	}
}

// TestEvaluateTierFallback covers R33: an empty or unknown tier falls back to
// the tier the table was compiled for, never to a probe of this machine.
func TestEvaluateTierFallback(t *testing.T) {
	f, rt := evalFixture(t)
	path := filepath.Join(f.project, "out", "keys", "id_ed25519")
	if rt.Tier != backend.TierLandlock && rt.Tier != backend.TierCgroup && rt.Tier != backend.TierBPFLSM {
		t.Fatalf("compiled tier %q", rt.Tier)
	}
	want := rt.Evaluate(Action{Kind: ActionFSRead, Path: path}, rt.Tier)
	for _, tier := range []backend.Tier{"", backend.TierAuto, "nonsense"} {
		if got := rt.Evaluate(Action{Kind: ActionFSRead, Path: path}, tier); got != want {
			t.Errorf("tier %q: got %+v, want %+v", tier, got, want)
		}
	}
}

// BenchmarkEvaluate guards the budgeted path: one `compile --test` row is a
// bounded scan of the rule table plus the rule name it reports, with no
// per-entry allocation.
func BenchmarkEvaluate(b *testing.B) {
	rt := &RuleTable{Tier: backend.TierCgroup, FS: []FSRule{
		{Path: "/work/out", Kind: FSWrite, Access: AccessWriteSet, Raw: "out/"},
		{Path: "/work/out/keys", Kind: FSDenyRead, Raw: "out/keys/"},
		{Path: "/work/config", Kind: FSWatch, Raw: "config/"},
	}}
	a := Action{Kind: ActionFSWrite, Path: "/work/out/deep/report.md"}
	b.ReportAllocs()
	for b.Loop() {
		if rt.Evaluate(a, backend.TierCgroup).Verdict != VerdictAllow {
			b.Fatal("unexpected verdict")
		}
	}
}
