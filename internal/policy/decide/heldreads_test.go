// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// heldTable is a table as compile leaves one with fs.write [/p] and the scan's /p/.env inside it, the built-in
// .env names over /p and the home patterns of /h/.ssh: tier landlock holds its reads (ADR 0069 D1).
func heldTable(mode agent.ReadsMode) *agent.RuleTable {
	env := agent.FSRule{Path: "/p/.env", Resolved: "/p/.env", Kind: agent.FSDenyRead, BuiltIn: true, Unenforced: true}
	secrets := agent.FSRule{Path: "/p/secrets", Resolved: "/p/secrets", Kind: agent.FSDenyRead, Raw: "secrets/", Unenforced: true}
	rt := &agent.RuleTable{Tier: backend.TierLandlock, Reach: []backend.Tier{backend.TierLandlock},
		FS: []agent.FSRule{{Path: "/p", Resolved: "/p", Kind: agent.FSWrite, Raw: "/p"}, env, secrets,
			{Path: "/h/.ssh", Resolved: "/h/.ssh", Kind: agent.FSDenyRead, BuiltIn: true}}}
	scopes := []agent.NameScope{{Canonical: "/p", Spelling: "/p"}}
	rt.Reads = agent.HeldReads{Mode: mode,
		Nested: []agent.NestedRead{{Rule: env.RuleName(), Path: env.Path}, {Rule: secrets.RuleName(), Path: secrets.Path}},
		Patterns: []agent.DenyReadPattern{{Pattern: "/h/.ssh", Rule: "fs.deny_read[/h/.ssh]"},
			{Pattern: "/p/keys/*.pem", Rule: "fs.deny_read[keys/*.pem]"}},
		Names: []agent.NameDenyRule{{Literal: ".env", Scopes: scopes, BuiltIn: true},
			{Literal: ".env.", Prefix: true, Except: []string{".env.example", ".env.sample", ".env.template", ".env.dist"}, Scopes: scopes, BuiltIn: true}},
		Exempt: []agent.NameExemptRule{{Parent: "/p/granted", Name: ".env"}}}
	return rt
}

// TestHeldReadRefusal holds the held-read floor to the objects a deputy can reach (ADR 0069 D3 (a), (c)): a nested
// target and its directory refused by path; a file made later refused by a name rule, folded; the example files, a
// dependency directory's .env and D3's exemption allowed; and an ordinary file allowed. The same answers come with
// and without the supervisor's advisory list.
func TestHeldReadRefusal(t *testing.T) {
	rt := heldTable(agent.ReadsAuto)
	x := NewHeldReadIndex(rt)
	list := NewAdvisoryTablesFor(rt).Resolved
	for _, tc := range []struct {
		path string
		dir  bool
		rule string // "" allowed
	}{
		{"/p/src/a.txt", false, ""},
		{"/p/.env", false, "fs.deny_read[/p/.env]"},
		{"/p/secrets", true, "fs.deny_read[secrets/]"},
		{"/p/secrets/token", false, "fs.deny_read[secrets/]"},
		{"/p/.ENV", false, "fs.deny_read[/p/**/.env]"},
		{"/p/sub/.env.local", false, "fs.deny_read[/p/**/.env.*]"},
		{"/p/sub/.Env.Production", false, "fs.deny_read[/p/**/.env.*]"},
		{"/p/.env.example", false, ""},
		{"/p/node_modules/x/.env", false, ""},
		{"/p/granted/.env", false, ""},
		{"/p/.env.d", true, ""}, // a directory is no name entry's (ADR 0043 D1)
		{"/h/.ssh/id_new", false, "fs.deny_read[/h/.ssh]"},
		{"/h/.SSH/id_new", false, "fs.deny_read[/h/.ssh]"},
		{"/p/keys/new.pem", false, "fs.deny_read[keys/*.pem]"},
		{"/p/KEYS/new.PEM", false, "fs.deny_read[keys/*.pem]"},
		{"/p/keys/new.txt", false, ""},
		{"/elsewhere/.env", false, ""},
	} {
		for _, l := range []*AdvisoryList{nil, list} {
			rule, refused := x.Refusal(l, tc.path, tc.dir)
			if refused != (tc.rule != "") || rule != tc.rule {
				t.Errorf("%s (list %v): refused %v rule %q, want %q", tc.path, l != nil, refused, rule, tc.rule)
			}
		}
	}
}

// TestHeldReadNearerWriteReopens holds the name rules of D3 (c) to D3 (a)'s nearest entry (SEMANTICS §2): a write
// entry nested inside a deny_read name rule's tree reopens its own subtree, whether the rule is a built-in home path
// (a literal pattern) or a declared glob matching an ancestor, so holding reads for a .env elsewhere takes away no
// read the contract granted; what lies beside the write entry, or a pattern matching the object itself beneath it,
// is still refused.
func TestHeldReadNearerWriteReopens(t *testing.T) {
	rt := heldTable(agent.ReadsAuto)
	rt.FS = append(rt.FS,
		agent.FSRule{Path: "/h/.ssh/out", Resolved: "/h/.ssh/out", Kind: agent.FSWrite, Raw: "~/.ssh/out/"},
		agent.FSRule{Path: "/p/vault1/out", Resolved: "/p/vault1/out", Kind: agent.FSWrite, Raw: "vault1/out/"})
	rt.Reads.Patterns = append(rt.Reads.Patterns, agent.DenyReadPattern{Pattern: "/p/vault*", Rule: "fs.deny_read[vault*]"},
		agent.DenyReadPattern{Pattern: "/p/vault1/out/*.pem", Rule: "fs.deny_read[vault1/out/*.pem]"})
	x := NewHeldReadIndex(rt)
	list := NewAdvisoryTablesFor(rt).Resolved
	for _, tc := range []struct {
		path string
		dir  bool
		rule string // "" allowed
	}{
		{"/h/.ssh/out", true, ""},
		{"/h/.ssh/out/x", false, ""},
		{"/h/.ssh/out/deep/y", false, ""},
		{"/h/.ssh/id_ed25519", false, "fs.deny_read[/h/.ssh]"},
		{"/h/.ssh/outside", false, "fs.deny_read[/h/.ssh]"},
		{"/h/.SSH/out/x", false, "fs.deny_read[/h/.ssh]"}, // another directory on a case-sensitive file system
		{"/p/vault1/out/x", false, ""},
		{"/p/vault1/y", false, "fs.deny_read[vault*]"},
		{"/p/vault1/out/k.pem", false, "fs.deny_read[vault1/out/*.pem]"},
	} {
		for _, l := range []*AdvisoryList{nil, list} {
			rule, refused := x.Refusal(l, tc.path, tc.dir)
			if refused != (tc.rule != "") || rule != tc.rule {
				t.Errorf("%s (list %v): refused %v rule %q, want %q", tc.path, l != nil, refused, rule, tc.rule)
			}
		}
	}
	read := agent.Action{Kind: agent.ActionFSRead, Path: "/h/.ssh/out/x"}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		rt.Reads.Mode = agent.ReadsHeld
		if got := Evaluate(rt, read, tier); got.Verdict != agent.VerdictAllow {
			t.Errorf("a read the nearer write entry grants at %s under fs.reads: held: %+v", tier, got)
		}
	}
}

// TestAdvisoryOPathOpenUnderADenyRead: at every tier an O_PATH open beneath a deny_read, nested or enforced, is
// allowed by the entry with the O_PATH marker, since no file_open hook runs for one, so neither Landlock nor tier 2's
// fanotify listener nor the decision plane refuses it; the same path opened to read keeps its
// old answer.
func TestAdvisoryOPathOpenUnderADenyRead(t *testing.T) {
	rt := heldTable(agent.ReadsAuto)
	list := NewAdvisoryTablesFor(rt).Resolved
	for _, tc := range []struct {
		path    string
		flags   int
		tier    backend.Tier
		rule    string
		verdict record.Verdict
	}{
		{"/p/secrets", OPath, backend.TierLandlock, "fs.deny_read[secrets/]" + agent.OPathSuffix, record.VerdictAllow},
		{"/h/.ssh", OPath, backend.TierLandlock, "fs.deny_read[/h/.ssh]" + agent.OPathSuffix, record.VerdictAllow},
		{"/h/.ssh/id", OPath | 1, backend.TierLandlock, "fs.deny_read[/h/.ssh]" + agent.OPathSuffix, record.VerdictAllow},
		{"/h/.ssh/id", 0, backend.TierLandlock, "fs.deny_read[/h/.ssh]", record.VerdictRefused},
		{"/p/secrets/k", 0, backend.TierLandlock, "fs.deny_read[secrets/]" + agent.UnenforcedSuffix, record.VerdictAllow},
		{"/h/.ssh/id", OPath, backend.TierBPFLSM, "fs.deny_read[/h/.ssh]" + agent.OPathSuffix, record.VerdictAllow},
		{"/h/.ssh/id", OPath, backend.TierCgroup, "fs.deny_read[/h/.ssh]" + agent.OPathSuffix, record.VerdictAllow},
		{"/p/secrets/k", OPath, backend.TierCgroup, "fs.deny_read[secrets/]" + agent.OPathSuffix, record.VerdictAllow},
		{"/p/secrets", OPath, backend.TierBPFLSM, "fs.deny_read[secrets/]" + agent.OPathSuffix, record.VerdictAllow},
		{"/h/.ssh/id", 0, backend.TierBPFLSM, "fs.deny_read[/h/.ssh]", record.VerdictRefused},
		{"/h/.ssh/id", 0, backend.TierCgroup, "fs.deny_read[/h/.ssh]", record.VerdictRefused},
		{"/p/secrets/k", 0, backend.TierCgroup, "fs.deny_read[secrets/]", record.VerdictRefused},
	} {
		rt.Tier = tc.tier
		rule, verdict, _ := AdvisoryFS(rt, list, tc.path, record.FSOpen, tc.flags, false)
		if rule != tc.rule || verdict != tc.verdict {
			t.Errorf("open %s flags %#x at %s: %s by %q, want %s by %q", tc.path, tc.flags, tc.tier, verdict, rule, tc.verdict, tc.rule)
		}
	}
}

// TestEvaluateHeldReads holds compile --test's model to held reads (ADR 0069 D1, ADR 0028): at tier landlock a
// nested deny_read and a .env made later are refused while reads are held, allowed as unenforced under direct; no
// records-only run holds; and the ruleset alone (LandlockRuleset) still allows the nested target, as the Landlock
// ruleset does.
func TestEvaluateHeldReads(t *testing.T) {
	read := func(p string) agent.Action { return agent.Action{Kind: agent.ActionFSRead, Path: p} }
	for _, tc := range []struct {
		mode    agent.ReadsMode
		tier    backend.Tier
		path    string
		verdict agent.Verdict
	}{
		{agent.ReadsAuto, backend.TierLandlock, "/p/.env", agent.VerdictRefused},
		{agent.ReadsAuto, backend.TierLandlock, "/p/sub/.env.local", agent.VerdictRefused},
		{agent.ReadsAuto, backend.TierLandlock, "/p/src/a.txt", agent.VerdictAllow},
		{agent.ReadsDirect, backend.TierLandlock, "/p/.env", agent.VerdictAllow},
		{agent.ReadsDirect, backend.TierLandlock, "/p/sub/.env.local", agent.VerdictAllow},
		{agent.ReadsHeld, backend.TierCgroup, "/p/sub/.env.local", agent.VerdictRefused},
		{agent.ReadsAuto, backend.TierCgroup, "/p/sub/.env.local", agent.VerdictAllow},
		{agent.ReadsHeld, backend.TierObserve, "/p/.env", agent.VerdictAllow},
	} {
		got := Evaluate(heldTable(tc.mode), read(tc.path), tc.tier)
		if got.Verdict != tc.verdict {
			t.Errorf("%s at %s, fs.reads %s: %+v, want %s", tc.path, tc.tier, tc.mode, got, tc.verdict)
		}
		if tc.verdict == agent.VerdictRefused && got.Reason != record.ReasonReadDenied {
			t.Errorf("%s at %s: reason %q", tc.path, tc.tier, got.Reason)
		}
	}
	if got := LandlockRuleset(heldTable(agent.ReadsHeld), read("/p/.env")); got.Verdict != agent.VerdictAllow {
		t.Errorf("the ruleset alone refuses a nested target: %+v", got)
	}
}

func TestHeldReadRefusalByRetainedIdentity(t *testing.T) {
	rt := &agent.RuleTable{}
	id := HeldReadID{Dev: 7, Ino: 42}
	x := NewHeldReadIndex(rt, HeldReadPin{ID: id, Rule: "fs.deny_read[secret]"})
	for _, path := range []string{"/write/alias", ""} {
		if rule, refused := x.RefusalOn(nil, path, false, id); !refused || rule != "fs.deny_read[secret]" {
			t.Fatalf("%q: refusal %t by %q, want the retained identity", path, refused, rule)
		}
	}
	for _, other := range []HeldReadID{{Dev: 8, Ino: 42}, {Dev: 7, Ino: 43}, {}} {
		if _, refused := x.RefusalOn(nil, "/write/alias", false, other); refused {
			t.Fatalf("unrelated object %+v refused", other)
		}
	}
}
