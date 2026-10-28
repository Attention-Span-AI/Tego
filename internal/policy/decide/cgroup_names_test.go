// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestListenerDecidesTheUnlinkedSpelling is ADR 0043 C0: the path the listener reads back from an event's descriptor
// ends in " (deleted)" once the file was unlinked or renamed over while the open waited, and is decided under that
// spelling and the one without the suffix, refused when either is. The table walk (Evaluate's tier-2 column, the
// supervisor's advisory write-open) and its index answer the same.
func TestListenerDecidesTheUnlinkedSpelling(t *testing.T) {
	t.Parallel()
	rt := &agent.RuleTable{Tier: backend.TierCgroup, FS: []agent.FSRule{
		{Kind: agent.FSWrite, Path: "/p", Resolved: "/p", Raw: "/p", Access: agent.AccessWriteSet},
		{Kind: agent.FSDenyRead, Path: "/p/.secret", Resolved: "/p/.secret", Raw: "/p/.secret"},
		{Kind: agent.FSDenyRead, Path: "/p/keys", Resolved: "/p/keys", Raw: "/p/keys"},
	}}
	deny, readable, names := listenerIndexes(rt)
	ix := NewFSIndex(rt)
	for _, tc := range []struct {
		path string
		rule string // "" for allowed
	}{
		{"/p/.secret (deleted)", "fs.deny_read[/p/.secret]"},
		{"/p/.secret", "fs.deny_read[/p/.secret]"},
		{"/p/keys/id (deleted)", "fs.deny_read[/p/keys]"},
		{"/p/other (deleted)", ""},
		{"/p/other", ""},
		// A real name that ends in the suffix is decided under the shorter spelling too: the stricter side.
		{"/p/.secret (deleted) (deleted)", ""},
		{" (deleted)", ""},
	} {
		i, refused := ListenerOpen(&deny, &readable, tc.path)
		got := ""
		if refused {
			got = names[i]
		}
		if got != tc.rule {
			t.Errorf("ListenerOpen(%q) = %q, want %q", tc.path, got, tc.rule)
		}
		r, walked := ListenerOpenRefused(rt, tc.path)
		if walked != (tc.rule != "") || (walked && r.RuleName() != tc.rule) {
			t.Errorf("ListenerOpenRefused(%q) = %v %s, want %q", tc.path, walked, r.RuleName(), tc.rule)
		}
		r, indexed := ix.ListenerOpenRefused(tc.path)
		if indexed != (tc.rule != "") || (indexed && r.RuleName() != tc.rule) {
			t.Errorf("FSIndex.ListenerOpenRefused(%q) = %v %s, want %q", tc.path, indexed, r.RuleName(), tc.rule)
		}
	}
	// An exec is allowed only when both spellings are: a file entry never covers the suffixed spelling.
	x := NewPathIndex([]IndexEntry{{Path: "/usr/bin/git"}, {Path: "/opt/tools", Dir: true}})
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/usr/bin/git (deleted)", false},
		{"/opt/tools/rg (deleted)", true},
		{"/opt/x (deleted)", false},
	} {
		if got := ListenerExec(false, &x, tc.path); got != tc.want {
			t.Errorf("ListenerExec(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestListenerRefusesNameMatchedOpen is ADR 0043 D7's fallback: tier 2's listener refuses an open of a file a name
// entry covers beneath its scope, read-denied and named per D8, also under its unlinked spelling, and a climb that
// cannot decide refuses path-unresolved; an exempt name, an exception, a dependency directory and a path outside
// every scope are allowed.
func TestListenerRefusesNameMatchedOpen(t *testing.T) {
	n := NewNameIndex(nameTable(backend.TierCgroup))
	deep := "/p" + repeatPath("/d", agent.MaxWalk+1) + "/.env"
	for _, tc := range []struct {
		path   string
		rule   string
		reason record.Reason
	}{
		{"/p/later/.env.local", labelEnvPfx, record.ReasonReadDenied},
		{"/p/src/.ENV", labelEnv, record.ReasonReadDenied},
		{"/p/later/.env.local (deleted)", labelEnvPfx, record.ReasonReadDenied},
		{"/p/cfg/a/token.json", ruleToken, record.ReasonReadDenied},
		{deep, agent.UnmatchedRule, record.ReasonPathUnresolved},
		{"/p/x/.env.example", "", ""},
		{"/p/app/.env.test", "", ""},
		{"/p/node_modules/m/.env", "", ""},
		{"/q/.env", "", ""},
		{"/p/later/.envrc", "", ""},
	} {
		rule, reason, refused := ListenerOpenName(n, tc.path)
		if refused != (tc.rule != "") || rule != tc.rule || reason != tc.reason {
			t.Errorf("ListenerOpenName(%s) = %v %q %q, want %q %q", tc.path, refused, rule, reason, tc.rule, tc.reason)
		}
	}
	if _, _, refused := ListenerOpenName(nil, "/p/.env"); refused {
		t.Error("a nil index refused")
	}
}

// TestListenerOpenNameMatchesEvaluate holds the listener's open decision, its path half (ListenerOpen) and its
// name half (ListenerOpenName) together, to Evaluate's tier-2 write-open column on every generated name table: the
// listener sees no access mode, so whatever it refuses Evaluate refuses for a write-open with the same rule and
// reason, and every read-denied refusal Evaluate makes there is the listener's.
func TestListenerOpenNameMatchesEvaluate(t *testing.T) {
	bad := 0
	genNameTables(func(desc string, rt, _ *agent.RuleTable) {
		rt.Tier = backend.TierCgroup
		deny, readable, names := listenerIndexes(rt)
		n := NewNameIndex(rt)
		for _, p := range nameProbes {
			// The listener reads back the canonical path the kernel opened (pathVerdict).
			c := Canonical(rt, p)
			var got agent.EvalResult
			if i, refused := ListenerOpen(&deny, &readable, c); refused {
				got = refuseBy(names[i], record.ReasonReadDenied)
			} else if rule, reason, refused := ListenerOpenName(n, c); refused {
				got = refuseBy(rule, reason)
			}
			want := Evaluate(rt, agent.Action{Kind: agent.ActionFSWrite, Path: p}, backend.TierCgroup)
			// A write-open Evaluate refuses for another reason first (a deny_write target, the supervisor's) the
			// listener may refuse as well: it refuses only where Evaluate does, and every read-denied answer is its own.
			ok := got.Verdict != agent.VerdictRefused || want.Verdict == agent.VerdictRefused
			if got.Reason == record.ReasonPathUnresolved || (want.Verdict == agent.VerdictRefused && want.Reason == record.ReasonReadDenied) {
				ok = ok && got == want
			}
			if !ok {
				bad++
				if bad < 20 {
					t.Errorf("%s %s: listener %+v, Evaluate's write-open %+v", desc, p, got, want)
				}
			}
		}
	})
}

// BenchmarkListenerOpenName is the name half of the listener's decision for one open (ADR 0043's benchmark table:
// limit 200 ns and 0 allocs), a covered name refused, a name passing no entry, and a lead with no row.
func BenchmarkListenerOpenName(b *testing.B) {
	n := NewNameIndex(nameTable(backend.TierCgroup))
	for _, bc := range []struct{ name, path string }{
		{"refused", "/p/src/deep/er/later/.env.local"},
		{"miss", "/p/src/deep/er/later/main.go"},
		{"lead", "/p/src/deep/er/later/.envrc"},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, _, _ = ListenerOpenName(n, bc.path)
			}
		})
	}
}

// repeatPath is s repeated n times.
func repeatPath(s string, n int) string {
	out := ""
	for range n {
		out += s
	}
	return out
}
