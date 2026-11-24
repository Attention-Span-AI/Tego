// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/inforce"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// hitsText is a rules file with two command-word entries of one tool and a plain program entry.
const hitsText = `version: 0
name: demo
command: [sh]
capture: off
fs:
  write: [./out/]
exec:
  allow: [sh, "git status", "git diff"]
`

const unmatchedAttr = `"attribution":{"confidence":"unattributed","method":"none"}`

// execLine is an allowed exec line of git whose command rule is entry (list allow), as a run with command rules
// records it: the line's rule is its program's, the entry is in command_rule.
func execLine(id, entry string) string {
	return `"kind":"exec","source":"seccomp","rule":"exec[git]","verdict":"allow","authority":"rule","argv":["git","x"],"exec_id":"x/10/` + id +
		`","path":"/usr/bin/git","command_rule":"` + entry + `","command_list":"allow","command_match":"definite"`
}

// both reads the view of f from the ledger and from the read model's run, which count through different code.
func both(t *testing.T, f *fixture) map[string]*InForceView {
	t.Helper()
	scanned := f.inForce(t)
	r, err := ledgerview.Open(f.root).Run(f.run)
	if err != nil {
		t.Fatal(err)
	}
	cached := InForce(context.Background(), f.root, f.run, Options{Machine: f.m, Run: r})
	if cached.Err != "" {
		t.Fatalf("InForce (read model): %s", cached.Err)
	}
	return map[string]*InForceView{"ledger": scanned, "read model": cached}
}

// TestCommandWordEntryCountsItsOwnInvocations (C148): "git status" and "git diff" are two entries of one program,
// and every allowed git exec carries the program's rule (exec[git]), the entry that admitted it in command_rule. Each
// entry counts the lines it admitted, not every exec of git; a plain program entry still counts every exec of its file.
func TestCommandWordEntryCountsItsOwnInvocations(t *testing.T) {
	f := newFixtureWith(t, "r-aaaaaaaa-0000000000101-cwords", hitsText, "")
	f.add(execLine("1", "git status"))
	f.add(execLine("2", "git status"))
	f.add(execLine("3", "git diff"))
	f.add(`"kind":"exec","source":"seccomp","rule":"exec[sh]","verdict":"allow","authority":"rule","argv":["sh"],"exec_id":"x/10/4","path":"/bin/sh"`)
	for name, v := range both(t, f) {
		for _, w := range []struct {
			entry string
			hits  int
		}{{"git status", 2}, {"git diff", 1}} {
			if r := rule(t, v, "exec.allow", w.entry); r.Hits != w.hits {
				t.Errorf("%s: exec.allow %q has %d hits, want %d (its own invocations)", name, w.entry, r.Hits, w.hits)
			}
		}
	}
}

// TestCommandWordEntryCountsBeyondTheExecScanBound: the programs' directories are read from at most maxExecScan exec
// lines, but a command entry's hits are every line that names it.
func TestCommandWordEntryCountsBeyondTheExecScanBound(t *testing.T) {
	f := newFixtureWith(t, "r-aaaaaaaa-0000000000102-cbound", hitsText, "")
	for range maxExecScan + 10 {
		f.add(execLine("1", "git diff"))
	}
	for name, v := range both(t, f) {
		if r := rule(t, v, "exec.allow", "git diff"); r.Hits != maxExecScan+10 {
			t.Errorf("%s: exec.allow \"git diff\" has %d hits, want %d", name, r.Hits, maxExecScan+10)
		}
	}
}

// TestUnlistedInvocationCountsOnItsToolsRow (C149): a constrained tool's unlisted invocation is refused under
// exec.args[<tool>]. The tool's own row in the programs says so and counts those lines, which no row counted.
func TestUnlistedInvocationCountsOnItsToolsRow(t *testing.T) {
	f := newFixtureWith(t, "r-aaaaaaaa-0000000000103-cargs1", hitsText, "")
	f.add(`"kind":"exec","source":"seccomp","rule":"exec.args[git]","verdict":"refused","authority":"rule","reason":"exec-not-allowed",` + unmatchedAttr +
		`,"argv":["git","log"],"exec_id":"x/10/1","path":"/usr/bin/git","command_rule":"git","command_list":"unlisted","command_match":"definite"`)
	f.add(execLine("2", "git status"))
	for name, v := range both(t, f) {
		r := rule(t, v, "exec.args", "git")
		if r.Group != inforce.GroupPrograms || r.Hits != 1 || r.RuleKey != "exec.args[git]" {
			t.Errorf("%s: exec.args git: group %q key %q hits %d, want programs, exec.args[git] and 1", name, r.Group, r.RuleKey, r.Hits)
		}
		if r.Effect != inforce.EffectDeny || !strings.Contains(r.Sentence, "git") {
			t.Errorf("%s: exec.args git says %q (effect %s), want a refusal naming git", name, r.Sentence, r.Effect)
		}
		if st := rule(t, v, "exec.allow", "git status"); st.Hits != 1 {
			t.Errorf("%s: an unlisted invocation counted for \"git status\": %d hits, want 1", name, st.Hits)
		}
	}
}

// TestHarnessHookGrantHasARow (C149): the run's own exec grant for the harness hook (run_start's runtime_grants) is a
// rule in force with its own row, and the lines under exec.harness-hook[<tego>] count there.
func TestHarnessHookGrantHasARow(t *testing.T) {
	const hook = "/opt/tego/bin/tego"
	f := newFixtureWith(t, "r-aaaaaaaa-0000000000104-chook1", hitsText,
		`,"runtime_grants":["exec.harness-hook[`+hook+`]"]`)
	for range 3 {
		f.add(`"kind":"exec","source":"seccomp","rule":"exec.harness-hook[` + hook + `]","verdict":"allow","authority":"rule","argv":["` + hook + `","hook"],"exec_id":"x/10/9","path":"` + hook + `"`)
	}
	for name, v := range both(t, f) {
		var got *inforce.Rule
		for _, r := range v.View.Rules() {
			if r.RuleKey == "exec.harness-hook["+hook+"]" {
				got = &r
			}
		}
		if got == nil {
			t.Fatalf("%s: no rule carries exec.harness-hook[%s]:\n%s", name, hook, v.View.Text())
		}
		if got.Group != inforce.GroupPrograms || got.Hits != 3 || got.Effect != inforce.EffectAllow || got.Source.Origin != inforce.OriginTego {
			t.Errorf("%s: hook row %+v, want programs, allow, tego, 3 hits", name, *got)
		}
	}
}
