// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// A running run that cannot take a change live keeps its rules. The preview and the Saved page used to say "Next
// run" and the compiler-side reason ("an ask cannot be added live"), and never what the person should do about it.
// They now say the change is in force the next time the agent starts, and give the line that starts it again.
func TestAChangeThatCannotApplyLiveSaysWhatTheNextRunIsAndHowToRestart(t *testing.T) {
	f := newRulesFix(t)
	plan := &rules.ChangePlan{Ref: "00112233aabbccdd", Contract: f.source, Agent: "demo", Base: "b2", Direction: "narrows",
		Summary: "fs.ask_read += ./docs/", Diff: "--- agent.yaml\n+  ask_read: [./docs/]\n",
		Sentences: []rules.Sentence{{Before: "May read ./docs/", After: "Asks you before it reads ./docs/", Direction: "narrows"}},
		Now:       []rules.NowOption{{Run: rulesRunB, Change: "fs.ask_read += ./docs/", Why: "an ask cannot be added live: the run asks from its next run"}}}
	fc := &fakeChange{plan: plan, applied: &rules.Applied{Plan: plan, ID: "j1", Bak: f.source + ".bak"}}
	s, err := New(Config{Ledger: f.root, Port: port, Token: "tok123", Machine: config.Builtin(), Rules: fc})
	if err != nil {
		t.Fatal(err)
	}
	trustPeer(s)
	c := login(t, s)
	want := []string{"This run keeps the rules it started with. The change is in force the next time the agent starts: stop this run, then start the agent again", "tego run " + f.source + " -- sh", "an ask cannot be added live"}
	w := do(s, "GET", "/rules/change/preview?c=00112233aabbccdd&base=b1&op=add&key=fs.ask_read&v=./docs/", "127.0.0.1:8484", c)
	for _, x := range want {
		if !strings.Contains(w.Body.String(), strings.ReplaceAll(x, "'", "&#39;")) {
			t.Errorf("the preview lacks %q", x)
		}
	}
	body := follow(t, s, c, post(s, "/rules/change", url.Values{"csrf": {s.csrf}, "c": {"00112233aabbccdd"}, "base": {"b2"}, "op": {"add"},
		"key": {"fs.ask_read"}, "v": {"./docs/"}}, own, "", c))
	for _, x := range want {
		if !strings.Contains(body, strings.ReplaceAll(x, "'", "&#39;")) {
			t.Errorf("the Saved page lacks %q", x)
		}
	}
}

// The Change rules form's hints name "~" only with what it is, and the preview calls its live box what the box says.
func TestChangeRulesHintsAndLiveBoxUsePlainWords(t *testing.T) {
	for _, g := range changeGroups {
		if strings.Contains(g.Hint, "~") && !strings.Contains(g.Hint, "home folder") {
			t.Errorf("%s: the hint names ~ and not what it is: %q", g.Key, g.Hint)
		}
		if strings.Contains(g.Hint, "ending in /") {
			t.Errorf("%s: the hint says %q", g.Key, g.Hint)
		}
	}
	plan := &rules.ChangePlan{Ref: "00112233aabbccdd", Contract: "/p/agent.yaml", Agent: "demo", Base: "b2", Direction: "narrows",
		Summary: "exec.allow -= ls", Diff: "--- agent.yaml\n", Sentences: []rules.Sentence{{Before: "May run ls", After: "Cannot run ls", Direction: "narrows"}},
		Now: []rules.NowOption{{Run: "r-live-1", Kind: "exec", Value: "/usr/bin/ls", Block: "exec:/usr/bin/ls", OK: true}}}
	s, err := New(Config{Ledger: t.TempDir(), Port: port, Token: "tok123", Machine: config.Builtin(), Rules: &fakeChange{plan: plan}})
	if err != nil {
		t.Fatal(err)
	}
	trustPeer(s)
	w := do(s, "GET", "/rules/change/preview?c=00112233aabbccdd&base=b1&op=remove&key=exec.allow&v=ls", "127.0.0.1:8484", login(t, s))
	if body := w.Body.String(); strings.Contains(body, "Also apply now") || !strings.Contains(body, "Apply now to") {
		t.Errorf("the preview words its live box as jargon: %s", regexpFind(body, `rc-next-on[^<]*`))
	}
}

func regexpFind(s, re string) string { return regexp.MustCompile(re).FindString(s) }

// The restart line is printed where the run's own command would be, and a command with a value that looks like a
// credential is not printed in it: the dashboard hides such values everywhere it prints a command line.
func TestRestartLineHidesACredentialInTheRecordedCommand(t *testing.T) {
	f := newRulesFix(t)
	file := filepath.Join(f.root, rulesRunB, "events.jsonl")
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "sk-live-0123456789abcdef"
	if err := os.WriteFile(file, []byte(strings.Replace(string(b), `"command":["sh"]`, `"command":["sh","-c","deploy --token `+secret+`"]`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	line := f.s.restartLine(rulesRunB)
	if strings.Contains(line, secret) || !strings.HasPrefix(line, "tego run "+f.source+" -- <the command on the run's page") {
		t.Fatalf("restart line %q", line)
	}
	// An ordinary command is printed as it is.
	if got := newRulesFix(t); !strings.HasSuffix(got.s.restartLine(rulesRunB), " -- sh") {
		t.Fatalf("an ordinary command is not printed: %q", got.s.restartLine(rulesRunB))
	}
}
