// SPDX-License-Identifier: Apache-2.0

package rules

// The tests here hold the rule editor to the decision engine, which the control plane never links in its binary
// (ADR 0100 (1a)): a test binary may, and this file is the one exception in the depguard list (.golangci.yml).

import (
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/nextrun"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// decisions are the verdicts of the probes in the contract text, at the tiers that decide files.
func (f *fixture) decisions(t *testing.T, text []byte, probes ...agent.Action) map[string]agent.Verdict {
	t.Helper()
	cc := CheckContext{Contract: f.contract, Cwd: f.proj, Tier: "landlock"}
	rt, err := nextrun.Compile(t.Context(), f.s.Machine, f.s.nextrunContext(cc), text)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]agent.Verdict{}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierBPFLSM} {
		for _, p := range probes {
			out[string(tier)+" "+string(p.Kind)+" "+strings.TrimPrefix(p.Path, f.proj)] = decide.Evaluate(rt, p, tier).Verdict
		}
	}
	return out
}

// Composition of edits with the entries nested beneath them. A restriction a person wrote beneath the entry they edit
// is never lost: it stays where the edit leaves it alone, or the refusal that replaces its parent covers it and the
// preview says it goes.
func TestEditsKeepTheAskRestrictionsNestedBeneathThem(t *testing.T) {
	f := realFixture(t)
	at := func(kind agent.ActionKind, p string) agent.Action {
		return agent.Action{Kind: kind, Path: filepath.Join(f.proj, p)}
	}
	probes := []agent.Action{at(agent.ActionFSWrite, "a/y/f"), at(agent.ActionFSWrite, "a/x/f"), at(agent.ActionFSRead, "b/x/f"), at(agent.ActionFSRead, "b/x/g")}

	t.Run("removing a broader write ask leaves the nested one asking", func(t *testing.T) {
		body := "fs:\n  write: [./out/]\n  ask: [./a/, ./a/y/]\n"
		p := f.plan(t, body, Edit{"remove", "fs.ask", "./a/"})
		if p.Err != "" || p.Direction != "narrows" || p.NeedsAck {
			t.Fatalf("%+v", p)
		}
		if !strings.Contains(string(p.text), "./a/y/") || strings.Contains(string(p.text), "- ./a/\n") {
			t.Fatalf("the nested ask did not survive the removal:\n%s", p.text)
		}
		before := f.decisions(t, []byte(directionHead+body), probes...)
		after := f.decisions(t, p.text, probes...)
		if after["landlock fs_write /a/y/f"] != before["landlock fs_write /a/y/f"] {
			t.Fatalf("the nested ask changed its answer: %v -> %v", before, after)
		}
		if after["landlock fs_write /a/x/f"] != agent.VerdictRefused {
			t.Fatalf("the removed ask's other folders are not refused: %v", after)
		}
	})

	t.Run("a refusal of a broader read ask covers the nested ask it replaces, and says so", func(t *testing.T) {
		body := "fs:\n  write: [./out/]\n  ask_read: [./b/, ./b/x/]\n"
		p := f.plan(t, body, Edit{"never", "fs.ask_read", "./b/"})
		if p.Err != "" || p.Direction != "narrows" || p.NeedsAck {
			t.Fatalf("%+v", p)
		}
		var said bool
		for _, s := range p.Sentences {
			said = said || strings.Contains(s.Before, "./b/x/") && strings.Contains(s.After, "Can never read ./b/x/")
		}
		if !said {
			t.Fatalf("the nested ask that goes is not in the sentences: %+v", p.Sentences)
		}
		after := f.decisions(t, p.text, probes...)
		if after["landlock fs_read /b/x/f"] != agent.VerdictRefused {
			t.Fatalf("the nested restriction was lost: %v", after)
		}
	})
}

// What the sentence says is what the engine does: a file that matches the glob and exists at compile is refused, one
// made afterwards is not.
func TestAGlobSentenceIsTrueOfALaterFile(t *testing.T) {
	f := realFixture(t)
	p := f.plan(t, "fs:\n  write: [./out/]\n", Edit{"add", "fs.deny_read", "./*.pem"})
	cc := CheckContext{Contract: f.contract, Cwd: f.proj, Tier: "landlock"}
	rt, err := nextrun.Compile(t.Context(), f.s.Machine, f.s.nextrunContext(cc), p.text)
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) agent.Verdict {
		return decide.Evaluate(rt, agent.Action{Kind: agent.ActionFSRead, Path: filepath.Join(f.proj, name)}, backend.TierLandlock).Verdict
	}
	writeFile(t, filepath.Join(f.proj, "later.pem"), "x") // made after the table was compiled
	if read("a.pem") != agent.VerdictRefused || read("later.pem") != agent.VerdictAllow {
		t.Fatalf("the engine no longer matches the sentence's limit: a.pem %s, later.pem %s", read("a.pem"), read("later.pem"))
	}
}

// Over random contracts and random edits through the whole service (the real compiler, the real comparison), a plan
// that says narrows never lets the decision engine answer more permissively afterwards.
func TestPlannedNarrowsNeverLoosensWhatTheEngineAllows(t *testing.T) {
	f := realFixture(t)
	for _, p := range []string{"more"} {
		if err := os.MkdirAll(filepath.Join(f.proj, p), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	lists := map[string][]string{
		"fs.write":      {"./out/", "./a/", "./b/", "./a/x/"},
		"fs.deny_read":  {"./secret/", "./a/y/", "./a/x/f", "./*.pem", "./a/*/f"},
		"fs.ask_read":   {"./docs/", "./b/x/", "./a/x/"},
		"fs.ask":        {"./askme/", "./a/y/", "./b/x/"},
		"fs.deny_write": {"./a/x/", "./b/x/"},
		"exec.allow":    {"cat", "ls", "/usr/bin/cat"},
		"net.allow":     {"192.0.2.1:443", "192.0.2.2:443"},
		"net.ask":       {"192.0.2.1:443", "192.0.2.4:443"},
	}
	keys := []string{"fs.write", "fs.deny_read", "fs.ask_read", "fs.ask", "fs.deny_write", "exec.allow", "net.allow", "net.ask"}
	r := rand.New(rand.NewSource(20261121))
	rounds := 300
	if testing.Short() {
		rounds = 40
	}
	var probes []agent.Action
	for _, p := range []string{"out", "a", "a/x", "a/y", "a/x/f", "a/y/f", "b", "b/x", "b/x/f", "docs", "secret", "askme", "a.pem", "more"} {
		abs := filepath.Join(f.proj, p)
		probes = append(probes, agent.Action{Kind: agent.ActionFSRead, Path: abs}, agent.Action{Kind: agent.ActionFSWrite, Path: abs},
			agent.Action{Kind: agent.ActionFSWrite, Path: abs + "/new"})
	}
	for _, h := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.4"} {
		probes = append(probes, agent.Action{Kind: agent.ActionNetConnect, Host: h, Port: 443, Proto: "tcp"})
	}
	probes = append(probes, agent.Action{Kind: agent.ActionExec, Path: "/usr/bin/cat"}, agent.Action{Kind: agent.ActionExec, Path: "/usr/bin/ls"})
	// rank is how much the engine lets one probe through: 2 allowed, 1 asked (the engine refuses with an ask rule's
	// name, or asks), 0 refused. A refusal made a question lets the person approve what was refused.
	rank := func(a agent.Action, res agent.EvalResult) int {
		switch {
		case res.Verdict == agent.VerdictAllow:
			return 2
		case res.Verdict == agent.VerdictAsk,
			a.Kind == agent.ActionFSRead && strings.HasPrefix(res.Rule, "fs.ask_read["),
			a.Kind == agent.ActionFSWrite && strings.HasPrefix(res.Rule, "fs.ask["),
			a.Kind == agent.ActionNetConnect && strings.HasPrefix(res.Rule, "net.ask["):
			return 1
		}
		return 0
	}
	profiles := filepath.Join(f.dir, "profiles")
	if err := os.MkdirAll(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	f.s.Machine.Profiles.Value = profiles
	planned, narrowing := 0, 0
	for i := 0; i < rounds; i++ {
		var body strings.Builder
		cur := map[string][]string{}
		var want *Edit // an edit a scenario asks for, so shapes the random pick rarely reaches are tried
		profile := ""
		if r.Intn(5) == 0 {
			profile = []string{"fs:\n  write: [./a/]\n", "fs:\n  deny_read: [./secret/]\n", "fs:\n  ask_read: [./docs/]\n"}[r.Intn(3)]
		}
		writeFile(t, filepath.Join(profiles, "shared.yaml"), "version: 0\nname: shared\n"+profile)
		sections := map[string][]string{}
		for _, k := range keys {
			for _, e := range lists[k] {
				if r.Intn(4) == 0 {
					cur[k] = append(cur[k], e)
				}
			}
			sec, field, _ := strings.Cut(k, ".")
			if len(cur[k]) > 0 {
				sections[sec] = append(sections[sec], "  "+field+": ["+strings.Join(cur[k], ", ")+"]")
			}
		}
		switch r.Intn(6) { // a scenario overrides the random pick of the lists it names
		case 0: // a deny_write beneath a write grant goes
			cur["fs.write"], cur["fs.deny_write"] = []string{"./a/"}, []string{"./a/x/"}
			want = &Edit{"remove", "fs.deny_write", "./a/x/"}
		case 1: // a refusal made a question at the same place
			cur["fs.deny_read"], cur["fs.ask_read"] = []string{"./secret/"}, nil
			want = &Edit{"remove", "fs.deny_read", "./secret/"}
		case 2: // a pattern goes
			cur["fs.deny_read"] = []string{"./*.pem"}
			want = &Edit{"remove", "fs.deny_read", "./*.pem"}
		case 3: // a refusal nested inside a write grant goes
			cur["fs.write"], cur["fs.deny_read"] = []string{"./a/"}, []string{"./a/y/"}
			want = &Edit{"remove", "fs.deny_read", "./a/y/"}
		}
		sections = map[string][]string{}
		for _, k := range keys {
			sec, field, _ := strings.Cut(k, ".")
			if len(cur[k]) > 0 {
				sections[sec] = append(sections[sec], "  "+field+": ["+strings.Join(cur[k], ", ")+"]")
			}
		}
		if profile != "" {
			body.WriteString("extends: shared\n")
		}
		sections["net"] = append(sections["net"], "  allow: [192.0.2.9:443]")
		for _, sec := range []string{"fs", "net"} {
			if len(sections[sec]) > 0 {
				body.WriteString(sec + ":\n" + strings.Join(sections[sec], "\n") + "\n")
			}
		}
		k := keys[r.Intn(len(keys))]
		var e Edit
		if len(cur[k]) > 0 && r.Intn(2) == 0 {
			op := "remove"
			if (k == "fs.ask_read" || k == "fs.ask" || k == "net.ask") && r.Intn(2) == 0 {
				op = "never"
			}
			e = Edit{op, k, cur[k][r.Intn(len(cur[k]))]}
		} else {
			e = Edit{"add", k, lists[k][r.Intn(len(lists[k]))]}
		}
		if want != nil && r.Intn(3) != 0 {
			e = *want
		}
		text := directionHead + body.String()
		writeFile(t, f.contract, text)
		c := f.ref(t, f.contract)
		p, err := f.s.PlanChange(t.Context(), ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{e}})
		if err != nil || p.Err != "" {
			continue
		}
		planned++
		if p.Direction != "narrows" {
			continue
		}
		narrowing++
		cc := CheckContext{Contract: f.contract, Cwd: f.proj, Tier: "landlock"}
		a, err := nextrun.Compile(t.Context(), f.s.Machine, f.s.nextrunContext(cc), []byte(text))
		if err != nil {
			t.Fatal(err)
		}
		b, err := nextrun.Compile(t.Context(), f.s.Machine, f.s.nextrunContext(cc), p.text)
		if err != nil {
			t.Fatal(err)
		}
		for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
			for _, pr := range probes {
				before, after := decide.Evaluate(a, pr, tier), decide.Evaluate(b, pr, tier)
				if rank(pr, after) > rank(pr, before) {
					t.Fatalf("%s %s: the plan says narrows (%s) but %s %s%s goes %s -> %s at %s\nbefore:\n%s\nafter:\n%s", e.Op, e.Key+" "+e.Entry, p.Why,
						pr.Kind, pr.Path, pr.Host, before.Verdict, after.Verdict, tier, text, p.text)
				}
			}
		}
	}
	t.Logf("%d plans, %d narrowing", planned, narrowing)
	if planned < rounds/4 || narrowing < planned/5 {
		t.Fatalf("vacuous: %d plans, %d narrowing of %d rounds", planned, narrowing, rounds)
	}
}
