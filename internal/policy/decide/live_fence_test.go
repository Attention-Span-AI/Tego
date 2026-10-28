// SPDX-License-Identifier: Apache-2.0

package decide_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// liveFenceTable compiles a cgroup contract with an exec allow-list holding a whole directory, an exec.deny entry, a
// deny_read entry and a net section, plus the live: section live writes for the program directory, and returns the
// table and that directory.
func liveFenceTable(t *testing.T, live func(bin string) string) (*agent.RuleTable, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home, bin := filepath.Join(root, "home"), filepath.Join(root, "bin")
	for _, d := range []string{home, bin, filepath.Join(root, "secrets"), filepath.Join(root, "ledger"), filepath.Join(root, "out")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	prog, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Skip("no /bin/true to copy:", err)
	}
	if err := os.WriteFile(filepath.Join(bin, "static-tool"), prog, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "agent.yaml")
	data := []byte("version: 0\nname: fence\ncommand: [\"/bin/sh\"]\ntier: cgroup\n" +
		"fs:\n  write: [out/]\n  deny_read: [secrets/]\n" +
		"net:\n  allow: [\"192.0.2.10:443\"]\n" +
		"exec:\n  allow: [\"/bin/sh\", \"" + bin + "/\"]\n  deny: [static-tool]\n" +
		"env: {pass: [PATH, HOME]}\n" + live(bin))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	c, ds, err := agent.LoadBytes(path, data, nil)
	if err != nil {
		t.Fatalf("load: %v %v", err, ds)
	}
	m := config.Builtin()
	m.LedgerRoot.Value = filepath.Join(root, "ledger")
	rt, ds, err := agent.Compile(c, m, agent.WithCwd(root), agent.WithHome(home), agent.WithMountInfo(""), agent.Offline())
	if err != nil {
		t.Fatalf("compile: %v %v", err, ds)
	}
	return rt, bin
}

// TestLiveFenceNamesAllowedActions: under Adjustable, an action allowed only because a fence
// entry took out a refusal is named after that entry by both decision models, even where a contract rule matched it
// (the exec.allow directory that holds the fenced program), and a fence net entry admits TCP alone. The same contract
// Locked names every action as before.
func TestLiveFenceNamesAllowedActions(t *testing.T) {
	rt0, bin0 := liveFenceTable(t, func(string) string { return "" })
	rt, bin := liveFenceTable(t, func(bin string) string {
		return "live:\n  mode: adjustable\n  fence:\n    read: [secrets]\n    net: [\"192.0.2.40:443\"]\n    exec: [" + bin + "/static-tool]\n"
	})
	if !rt.Adjustable() {
		t.Fatal("not Adjustable")
	}
	tool, secrets := filepath.Join(bin, "static-tool"), filepath.Join(filepath.Dir(bin), "secrets")
	ev := decide.NewEvaluator(rt)
	for _, tc := range []struct {
		name    string
		a       agent.Action
		verdict agent.Verdict
		rule    string
	}{
		{"exec shadowed by a directory grant", agent.Action{Kind: agent.ActionExec, Path: tool}, agent.VerdictAllow, agent.LiveFenceRule(agent.LiveKindExec, tool)},
		{"read", agent.Action{Kind: agent.ActionFSRead, Path: filepath.Join(secrets, "key.pem")}, agent.VerdictAllow, agent.LiveFenceRule(agent.LiveKindRead, secrets)},
		{"tcp connect", agent.Action{Kind: agent.ActionNetConnect, Host: "192.0.2.40", Port: 443, Proto: "tcp"}, agent.VerdictAllow, agent.LiveFenceRule(agent.LiveKindNet, "192.0.2.40:443")},
		{"udp to the fence", agent.Action{Kind: agent.ActionNetConnect, Host: "192.0.2.40", Port: 443, Proto: "udp"}, agent.VerdictRefused, ""},
		{"contract net", agent.Action{Kind: agent.ActionNetConnect, Host: "192.0.2.10", Port: 443, Proto: "tcp"}, agent.VerdictAllow, "net[192.0.2.10:443]"},
	} {
		for _, got := range []agent.EvalResult{decide.Evaluate(rt, tc.a, backend.TierCgroup), ev.Evaluate(tc.a, backend.TierCgroup)} {
			if got.Verdict != tc.verdict || tc.rule != "" && got.Rule != tc.rule {
				t.Errorf("%s: %s via %s, want %s via %s", tc.name, got.Verdict, got.Rule, tc.verdict, tc.rule)
			}
		}
	}
	// Locked: the program stays refused by exec.deny and no rule is a fence rule.
	a := agent.Action{Kind: agent.ActionExec, Path: filepath.Join(bin0, "static-tool")}
	for _, got := range []agent.EvalResult{decide.Evaluate(rt0, a, backend.TierCgroup), decide.NewEvaluator(rt0).Evaluate(a, backend.TierCgroup)} {
		if got.Verdict != agent.VerdictRefused || strings.HasPrefix(got.Rule, "live.fence") {
			t.Errorf("locked exec: %s via %s", got.Verdict, got.Rule)
		}
	}
}
