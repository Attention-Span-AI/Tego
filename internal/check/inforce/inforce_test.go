// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// fixture is a temporary machine: a home, a project, and a bin directory of stand-in programs, so a compile is the
// same on every box.
type fixture struct {
	root, home, proj, bin string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	root := t.TempDir()
	f := fixture{root: root, home: filepath.Join(root, "home"), proj: filepath.Join(root, "proj"), bin: filepath.Join(root, "bin")}
	for _, d := range []string{f.home, f.proj, f.bin, filepath.Join(f.home, ".ssh"), filepath.Join(f.home, ".config", "telemetry"), filepath.Join(f.home, "codex-home"), filepath.Join(f.bin, "codexhost"), filepath.Join(f.proj, "confidential"), filepath.Join(f.proj, "private"), filepath.Join(f.proj, "work", "secrets"), filepath.Join(f.home, ".aws"), filepath.Join(f.proj, "work", ".git", "hooks")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{filepath.Join(f.home, ".ssh", "id_ed25519"), filepath.Join(f.home, ".config", "telemetry", "token")} {
		if err := os.WriteFile(p, []byte("fake\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	progs := []string{"bash", "git", "env", "sh", "cat", "ls", "mkdir", "touch", "grep", "sed", "head", "tail", "find", "wc", "tr", "sort", "uname", "python3", "python3.12", "codex", "codexhost/codex-code-mode-host"}
	for _, p := range progs {
		if err := os.WriteFile(filepath.Join(f.bin, p), []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// profiles serves extends: from a map, labelled under the fixture's profiles directory.
type profiles struct {
	dir   string
	files map[string]string
}

func (p profiles) Resolve(name string) (string, []byte, error) {
	text, ok := p.files[name]
	if !ok {
		return "", nil, fmt.Errorf("profile %s: %w", name, fs.ErrNotExist)
	}
	return filepath.Join(p.dir, name+".yaml"), []byte(text), nil
}

// compile loads and compiles text as the project's agent.yaml.
func (f fixture) compile(t *testing.T, text string, ps agent.ProfileSource) *agent.RuleTable {
	t.Helper()
	cp := filepath.Join(f.proj, "agent.yaml")
	if err := os.WriteFile(cp, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _, err := agent.LoadBytes(cp, []byte(text), ps)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	rt, _, err := agent.Compile(c, config.Builtin(), agent.WithPATH(f.bin), agent.WithCwd(f.proj), agent.WithHome(f.home), agent.Offline())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return rt
}

// supplyChain is the demo's contract template filled for the fixture, as the demo's setup fills it.
func (f fixture) supplyChain(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "supply-chain-demo", "contracts", "codex-chatgpt.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.NewReplacer(
		"@@CODEXHOME@@", filepath.Join(f.home, "codex-home"),
		"@@DENY_SSH@@", filepath.Join(f.home, ".ssh", "id_ed25519"),
		"@@DENY_TOKEN@@", filepath.Join(f.home, ".config", "telemetry", "token"),
		"@@PYREAL@@", filepath.Join(f.bin, "python3.12"),
		"@@CODEXHOST@@", filepath.Join(f.bin, "codexhost"),
		"@@APIADDR@@", "127.0.0.1:8803",
	).Replace(string(b))
}

// render is the golden form of a view: its text, then each rule's ledger key, so a golden pins what Count matches.
func render(v *View, root string) string {
	var b strings.Builder
	b.WriteString(v.Text())
	b.WriteString("\nRule keys:\n")
	for _, r := range v.Rules() {
		if r.RuleKey == "" {
			continue
		}
		fmt.Fprintf(&b, "  %s %s %s %s", r.Group, r.Key, r.RuleKey, r.State)
		if len(r.Covers) > 0 {
			fmt.Fprintf(&b, " (+%d more)", len(r.Covers))
		}
		b.WriteString("\n")
	}
	if root == "" {
		return b.String()
	}
	return strings.ReplaceAll(b.String(), root, "$T")
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to write it)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from the golden; run with -update to accept.\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

// TestGoldens pins the view of the demo contract, a contract with no net:, one that extends a profile, one with a
// deny_read entry a write entry shadows, the init starter, and the demo template read as text.
func TestGoldens(t *testing.T) {
	t.Run("supply-chain-landlock", func(t *testing.T) {
		f := newFixture(t)
		rt := f.compile(t, f.supplyChain(t), nil)
		v := Of(rt, backend.TierLandlock, "")
		golden(t, "supply-chain-landlock", render(&v, f.root))
	})
	t.Run("no-net", func(t *testing.T) {
		f := newFixture(t)
		rt := f.compile(t, `version: 0
name: no-net
command: ["bash", "agent.sh"]
fs:
  write: ["./out/"]
exec:
  allow: [bash, cat]
env:
  pass: [PATH, HOME]
`, nil)
		v := Of(rt, backend.TierLandlock, "")
		golden(t, "no-net", render(&v, f.root))
	})
	t.Run("extends", func(t *testing.T) {
		f := newFixture(t)
		ps := profiles{dir: filepath.Join(f.root, "profiles"), files: map[string]string{"base/mini": `version: 0
fs:
  write: ["./build/"]
  deny_read: ["./private/"]
exec:
  allow: [git]
`}}
		rt := f.compile(t, `version: 0
name: ext-agent
extends: base/mini
command: ["bash", "-c", "ls ./out"]
tier: landlock
fs:
  write: ["./out/", "/dev/null"]
net:
  allow: ["127.0.0.1:1"]
exec:
  allow: [bash, cat]
`, ps)
		v := Of(rt, backend.TierLandlock, "")
		golden(t, "extends", render(&v, f.root))
	})
	t.Run("unenforced-deny-read", func(t *testing.T) {
		f := newFixture(t)
		rt := f.compile(t, `version: 0
name: shadowed
command: ["bash", "agent.sh"]
tier: landlock
fs:
  write: ["./work/"]
  reads: direct
  deny_read: ["./work/secrets/"]
net:
  allow: []
exec:
  allow: [bash]
`, nil)
		v := Of(rt, backend.TierLandlock, "")
		golden(t, "unenforced-deny-read", render(&v, f.root))
	})
	t.Run("init-starter", func(t *testing.T) {
		f := newFixture(t)
		b, err := os.ReadFile(filepath.Join("..", "..", "cli", "agent.starter.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		rt := f.compile(t, strings.ReplaceAll(string(b), "__NAME__", "my-agent"), nil)
		v := Of(rt, backend.TierLandlock, "")
		golden(t, "init-starter", render(&v, f.root))
	})
	t.Run("command-rules", func(t *testing.T) {
		f := newFixture(t)
		rt := f.compile(t, commandRules, nil)
		v := Of(rt, backend.TierLandlock, "")
		golden(t, "command-rules", render(&v, f.root))
	})
	t.Run("declared-template", func(t *testing.T) {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "supply-chain-demo", "contracts", "codex-chatgpt.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		v, err := Declared(b, "codex-chatgpt.yaml")
		if err != nil {
			t.Fatal(err)
		}
		golden(t, "declared-template", render(&v, ""))
	})
}

// TestRouteReadsAreSaid: under every contract a run can read the host's interfaces, addresses, routes and neighbours
// (ADR 0128), so the view says so wherever it is built from, as a thing the run gets, with no claim that anything
// enforces it, and a run's relayed queries are counted on the row.
func TestRouteReadsAreSaid(t *testing.T) {
	const head = "version: 0\nname: r\ncommand: [\"bash\", \"agent.sh\"]\nexec:\n  allow: [bash]\n"
	for _, c := range []struct{ name, section string }{
		{"no net section", ""},
		{"a net section", "net:\n  allow: []\n"},
		{"host_sockets", "host_sockets: true\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			compiled := Of(f.compile(t, head+c.section, nil), backend.TierLandlock, "")
			declared, err := Declared([]byte(head+c.section), "agent.yaml")
			if err != nil {
				t.Fatal(err)
			}
			for name, v := range map[string]*View{"compiled": &compiled, "declared": &declared} {
				var got *Rule
				g := v.Group(GroupAlwaysOn)
				for i := range g.Rules {
					if g.Rules[i].Key == "built-in.route-read" {
						got = &g.Rules[i]
					}
				}
				if got == nil {
					t.Fatalf("%s: no row in %+v", name, g.Rules)
				}
				if got.Effect != EffectAllow || got.State != StateNone || got.Enforced || got.EnforcedText != "" ||
					!strings.Contains(got.Sentence, "interface names and addresses") {
					t.Errorf("%s: %+v", name, got)
				}
				v.Count(slices.Values([]string{"route-query", "route-query", "route-change"}))
				if got.Hits != 2 {
					t.Errorf("%s: %d hits, want the two queries", name, got.Hits)
				}
			}
		})
	}
}

// TestGroupOrder: every view lists every group, in the one order, whatever it was built from.
func TestGroupOrder(t *testing.T) {
	f := newFixture(t)
	views := map[string]View{"of": Of(f.compile(t, f.supplyChain(t), nil), backend.TierLandlock, ""), "nil": Of(nil, "", "")}
	d, err := Declared([]byte("version: 0\nname: x\n"), "x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	views["declared"] = d
	bad, err := Declared([]byte("a: [\n"), "bad.yaml")
	if err == nil {
		t.Error("Declared took text that is not YAML")
	}
	views["bad"] = bad
	for name, v := range views {
		var ids []string
		for _, g := range v.Groups {
			ids = append(ids, g.ID)
			if g.Title == "" || g.Lede == "" {
				t.Errorf("%s: group %s has no copy", name, g.ID)
			}
		}
		if !slices.Equal(ids, GroupOrder) {
			t.Errorf("%s: groups %v, want %v", name, ids, GroupOrder)
		}
	}
}

// TestNoEnvValues is the canary: an env.set value never reaches the view, its text or its JSON, from a compiled table
// or from text.
func TestNoEnvValues(t *testing.T) {
	const canary = "canary-value-d41d8cd9"
	text := `version: 0
name: env-agent
command: ["bash", "agent.sh"]
fs:
  write: ["./out/"]
exec:
  allow: [bash]
net:
  allow: []
env:
  pass: [PATH, HOME]
  set:
    API_TOKEN: "` + canary + `"
    OTHER: "x-` + canary + `"
`
	f := newFixture(t)
	of := Of(f.compile(t, text, nil), backend.TierLandlock, "")
	decl, err := Declared([]byte(text), "agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]View{"of": of, "declared": decl} {
		js, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		for form, s := range map[string]string{"json": string(js), "text": v.Text()} {
			if strings.Contains(s, canary) {
				t.Errorf("%s %s shows an env.set value:\n%s", name, form, s)
			}
			if !strings.Contains(s, "API_TOKEN") {
				t.Errorf("%s %s does not name API_TOKEN", name, form)
			}
		}
	}
}

// TestHitsByRuleKey counts the rule fields a run of the demo contract writes, spelled as the ledger spells them.
func TestHitsByRuleKey(t *testing.T) {
	f := newFixture(t)
	v := Of(f.compile(t, f.supplyChain(t), nil), backend.TierLandlock, "")
	token := filepath.Join(f.home, ".config", "telemetry", "token")
	ssh := filepath.Join(f.home, ".ssh", "id_ed25519")
	v.AddLive("path", token, "uid:1000 pid:42 dashboard")
	events := []record.Event{
		{Rule: "fs.write[./tmp/]"}, {Rule: "fs.write[./tmp/]"},
		{Rule: "exec[git]"}, {Rule: "exec[python3]"},
		{Rule: "net[tcp://chatgpt.com:443]"}, {Rule: "net[tcp://chatgpt.com:443]"}, {Rule: "net[tcp://chatgpt.com:443]"},
		{Rule: "net[127.0.0.1:8803]"},
		{Rule: "fs.ask_read[" + token + "]"}, {Rule: "fs.ask_read[" + token + "]"},
		{Rule: "fs.deny_read[" + ssh + "]"},
		{Rule: "fs.ask[./held/]"},
		{Rule: "live.block[path:" + token + "]"},
		{Rule: "unmatched"}, {Rule: "unmatched"}, {Rule: "unmatched"},
		{Rule: ""}, {Rule: "net.resolver"},
	}
	v.CountEvents(events)
	want := map[string]int{
		"fs.write[./tmp/]": 2, "fs.write[./src/]": 0, "exec[git]": 1, "exec[python3]": 1,
		"net[tcp://chatgpt.com:443]": 3, "net[127.0.0.1:8803]": 1, "fs.ask_read[" + token + "]": 2,
		"fs.deny_read[" + ssh + "]": 1, "fs.ask[./held/]": 1, "live.block[path:" + token + "]": 1,
	}
	got := map[string]int{}
	for _, r := range v.Rules() {
		if _, ok := want[r.RuleKey]; ok {
			got[r.RuleKey] += r.Hits
		}
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("hits of %s = %d, want %d", k, got[k], n)
		}
	}
	if v.Unmatched != 3 {
		t.Errorf("unmatched = %d, want 3", v.Unmatched)
	}
	// The built-in secret list is one rule over many entries: a hit on any of them counts there.
	b := findRule(t, &v, "built-in.deny_read", "")
	if b.RuleKey == "" || len(b.Covers) == 0 {
		t.Fatalf("built-in secret list carries no rule keys: %+v", b)
	}
	v.Count(slices.Values([]string{b.Covers[0], b.RuleKey}))
	if b = findRule(t, &v, "built-in.deny_read", ""); b.Hits != 2 {
		t.Errorf("built-in secret list hits = %d, want 2", b.Hits)
	}
}

// TestWordsMatchesWebLabels holds Words to the labels the dashboard's ruleName gives today (web/pages.go), so the
// dashboard can call Words in its place without one label changing.
func TestWordsMatchesWebLabels(t *testing.T) {
	for key, want := range map[string]string{
		"":                                "",
		"unmatched":                       "Not in the rules (default)",
		"net.resolver":                    "DNS lookup (always allowed)",
		"held-unsupported":                "Held reads cannot hold this file",
		"host-sockets":                    "A socket of the host, refused by default (no net: section)",
		"fs.write[./tmp/]":                "Writable: ./tmp/",
		"fs.deny_read[~/.ssh]":            "Secret, never readable: ~/.ssh",
		"fs.deny_write[.git/hooks/]":      "Protected from changes: .git/hooks/",
		"fs.ask[./held/]":                 "Asks you first: ./held/",
		"fs.ask_read[/h/.config/t/token]": "Asks you before a read: /h/.config/t/token",
		"fs.read[/etc/]":                  "Readable: /etc/",
		"exec[git]":                       "Allowed program: git",
		"live.block[path:/h/x]":           "Blocked live: path:/h/x",
		"net[tcp://chatgpt.com:443]":      "Allowed destination: chatgpt.com:443",
		"net[udp://1.1.1.1:53]":           "Allowed destination: 1.1.1.1:53",
		"net[127.0.0.1:8803]":             "Allowed destination: 127.0.0.1:8803",
		"net[unix:/var/run/nscd/socket]":  "Allowed socket: /var/run/nscd/socket",
		"fs.codex_home[/h/r/codex]":       "fs.codex_home[/h/r/codex]",
		"something-new":                   "something-new",
		"exec.deny[rm]":                   "Never-run program: rm",
		"fs.watch[./notes/]":              "Watched: ./notes/",
	} {
		if got := Words(key); got != want {
			t.Errorf("Words(%q) = %q, want %q", key, got, want)
		}
	}
}

// TestEnforcementByTier: the same table says different things at different tiers.
func TestEnforcementByTier(t *testing.T) {
	f := newFixture(t)
	rt := f.compile(t, f.supplyChain(t), nil)
	token := filepath.Join(f.home, ".config", "telemetry", "token")

	ll := Of(rt, backend.TierLandlock, "")
	if r := findRule(t, &ll, "fs.ask_read", token); r.Group != GroupAsk || r.Effect != EffectAsk {
		t.Errorf("at landlock an ask_read entry asks: %+v", r)
	}
	if r := findRule(t, &ll, "net.allow", "tcp://chatgpt.com:443"); !r.Enforced || r.EnforcedText != textTegoConnect {
		t.Errorf("net at landlock: %+v", r)
	}

	cg := Of(rt, backend.TierCgroup, "")
	if r := findRule(t, &cg, "fs.ask_read", token); r.Group != GroupNeverRead || r.Effect != EffectDeny || r.EnforcedText != textAskReadTier {
		t.Errorf("above landlock an ask_read entry is refused: %+v", r)
	}
	if r := findRule(t, &cg, "net.allow", "tcp://chatgpt.com:443"); r.EnforcedText != textKernel {
		t.Errorf("net at cgroup: %+v", r)
	}

	ob := Of(rt, backend.TierObserve, "")
	for _, r := range ob.Rules() {
		if r.Enforced {
			t.Errorf("an observe run enforces %q", r.Sentence)
		}
	}

	// The demo's write entries hold no git hooks or shell startup file, so it lists no built-in deny_write rule.
	for _, r := range ll.Rules() {
		if r.Key == "built-in.deny_write" {
			t.Errorf("the demo lists a built-in deny_write rule: %+v", r)
		}
	}
}

// commandRules is a contract with command patterns: an exec.allow entry with words, an exec.deny and an exec.ask.
const commandRules = `version: 0
name: cmds
command: ["bash", "agent.sh"]
tier: landlock
fs:
  write: ["./out/"]
net:
  allow: []
exec:
  allow: [bash, "git status"]
  deny: ["git push"]
  ask: ["git commit"]
`

// TestExecCommandRules: exec.ask is reserved, so it is listed as a refusal among the programs and never as a question;
// exec.deny is a command rule, decided on tego's copy of the words, so it carries the same best-effort claim as an
// exec.allow entry with words.
func TestExecCommandRules(t *testing.T) {
	f := newFixture(t)
	rt := f.compile(t, commandRules, nil)
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
		v := Of(rt, tier, "")
		best := false
		for _, c := range rt.BestEffortCellsAt(tier, "") {
			best = best || c == agent.BestEffortExecRules
		}
		if !best {
			t.Fatalf("%s: a table with command rules lists no %s cell", tier, agent.BestEffortExecRules)
		}
		ask := findRule(t, &v, "exec.ask", "git commit")
		if ask.Group != GroupPrograms || ask.Effect != EffectDeny || ask.Enforced ||
			ask.EnforcedText != textExecAskReservedBest || ask.State != StateBestEffort ||
			ask.Sentence != "Can never run git commit (asking first is not supported yet)" || ask.RuleKey != "exec.ask[git commit]" {
			t.Errorf("%s: exec.ask is a refusal: %+v", tier, ask)
		}
		if g := v.Group(GroupAsk); len(g.Rules) != 0 || g.Default != "" {
			t.Errorf("%s: an exec.ask entry makes a question: %+v", tier, g)
		}
		deny := findRule(t, &v, "exec.deny", "git push")
		if deny.Enforced || deny.EnforcedText != textTegoCommands || deny.State != StateBestEffort {
			t.Errorf("%s: exec.deny claims more than best effort: %+v", tier, deny)
		}
	}
	// Hits: the engine names a command pattern's decision exec.allow[...], a bare program's exec[...].
	v := Of(rt, backend.TierLandlock, "")
	v.Count(slices.Values([]string{"exec.allow[git status]", "exec[git status]", "exec.ask[git commit]", "exec.deny[git push]"}))
	if r := findRule(t, &v, "exec.allow", "git status"); r.Hits != 2 {
		t.Errorf("an exec.allow entry with words counts both spellings: hits %d", r.Hits)
	}
	if r := findRule(t, &v, "exec.ask", "git commit"); r.Hits != 1 {
		t.Errorf("exec.ask hits %d", r.Hits)
	}
}

// TestStates: the one-word state tells a best-effort rule, an unenforced one and one with no claim apart.
func TestStates(t *testing.T) {
	for _, c := range []struct {
		ok   bool
		text string
		want State
	}{
		{true, textKernel, StateEnforced}, {false, textBestEffort, StateBestEffort}, {false, textTegoCommands, StateBestEffort},
		{false, textShadowed, StateNotEnforced}, {false, textObserve, StateNotEnforced}, {false, "", StateNone},
		{true, textExecAskReserved, StateEnforced}, {false, textExecAskReservedBest, StateBestEffort},
	} {
		if got := stateOf(c.ok, c.text); got != c.want {
			t.Errorf("stateOf(%v, %q) = %s, want %s", c.ok, c.text, got, c.want)
		}
	}
	f := newFixture(t)
	v := Of(f.compile(t, f.supplyChain(t), nil), backend.TierLandlock, "")
	for _, r := range v.Rules() {
		if r.State == "" {
			t.Errorf("rule %q has no state", r.Sentence)
		}
		if r.Effect == EffectLimit && r.State != StateNone {
			t.Errorf("a limit makes a claim: %+v", r)
		}
	}
	d, err := Declared([]byte(commandRules), "agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range d.Rules() {
		if r.State != StateNone {
			t.Errorf("a Declared view makes a claim: %+v", r)
		}
	}
}

// TestWordsCommandRules: the command rules' ledger spellings (execmatch Result.Rule) get labels too.
func TestWordsCommandRules(t *testing.T) {
	for key, want := range map[string]string{
		"exec.allow[git status]": "Allowed command: git status",
		"exec.ask[npm install]":  "Never-run program (asking first is not supported yet): npm install",
		"exec.args[git]":         "Command not in the rules for: git",
	} {
		if got := Words(key); got != want {
			t.Errorf("Words(%q) = %q, want %q", key, got, want)
		}
	}
}

// TestBuiltInDenyWrite: the built-in deny_write set is best effort where no decision plane decides, and enforced
// by the kernel where one does.
func TestBuiltInDenyWrite(t *testing.T) {
	f := newFixture(t)
	rt := f.compile(t, "version: 0\nname: dw\ncommand: [\"bash\"]\nfs:\n  write: [\"./work/\"]\nnet:\n  allow: []\n", nil)
	ll := Of(rt, backend.TierLandlock, "")
	if r := findRule(t, &ll, "built-in.deny_write", ""); r.Enforced || r.EnforcedText != textBestEffort || r.RuleKey == "" {
		t.Errorf("built-in deny_write at landlock: %+v", r)
	}
	lsm := Of(rt, backend.TierBPFLSM, record.DecisionPlaneLSM)
	if r := findRule(t, &lsm, "built-in.deny_write", ""); !r.Enforced || r.EnforcedText != textKernel {
		t.Errorf("built-in deny_write under a plane: %+v", r)
	}
}

// TestHeldReadsEnforceShadowed: with reads held (auto, a deny_read beneath a write entry), the shadowed entry is
// refused by tego after all.
func TestHeldReadsEnforceShadowed(t *testing.T) {
	f := newFixture(t)
	rt := f.compile(t, `version: 0
name: held
command: ["bash", "agent.sh"]
tier: landlock
fs:
  write: ["./work/"]
  deny_read: ["./work/secrets/"]
net:
  allow: []
exec:
  allow: [bash]
`, nil)
	v := Of(rt, backend.TierLandlock, "")
	if r := findRule(t, &v, "fs.deny_read", "./work/secrets/"); !r.Enforced || r.EnforcedText != textTegoRead {
		t.Errorf("held reads refuse a shadowed deny_read: %+v", r)
	}
}

// TestEditableAndSources: only the top file's entries under the change form's keys are editable, each with its line.
func TestEditableAndSources(t *testing.T) {
	f := newFixture(t)
	ps := profiles{dir: filepath.Join(f.root, "profiles"), files: map[string]string{"base": "version: 0\nfs:\n  write: [\"./build/\"]\n"}}
	rt := f.compile(t, "version: 0\nname: e\nextends: base\ncommand: [\"bash\"]\nfs:\n  write: [\"./out/\"]\nnet:\n  allow: [\"127.0.0.1:1\"]\nlimits:\n  wall: 1h\n", ps)
	v := Of(rt, backend.TierLandlock, "")
	out := findRule(t, &v, "fs.write", "./out/")
	if !out.Editable || out.Source.Origin != OriginContract || out.Source.Line != 6 {
		t.Errorf("./out/: %+v", out)
	}
	build := findRule(t, &v, "fs.write", "./build/")
	if build.Editable || build.Source.Origin != OriginProfile || build.Source.Line != 3 || !strings.HasSuffix(build.Source.File, "base.yaml") {
		t.Errorf("./build/ from the profile: %+v", build)
	}
	if r := findRule(t, &v, "limits.wall", "1h"); r.Editable || r.Sentence != "Is stopped after 1 hour" {
		t.Errorf("wall: %+v", r)
	}
	if r := findRule(t, &v, "built-in.own-records", ""); r.Editable || r.Source.Origin != OriginBuiltIn {
		t.Errorf("own records: %+v", r)
	}
}

// TestSentences pins the plain words for the shapes an entry can take.
func TestSentences(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{first(pathSentence("Can change", "./src/", "")), "Can change files in ./src/"},
		{first(pathSentence("Can never read", "/h/me/.ssh/id_ed25519", "/h/me")), "Can never read ~/.ssh/id_ed25519"},
		{first(pathSentence("Can never read", "./**/*.pem", "")), "Can never read files matching ./**/*.pem"},
		{first(programSentence("Can run", "/opt/tools/", "")), "Can run programs in /opt/tools/"},
		{first(programSentence("Can run", "/usr/bin/python3.12", "")), "Can run python3.12"},
		{first(programSentence("Can never run", "/usr/bin/git push", "")), "Can never run git push"},
		{first(programSentence("Can run", "/opt/*/bin/tool", "")), "Can run /opt/*/bin/tool"},
		{netTarget("tcp://chatgpt.com:443"), "chatgpt.com on port 443"},
		{netTarget("udp://1.1.1.1:53"), "1.1.1.1 on port 53 (UDP)"},
		{netTarget("127.0.0.1:8803"), "127.0.0.1 on port 8803"},
		{netTarget("[::1]:8080"), "::1 on port 8080"},
		{netTarget("example.com"), "example.com on any port"},
		{netTarget("10.0.0.0/8"), "addresses in 10.0.0.0/8"},
		{netTarget("unix:/run/x.sock"), "the local socket /run/x.sock"},
		{limitSentence("memory", "4GiB"), "Can use at most 4 GiB of memory"},
		{limitSentence("stall_after", "10m"), "Is stopped when nothing happens for 10 minutes"},
		{liveSentence("net", "127.0.0.1:8802"), "Blocked now: cannot connect to 127.0.0.1 on port 8802"},
		{liveSentence("exec", "curl"), "Blocked now: cannot run curl"},
		{short("/h/me", "/h/me"), "~"},
		{short("/h/meant", "/h/me"), "/h/meant"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}

func first(a, _ string) string { return a }

// findRule is the rule with key and entry ("" matches any entry); it fails the test when there is none.
func findRule(t *testing.T, v *View, key, entry string) Rule {
	t.Helper()
	for _, r := range v.Rules() {
		if r.Key == key && (entry == "" || r.Entry == entry) {
			return r
		}
	}
	t.Fatalf("no rule %s %q in:\n%s", key, entry, v.Text())
	return Rule{}
}

// TestDeclaredBadShapes: text that is YAML but not a contract still gives a view, never a panic.
func TestDeclaredBadShapes(t *testing.T) {
	for _, text := range []string{"", "- a\n- b\n", "fs: 3\nexec: [x]\nnet: {allow: x}\nenv: {set: [a]}\nlimits: {wall: [1]}\n"} {
		v, err := Declared([]byte(text), "x.yaml")
		if err != nil && !errors.Is(err, errNotMapping) {
			t.Errorf("Declared(%q): %v", text, err)
		}
		if len(v.Groups) != len(GroupOrder) {
			t.Errorf("Declared(%q): %d groups", text, len(v.Groups))
		}
	}
}
