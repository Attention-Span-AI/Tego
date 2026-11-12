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
	"time"

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

// compile loads and compiles text as the project's agent.yaml under the built-in machine config.
func (f fixture) compile(t *testing.T, text string, ps agent.ProfileSource) *agent.RuleTable {
	t.Helper()
	return f.compileOn(t, text, ps, config.Builtin())
}

// compileOn is compile under the machine config m.
func (f fixture) compileOn(t *testing.T, text string, ps agent.ProfileSource, m *config.Machine) *agent.RuleTable {
	t.Helper()
	cp := filepath.Join(f.proj, "agent.yaml")
	if err := os.WriteFile(cp, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _, err := agent.LoadBytes(cp, []byte(text), ps)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	rt, _, err := agent.Compile(c, m, agent.WithPATH(f.bin), agent.WithCwd(f.proj), agent.WithHome(f.home), agent.Offline())
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

// TestDefaultHits: a line no rule named counts in Unmatched, and on the default of the group that decided it: an exec
// line on the programs', a net line on the network's. A file line, whose kind does not say whether it read or changed,
// and a refusal line count in Unmatched alone.
func TestDefaultHits(t *testing.T) {
	f := newFixture(t)
	v := Of(f.compile(t, commandRules, nil), backend.TierLandlock, "")
	v.CountEvents([]record.Event{
		{Kind: record.KindExec, Rule: "unmatched"}, {Kind: record.KindNet, Rule: "unmatched"},
		{Kind: record.KindNet, Rule: "unmatched"}, {Kind: record.KindNet, Rule: "unmatched"},
		{Kind: record.KindFS, Rule: "unmatched"}, {Kind: record.KindRefused, Rule: "unmatched"},
		{Kind: record.KindExec, Rule: "exec[bash]"}, {Kind: record.KindNet, Rule: "net.resolver"},
	})
	want := map[string]int{GroupPrograms: 1, GroupNetwork: 3}
	for _, g := range v.Groups {
		if g.DefaultHits != want[g.ID] {
			t.Errorf("%s default hits %d, want %d", g.ID, g.DefaultHits, want[g.ID])
		}
	}
	if v.Unmatched != 6 {
		t.Errorf("unmatched %d, want every kind's 6", v.Unmatched)
	}
	if r := findRule(t, &v, "exec.allow", "bash"); r.Hits != 1 {
		t.Errorf("a named line counts on its rule, not a default: %d hits", r.Hits)
	}
	text := v.Text()
	for _, want := range []string{"  Cannot run any other program.  [1 hits]\n", "  Cannot connect anywhere.  [3 hits]\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("the text lacks %q:\n%s", want, text)
		}
	}
	// A view adds what it is given: the kinds' counts, as the dashboard's scan hands them.
	v.CountDefault("net", 2)
	v.CountDefault("", 5)
	if g := v.Group(GroupNetwork); g.DefaultHits != 5 {
		t.Errorf("network default hits %d after two more, want 5", g.DefaultHits)
	}
	for _, g := range v.Groups {
		if (g.DefaultKind != "") != (g.ID == GroupPrograms || g.ID == GroupNetwork) {
			t.Errorf("%s has the default kind %q", g.ID, g.DefaultKind)
		}
	}
}

// TestWordsMatchesWebLabels holds Words to the labels the dashboard shows for a line's rule: its ruleName is Words
// (through rulesview.RuleWords), so a label changes here or nowhere. fs.ask and fs.ask_read both read "Ask first", a
// fence entry reads by its value, and a key with no label of its own reads as written.
func TestWordsMatchesWebLabels(t *testing.T) {
	for key, want := range map[string]string{
		"":                                   "",
		"unmatched":                          "Not in contract",
		"net.resolver":                       "DNS lookup",
		"held-unsupported":                   "Cannot hold",
		"host-sockets":                       "Host socket",
		"builtin.host_ipc":                   "Host IPC refused",
		"builtin.tego_surface":               "Tego control refused",
		"builtin.other_tty":                  "Other terminal refused",
		"fs.write[./tmp/]":                   "Write: ./tmp/",
		"fs.deny_read[~/.ssh]":               "Never read: ~/.ssh",
		"fs.deny_write[.git/hooks/]":         "No changes: .git/hooks/",
		"fs.ask[./held/]":                    "Ask first: ./held/",
		"fs.ask_read[/h/.config/t/token]":    "Ask first: /h/.config/t/token",
		"fs.read[/etc/]":                     "Read: /etc/",
		"exec[git]":                          "Program: git",
		"live.block[path:/h/x]":              "Blocked live: path:/h/x",
		"live.fence[read:/srv/exports]":      "Fence: /srv/exports",
		"live.fence[net:api.stripe.com:443]": "Fence: api.stripe.com:443",
		"live.fence[]":                       "Fence: ",
		"net[tcp://chatgpt.com:443]":         "Host: chatgpt.com:443",
		"net[udp://1.1.1.1:53]":              "Host: 1.1.1.1:53",
		"net[127.0.0.1:8803]":                "Host: 127.0.0.1:8803",
		"net[unix:/var/run/nscd/socket]":     "Socket: /var/run/nscd/socket",
		"fs.codex_home[/h/r/codex]":          "fs.codex_home[/h/r/codex]",
		"something-new":                      "something-new",
		"exec.deny[rm]":                      "Never-run program: rm",
		"fs.watch[./notes/]":                 "Watched: ./notes/",
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
	// Hits, spelled as a run spells them (rulesview's TestIntegrationRuleKeysAreARunsKeys): an exec an entry with
	// words admits carries its program's rule, exec[git], with the entry in command_rule; a refusal carries
	// exec.deny[...] or exec.ask[...].
	v := Of(rt, backend.TierLandlock, "")
	v.Count(slices.Values([]string{"exec[git]", "exec[git]", "exec.ask[git commit]", "exec.deny[git push]"}))
	if r := findRule(t, &v, "exec.allow", "git status"); r.RuleKey != "exec[git]" || r.Hits != 2 {
		t.Errorf("an exec.allow entry with words counts its program's lines: key %s, hits %d", r.RuleKey, r.Hits)
	}
	if r := findRule(t, &v, "exec.ask", "git commit"); r.Hits != 1 {
		t.Errorf("exec.ask hits %d", r.Hits)
	}
	if r := findRule(t, &v, "exec.deny", "git push"); r.Hits != 1 {
		t.Errorf("exec.deny hits %d", r.Hits)
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
		{false, textDatagram, StateBestEffort}, {true, textTegoRequest, StateEnforced}, {true, textGate, StateEnforced},
		{false, textHeldBest, StateBestEffort}, {true, textHeld, StateEnforced},
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

// TestBuiltInDenyWriteAgrees: the compiled view lists the built-in deny_write rule only when compile found files of
// its kinds beneath a write entry, and then says it plainly; read as text, where nothing can look, the rule is said
// with that condition, so the two views never claim different protections for one file.
func TestBuiltInDenyWriteAgrees(t *testing.T) {
	const plain = "Can never change files that would run code outside the agent: git hooks, shell startup files and agent settings"
	f := newFixture(t)
	for _, c := range []struct {
		dir   string
		found bool
	}{{"./work/", true}, {"./private/", false}} { // the fixture's ./work/ holds .git/hooks; ./private/ holds nothing
		text := "version: 0\nname: dw\ncommand: [\"bash\"]\nfs:\n  write: [\"" + c.dir + "\"]\nnet:\n  allow: []\n"
		of := Of(f.compile(t, text, nil), backend.TierLandlock, "")
		var got *Rule
		for _, r := range of.Rules() {
			if r.Key == "built-in.deny_write" {
				got = &r
			}
		}
		switch {
		case c.found && (got == nil || got.Sentence != plain):
			t.Errorf("%s: compiled rule %+v, want the plain sentence", c.dir, got)
		case !c.found && got != nil:
			t.Errorf("%s: compiled view lists a rule with nothing beneath it: %+v", c.dir, got)
		}
		d, err := Declared([]byte(text), "agent.yaml")
		if err != nil {
			t.Fatal(err)
		}
		if r := findRule(t, &d, "built-in.deny_write", ""); r.Sentence != plain+", where a run finds any in the folders it can change" {
			t.Errorf("%s: read as text, the rule says %q", c.dir, r.Sentence)
		}
	}
	d, err := Declared([]byte("version: 0\nname: ro\ncommand: [\"bash\"]\n"), "agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range d.Rules() {
		if r.Key == "built-in.deny_write" {
			t.Errorf("a contract with no write entry lists %+v", r)
		}
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
		{first(programSentence("Can run", "'/opt/My Tools/run'", "")), "Can run run"},
		{first(programSentence("Can run", "/usr/bin/git\tstatus", "")), "Can run git status"},
		{first(programSentence("Can run", "git add src/", "")), "Can run git add src/"},
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

// TestLimitsUnderMachineCeilings: compiled, the limits are the run's, each clamped to this computer's ceilings (R11):
// a limit a ceiling lowers says the lower value and the one its rules ask for, one under its ceiling is as written,
// and one only a ceiling sets is listed from the machine config. Read as text, the limits are as written.
func TestLimitsUnderMachineCeilings(t *testing.T) {
	const text = "version: 0\nname: l\ncommand: [\"bash\", \"agent.sh\"]\nexec:\n  allow: [bash]\nlimits:\n  wall: 2h\n  cost_usd: 10\n  memory: 512MiB\n  pids: 128\n"
	m := config.Builtin()
	m.Limits.Wall = config.Ceiling[time.Duration]{Value: time.Hour, Bounded: true}
	m.Limits.CostUSD = config.Ceiling[float64]{Value: 2.5, Bounded: true}
	m.Limits.Memory = config.Ceiling[config.ByteSize]{Value: 1 << 30, Bounded: true}
	m.Limits.Pids = config.Ceiling[int]{Value: 256, Bounded: true}
	m.Limits.CPUWeight = config.Ceiling[int]{Value: 50, Bounded: true}
	m.Limits.StallAfter = config.Ceiling[time.Duration]{Value: 10 * time.Minute, Bounded: true}
	f := newFixture(t)
	v := Of(f.compileOn(t, text, nil, m), backend.TierLandlock, "")
	type row struct{ key, entry, sentence, origin string }
	want := []row{
		{"limits.wall", "2h", "Is stopped after 1 hour, this computer's limit; its rules ask for 2 hours", OriginContract},
		{"limits.cost_usd", "10", "Is stopped after $2.5 of model use, this computer's limit; its rules ask for $10", OriginContract},
		{"limits.memory", "512MiB", "Can use at most 512 MiB of memory", OriginContract},
		{"limits.pids", "128", "Can run at most 128 processes at once", OriginContract},
		{"limits.cpu_weight", "50", "Gets a CPU share of 50 (100 is normal)", OriginMachine},
		{"limits.stall_after", "10m", "Is stopped when nothing happens for 10 minutes", OriginMachine},
	}
	g := v.Group(GroupLimits)
	var got []row
	for _, r := range g.Rules {
		got = append(got, row{r.Key, r.Entry, r.Sentence, r.Source.Origin})
		if r.Effect != EffectLimit || r.State != StateNone || r.Enforced || r.Editable {
			t.Errorf("%s makes a claim or is editable: %+v", r.Key, r)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("limits:\n got %+v\nwant %+v", got, want)
	}
	if g.Default != "" {
		t.Errorf("a contract with limits has the default %q", g.Default)
	}
	if !strings.Contains(v.Text(), "Gets a CPU share of 50 (100 is normal)  [machine config]") {
		t.Errorf("the text does not name the machine config:\n%s", v.Text())
	}
	d, err := Declared([]byte(text), "agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if rs := d.Group(GroupLimits).Rules; len(rs) != 4 || rs[0].Sentence != "Is stopped after 2 hours" {
		t.Errorf("read as text, the limits are not as written: %+v", rs)
	}
}

// TestHTTPAndIngressRows: net.http's entries are listed among the network rules with the rule key the model proxy's
// lines carry (net.http[i]) and tego's claim, and net.ingress's with the kernel's claim and no rule key, since no ledger
// line names one (a refused packet only adds to run_end's network counters), compiled or read as text; the network's
// last line says what each refuses beyond its entries.
func TestHTTPAndIngressRows(t *testing.T) {
	const http = "version: 0\nname: h\ncommand: [\"bash\", \"agent.sh\"]\ncapture: forwarder\nexec:\n  allow: [bash]\n" +
		"models:\n  - {provider: anthropic, host: api.anthropic.com, port: 443}\nnet:\n  allow: []\n  http:\n" +
		"    - {host: api.anthropic.com, allow: [/v1/messages, /v1/models], methods: [POST, GET]}\n    - {host: api.anthropic.com, allow: [/]}\n"
	const ingress = "version: 0\nname: i\ncommand: [\"bash\", \"agent.sh\"]\ntier: cgroup\nexec:\n  allow: [bash]\nnet:\n  allow: []\n" +
		"  listen: [\"tcp://127.0.0.1:8080\"]\n  ingress:\n    - {from: 10.0.0.0/8, to: \"tcp://127.0.0.1:8080\"}\n    - {from: 192.0.2.7, to: \"tcp://127.0.0.1:8080\"}\n"
	f := newFixture(t)
	for _, c := range []struct {
		name, text string
		tier       backend.Tier
		key        string
		want       []Rule // Key, RuleKey, Sentence, EnforcedText
		tail       string
	}{
		{"net.http", http, backend.TierLandlock, kNetHTTP, []Rule{
			{RuleKey: "net.http[0]", Sentence: "Can send POST, GET requests to api.anthropic.com under /v1/messages, /v1/models", EnforcedText: textTegoRequest},
			{RuleKey: "net.http[1]", Sentence: "Can send requests to api.anthropic.com at any path", EnforcedText: textTegoRequest},
		}, " Every other request to its model services is refused."},
		{"net.ingress", ingress, backend.TierCgroup, kNetIngress, []Rule{
			{Sentence: "Can accept connections on 127.0.0.1 on port 8080 from addresses in 10.0.0.0/8", EnforcedText: textKernel},
			{Sentence: "Can accept connections on 127.0.0.1 on port 8080 from 192.0.2.7", EnforcedText: textKernel},
		}, " Nothing else can connect to its listeners."},
	} {
		t.Run(c.name, func(t *testing.T) {
			compiled := Of(f.compile(t, c.text, nil), c.tier, "")
			declared, err := Declared([]byte(c.text), "agent.yaml")
			if err != nil {
				t.Fatal(err)
			}
			for name, v := range map[string]View{"compiled": compiled, "declared": declared} {
				var got []Rule
				for _, r := range v.Group(GroupNetwork).Rules {
					if r.Key == c.key {
						got = append(got, r)
					}
				}
				if len(got) != len(c.want) {
					t.Fatalf("%s: %d %s rows, want %d:\n%s", name, len(got), c.key, len(c.want), v.Text())
				}
				for i, w := range c.want {
					r := got[i]
					if r.Sentence != w.Sentence || r.Effect != EffectAllow || r.Source.Origin != OriginContract || r.Source.Line == 0 {
						t.Errorf("%s: row %d = %+v, want %q from a contract line", name, i, r, w.Sentence)
					}
					wantKey, wantText := w.RuleKey, w.EnforcedText
					if name == "declared" {
						wantText = "" // no claim read as text
					}
					if r.RuleKey != wantKey || len(r.Covers) != 0 || r.EnforcedText != wantText {
						t.Errorf("%s: row %d key %q claim %q, want %q and %q", name, i, r.RuleKey, r.EnforcedText, wantKey, wantText)
					}
				}
				if d := v.Group(GroupNetwork).Default; !strings.HasSuffix(d, c.tail) {
					t.Errorf("%s: network default %q does not end %q", name, d, c.tail)
				}
			}
			if c.key == kNetHTTP {
				compiled.Count(slices.Values([]string{c.want[1].RuleKey, c.want[1].RuleKey}))
				for _, r := range compiled.Rules() {
					if r.RuleKey == c.want[1].RuleKey && r.Hits != 2 {
						t.Errorf("%s hits %d, want 2", r.RuleKey, r.Hits)
					}
				}
			}
		})
	}
}

// TestGateRows: the gate's scored rules are listed where each one's score alone puts an action it matches (scores only
// add up): above the ask threshold among the refusals of its kind, from the allow threshold among the questions save a
// command, which is refused, and below it as what it adds, among the questions save a command's, listed among the
// programs since tego never asks before one runs. Each carries the rule key its lines carry and the claim its
// best-effort cells allow, a question's that tego holds it until you answer and a refusal's that it is scored, compiled
// or read as text, and a note says how the scores add up.
func TestGateRows(t *testing.T) {
	const text = "version: 0\nname: g\ncommand: [\"bash\", \"agent.sh\"]\ntier: landlock\nexec:\n  allow: [bash]\nnet:\n  allow: [\"127.0.0.1:1\"]\n" +
		"gate:\n  rules:\n    - fs.write outside worktree: 60\n    - 'exec matches \"curl *\"': 60\n    - 'fs.read matches \"~/.aws/*\"': 90\n" +
		"    - net to undeclared host: 20\n    - 'net to 93.184.216.34:443': 85\n    - 'exec matches \"rm *\"': 10\n" +
		"    - 'net to 198.51.100.7:443': 60\n  thresholds: {allow: 50, ask: 80}\n"
	type row struct {
		group    string
		effect   Effect
		sentence string
		claim    string
	}
	want := []row{
		{GroupAsk, EffectAsk, "Asks you before it changes a file outside its worktree (risk score 60)", textHeldBest},
		{GroupPrograms, EffectDeny, "Can never run a command matching curl * (risk score 60: asking first is not supported yet)", textBestEffort},
		{GroupNeverRead, EffectDeny, "Can never read a file matching ~/.aws/* (risk score 90)", textBestEffort},
		{GroupAsk, EffectNote, "Adds 20 to the risk score when it connects to a host its rules do not name", ""},
		{GroupNetwork, EffectDeny, "Can never connect to 93.184.216.34 on port 443 (risk score 85)", textGate},
		{GroupPrograms, EffectNote, "Adds 10 to the risk score when it runs a command matching rm *", ""},
		{GroupAsk, EffectAsk, "Asks you before it connects to 198.51.100.7 on port 443 (risk score 60)", textHeld},
	}
	f := newFixture(t)
	compiled := Of(f.compile(t, text, nil), backend.TierLandlock, "")
	declared, err := Declared([]byte(text), "agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]View{"compiled": compiled, "declared": declared} {
		byKey := map[string]Rule{}
		for _, r := range v.Rules() {
			if r.Key == "gate.rules" {
				byKey[r.RuleKey] = r
			}
		}
		var got []row // in the gate's order, which the rule keys number; the view lists them by group
		for i := range len(byKey) {
			r, ok := byKey[fmt.Sprintf("gate.rules[%d]", i)]
			if !ok || r.Source.Origin != OriginContract || r.Source.Line != 11+i || r.Editable {
				t.Errorf("%s: gate row %d: %+v", name, i, r)
			}
			got = append(got, row{r.Group, r.Effect, r.Sentence, r.EnforcedText})
		}
		w := want
		if name == "declared" { // no claim read as text
			w = slices.Clone(want)
			for i := range w {
				w[i].claim = ""
			}
		}
		if !slices.Equal(got, w) {
			t.Errorf("%s gate rows:\n got %+v\nwant %+v", name, got, w)
		}
		if !strings.Contains(strings.Join(v.Notes, " "), "from 50 it asks you first, above 80 it is refused") {
			t.Errorf("%s: no note on how the scores add up: %q", name, v.Notes)
		}
		if g := v.Group(GroupAsk); !strings.HasPrefix(g.Default, "If you do not answer within") {
			t.Errorf("%s: the gate's questions have no time limit said: %q", name, g.Default)
		}
	}
	compiled.Count(slices.Values([]string{"gate.rules[4]"}))
	if r := findRule(t, &compiled, "gate.rules", `net to 93.184.216.34:443`); r.Hits != 1 {
		t.Errorf("the net gate's refusal counts %d hits, want 1", r.Hits)
	}
	bad, err := Declared([]byte("version: 0\nname: b\ngate:\n  rules: [{shell expression x: 90}]\n"), "agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(bad.Notes, " "), "does not read as a gate") {
		t.Errorf("a gate that does not read is not named: %q", bad.Notes)
	}
	// A command's score asks nothing: a gate whose one rule scores a command below the allow threshold makes no question.
	const cmd = "version: 0\nname: c\ncommand: [\"bash\", \"agent.sh\"]\nexec:\n  allow: [bash]\ngate:\n  rules:\n    - 'exec matches \"rm *\"': 10\n"
	cd, err := Declared([]byte(cmd), "agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]View{"compiled": Of(f.compile(t, cmd, nil), backend.TierLandlock, ""), "declared": cd} {
		if g := v.Group(GroupAsk); len(g.Rules) != 0 || g.Default != "" {
			t.Errorf("%s: a command's score makes a question: %+v", name, g)
		}
		if r := findRule(t, &v, "gate.rules", `exec matches "rm *"`); r.Group != GroupPrograms || r.Effect != EffectNote {
			t.Errorf("%s: the command's score is not a note among the programs: %+v", name, r)
		}
	}
}

// TestDatagramResidual: at tier landlock tego lets the agent's own call send a datagram it does not refuse
// (supervisor R13b), so with a net: section the network names that residual as a best-effort refusal for every run,
// whatever its entries admit: every such run may open a UDP or local datagram socket, and a send that names no address
// is continued undecided for a racing thread to address. That includes the runs whose table admits no datagram: TCP
// alone with the resolver off, where a socket the run binds beneath a write entry (R11a) or the DNS broker's socket,
// granted at launch, is admitted all the same. Not at a root tier, not in an observe run, not without a net: section
// (Always on's host-sockets row says it there) and not read as text.
func TestDatagramResidual(t *testing.T) {
	const head = "version: 0\nname: d\ncommand: [\"bash\", \"agent.sh\"]\nexec:\n  allow: [bash]\n"
	f := newFixture(t)
	for _, c := range []struct {
		name, body string
		tier       backend.Tier
		want       bool
		noDatagram bool // the table admits no datagram: TCP entries alone, and no resolver
	}{
		{"an address", "net:\n  allow: [\"127.0.0.1:1\"]\n", backend.TierLandlock, true, false},
		{"none but the resolver", "net:\n  allow: []\n", backend.TierLandlock, true, false},
		{"a local socket, resolver off", "net:\n  allow: [\"unix:/run/x.sock\"]\n  dns: {mode: off}\n", backend.TierLandlock, true, false},
		{"TCP only, resolver off", "net:\n  allow: [\"tcp://127.0.0.1:1\"]\n  dns: {mode: off}\n", backend.TierLandlock, true, true},
		{"TCP only, resolver off, a write entry", "fs:\n  write: [\"./out/\"]\nnet:\n  allow: [\"tcp://127.0.0.1:1\"]\n  dns: {mode: off}\n", backend.TierLandlock, true, true},
		{"TCP only, the DNS broker", "net:\n  allow: [\"tcp://127.0.0.1:1\"]\n  dns: {mode: broker}\n", backend.TierLandlock, true, true},
		{"nothing at all, resolver off", "net:\n  allow: []\n  dns: {mode: off}\n", backend.TierLandlock, true, true},
		{"a root tier", "net:\n  allow: [\"127.0.0.1:1\"]\n", backend.TierCgroup, false, false},
		{"watched", "net:\n  allow: [\"127.0.0.1:1\"]\n", backend.TierObserve, false, false},
		{"no net section", "", backend.TierLandlock, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			rt := f.compile(t, head+c.body, nil)
			if c.noDatagram { // what the case stands for: no entry and no resolver admits a datagram, yet the run races one
				for _, n := range rt.Net {
					if n.Proto != agent.ProtoTCP {
						t.Fatalf("the table admits a datagram: %+v", n)
					}
				}
				if rt.DNS.SystemResolvers() {
					t.Fatal("the table keeps the machine's resolver")
				}
			}
			v := Of(rt, c.tier, "")
			var got *Rule
			for _, r := range v.Group(GroupNetwork).Rules {
				if r.Key == "built-in.datagrams" {
					got = &r
				}
			}
			if (got != nil) != c.want {
				t.Fatalf("datagram row %+v, want one: %v\n%s", got, c.want, v.Text())
			}
			if got != nil && (got.Effect != EffectDeny || got.State != StateBestEffort || got.Enforced || got.EnforcedText != textDatagram ||
				got.Source.Origin != OriginBuiltIn || got.Sentence != "Cannot send datagrams anywhere it may not connect") {
				t.Errorf("datagram row %+v", got)
			}
			if strings.HasPrefix(c.body, "net:\n  allow: []\n") && v.Group(GroupNetwork).Default != "Cannot connect anywhere." {
				t.Errorf("the row changed the default: %q", v.Group(GroupNetwork).Default)
			}
			d, err := Declared([]byte(head+c.body), "agent.yaml")
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range d.Rules() {
				if r.Key == "built-in.datagrams" {
					t.Errorf("read as text, the view names a tier's residual: %+v", r)
				}
			}
		})
	}
}

// TestOpenDefaults: a group's default is marked Open exactly where it leaves the agent wide open (any program, any
// address, every variable of the shell), compiled or read as text, so a view marks it by the flag and never by the
// sentence's words; the read default never is.
func TestOpenDefaults(t *testing.T) {
	const head = "version: 0\nname: o\ncommand: [\"bash\", \"agent.sh\"]\n"
	for _, c := range []struct {
		name, body string
		open       []string
	}{
		{"nothing narrowed", "", []string{GroupPrograms, GroupNetwork, GroupEnv}},
		{"host sockets", "host_sockets: true\nexec:\n  allow: [bash]\nenv:\n  pass: [PATH]\n", []string{GroupNetwork}},
		{"exec deny list", "exec:\n  deny: [\"git push\"]\nnet:\n  allow: []\nenv:\n  pass: [PATH]\n", []string{GroupPrograms}},
		{"all narrowed", "exec:\n  allow: [bash]\nnet:\n  allow: [\"127.0.0.1:1\"]\nenv:\n  pass: [PATH]\n", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			compiled := Of(f.compile(t, head+c.body, nil), backend.TierLandlock, "")
			declared, err := Declared([]byte(head+c.body), "agent.yaml")
			if err != nil {
				t.Fatal(err)
			}
			for name, v := range map[string]View{"compiled": compiled, "declared": declared} {
				var open []string
				for _, g := range v.Groups {
					if g.Open {
						open = append(open, g.ID)
						if g.Default == "" {
							t.Errorf("%s: group %s is open with no default", name, g.ID)
						}
					}
				}
				if !slices.Equal(open, c.open) {
					t.Errorf("%s: open defaults %v, want %v", name, open, c.open)
				}
			}
		})
	}
}

// TestByKernel: ByKernel marks exactly the rules the operating system enforces in full at the run's tier, so a table
// can leave their cells empty without reading the claim's words: not a best-effort rule, not one held by tego, not an
// always-on rule the run gets rather than is kept from, nothing in an observe run or a view read as text.
func TestByKernel(t *testing.T) {
	f := newFixture(t)
	rt := f.compile(t, commandRules, nil)
	ll := Of(rt, backend.TierLandlock, "")
	for _, r := range ll.Rules() {
		if want := r.State == StateEnforced && r.EnforcedText == textKernel; r.ByKernel != want {
			t.Errorf("%q (%s, %q): ByKernel %v, want %v", r.Sentence, r.State, r.EnforcedText, r.ByKernel, want)
		}
	}
	if r := findRule(t, &ll, "fs.write", "./out/"); !r.ByKernel {
		t.Errorf("a write entry at landlock is the kernel's: %+v", r)
	}
	if r := findRule(t, &ll, "exec.allow", "git status"); r.ByKernel {
		t.Errorf("a command pattern is best effort, not the kernel's: %+v", r)
	}
	if r := findRule(t, &ll, "built-in.route-read", ""); r.ByKernel {
		t.Errorf("an always-on grant makes no claim: %+v", r)
	}
	ob := Of(rt, backend.TierObserve, "")
	d, err := Declared([]byte(commandRules), "agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]View{"observe": ob, "declared": d} {
		for _, r := range v.Rules() {
			if r.ByKernel {
				t.Errorf("%s: %q is marked the kernel's", name, r.Sentence)
			}
		}
	}
}

// TestDeclaredBadShapes: text that is YAML but not a contract still gives a view, never a panic.
func TestDeclaredBadShapes(t *testing.T) {
	for _, text := range []string{"", "- a\n- b\n", "fs: 3\nexec: [x]\nnet: {allow: x}\nenv: {set: [a]}\nlimits: {wall: [1]}\n",
		"net: {http: [3, {host: [1], allow: x}], ingress: [1, {from: [2]}]}\ngate: {rules: [[], {a: b}]}\n", "gate: 3\nnet: {http: x, ingress: y}\n"} {
		v, err := Declared([]byte(text), "x.yaml")
		if err != nil && !errors.Is(err, errNotMapping) {
			t.Errorf("Declared(%q): %v", text, err)
		}
		if len(v.Groups) != len(GroupOrder) {
			t.Errorf("Declared(%q): %d groups", text, len(v.Groups))
		}
	}
}

func TestBuiltinRefusalsAreSeparateAlwaysOnRules(t *testing.T) {
	f := newFixture(t)
	text := "version: 0\nname: builtin-view\ncommand: [bash]\nfs:\n  write: [./out/]\n  deny_read: []\n  deny_write: []\nhost_sockets: true\n"
	rt := f.compile(t, text, nil)
	for _, tt := range []struct {
		tier  backend.Tier
		plane string
		ipc   bool
	}{{backend.TierLandlock, "", false}, {backend.TierCgroup, "fanotify", false}, {backend.TierCgroup, "fmod_ret", true}, {backend.TierBPFLSM, "lsm", true}, {backend.TierObserve, "", false}} {
		view := Of(rt, tt.tier, tt.plane)
		for _, id := range []string{agent.BuiltinHostIPC, agent.BuiltinTegoSurface, agent.BuiltinOtherTTY} {
			row := findRule(t, &view, id, "")
			want := tt.ipc
			if id == agent.BuiltinOtherTTY {
				want = tt.tier != backend.TierObserve
			}
			if row.RuleKey != id || row.Group != GroupAlwaysOn || row.Editable || row.Enforced != want {
				t.Errorf("%s/%s: %+v", tt.tier, id, row)
			}
			if Words(id) == id {
				t.Errorf("missing built-in label for %s", id)
			}
		}
	}
	declared, err := Declared([]byte(text), "agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{agent.BuiltinHostIPC, agent.BuiltinTegoSurface, agent.BuiltinOtherTTY} {
		row := findRule(t, &declared, id, "")
		if row.Enforced {
			t.Errorf("text-only view claims enforcement: %+v", row)
		}
	}
}
