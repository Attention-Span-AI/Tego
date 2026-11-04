// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/cli"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// compiled is the part of `tego compile --json` these tests read.
type compiled struct {
	Capture string            `json:"capture"`
	EnvSet  map[string]string `json:"env_set"`
	FS      []struct {
		Path string `json:"path"`
		Kind string `json:"kind"`
	} `json:"fs"`
	Exec []struct {
		Raw  string `json:"raw"`
		Path string `json:"path"`
		Dir  bool   `json:"dir"`
	} `json:"exec"`
	Net []struct {
		Raw  string `json:"raw"`
		Host string `json:"host"`
	} `json:"net"`
}

// writes lists the compiled write entries.
func (c compiled) writes() []string {
	var out []string
	for _, f := range c.FS {
		if f.Kind == "write" {
			out = append(out, f.Path)
		}
	}
	return out
}

// standIn is a stand-in machine: the project directory a contract runs from, the home and PATH directory of its user,
// the profiles directory and price table its machine config names, and the environment compile runs with there.
type standIn struct {
	work, home, bin, profiles, prices string
	env                               map[string]string
}

// bareMachine is a machine that has the agents' own tools and nothing else of a developer's: a PATH of stand-in
// executables for every tool an example names (compile resolves each one, R8), an empty home and project directory, a
// runtime directory, and a machine config that names a ledger root outside every write entry, and a profiles
// directory and a price table that do not exist, as a fresh machine's ~/.tego/profiles and ~/.tego/prices.yaml do
// not. Naming them also keeps the invoking user's own out of the test: tego finds ~/.tego through the passwd entry,
// not $HOME.
func bareMachine(t *testing.T) standIn {
	t.Helper()
	base := t.TempDir()
	// config.Load skips a layer whose directory others may write; t.TempDir is 0775 under umask 002.
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	m := standIn{work: filepath.Join(base, "work"), home: filepath.Join(base, "home"), bin: filepath.Join(base, "bin"),
		profiles: filepath.Join(base, "profiles"), prices: filepath.Join(base, "prices.yaml")}
	for _, d := range []string{m.home, m.bin, m.work, runtimeDir(m.work)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stand, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Skipf("no /bin/true to stand in for the agents' tools: %v", err)
	}
	// No `python`: stock Ubuntu and Debian ship python3 alone, so a stand-in for it would hide an example that
	// fails exec-not-on-path there.
	// codex.yaml names the programs a Codex task uses (cat, ls and mkdir beside bash and git); a name compile cannot
	// find on PATH is an exec-not-on-path error.
	for _, name := range []string{"claude", "codex", "bash", "git", "python3", "make", "go", "env", "mcp-postgres", "cat", "ls", "mkdir",
		"touch", "grep", "sed", "head", "tail", "find", "wc", "tr", "sort", "codex-code-mode-host"} {
		if err := os.WriteFile(filepath.Join(m.bin, name), stand, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(base, "config.yaml")
	body := "version: 0\nledger_root: " + filepath.Join(base, "runs") + "\nprofiles: " + m.profiles + "\nprices: " + m.prices + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// XDG_RUNTIME_DIR names the stand-in runtime directory, as a login session names /run/user/<uid>: compile protects
	// tego's runtime parent under it (agent-contract.md R10a, agent.WithRuntimeDir through config.RuntimeDirBases), so an
	// example that grants <runtime>/tego, which place moves a /run/user/<uid>/ grant into, is refused here as it is
	// on a real machine. Without it the check ran only on /run/user/<test uid>, which no rewritten example names, and
	// an example the real compile refuses passed.
	m.env = map[string]string{"HOME": m.home, "PATH": m.bin, "TEGO_CONFIG": cfg, "XDG_RUNTIME_DIR": runtimeDir(m.work)}
	return m
}

// machine is the machine most tests compile the examples on: bareMachine with the setup their comments name, short of
// a price table (the profiles under examples/profiles, the SDK's ./.deps, retriever.yaml's ./config, the Codex
// account's files and home; freshSetup), and the ./in directory claude-code.yaml's prompt reads. Its home has no
// ~/.ssh, ~/.aws or ~/.netrc, which many machines lack: the built-in deny_read list covers those wherever they exist,
// and an example that named one in deny_read anyway was refused [path-missing] on a machine without it.
func machine(t *testing.T) standIn {
	t.Helper()
	m := bareMachine(t)
	for _, s := range []setupStep{installProfiles, installSDK, makeConfigDir, codexFiles, codexChatGPTHome} {
		s.do(t, m)
	}
	if err := os.MkdirAll(filepath.Join(m.work, "in"), 0o755); err != nil {
		t.Fatal(err)
	}
	return m
}

// runtimeDir is the directory a contract's /run/user/<uid>/ stands for on the stand-in machine: next to the work
// directory, made by bareMachine, since compile refuses a write entry whose parent does not exist and a test
// machine's user need not be the uid an example names, or have a session at all.
func runtimeDir(work string) string { return filepath.Join(filepath.Dir(work), "xdg") }

// runtimeUserDir matches the /run/user/<uid>/ prefix of a path an example grants.
var runtimeUserDir = regexp.MustCompile(`"/run/user/[0-9]+/`)

// pkgDir is this package's directory, where the examples are: place changes the current directory, and a
// test may place more than one example.
var pkgDir, _ = os.Getwd()

// place writes an example, with paths that name a real machine's layout rewritten into the test's, next to
// the work directory of a new machine, makes the work directory the current one, and returns the written file's path.
// name is relative to this package's directory, so a contract elsewhere in the repository (test/poc) can be placed
// too; the copy keeps its base name.
func place(t *testing.T, name string, rewrite ...string) string {
	t.Helper()
	return placeOn(t, machine(t), name, rewrite...)
}

// placeOn is place on the stand-in machine m.
func placeOn(t *testing.T, m standIn, name string, rewrite ...string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(pkgDir, name))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range m.env {
		t.Setenv(k, v)
	}
	t.Chdir(m.work)
	y := strings.ReplaceAll(strings.NewReplacer(rewrite...).Replace(string(src)), "@WORK@", m.work)
	// compile expands ~ against the invoking user's own home, not $HOME; the test's home stands in for it.
	y = strings.ReplaceAll(y, `"~/`, `"`+m.home+`/`)
	// The Codex examples name the user's home (/home/USER/) and the helper directory Codex's installation holds
	// (/CHANGE/, which the example tells the reader to replace); the stand-in machine's home and PATH directory stand in.
	y = strings.ReplaceAll(y, "/home/USER/", m.home+"/")
	y = strings.ReplaceAll(y, "/path/to/project/", m.work+"/")
	y = strings.ReplaceAll(y, "/CHANGE/codex-code-mode-host", filepath.Join(m.bin, "codex-code-mode-host"))
	// The same for the runtime directory: the stand-in machine's own, never the uid an example names.
	y = runtimeUserDir.ReplaceAllLiteralString(y, `"`+runtimeDir(m.work)+`/`)
	path := filepath.Join(filepath.Dir(m.work), filepath.Base(name))
	if err := os.WriteFile(path, []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// compile places an example and compiles it, offline. It fails the test on any error diagnostic.
func compile(t *testing.T, name string, rewrite ...string) compiled {
	t.Helper()
	c, _ := compileWarnings(t, name, rewrite...)
	return c
}

// compileWarnings is compile, also returning the diagnostics compile printed.
func compileWarnings(t *testing.T, name string, rewrite ...string) (compiled, string) {
	t.Helper()
	path := place(t, name, rewrite...)
	var out, errb bytes.Buffer
	code := cli.Main([]string{"tego", "compile", path, "--offline", "--json"}, &out, &errb)
	if code != identity.ExitOK {
		t.Fatalf("tego compile %s: exit %d, want only warnings:\n%s", name, code, errb.String())
	}
	var c compiled
	if err := json.Unmarshal(out.Bytes(), &c); err != nil {
		t.Fatalf("compile --json: %v\n%s", err, out.String())
	}
	t.Logf("%s warnings:\n%s", name, errb.String())
	return c, errb.String()
}

// directConnectTable is a `compile --test` table of one action, a connect straight to the model host, in the
// tier the contract compiles to and in each enforcing tier by name, which must all be refused.
const directConnectTable = `version: 0
tests:
  - name: a direct connect to the model host, in the contract's own tier
    action: net.connect
    host_port: api.anthropic.com:443
    expect: refused
  - name: the same in tier landlock
    action: net.connect
    host_port: api.anthropic.com:443
    tier: landlock
    expect: refused
  - name: the same in tier cgroup
    action: net.connect
    host_port: api.anthropic.com:443
    tier: cgroup
    expect: refused
  - name: the same in tier bpflsm
    action: net.connect
    host_port: api.anthropic.com:443
    tier: bpflsm
    expect: refused
`

// requireDirectConnectRefused is R38's "a direct connect around the forwarder is refused" for the Anthropic API.
func requireDirectConnectRefused(t *testing.T, name string) {
	t.Helper()
	requireConnectRefused(t, name, "api.anthropic.com:443")
}

// requireConnectRefused asks the compiled rule table itself, through `compile --test`, which is what a user runs to
// check a contract, whether a direct connect to hostPort is refused in every tier. It fails the test on any row that
// is not refused, so a contract that stops restricting the network (no net: section at all, which
// spec/policy/SEMANTICS.md §1 reads as "deny nothing") fails it.
func requireConnectRefused(t *testing.T, name, hostPort string) {
	t.Helper()
	path := place(t, name)
	table := filepath.Join(filepath.Dir(path), "direct-connect.yaml")
	body := strings.ReplaceAll(directConnectTable, "api.anthropic.com:443", hostPort)
	if err := os.WriteFile(table, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := cli.Main([]string{"tego", "compile", path, "--offline", "--test", table}, &out, &errb); code != identity.ExitOK {
		t.Errorf("a direct connect to %s under %s is not refused in every tier (exit %d):\n%s%s",
			hostPort, name, code, out.String(), errb.String())
	}
}

// TestEveryExampleCompiles is the README's promise for every file here, including a file added later.
func TestEveryExampleCompiles(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(pkgDir, "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no examples: %v", err)
	}
	for _, f := range files {
		f = filepath.Base(f)
		t.Run(f, func(t *testing.T) {
			_, warns := compileWarnings(t, f)
			// A copy-paste starting point carries no rule its own profile already holds, and never two
			// warnings about one entry whose fixes say opposite things.
			if strings.Contains(warns, "[redundant-rule]") {
				t.Errorf("%s has a redundant rule:\n%s", f, warns)
			}
			if n := strings.Count(warns, "[model-direct-bypass]"); n > 1 {
				t.Errorf("%s draws %d model-direct-bypass warnings:\n%s", f, n, warns)
			}
		})
	}
}

// TestClaudeCodeExample pins what lets examples/agents/claude-code.yaml, `claude -p` (docs/FEATURES.md I3,
// P0-DESIGN §12.3), complete its own task under tego, which test/e2e/kt7-two-agents.sh runs: capture through
// the forwarder with Claude Code's nonessential traffic off; a permission mode, without which print mode
// refuses every edit the prompt asks for; /dev/null writable, which the Bash tool redirects into; Claude
// Code's scratch directory moved into the project instead of a grant of all of /tmp, which would contain any
// ledger or contract kept under /tmp; and a direct connect to the model host refused (R38).
func TestClaudeCodeExample(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgDir, "claude-code.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(src, []byte(`"--permission-mode", "acceptEdits"`)) {
		t.Error("the command has no --permission-mode acceptEdits: `claude -p` denies the Write its prompt asks for")
	}
	c := compile(t, "claude-code.yaml")
	if c.Capture != "forwarder" {
		t.Errorf("capture %q, want forwarder: Claude Code's static BoringSSL has no symbols for a uprobe", c.Capture)
	}
	for k, v := range map[string]string{"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "CLAUDE_CODE_TMPDIR": ".claude-state/tmp"} {
		if c.EnvSet[k] != v {
			t.Errorf("env.set %s = %q, want %q", k, c.EnvSet[k], v)
		}
	}
	w := c.writes()
	if !slices.Contains(w, "/dev/null") {
		t.Errorf("fs.write %v lacks /dev/null", w)
	}
	if slices.Contains(w, "/tmp") {
		t.Errorf("fs.write %v grants all of /tmp", w)
	}
	requireDirectConnectRefused(t, "claude-code.yaml")
}

// TestClaudeAgentSDKExampleIsKillTestSevenA pins what kill test 7 (a) names about its contract
// (docs/FEATURES.md "Kill test 7"): capture through the forwarder, Claude Code's nonessential traffic off, the
// SDK's directory granted for the Claude Code binary it bundles, /dev/null writable through base/python-dev,
// and a direct connect to the model host refused (R38).
func TestClaudeAgentSDKExampleIsKillTestSevenA(t *testing.T) {
	c := compile(t, "claude-agent-sdk.yaml")
	if c.Capture != "forwarder" {
		t.Errorf("capture %q, want forwarder: the SDK's bundled Claude Code has no symbols for a uprobe", c.Capture)
	}
	if c.EnvSet["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] != "1" {
		t.Errorf("env.set %v lacks CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1", c.EnvSet)
	}
	deps := false
	for _, e := range c.Exec {
		deps = deps || (e.Raw == "./.deps/" && e.Dir)
	}
	if !deps {
		t.Errorf("exec.allow %v does not grant the ./.deps/ directory the kill test installs the SDK into", c.Exec)
	}
	if w := c.writes(); !slices.Contains(w, "/dev/null") {
		t.Errorf("fs.write %v lacks /dev/null", w)
	}
	requireDirectConnectRefused(t, "claude-agent-sdk.yaml")
}

// TestPythonSDKExampleIsKillTestSevenB pins what kill test 7 (b) runs: capture by uprobes, the model host
// declared where test/e2e/kt7-two-agents.sh moves it to the local stand-in, and allowed directly, since an
// agent read by uprobes speaks TLS to the host itself.
func TestPythonSDKExampleIsKillTestSevenB(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgDir, "anthropic-sdk-python.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"host: api.anthropic.com, port: 443", `"api.anthropic.com:443"`} {
		if !bytes.Contains(src, []byte(want)) {
			t.Errorf("the example no longer contains %s, which kill test 7 (b) rewrites to its stand-in", want)
		}
	}
	if !bytes.Contains(src, []byte("capture: uprobe")) {
		t.Error("the example no longer pins capture: uprobe, which kill test 7 (b) runs")
	}
	c := compile(t, "anthropic-sdk-python.yaml")
	// Compile resolves the contract's auto tier to the highest this build constructs (ADR 0019): a build with
	// tier cgroup, the one kill test 7 (b) runs, keeps uprobe capture, and a tier-1 build lowers it to the
	// forwarder, since tier landlock runs no uprobes.
	want := "uprobe"
	if enforce.Buildable(backend.TierCgroup) != nil {
		want = "forwarder"
	}
	if c.Capture != want {
		t.Errorf("capture %q, want %s", c.Capture, want)
	}
	found := false
	for _, n := range c.Net {
		found = found || strings.Contains(n.Raw, "api.anthropic.com:443")
	}
	if !found {
		t.Errorf("net.allow %v does not name api.anthropic.com:443", c.Net)
	}
}

// TestNoExampleSaysADeclaredBudgetNeverTrips: a tokens, cost_usd or repeats budget a contract
// declares with nothing to count it is refused at launch, 125 [budget-unmetered] (limits-check-doctor-cli.md R32), so
// a starting point's comment that such a budget "never trips" tells an operator the run goes ahead when it is
// refused. Nor may the operator's guide for unattended runs say a budget with nothing to count is not an error.
func TestNoExampleSaysADeclaredBudgetNeverTrips(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(pkgDir, "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no examples: %v", err)
	}
	budget := regexp.MustCompile(`^\s*(tokens|cost_usd|repeats):.*#.*never trips`)
	// A comment's sentence may run over several lines ("tokens, cost_usd and repeats below count
	// NOTHING without this entry;" on one, "an [unenforced] warning, and a run records gap budget-unmetered" on the
	// next), so a block of comment lines is read as one text. One that names a model budget and says what only a
	// machine ceiling's budget gets (an [unenforced] warning, a budget-unmetered gap, a run that goes ahead) says the
	// declared budget's run is not refused.
	modelBudget := regexp.MustCompile(`\b(tokens|cost_usd|repeats)\b`)
	goesAhead := regexp.MustCompile(`\[unenforced\]|gap (what=record )?(why=)?budget-unmetered|goes ahead|never trips`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var block []string
		start := 0
		flush := func() {
			if text := strings.Join(block, " "); modelBudget.MatchString(text) && goesAhead.MatchString(text) {
				t.Errorf("%s:%d says a declared model budget nothing counts is only warned about or goes ahead, but its run is refused, exit 125 [budget-unmetered]: %s",
					filepath.Base(f), start, text)
			}
			block = nil
		}
		for i, line := range strings.Split(string(b), "\n") {
			if budget.MatchString(line) {
				t.Errorf("%s:%d says a declared budget never trips, but its run is refused: %s", filepath.Base(f), i+1, line)
			}
			if c, ok := strings.CutPrefix(strings.TrimSpace(line), "#"); ok {
				if block == nil {
					start = i + 1
				}
				block = append(block, strings.TrimSpace(c))
				continue
			}
			flush()
		}
		flush()
	}
	ops, err := os.ReadFile(filepath.Join(pkgDir, "..", "..", "docs", "OPERATIONS.md"))
	if err != nil {
		t.Fatal(err)
	}
	if s := "A budget with nothing to count is not an error"; strings.Contains(string(ops), s) {
		t.Errorf("docs/OPERATIONS.md still says %q, while a declared budget nothing counts is refused", s)
	}
}
