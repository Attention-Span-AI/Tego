// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/presets"
)

// project makes a project directory holding files (a name ending in / is a folder) and returns it with its symlinks
// resolved, as Options.Dir and Create take it (a TMPDIR may run through a link).
func project(t *testing.T, files ...string) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		p := filepath.Join(dir, filepath.FromSlash(f))
		if strings.HasSuffix(f, "/") {
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// compose composes o and creates the folders the result names, as init does.
func compose(t *testing.T, o Options) *Result {
	t.Helper()
	if o.Name == "" {
		o.Name = "proj"
	}
	r, err := Compose(o)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	for _, d := range r.MakeDirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

// compile loads and compiles contract bytes as agent.yaml in dir, offline, home standing in for the user's, from
// dir: a contract's relative paths resolve against the run's cwd.
func compile(t *testing.T, dir, home string, contract []byte) *agent.RuleTable {
	t.Helper()
	t.Chdir(dir)
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, contract, 0o644); err != nil {
		t.Fatal(err)
	}
	c, ds, err := agent.Load(path, (&agent.ProfileChain{}).WithBuiltin(presets.Source{}))
	if err != nil || agent.HasErrors(ds) {
		t.Fatalf("Load: %v %v\n%s", err, ds, contract)
	}
	rt, ds, err := agent.Compile(c, config.Builtin(), agent.Offline(), agent.WithHome(home), agent.WithPATH("/usr/bin:/bin"))
	if err != nil || agent.HasErrors(ds) {
		t.Fatalf("Compile: %v %v\n%s", err, ds, contract)
	}
	return rt
}

// TestEveryCombinationComposesAndCompiles: each of the seven non-empty preset combinations composes into a
// contract that extends them in catalog order and loads and compiles with no error.
func TestEveryCombinationComposesAndCompiles(t *testing.T) {
	all := presets.List()
	for mask := 1; mask < 1<<len(all); mask++ {
		var names, refs []string
		for i, p := range all {
			if mask&(1<<i) != 0 {
				names = append(names, p.Name)
				refs = append(refs, p.Ref())
			}
		}
		// The list is given in reverse to show the order is the catalog's, not the flag's.
		rev := append([]string(nil), names...)
		for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
			rev[i], rev[j] = rev[j], rev[i]
		}
		t.Run(strings.Join(names, ","), func(t *testing.T) {
			dir := project(t, "src/")
			r := compose(t, Options{Presets: []string{strings.Join(rev, ",")}, Writes: []string{"src"}, Hosts: []string{"127.0.0.1:8080"}, Dir: dir})
			if want := "extends: [" + strings.Join(refs, ", ") + "]\n"; !strings.Contains(string(r.Contract), want) {
				t.Errorf("no %q in\n%s", want, r.Contract)
			}
			if !strings.HasPrefix(string(r.Contract), Marker) {
				t.Errorf("the contract does not open with the init marker:\n%s", r.Contract)
			}
			compile(t, dir, t.TempDir(), r.Contract)
		})
	}
}

// TestNoSecretsDenyListCoversSecrets: under tego/no-secrets the compiled deny_read list holds the project's .env
// files, SSH keys, cloud credentials and token stores, and env.pass is the preset's allow-list, so a credential
// variable is not passed.
func TestNoSecretsDenyListCoversSecrets(t *testing.T) {
	home := project(t, ".ssh/id_ed25519", ".aws/credentials", ".config/gcloud/credentials.db", ".kube/config",
		".config/gh/hosts.yml", ".npmrc", ".git-credentials", ".netrc", ".docker/config.json")
	dir := project(t, ".env", "config/.env.local")
	r := compose(t, Options{Presets: []string{"no-secrets"}, Dir: dir})
	rt := compile(t, dir, home, r.Contract)
	denied := map[string]bool{}
	for _, f := range rt.FS {
		if f.Kind == agent.FSDenyRead {
			denied[f.Path] = true
		}
	}
	for _, want := range []string{
		filepath.Join(dir, ".env"), filepath.Join(dir, "config/.env.local"), // .env files
		filepath.Join(home, ".ssh"),                                                                             // SSH keys
		filepath.Join(home, ".aws"), filepath.Join(home, ".config/gcloud"), filepath.Join(home, ".kube/config"), // cloud credentials
		filepath.Join(home, ".config/gh"), filepath.Join(home, ".npmrc"), filepath.Join(home, ".git-credentials"), // token stores
		filepath.Join(home, ".netrc"), filepath.Join(home, ".docker/config.json"),
	} {
		if !denied[want] {
			t.Errorf("%s is not in deny_read; the list is %v", want, denied)
		}
	}
	if rt.Env == nil {
		t.Fatal("env.pass is unset: the whole environment would pass")
	}
	for _, v := range rt.Env {
		if strings.Contains(v, "TOKEN") || strings.Contains(v, "SECRET") || strings.Contains(v, "KEY") {
			t.Errorf("env.pass passes %s", v)
		}
	}
}

// TestRepoOnlyWritesNeedsAFolder: repo-only-writes with no --write and no marker is a usage error naming --write;
// a marker alone is enough.
func TestRepoOnlyWritesNeedsAFolder(t *testing.T) {
	_, err := Compose(Options{Presets: []string{"repo-only-writes"}, Name: "p", Dir: project(t)})
	if !IsUsage(err) || !strings.Contains(err.Error(), "--write") {
		t.Fatalf("err %v", err)
	}
	dir := project(t, "package.json")
	r := compose(t, Options{Presets: []string{"repo-only-writes"}, Dir: dir})
	if !strings.Contains(squeeze(r.Contract), `"./node_modules/"   # package.json`) {
		t.Errorf("no node_modules entry:\n%s", r.Contract)
	}
	compile(t, dir, t.TempDir(), r.Contract)
}

// TestMarkersAndGroupsExpand: markers add their folders and cache variables; a host group expands into its
// host:port entries with a comment naming it; a bare host, an IPv6 address too, gets :443.
func TestMarkersAndGroupsExpand(t *testing.T) {
	dir := project(t, "go.mod", "Cargo.toml", "requirements-dev.txt", "src/")
	r := compose(t, Options{Presets: []string{"repo-only-writes,no-prod"}, Writes: []string{"./src/"}, Hosts: []string{"@go-proxy", "example.com", "::1", "[::1]:8080"}, Dir: dir})
	s := squeeze(r.Contract)
	for _, want := range []string{
		`"./src/"   # --write`, `"./target/"   # Cargo.toml`, `"./.venv/"   # pyproject.toml`, `"./.tego/cache/"   # go.mod`,
		`"./.tego/tmp/"`, `GOCACHE: "${TEGO_PROJECT_DIR}/.tego/cache/go-build`, `TMPDIR: "${TEGO_PROJECT_DIR}/.tego/tmp`,
		`"proxy.golang.org:443"   # --allow-host @go-proxy`, `"sum.golang.org:443"   # --allow-host @go-proxy`,
		`"example.com:443"   # --allow-host, port 443`, `"[::1]:443"`, `"[::1]:8080"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("no %q in\n%s", want, s)
		}
	}
	compile(t, dir, t.TempDir(), r.Contract)
}

// TestUsageErrorsListTheKnown: an unknown preset or host group is a usage error naming the known ones; a URL is
// not a host; a missing folder outside the project is refused.
func TestUsageErrorsListTheKnown(t *testing.T) {
	dir := project(t, "src/")
	for _, tc := range []struct {
		o    Options
		want string
	}{
		{Options{Presets: []string{"no-secret"}}, "the presets are no-secrets, no-prod, repo-only-writes"},
		{Options{Presets: []string{""}}, "names no preset"},
		{Options{Presets: []string{"no-prod"}, Hosts: []string{"@nope"}}, "the groups are @github, @npm"},
		{Options{Presets: []string{"no-prod"}, Hosts: []string{"https://example.com"}}, "not a URL"},
		{Options{Presets: []string{"no-prod"}, Hosts: []string{"example.com:0"}}, "port"},
		{Options{Presets: []string{"repo-only-writes"}, Writes: []string{"/nonexistent-tego-test/x"}}, "does not exist"},
		{Options{Presets: []string{"repo-only-writes"}, Writes: []string{"src/*"}}, "never a glob"},
	} {
		tc.o.Dir, tc.o.Name = dir, "p"
		_, err := Compose(tc.o)
		if !IsUsage(err) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: err %v, want %q", tc.o, err, tc.want)
		}
	}
}

// TestAbsoluteWriteThroughALinkIsPlacedWhereItLeads: Dir is resolved, and an absolute --write is placed with the links
// of its existing part resolved. One spelled through the link the project was reached by is inside the project and
// written ./x/, as typed relative, a missing one made there; it was outside, and a missing one a usage error. One a
// link in the project leads out of it is outside, and a missing one is a usage error saying where the link places
// it, never a folder to make.
func TestAbsoluteWriteThroughALinkIsPlacedWhereItLeads(t *testing.T) {
	dir := project(t, "src/")
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	r, err := Compose(Options{Presets: []string{"repo-only-writes"}, Writes: []string{filepath.Join(link, "newdir"),
		filepath.Join(link, "src"), link}, Dir: dir, Name: "p"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"./newdir/"`, `"./src/"`, `"./"`} {
		if !strings.Contains(string(r.Contract), want) {
			t.Errorf("the contract lacks %s:\n%s", want, r.Contract)
		}
	}
	if strings.Contains(string(r.Contract), link) {
		t.Errorf("the contract names the link %s:\n%s", link, r.Contract)
	}
	if !slices.Contains(r.MakeDirs, filepath.Join(dir, "newdir")) {
		t.Errorf("MakeDirs = %q, want %s", r.MakeDirs, filepath.Join(dir, "newdir"))
	}

	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	_, err = Compose(Options{Presets: []string{"repo-only-writes"}, Writes: []string{filepath.Join(dir, "out", "x")}, Dir: dir, Name: "p"})
	if !IsUsage(err) || !strings.Contains(err.Error(), "places it at "+filepath.Join(outside, "x")+", outside the project") {
		t.Errorf("a missing folder a link leads out of the project: %v", err)
	}
}

// TestCommandLine: a plain line becomes its words; one with shell syntax runs under /bin/sh -c; no line writes the
// demo, which names the refusals it shows.
func TestCommandLine(t *testing.T) {
	if got := commandArgv("claude --model x"); strings.Join(got, "|") != "claude|--model|x" {
		t.Errorf("plain: %q", got)
	}
	if got := commandArgv("make test && echo ok"); len(got) != 3 || got[0] != "/bin/sh" || got[2] != "make test && echo ok" {
		t.Errorf("shell: %q", got)
	}
	dir := project(t, "src/")
	r := compose(t, Options{Presets: []string{"no-secrets,repo-only-writes"}, Writes: []string{"src"}, Dir: dir})
	for _, want := range []string{"refused by repo-only-writes", "no secret variable reached the agent", "./src/tego-hello.txt"} {
		if !strings.Contains(string(r.Contract), want) {
			t.Errorf("demo lacks %q:\n%s", want, r.Contract)
		}
	}
}

// TestDemoQuotesTheWritePath: a --write folder holding a single quote stays one word in both halves of the demo
// line, the echoed text included.
func TestDemoQuotesTheWritePath(t *testing.T) {
	got := demoCommand(func(n string) bool { return n == "repo-only-writes" }, "./it's/")
	line := strings.SplitN(got, "\n", 2)[0]
	want := `echo hello > './it'\''s/tego-hello.txt' && echo 'wrote ./it'\''s/tego-hello.txt: allowed'`
	if line != want {
		t.Errorf("demo line\n got %s\nwant %s", line, want)
	}
}

// TestWriteToASecretFolderIsNoted: a --write folder that is, holds or lies inside a built-in deny_read path under
// home adds a note naming it; another folder outside the project adds none.
func TestWriteToASecretFolderIsNoted(t *testing.T) {
	home := t.TempDir()
	for _, d := range []string{".ssh/keys", "work"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dir := project(t, "src/")
	for _, tc := range []struct {
		write, want string
	}{
		{"~/.ssh", "reaches ~/.ssh"},
		{"~/.ssh/keys", "reaches ~/.ssh"},
		{"~", "reaches ~/.ssh"},
		{"~/work", ""},
		{"src", ""},
	} {
		r, err := Compose(Options{Name: "p", Presets: []string{"repo-only-writes"}, Writes: []string{tc.write}, Dir: dir, Home: home})
		if err != nil {
			t.Fatalf("%s: %v", tc.write, err)
		}
		notes := strings.Join(r.Notes, "\n")
		if noted := strings.Contains(notes, "built-in deny_read"); noted != (tc.want != "") || !strings.Contains(notes, tc.want) {
			t.Errorf("--write %s: notes\n%s\nwant %q", tc.write, notes, tc.want)
		}
	}
}

// TestAgentNeeds: the dashboard's New contract for Claude Code under all three presets gets Claude's own folder in the
// project, its socket folder, its model host and its login variables, plus the asked-for variables and ask-first
// reads; without AgentNeeds (tego init) none of Claude's needs are added.
func TestAgentNeeds(t *testing.T) {
	dir := t.TempDir()
	o := Options{Presets: []string{"no-secrets", "no-prod", "repo-only-writes"}, Writes: []string{"src/"}, Command: "claude",
		Name: "demo", Dir: dir, Home: "/home/u", Pass: []string{"SERVICE_TOKEN"}, AskRead: []string{"~/.config/telemetry/token"},
		AgentNeeds: true}
	res, err := Compose(o)
	if err != nil {
		t.Fatal(err)
	}
	got := string(res.Contract)
	for _, want := range []string{`"./.tego/claude/"`, "CLAUDE_CONFIG_DIR", `"api.anthropic.com:443"`, `"CLAUDE_CODE_OAUTH_TOKEN"`,
		`"SERVICE_TOKEN"`, "ask_read:", `"/home/u/.config/telemetry/token"`, "timeout: 5m", "tier: landlock", "XDG_RUNTIME_DIR", `"%R"`, `"/dev/tty"`} {
		if !strings.Contains(got, want) {
			t.Errorf("contract lacks %s:\n%s", want, got)
		}
	}
	// Each preset says what its promise now excepts: "Only hosts I list" holds a host nobody listed.
	for preset, want := range map[string]string{"no-prod": "api.anthropic.com:443", "repo-only-writes": "./.tego/claude/", "no-secrets": "ANTHROPIC_API_KEY"} {
		if !slices.Contains(res.Grants[preset], want) {
			t.Errorf("%s's grants %v lack %s", preset, res.Grants[preset], want)
		}
	}
	o.AgentNeeds = false
	res, err = Compose(o)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(res.Contract); strings.Contains(got, "CLAUDE_CONFIG_DIR") || strings.Contains(got, "api.anthropic.com") {
		t.Errorf("tego init's contract got Claude's needs:\n%s", got)
	}
	if res.Grants != nil {
		t.Errorf("tego init's contract names grants: %v", res.Grants)
	}
}

// TestAgentNeedsGrantsOnlyWhatIsAdded: a host the person listed is no grant past the label, and a preset not chosen
// states nothing, though its need went in with the list a chosen one opened.
func TestAgentNeedsGrantsOnlyWhatIsAdded(t *testing.T) {
	res, err := Compose(Options{Presets: []string{"no-prod"}, Hosts: []string{"api.anthropic.com:443"}, Writes: []string{"src/"}, Command: "claude",
		Name: "demo", Dir: t.TempDir(), Home: "/home/u", AgentNeeds: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Grants) != 0 {
		t.Errorf("grants %v, want none: the host was listed, and the writes are no chosen preset's", res.Grants)
	}
}

// TestAgentNeedsTerminal: an interactive agent's terminal is granted as the example contracts grant it: Claude Code draws
// on /dev/tty, and Codex also runs each command in a pseudo-terminal. Another program gets neither.
func TestAgentNeedsTerminal(t *testing.T) {
	for cmd, want := range map[string][]string{
		"claude":            {`"/dev/null"`, `"/dev/tty"`},
		"codex --no-daemon": {`"/dev/null"`, `"/dev/tty"`, `"/dev/ptmx"`, `"/dev/pts/"`},
	} {
		res, err := Compose(Options{Presets: []string{"repo-only-writes"}, Writes: []string{"src/"}, Command: cmd, Name: "demo",
			Dir: t.TempDir(), Home: "/home/u", AgentNeeds: true})
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range want {
			if !strings.Contains(string(res.Contract), w) {
				t.Errorf("%s lacks %s:\n%s", cmd, w, res.Contract)
			}
		}
	}
	res, err := Compose(Options{Presets: []string{"repo-only-writes"}, Writes: []string{"src/"}, Command: "sh", Name: "demo",
		Dir: t.TempDir(), Home: "/home/u", AgentNeeds: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(res.Contract), `"/dev/tty"`) {
		t.Errorf("another program got the terminal:\n%s", res.Contract)
	}
}

// TestReadsWritesTheReasonBlock: Options.Reads writes reason: {reads: on} after the command, in tego learn --reads
// on's words, and the contract compiles with refused reads recorded; without it there is no reason: key, as tego init
// writes it.
func TestReadsWritesTheReasonBlock(t *testing.T) {
	dir := project(t, "src/")
	block := "\nreason:\n  # A read this contract refuses is recorded at tier landlock too, under every record level (" + agent.ReasonReadCost + ").\n  reads: on\n"
	on := compose(t, Options{Presets: []string{"no-secrets"}, Command: "sh", Dir: dir, Name: "p", Reads: true})
	if !strings.Contains(string(on.Contract), "command: [\"sh\"]\n"+block) {
		t.Fatalf("no reason block after the command:\n%s", on.Contract)
	}
	if rt := compile(t, dir, t.TempDir(), on.Contract); rt.ReasonReads != agent.ReasonReadsOn {
		t.Errorf("compiled reason.reads is %q, want on", rt.ReasonReads)
	}
	off := compose(t, Options{Presets: []string{"no-secrets"}, Command: "sh", Dir: dir, Name: "p"})
	if strings.Contains(string(off.Contract), "reason:") {
		t.Errorf("a draft without Reads has a reason: key:\n%s", off.Contract)
	}
}
