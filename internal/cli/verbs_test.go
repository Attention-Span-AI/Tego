// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestGroupedHelp: tego --help is the grouped text (testdata/help.golden), and it names every command a person can
// type, so a command added without a place in it fails here.
func TestGroupedHelp(t *testing.T) {
	code, out, errs := run(t, "--help")
	if code != identity.ExitOK || errs != "" {
		t.Fatalf("tego --help: exit %d stderr %q", code, errs)
	}
	golden := filepath.Join("testdata", "help.golden")
	if *updateGolden {
		if err := os.WriteFile(golden, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if out != string(want) {
		t.Errorf("tego --help differs from %s:\n%s", golden, out)
	}
	if _, short, _ := run(t, "-h"); short != out {
		t.Errorf("tego -h differs from tego --help:\n%s", short)
	}
	words := map[string]bool{}
	for _, w := range regexp.MustCompile(`[a-z]+`).FindAllString(out, -1) {
		words[w] = true
	}
	for _, c := range commands() {
		if !c.Hidden && !words[c.Name] {
			t.Errorf("tego --help does not name the command %s", c.Name)
		}
	}
}

// sessionsOf writes n ended sessions of agent name, one an hour apart, and returns their run ids.
func sessionsOf(t *testing.T, root, name string, n int) []string {
	t.Helper()
	var ids []string
	for i := range n {
		ids = append(ids, endedRunAs(t, root, [32]byte{}, name, time.Now().Add(-time.Duration(n-i)*time.Hour)))
	}
	return ids
}

func TestGetSessions(t *testing.T) {
	root := gcRoot(t)
	t.Chdir(t.TempDir())
	if code, out, _ := run(t, "get", "sessions"); code != identity.ExitOK || out != "No sessions yet. Start one: tego run AGENT\n" {
		t.Fatalf("no sessions: exit %d stdout %q", code, out)
	}
	ids := sessionsOf(t, root, "tego-sample", 1)
	code, out, errs := run(t, "get", "sessions")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != identity.ExitOK || len(lines) != 2 || !regexp.MustCompile(`^NAME +AGENT +STATUS +AGE +BLOCKED$`).MatchString(lines[0]) ||
		!regexp.MustCompile(`^`+sessionName("tego-sample", ids[0])+` +tego-sample +ended +1h +0$`).MatchString(lines[1]) {
		t.Fatalf("one session: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	ids = append(ids, sessionsOf(t, root, "tego-sample", 1)...)
	_, out, _ = run(t, "get", "sessions")
	if lines = strings.Split(strings.TrimSpace(out), "\n"); len(lines) != 3 ||
		!strings.HasPrefix(lines[1], sessionName("tego-sample", ids[0])+" ") || !strings.HasPrefix(lines[2], sessionName("tego-sample", ids[1])+" ") {
		t.Fatalf("two sessions of one agent:\n%s", out)
	}
	if code, out, _ := run(t, "get", "sessions", "--json"); code != identity.ExitOK || !strings.Contains(out, `"runs":`) || !strings.Contains(out, ids[1]) {
		t.Fatalf("get sessions --json is status --all --json: exit %d\n%s", code, out)
	}
}

// TestSessionNameWorksAsARun: describe, logs, stop and status take a session's name where they take its run id.
func TestSessionNameWorksAsARun(t *testing.T) {
	root := gcRoot(t)
	t.Chdir(t.TempDir())
	ids := sessionsOf(t, root, "tego-sample", 2)
	id := ids[1]
	name := sessionName("tego-sample", id)
	if code, out, errs := run(t, "describe", "session", name); code != identity.ExitOK || !strings.HasPrefix(out, "Receipt for run "+id+" ") {
		t.Errorf("describe session %s: exit %d\nstdout %s\nstderr %s", name, code, out, errs)
	}
	if code, out, errs := run(t, "logs", name, "--json"); code != identity.ExitOK || !strings.Contains(out, `"run":"`+id+`"`) {
		t.Errorf("logs %s: exit %d\nstdout %s\nstderr %s", name, code, out, errs)
	}
	if code, out, errs := run(t, "stop", name); code != identity.ExitOK || out != id+": not running\n" {
		t.Errorf("stop %s: exit %d\nstdout %s\nstderr %s", name, code, out, errs)
	}
	if code, out, errs := run(t, "status", name, "--json"); code != identity.ExitOK || !strings.Contains(out, `"run":"`+id+`"`) {
		t.Errorf("status %s: exit %d\nstdout %s\nstderr %s", name, code, out, errs)
	}
	// Another agent's name with the same four characters names no session.
	other := sessionName("someone-else", id)
	if code, _, errs := run(t, "logs", other); code != identity.ExitUsage {
		t.Errorf("logs %s: exit %d, want 2\nstderr %s", other, code, errs)
	}
	if code, out, errs := run(t, "describe", "session", "--last"); code != identity.ExitOK || !strings.HasPrefix(out, "Receipt for run "+id+" ") {
		t.Errorf("describe session --last: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
}

func TestSessionNameShape(t *testing.T) {
	const id = "r-519c2703-0dmw7w54wuixg-naw97n"
	if got := sessionName("tego-sample", id); got != "tego-sample-w97n" {
		t.Fatalf("sessionName = %q", got)
	}
	if a, end, ok := sessionShape("tego-sample-w97n"); !ok || a != "tego-sample" || end != "w97n" {
		t.Fatalf("sessionShape = %q %q %v", a, end, ok)
	}
	for _, bad := range []string{"w97n", "-w97n", "a-w97", "a-w97nn", "A-w97n", "a/b-w97n"} {
		if _, _, ok := sessionShape(bad); ok {
			t.Errorf("sessionShape(%q) accepted", bad)
		}
	}
	if got := runMinted(id); got.IsZero() {
		t.Fatal("runMinted read no time")
	}
}

// applyFile writes a rules file named file in dir.
func applyFile(t *testing.T, dir, file, text string) string {
	t.Helper()
	p := filepath.Join(dir, file)
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestApply(t *testing.T) {
	w := newRegistryWorld(t)
	saved := filepath.Join(w.user, "agents", "helper.yaml")
	good := applyFile(t, w.project, "rules.yaml", "version: 0\nname: helper\ncommand: [\"/bin/sh\"]\n")
	if code, out, errs := run(t, "apply", "-f", good); code != identity.ExitOK || out != "✓ Agent helper configured: "+saved+"\n" {
		t.Fatalf("apply: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	// Again with other rules: replaced.
	good2 := applyFile(t, w.project, "rules2.yaml", "version: 0\nname: helper\ncommand: [\"/bin/true\"]\n")
	if code, _, errs := run(t, "apply", "-f", good2); code != identity.ExitOK {
		t.Fatalf("apply over a saved agent: exit %d\nstderr %s", code, errs)
	}
	if b, _ := os.ReadFile(saved); !strings.Contains(string(b), "/bin/true") {
		t.Fatalf("apply did not replace the saved agent:\n%s", b)
	}
	// --name names it.
	if code, out, errs := run(t, "apply", "-f", good, "--name", "other"); code != identity.ExitOK || !strings.Contains(out, "✓ Agent other configured") {
		t.Fatalf("apply --name: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	if code, out, _ := run(t, "get", "agents"); code != identity.ExitOK || !strings.HasPrefix(out, "NAME ") ||
		!regexp.MustCompile(`(?m)^helper +0$`).MatchString(out) || !regexp.MustCompile(`(?m)^other +0$`).MatchString(out) {
		t.Fatalf("get agents: exit %d\n%s", code, out)
	}
	// A rules file that does not compile: nothing saved, and the agent saved before stays.
	bad := applyFile(t, w.project, "bad.yaml", "version: 0\nname: helper\ncommand: [\"/bin/sh\"]\nnet:\n  allow: [\"not a host\"]\n")
	if code, out, errs := run(t, "apply", "-f", bad); code != identity.ExitFinding || out != "" || !strings.Contains(errs, "✗") {
		t.Fatalf("apply bad: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	if b, _ := os.ReadFile(saved); !strings.Contains(string(b), "/bin/true") {
		t.Fatalf("a refused apply changed the saved agent:\n%s", b)
	}
	// Bad YAML.
	broken := applyFile(t, w.project, "broken.yaml", "version: 0\nname: [\n")
	if code, _, errs := run(t, "apply", "-f", broken); code != identity.ExitFinding || !strings.Contains(errs, "nothing was saved") {
		t.Fatalf("apply broken yaml: exit %d\nstderr %s", code, errs)
	}
	// A rules file that lets its agent change the folder it would be saved in.
	inside := applyFile(t, w.project, "inside.yaml", "version: 0\nname: writer\ncommand: [\"/bin/sh\"]\nfs:\n  write: [\""+w.user+"\"]\n")
	if code, _, errs := run(t, "apply", "-f", inside); code != identity.ExitFinding || !strings.Contains(errs, "a folder the agent may change") {
		t.Fatalf("apply inside its own write folder: exit %d\nstderr %s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(w.user, "agents", "writer.yaml")); err == nil {
		t.Fatal("a refused apply saved the file")
	}
}

func TestDescribeAndEditAgent(t *testing.T) {
	w := newRegistryWorld(t)
	rules := applyFile(t, w.project, "rules.yaml", "version: 0\nname: helper\nextends: [tego/no-prod]\ncommand: [\"/bin/sh\"]\n"+
		"fs:\n  write: [\""+w.project+"/\"]\nnet:\n  allow: [\"api.example.com:443\"]\n")
	if code, _, errs := run(t, "apply", "-f", rules); code != identity.ExitOK {
		t.Fatalf("apply: exit %d\nstderr %s", code, errs)
	}
	code, out, errs := run(t, "describe", "agent", "helper")
	for _, want := range []string{"Agent helper\n", "Rules file:", "Presets:         tego/no-prod\n", "May change:      " + w.project + "/\n",
		"Never reads:     your secret files", "May connect to:  api.example.com:443\n"} {
		if code != identity.ExitOK || !strings.Contains(out, want) {
			t.Errorf("describe agent: exit %d, lacks %q\nstdout %s\nstderr %s", code, want, out, errs)
		}
	}
	if code, _, _ := run(t, "describe", "agent", "nobody"); code != identity.ExitUsage {
		t.Errorf("describe agent nobody: exit %d", code)
	}
	t.Setenv("EDITOR", "true")
	if code, out, errs := run(t, "edit", "agent", "helper"); code != identity.ExitOK || !strings.HasPrefix(out, "✓ Agent helper's rules are valid") {
		t.Errorf("edit: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	saved := filepath.Join(w.user, "agents", "helper.yaml")
	if err := os.WriteFile(filepath.Join(w.project, "ed.sh"), []byte("#!/bin/sh\nprintf 'exec:\\n  allow: 3\\n' >> \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDITOR", filepath.Join(w.project, "ed.sh"))
	if code, out, _ := run(t, "edit", "agent", "helper"); code != identity.ExitFinding || !strings.HasPrefix(out, "✗ "+saved+" has errors") {
		t.Errorf("edit to a broken file: exit %d\nstdout %s", code, out)
	}
}

func TestRemoveAgent(t *testing.T) {
	w := newRegistryWorld(t)
	saved := filepath.Join(w.user, "agents", "helper.yaml")
	save := func() {
		rules := applyFile(t, w.project, "rules.yaml", "version: 0\nname: helper\ncommand: [\"/bin/sh\"]\n")
		if code, _, errs := run(t, "apply", "-f", rules); code != identity.ExitOK {
			t.Fatalf("apply: exit %d\nstderr %s", code, errs)
		}
	}
	answer := func(term bool, typed string) {
		prevTerm, prevIn := stdinIsTerminal, confirmInput
		t.Cleanup(func() { stdinIsTerminal, confirmInput = prevTerm, prevIn })
		stdinIsTerminal = func() bool { return term }
		confirmInput = strings.NewReader(typed)
	}
	save()
	answer(false, "")
	if code, _, errs := run(t, "remove", "agent", "helper"); code != identity.ExitUsage || !strings.Contains(errs, "--yes") {
		t.Fatalf("delete without a terminal: exit %d\nstderr %s", code, errs)
	}
	answer(true, "n\n")
	if code, out, _ := run(t, "remove", "agent", "helper"); code != identity.ExitFinding ||
		!strings.HasPrefix(out, "Remove agent helper ("+saved+")? [y/N] ") {
		t.Fatalf("delete answered no: exit %d\nstdout %s", code, out)
	}
	if _, err := os.Stat(saved); err != nil {
		t.Fatal("a no removed the agent")
	}
	answer(true, "y\n")
	if code, out, _ := run(t, "remove", "agent", "helper"); code != identity.ExitOK || !strings.HasSuffix(out, "✓ Agent helper removed\n") {
		t.Fatalf("delete answered yes: exit %d\nstdout %s", code, out)
	}
	save()
	answer(false, "")
	if code, out, _ := run(t, "remove", "agent", "helper", "--yes"); code != identity.ExitOK || out != "✓ Agent helper removed\n" {
		t.Fatalf("delete --yes: exit %d\nstdout %s", code, out)
	}
	if _, err := os.Stat(saved); err == nil {
		t.Fatal("delete --yes left the file")
	}
	if code, _, _ := run(t, "remove", "agent", "helper", "--yes"); code != identity.ExitUsage {
		t.Fatalf("delete of no agent: exit %d", code)
	}
}

func TestGetPresetsAndDescribePreset(t *testing.T) {
	code, out, _ := run(t, "get", "presets")
	if code != identity.ExitOK || !strings.HasPrefix(out, "NAME") || !strings.Contains(out, "WHAT IT DOES") || !strings.Contains(out, "no-secrets") {
		t.Fatalf("get presets: exit %d\n%s", code, out)
	}
	code, out, _ = run(t, "describe", "preset", "no-prod")
	if code != identity.ExitOK || !strings.Contains(out, "What it does: The agent reaches no network host") || !strings.Contains(out, "  net:") {
		t.Fatalf("describe preset: exit %d\n%s", code, out)
	}
	if code, _, _ := run(t, "describe", "preset", "nope"); code != identity.ExitUsage {
		t.Fatalf("describe preset nope: exit %d", code)
	}
}

func TestAllowIsApprove(t *testing.T) {
	a, b := cmdAllow(), cmdApprove()
	if a.Usage != b.Usage {
		t.Fatalf("allow takes %q, approve %q", a.Usage, b.Usage)
	}
	if code, _, errs := run(t, "allow", "r-1", "q-0123456789abcdef0123456789abcdef"); code != identity.ExitUsage || !strings.Contains(errs, "is not a run id") {
		t.Fatalf("allow a malformed run: exit %d stderr %s", code, errs)
	}
}

// TestAddAgent: tego add agent writes an agent's rules file from a preset, through the same code as tego start, and
// refuses an agent name already taken, an unknown preset and a missing project.
func TestAddAgent(t *testing.T) {
	f := onFixture(t, "fresh")
	noLogins(t)
	fakeProgram(t, "claude")
	app := filepath.Join(f.Home, "app")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "add", "agent", "--project", app, "--preset", "read-only-review")
	if code != identity.ExitOK || !strings.Contains(out, "✓ Agent app added: ~/") || !strings.Contains(out, "cd ~/app && tego run app") {
		t.Fatalf("add: exit %d\n%s\n%s", code, out, errs)
	}
	if code, out, _ := run(t, "add", "agent", "--project", app); code != identity.ExitFinding || !strings.Contains(out, "✗ Agent app already exists") {
		t.Errorf("a taken name: exit %d\n%s", code, out)
	}
	if code, _, errs := run(t, "add", "agent", "--project", app, "--preset", "strict"); code != identity.ExitUsage || !strings.Contains(errs, "base-development") {
		t.Errorf("an unknown preset: exit %d\n%s", code, errs)
	}
	if code, _, errs := run(t, "add", "agent", "other", "--project", filepath.Join(f.Home, "nope")); code != identity.ExitUsage || !strings.Contains(errs, "doesn't exist") {
		t.Errorf("a missing project: exit %d\n%s", code, errs)
	}
}
