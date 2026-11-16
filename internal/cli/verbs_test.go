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

// TestHelpPages: each help page is its golden file (go test -run HelpPages -update), and tego help -a names every
// command a person can type, so a command added without a place on it fails here.
func TestHelpPages(t *testing.T) {
	pages := []struct {
		golden string
		args   []string
	}{
		{"help.golden", []string{"help"}},
		{"help-all.golden", []string{"help", "-a"}},
		{"help-rules.golden", []string{"rules"}},
		{"help-session.golden", []string{"session"}},
		{"help-machine.golden", []string{"machine"}},
	}
	for _, p := range pages {
		code, out, errs := run(t, p.args...)
		if code != identity.ExitOK || errs != "" {
			t.Fatalf("tego %s: exit %d stderr %q", strings.Join(p.args, " "), code, errs)
		}
		golden := filepath.Join("testdata", p.golden)
		if *updateGolden {
			if err := os.WriteFile(golden, []byte(out), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if want, err := os.ReadFile(golden); err != nil || out != string(want) {
			t.Errorf("tego %s differs from %s (%v):\n%s", strings.Join(p.args, " "), golden, err, out)
		}
	}
	_, help, _ := run(t, "help")
	for _, args := range [][]string{{"--help"}, {"-h"}} {
		if _, out, _ := run(t, args...); out != help {
			t.Errorf("tego %s differs from tego help:\n%s", args[0], out)
		}
	}
	for _, args := range [][]string{{"rules", "-h"}, {"help", "rules"}, {"session", "--help"}, {"help", "session"}} {
		_, want, _ := run(t, args[0])
		if args[0] == "help" {
			_, want, _ = run(t, args[1])
		}
		if _, out, _ := run(t, args...); out != want {
			t.Errorf("tego %s differs from the noun page:\n%s", strings.Join(args, " "), out)
		}
	}
	_, all, _ := run(t, "help", "-a")
	listed := map[string]bool{}
	for _, l := range strings.Split(all, "\n") {
		if f := strings.Fields(l); strings.HasPrefix(l, "   ") && len(f) > 0 {
			listed[f[0]] = true
		}
	}
	for _, c := range commands() {
		if !c.Hidden && !listed[c.Name] {
			t.Errorf("tego help -a does not list the command %s", c.Name)
		}
	}
}

// TestCommandHelp: every command's -h, and every tree verb's, starts with its usage line under the name typed.
func TestCommandHelp(t *testing.T) {
	for _, c := range commands() {
		if c.Hidden || c.Raw != nil {
			continue
		}
		if code, _, errs := run(t, c.Name, "-h"); code != identity.ExitOK || !strings.HasPrefix(errs, "usage: tego "+c.Name) {
			t.Errorf("tego %s -h: exit %d\n%s", c.Name, code, errs)
		}
	}
	for _, n := range trees() {
		for _, v := range n.verbs {
			name := n.name + " " + v.name
			if code, _, errs := run(t, n.name, v.name, "-h"); code != identity.ExitOK || !strings.HasPrefix(errs, "usage: tego "+name) {
				t.Errorf("tego %s -h: exit %d\n%s", name, code, errs)
			}
			if code, _, errs := run(t, "help", n.name, v.name); code != identity.ExitOK || !strings.HasPrefix(errs, "usage: tego "+name) {
				t.Errorf("tego help %s: exit %d\n%s", name, code, errs)
			}
		}
	}
	if code, _, errs := run(t, "session", "bogus"); code != identity.ExitUsage || !strings.Contains(errs, `unknown command "bogus"`) {
		t.Errorf("tego session bogus: exit %d\n%s", code, errs)
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

func TestSessionList(t *testing.T) {
	root := gcRoot(t)
	t.Chdir(t.TempDir())
	if code, out, _ := run(t, "session", "list"); code != identity.ExitOK || out != "No sessions yet. Start one: tego run AGENT\n" {
		t.Fatalf("no sessions: exit %d stdout %q", code, out)
	}
	ids := sessionsOf(t, root, "tego-sample", 1)
	code, out, errs := run(t, "session", "list")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != identity.ExitOK || len(lines) != 2 || !regexp.MustCompile(`^NAME +AGENT +STATUS +STARTED +BLOCKED$`).MatchString(lines[0]) ||
		!regexp.MustCompile(`^`+sessionName("tego-sample", ids[0])+` +tego-sample +ended +1h ago +0$`).MatchString(lines[1]) {
		t.Fatalf("one session: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	ids = append(ids, sessionsOf(t, root, "tego-sample", 1)...)
	_, out, _ = run(t, "session", "list")
	if lines = strings.Split(strings.TrimSpace(out), "\n"); len(lines) != 3 ||
		!strings.HasPrefix(lines[1], sessionName("tego-sample", ids[0])+" ") || !strings.HasPrefix(lines[2], sessionName("tego-sample", ids[1])+" ") {
		t.Fatalf("two sessions of one agent:\n%s", out)
	}
	if code, out, _ := run(t, "session", "list", "--json"); code != identity.ExitOK || !strings.Contains(out, `"runs":`) || !strings.Contains(out, ids[1]) {
		t.Fatalf("session list --json is status --all --json: exit %d\n%s", code, out)
	}
}

// TestSessionNameWorksAsARun: session show, events, stop and status take a session's name where they take its run id.
func TestSessionNameWorksAsARun(t *testing.T) {
	root := gcRoot(t)
	t.Chdir(t.TempDir())
	ids := sessionsOf(t, root, "tego-sample", 2)
	id := ids[1]
	name := sessionName("tego-sample", id)
	if code, out, errs := run(t, "session", "show", name); code != identity.ExitOK || !strings.HasPrefix(out, "Receipt for run "+id+" ") {
		t.Errorf("session show %s: exit %d\nstdout %s\nstderr %s", name, code, out, errs)
	}
	if code, out, errs := run(t, "events", name, "--json"); code != identity.ExitOK || !strings.Contains(out, `"run":"`+id+`"`) {
		t.Errorf("events %s: exit %d\nstdout %s\nstderr %s", name, code, out, errs)
	}
	if code, out, errs := run(t, "stop", name); code != identity.ExitOK || out != id+": not running\n" {
		t.Errorf("stop %s: exit %d\nstdout %s\nstderr %s", name, code, out, errs)
	}
	if code, out, errs := run(t, "status", name, "--json"); code != identity.ExitOK || !strings.Contains(out, `"run":"`+id+`"`) {
		t.Errorf("status %s: exit %d\nstdout %s\nstderr %s", name, code, out, errs)
	}
	// Another agent's name with the same four characters names no session.
	other := sessionName("someone-else", id)
	if code, _, errs := run(t, "events", other); code != identity.ExitUsage {
		t.Errorf("events %s: exit %d, want 2\nstderr %s", other, code, errs)
	}
	if code, out, errs := run(t, "session", "show", "--last"); code != identity.ExitOK || !strings.HasPrefix(out, "Receipt for run "+id+" ") {
		t.Errorf("session show --last: exit %d\nstdout %s\nstderr %s", code, out, errs)
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

// TestRulesEdit: rules edit saves an edit that checks and keeps the file as it was when the edit has errors.
func TestRulesEdit(t *testing.T) {
	w := newRegistryWorld(t)
	path := filepath.Join(w.project, "agent.yaml")
	const good = "version: 0\nname: helper\ncommand: [\"/bin/sh\"]\n"
	if err := os.WriteFile(path, []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	editor := func(line string) {
		script := filepath.Join(t.TempDir(), "ed.sh")
		if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' '"+line+"' >> \"$1\"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("VISUAL", script)
	}
	editor("net:\n  allow: [\"api.example.com:443\"]")
	if code, out, errs := run(t, "rules", "edit", path); code != identity.ExitOK || out != "✓ Saved and checked "+path+"\n" {
		t.Fatalf("a good edit: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	saved, _ := os.ReadFile(path)
	editor("net:\n  allow: [\"not a host\"]")
	code, out, errs := run(t, "rules", "edit", path)
	if code != identity.ExitFinding || !strings.HasPrefix(out, "✗ Not saved") || errs == "" {
		t.Fatalf("a bad edit: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	if now, _ := os.ReadFile(path); string(now) != string(saved) {
		t.Fatalf("a bad edit changed the file:\n%s", now)
	}
	if b, err := os.ReadFile(path + ".rejected"); err != nil || !strings.Contains(string(b), "not a host") {
		t.Fatalf("the bad edit was not kept: %v", err)
	}
}
