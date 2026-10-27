// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func scoped(t *testing.T, contract string, e *record.Event, a Action, mod func(*Request)) (*Result, error) {
	t.Helper()
	r := Request{Contract: []byte(contract), ContractPath: cpath, Home: "/home/u", Event: e, Action: a, Date: "2026-10-26"}
	mod(&r)
	return Apply(r)
}

func TestAncestors(t *testing.T) {
	for _, c := range []struct {
		file, cwd, home string
		want            []string
	}{
		{"/p/proj/a/b/c.txt", "/p/proj", "/home/u", []string{"/p/proj/a/b/c.txt", "/p/proj/a/b", "/p/proj/a", "/p/proj"}},
		{"/home/u/s/k.pem", "/p/proj", "/home/u", []string{"/home/u/s/k.pem", "/home/u/s", "/home/u"}},
		{"/etc/x/y", "/p/proj", "/home/u", []string{"/etc/x/y", "/etc/x"}},
		{"/x", "/p/proj", "/home/u", []string{"/x"}},
	} {
		if got := Ancestors(c.file, c.cwd, c.home); !slices.Equal(got, c.want) {
			t.Errorf("Ancestors(%s) = %v, want %v", c.file, got, c.want)
		}
	}
}

// TestLevelNamesTheAncestorPicked: a level names exactly that folder, never past the run's working directory or
// home, and lifting a deny entry at a level never lifts more than that folder.
func TestLevelNamesTheAncestorPicked(t *testing.T) {
	read := ev(t, record.KindFS, record.VerdictAllow, "unmatched", "", record.FSPayload{Op: "open", Path: "/p/proj/a/b/c.txt"})
	res, err := scoped(t, base, read, Block, func(r *Request) { r.Level = 2 })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res.Text), "- ./a/ # from run r-1 line #7, 2026-10-26") || !strings.Contains(res.Effect, "files under /p/proj/a/") {
		t.Fatalf("level 2:\n%s\n%s", res.Text, res.Effect)
	}
	if res, err = scoped(t, base, read, Ask, func(r *Request) { r.Level = 1 }); err != nil || !strings.Contains(string(res.Text), "ask_read:\n    - ./a/b/") {
		t.Fatalf("ask level 1: %v\n%v", err, res)
	}
	if _, err := scoped(t, base, read, Block, func(r *Request) { r.Level = 4 }); !errors.Is(err, ErrRefused) {
		t.Fatalf("level past the working directory: %v", err)
	}
	// A write at level 2 adds deny_write for that folder.
	write := ev(t, record.KindFS, record.VerdictAllow, "fs.write[./out/]", "", record.FSPayload{Op: "open", Path: "/p/proj/out/x/y.txt", Flags: 0o1101})
	if res, err = scoped(t, base, write, Block, func(r *Request) { r.Level = 2 }); err != nil || !strings.Contains(string(res.Text), "deny_write:\n    - ./out/") {
		t.Fatalf("write level 2: %v\n%v", err, res)
	}
	// Never widen: the refusal came from ./a/b/; allowing ./a/ (level 2) would lift more than the entry... and the
	// entry covers less than the folder picked, so removing it is refused; at level 1 it is the exact entry.
	denied := `version: 0
name: demo
command: [sh]
fs:
  deny_read:
    - ./a/b/
tier: landlock
`
	refused := ev(t, record.KindRefused, "", "fs.deny_read[./a/b/]", record.ReasonReadDenied, record.RefusedPayload{Op: "open", Target: "/p/proj/a/b/c.txt"})
	if _, err := scoped(t, denied, refused, Allow, func(r *Request) { r.Level = 2 }); !errors.Is(err, ErrRefused) {
		t.Fatalf("allow at level 2 lifted ./a/b/: %v", err)
	}
	if res, err = scoped(t, denied, refused, Allow, func(r *Request) { r.Level = 1 }); err != nil || strings.Contains(string(res.Text), "./a/b/") {
		t.Fatalf("allow at level 1: %v\n%v", err, res)
	}
	// Level and Folder agree.
	a, _ := scoped(t, base, read, Block, func(r *Request) { r.Level = 1 })
	b, _ := scoped(t, base, read, Block, func(r *Request) { r.Folder = true })
	if a == nil || b == nil || string(a.Text) != string(b.Text) {
		t.Fatal("level 1 and folder differ")
	}
	// A level is a read or write's scope only.
	exe := ev(t, record.KindExec, record.VerdictAllow, "exec[sh]", "", record.ExecPayload{Path: "/usr/bin/cat", Argv: []string{"cat", "x"}})
	if _, err := scoped(t, base, exe, Block, func(r *Request) { r.Level = 2 }); !errors.Is(err, ErrRefused) {
		t.Fatalf("level on an exec: %v", err)
	}
}

func TestCommand(t *testing.T) {
	for _, c := range []struct {
		argv    []string
		want    string
		grammar bool
	}{
		{[]string{"git", "push", "origin", "main"}, "git push", true},
		{[]string{"git", "-C", ".", "push"}, "git push", true},
		{[]string{"git", "status"}, "git status", true},
		{[]string{"git"}, "", false},
		{[]string{"make", "test"}, "make test", false},
		{[]string{"make", "-j4"}, "", false},
		{[]string{"make", "a b"}, "", false},
	} {
		got, g := Command("/usr/bin/"+c.argv[0], c.argv)
		if got != c.want || got != "" && g != c.grammar {
			t.Errorf("Command(%v) = %q, %v; want %q, %v", c.argv, got, g, c.want, c.grammar)
		}
	}
}

const gitContract = `version: 0
name: demo
command: [sh, agent.sh]
exec:
  allow:
    - sh
    - git
tier: landlock
`

// TestCommandRule: block of the command adds an exec.deny command entry, so the program's other commands still run;
// allow lifts only a command entry of this file that refused the event; ask has no form.
func TestCommandRule(t *testing.T) {
	push := ev(t, record.KindExec, record.VerdictAllow, "exec[git]", "", record.ExecPayload{Path: "/usr/bin/git", Argv: []string{"git", "push", "origin"}})
	res, err := scoped(t, gitContract, push, Block, func(r *Request) { r.Command = true })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res.Text), "  deny:\n    - git push # from run r-1 line #7, 2026-10-26") || !strings.Contains(string(res.Text), "    - git\n") {
		t.Fatalf("block git push:\n%s", res.Text)
	}
	if !strings.Contains(res.Effect, "other git commands still run") {
		t.Errorf("effect %q", res.Effect)
	}
	if _, err := scoped(t, gitContract, push, Ask, func(r *Request) { r.Command = true }); !errors.Is(err, ErrRefused) {
		t.Fatalf("ask a command: %v", err)
	}
	bare := ev(t, record.KindExec, record.VerdictAllow, "exec[git]", "", record.ExecPayload{Path: "/usr/bin/git", Argv: []string{"git"}})
	if _, err := scoped(t, gitContract, bare, Block, func(r *Request) { r.Command = true }); !errors.Is(err, ErrRefused) {
		t.Fatalf("a bare program has no command: %v", err)
	}
	// The run's own command is never blocked.
	own := ev(t, record.KindExec, record.VerdictAllow, "exec[sh]", "", record.ExecPayload{Path: "/bin/sh", Argv: []string{"sh", "agent.sh"}})
	if _, err := scoped(t, gitContract, own, Block, func(r *Request) { r.Command = true }); !errors.Is(err, ErrRefused) {
		t.Fatalf("own command: %v", err)
	}
	// Allow lifts the command entry that refused the event, and nothing broader.
	denied := strings.Replace(gitContract, "tier:", "  deny:\n    - git push\n    - git\ntier:", 1)
	refused := ev(t, record.KindRefused, "", "exec.deny[git push]", record.ReasonExecNotAllowed, record.RefusedPayload{Op: "exec", Target: "/usr/bin/git"})
	if res, err = scoped(t, denied, refused, Allow, func(r *Request) { r.Command = true }); err != nil || strings.Contains(string(res.Text), "git push") ||
		!strings.Contains(string(res.Text), "    - git\n") {
		t.Fatalf("allow git push: %v\n%v", err, res)
	}
	whole := ev(t, record.KindRefused, "", "exec.deny[git]", record.ReasonExecNotAllowed, record.RefusedPayload{Op: "exec", Target: "/usr/bin/git"})
	if _, err := scoped(t, denied, whole, Allow, func(r *Request) { r.Command = true }); !errors.Is(err, ErrRefused) {
		t.Fatalf("allow as a command lifted a whole-program entry: %v", err)
	}
	// A contract with no exec list is refused: exec.deny alone would open every other program.
	if _, err := scoped(t, "version: 0\nname: d\ncommand: [sh]\ntier: landlock\n", push, Block, func(r *Request) { r.Command = true }); !errors.Is(err, ErrRefused) {
		t.Fatalf("no exec list: %v", err)
	}
}

const netContract = `version: 0
name: demo
command: [sh]
net:
  allow:
    - api.example.com:443
    - api.example.com:80
    - other.example.com:443
tier: landlock
`

// TestHostRule: block of the whole host removes every entry of this file for it and no other host's; allow and ask
// have no any-port form.
func TestHostRule(t *testing.T) {
	conn := ev(t, record.KindNet, record.VerdictAllow, "net[api.example.com:443]", "", record.NetPayload{Op: "connect", Dst: "1.2.3.4:443", Host: "api.example.com"})
	res, err := scoped(t, netContract, conn, Block, func(r *Request) { r.HostOnly = true })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(res.Text), "api.example.com") || !strings.Contains(string(res.Text), "other.example.com:443") {
		t.Fatalf("host block:\n%s", res.Text)
	}
	for _, a := range []Action{Allow, Ask} {
		if _, err := scoped(t, netContract, conn, a, func(r *Request) { r.HostOnly = true }); !errors.Is(err, ErrRefused) {
			t.Errorf("%s host: %v", a, err)
		}
	}
	// An allow the file does not spell is never changed.
	builtin := ev(t, record.KindNet, record.VerdictAllow, "net[profile.example.com:443]", "", record.NetPayload{Op: "connect", Dst: "1.2.3.4:443", Host: "profile.example.com"})
	if _, err := scoped(t, netContract, builtin, Block, func(r *Request) { r.HostOnly = true }); !errors.Is(err, ErrRefused) {
		t.Fatalf("builtin: %v", err)
	}
	// The host:port scope still blocks the one destination only.
	if res, err = scoped(t, netContract, conn, Block, func(r *Request) {}); err != nil || !strings.Contains(string(res.Text), "api.example.com:80") {
		t.Fatalf("one destination: %v\n%v", err, res)
	}
}

// TestScopesCompile: the real compiler takes what each new scope makes (an ancestor folder, an exec command rule).
func TestScopesCompile(t *testing.T) {
	dir := t.TempDir()
	proj := filepath.Join(dir, "proj")
	deep := filepath.Join(proj, "data", "nested")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(deep, "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cp := filepath.Join(proj, "agent.yaml")
	check := func(b []byte) error {
		c, _, err := agent.LoadBytes(cp, b, nil)
		if err != nil {
			return err
		}
		_, _, err = agent.Compile(c, config.Builtin(), agent.WithPATH("/usr/bin:/bin"), agent.WithCwd(proj), agent.Offline())
		return err
	}
	if err := check([]byte(gitContract)); err != nil {
		t.Skipf("the fixture does not compile here: %v", err)
	}
	read := ev(t, record.KindFS, record.VerdictAllow, "unmatched", "", record.FSPayload{Op: "open", Path: file})
	res, err := Apply(Request{Contract: []byte(gitContract), ContractPath: cp, Cwd: proj, Event: read, Action: Block, Level: 2, Date: "d", Check: check})
	if err != nil || !strings.Contains(string(res.Text), "- ./data/ #") {
		t.Fatalf("level 2: %v\n%v", err, res)
	}
	push := ev(t, record.KindExec, record.VerdictAllow, "exec[git]", "", record.ExecPayload{Path: "/usr/bin/git", Argv: []string{"git", "push"}})
	if _, err = Apply(Request{Contract: res.Text, ContractPath: cp, Cwd: proj, Event: push, Action: Block, Command: true, Date: "d", Check: check}); err != nil {
		t.Fatalf("git push: %v", err)
	}
	// A text the compiler refuses is never returned, for a new scope too.
	if _, err = Apply(Request{Contract: []byte(gitContract), ContractPath: cp, Cwd: proj, Event: push, Action: Block, Command: true,
		Check: func([]byte) error { return errors.New("no") }}); !errors.Is(err, ErrRefused) {
		t.Fatalf("refused text returned: %v", err)
	}
}

// TestAllowRefusesSystemFolder (CR-04): a write outside the run's working directory and home offers no folder-level
// Allow, since the folder is a system folder (a write to /dev/null once previewed fs.write += /dev/); Allow of the
// file itself stays, and Block and Ask keep the folder, since they only take away.
func TestAllowRefusesSystemFolder(t *testing.T) {
	for _, file := range []string{"/dev/null", "/etc/x/y"} {
		refused := ev(t, record.KindRefused, "", "unmatched", record.ReasonWriteOutsideContract, record.RefusedPayload{Op: "open", Target: file})
		_, err := scoped(t, base, refused, Allow, func(r *Request) { r.Level = 1 })
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "the folder of "+file+" is a system folder: name the file") {
			t.Errorf("%s: Allow at its folder: %v", file, err)
		}
		res, err := scoped(t, base, refused, Allow, func(r *Request) {})
		if err != nil || !strings.Contains(string(res.Text), "- "+file+" #") {
			t.Errorf("%s: Allow of the file itself: %v\n%v", file, err, res)
		}
		for _, a := range []Action{Block, Ask} {
			if _, err := scoped(t, base, refused, a, func(r *Request) { r.Level = 1 }); err != nil && strings.Contains(err.Error(), "system folder") {
				t.Errorf("%s: %s at its folder refused as a system folder: %v", file, a, err)
			}
		}
		written := ev(t, record.KindFS, record.VerdictAllow, "fs.write["+file+"]", "", record.FSPayload{Op: "open", Path: file, Flags: 0o1101})
		if _, err := scoped(t, base, written, Block, func(r *Request) { r.Level = 1 }); err != nil {
			t.Errorf("%s: Block at its folder: %v", file, err)
		}
	}
	// Inside the working directory the folder stays offered.
	inside := ev(t, record.KindRefused, "", "unmatched", record.ReasonWriteOutsideContract, record.RefusedPayload{Op: "open", Target: "/p/proj/logs/a.txt"})
	if res, err := scoped(t, base, inside, Allow, func(r *Request) { r.Level = 1 }); err != nil || !strings.Contains(string(res.Text), "- ./logs/ #") {
		t.Errorf("a write in the project: Allow at its folder: %v\n%v", err, res)
	}
}
