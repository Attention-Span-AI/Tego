// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for in, want := range map[string]Name{"": Auto, "auto": Auto, "claude-code": ClaudeCode, "codex": Codex, "generic": Generic, "none": None} {
		if got, err := Parse(in); err != nil || got != want {
			t.Errorf("Parse(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"claude", "Auto", "none ", "cursor"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}

func TestDetectAndResolve(t *testing.T) {
	for cmd, want := range map[string]Name{
		"/usr/local/bin/claude": ClaudeCode, "claude": ClaudeCode, "/opt/codex": Codex,
		"/usr/bin/python3": Generic, "/usr/bin/claude-wrapper": Generic, "": Generic,
	} {
		if got := Auto.Resolve(cmd); got != want {
			t.Errorf("Auto.Resolve(%q) = %q, want %q", cmd, got, want)
		}
		if got := Name("").Resolve(cmd); got != want {
			t.Errorf(`"".Resolve(%q) = %q, want %q`, cmd, got, want)
		}
	}
	if got := None.Resolve("/usr/bin/claude"); got != None {
		t.Errorf("None.Resolve = %q", got)
	}
	if got := ClaudeCode.Resolve("/bin/sh"); got != ClaudeCode {
		t.Errorf("ClaudeCode.Resolve = %q", got)
	}
}

func TestProvisionCheck(t *testing.T) {
	run := Run{Argv: []string{"/usr/bin/claude", "-p"}, CodexHome: ""}
	ok := Provision{
		Argv:  []string{"/usr/bin/claude", "--settings", "/x", "-p"},
		Env:   []string{"TEGO_CLAUDE_SETTINGS=/x"},
		Files: []File{{Dir: Runtime, Name: "claude-settings.json", Bytes: []byte("{}")}},
		Hook:  &Hook{Argv: []string{"/usr/bin/tego", "hook"}},
	}
	if err := ok.Check(run); err != nil {
		t.Fatalf("good provision refused: %v", err)
	}
	if err := (Provision{}).Check(run); err != nil {
		t.Fatalf("zero provision refused: %v", err)
	}
	cases := map[string]func(p *Provision){
		"slash":      func(p *Provision) { p.Files[0].Name = "a/b" },
		"dotdot":     func(p *Provision) { p.Files[0].Name = ".." },
		"dot":        func(p *Provision) { p.Files[0].Name = "." },
		"empty":      func(p *Provision) { p.Files[0].Name = "" },
		"nul":        func(p *Provision) { p.Files[0].Name = "a\x00b" },
		"twice":      func(p *Provision) { p.Files = append(p.Files, p.Files[0]) },
		"codexhome":  func(p *Provision) { p.Files[0].Dir = CodexHome },
		"baddir":     func(p *Provision) { p.Files[0].Dir = Dir(7) },
		"env-prefix": func(p *Provision) { p.Env = []string{"CLAUDE_SETTINGS=/x"} },
		"env-bare":   func(p *Provision) { p.Env = []string{"TEGO_=x"} },
		"env-noeq":   func(p *Provision) { p.Env = []string{"TEGO_X"} },
		"env-lower":  func(p *Provision) { p.Env = []string{"TEGO_x=1"} },
		"env-twice":  func(p *Provision) { p.Env = []string{"TEGO_X=1", "TEGO_X=2"} },
		"argv0":      func(p *Provision) { p.Argv = []string{"/bin/sh", "-c", "claude"} },
		"argv-empty": func(p *Provision) { p.Argv = []string{} },
		"hook-empty": func(p *Provision) { p.Hook = &Hook{} },
	}
	for name, mutate := range cases {
		p := ok
		p.Files = append([]File(nil), ok.Files...)
		mutate(&p)
		if err := p.Check(run); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	withHome := run
	withHome.CodexHome = "/run/user/1/tego/r/codex"
	p := Provision{Files: []File{{Dir: CodexHome, Name: "hooks.json"}, {Dir: Runtime, Name: "hooks.json"}}}
	if err := p.Check(withHome); err != nil {
		t.Fatalf("same name in two directories refused: %v", err)
	}
}

func TestNamesMatchParseMessage(t *testing.T) {
	_, err := Parse("x")
	for _, n := range Names() {
		if !strings.Contains(err.Error(), string(n)) {
			t.Errorf("Parse's message does not name %s", n)
		}
	}
}
