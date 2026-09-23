// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"os/exec"
	"strings"
	"testing"
)

// TestCodexConfig pins the file a run's CODEX_HOME holds (RUN-IDENTITY.md, the CODEX_HOME row): the tego
// key first, because a TOML top-level key must precede every table, then the user's own file unchanged.
func TestCodexConfig(t *testing.T) {
	const base = "http://127.0.0.1:41234/v1"
	cases := []struct {
		name string
		user string
		want string
	}{
		{"no user file", "", "openai_base_url = \"" + base + "\"\n"},
		{"the user's file follows", "model = \"gpt-5\"\n[tui]\nx = 1",
			"openai_base_url = \"" + base + "\"\n\nmodel = \"gpt-5\"\n[tui]\nx = 1\n"},
		{"a byte-order mark is not carried into the middle", "\xef\xbb\xbfmodel = \"m\"\n",
			"openai_base_url = \"" + base + "\"\n\nmodel = \"m\"\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(CodexConfig(base, []byte(tc.user)))
			body := got[strings.Index(got, "openai_base_url"):]
			if body != tc.want {
				t.Errorf("CodexConfig = %q, want %q after the comment", body, tc.want)
			}
			if !strings.HasPrefix(got, "#") {
				t.Errorf("CodexConfig = %q, want it to say who wrote it", got)
			}
		})
	}
}

// TestCodexConfigQuotesTheURL: a value is a TOML basic string whatever it holds, so a URL can never end the
// string early and write a key of its own into the file.
func TestCodexConfigQuotesTheURL(t *testing.T) {
	got := string(CodexConfig("http://h/\"\nmodel_provider = \"evil\\", nil))
	want := `openai_base_url = "http://h/\"\u000Amodel_provider = \"evil\\"` + "\n"
	if !strings.HasSuffix(got, want) {
		t.Errorf("CodexConfig = %q, want it to end %q", got, want)
	}
	if strings.Count(got, "\n") != 3 {
		t.Errorf("CodexConfig = %q: a newline in the value became a line of its own", got)
	}
}

// TestCodexConfigIsTOML reads the rendered file with a real TOML parser when the box has one (Python's
// tomllib), so the format is checked against TOML itself and not only against this package's idea of it.
// A user file that sets openai_base_url too must not parse: that is what keeps Codex from starting with
// its traffic routed around the forwarder.
func TestCodexConfigIsTOML(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3 to parse TOML with")
	}
	if exec.Command(py, "-c", "import tomllib").Run() != nil {
		t.Skip("python3 has no tomllib (Python < 3.11)")
	}
	read := func(doc []byte) (string, error) {
		cmd := exec.Command(py, "-c", "import sys, tomllib; print(tomllib.loads(sys.stdin.read())['openai_base_url'], end='')")
		cmd.Stdin = strings.NewReader(string(doc))
		out, err := cmd.Output()
		return string(out), err
	}
	const base = "http://127.0.0.1:41234/v1"
	got, err := read(CodexConfig(base, []byte("model = \"gpt-5\"\n[profiles.fast]\nmodel = \"m\"\n")))
	if err != nil || got != base {
		t.Errorf("tomllib read openai_base_url = %q, %v; want %q", got, err, base)
	}
	odd := "http://h/\"x\\y\tz"
	if got, err := read(CodexConfig(odd, nil)); err != nil || got != odd {
		t.Errorf("tomllib read %q back as %q, %v", odd, got, err)
	}
	if _, err := read(CodexConfig(base, []byte("openai_base_url = \"https://api.openai.com/v1\"\n"))); err == nil {
		t.Error("a user file that sets openai_base_url itself still parsed: Codex would start with its own URL")
	}
}
