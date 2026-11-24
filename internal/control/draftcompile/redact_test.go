// SPDX-License-Identifier: Apache-2.0

package draftcompile

import (
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/nextrun"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestCompilerInheritedAssignmentRedaction(t *testing.T) {
	for _, mode := range []string{"one directory", "directory list", "project expansion"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			project, profiles := filepath.Join(root, "project"), filepath.Join(root, "profiles")
			for _, p := range []string{project, profiles} {
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
			}
			first, second := filepath.Join(root, "private-inherited-first"), filepath.Join(root, "private-inherited-second")
			value := first
			switch mode {
			case "directory list":
				value += string(os.PathListSeparator) + second
			case "project expansion":
				value = "${TEGO_PROJECT_DIR}/private-inherited-first"
			}
			if err := os.WriteFile(filepath.Join(profiles, "hidden.yaml"), []byte("env:\n  set:\n    PATH: "+value+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			m := config.Builtin()
			m.Home, m.Profiles.Value = root, profiles
			text := []byte("version: 0\nname: hidden-profile\nextends: hidden\ncommand: [no-such-compiler-redaction-command]\n")
			r := compile(Request{Machine: m, Context: nextrun.Context{Contract: filepath.Join(project, "agent.yaml"), Cwd: project, Home: root, PATH: "/usr/bin:/bin"}, Text: text})
			if r.Error == "" || !strings.Contains(r.Error, "no-such-compiler-redaction-command") {
				t.Fatal("the missing-command diagnostic was lost")
			}
			for _, hidden := range []string{value, first, second, "private-inherited-first", "private-inherited-second"} {
				if strings.Contains(r.Error, hidden) {
					t.Fatal("a hidden inherited assignment appeared in the returned compiler diagnostic")
				}
			}
		})
	}
}

func TestCompilerFailedDependencyLoadRedaction(t *testing.T) {
	root := t.TempDir()
	profiles := filepath.Join(root, "profiles")
	if err := os.Mkdir(profiles, 0700); err != nil {
		t.Fatal(err)
	}
	const hidden = "private-inherited-invalid-map-value"
	if err := os.WriteFile(filepath.Join(profiles, "hidden.yaml"), []byte("env:\n  set: {TOKEN: "+hidden+"}\nlimits: {wall: "+hidden+"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m := config.Builtin()
	m.Home, m.Profiles.Value = root, profiles
	r := compile(Request{Machine: m, Context: nextrun.Context{Contract: filepath.Join(root, "agent.yaml"), Cwd: root, Home: root, PATH: "/usr/bin:/bin"}, Text: []byte("version: 0\nname: hidden-profile\nextends: hidden\ncommand: [sh]\n")})
	if r.Error == "" || strings.Contains(r.Error, hidden) {
		t.Fatal("a failed dependency load exposed its hidden assignment")
	}
}

func TestCompilerOwnFileSchemaDiagnosticPreserved(t *testing.T) {
	root := t.TempDir()
	m := config.Builtin()
	m.Home = root
	r := compile(Request{Machine: m, Context: nextrun.Context{Contract: filepath.Join(root, "agent.yaml"), Cwd: root, Home: root, PATH: "/usr/bin:/bin"}, Text: []byte("version: 0\nname: own-file\ncommand: [sh]\nlimits: {wall: invalid-duration}\n")})
	if !strings.Contains(r.Error, "limits.wall") {
		t.Fatal("the safe own-file schema diagnostic was lost")
	}
}

func TestCompilerMissingCommandWithoutEnvironment(t *testing.T) {
	root := t.TempDir()
	m := config.Builtin()
	m.Home = root
	r := compile(Request{Machine: m, Context: nextrun.Context{Contract: filepath.Join(root, "agent.yaml"), Cwd: root, Home: root, PATH: "/usr/bin:/bin"}, Text: []byte("version: 0\nname: no-environment\ncommand: [no-such-command-without-environment]\n")})
	if !strings.Contains(r.Error, "no-such-command-without-environment") {
		t.Fatal("missing command without environment lost its diagnostic")
	}
}

func TestCompilerQuotedInheritedAssignmentRedaction(t *testing.T) {
	root := t.TempDir()
	profiles := filepath.Join(root, "profiles")
	if err := os.Mkdir(profiles, 0700); err != nil {
		t.Fatal(err)
	}
	const hidden = "private-quoted\"value"
	profile := "command: [" + strconv.Quote(hidden) + "]\nenv:\n  set: {TOKEN: " + strconv.Quote(hidden) + "}\n"
	if err := os.WriteFile(filepath.Join(profiles, "hidden.yaml"), []byte(profile), 0600); err != nil {
		t.Fatal(err)
	}
	m := config.Builtin()
	m.Home, m.Profiles.Value = root, profiles
	r := compile(Request{Machine: m, Context: nextrun.Context{Contract: filepath.Join(root, "agent.yaml"), Cwd: root, Home: root, PATH: "/usr/bin:/bin"}, Text: []byte("version: 0\nname: hidden-profile\nextends: hidden\n")})
	if r.Error == "" || strings.Contains(r.Error, "private-quoted") {
		t.Fatal("a quoted hidden inherited assignment appeared in the returned compiler diagnostic")
	}
}

func TestCompilerRedactionDoesNotRewritePlaceholders(t *testing.T) {
	if got := redactValues("d private-whole-value", []string{"d", "private-whole-value"}); got != "[hidden] [hidden]" {
		t.Fatal("overlapping short assignments rewrote the replacement marker")
	}
}

// Malformed submitted YAML has no trustworthy assignment map. Keep only the
// parser's numeric source location; neither its message nor source text escapes.
func TestCompilerMalformedDraftKeepsOnlyParserLine(t *testing.T) {
	root := t.TempDir()
	m := config.Builtin()
	m.Home = root
	const secret = "private-syntax-message-value"
	text := []byte("version: 0\nname: " + secret + "\n\tcommand: [sh]\n")
	r := compile(Request{Machine: m, Context: nextrun.Context{Contract: filepath.Join(root, "agent.yaml"), Cwd: root, Home: root, PATH: "/usr/bin:/bin"}, Text: text})
	if want := hiddenCompileError + " at line 2"; r.Error != want {
		t.Fatalf("malformed draft diagnostic = %q, want %q", r.Error, want)
	}
	if got := redactLoadError(text, "yaml: line 99: quoted "+secret); got != r.Error {
		t.Fatalf("untrusted diagnostic affected submitted source location: %q", got)
	}
	valid := []byte("version: 0\nextends: hidden-profile\n")
	if got := redactLoadError(valid, "yaml: line 3: quoted "+secret); got != "the draft or an inherited profile could not be loaded; check them in a terminal" {
		t.Fatalf("inherited diagnostic was not fully withheld: %q", got)
	}
}

// A fault in a profile the draft extends names the profile, its file and its line, and never the compiler's words,
// which may quote a value.
func TestInheritedLoadErrorNamesWhereAndNeverWhat(t *testing.T) {
	const secret = "private-profile-value"
	ds := []agent.Diagnostic{
		{File: "/h/profiles/team/base.yaml", Line: 4, Severity: "error", Message: "env.set.TOKEN: " + secret},
		{File: "/p/agent.yaml", Line: 3, Severity: "error", Message: "x " + secret},
		{File: "/h/profiles/team/base.yaml", Line: 4, Severity: "error"},
		{File: "/h/profiles/other.yaml", Line: 2, Severity: "warning"},
	}
	where := inheritedWhere(ds, "/p/agent.yaml", "/h/profiles")
	want := []string{"profile team/base · /h/profiles/team/base.yaml · line 4", "the draft · line 3"}
	if !slices.Equal(where, want) {
		t.Fatalf("where = %q, want %q", where, want)
	}
	got := redactLoadError([]byte("version: 0\nextends: team/base\n"), "error: "+secret, where...)
	if strings.Contains(got, secret) || !strings.Contains(got, want[0]) || !strings.HasPrefix(got, "the draft or an inherited profile could not be loaded") {
		t.Fatalf("%q", got)
	}
}
