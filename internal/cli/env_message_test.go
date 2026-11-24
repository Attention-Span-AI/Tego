// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// envValues are env values of one, two and three bytes and a long one, made of characters no diagnostic uses, so a
// message that holds one of them printed it.
var envValues = []string{"@", "@&", "@&;", "@&;-a-long-secret-value"}

// TestCompileErrorNeverShowsAnEnvValue: at the command line, a compile error or warning about a contract's env
// section never shows a value of any length, wherever the value sits (rule (a) of pkg/spec/identity envtext.go;
// A40). It names the variable; an entry whose name cannot be told from its value is called by its position.
func TestCompileErrorNeverShowsAnEnvValue(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	t.Setenv("PATH", "/usr/bin:/bin") // an inherited PATH's directories are places and are printed: none holds the marker
	for _, c := range []struct {
		name, env string // env is the contract's env section, %s the value
		want      string // what the diagnostics must say
	}{
		{"a set PATH that does not hold the program", "set: {PATH: \"/nonexistent-%s\"}", "env.set PATH (an env.set value is not shown)"},
		{"a value in a name field of set", "set: {\"%s\": x}", "env.set: this entry is not an environment variable name"},
		{"a NAME=value in pass", "pass: [\"TOKEN=%s\"]", "environment entry for variable \"TOKEN\""},
		{"a bare value in pass", "pass: [PATH, \"%s\"]", "env.pass.1: this entry is not an environment variable name"},
		{"a NAME=value in deny", "deny: [\"TOKEN=%s\"]", "environment entry for variable \"TOKEN\""},
		{"a bare value in mask", "mask: [\"%s\"]", "env.mask.0: this entry is not an environment variable name"},
		{"a reserved name", "set: {TEGO_X: \"%s\"}", "TEGO_X"},
		{"a proxy", "set: {HTTP_PROXY: \"%s\"}", "HTTP_PROXY"},
		{"a value that is a list", "set: {TOKEN: [\"%s\"]}", "env.set.TOKEN"},
		{"a value that is a mapping", "set: {TOKEN: {k: \"%s\"}}", "env.set.TOKEN"},
		{"a value given twice", "set: {TOKEN: \"%s\", TOKEN: \"%s\"}", "TOKEN"},
		{"a value with a line break", "set: {TOKEN: \"%s\\nx\"}", "env.set.TOKEN"},
	} {
		for _, v := range envValues {
			t.Run(c.name+"/"+strconv.Itoa(len(v))+" bytes", func(t *testing.T) { // the value is kept out of the test's own paths
				dir := t.TempDir()
				t.Chdir(dir)
				path := filepath.Join(dir, "agent.yaml")
				body := "version: 0\nname: env-message\ncommand: [\"no-such-program-for-this-test\"]\nenv:\n  " + strings.ReplaceAll(c.env, "%s", v) + "\n"
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				code, _, errs := run(t, "compile", path, "--offline")
				if code == identity.ExitOK || !strings.Contains(errs, c.want) {
					t.Fatalf("exit %d, diagnostics lack %q:\n%s", code, c.want, errs)
				}
				if strings.Contains(errs, "@") {
					t.Fatalf("a diagnostic shows the env value %q:\n%s", v, errs)
				}
			})
		}
	}
}

// TestCompileNamesAnInheritedPATH: a PATH the run inherits from the caller is a list of places, so the error that
// did not find a program on it still lists them; and the rule table names an inherited PATH with where it comes from
// instead of printing it, while a PATH the contract sets is shown as the file has it (rules (c) and (d)).
func TestCompileNamesAnInheritedPATH(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "tool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	dir := t.TempDir()
	t.Chdir(dir)
	write := func(body string) string {
		path := filepath.Join(dir, "agent.yaml")
		if err := os.WriteFile(path, []byte("version: 0\nname: path-row\n"+body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if _, _, errs := run(t, "compile", write("command: [\"absent-tool\"]\n"), "--offline"); !strings.Contains(errs, "searched: "+bin) {
		t.Errorf("an inherited PATH's directories are places and were not listed:\n%s", errs)
	}
	code, out, errs := run(t, "compile", write("command: [\"tool\"]\n"), "--offline")
	if code != identity.ExitOK || !strings.Contains(out, "path      PATH, inherited from the caller's environment") || strings.Contains(out, "path      "+bin) {
		t.Errorf("exit %d: the table prints the caller's PATH:\n%s%s", code, out, errs)
	}
	code, out, errs = run(t, "compile", write("command: [\"tool\"]\nenv:\n  set: {PATH: \""+bin+"\"}\n"), "--offline")
	if code != identity.ExitOK || !strings.Contains(out, "path      "+bin) {
		t.Errorf("exit %d: a PATH the contract sets is not shown as the file has it:\n%s%s", code, out, errs)
	}
}
