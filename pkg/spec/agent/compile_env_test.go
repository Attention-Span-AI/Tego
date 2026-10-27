// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// secretEnviron is a launching environment with secret-looking variables, each value distinctive so a test can
// show it is printed nowhere.
var secretEnviron = []string{
	"PATH=/usr/bin", "HOME=/home/u", "LANG=C.UTF-8",
	"GITHUB_TOKEN=value-gh-0001", "AWS_SECRET_ACCESS_KEY=value-aws-0002", "STRIPE_API_KEY=value-stripe-0003",
	"DB_PASSWORD=value-db-0004", "TOKENIZER_PATH=/opt/tok", "AWS_ACCESS_KEY_ID=AKIDEXAMPLE",
}

func secretEnvDiags(ds []Diagnostic) []Diagnostic {
	var out []Diagnostic
	for _, d := range ds {
		if d.Code == CodeSecretEnv {
			out = append(out, d)
		}
	}
	return out
}

// TestSecretEnvWarnsWhenTheWholeEnvironmentPasses (ADR 0067): a contract with no env.pass passes the launcher's
// whole environment to the agent, so compile names the variables whose names look secret, once, as a warning,
// with the fix. Names that only look alike (TOKENIZER_PATH, AWS_ACCESS_KEY_ID) are not named.
func TestSecretEnvWarnsWhenTheWholeEnvironmentPasses(t *testing.T) {
	f := newFixture(t)
	_, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\n"), WithEnviron(secretEnviron))
	got := secretEnvDiags(ds)
	if len(got) != 1 {
		t.Fatalf("%d secret-env diagnostics, want 1:\n%s", len(got), render(ds))
	}
	d := got[0]
	if d.Severity != SeverityWarning {
		t.Errorf("severity %q, want warning", d.Severity)
	}
	if want := "AWS_SECRET_ACCESS_KEY, DB_PASSWORD, GITHUB_TOKEN, STRIPE_API_KEY"; !strings.Contains(d.Message, want) {
		t.Errorf("message %q does not name %s in order", d.Message, want)
	}
	for _, not := range []string{"TOKENIZER_PATH", "AWS_ACCESS_KEY_ID", "LANG"} {
		if strings.Contains(d.Message, not) {
			t.Errorf("message names %s, which does not look secret: %q", not, d.Message)
		}
	}
	if d.Fix != "add env.pass naming the variables the agent needs" {
		t.Errorf("fix %q", d.Fix)
	}
}

// TestSecretEnvNeverPrintsAValue: the option keeps names only, so no value reaches the compiler, and no diagnostic
// and nothing in the compiled table carries one.
func TestSecretEnvNeverPrintsAValue(t *testing.T) {
	var o compileOptions
	WithEnviron(append([]string{"=C:=x", "NOVALUE"}, secretEnviron...))(&o)
	for _, n := range o.envNames {
		if strings.ContainsAny(n, "=") || strings.HasPrefix(n, "value-") {
			t.Errorf("WithEnviron kept %q, want names only", n)
		}
	}
	if len(o.envNames) != len(secretEnviron)+1 { // "=C:=x" has no name; "NOVALUE" is a name
		t.Errorf("WithEnviron kept %d names: %q", len(o.envNames), o.envNames)
	}
	f := newFixture(t)
	rt, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\n"), WithEnviron(secretEnviron))
	all := render(ds) + fmt.Sprintf("%#v", *rt)
	for _, kv := range secretEnviron {
		v := kv[strings.IndexByte(kv, '=')+1:]
		if strings.HasPrefix(v, "value-") && strings.Contains(all, v) {
			t.Errorf("value %q printed:\n%s", v, render(ds))
		}
	}
}

// TestSecretEnvOrderIsDeterministic: the names come out sorted and once, whatever order the environment lists them
// in and however often one repeats.
func TestSecretEnvOrderIsDeterministic(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python]\n")
	reversed := make([]string, 0, len(secretEnviron)+1)
	for i := len(secretEnviron) - 1; i >= 0; i-- {
		reversed = append(reversed, secretEnviron[i])
	}
	reversed = append(reversed, "GITHUB_TOKEN=again")
	_, a := f.compile(c, WithEnviron(secretEnviron))
	_, b := f.compile(c, WithEnviron(reversed))
	da, db := secretEnvDiags(a), secretEnvDiags(b)
	if len(da) != 1 || len(db) != 1 || da[0].Message != db[0].Message {
		t.Errorf("messages differ by environment order:\n%s\n%s", render(da), render(db))
	}
	if strings.Count(db[0].Message, "GITHUB_TOKEN") != 1 {
		t.Errorf("GITHUB_TOKEN named more than once: %q", db[0].Message)
	}
}

// TestSecretEnvSilentCases: an env.pass list (the author chose what passes, empty included), a contract whose
// env.deny and env.set leave no inherited secret, an environment with none, and a compile given no environment
// warn nothing; a profile's env.pass counts, since the warning reads the merged contract.
func TestSecretEnvSilentCases(t *testing.T) {
	f := newFixture(t)
	f.profiles() // copies testdata/profiles, so the file below joins them
	f.file(filepath.Join(f.root, "profiles", "passes.yaml"), "env:\n  pass: [PATH, GITHUB_TOKEN]\n", 0o644)
	cases := []struct {
		name, yaml string
		environ    []string
	}{
		{"env.pass present", "version: 0\nname: a\ncommand: [python]\nenv:\n  pass: [PATH, HOME, GITHUB_TOKEN]\n", secretEnviron},
		{"env.pass empty", "version: 0\nname: a\ncommand: [python]\nenv:\n  pass: []\n  set: {PATH: \"" + f.bin + "\"}\n", secretEnviron},
		{"env.pass from a profile", "version: 0\nname: a\nextends: passes\ncommand: [python]\n", secretEnviron},
		{"denied and set", "version: 0\nname: a\ncommand: [python]\nenv:\n  deny: [GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY]\n  set: {STRIPE_API_KEY: test, DB_PASSWORD: test}\n", secretEnviron},
		{"no secret names", "version: 0\nname: a\ncommand: [python]\n", []string{"PATH=/usr/bin", "HOME=/h", "TOKENIZER_PATH=/x"}},
		{"no environment given", "version: 0\nname: a\ncommand: [python]\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var extra []CompileOption
			if tc.environ != nil {
				extra = append(extra, WithEnviron(tc.environ))
			}
			_, ds := f.compile(f.load(tc.yaml), extra...)
			if got := secretEnvDiags(ds); len(got) != 0 {
				t.Errorf("secret-env fired:\n%s", render(got))
			}
		})
	}
}

// TestSecretEnvNamesMatch pins the fixed list: the exact names and the suffixes, matched without regard to case,
// a suffix only after a prefix of its own.
func TestSecretEnvNamesMatch(t *testing.T) {
	for name, want := range map[string]bool{
		"GITHUB_TOKEN": true, "GH_TOKEN": true, "NPM_TOKEN": true, "AWS_SECRET_ACCESS_KEY": true,
		"AWS_SESSION_TOKEN": true, "ANTHROPIC_API_KEY": true, "OPENAI_API_KEY": true,
		"CI_JOB_TOKEN": true, "APP_SECRET": true, "DJANGO_SECRET_KEY": true, "PGPASSWORD": false, "DB_PASSWORD": true,
		"X_API_KEY": true, "MINIO_ACCESS_KEY": true, "SSH_PRIVATE_KEY": true, "GOOGLE_APPLICATION_CREDENTIALS": true,
		"github_token": true, "TOKEN": false, "_TOKEN": false, "TOKENIZER_PATH": false, "AWS_ACCESS_KEY_ID": false,
		"PASSWORD_FILE": false, "HOME": false,
	} {
		if got := secretEnvName(name); got != want {
			t.Errorf("secretEnvName(%q) = %v, want %v", name, got, want)
		}
	}
}
