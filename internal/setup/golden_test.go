// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/presets"
)

var update = flag.Bool("update", false, "rewrite the golden files under testdata/compose/")

// squeeze is the contract with every run of two or more spaces written as three, so a test names an entry and its
// reason without the column padding.
func squeeze(b []byte) string {
	return regexp.MustCompile(` {2,}`).ReplaceAllString(string(b), "   ")
}

// golden compares got, the project directory written as $PROJECT, with testdata/compose/<name>.golden.
func golden(t *testing.T, name, dir string, got []byte) {
	t.Helper()
	s := strings.ReplaceAll(string(got), dir, "$PROJECT")
	path := filepath.Join("testdata", "compose", name+".golden")
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (go test -run TestComposeGolden ./internal/setup -update writes it)", err)
	}
	if s != string(want) {
		t.Errorf("%s differs from the composed contract (rerun with -update to accept):\n%s", path, s)
	}
}

// TestComposeGolden pins the bytes init writes for every non-empty preset combination, with --write and
// --allow-host, and for the projects whose markers and host groups add entries: each line and its comment are
// part of what the person reads first.
func TestComposeGolden(t *testing.T) {
	all := presets.List()
	for mask := 1; mask < 1<<len(all); mask++ {
		var names []string
		for i, p := range all {
			if mask&(1<<i) != 0 {
				names = append(names, p.Name)
			}
		}
		list := strings.Join(names, ",")
		t.Run(list, func(t *testing.T) {
			dir := project(t, "src/")
			r := compose(t, Options{Presets: []string{list}, Writes: []string{"src"}, Hosts: []string{"127.0.0.1:8080"}, Dir: dir})
			golden(t, strings.ReplaceAll(list, ",", "+"), dir, r.Contract)
		})
	}
	for _, tc := range []struct {
		name  string
		files []string
		o     Options
	}{
		{"markers-node-python", []string{"package.json", "requirements.txt"}, Options{Presets: []string{"repo-only-writes"}}},
		{"markers-go-groups", []string{"go.mod", "src/"}, Options{Presets: []string{"no-secrets,no-prod,repo-only-writes"}, Writes: []string{"src"}, Hosts: []string{"@github", "@go-proxy"}, Command: "claude"}},
		{"no-prod-no-hosts", nil, Options{Presets: []string{"no-prod,no-secrets"}, Command: "make test && echo ok"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := project(t, tc.files...)
			tc.o.Dir = dir
			r := compose(t, tc.o)
			golden(t, tc.name, dir, r.Contract)
			if tc.o.Command == "" || tc.o.Command == "make test && echo ok" {
				compile(t, dir, t.TempDir(), r.Contract) // claude is not on a test machine's PATH
			}
		})
	}
}

// TestDraftCreatesNothingAndCompiles: Draft compiles the composed bytes against the folders it would create without
// creating them (a nested .tego/tmp/ in a project with no .tego/ yet), reports OK, and Create then makes them; a
// --command not on PATH is a Result with OK false and the compile's exec-not-on-path diagnostic, not an error.
func TestDraftCreatesNothingAndCompiles(t *testing.T) {
	dir := project(t)
	env := CheckEnv{Options: []agent.CompileOption{agent.WithPATH("/usr/bin:/bin"), agent.WithHome(t.TempDir())}}
	o := Options{Presets: []string{"no-secrets,no-prod,repo-only-writes"}, Writes: []string{"src/deep"}, Name: "p", Dir: dir, Command: "sh -c true"}
	r, err := Draft(o, env)
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK || agent.HasErrors(r.Diagnostics) {
		t.Fatalf("Draft: not OK: %v\n%s", r.Diagnostics, r.Contract)
	}
	for _, d := range r.MakeDirs {
		if exists(d) {
			t.Errorf("Draft created %s", d)
		}
	}
	made, ds, ok, err := Apply(r, dir, env)
	if err != nil || !ok {
		t.Fatalf("Apply: %v %v", err, ds)
	}
	if strings.Join(made, " ") != "src src/deep .tego .tego/tmp" {
		t.Errorf("Apply made %q", made)
	}

	o.Command = "tego-no-such-agent-binary"
	r, err = Draft(o, env)
	if err != nil {
		t.Fatal(err)
	}
	if r.OK {
		t.Fatal("Draft of a command not on PATH is OK")
	}
	found := false
	for _, d := range r.Diagnostics {
		found = found || (d.Code == agent.CodeExecNotOnPath && d.File == filepath.Join(dir, ContractFile))
	}
	if !found {
		t.Errorf("no exec-not-on-path at %s: %v", filepath.Join(dir, ContractFile), r.Diagnostics)
	}
}

// TestApplyRemovesWhatItMadeWhenTheSecondCompileRefuses: a check compile cannot make while a folder is missing (an
// entry inside tego's own directory, R10: here the chain anchor's folder is the .tego/tmp/ init would create) passes
// Draft, fails Apply's compile once the folder exists, and Apply removes every folder it made, leaving a folder that
// was there before.
func TestApplyRemovesWhatItMadeWhenTheSecondCompileRefuses(t *testing.T) {
	dir := project(t, "src/")
	env := CheckEnv{Options: []agent.CompileOption{agent.WithPATH("/usr/bin:/bin"), agent.WithHome(t.TempDir()),
		agent.WithChainAnchor(filepath.Join(dir, ".tego", "tmp", "chain.log"))}}
	r, err := Draft(Options{Presets: []string{"repo-only-writes"}, Writes: []string{"src"}, Name: "p", Dir: dir, Command: "sh -c true"}, env)
	if err != nil || !r.OK {
		t.Fatalf("Draft: %v %v", err, r.Diagnostics)
	}
	made, ds, ok, err := Apply(r, dir, env)
	if err != nil || ok || made != nil || !agent.HasErrors(ds) {
		t.Fatalf("Apply: made %q, ok %v, err %v, %v", made, ok, err, ds)
	}
	if exists(filepath.Join(dir, ".tego")) {
		t.Error("Apply left .tego/ behind")
	}
	if !exists(filepath.Join(dir, "src")) {
		t.Error("Apply removed src/, which was there before")
	}
}
