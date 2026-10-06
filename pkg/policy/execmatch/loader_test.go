// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

// TestLoaderName: the loaders glibc and musl ship are loaders by basename; libraries and tools are not.
func TestLoaderName(t *testing.T) {
	for _, n := range []string{"ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2", "ld-linux.so.2", "ld-linux-aarch64.so.1",
		"ld-linux-armhf.so.3", "ld-musl-x86_64.so.1", "ld-musl-aarch64.so.1", "ld64.so.2", "ld.so", "ld-2.31.so"} {
		if !execmatch.LoaderName(n) {
			t.Errorf("%s is a loader", n)
		}
	}
	for _, n := range []string{"ld", "ldd", "ldconfig", "libc.so.6", "rm", "ld-linux", "lddtree"} {
		if execmatch.LoaderName(n) {
			t.Errorf("%s is no loader", n)
		}
	}
}

// TestLoaderProgram: the program operand is the first word that is not an option, after glibc's and musl's options
// and their values; --argv0 sets the program's argv[0]; an info option, a missing operand and a value option with no
// value run nothing; an option neither loader has is unknown.
func TestLoaderProgram(t *testing.T) {
	ld := "/lib64/ld-linux-x86-64.so.2"
	for _, c := range []struct {
		argv []string
		i    int
		prog []string
		out  execmatch.LoaderOutcome
	}{
		{[]string{ld, "/usr/bin/rm", "-rf", "t"}, 1, []string{"/usr/bin/rm", "-rf", "t"}, execmatch.LoaderRuns},
		{[]string{ld, "--library-path", "/x", "--preload", "l.so", "/usr/bin/rm", "-r"}, 5, []string{"/usr/bin/rm", "-r"}, execmatch.LoaderRuns},
		{[]string{ld, "--argv0", "ls", "/usr/bin/rm", "-r"}, 3, []string{"ls", "-r"}, execmatch.LoaderRuns},
		{[]string{ld, "--argv0=ls", "--", "/usr/bin/rm", "-r"}, 3, []string{"ls", "-r"}, execmatch.LoaderRuns},
		{[]string{ld, "--inhibit-cache", "--audit", "a.so", "--", "--weird", "x"}, 5, []string{"--weird", "x"}, execmatch.LoaderRuns},
		{[]string{ld, "--verify", "./p"}, 2, []string{"./p"}, execmatch.LoaderRuns},
		{[]string{ld, "-r", "x"}, 1, []string{"-r", "x"}, execmatch.LoaderRuns}, // a single dash is the program
		{[]string{ld, "--help", "/usr/bin/rm"}, 0, nil, execmatch.LoaderExits},
		{[]string{ld}, 0, nil, execmatch.LoaderExits},
		{[]string{ld, "--preload"}, 0, nil, execmatch.LoaderExits},
		{[]string{ld, "--frobnicate", "x", "/usr/bin/rm"}, 0, nil, execmatch.LoaderUnknown},
	} {
		i, prog, out := execmatch.LoaderProgram(c.argv)
		if i != c.i || !slices.Equal(prog, c.prog) || out != c.out {
			t.Errorf("LoaderProgram(%q) = %d %q %v, want %d %q %v", c.argv, i, prog, out, c.i, c.prog, c.out)
		}
	}
}

// TestLoadedProgramIsDecided: a directly-invoked loader runs its program in-process, with no execve of the program's
// own, so the program is decided as the exec's image (the reviewer's repro). `ld-linux /usr/bin/rm -rf tree` under
// deny: [rm -r] was allowed unmatched while `rm -rf tree` was refused; it is refused via loader now, by the operand's
// name, by the walked file's name (a symlink x to rm) and by its identity, and under an allow list a constrained
// tool's unlisted invocation through the loader is refused unlisted.
func TestLoadedProgramIsDecided(t *testing.T) {
	ix := index(t, "deny: rm -r", "deny: git push")
	loaderFacts := func(loaded *execmatch.Loaded, argv ...string) execmatch.Facts {
		return execmatch.Facts{Requested: "ld-linux-x86-64.so.2", Image: "ld-linux-x86-64.so.2", Argv0: argv[0],
			ID: execmatch.ID{Dev: 1, Ino: 99}, HasID: true, Form: execmatch.FormDirect, Argv: argv, ArgvComplete: true, Loaded: loaded}
	}
	ld := "/lib64/ld-linux-x86-64.so.2"
	without := loaderFacts(nil, ld, "/usr/bin/rm", "-rf", "/tmp/tree")
	if ix.Guarded(&without) || ix.Decide(&without).Outcome != execmatch.OutcomeNone {
		t.Fatal("the loader's own facts name no ruled tool: the reviewer's repro is the matcher's miss without Loaded")
	}
	for _, c := range []struct {
		name   string
		loaded execmatch.Loaded
		argv   []string
		want   string
	}{
		{"by the operand's name", execmatch.Loaded{Path: "/usr/bin/rm", Argv: []string{"/usr/bin/rm", "-rf", "/tmp/tree"}}, []string{ld, "/usr/bin/rm", "-rf", "/tmp/tree"}, "exec.deny[rm -r]"},
		{"by the walked image", execmatch.Loaded{Path: "./x", Image: "rm", HasID: true, ID: execmatch.ID{Dev: 1, Ino: 5}, Argv: []string{"./x", "-r", "t"}}, []string{ld, "./x", "-r", "t"}, "exec.deny[rm -r]"},
		{"git behind --argv0", execmatch.Loaded{Path: "/usr/bin/git", Image: "git", Argv: []string{"ls", "push"}}, []string{ld, "--argv0", "ls", "/usr/bin/git", "push"}, "exec.deny[git push]"},
	} {
		f := loaderFacts(&c.loaded, c.argv...)
		if !ix.Guarded(&f) {
			t.Errorf("%s: not guarded", c.name)
		}
		r := ix.Decide(&f)
		if r.Outcome != execmatch.OutcomeRefused || r.Rule() != c.want || r.Via != execmatch.ViaLoader {
			t.Errorf("%s: %v %s via %v, want refused %s via loader", c.name, r.Outcome, r.Rule(), r.Via, c.want)
		}
	}
	ok := loaderFacts(&execmatch.Loaded{Path: "/usr/bin/rm", Image: "rm", Argv: []string{"/usr/bin/rm", "-f", "x"}}, ld, "/usr/bin/rm", "-f", "x")
	if r := ix.Decide(&ok); r.Outcome != execmatch.OutcomeNone {
		t.Errorf("rm -f through the loader: %v %s, want no rule", r.Outcome, r.Rule())
	}
	allow := index(t, "allow: git status")
	f := loaderFacts(&execmatch.Loaded{Path: "/usr/bin/git", Image: "git", Argv: []string{"/usr/bin/git", "push"}}, ld, "/usr/bin/git", "push")
	if r := allow.Decide(&f); r.Outcome != execmatch.OutcomeRefused || r.Rule() != "exec.args[git]" {
		t.Errorf("git push through the loader under allow: [git status]: %v %s, want refused exec.args[git]", r.Outcome, r.Rule())
	}
}
