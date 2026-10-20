// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestCompileRefusesWritesOverTegosRuntimeDir is R10a (Codex POC F2): a forwarder-routed Codex keeps its state in
// $XDG_RUNTIME_DIR/tego/<run id>/codex, which no entry can name, so contracts granted $XDG_RUNTIME_DIR/tego/,
// and that grant reached every other run's private directory. The run grants its own CODEX_HOME itself; a write
// or ask entry at, over or inside tego's runtime parent is a contradiction. An entry beside it under
// XDG_RUNTIME_DIR is not.
func TestCompileRefusesWritesOverTegosRuntimeDir(t *testing.T) {
	f := newFixture(t)
	xdg := filepath.Join(f.root, "xdg")
	parent := filepath.Join(xdg, RuntimeDirName)
	other := filepath.Join(parent, "r-00000000-000000000000b-bbbbbb")
	for _, d := range []string{other, filepath.Join(xdg, "cc-socks")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(f.project, "rt")
	if err := os.Symlink(parent, link); err != nil {
		t.Fatal(err)
	}
	refused := map[string]string{
		"the parent":                 "fs:\n  write: [\"" + parent + "/\"]\n",
		"XDG_RUNTIME_DIR itself":     "fs:\n  write: [\"" + xdg + "\"]\n",
		"another run's directory":    "fs:\n  write: [\"" + other + "/\"]\n",
		"a link to the parent":       "fs:\n  write: [\"./rt/\"]\n",
		"an ask scope on the parent": "fs:\n  ask: [\"" + parent + "/\"]\n",
	}
	for name, section := range refused {
		t.Run(name, func(t *testing.T) {
			c := f.load("version: 0\nname: a\ncommand: [python]\n" + section)
			_, ds, err := Compile(c, f.machine, f.opts(WithRuntimeDir(xdg))...)
			if err == nil || !slices.ContainsFunc(ds, func(d Diagnostic) bool {
				return d.Code == CodeContradiction && d.Severity == SeverityError && strings.Contains(d.Message, "runtime directory")
			}) {
				t.Fatalf("no contradiction naming tego's runtime directory (err=%v):\n%s", err, render(ds))
			}
		})
	}
	t.Run("a directory beside it", func(t *testing.T) {
		c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"" + filepath.Join(xdg, "cc-socks") + "/\"]\n")
		if _, ds, err := Compile(c, f.machine, f.opts(WithRuntimeDir(xdg))...); err != nil {
			t.Fatalf("refused: %v\n%s", err, render(ds))
		}
	})
	t.Run("no XDG_RUNTIME_DIR named", func(t *testing.T) {
		c := f.load("version: 0\nname: a\ncommand: [python]\n" + refused["the parent"])
		if _, ds, err := Compile(c, f.machine, f.opts(WithRuntimeDir(""))...); err != nil {
			t.Fatalf("refused with no runtime directory to protect: %v\n%s", err, render(ds))
		}
	})
	t.Run("own state", func(t *testing.T) {
		c := f.load("version: 0\nname: a\ncommand: [python]\n")
		rt, _ := f.compile(c, WithRuntimeDir(xdg))
		if !slices.Contains(rt.OwnState, parent) {
			t.Fatalf("OwnState %q does not hold %s", rt.OwnState, parent)
		}
	})
	// The CLI names the user's logind directory whatever XDG_RUNTIME_DIR says, and the variable's own
	// directory when it names another, so every base named is protected, given in one call or several.
	logind := filepath.Join(f.root, "logind")
	logindParent := filepath.Join(logind, RuntimeDirName)
	if err := os.MkdirAll(filepath.Join(logindParent, "r-00000000-000000000000c-cccccc"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, opts := range map[string][]CompileOption{
		"two bases in one call":  {WithRuntimeDir(logind, xdg)},
		"two bases in two calls": {WithRuntimeDir(logind), WithRuntimeDir("", xdg)},
	} {
		t.Run(name, func(t *testing.T) {
			for _, p := range []string{logindParent + "/", filepath.Join(logindParent, "r-00000000-000000000000c-cccccc"), parent + "/"} {
				c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"" + p + "\"]\n")
				_, ds, err := Compile(c, f.machine, f.opts(opts...)...)
				if err == nil || !slices.ContainsFunc(ds, func(d Diagnostic) bool {
					return d.Code == CodeContradiction && strings.Contains(d.Message, "runtime directory")
				}) {
					t.Fatalf("fs.write %s: no contradiction naming tego's runtime directory (err=%v):\n%s", p, err, render(ds))
				}
			}
			rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\n"), opts...)
			if !slices.Contains(rt.OwnState, logindParent) || !slices.Contains(rt.OwnState, parent) {
				t.Fatalf("OwnState %q does not hold both %s and %s", rt.OwnState, logindParent, parent)
			}
		})
	}
}

// TestCompileWarnsAnExecDirectoryOverTheRuntimeDir: a run whose Codex is routed grants
// the agent write on its own CODEX_HOME under tego's runtime directory, which no entry declares, so execUnderWrite
// never saw it, and an exec.allow directory over the runtime directory made every file the agent wrote there
// executable without a word. It is an exec-writable warning now (the launcher refuses such a run when it makes the
// grant); an exec directory elsewhere is not.
func TestCompileWarnsAnExecDirectoryOverTheRuntimeDir(t *testing.T) {
	f := newFixture(t)
	xdg := filepath.Join(f.root, "xdg")
	if err := os.MkdirAll(filepath.Join(xdg, RuntimeDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(f.root, "tools")
	if err := os.MkdirAll(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	warned := func(entry string) bool {
		c := f.load("version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [python, \"" + entry + "\"]\n")
		_, ds := f.compile(c, WithRuntimeDir(xdg))
		return slices.ContainsFunc(ds, func(d Diagnostic) bool {
			return d.Code == CodeExecWritable && strings.Contains(d.Message, "runtime directory")
		})
	}
	for _, entry := range []string{xdg + "/", filepath.Join(xdg, RuntimeDirName) + "/"} {
		if !warned(entry) {
			t.Errorf("exec.allow %s: no exec-writable warning naming tego's runtime directory", entry)
		}
	}
	if warned(elsewhere + "/") {
		t.Errorf("exec.allow %s: warned though it holds no runtime directory", elsewhere)
	}
}
