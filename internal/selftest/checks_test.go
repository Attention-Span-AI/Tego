// SPDX-License-Identifier: Apache-2.0

package selftest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"gopkg.in/yaml.v3"
)

// newTestTree is a tree under t's temporary directory, removed with it.
func newTestTree(t *testing.T) tree {
	t.Helper()
	tr, err := newTree(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// TestCheckMainRefusesAnythingButItsOwnTree: the hidden verb takes exactly a known check name and a workdir tego
// test made, so it can be pointed at nothing else on the machine.
func TestCheckMainRefusesAnythingButItsOwnTree(t *testing.T) {
	tr := newTestTree(t)
	unmarked := filepath.Join(t.TempDir(), rootPattern+"x", workName)
	if err := os.MkdirAll(unmarked, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), rootPattern+"y")
	if err := os.MkdirAll(link, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(tr.work, filepath.Join(link, workName)); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
	}{
		{"no arguments", nil},
		{"one argument", []string{CheckReadSecret}},
		{"three arguments", []string{CheckReadSecret, tr.work, "x"}},
		{"unknown check", []string{"read-anything", tr.work}},
		{"relative workdir", []string{CheckReadSecret, "work"}},
		{"unclean workdir", []string{CheckReadSecret, tr.work + "/../work"}},
		{"not a tree", []string{CheckReadSecret, os.Getenv("HOME")}},
		{"the tree's root", []string{CheckReadSecret, tr.root}},
		{"no marker", []string{CheckReadSecret, unmarked}},
		{"a link to a tree", []string{CheckReadSecret, filepath.Join(link, workName)}},
		{"a linked home", []string{CheckReadSecret, linkedTree(t, "home")}},
		{"a linked .ssh", []string{CheckReadSecret, linkedTree(t, filepath.Join("home", ".ssh"))}},
		{"a linked bin", []string{CheckRunUnlisted, linkedTree(t, "bin")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if code := CheckMain(tc.args, &out, &errb); code != identity.ExitUsage {
				t.Errorf("exit %d, want %d (stderr %q)", code, identity.ExitUsage, errb.String())
			}
			if out.Len() != 0 {
				t.Errorf("printed a result for refused arguments: %q", out.String())
			}
		})
	}
}

// linkedTree is the workdir of a tree whose folder rel (below the workdir) was replaced by a link to a folder
// outside it holding the same files: what someone laying out a tree of their own would do to lead a check off it.
func linkedTree(t *testing.T, rel string) string {
	t.Helper()
	tr := newTestTree(t)
	moved := filepath.Join(t.TempDir(), "moved")
	if err := os.Rename(filepath.Join(tr.work, rel), moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, filepath.Join(tr.work, rel)); err != nil {
		t.Fatal(err)
	}
	return tr.work
}

// TestEveryCheckWorksWithoutTego is the baseline half in this process: each action takes effect on its decoy, which
// is what makes a refusal under tego run mean something.
func TestEveryCheckWorksWithoutTego(t *testing.T) {
	tr := newTestTree(t)
	s, err := listen()
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if err := tr.writePort(s.port()); err != nil {
		t.Fatal(err)
	}
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := CheckMain([]string{name, tr.work}, &out, &errb)
			line, ok := strings.CutPrefix(strings.TrimSpace(out.String()), resultPrefix)
			if !ok {
				t.Fatalf("no result line: %q (stderr %q)", out.String(), errb.String())
			}
			var res checkResult
			if err := json.Unmarshal([]byte(line), &res); err != nil {
				t.Fatal(err)
			}
			if code != identity.ExitOK || !res.Done || res.Check != name {
				t.Errorf("exit %d result %+v, want done", code, res)
			}
		})
	}
	if _, err := os.Stat(tr.outside()); err != nil {
		t.Errorf("the write check left no file: %v", err)
	}
	if !s.above(0, 5*time.Second) || s.count() != 1 {
		t.Errorf("the listener accepted %d connections, want 1", s.count())
	}
}

// TestBlockedIsAPermissionRefusal: a check that fails with EACCES says blocked, the way an enforced rule fails it.
func TestBlockedIsAPermissionRefusal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-0000 file")
	}
	tr := newTestTree(t)
	if err := os.Chmod(tr.key(), 0); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := CheckMain([]string{CheckReadSecret, tr.work}, &out, &errb); code != identity.ExitFinding {
		t.Fatalf("exit %d, want %d", code, identity.ExitFinding)
	}
	var res checkResult
	if err := json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(out.String()), resultPrefix)), &res); err != nil {
		t.Fatal(err)
	}
	if res.Done || !res.Blocked {
		t.Errorf("result %+v, want blocked and not done", res)
	}
}

// TestContractNamesOnlyTheTree: the filled contract grants the project's out/ alone, denies the decoy secrets, allows
// no destination and no program but its command, and every path in it but the binary's lies in the tree.
func TestContractNamesOnlyTheTree(t *testing.T) {
	tr := newTestTree(t)
	if err := tr.writeContract("/usr/local/bin/te\"go"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(tr.contract())
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Command []string `yaml:"command"`
		FS      struct {
			Write    []string `yaml:"write"`
			DenyRead []string `yaml:"deny_read"`
		} `yaml:"fs"`
		Net struct {
			Allow []string `yaml:"allow"`
		} `yaml:"net"`
		Exec struct {
			Allow []string `yaml:"allow"`
		} `yaml:"exec"`
		Record string `yaml:"record"`
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	if len(c.Command) != 2 || c.Command[0] != "/usr/local/bin/te\"go" || c.Command[1] != CheckVerb {
		t.Errorf("command %q", c.Command)
	}
	if len(c.FS.Write) != 1 || c.FS.Write[0] != tr.out() {
		t.Errorf("fs.write %q, want [%s]", c.FS.Write, tr.out())
	}
	for _, p := range append(append([]string{}, c.FS.Write...), c.FS.DenyRead...) {
		if !strings.HasPrefix(p, tr.work+"/") {
			t.Errorf("%s lies outside the workdir", p)
		}
	}
	if len(c.FS.DenyRead) != 2 || len(c.Net.Allow) != 0 || len(c.Exec.Allow) != 0 || c.Record != "full" {
		t.Errorf("contract %+v", c)
	}
}

// TestConfigKeepsTheCallersLayerButTheLedger: the runs read the caller's own $TEGO_CONFIG layer, with ledger_root
// replaced by the tree's, so the records stay in the tree and every other setting is the caller's.
func TestConfigKeepsTheCallersLayerButTheLedger(t *testing.T) {
	tr := newTestTree(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { // tego run trusts no layer in a group-writable directory (R20)
		t.Fatal(err)
	}
	layer := filepath.Join(dir, "tego.yaml")
	if err := os.WriteFile(layer, []byte("ledger_root: /somewhere/ledger\ngc_interval: 1h\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, layer, wantKept string }{{"caller's layer", layer, "gc_interval"}, {"no layer", "", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tr.writeConfig(tc.layer); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(tr.config())
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := yaml.Unmarshal(b, &m); err != nil {
				t.Fatal(err)
			}
			if m["ledger_root"] != tr.ledger() {
				t.Errorf("ledger_root %v, want %s", m["ledger_root"], tr.ledger())
			}
			if tc.wantKept != "" && m[tc.wantKept] == nil {
				t.Errorf("%s was dropped: %s", tc.wantKept, b)
			}
			if fi, err := os.Stat(tr.config()); err != nil || fi.Mode().Perm() != 0o600 {
				t.Errorf("config mode %v %v, want 0600", fi.Mode(), err)
			}
		})
	}
}

// TestConfigRefusesALayerTegoRunRefuses: a caller's $TEGO_CONFIG layer that tego run would refuse ([config-untrusted])
// is refused here too, never copied into the tree where the copy would pass the checks the original fails.
func TestConfigRefusesALayerTegoRunRefuses(t *testing.T) {
	tr := newTestTree(t)
	dir := t.TempDir()
	lax := filepath.Join(dir, "lax.yaml")
	if err := os.WriteFile(lax, []byte("gc_interval: 1h\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lax, 0o666); err != nil { // the umask narrows WriteFile's mode
		t.Fatal(err)
	}
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "rel.yaml"), []byte("gc_interval: 1h\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, layer string }{
		{"a world-writable layer", lax},
		{"a relative layer", "rel.yaml"},
		{"a layer through procfs", "/proc/self/cwd/rel.yaml"},
		{"a missing layer", filepath.Join(dir, "absent.yaml")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_ = os.Remove(tr.config()) // a layer from an earlier case would hide a write
			err := tr.writeConfig(tc.layer)
			var ce *ConfigError
			if !errors.As(err, &ce) {
				t.Fatalf("writeConfig(%q) = %v, want a *ConfigError", tc.layer, err)
			}
			if _, err := os.Stat(tr.config()); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a layer was written for a refused caller layer: %v", err)
			}
		})
	}
}

// TestTreeParentLeavesTegosDirectory: a temporary folder inside the tego binary's own directory, where compile_fs
// refuses every write entry, is passed over for $XDG_RUNTIME_DIR, and with nothing else usable the error says to set
// TMPDIR elsewhere.
func TestTreeParentLeavesTegosDirectory(t *testing.T) {
	base := t.TempDir()
	bin := filepath.Join(base, "dl")
	tmp := filepath.Join(bin, "t")
	run := filepath.Join(base, "run")
	for _, d := range []string{tmp, run} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	tego := filepath.Join(bin, "tego")
	if err := os.WriteFile(tego, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err := treeParent(run, tego, nil); err != nil || got != run {
		t.Errorf("a folder outside: %q %v, want %q", got, err, run)
	}
	if got, err := treeParent(tmp, tego, []string{"XDG_RUNTIME_DIR=" + run}); err != nil || got != run {
		t.Errorf("inside, with a runtime dir: %q %v, want %q", got, err, run)
	}
	// A link to the binary is judged by the directory it resolves to.
	other := filepath.Join(base, "links")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(tego, filepath.Join(other, "tego")); err != nil {
		t.Fatal(err)
	}
	if got, err := treeParent(tmp, filepath.Join(other, "tego"), []string{"XDG_RUNTIME_DIR=" + run}); err != nil || got != run {
		t.Errorf("inside, through a link to the binary: %q %v, want %q", got, err, run)
	}
	t.Setenv("XDG_CACHE_HOME", filepath.Join(bin, "cache")) // inside too: nothing usable is left
	t.Setenv("HOME", bin)
	if _, err := treeParent(tmp, tego, nil); err == nil || !strings.Contains(err.Error(), "set TMPDIR") {
		t.Errorf("nothing usable: %v, want an error that says to set TMPDIR", err)
	}
}

// TestTrueProgramIsAnExecutable: the program copied as the unlisted one is a regular executable file named true.
func TestTrueProgramIsAnExecutable(t *testing.T) {
	p := trueProgram()
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 || filepath.Base(p) != "true" {
		t.Errorf("trueProgram() = %s (%v %v)", p, fi, err)
	}
}

// TestSelftestTouchesNothingOutsideItsTree: with the decoys beside a fake HOME, all four checks run directly (the
// half with no Tego to stop them) change nothing outside the tree: every path made, changed or removed lies in it.
func TestSelftestTouchesNothingOutsideItsTree(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "home")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), []byte("the person's own key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	tr, err := newTree(parent)
	if err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, parent, tr.root)
	s, err := listen()
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if err := tr.writePort(s.port()); err != nil {
		t.Fatal(err)
	}
	for _, name := range Names() {
		var out, errb bytes.Buffer
		if code := CheckMain([]string{name, tr.work}, &out, &errb); code != identity.ExitOK {
			t.Fatalf("%s: exit %d: %s", name, code, errb.String())
		}
	}
	after := snapshot(t, parent, tr.root)
	for p, st := range after {
		if before[p] != st {
			t.Errorf("%s changed outside the tree", p)
		}
	}
	for p := range before {
		if _, ok := after[p]; !ok {
			t.Errorf("%s removed outside the tree", p)
		}
	}
}

// snapshot is every path under dir but skip's subtree, with its size, mode and modification time.
func snapshot(t *testing.T, dir, skip string) map[string]string {
	t.Helper()
	m := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == skip {
			return filepath.SkipDir
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		m[p] = fmt.Sprintf("%d %v %d", fi.Size(), fi.Mode(), fi.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}
