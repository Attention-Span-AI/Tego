// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func configOnlyBaseline(t *testing.T) *config.Machine {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	// Deliberately contradictory/missing entries: slice 2 must never read them for a decision,
	// even if the compile owner has no resolved home and the command/env would conflict.
	data := []byte("baseline:\n  fs:\n    deny_read: [~/missing-secret, /usr/lib]\n    deny_write: [/home, /srv/missing]\n  exec: {deny: [sh, python3, 'git push']}\n  env: {deny: [PATH, HOME]}\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	m, ds, err := config.LoadSources(config.Sources{User: path}, "/config-caller", os.Getuid(), config.TrustAbort)
	if err != nil || m == nil || func() bool { b, _ := m.BaselineSnapshot(); return b.Empty() }() {
		t.Fatalf("baseline config: %v %v", err, ds)
	}
	return m
}

// TestEmptyBaselineLeavesCompileGoldensUnchanged runs the existing byte fixtures with a
// empty baseline. Expected files are never regenerated.
// Only the new value varies; R10 layer paths and all ordinary settings remain identical.
func TestEmptyBaselineLeavesCompileGoldensUnchanged(t *testing.T) {
	testLiveOffGolden(t, config.Builtin())
}

// TestEmptyBaselineLeavesEveryContractUnchanged compares compiled output/diagnostics, source
// canonical bytes and hashes for every loadable YAML contract in the tree, with and without the
// empty snapshot. A nonempty snapshot may fail compilation but must not mutate source.
// TestContractHashesUnchanged also binds the historical hash fixture.
func TestEmptyBaselineLeavesEveryContractUnchanged(t *testing.T) {
	baseline := configOnlyBaseline(t)
	TestContractHashesUnchanged(t)
	t.Setenv("TMUX_TMPDIR", "")
	t.Setenv("SCREENDIR", "")
	tmp := t.TempDir()
	home, bin := filepath.Join(tmp, "home"), filepath.Join(tmp, "bin")
	for _, dir := range []string{home, bin} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	goldenBin(t, bin)
	goldenHome(t, home)
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	subst := strings.NewReplacer(home, "$HOME", bin, "$BIN", root, "$REPO", tmp, "$TMP")
	n := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".github", "node_modules", ".claude":
				return filepath.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(path); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, source := range []ProfileSource{dirSource{root: filepath.Join(root, "examples", "profiles")}, testProfiles()} {
			c, _, err := LoadBytes(path, data, source)
			if err != nil {
				continue
			}
			before, err := c.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			hashBefore, err := c.Hash()
			if err != nil {
				t.Fatal(err)
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			fixture := goldenContract{name: rel, path: path}
			without := compileGolden(t, fixture, home, bin, subst)
			with := compileGolden(t, fixture, home, bin, subst, config.Builtin())
			if with != without {
				t.Errorf("%s changed with config baseline:\n%s", rel, firstDiff(without, with))
			}
			// Compile the same source object too, so mutation cannot hide behind reloading the file.
			m := baseline
			_, _, _ = Compile(c, m, WithHome(home), WithCwd(filepath.Dir(path)), WithPATH(bin), WithMountInfo(""), WithResolver(goldenResolver{}))
			after, err := c.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			hashAfter, err := c.Hash()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) || hashBefore != hashAfter {
				t.Errorf("%s source bytes/hash mutated", rel)
			}
			n++
			break
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 30 {
		t.Fatalf("only %d contracts compared", n)
	}
	t.Logf("compared all %d loadable tree contracts and historical hashes", n)
}

// Run the actual update entry point in a subprocess, with every possible golden write
// redirected to a throwaway directory. The refusal must precede even creating that directory.
func TestBaselineGoldenUpdateRefused(t *testing.T) {
	const childEnv = "TEGO_TEST_BASELINE_GOLDEN_REFUSAL_CHILD"
	if dir := os.Getenv(childEnv); dir != "" {
		*updateLiveOff = true
		testLiveOffGoldenIn(t, dir, configOnlyBaseline(t))
		return
	}
	goldenDir := filepath.Join(t.TempDir(), "goldens")
	cmd := exec.Command(os.Args[0], "-test.run=^TestBaselineGoldenUpdateRefused$", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"="+goldenDir)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "refusing -update-live-off with a configured or unknown baseline") {
		t.Fatalf("baseline golden update was not refused: %v\n%s", err, out)
	}
	if _, err := os.Stat(goldenDir); !os.IsNotExist(err) {
		t.Fatalf("baseline update touched its golden directory: %v", err)
	}
}

func TestCompileRefusesUnknownBaseline(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("baseline: {env: {deny: [TOKEN]}}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	machine, _, err := config.LoadSources(config.Sources{User: path}, dir, os.Getuid(), config.TrustWarn)
	if err != nil || machine == nil || machine.BaselineKnown() {
		t.Fatalf("degraded snapshot: %v %v", machine, err)
	}
	f := newFixture(t)
	contract := f.load("version: 0\nname: unknown-baseline\ncommand: [python]\n")
	table, ds, err := Compile(contract, machine, f.opts()...)
	if table != nil || err == nil || len(ds) != 1 || ds[0].Code != CodeBaselineUnknown || !ds[0].IsError() ||
		!strings.Contains(ds[0].Message, "UNKNOWN") || !strings.Contains(ds[0].Message, path) {
		t.Fatalf("unknown baseline decided rules: table present=%t, diagnostics=%v, error=%v", table != nil, ds, err)
	}
}
