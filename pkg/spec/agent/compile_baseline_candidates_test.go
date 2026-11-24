// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func baselineGitLayout(t *testing.T, f *fixture, prefix, layout string, names ...string) (string, string) {
	t.Helper()
	image, err := os.ReadFile(filepath.Join(f.bin, "static-tool"))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(prefix, "bin")
	dir := filepath.Join(prefix, layout, "git-core")
	for _, p := range []string{bin, dir} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	git := filepath.Join(bin, "git")
	f.file(git, string(image), 0o755)
	f.file(filepath.Join(dir, "git"), string(image), 0o755)
	for _, name := range names {
		f.file(filepath.Join(dir, "git-"+name), string(image), 0o755)
	}
	return git, dir
}

func TestBaselineCommandCandidateOrdinaryLayouts(t *testing.T) {
	for _, layout := range []string{"lib", "libexec", "symlink", "image symlink"} {
		t.Run(layout, func(t *testing.T) {
			f := newFixture(t)
			actual := layout
			if actual == "symlink" || actual == "image symlink" {
				actual = "libexec"
			}
			prefix := f.root
			if layout == "image symlink" {
				prefix = filepath.Join(f.root, "install")
			}
			git, dir := baselineGitLayout(t, f, prefix, actual, "external-review", strings.Repeat("a", 63), "push")
			if layout == "symlink" {
				if err := os.Mkdir(filepath.Join(f.root, "lib"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dir, filepath.Join(f.root, "lib", "git-core")); err != nil {
					t.Fatal(err)
				}
			}
			if layout == "image symlink" {
				alias := filepath.Join(f.bin, "git")
				if err := os.Symlink(git, alias); err != nil {
					t.Fatal(err)
				}
				git = alias
			}
			m := baselineMachine(t, f, "  exec: {deny: ['git push']}\n")
			c := f.load("version: 0\nname: inventory\ncommand: [static-tool]\nexec: {allow: [" + git + "]}\n")
			rt, ds, err := Compile(c, m, f.opts()...)
			if err != nil || rt.ExecCommands.Candidates == nil || !rt.ExecCommands.Candidates.Has("external-review") || !rt.ExecCommands.Candidates.Has(strings.Repeat("a", 63)) {
				t.Fatalf("ordinary %s inventory: %v %s", layout, err, render(ds))
			}
			t.Logf("layout=%s retained=%d, 63-byte helper retained, duplicate builtin retained once", layout, len(rt.ExecCommands.Candidates.Names()))
		})
	}
}

func TestBaselineCommandCandidateNoHelperDirectory(t *testing.T) {
	f := newFixture(t)
	image, err := os.ReadFile(filepath.Join(f.bin, "static-tool"))
	if err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(f.bin, "git"), string(image), 0o755)
	m := baselineMachine(t, f, "  exec: {deny: ['git push']}\n")
	c := f.load("version: 0\nname: no-helper-directory\ncommand: [static-tool]\nexec: {allow: [git]}\n")
	rt, ds, err := Compile(c, m, f.opts()...)
	if err != nil || len(rt.ExecCommands.Candidates.Names()) != len(rows.Git().Builtins) {
		t.Fatalf("absent optional helper directories changed builtins: %v %s", err, render(ds))
	}
	t.Logf("absent lib/libexec helper directories: %d builtin names retained", len(rt.ExecCommands.Candidates.Names()))
}

func TestBaselineCommandCandidateIncomplete(t *testing.T) {
	for _, failure := range []string{"64-byte helper", "unreadable", "partial", "cut", "unstatable"} {
		t.Run(failure, func(t *testing.T) {
			f := newFixture(t)
			git, dir := baselineGitLayout(t, f, f.root, "lib", "ordinary-helper")
			switch failure {
			case "64-byte helper":
				f.file(filepath.Join(dir, "git-"+strings.Repeat("a", 64)), "fixture", 0o755)
			case "unstatable":
				if err := os.Symlink("missing", filepath.Join(dir, "git-unstatable")); err != nil {
					t.Fatal(err)
				}
			default:
				original := readDirN
				readDirN = func(file *os.File, n int) ([]os.DirEntry, error) {
					if file.Name() != dir {
						return original(file, n)
					}
					if failure == "unreadable" {
						return nil, os.ErrPermission
					}
					entries, err := original(file, 1)
					if err != nil || len(entries) == 0 {
						return entries, err
					}
					if failure == "partial" {
						return entries, syscall.EIO
					}
					full := make([]os.DirEntry, n)
					for i := range full {
						full[i] = entries[0]
					}
					return full, nil
				}
				t.Cleanup(func() { readDirN = original })
			}
			c := f.load("version: 0\nname: inventory\ncommand: [static-tool]\nexec: {allow: [" + git + "], deny: ['git push']}\n")
			m := baselineMachine(t, f, "  exec: {deny: ['git push']}\n")
			rt, ds, err := Compile(c, m, f.opts()...)
			if err == nil || rt != nil || !strings.Contains(render(ds), CodeBaselinePlacement) || !strings.Contains(render(ds), "command inventory") || !strings.Contains(render(ds), "owner uid") {
				t.Fatalf("incomplete %s inventory accepted or lacked source diagnostic: %v %s", failure, err, render(ds))
			}
			// The new refusal belongs only to the applicable git baseline.
			for _, machine := range []*config.Machine{f.machine, baselineMachine(t, f, "  env: {deny: [BASELINE_TOKEN]}\n"), baselineMachine(t, f, "  exec: {deny: ['rm -r']}\n")} {
				if _, ds, err := Compile(c, machine, f.opts()...); err != nil {
					t.Fatalf("unrelated or empty baseline gained inventory refusal: %v %s", err, render(ds))
				}
			}
			if _, ds, err := Compile(c, m, f.opts(WithObserve())...); err != nil {
				t.Fatalf("not-applied baseline gained inventory refusal: %v %s", err, render(ds))
			}
			t.Logf("%s: git baseline refuses; empty/env/rm baseline and record-only preserve existing behavior", failure)
		})
	}
}

func TestBaselineCommandCandidateMultipleInstallations(t *testing.T) {
	for _, different := range []bool{false, true} {
		t.Run(map[bool]string{false: "same vocabulary", true: "different vocabulary"}[different], func(t *testing.T) {
			f := newFixture(t)
			first, _ := baselineGitLayout(t, f, filepath.Join(f.root, "one"), "lib", "external-review")
			secondNames := []string{"external-review"}
			if different {
				secondNames = []string{"other-helper"}
			}
			second, _ := baselineGitLayout(t, f, filepath.Join(f.root, "two"), "libexec", secondNames...)
			c := f.load("version: 0\nname: installations\ncommand: [static-tool]\nexec: {allow: [" + first + ", " + second + "], deny: ['git status']}\n")
			m := baselineMachine(t, f, "  exec: {deny: ['git push']}\n")
			rt, ds, err := Compile(c, m, f.opts(WithPATH(filepath.Dir(first)+":"+f.bin))...)
			if (err != nil) != different {
				t.Fatalf("different=%v: %v %s", different, err, render(ds))
			}
			if different && (rt != nil || !strings.Contains(render(ds), "different candidate inventories")) {
				t.Fatalf("different inventories did not fail closed: %s", render(ds))
			}
			if !different && len(rt.ExecCommands.Candidates.Names()) != len(rows.Git().Builtins)+1 {
				t.Fatalf("shared inventory changed: %v", rt.ExecCommands.Candidates.Names())
			}
			if _, ds, err := Compile(c, f.machine, f.opts(WithPATH(filepath.Dir(first)+":"+f.bin))...); err != nil {
				t.Fatalf("no-baseline multiple installations changed: %v %s", err, render(ds))
			}
			t.Logf("two installations, different=%v: baseline refusal=%v, no-baseline allowed", different, different)
		})
	}
}
