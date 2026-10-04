// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestGlobExpansionBounded: an fs.deny_read or fs.watch glob may name a directory the agent writes into, so its
// expansion is bounded by entries, matches and time, every glob of a compile together (I6). filepath.Glob listed
// each directory whole and returned every match, so a planted directory of millions of names cost the next compile
// unbounded time and memory and one rule per name. A deny_read glob cut short fails the compile, since the files
// it did not reach would stay readable under an entry that names them; a watch glob cut short warns.
func TestGlobExpansionBounded(t *testing.T) {
	setup := func(t *testing.T) *fixture {
		f := newFixture(t)
		plant := filepath.Join(f.project, "out", "plant")
		if err := os.MkdirAll(plant, 0o755); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 40; i++ {
			f.file(filepath.Join(plant, "s"+strconv.Itoa(i)), "", 0o600)
		}
		return f
	}
	for _, bound := range []struct {
		name, want string
		set        func() func()
	}{
		{"entries", "directory entries", func() func() {
			n := globScanMaxEntries
			globScanMaxEntries = 10
			return func() { globScanMaxEntries = n }
		}},
		{"matches", "files all of this compile's globs may cover", func() func() {
			n := globMaxMatches
			globMaxMatches = 5
			return func() { globMaxMatches = n }
		}},
		{"time", "ran out of", func() func() {
			d := globScanMaxTime
			globScanMaxTime = -time.Second
			return func() { globScanMaxTime = d }
		}},
	} {
		t.Run(bound.name+"/deny_read", func(t *testing.T) {
			defer bound.set()()
			f := setup(t)
			c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  deny_read: [\"./out/plant/s*\"]\n")
			rt, ds, err := Compile(c, f.machine, f.opts()...)
			if err == nil || !hasCode(ds, CodeUnenforced) || !strings.Contains(render(ds), bound.want) {
				t.Fatalf("a deny_read glob cut at its %s bound: err = %v, want a refusal naming it\n%s", bound.name, err, render(ds))
			}
			if rt != nil {
				t.Error("a table was returned for a refused contract")
			}
		})
		t.Run(bound.name+"/watch", func(t *testing.T) {
			defer bound.set()()
			f := setup(t)
			rt, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  watch: [\"./out/plant/s*\"]\n"))
			if !strings.Contains(render(ds), bound.want) {
				t.Errorf("a watch glob cut at its %s bound said nothing:\n%s", bound.name, render(ds))
			}
			n := 0
			for _, r := range rt.FS {
				if r.Kind == FSWatch {
					n++
				}
			}
			if n >= 40 {
				t.Errorf("%d watch rules from a glob cut short, want fewer than the 40 files", n)
			}
		})
	}
}

// TestGlobExpandMatchesFilepathGlob: within its bounds, the bounded expansion finds what filepath.Glob finds: a
// pattern in the last component, in a middle one (a match that is no directory is skipped there), through a
// symlinked directory, and nothing for a directory that is not there.
func TestGlobExpandMatchesFilepathGlob(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"a/x.txt", "a/y.txt", "a/z.md", "b/x.txt", "b/sub/x.txt", "c.txt", ".hidden/x.txt"} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "a"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	for _, pat := range []string{"a/*.txt", "*/x.txt", "*", "link/*", "l?nk/[xy].txt", "none/*", "*/sub/*", "*.txt"} {
		p := filepath.Join(root, pat)
		want, err := filepath.Glob(p)
		if err != nil {
			t.Fatal(err)
		}
		got, stop, err := newGlobBudget().expand(p)
		if err != nil || stop != globWhole {
			t.Fatalf("expand(%s): stop %q, err %v", pat, stop, err)
		}
		slices.Sort(want)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("expand(%s) = %v, filepath.Glob = %v", pat, got, want)
		}
	}
	if _, _, err := newGlobBudget().expand(filepath.Join(root, "[")); err == nil {
		t.Error("a bad pattern expanded")
	}
}
