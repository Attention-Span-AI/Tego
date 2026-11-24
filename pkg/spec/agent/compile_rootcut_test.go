// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// The stages beyond the deny_read and name-entry compile that a permission failure can cut short for a normal user
// and that root finishes (ADR 0043, amendment 2026-11-19): each reports the place to the one flag a root-tier
// prediction reads (compiler.namePredictionUnavailable), and nothing when the same compile runs with every place
// readable. Each case cuts one stage.

// cutRecorder is a WithNamePrediction callback that keeps every place it hears.
type cutRecorder struct {
	got   []string
	reach map[string]CutReach
}

func (r *cutRecorder) hear(c NameCut) {
	r.got = append(r.got, c.Path)
	if r.reach == nil {
		r.reach = map[string]CutReach{}
	}
	r.reach[c.Path] = c.Reach
}

func (r *cutRecorder) option() CompileOption { return WithNamePrediction(r.hear) }

// heard reports whether a place at or beneath p was reported.
func (r *cutRecorder) heard(p string) bool {
	return slices.ContainsFunc(r.got, func(g string) bool { return g == p || strings.HasPrefix(g, p+"/") })
}

// cutFn is the callback form the direct-call helpers take, recording what the compiler's would report.
func (r *cutRecorder) cutFn(p string, err error) {
	if errors.Is(err, os.ErrPermission) {
		r.hear(NameCut{Path: p})
	}
}

// restrict sets dir's mode for the test, back to 0755 after it, and reports whether this process is then refused
// listing it: root reads through any mode, and then has nothing to report.
func restrict(t *testing.T, dir string, mode os.FileMode) bool {
	t.Helper()
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	_, err := os.ReadDir(dir)
	return err != nil
}

func mkdirs(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// The deny-write search: a folder beneath a write entry this user may search and not list (the review's 0711 folder
// of another account, here the test's own folder at 0311) holds a repository root's search finds; a git config this
// user may not read names hooks root's search reads; a candidate behind a folder this user may not search is one
// root's probe lands. The write entry lies outside the project, where the built-in .env traversal, which reports a
// folder it may not list already, does not look.
func TestRootCutDenyWriteSearch(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(t *testing.T, w string) (cut string, holds bool)
	}{
		{"a folder it may search and not list", func(t *testing.T, w string) (string, bool) {
			mkdirs(t, filepath.Join(w, "sub", "repo", ".git", "hooks"))
			if err := os.WriteFile(filepath.Join(w, "sub", "repo", ".git", "config"), []byte("[core]\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(w, "sub"), restrict(t, filepath.Join(w, "sub"), 0o311)
		}},
		{"a git config it may not read", func(t *testing.T, w string) (string, bool) {
			mkdirs(t, filepath.Join(w, "repo", ".git", "hooks"))
			cfg := filepath.Join(w, "repo", ".git", "config")
			if err := os.WriteFile(cfg, []byte("[core]\n\thooksPath = elsewhere\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(cfg, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(cfg, 0o600) })
			_, err := os.ReadFile(cfg)
			return cfg, err != nil
		}},
		{"a candidate whose link leads behind a folder it may not search", func(t *testing.T, w string) (string, bool) {
			// The walk lists w and does not follow the link; only the probe of the candidate .claude walks it. Root's
			// probe lands outside every write entry and holds the link's own name, a row this user's table lacks.
			locked := filepath.Join(filepath.Dir(w), "locked")
			mkdirs(t, filepath.Join(locked, "claude"))
			if err := os.Symlink(filepath.Join(locked, "claude"), filepath.Join(w, ".claude")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(w, ".claude"), restrict(t, locked, 0)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			w := filepath.Join(f.root, "outside", "w")
			mkdirs(t, w)
			cut, holds := tc.build(t, w)
			var r cutRecorder
			_, _, _ = f.compileErr(f.load("version: 0\nname: cut\ncommand: [\"python\"]\nfs:\n  write: ["+w+"]\n"), r.option())
			if holds && !r.heard(cut) {
				t.Errorf("the search was cut short at %s and the prediction heard %q", cut, r.got)
			}
			if !holds && r.heard(cut) {
				t.Errorf("root was told it was cut short at %s", cut)
			}
		})
	}
}

// The search for hard-linked files beneath a deny_write directory target (searchDenyWriteLinked) meets a folder this
// user may not list: root lists it and keys the linked files there. Outside the project, as above.
func TestRootCutLinkedFileSearch(t *testing.T) {
	f := newFixture(t)
	outside := filepath.Join(f.root, "outside")
	guard := filepath.Join(outside, "guard")
	mkdirs(t, filepath.Join(guard, "sub"))
	holds := restrict(t, filepath.Join(guard, "sub"), 0o311)
	var r cutRecorder
	_, _, _ = f.compileErr(f.load("version: 0\nname: cut\ncommand: [\"python\"]\nfs:\n  write: ["+outside+"]\n  deny_write: ["+guard+"/]\n"),
		r.option(), WithTiers(backend.TierCgroup))
	if holds != r.heard(filepath.Join(guard, "sub")) {
		t.Errorf("listing refused %v; the prediction heard %q", holds, r.got)
	}
}

// The FIFO inventory of host_ipc (builtinFIFOs) meets a folder this user may not list beneath an IPC folder (the
// fixture's ~/.screen): this user refuses the whole folder, root lists it and refuses only its FIFOs.
func TestRootCutFIFOInventory(t *testing.T) {
	f := newFixture(t)
	screen := filepath.Join(f.home, ".screen")
	mkdirs(t, filepath.Join(screen, "sub"))
	holds := restrict(t, filepath.Join(screen, "sub"), 0o311)
	var r cutRecorder
	_, _, _ = f.compileErr(f.load("version: 0\nname: cut\ncommand: [\"python\"]\n"), r.option())
	if holds != r.heard(filepath.Join(screen, "sub")) {
		t.Errorf("listing refused %v; the prediction heard %q", holds, r.got)
	}
	// What root finds beneath a built-in IPC folder is a FIFO's name beneath it: the cut reaches that place only, not
	// every file-backed row (ADR 0043, amendment 2026-11-19; the guest's /run/user/1001/systemd/inaccessible/dir).
	if got, ok := r.reach[filepath.Join(screen, "sub")]; holds && (!ok || got != CutHere) {
		t.Errorf("the FIFO inventory's cut reaches %v (heard %v), want CutHere", got, ok)
	}
}

// The reach each step reports (CutReach): the built-in lists' places reach their own paths, the exec lists' places
// every exec row, and every other step, and a step that names none, every file-backed row.
func TestRootCutReaches(t *testing.T) {
	var r cutRecorder
	k := &compiler{o: compileOptions{predictNames: true, namePredictionUnavailable: r.hear}}
	denied := os.ErrPermission
	k.builtinCut("/built", denied)
	k.execCut("/exec", denied)
	k.namePredictionUnavailable("/wide", denied)
	k.builtinCut("/absent", os.ErrNotExist) // not a permission failure: nothing to report
	want := map[string]CutReach{"/built": CutHere, "/exec": CutExec, "/wide": CutWide}
	if len(r.reach) != len(want) {
		t.Errorf("heard %v, want %v", r.reach, want)
	}
	for p, w := range want {
		if got, ok := r.reach[p]; !ok || got != w {
			t.Errorf("%s: reach %v (heard %v), want %v", p, got, ok, w)
		}
	}
	var zero NameCut
	if zero.Reach != CutWide {
		t.Errorf("a cut that names no reach is %v, want the widest", zero.Reach)
	}
}

// compiler.resolve, which every stage asks for where an entry leads: a write entry behind a folder this user may not
// search is placed by root's walk, perhaps elsewhere.
func TestRootCutEntryWalk(t *testing.T) {
	f := newFixture(t)
	locked := filepath.Join(f.root, "outside", "locked")
	mkdirs(t, filepath.Join(locked, "w"))
	holds := restrict(t, locked, 0)
	var r cutRecorder
	_, _, _ = f.compileErr(f.load("version: 0\nname: cut\ncommand: [\"python\"]\nfs:\n  write: ["+filepath.Join(locked, "w")+"]\n"), r.option())
	if holds != r.heard(filepath.Join(locked, "w")) {
		t.Errorf("walk refused %v; the prediction heard %q", holds, r.got)
	}
}

// The built-in boundary's link reads (a built-in path's canonical prefix, a declared container socket's alias, a peer
// socket's folder) and the exec lists' listings (the loaders' folders, a tool's helper folder) and Tego's own backing
// source: each place a permission failure keeps from this user is reported.
func TestRootCutBuiltinAndExecListings(t *testing.T) {
	base := t.TempDir()
	locked := filepath.Join(base, "locked")
	listless := filepath.Join(base, "listless")
	mkdirs(t, filepath.Join(locked, "run", "gnupg"), listless)
	if err := os.WriteFile(filepath.Join(listless, "git-push"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !restrict(t, locked, 0) || !restrict(t, listless, 0o311) {
		t.Skip("this process reads through every mode (root): nothing is cut short")
	}
	for _, tc := range []struct {
		name string
		at   string
		run  func(r *cutRecorder)
	}{
		{"a built-in path's prefix", locked, func(r *cutRecorder) {
			builtinResolvedPath(filepath.Join(locked, "run", "docker.sock"), r.cutFn)
		}},
		{"a peer socket's folder", locked, func(r *cutRecorder) {
			k := &compiler{o: compileOptions{predictNames: true, namePredictionUnavailable: r.hear},
				rt: &RuleTable{Builtins: &BuiltinRefusals{PeerSockets: []string{filepath.Join(locked, "run", "gnupg", "S.gpg-agent.ssh")}}}}
			k.builtinPeerNames()
			if r.reach[filepath.Join(locked, "run", "gnupg")] != CutHere {
				t.Errorf("a peer socket's folder reaches %v, want CutHere", r.reach)
			}
		}},
		{"a declared container socket's alias", locked, func(r *cutRecorder) {
			rt := filepath.Join(locked, "run")
			k := &compiler{o: compileOptions{predictNames: true, namePredictionUnavailable: r.hear},
				rt: &RuleTable{Builtins: &BuiltinRefusals{Runtime: []string{rt}},
					Net: []NetRule{{Proto: ProtoUnix, Verdict: VerdictAllow, UnixPath: filepath.Join(rt, "docker.sock")}}}}
			k.builtinContainerAliases()
		}},
		{"a loaders' folder", listless, func(r *cutRecorder) { execLoaders([]string{listless}, r.cutFn) }},
		{"a tool's helper folder", listless, func(r *cutRecorder) { listDashed(listless, "git", r.cutFn) }},
		{"Tego's own backing source", locked, func(r *cutRecorder) {
			backingSource(FileMount{Unmapped: "fuse.sshfs", Source: filepath.Join(locked, "run")}, r.cutFn)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r cutRecorder
			tc.run(&r)
			if !r.heard(tc.at) {
				t.Errorf("a permission failure under %s was not reported: heard %q", tc.at, r.got)
			}
		})
	}
}

// The native-code scan under a write entry decides no rule (each tree it finds is a warning), so a folder it may not
// list is not a root-tier unknown: the scan's warning names the folder instead of falling silent.
func TestExecMapScanNamesAFolderItCannotList(t *testing.T) {
	f := newFixture(t)
	w := filepath.Join(f.project, "w")
	mkdirs(t, filepath.Join(w, "lib"))
	holds := restrict(t, filepath.Join(w, "lib"), 0o311)
	_, ds := f.compile(f.load("version: 0\nname: cut\ncommand: [\"python\"]\nfs:\n  write: [./w]\nexec:\n  allow: [python]\n"),
		WithTiers(backend.TierCgroup))
	got := render(ds)
	if want := "could not list " + filepath.Join(w, "lib") + " (permission denied)"; holds != strings.Contains(got, want) {
		t.Errorf("listing refused %v; want the warning %q in:\n%s", holds, want, got)
	}
}

// The remaining walks that decided a row or a probe with "not there" for what only this user cannot see (the review of
// fix batch 1): the bare-name PATH search, an exec entry's own stat, and the git-directory probes of the deny_write
// search each report a place a permission failure keeps from this user.
func TestRootCutPathSearchAndGitProbes(t *testing.T) {
	base := t.TempDir()
	locked := filepath.Join(base, "locked")
	later := filepath.Join(base, "later")
	mkdirs(t, filepath.Join(locked, "gd"), later)
	for _, p := range []string{filepath.Join(locked, "tool"), filepath.Join(later, "tool")} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	restrict(t, locked, 0o600) // listable, not searchable: nothing in it can be looked at
	if _, err := os.Stat(filepath.Join(locked, "tool")); !errors.Is(err, os.ErrPermission) {
		t.Skip("this process reads through every mode (root): nothing is cut short")
	}
	for _, tc := range []struct {
		name string
		run  func(r *cutRecorder)
	}{
		{"a PATH folder this user may not search", func(r *cutRecorder) {
			k := &compiler{o: compileOptions{predictNames: true, namePredictionUnavailable: r.hear}}
			b := &execBuilder{k: k}
			if got, ok := b.searchPath("tool", []string{locked, later}); ok && got == filepath.Join(locked, "tool") {
				t.Errorf("the search found a file this user cannot see: %s", got)
			}
		}},
		{"an exec entry this user may not stat", func(r *cutRecorder) {
			f := newFixture(t)
			_, _, _ = f.compileErr(f.load("version: 0\nname: cut\ncommand: [\"python\"]\nexec:\n  allow: ["+filepath.Join(locked, "tool")+"]\n"), r.option())
		}},
		{"a git directory's layout probe", func(r *cutRecorder) { isGitDir(filepath.Join(locked, "gd"), r.cutFn) }},
		{"a git directory's own stat", func(r *cutRecorder) {
			s := &denySearch{known: map[fileID]*gitDirInfo{}, cutShort: r.cutFn}
			s.info(filepath.Join(locked, "gd"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r cutRecorder
			tc.run(&r)
			if !r.heard(locked) {
				t.Errorf("a permission failure under %s was not reported: heard %q", locked, r.got)
			}
		})
	}
}
