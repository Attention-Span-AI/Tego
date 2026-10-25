// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// r10WalkLayout is <root>/w/sub/deeper, a real directory a ".." leaves, beside <root>/w where the targets land, and
// <root>/beside, where a write entry reaches no walk.
func r10WalkLayout(t *testing.T, f *fixture) (w, beside string) {
	t.Helper()
	w, beside = filepath.Join(f.root, "w"), filepath.Join(f.root, "beside")
	for _, d := range []string{filepath.Join(w, "sub", "deeper"), filepath.Join(w, "reg", "agents"), filepath.Join(w, "pt"),
		filepath.Join(w, "pp"), filepath.Join(w, "ca"), beside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.file(filepath.Join(w, "pt", "prices.yaml"), "version: 1\n", 0o644)
	f.file(filepath.Join(w, "machine.yaml"), "stop_grace: 3s\n", 0o600)
	return w, beside
}

// TestAWriteOverADirectoryTheWalkReadsANameInIsRefused: R10 protects a target by its kernel walk, so a write entry over
// any directory that walk looks a name up in is a contradiction, whatever that name is: a real directory a later ".."
// leaves (<w>/sub/deeper/../../pt), a name not there yet (<w>/sub/missing/../../reg), or a name in a link's own text
// (<w>/lnk -> sub/deeper/../../reg). Only the directories holding a symlink the walk followed were compared, so
// fs.write [<w>/sub] compiled, the run made deeper (or missing) a link elsewhere, and the next run loaded the registry,
// price table, profiles, machine config or contract the agent wrote there. An entry below the name
// (<w>/sub/deeper itself) reads no name the walk takes and compiles, as does one beside every walk.
func TestAWriteOverADirectoryTheWalkReadsANameInIsRefused(t *testing.T) {
	f := newFixture(t)
	w, beside := r10WalkLayout(t, f)
	if err := os.Symlink("sub/deeper/../../reg", filepath.Join(w, "lnk")); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(w, "sub")
	deeper := filepath.Join(sub, "deeper")
	for _, c := range []struct {
		name, spelled string
		set           func(m *config.Machine, spelled string) []CompileOption
		below         bool // an entry at <w>/sub/deeper compiles (the name is a real directory)
	}{
		{"the user registry's agents/", w + "/sub/missing/../../reg",
			func(m *config.Machine, s string) []CompileOption { m.Registry.Value = s; return nil }, false},
		{"the user registry's agents/", w + "/sub/deeper/../../reg",
			func(m *config.Machine, s string) []CompileOption { m.Registry.Value = s; return nil }, true},
		{"the user registry's agents/", w + "/lnk",
			func(m *config.Machine, s string) []CompileOption { m.Registry.Value = s; return nil }, true},
		{"the price table", w + "/sub/deeper/../../pt/prices.yaml",
			func(m *config.Machine, s string) []CompileOption { m.Prices.Value = s; return nil }, true},
		{"the profiles directory", w + "/sub/deeper/../../pp",
			func(m *config.Machine, s string) []CompileOption { m.Profiles.Value = s; return nil }, true},
		{"the machine config", w + "/sub/missing/../../machine.yaml",
			func(m *config.Machine, s string) []CompileOption { m.Layers = []string{s}; return nil }, false},
		{"the chain anchor", w + "/sub/deeper/../../ca/chain.log",
			func(_ *config.Machine, s string) []CompileOption { return []CompileOption{WithChainAnchor(s)} }, true},
	} {
		m := *f.machine
		extra := c.set(&m, c.spelled)
		compileWrite := func(entry string) (string, error) {
			_, ds, err := Compile(f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\""+entry+"\"]\n"), &m, f.opts(extra...)...)
			return render(ds), err
		}
		out, err := compileWrite(sub)
		if err == nil || !strings.Contains(out, c.name) || !strings.Contains(out, "on the way to") {
			t.Errorf("%s %s: fs.write %s, a directory its walk reads a name in, compiled: %v\n%s", c.name, c.spelled, sub, err, out)
		}
		if c.below {
			if out, err := compileWrite(deeper); err != nil {
				t.Errorf("%s %s: fs.write %s, below every name its walk reads, refused: %v\n%s", c.name, c.spelled, deeper, err, out)
			}
		}
		if out, err := compileWrite(beside); err != nil {
			t.Errorf("%s %s: fs.write %s, beside its walk, refused: %v\n%s", c.name, c.spelled, beside, err, out)
		}
	}
	// The contract file itself, given by a path that leaves a real directory by "..".
	f.file(filepath.Join(w, "agent.yaml"), "version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\""+sub+"\"]\n", 0o644)
	spelled := w + "/sub/deeper/../../agent.yaml"
	c, ds, err := Load(spelled, nil)
	if err != nil {
		t.Fatalf("load %s: %v\n%s", spelled, err, render(ds))
	}
	if _, ds, err := Compile(c, f.machine, f.opts()...); err == nil || !strings.Contains(render(ds), "the contract file") {
		t.Errorf("contract %s: fs.write %s, a directory its walk reads a name in, compiled: %v\n%s", spelled, sub, err, render(ds))
	}
}

// TestATargetIsWalkedAlikeWithoutProc: R10 places its targets by reading each name's link (ResolveUnixPlace), never by
// a descriptor's /proc/self/fd name, so a compile where /proc is not mounted places a target that is a link leading
// nowhere yet where the link leads, as it does with /proc. The /proc-less fallback (filepath.EvalSymlinks of the
// target's directory) placed such a price table at the link itself, so fs.write over the link's missing target
// compiled there.
func TestATargetIsWalkedAlikeWithoutProc(t *testing.T) {
	f := newFixture(t)
	work, real := dotDotLayout(t, f)
	prices := filepath.Join(work, "prices.yaml")
	if err := os.Symlink(filepath.Join(real, "pt", "prices.yaml"), prices); err != nil {
		t.Fatal(err)
	}
	anchor := filepath.Join(work, "chain.log")
	if err := os.Symlink(filepath.Join(real, "ca", "chain.log"), anchor); err != nil {
		t.Fatal(err)
	}
	saved := procSelfFD
	procSelfFD = filepath.Join(f.root, "no-proc", "self", "fd") + "/"
	t.Cleanup(func() { procSelfFD = saved })
	if procMounted() {
		t.Fatal("procSelfFD still names a directory")
	}
	m := *f.machine
	m.Prices.Value = prices
	c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + real + "\"]\n")
	if _, ds, err := Compile(c, &m, f.opts()...); err == nil || !strings.Contains(render(ds), "the price table") {
		t.Errorf("without /proc: fs.write %s over where the price table's link leads compiled: %v\n%s", real, err, render(ds))
	}
	if _, ds, err := Compile(c, f.machine, f.opts(WithChainAnchor(anchor))...); err == nil || !strings.Contains(render(ds), "the chain anchor") {
		t.Errorf("without /proc: fs.write %s over where the chain anchor's link leads compiled: %v\n%s", real, err, render(ds))
	}
}

// TestWalkTargetReadsEveryNameOnTheWay pins walkTarget: the place is where the walk lands, missing names made, and its
// names lie in every directory a name is looked up in, in walk order, those a ".." leaves and those of a link's text
// included, and nowhere else.
func TestWalkTargetReadsEveryNameOnTheWay(t *testing.T) {
	f := newFixture(t)
	w, _ := r10WalkLayout(t, f)
	if err := os.Symlink("sub/deeper/../../reg", filepath.Join(w, "lnk")); err != nil {
		t.Fatal(err)
	}
	loop := filepath.Join(w, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	ancestors := func(p string) []string {
		var out []string
		for d := filepath.Dir(p); ; d = filepath.Dir(d) {
			out = append([]string{d}, out...)
			if d == "/" {
				return out
			}
		}
	}
	sub := filepath.Join(w, "sub")
	for _, c := range []struct {
		p, place string
		placed   bool
		dirs     []string // beyond <w>'s ancestors and <w>
		links    []string
	}{
		{w + "/sub/deeper/../../pt/prices.yaml", filepath.Join(w, "pt", "prices.yaml"), true,
			[]string{sub, filepath.Join(w, "pt")}, nil},
		{w + "/sub/missing/../../reg", filepath.Join(w, "reg"), true, []string{sub}, nil},
		{w + "/lnk/agents", filepath.Join(w, "reg", "agents"), true,
			[]string{sub, filepath.Join(w, "reg")}, []string{filepath.Join(w, "lnk")}},
		{w + "/new/agents", filepath.Join(w, "new", "agents"), true, []string{filepath.Join(w, "new")}, nil},
		{loop, loop, false, nil, nil},
	} {
		got := walkTarget(c.p)
		if got.place != c.place || got.placed != c.placed {
			t.Errorf("walkTarget(%s) = %s, %v; want %s, %v", c.p, got.place, got.placed, c.place, c.placed)
		}
		if !c.placed {
			continue
		}
		want := append(append(ancestors(w), w), c.dirs...)
		var dirs []string
		for _, n := range got.names {
			if d := filepath.Dir(n); !slices.Contains(dirs, d) {
				dirs = append(dirs, d)
			}
		}
		if !slices.Equal(dirs, want) {
			t.Errorf("walkTarget(%s) reads names in %v; want %v (names %v)", c.p, dirs, want, got.names)
		}
		if !slices.Equal(got.links, c.links) {
			t.Errorf("walkTarget(%s).links = %v; want %v", c.p, got.links, c.links)
		}
	}
	if got := walkTarget("rel/path"); got.placed {
		t.Errorf("walkTarget of a relative path placed it at %s", got.place)
	}
}

// TestARelativeChainAnchorIsTakenAgainstTheWorkingDirectory: a chain anchor named relatively (a test hook's) is opened
// by the ledger against the run's working directory, so R10 and OwnState take it there, not against the compiling
// process's own directory, which a probe of the relative spelling used.
func TestARelativeChainAnchorIsTakenAgainstTheWorkingDirectory(t *testing.T) {
	f := newFixture(t)
	state := filepath.Join(f.project, "state")
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	anchor := WithChainAnchor("state/chain.log")
	over := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + state + "\"]\n")
	if _, ds, err := Compile(over, f.machine, f.opts(anchor)...); err == nil || !strings.Contains(render(ds), "the chain anchor") {
		t.Errorf("fs.write %s over the relative chain anchor's place compiled: %v\n%s", state, err, render(ds))
	}
	beside := filepath.Join(f.root, "beside")
	if err := os.MkdirAll(beside, 0o755); err != nil {
		t.Fatal(err)
	}
	rt, ds, err := Compile(f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\""+beside+"\"]\n"), f.machine, f.opts(anchor)...)
	if err != nil {
		t.Fatalf("fs.write beside it refused: %v\n%s", err, render(ds))
	}
	for _, want := range []string{state, filepath.Join(state, "chain.log")} {
		if !slices.Contains(rt.OwnState, want) {
			t.Errorf("OwnState %v misses %s", rt.OwnState, want)
		}
	}
	// And an entry inside the anchor's directory, tego's own, is refused there too.
	inside := filepath.Join(state, "sub")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	in := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + inside + "\"]\n")
	if _, ds, err := Compile(in, f.machine, f.opts(anchor)...); err == nil || !strings.Contains(render(ds), "tego's own directory") {
		t.Errorf("fs.write %s inside the relative chain anchor's directory compiled: %v\n%s", inside, err, render(ds))
	}
}
