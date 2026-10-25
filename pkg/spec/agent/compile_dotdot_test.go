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

// dotDotLayout is <root>/work/lnk -> <root>/real/sub: "<root>/work/lnk/../x" names <root>/real/x as the kernel walks
// it, and <root>/work/x as filepath.Clean spells it.
func dotDotLayout(t *testing.T, f *fixture) (work, real string) {
	t.Helper()
	work, real = filepath.Join(f.root, "work"), filepath.Join(f.root, "real")
	for _, d := range []string{work, filepath.Join(real, "sub")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(real, "sub"), filepath.Join(work, "lnk")); err != nil {
		t.Fatal(err)
	}
	return work, real
}

// TestALayerWithDotDotAfterALinkIsTheFileTheLoadRead: $TEGO_CONFIG=<work>/lnk/../machine.yaml is read, by the
// kernel's walk, at <real>/machine.yaml, and R10 keeps every write entry off that file. The layer was recorded by
// filepath.Abs, which cleaned it lexically to <work>/machine.yaml, a file that does not exist, so fs.write [<real>]
// compiled and the run rewrote the machine config of every later run. OwnReadable holds the file read
// too. The relative spelling lnk/../machine.yaml is refused by the Load (config's
// TestLoadSourcesRefusesARelativeLayer).
func TestALayerWithDotDotAfterALinkIsTheFileTheLoadRead(t *testing.T) {
	f := newFixture(t)
	work, real := dotDotLayout(t, f)
	f.file(filepath.Join(real, "machine.yaml"), "stop_grace: 3s\n", 0o600)
	c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + real + "\"]\n")
	for _, spelled := range []string{work + "/lnk/../machine.yaml"} {
		loaded, _, err := config.LoadSources(config.Sources{EnvFile: spelled}, f.home, os.Getuid(), config.TrustAbort)
		if err != nil {
			t.Fatal(err)
		}
		if loaded.StopGrace.Value.Seconds() != 3 {
			t.Fatalf("%s: the Load did not read %s", spelled, filepath.Join(real, "machine.yaml"))
		}
		m := *f.machine
		m.Layers = loaded.Layers
		if _, ds, err := Compile(c, &m, f.opts()...); err == nil || !strings.Contains(render(ds), "the machine config") {
			t.Errorf("layer %s: fs.write %s over the machine config the Load read compiled: %v\n%s", spelled, real, err, render(ds))
		}
		beside := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + filepath.Join(f.root, "beside") + "\"]\n")
		if err := os.MkdirAll(filepath.Join(f.root, "beside"), 0o755); err != nil {
			t.Fatal(err)
		}
		rt, ds, err := Compile(beside, &m, f.opts()...)
		if err != nil {
			t.Fatalf("layer %s: fs.write beside it refused: %v\n%s", spelled, err, render(ds))
		}
		if !slices.Contains(rt.OwnReadable, filepath.Join(real, "machine.yaml")) {
			t.Errorf("layer %s: OwnReadable %v misses the machine config the Load read", spelled, rt.OwnReadable)
		}
		if slices.Contains(rt.OwnReadable, filepath.Join(work, "machine.yaml")) {
			t.Errorf("layer %s: OwnReadable %v names %s, which the Load never read", spelled, rt.OwnReadable, filepath.Join(work, "machine.yaml"))
		}
	}
}

// TestAContractPathWithDotDotAfterALinkIsTheFileLoadRead: a contract given as <work>/lnk/../agent.yaml, or relatively
// as lnk/../agent.yaml, is the file <real>/agent.yaml Load read. R10 keeps every write entry off that file and its
// directory's links, and ContractPath (what run_start records as contract_source.path, and where the .env scan
// starts) names it. ContractPath was cleaned lexically to <work>/agent.yaml, a file that does not exist, so
// fs.write [<real>] compiled and the run rewrote its own contract.
func TestAContractPathWithDotDotAfterALinkIsTheFileLoadRead(t *testing.T) {
	f := newFixture(t)
	work, real := dotDotLayout(t, f)
	beside := filepath.Join(f.root, "beside")
	if err := os.MkdirAll(beside, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)
	compileAt := func(spelled, write string) (*RuleTable, string, error) {
		f.file(filepath.Join(real, "agent.yaml"), "version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\""+write+"\"]\n", 0o644)
		c, ds, err := Load(spelled, nil)
		if err != nil {
			t.Fatalf("load %s: %v\n%s", spelled, err, render(ds))
		}
		rt, ds, err := Compile(c, f.machine, f.opts(WithCwd(work))...)
		return rt, render(ds), err
	}
	for _, spelled := range []string{work + "/lnk/../agent.yaml", "lnk/../agent.yaml"} {
		if _, out, err := compileAt(spelled, real); err == nil || !strings.Contains(out, "contains the contract file") {
			t.Errorf("contract %s: fs.write %s over the contract Load read compiled: %v\n%s", spelled, real, err, out)
		}
		if _, out, err := compileAt(spelled, work); err == nil || !strings.Contains(out, "holds the symlink "+filepath.Join(work, "lnk")) {
			t.Errorf("contract %s: fs.write %s over the link its path walks compiled: %v\n%s", spelled, work, err, out)
		}
		rt, out, err := compileAt(spelled, beside)
		if err != nil {
			t.Fatalf("contract %s: fs.write beside it refused: %v\n%s", spelled, err, out)
		}
		if want := filepath.Join(real, "agent.yaml"); rt.ContractPath != want {
			t.Errorf("contract %s: ContractPath %s, want the file Load read, %s", spelled, rt.ContractPath, want)
		}
	}
}

// TestARegistryWithDotDotAfterALinkIsTheDirectoryItsEntriesAreReadFrom: registry: <work>/lnk/../reg is opened, by the
// kernel's walk, at <real>/reg, and R10 keeps every write entry off its agents/ and skills/ there (made here; not made
// yet is TestARegistryNotMadeYetIsPlacedWhereItsWalkWillLand's).
// The targets were joined with filepath.Join, which cleaned them to <work>/reg/agents, so fs.write [<real>] compiled
// and the run could plant the contract a later `tego run <name>` resolves. OwnReadable holds the
// directories read too.
func TestARegistryWithDotDotAfterALinkIsTheDirectoryItsEntriesAreReadFrom(t *testing.T) {
	f := newFixture(t)
	work, real := dotDotLayout(t, f)
	if err := os.MkdirAll(filepath.Join(real, "reg", "agents"), 0o755); err != nil {
		t.Fatal(err)
	}
	beside := filepath.Join(f.root, "beside")
	if err := os.MkdirAll(beside, 0o755); err != nil {
		t.Fatal(err)
	}
	m := *f.machine
	m.Registry.Value = work + "/lnk/../reg"
	for _, w := range []string{real, filepath.Join(real, "reg"), filepath.Join(real, "reg", "agents"), filepath.Join(real, "reg", "skills")} {
		c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + w + "\"]\n")
		if _, ds, err := Compile(c, &m, f.opts()...); err == nil || !strings.Contains(render(ds), "the user registry's") {
			t.Errorf("registry %s: fs.write %s over the registry read compiled: %v\n%s", m.Registry.Value, w, err, render(ds))
		}
	}
	c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + beside + "\"]\n")
	rt, ds, err := Compile(c, &m, f.opts()...)
	if err != nil {
		t.Fatalf("fs.write beside the registry refused: %v\n%s", err, render(ds))
	}
	for _, want := range []string{filepath.Join(real, "reg", "agents"), filepath.Join(real, "reg", "skills")} {
		if !slices.Contains(rt.OwnReadable, want) {
			t.Errorf("OwnReadable %v misses %s", rt.OwnReadable, want)
		}
	}
	if slices.Contains(rt.OwnReadable, filepath.Join(work, "reg", "agents")) {
		t.Errorf("OwnReadable %v names %s, which the registry is not read from", rt.OwnReadable, filepath.Join(work, "reg", "agents"))
	}
}

// TestWalkedPathSpellsWhereTheKernelsWalkLands: Clean's spelling when no ".." follows a name, else the directory up to
// the last ".." placed by the kernel's walk and the names after it kept.
func TestWalkedPathSpellsWhereTheKernelsWalkLands(t *testing.T) {
	f := newFixture(t)
	work, real := dotDotLayout(t, f)
	for _, c := range []struct{ in, want string }{
		{work + "//./x/", filepath.Join(work, "x")},
		{work + "/lnk/x", filepath.Join(work, "lnk", "x")},
		{work + "/lnk/../x", filepath.Join(real, "x")},
		{work + "/lnk/../lnk2/../y/z", filepath.Join(real, "y", "z")},
		{work + "/a/../x", filepath.Join(work, "x")},
		{work + "/lnk/..", real},
	} {
		got, ok := WalkedPath(c.in)
		if !ok || got != c.want {
			t.Errorf("WalkedPath(%s) = %s, %v, want %s", c.in, got, ok, c.want)
		}
	}
	if _, ok := WalkedPath("rel/../x"); ok {
		t.Error("WalkedPath placed a relative path")
	}
}

// TestARegistryNotMadeYetIsPlacedWhereItsWalkWillLand: a registry whose directory is not made yet is placed where the
// kernel's walk of it lands once it is made, as realpath -m places it, whatever its spelling: "." and "//" are no
// step, "x/.." goes up from x, and a link on the way is followed, before a ".." too. R10 placed only a path that
// exists, or whose directory does, so a registry's agents/ below a missing reg/ kept its raw spelling: fs.write
// [<the place>] compiled, the run made reg/agents/x.yaml there, and the next `tego run x` ran the contract the agent
// wrote. OwnReadable holds the place too.
func TestARegistryNotMadeYetIsPlacedWhereItsWalkWillLand(t *testing.T) {
	f := newFixture(t)
	work, real := dotDotLayout(t, f)
	if err := os.MkdirAll(filepath.Join(work, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	beside := filepath.Join(f.root, "beside")
	if err := os.MkdirAll(beside, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ reg, place string }{
		{work + "/./reg", filepath.Join(work, "reg")},
		{work + "//reg", filepath.Join(work, "reg")},
		{work + "/x/../reg", filepath.Join(work, "reg")},
		{work + "/lnk/../reg", filepath.Join(real, "reg")},
		{work + "/lnk/reg", filepath.Join(real, "sub", "reg")},
	} {
		m := *f.machine
		m.Registry.Value = c.reg
		over := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + c.place + "\"]\n")
		if _, ds, err := Compile(over, &m, f.opts()...); err == nil || !strings.Contains(render(ds), "the user registry's") {
			t.Errorf("registry %s (not made): fs.write %s over where it will be made compiled: %v\n%s", c.reg, c.place, err, render(ds))
		}
		next := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + beside + "\"]\n")
		rt, ds, err := Compile(next, &m, f.opts()...)
		if err != nil {
			t.Errorf("registry %s (not made): fs.write beside it refused: %v\n%s", c.reg, err, render(ds))
			continue
		}
		for _, want := range []string{filepath.Join(c.place, "agents"), filepath.Join(c.place, "skills")} {
			if !slices.Contains(rt.OwnReadable, want) {
				t.Errorf("registry %s (not made): OwnReadable %v misses %s", c.reg, rt.OwnReadable, want)
			}
		}
		if _, err := os.Lstat(c.place); err == nil {
			t.Fatalf("compile made %s", c.place)
		}
	}
}

// TestTargetsBelowAMissingDirectoryArePlacedWhereTheirWalkWillLand: the price table, the profiles directory and the
// chain anchor, set below a directory not made yet beyond a link, are placed where the kernel's walk lands once it is
// made, as the registry is: R10 refuses fs.write [<lnk's target>/new], over where the run would make them, and
// OwnState holds the place. They kept the spelling through the link, which no write entry is compared with, so the
// entry compiled and the run could write the prices, the profiles or the anchor a later run loads (the class).
func TestTargetsBelowAMissingDirectoryArePlacedWhereTheirWalkWillLand(t *testing.T) {
	f := newFixture(t)
	work, real := dotDotLayout(t, f)
	beside := filepath.Join(f.root, "beside")
	if err := os.MkdirAll(beside, 0o755); err != nil {
		t.Fatal(err)
	}
	newDir := filepath.Join(real, "sub", "new")
	for _, c := range []struct{ name, own string }{
		{"the price table", filepath.Join(newDir, "prices.yaml")},
		{"the profiles directory", filepath.Join(newDir, "profiles")},
		{"the chain anchor", newDir},
	} {
		m := *f.machine
		var extra []CompileOption
		switch c.name {
		case "the price table":
			m.Prices.Value = work + "/lnk/new/prices.yaml"
		case "the profiles directory":
			m.Profiles.Value = work + "/lnk/new/profiles"
		default:
			extra = append(extra, WithChainAnchor(work+"/lnk/new/chain.log"))
		}
		over := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + newDir + "\"]\n")
		if _, ds, err := Compile(over, &m, f.opts(extra...)...); err == nil || !strings.Contains(render(ds), c.name) {
			t.Errorf("%s (not made): fs.write %s over where it will be made compiled: %v\n%s", c.name, newDir, err, render(ds))
		}
		next := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + beside + "\"]\n")
		rt, ds, err := Compile(next, &m, f.opts(extra...)...)
		if err != nil {
			t.Errorf("%s (not made): fs.write beside it refused: %v\n%s", c.name, err, render(ds))
			continue
		}
		if !slices.Contains(rt.OwnState, c.own) {
			t.Errorf("%s (not made): OwnState %v misses %s", c.name, rt.OwnState, c.own)
		}
		if _, err := os.Lstat(newDir); err == nil {
			t.Fatalf("compile made %s", newDir)
		}
	}
}

// TestARelativePriceTableAndProfilesArePlacedAgainstTheCwd: a machine config not expanded by a Load (config.Builtin()
// as Compile's callers pass it: prices: ~/.tego/prices.yaml) names its price table and profiles relative to the
// working directory, where their loaders open them as given, in a directory literally named "~". R10 and OwnState
// place them there, as the registry's directories are (asWalked): resolved as given, a relative path that is not there
// stayed relative, no write entry was compared with it, and fs.write [<cwd>/~] compiled (the class).
func TestARelativePriceTableAndProfilesArePlacedAgainstTheCwd(t *testing.T) {
	f := newFixture(t)
	tilde := filepath.Join(f.project, "~")
	if err := os.MkdirAll(tilde, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, place string }{
		{"the price table", filepath.Join(tilde, ".tego", "prices.yaml")},
		{"the profiles directory", filepath.Join(tilde, ".tego", "profiles")},
	} {
		m := *f.machine
		if c.name == "the price table" {
			m.Prices.Value = "~/.tego/prices.yaml"
		} else {
			m.Profiles.Value = "~/.tego/profiles"
		}
		over := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + tilde + "\"]\n")
		if _, ds, err := Compile(over, &m, f.opts()...); err == nil || !strings.Contains(render(ds), c.name) {
			t.Errorf("%s %s: fs.write %s over it compiled: %v\n%s", c.name, c.place, tilde, err, render(ds))
		}
		next := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + f.root + "/beside\"]\n")
		if err := os.MkdirAll(filepath.Join(f.root, "beside"), 0o755); err != nil {
			t.Fatal(err)
		}
		rt, ds, err := Compile(next, &m, f.opts()...)
		if err != nil {
			t.Errorf("%s: fs.write beside it refused: %v\n%s", c.name, err, render(ds))
			continue
		}
		if !slices.Contains(rt.OwnState, c.place) {
			t.Errorf("%s: OwnState %v misses %s", c.name, rt.OwnState, c.place)
		}
	}
}

// TestAnR10TargetNoWalkPlacesRefusesEveryWriteEntry: a registry through a loop of links cannot be placed, so no write
// entry can be shown to stay off it: each is refused, naming the target, rather than compared with its raw spelling.
// A contract with no write entry still compiles.
func TestAnR10TargetNoWalkPlacesRefusesEveryWriteEntry(t *testing.T) {
	f := newFixture(t)
	work, _ := dotDotLayout(t, f)
	if err := os.Symlink(filepath.Join(work, "loopb"), filepath.Join(work, "loopa")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(work, "loopa"), filepath.Join(work, "loopb")); err != nil {
		t.Fatal(err)
	}
	beside := filepath.Join(f.root, "beside")
	if err := os.MkdirAll(beside, 0o755); err != nil {
		t.Fatal(err)
	}
	m := *f.machine
	m.Registry.Value = work + "/loopa/reg"
	c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + beside + "\"]\n")
	if _, ds, err := Compile(c, &m, f.opts()...); err == nil || !strings.Contains(render(ds), "cannot place the user registry's agents/") {
		t.Errorf("registry %s (no place): fs.write %s compiled: %v\n%s", m.Registry.Value, beside, err, render(ds))
	}
	none := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\n")
	if _, ds, err := Compile(none, &m, f.opts()...); err != nil {
		t.Errorf("registry %s (no place): a contract with no write entry refused: %v\n%s", m.Registry.Value, err, render(ds))
	}
}

// TestATargetThatIsADanglingLinkIsPlacedWhereTheLinkLeads: a registry, a price table, a profiles directory, a chain
// anchor or a machine config layer that is a symlink leading nowhere yet is opened by its loader through the link, so
// a file the run makes where the link leads is what a later run loads. R10 placed such a target at the link's own
// spelling (resolveProbe answers a link leading nowhere as itself), and a registry's agents/ below it beside the link:
// fs.write over the link's missing target compiled, the run planted <target>/agents/x.yaml or the price table, and
// the next run loaded it. Each is placed where the walk lands once the target is made, as realpath -m
// places it: the entry is refused, OwnReadable or OwnState holds the place, and a final link in a loop, which no walk
// places, refuses every write entry.
func TestATargetThatIsADanglingLinkIsPlacedWhereTheLinkLeads(t *testing.T) {
	f := newFixture(t)
	work, real := dotDotLayout(t, f)
	beside := filepath.Join(f.root, "beside")
	if err := os.MkdirAll(beside, 0o755); err != nil {
		t.Fatal(err)
	}
	link := func(name, target string) string {
		t.Helper()
		l := filepath.Join(work, name)
		if err := os.Symlink(target, l); err != nil {
			t.Fatal(err)
		}
		return l
	}
	regLink := link("dang", filepath.Join(real, "newreg"))
	pricesLink := link("prices.yaml", filepath.Join(real, "pt", "prices.yaml"))
	profilesLink := link("profiles", "../real/pp/profiles") // a relative link, taken from the link's directory
	anchorLink := link("chain.log", filepath.Join(real, "ca", "chain.log"))
	layerLink := link("machine.yaml", filepath.Join(real, "machine.yaml"))
	for _, c := range []struct {
		name   string
		set    func(m *config.Machine) []CompileOption
		over   []string // write entries over where the link leads, each refused
		own    []string // the places OwnReadable or OwnState hold
		inRead bool     // own is in OwnReadable, not OwnState
	}{
		{"the user registry's agents/", func(m *config.Machine) []CompileOption { m.Registry.Value = regLink; return nil },
			[]string{real, filepath.Join(real, "newreg")},
			[]string{filepath.Join(real, "newreg", "agents"), filepath.Join(real, "newreg", "skills")}, true},
		{"the price table", func(m *config.Machine) []CompileOption { m.Prices.Value = pricesLink; return nil },
			[]string{real}, []string{filepath.Join(real, "pt", "prices.yaml")}, false},
		{"the profiles directory", func(m *config.Machine) []CompileOption { m.Profiles.Value = profilesLink; return nil },
			[]string{real}, []string{filepath.Join(real, "pp", "profiles")}, false},
		{"the chain anchor", func(*config.Machine) []CompileOption { return []CompileOption{WithChainAnchor(anchorLink)} },
			[]string{real, filepath.Join(real, "ca")}, []string{filepath.Join(real, "ca", "chain.log")}, false},
		{"the machine config", func(m *config.Machine) []CompileOption { m.Layers = []string{layerLink}; return nil },
			[]string{real}, []string{filepath.Join(real, "machine.yaml")}, true},
	} {
		m := *f.machine
		extra := c.set(&m)
		for _, entry := range c.over {
			over := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + entry + "\"]\n")
			if _, ds, err := Compile(over, &m, f.opts(extra...)...); err == nil || !strings.Contains(render(ds), c.name) {
				t.Errorf("%s (a link leading nowhere yet): fs.write %s over where it leads compiled: %v\n%s", c.name, entry, err, render(ds))
			}
		}
		next := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + beside + "\"]\n")
		rt, ds, err := Compile(next, &m, f.opts(extra...)...)
		if err != nil {
			t.Errorf("%s (a link leading nowhere yet): fs.write beside it refused: %v\n%s", c.name, err, render(ds))
			continue
		}
		list := rt.OwnState
		if c.inRead {
			list = rt.OwnReadable
		}
		for _, want := range c.own {
			if !slices.Contains(list, want) {
				t.Errorf("%s (a link leading nowhere yet): %v misses %s", c.name, list, want)
			}
		}
	}
	for _, p := range []string{"newreg", "pt", "pp", "ca", "machine.yaml"} {
		if _, err := os.Lstat(filepath.Join(real, p)); err == nil {
			t.Fatalf("compile made %s", filepath.Join(real, p))
		}
	}
	// A final link in a loop leads nowhere a walk places: every write entry is refused, naming the target.
	loop := link("loopa", filepath.Join(work, "loopb"))
	link("loopb", loop)
	m := *f.machine
	m.Registry.Value = loop
	c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + beside + "\"]\n")
	if _, ds, err := Compile(c, &m, f.opts()...); err == nil || !strings.Contains(render(ds), "cannot place the user registry's agents/") {
		t.Errorf("registry %s (a loop): fs.write %s compiled: %v\n%s", loop, beside, err, render(ds))
	}
}

// TestPlacePathFollowsADirectoryLinkLeadingNowhere: a name below a directory that is a symlink leading nowhere yet is
// placed where the link leads, by placePath and walkTarget alike, since every walk goes through a directory; the
// link's own spelling with the name beneath it, which placePath answered, is a place no walk reaches. A
// final link leading nowhere is itself to placePath (compiler.resolve) and where it leads to walkTarget (R10's
// targets), and a final link in a loop is not placed by walkTarget.
func TestPlacePathFollowsADirectoryLinkLeadingNowhere(t *testing.T) {
	f := newFixture(t)
	work, real := dotDotLayout(t, f)
	dang := filepath.Join(work, "dang")
	if err := os.Symlink(filepath.Join(real, "new"), dang); err != nil {
		t.Fatal(err)
	}
	loop := filepath.Join(work, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		p, path, target  string
		pathOK, targetOK bool
	}{
		{dang + "/agents", filepath.Join(real, "new", "agents"), filepath.Join(real, "new", "agents"), true, true},
		{dang, dang, filepath.Join(real, "new"), true, true},
		{loop, loop, loop, true, false},
		{loop + "/agents", loop + "/agents", loop + "/agents", false, false},
	} {
		if got, ok := placePath(c.p); got != c.path || ok != c.pathOK {
			t.Errorf("placePath(%s) = %s, %v; want %s, %v", c.p, got, ok, c.path, c.pathOK)
		}
		if got := walkTarget(c.p); got.place != c.target || got.placed != c.targetOK {
			t.Errorf("walkTarget(%s) = %s, %v; want %s, %v", c.p, got.place, got.placed, c.target, c.targetOK)
		}
	}
}
