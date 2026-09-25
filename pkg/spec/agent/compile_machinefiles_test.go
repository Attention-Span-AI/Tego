// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestMovedPriceTableAndProfilesAreTegosOwn: the price table and the profiles directory are tego's own files
// wherever the machine config puts them (limits-check-doctor-cli.md §3), not only under ~/.tego, which R6a
// read-denies and R10 keeps every write entry off. Moved out, an agent could read them, and with a write entry
// over them price every model at $0 or widen every contract that extends a profile, for the runs after it.
func TestMovedPriceTableAndProfilesAreTegosOwn(t *testing.T) {
	f := newFixture(t)
	etc := filepath.Join(f.root, "etc-tego")
	profiles := filepath.Join(etc, "profiles")
	if err := os.MkdirAll(filepath.Join(profiles, "base"), 0o755); err != nil {
		t.Fatal(err)
	}
	prices := filepath.Join(etc, "prices.yaml")
	f.file(prices, "version: 1\n", 0o644)
	f.file(filepath.Join(profiles, "base", "py.yaml"), "version: 0\n", 0o644)
	m := *f.machine
	m.Prices = config.Setting[string]{Value: prices}
	m.Profiles = config.Setting[string]{Value: profiles}

	c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"./out/\"]\n")
	rt, ds, err := Compile(c, &m, f.opts()...)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, render(ds))
	}
	for _, p := range []string{prices, filepath.Join(profiles, "base", "py.yaml")} {
		for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
			if got := rt.Evaluate(Action{Kind: ActionFSRead, Path: p}, tier); got.Verdict != VerdictRefused {
				t.Errorf("tier %s: reading %s = %+v, want refused", tier, p, got)
			}
		}
	}

	for _, w := range []string{etc, filepath.Join(profiles, "base")} {
		c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + w + "\"]\n")
		if _, ds, err := Compile(c, &m, f.opts()...); err == nil || !hasCode(ds, CodeContradiction) {
			t.Errorf("fs.write %s over the price table or the profiles compiled: %v\n%s", w, err, render(ds))
		}
	}
}

// TestTheUserRegistryIsTegosOwnToWrite: the user registry's agents/ and skills/ are what other runs resolve an agent's
// name to (agent-contract.md R26), so a write entry over either, or inside either, is R10's contradiction, as for the
// profiles: with fs.write over ~/.config the agent could rewrite every user-registry contract, and the next
// `tego run <name>` would run what it wrote. An entry beside them in the registry directory, which holds neither, is
// not.
func TestTheUserRegistryIsTegosOwnToWrite(t *testing.T) {
	f := newFixture(t)
	registry := filepath.Join(f.root, "dotconfig", "tego")
	for _, d := range []string{filepath.Join(registry, "agents", "sub"), filepath.Join(registry, "cache")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	m := *f.machine
	m.Registry = config.Setting[string]{Value: registry}
	for _, w := range []string{filepath.Dir(registry), registry, filepath.Join(registry, "agents"),
		filepath.Join(registry, "agents", "sub"), filepath.Join(registry, "skills")} {
		c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + w + "\"]\n")
		_, ds, err := Compile(c, &m, f.opts()...)
		if err == nil || !hasCode(ds, CodeContradiction) || !strings.Contains(render(ds), "the user registry") {
			t.Errorf("fs.write %s over or inside the user registry compiled: %v\n%s", w, err, render(ds))
		}
	}
	c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + filepath.Join(registry, "cache") + "\"]\n")
	rt, ds, err := Compile(c, &m, f.opts()...)
	if err != nil {
		t.Fatalf("fs.write beside agents/ and skills/ refused: %v\n%s", err, render(ds))
	}
	// They are tego's own state as well, which a person's alternate for a held fs.ask write never reaches (ADR 0057
	// D2): an fs.ask scope over ~/.config is not a way into them either. But a run may read them, so they are
	// OwnReadable, not OwnState: an fs.ask_read entry beneath them compiles, and a held read there is asked, not
	// refused read-denied.
	for _, sub := range []string{"agents", "skills"} {
		p := filepath.Join(registry, sub)
		if !slices.Contains(rt.OwnReadable, p) || slices.Contains(rt.OwnState, p) {
			t.Errorf("OwnReadable %v, OwnState %v: want %s in the first only", rt.OwnReadable, rt.OwnState, p)
		}
	}
	skill := filepath.Join(registry, "skills", "s.md")
	if err := os.MkdirAll(filepath.Dir(skill), 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(skill, "a skill\n", 0o644)
	c = f.load(askReadContract(`  write: ["out/"]`, `  ask_read: ["`+skill+`"]`))
	if rt, ds, err := Compile(c, &m, f.opts()...); err != nil || findFS(rt, FSDenyRead, skill) == nil {
		t.Errorf("fs.ask_read of a skill in the user registry refused: %v\n%s", err, render(ds))
	}
	m.Registry = config.Setting[string]{} // registry: "" names none
	c = f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + registry + "\"]\n")
	if _, ds, err := Compile(c, &m, f.opts()...); err != nil {
		t.Errorf("with no user registry, fs.write %s refused: %v\n%s", registry, err, render(ds))
	}
}

// TestAWriteOverALinkOnTheWayToTegosOwnIsRefused: R10 compares a write entry with every directory that holds a
// symlink the walk to one of tego's own targets follows, as well as with where the walk lands. With
// registry: ~/.config/tego, tego a link into a dotfiles tree (a stow layout), an entry over ~/.config compared clean
// against the resolved agents/ and let the agent replace the link: every later `tego run <name>` then loaded the
// contract it planted, while run_start's contract_source spelled the same path as before. A link in the middle of the
// chain counts too, the price table, the profiles directory and the chain anchor alike, and an entry beside the link
// is still compiled.
func TestAWriteOverALinkOnTheWayToTegosOwnIsRefused(t *testing.T) {
	f := newFixture(t)
	home := filepath.Join(f.root, "home")
	stow := filepath.Join(f.root, "stow", "tego")
	dotfiles := filepath.Join(f.root, "dotfiles")
	for _, d := range []string{filepath.Join(home, ".config", "other"), filepath.Join(stow, "agents"), filepath.Join(stow, "skills"),
		filepath.Join(stow, "profiles"), dotfiles} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.file(filepath.Join(stow, "prices.yaml"), "version: 1\n", 0o644)
	// ~/.config/tego -> dotfiles/tego -> stow/tego: two links, in two directories outside where the walk lands.
	if err := os.Symlink(filepath.Join(dotfiles, "tego"), filepath.Join(home, ".config", "tego")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(stow, filepath.Join(dotfiles, "tego")); err != nil {
		t.Fatal(err)
	}
	declared := filepath.Join(home, ".config", "tego")
	for what, set := range map[string]func(m *config.Machine){
		"the user registry": func(m *config.Machine) { m.Registry = config.Setting[string]{Value: declared} },
		"the profiles directory": func(m *config.Machine) {
			m.Profiles = config.Setting[string]{Value: filepath.Join(declared, "profiles")}
		},
		"the price table": func(m *config.Machine) {
			m.Prices = config.Setting[string]{Value: filepath.Join(declared, "prices.yaml")}
		},
	} {
		m := *f.machine
		set(&m)
		for _, w := range []string{filepath.Join(home, ".config"), dotfiles} {
			c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + w + "\"]\n")
			_, ds, err := Compile(c, &m, f.opts()...)
			if err == nil || !hasCode(ds, CodeContradiction) || !strings.Contains(render(ds), what) {
				t.Errorf("%s: fs.write %s, which holds a link on the way to it, compiled: %v\n%s", what, w, err, render(ds))
			}
		}
		c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + filepath.Join(home, ".config", "other") + "\"]\n")
		if _, ds, err := Compile(c, &m, f.opts()...); err != nil {
			t.Errorf("%s: fs.write beside the link refused: %v\n%s", what, err, render(ds))
		}
	}
	// The chain anchor's directory reached through a link (~/.tego -> dotfiles/tego): a write over ~'s neighbour
	// that holds the link is refused, though it contains neither ~/.tego's spelling nor where it leads.
	anchor := filepath.Join(declared, "chain.log")
	c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + dotfiles + "\"]\n")
	if _, ds, err := Compile(c, f.machine, f.opts(WithChainAnchor(anchor))...); err == nil || !strings.Contains(render(ds), "the chain anchor") {
		t.Errorf("fs.write %s over a link on the way to the chain anchor compiled: %v\n%s", dotfiles, err, render(ds))
	}
}

// TestNoWriteEntryReachesANameOfTheContractFile: R10 protects the contract as the file the next run reads, by every
// name the walk to it reads (ADR 0059). The contract's directory and the directory its path led to were targets, and
// only the links on the way to those directories were walked, so neither an entry at the file itself nor one over the
// directory of a link in the middle of the contract path's own chain was compared: agent.yaml -> l1/x.yaml ->
// l2/real.yaml with fs.write [l1] compiled, and the agent could repoint l1/x.yaml at a contract it wrote; fs.write
// [./agent.yaml] compiled, and the agent could rewrite the contract in place.
func TestNoWriteEntryReachesANameOfTheContractFile(t *testing.T) {
	f := newFixture(t)
	l1, l2, beside := filepath.Join(f.root, "l1"), filepath.Join(f.root, "l2"), filepath.Join(f.root, "beside")
	for _, d := range []string{l1, l2, beside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	real := filepath.Join(l2, "real.yaml")
	if err := os.Symlink(real, filepath.Join(l1, "x.yaml")); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(f.project, "linked.yaml")
	if err := os.Symlink(filepath.Join(l1, "x.yaml"), linked); err != nil {
		t.Fatal(err)
	}
	compileAt := func(path, write string) (string, error) {
		f.file(real, "version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\""+write+"\"]\n", 0o644)
		if path != linked {
			f.file(path, "version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\""+write+"\"]\n", 0o644)
		}
		c, ds, err := Load(path, nil)
		if err != nil {
			t.Fatalf("load %s: %v\n%s", path, err, render(ds))
		}
		_, ds, err = Compile(c, f.machine, f.opts()...)
		return render(ds), err
	}
	plain := filepath.Join(f.project, "agent.yaml")
	for _, c := range []struct{ path, write, says string }{
		{plain, plain, "contains the contract file"},
		{linked, linked, "the contract file"},
		{linked, real, "the contract file"},
		{linked, l1, "holds the symlink " + filepath.Join(l1, "x.yaml")},
		{linked, l2, "the contract file"},
		{linked, f.project, "holds the symlink " + linked},
	} {
		if out, err := compileAt(c.path, c.write); err == nil || !strings.Contains(out, "contradiction") || !strings.Contains(out, c.says) {
			t.Errorf("contract %s with fs.write %s compiled (%v), want a contradiction saying %q:\n%s", c.path, c.write, err, c.says, out)
		}
	}
	for _, path := range []string{plain, linked} {
		if out, err := compileAt(path, beside); err != nil {
			t.Errorf("contract %s with fs.write beside every name of it refused: %v\n%s", path, err, out)
		}
	}
}

// TestTheMachineConfigsLayersAreR10Targets: every layer file a Load consulted (config.Machine.Layers), there or not
// yet, decides the runs after this one (their registry, profiles, prices and ledger root among them), so no write
// entry may reach it by any name (ADR 0059): $TEGO_CONFIG names a file anywhere, and ~/.tego/config.yaml may be a
// link into a dotfiles tree.
func TestTheMachineConfigsLayersAreR10Targets(t *testing.T) {
	f := newFixture(t)
	envDir, dot, beside := filepath.Join(f.root, "envcfg"), filepath.Join(f.root, "dot"), filepath.Join(f.root, "beside")
	for _, d := range []string{envDir, dot, beside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	env := filepath.Join(envDir, "tego.yaml")
	f.file(env, "version: 0\n", 0o600)
	f.file(filepath.Join(dot, "user.yaml"), "version: 0\n", 0o600)
	user := filepath.Join(envDir, "user.yaml")
	if err := os.Symlink(filepath.Join(dot, "user.yaml"), user); err != nil {
		t.Fatal(err)
	}
	// A layer place with no file yet (/etc/tego/config.yaml on most machines) is one a later Load reads too.
	etcDir := filepath.Join(f.root, "etc")
	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	m := *f.machine
	m.Layers = []string{filepath.Join(etcDir, "tego", "config.yaml"), user, env}
	for _, w := range []string{envDir, env, dot, filepath.Join(dot, "user.yaml"), etcDir} {
		c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + w + "\"]\n")
		if _, ds, err := Compile(c, &m, f.opts()...); err == nil || !strings.Contains(render(ds), "the machine config") {
			t.Errorf("fs.write %s over a layer of the machine config compiled: %v\n%s", w, err, render(ds))
		}
	}
	c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + beside + "\"]\n")
	if _, ds, err := Compile(c, &m, f.opts()...); err != nil {
		t.Errorf("fs.write beside the machine config's layers refused: %v\n%s", err, render(ds))
	}
}

// A layer is walked for the links on the way to it ($TEGO_CONFIG=<work>/cfglink/machine.yaml): an entry over the
// directory holding cfglink lets the agent repoint it, so every later run loads a machine config the agent wrote
// (ADR 0059). Load refuses a relative layer outright, so the path is the absolute one.
func TestALayerIsWalkedForTheLinksOnTheWay(t *testing.T) {
	f := newFixture(t)
	cfg, work := filepath.Join(f.root, "cfg"), filepath.Join(f.root, "work")
	for _, d := range []string{cfg, work} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.file(filepath.Join(cfg, "machine.yaml"), "stop_grace: 3s\n", 0o600)
	link := filepath.Join(work, "cfglink")
	if err := os.Symlink(cfg, link); err != nil {
		t.Fatal(err)
	}
	c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + work + "\"]\n")
	loaded, _, err := config.LoadSources(config.Sources{EnvFile: link + "/machine.yaml"}, f.home, os.Getuid(), config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	m := *f.machine
	m.Layers = loaded.Layers
	if _, ds, err := Compile(c, &m, f.opts()...); err == nil || !strings.Contains(render(ds), "the symlink "+link+" on the way to the machine config") {
		t.Errorf("fs.write %s over the link on the way to a layer compiled: %v\n%s", work, err, render(ds))
	}
}
