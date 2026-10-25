// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// registryWorld is a project directory (the working directory) and a user registry, under a machine config naming
// that registry and a ledger root of its own (agent-contract.md R26).
type registryWorld struct {
	project, user, runs string
}

// newRegistryWorld makes the world and changes into its project directory.
func newRegistryWorld(t *testing.T) registryWorld {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	w := registryWorld{project: filepath.Join(base, "proj"), user: filepath.Join(base, "reg"), runs: filepath.Join(base, "runs")}
	for _, d := range []string{w.project, w.user, w.runs} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(base, "tego.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+w.runs+"\nregistry: "+w.user+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	useAnchor(t, filepath.Join(t.TempDir(), "chain.log"))
	t.Chdir(w.project)
	return w
}

// contract writes a minimal contract named name at path (its directories 0755, the file 0644).
func (registryWorld) contract(t *testing.T, path, name string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("version: 0\nname: "+name+"\ncommand: [\"/bin/sh\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// compileSource compiles arg with --json and returns its source.
func compileSource(t *testing.T, arg string) *TableSource {
	t.Helper()
	code, out, errs := run(t, "compile", arg, "--offline", "--json")
	if code != identity.ExitOK {
		t.Fatalf("compile %s: exit %d stderr %s", arg, code, errs)
	}
	var tbl Table
	if err := json.Unmarshal([]byte(out), &tbl); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	return tbl.Source
}

// `tego compile retriever`: the project's agent.yaml whose name: is retriever is the contract, and the
// print names where it came from.
func TestCompileByNameFindsTheProjectsAgentFile(t *testing.T) {
	w := newRegistryWorld(t)
	path := w.contract(t, filepath.Join(w.project, "agent.yaml"), "retriever")
	src := compileSource(t, "retriever")
	if src == nil || *src != (TableSource{Path: path, Name: "retriever", Registry: "project"}) {
		t.Fatalf("source = %+v, want %s from the project registry", src, path)
	}
	code, out, errs := run(t, "compile", "retriever", "--offline")
	if code != identity.ExitOK {
		t.Fatalf("compile: exit %d stderr %s", code, errs)
	}
	if !strings.HasPrefix(out, "agent     retriever, from the project registry\ncontract  "+path+"\n") {
		t.Fatalf("print does not open with the source:\n%s", out)
	}
}

// The user registry answers a name the project does not hold; once the project holds it too the name is ambiguous,
// and each file is still reached by its path.
func TestCompileByNameTheUserRegistryAnswersAndBothAreAmbiguous(t *testing.T) {
	w := newRegistryWorld(t)
	user := w.contract(t, filepath.Join(w.user, "agents", "retriever.yaml"), "retriever")
	if src := compileSource(t, "retriever"); src == nil || src.Path != user || src.Registry != "user" {
		t.Fatalf("source = %+v, want %s from the user registry", src, user)
	}
	proj := w.contract(t, filepath.Join(w.project, ".tego", "agents", "retriever.yaml"), "retriever")
	code, out, errs := run(t, "compile", "retriever", "--offline")
	if code != identity.ExitFinding || out != "" || !strings.Contains(errs, "[agent-ambiguous]") ||
		!strings.Contains(errs, proj) || !strings.Contains(errs, user) || !strings.Contains(errs, "./.tego/agents/retriever.yaml") {
		t.Fatalf("exit %d, want 1 [agent-ambiguous] naming both files and the ./ fix\nstdout %s\nstderr %s", code, out, errs)
	}
	for _, p := range []string{"./.tego/agents/retriever.yaml", user} {
		if src := compileSource(t, p); src == nil || src.Registry != "" {
			t.Fatalf("compile %s: source = %+v, want the path alone", p, src)
		}
	}
}

// F1 of the D-REGISTRY review: a user-registry agent whose contract writes its working directory plants
// .tego/agents/<name>.yaml there during its run; the next `tego run <name>` in that directory refuses, before
// anything runs, rather than running the planted contract.
func TestARunCannotPlantTheProjectEntryItsNextRunLoads(t *testing.T) {
	calls := sandboxedLaunch(t)
	w := newRegistryWorld(t)
	w.contract(t, filepath.Join(w.user, "agents", "retriever.yaml"), "retriever")
	planted := filepath.Join(w.project, ".tego", "agents", "retriever.yaml")
	inner := startRun
	startRun = func(ctx context.Context, rt *agent.RuleTable, command []string, d tegoruntime.Deps) (tegoruntime.Result, error) {
		w.contract(t, planted, "retriever") // what the agent's shell did under fs.write ["./"]
		return inner(ctx, rt, command, d)
	}
	var errs bytes.Buffer
	argv := []string{"tego", "run", "retriever", "--offline", "--", "/bin/true"}
	if code := mainWith(t.Context(), argv, io.Discard, &errs, []Command{cmdRun()}); code != identity.ExitOK || len(*calls) != 1 {
		t.Fatalf("first run: exit %d, %d launches\n%s", code, len(*calls), errs.String())
	}
	errs.Reset()
	if code := mainWith(t.Context(), argv, io.Discard, &errs, []Command{cmdRun()}); code != identity.ExitLauncher ||
		len(*calls) != 1 || !strings.Contains(errs.String(), "[agent-ambiguous]") || !strings.Contains(errs.String(), planted) {
		t.Fatalf("the run after the plant: exit %d, %d launches, want 125 [agent-ambiguous] naming %s and nothing run\n%s",
			code, len(*calls), planted, errs.String())
	}
}

// A path still works, relative or absolute, and its source is the file's absolute path with no name.
func TestCompileByPathStillWorks(t *testing.T) {
	w := newRegistryWorld(t)
	path := w.contract(t, filepath.Join(w.project, "agent.yaml"), "retriever")
	for _, arg := range []string{"agent.yaml", "./agent.yaml", path} {
		if src := compileSource(t, arg); src == nil || *src != (TableSource{Path: path}) {
			t.Fatalf("compile %s: source = %+v, want the path alone", arg, src)
		}
	}
	_, out, _ := run(t, "compile", "agent.yaml", "--offline")
	if strings.HasPrefix(out, "agent ") {
		t.Fatalf("a path prints a registry line:\n%s", out)
	}
}

// A missing or ambiguous name is refused with the fix, by compile (exit 1, as a missing file) and by run (exit 125,
// before the agent runs).
func TestARefusedNameSaysTheFix(t *testing.T) {
	w := newRegistryWorld(t)
	w.contract(t, filepath.Join(w.project, "agent.yaml"), "alpha")
	cases := []struct {
		name, arg, code string
		setup           func()
		says            []string
	}{
		{name: "missing", arg: "retriever", code: "agent-not-found",
			says: []string{filepath.Join(w.project, ".tego", "agents", "retriever.yaml"), filepath.Join(w.user, "agents", "retriever.yaml"), "alpha", "give the contract's path"}},
		{name: "a file of the same name", arg: "alpha", code: "agent-ambiguous", setup: func() {
			if err := os.WriteFile(filepath.Join(w.project, "alpha"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}, says: []string{"./alpha"}},
		{name: "held twice", arg: "beta", code: "agent-ambiguous", setup: func() {
			w.contract(t, filepath.Join(w.project, ".tego", "agents", "beta.yaml"), "beta")
			w.contract(t, filepath.Join(w.project, "beta.yaml"), "beta") // not a registry place: no ambiguity from it
			if err := os.Rename(filepath.Join(w.project, "agent.yaml"), filepath.Join(w.project, "alpha.yaml")); err != nil {
				t.Fatal(err)
			}
			w.contract(t, filepath.Join(w.project, "agent.yaml"), "beta")
		}, says: []string{"twice", "remove one"}},
		{name: "a wrong name inside", arg: "gamma", code: "registry-entry", setup: func() {
			w.contract(t, filepath.Join(w.user, "agents", "gamma.yaml"), "delta")
		}, says: []string{`"delta"`, "rename it to delta.yaml"}},
		{name: "writable by others", arg: "zeta", code: "config-untrusted", setup: func() {
			p := w.contract(t, filepath.Join(w.user, "agents", "zeta.yaml"), "zeta")
			if err := os.Chmod(p, 0o666); err != nil {
				t.Fatal(err)
			}
		}, says: []string{"chmod go-w"}},
		// ADR 0059: an entry is read through agents/ itself, so a link that leaves it, though not the registry, is
		// refused; and it has one name, so no hard link elsewhere can rewrite it.
		{name: "a link out of agents/", arg: "eta", code: "registry-entry", setup: func() {
			w.contract(t, filepath.Join(w.user, "versions", "eta.yaml"), "eta")
			if err := os.Symlink(filepath.Join("..", "versions", "eta.yaml"), filepath.Join(w.user, "agents", "eta.yaml")); err != nil {
				t.Fatal(err)
			}
		}, says: []string{"inside agents/"}},
		{name: "a second name", arg: "theta", code: "config-untrusted", setup: func() {
			p := w.contract(t, filepath.Join(w.user, "agents", "theta.yaml"), "theta")
			asInvoker(t, p)
			if err := os.Link(p, filepath.Join(filepath.Dir(w.user), "theta-kept.yaml")); err != nil {
				t.Fatal(err)
			}
		}, says: []string{"2 names", "hard link"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.setup != nil {
				c.setup()
			}
			code, out, errs := run(t, "compile", c.arg, "--offline")
			if code != identity.ExitFinding || out != "" || !strings.Contains(errs, "["+c.code+"]") {
				t.Fatalf("compile %s: exit %d, want 1 [%s]\nstdout %s\nstderr %s", c.arg, code, c.code, out, errs)
			}
			for _, s := range c.says {
				if !strings.Contains(errs, s) {
					t.Errorf("compile %s: refusal does not say %q:\n%s", c.arg, s, errs)
				}
			}
			marker := filepath.Join(t.TempDir(), "ran")
			code, _, errs = run(t, "run", c.arg, "--", "/bin/sh", "-c", "touch "+marker)
			if code != identity.ExitLauncher || !strings.Contains(errs, "["+c.code+"]") {
				t.Fatalf("run %s: exit %d, want 125 [%s]\nstderr %s", c.arg, code, c.code, errs)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Fatalf("run %s: the agent ran", c.arg)
			}
		})
	}
}

// A contract given by its path that has a second name is refused by compile and by run, which runs nothing (ADR 0059):
// a write entry over the other name would rewrite the contract the next run loads, and R10 never sees that name.
func TestAContractWithASecondNameIsRefused(t *testing.T) {
	w := newRegistryWorld(t)
	p := w.contract(t, filepath.Join(w.project, "agent.yaml"), "alpha")
	asInvoker(t, p)
	if err := os.Link(p, filepath.Join(filepath.Dir(w.project), "kept.yaml")); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "compile", "./agent.yaml", "--offline")
	if code != identity.ExitFinding || out != "" || !strings.Contains(errs, "[config-untrusted]") || !strings.Contains(errs, "2 names") {
		t.Fatalf("compile: exit %d, want 1 [config-untrusted] naming 2 names\nstdout %s\nstderr %s", code, out, errs)
	}
	marker := filepath.Join(t.TempDir(), "ran")
	code, _, errs = run(t, "run", "./agent.yaml", "--", "/bin/sh", "-c", "touch "+marker)
	if code != identity.ExitLauncher || !strings.Contains(errs, "[config-untrusted]") {
		t.Fatalf("run: exit %d, want 125 [config-untrusted]\nstderr %s", code, errs)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("run: the agent ran")
	}
}

// A registry inside tego's own directory would make that directory readable to the agent (R6a lifts its deny for
// the contract's directory), so a name found there is refused.
func TestARegistryInsideTegosOwnDirectoryIsRefused(t *testing.T) {
	w := newRegistryWorld(t)
	w.contract(t, filepath.Join(w.runs, "agents", "retriever.yaml"), "retriever")
	cfg := filepath.Join(filepath.Dir(w.runs), "tego.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+w.runs+"\nregistry: "+w.runs+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs := run(t, "compile", "retriever", "--offline")
	if code != identity.ExitFinding || !strings.Contains(errs, "[registry-entry]") || !strings.Contains(errs, "R6a") {
		t.Fatalf("exit %d, want 1 [registry-entry] naming R6a\nstderr %s", code, errs)
	}
}

// What run records: compileForRun hands run_start the file, and the name and registry it came from; a contract given
// by path its absolute path alone; a contract tego generated none.
func TestCompileForRunReturnsTheContractSource(t *testing.T) {
	w := newRegistryWorld(t)
	m, _, err := loadMachine(config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	user := w.contract(t, filepath.Join(w.user, "agents", "retriever.yaml"), "retriever")
	proj := w.contract(t, filepath.Join(w.project, "agent.yaml"), "writer")
	for _, c := range []struct {
		o    runOptions
		want *record.ContractSource
	}{
		{runOptions{contract: "retriever", offline: true}, &record.ContractSource{Path: user, Name: "retriever", Registry: "user"}},
		{runOptions{contract: "writer", offline: true}, &record.ContractSource{Path: proj, Name: "writer", Registry: "project"}},
		{runOptions{contract: "agent.yaml", offline: true}, &record.ContractSource{Path: proj}},
		{runOptions{contract: proj, generated: true, offline: true}, nil},
	} {
		var errs bytes.Buffer
		rt, _, src, code := compileForRun(t.Context(), c.o, m, &errs)
		if rt == nil || code != identity.ExitOK {
			t.Fatalf("%s: exit %d\n%s", c.o.contract, code, errs.String())
		}
		if (src == nil) != (c.want == nil) || src != nil && *src != *c.want {
			t.Fatalf("%s: source = %+v, want %+v", c.o.contract, src, c.want)
		}
	}
}

// A contract given as clink/../agent.yaml, clink a link to <base>/cdir/sub, is the file <base>/cdir/agent.yaml the
// load read: compile refuses an entry over <base>/cdir as it refuses one given by that file's own path, and run_start's
// contract_source.path names that file. The path was cleaned lexically to <proj>/agent.yaml, a file that does not
// exist: the entry compiled and the run rewrote its own contract.
func TestAContractPathWithDotDotAfterALinkIsTheFileRead(t *testing.T) {
	w := newRegistryWorld(t)
	base := filepath.Dir(w.project)
	cdir := filepath.Join(base, "cdir")
	if err := os.MkdirAll(filepath.Join(cdir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(cdir, "sub"), filepath.Join(w.project, "clink")); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(cdir, "agent.yaml")
	if err := os.WriteFile(contract, []byte("version: 0\nname: a\ncommand: [\"/bin/sh\"]\nfs:\n  write: [\""+cdir+"\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, arg := range []string{"clink/../agent.yaml", w.project + "/clink/../agent.yaml", contract} {
		code, _, errs := run(t, "compile", arg, "--offline")
		if code != identity.ExitFinding || !strings.Contains(errs, "contains the contract file") {
			t.Errorf("compile %s with fs.write %s: exit %d, want 1 naming the contract file\nstderr %s", arg, cdir, code, errs)
		}
	}
	w.contract(t, contract, "a")
	want, err := filepath.EvalSymlinks(contract)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := loadMachine(config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range []string{"clink/../agent.yaml", w.project + "/clink/../agent.yaml"} {
		var errs bytes.Buffer
		rt, _, src, code := compileForRun(t.Context(), runOptions{contract: arg, offline: true}, m, &errs)
		if rt == nil || code != identity.ExitOK {
			t.Fatalf("%s: exit %d\n%s", arg, code, errs.String())
		}
		if src == nil || src.Path != want {
			t.Errorf("%s: contract_source = %+v, want the file read, %s", arg, src, want)
		}
	}
}

// F3 of the D-REGISTRY review: "-" is compile's standard input and nothing else's. run, watch --boundary and adopt
// --boundary refuse it as a usage error before anything runs: read as standard input it would consume the agent's
// stdin and record no contract_source, which says tego generated the contract.
func TestStandardInputIsNoContractForARun(t *testing.T) {
	calls := sandboxedLaunch(t)
	w := newRegistryWorld(t)
	w.contract(t, filepath.Join(w.project, "-"), "dash") // a file named "-" is reached as ./-
	m, _, err := loadMachine(config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	for _, argv := range [][]string{
		{"tego", "run", "-", "--offline", "--", "/bin/true"},
		{"tego", "watch", "--offline", "--boundary", "-", "--", "/bin/true"},
	} {
		var errs bytes.Buffer
		cmds := []Command{cmdRun(), cmdWatch()}
		if code := mainWith(t.Context(), argv, io.Discard, &errs, cmds); code != identity.ExitUsage || len(*calls) != 0 ||
			!strings.Contains(errs.String(), "[usage]") || !strings.Contains(errs.String(), "./-") {
			t.Fatalf("%v: exit %d, %d launches, want 2 [usage] naming ./- and nothing run\n%s", argv[1:], code, len(*calls), errs.String())
		}
	}
	var errs bytes.Buffer
	// The owner's home is the test's: a boundary adoption makes the owner's ~/.tego before it compiles (makeOwnRecords),
	// and the usage error must come first and make nothing (as root the passwd home was /root).
	home := t.TempDir()
	prevHome := adoptHomeOf
	adoptHomeOf = func(int) (string, error) { return home, nil }
	t.Cleanup(func() { adoptHomeOf = prevHome })
	a := &preparedAdoption{m: m, boundary: true, cleanup: func() {}, owner: os.Getuid()}
	if rt, code := compileAdoptionTable(t.Context(), m, adoptOptions{boundary: "-"}, adopt.Process{}, a, &errs); rt != nil ||
		code != identity.ExitUsage || !strings.Contains(errs.String(), "[usage]") {
		t.Fatalf("adopt --boundary -: table %v, exit %d, want 2 [usage]\n%s", rt != nil, code, errs.String())
	}
	if _, err := os.Lstat(filepath.Join(home, ".tego")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("adopt --boundary -: the owner's ~/.tego was made before the usage error: %v", err)
	}
	var out bytes.Buffer
	argv := []string{"tego", "run", "./-", "--offline", "--", "/bin/true"}
	if code := mainWith(t.Context(), argv, &out, &errs, []Command{cmdRun()}); code != identity.ExitOK || len(*calls) != 1 || (*calls)[0].name != "dash" {
		t.Fatalf("run ./-: exit %d, launches %+v\n%s", code, *calls, errs.String())
	}
}

// A boundary adoption makes the owner's ~/.tego before it compiles (makeOwnRecords), so the deny of the owner's own
// records attaches; a boundary that cannot load is refused before that, with nothing made, as "-" is (the root suites
// of 2026-10-27 found /root/.tego made before the refusal). The owner's home and the machine's ledger root are the
// test's (newRegistryWorld's ledger_root, TestMain's isolated machine), never the invoking user's ~/.tego.
func TestAdoptRefusesABoundaryThatCannotLoadBeforeMakingTheOwnersRecords(t *testing.T) {
	w := newRegistryWorld(t)
	good := w.contract(t, filepath.Join(w.project, "agent.yaml"), "alpha")
	w.contract(t, filepath.Join(w.user, "agents", "gamma.yaml"), "delta") // a wrong name inside
	broken := filepath.Join(w.project, "broken.yaml")
	if err := os.WriteFile(broken, []byte("version: 0\nname: broken\ncommand: [\"/bin/sh\"]\nno_such_key: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, _, err := loadMachine(config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	prevHome := adoptHomeOf
	t.Cleanup(func() { adoptHomeOf = prevHome })
	adopt1 := func(t *testing.T, boundary string) (string, *agent.RuleTable, int, string) {
		t.Helper()
		home := t.TempDir()
		adoptHomeOf = func(int) (string, error) { return home, nil }
		var errs bytes.Buffer
		a := &preparedAdoption{m: m, boundary: true, cleanup: func() {}, owner: os.Getuid()}
		rt, code := compileAdoptionTable(t.Context(), m, adoptOptions{boundary: boundary}, adopt.Process{}, a, &errs)
		a.cleanup()
		return home, rt, code, errs.String()
	}
	for _, c := range []struct{ name, boundary, code string }{
		{"a missing file", filepath.Join(w.project, "gone.yaml"), agent.CodePathMissing},
		{"a name in no registry", "retriever", "agent-not-found"},
		{"a registry entry of another name", "gamma", "registry-entry"},
		{"a file that does not load", broken, agent.CodeSchema},
	} {
		t.Run(c.name, func(t *testing.T) {
			home, rt, code, errs := adopt1(t, c.boundary)
			if rt != nil || code != identity.ExitLauncher || !strings.Contains(errs, "["+c.code+"]") {
				t.Fatalf("adopt --boundary %s: table %v, exit %d, want 125 [%s]\n%s", c.boundary, rt != nil, code, c.code, errs)
			}
			if _, err := os.Lstat(filepath.Join(home, ".tego")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("adopt --boundary %s: the owner's ~/.tego was made before the refusal: %v", c.boundary, err)
			}
		})
	}
	// The same compile of a boundary that loads makes it, so the absence above is the refusal's order, not the stub's.
	home, rt, code, errs := adopt1(t, good)
	if rt == nil {
		t.Fatalf("adopt --boundary %s: exit %d\n%s", good, code, errs)
	}
	if fi, err := os.Lstat(filepath.Join(home, ".tego")); err != nil || !fi.IsDir() {
		t.Fatalf("adopt --boundary %s: the owner's ~/.tego after the compile: %v %v, want a directory", good, fi, err)
	}
}

// RD1 of the D-REGISTRY review: watch and adopt hand run_start the contract's source through their own wiring, which
// TestCompileForRunReturnsTheContractSource does not reach. A watch with no boundary, whose contract tego wrote to a
// temporary file, records none; with a boundary, by name or by path, it records the file. adopt's compile keeps the
// boundary's source for run_start (preparedAdoption.source) and has none for its own record-only contract.
func TestWatchAndAdoptHandRunStartTheContractSource(t *testing.T) {
	calls := sandboxedLaunch(t)
	w := newRegistryWorld(t)
	user := w.contract(t, filepath.Join(w.user, "agents", "retriever.yaml"), "retriever")
	proj := w.contract(t, filepath.Join(w.project, "agent.yaml"), "writer")
	for _, c := range []struct {
		boundary []string
		want     *record.ContractSource
	}{
		{nil, nil},
		{[]string{"--boundary", "retriever"}, &record.ContractSource{Path: user, Name: "retriever", Registry: "user"}},
		{[]string{"--boundary", "agent.yaml"}, &record.ContractSource{Path: proj}},
	} {
		*calls = nil
		var errs bytes.Buffer
		argv := append(append([]string{"tego", "watch", "--offline"}, c.boundary...), "--", "/bin/true")
		if code := mainWith(t.Context(), argv, io.Discard, &errs, []Command{cmdWatch()}); code != identity.ExitOK || len(*calls) != 1 {
			t.Fatalf("%v: exit %d, %d launches\n%s", argv[2:], code, len(*calls), errs.String())
		}
		if got := (*calls)[0].source; (got == nil) != (c.want == nil) || got != nil && *got != *c.want {
			t.Fatalf("%v: run_start contract_source %+v, want %+v", argv[2:], got, c.want)
		}
	}

	home := t.TempDir()
	prevHome := adoptHomeOf
	adoptHomeOf = func(int) (string, error) { return home, nil }
	t.Cleanup(func() { adoptHomeOf = prevHome })
	m, _, err := loadMachine(config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		boundary string
		want     *record.ContractSource
	}{
		{"retriever", &record.ContractSource{Path: user, Name: "retriever", Registry: "user"}},
		{proj, &record.ContractSource{Path: proj}},
		{"", nil},
	} {
		var errs bytes.Buffer
		a := &preparedAdoption{m: m, boundary: c.boundary != "", cleanup: func() {}, owner: os.Getuid()}
		target := adopt.Process{Comm: "agent", Exe: "/bin/true", Argv: []string{"/bin/true"}}
		rt, code := compileAdoptionTable(t.Context(), m, adoptOptions{boundary: c.boundary}, target, a, &errs)
		a.cleanup()
		if rt == nil {
			t.Fatalf("adopt --boundary %q: exit %d\n%s", c.boundary, code, errs.String())
		}
		if (a.source == nil) != (c.want == nil) || a.source != nil && *a.source != *c.want {
			t.Fatalf("adopt --boundary %q: source %+v, want %+v", c.boundary, a.source, c.want)
		}
		if d := a.deps(time.Time{}, slog.New(slog.DiscardHandler)); d.ContractSource != a.source { // what run_start is written from
			t.Fatalf("adopt --boundary %q: AdoptDeps.ContractSource %+v, want %+v", c.boundary, d.ContractSource, a.source)
		}
	}
}
