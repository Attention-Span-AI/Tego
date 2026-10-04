// SPDX-License-Identifier: Apache-2.0

// Package contracttest builds real contracts over isolated temporary trees.
// Only tests import it. Kernel-wire and intentionally malformed tables remain
// explicit in their tests instead of being passed off as compiler output.
package contracttest

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Tree maps project-relative files to contents. A trailing slash creates a
// directory. Files below bin/ are executable; other files are private data.
type Tree map[string]string

// Fixture holds the actual inputs and output of agent.Load/Compile.
type Fixture struct {
	Root, Home  string
	Contract    *agent.Contract
	Rules       *agent.RuleTable
	Diagnostics []agent.Diagnostic
}

// Path names a path in the private project. The caller supplies a relative path.
func (f *Fixture) Path(relative string) string { return filepath.Join(f.Root, relative) }

// Resolver is a deterministic DNS fixture. Unknown hosts fail instead of using
// the network; results are copied so compilation cannot mutate fixture state.
type Resolver map[string][]netip.Addr

func (r Resolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if network != "ip" {
		return nil, fmt.Errorf("contracttest: unexpected network %q", network)
	}
	addresses, ok := r[host]
	if !ok {
		return nil, fmt.Errorf("contracttest: no fixture DNS answer for %q", host)
	}
	return append([]netip.Addr(nil), addresses...), nil
}

// Build creates a temporary project and compiles its on-disk contract. A private
// executable named fixture is supplied for command: [fixture]. Options are
// appended to deterministic defaults and may override them deliberately.
func Build(t testing.TB, yaml string, tree Tree, options ...agent.CompileOption) *Fixture {
	t.Helper()
	return BuildAt(t, t.TempDir(), yaml, tree, options...)
}

// BuildAt uses an existing private project root, for tests which already have
// kernel objects or a fake proc tree rooted beside it. It never changes $HOME,
// PATH or the default resolver process-wide.
func BuildAt(t testing.TB, root, yaml string, tree Tree, options ...agent.CompileOption) *Fixture {
	t.Helper()
	home := t.TempDir()
	entries := make(Tree, len(tree)+1)
	entries["bin/fixture"] = "#!/bin/sh\nexit 0\n"
	for path, content := range tree {
		entries[path] = content
	}
	if err := createTree(root, entries); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "contract.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, loadDiagnostics, err := agent.Load(path, nil)
	if err != nil {
		t.Fatalf("load real fixture: %v; diagnostics: %v", err, loadDiagnostics)
	}
	opts := []agent.CompileOption{
		agent.WithCwd(root), agent.WithHome(home), agent.WithPATH(filepath.Join(root, "bin")),
		agent.WithMountInfo(""), agent.WithResolver(Resolver{}), agent.WithTiers(backend.Tiers()...),
		agent.WithClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }),
	}
	opts = append(opts, options...)
	// The built-in machine config as config.Load gives it with no layer file: its "~/" settings (prices, profiles,
	// registry, ledger root) expanded against the fixture's home. Compile places a setting as the open of its spelling
	// would, so config.Builtin()'s raw "~/.tego/prices.yaml" named a directory "~" in the working directory, and a
	// fixture writing its root was refused as containing it.
	machine, machineDiagnostics, err := config.LoadSources(config.Sources{}, home, os.Getuid(), config.TrustAbort)
	if err != nil {
		t.Fatalf("built-in machine config: %v; diagnostics: %v", err, machineDiagnostics)
	}
	rules, compileDiagnostics, err := agent.Compile(c, machine, opts...)
	if err != nil {
		t.Fatalf("compile real fixture: %v; diagnostics: %v", err, compileDiagnostics)
	}
	if host := hostExecutables(root, rules); len(host) > 0 {
		t.Fatalf("compiled exec entries outside the fixture's private tree %s: %v; supply them in the Tree under bin/", root, host)
	}
	return &Fixture{Root: root, Home: home, Contract: c, Rules: rules,
		Diagnostics: append(loadDiagnostics, compileDiagnostics...)}
}

// hostExecutables names the command, exec.allow and MCP entries that compiled to a file outside root. A
// fixture that takes one from the host compiles only where the host has it: the observe fixture's exec.allow
// [git] failed every test that used it as root in the KVM guest, which has no git (root-suites R1). Only an
// interpreter a fixture script names (the default #!/bin/sh) may be the host's.
func hostExecutables(root string, rules *agent.RuleTable) []string {
	roots := []string{root}
	if real, err := filepath.EvalSymlinks(root); err == nil && real != root {
		roots = append(roots, real) // Resolved follows a linked temporary directory
	}
	within := func(path string) bool {
		for _, r := range roots {
			if rel, err := filepath.Rel(r, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}
	var host []string
	for _, r := range rules.Exec {
		declared := false
		for _, source := range strings.Split(r.Source, ",") {
			declared = declared || !strings.HasPrefix(source, agent.ExecSourceInterpreter)
		}
		if declared && (!within(r.Path) || (r.Resolved != "" && !within(r.Resolved))) {
			host = append(host, r.Source+" "+r.Path)
		}
	}
	return host
}

func createTree(root string, tree Tree) error {
	paths := make([]string, 0, len(tree))
	for path := range tree {
		clean := filepath.Clean(path)
		if path == "" || clean == "." || filepath.IsAbs(path) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean != strings.TrimSuffix(path, "/") {
			return fmt.Errorf("contracttest: invalid relative tree path %q", path)
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, relative := range paths {
		path := filepath.Join(root, relative)
		if strings.HasSuffix(relative, "/") {
			if err := os.MkdirAll(path, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		mode := os.FileMode(0o600)
		if strings.HasPrefix(relative, "bin/") {
			mode = 0o700
		}
		if err := os.WriteFile(path, []byte(tree[relative]), mode); err != nil {
			return err
		}
	}
	return nil
}
