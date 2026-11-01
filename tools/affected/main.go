// SPDX-License-Identifier: Apache-2.0

// Command affected says what a change-scoped precommit run must check: `make precommit-affected BASE=<rev>` and
// scripts/precommit.sh with TEGO_PRECOMMIT_SINCE=<rev> run what it selects. It is for in-between checks (an agent's
// run before it hands a branch over, a merge queue); a merge to main keeps the full gate (docs/OPERATIONS.md,
// "Precommit modes").
//
// The change is the working tree against the merge base of HEAD and -base: committed, staged, unstaged and
// untracked files, deleted ones included. Each file is classified, and the classes decide the selection:
//
//   - global input (go.mod, go.sum, Makefile, .golangci.yml, .github/, .githooks/, .goreleaser.yaml, scripts/,
//     test/vm/, test/e2e/, test/*-skips.txt, tools/, internal/testutil/, bpf/, internal/bpf/, the license files, the
//     other files the script self-tests read (the edgelint fixture, test/workloads/build/, two test files), a shell
//     script outside a Go package, any *_test.sh, a test file that takes its directory on or off the tegotesthooks
//     list): the FULL gate, with the reason printed;
//   - Go source of a package: that package and every package whose build or test binary depends on it, in each
//     build (default, integration, tegobpf, integration+tegobpf, tegotesthooks), from `go list -e -test -json`;
//   - a _test.go file: that package's tests;
//   - an embedded file (go:embed): as a change to the embedding package's source (or its tests, for a test embed);
//   - testdata or any other file under a package's directory: the owning package's tests (a deleted one: the
//     owner's source, since it may have been embedded);
//   - Markdown outside testdata, not embedded: docs (a deleted one under a package: the owner's source); a change of
//     docs alone is the quick docs gate (rulecheck, check-spdx and the tests that read Markdown);
//   - any other file: the packages whose tests name it (a path literal, or a known reader); none means FULL.
//
// Two rules add packages whatever the change: the source scanners (tests that read the tree rather than import the
// changed code, found by scanning test code for walks of the module, reads of .go files and repo-root paths, seeded
// with the known ones) always run, as single tests where the scan can name them; and the binary closure: a package
// whose tests build, run or list a package of this module by its path (cmd/tego, cmd/tego-control, a test
// workload), or whose test binary links a helper whose own code names one, is selected when the change reaches that
// package's dependency closure in any build ("./..." and ".../..." name every package under that directory). The
// lint covers every package the vets do.
//
// Usage: go run ./tools/affected [-base REV] [-C DIR] [-plan]
//
// Without -plan it prints the explanation; with -plan it prints the plan on stdout (one directive per line:
// "mode scoped|docs|full", "reason TEXT", "vet TAGS DIR...", "test TAGS DIR...", "run TAGS REGEX DIR...",
// "lint DIR...", "shell FILE..."; TAGS is "-" for the default build, else comma-separated) and the explanation on
// stderr. The output is sorted and deterministic for a given tree.
//
// Exit: 0 on a plan, 1 when git or go list failed, 2 on a usage error.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("affected", flag.ContinueOnError)
	fs.SetOutput(stderr)
	base := fs.String("base", "main", "the revision whose merge base with HEAD the change is taken from")
	dir := fs.String("C", ".", "the module's root directory")
	planOut := fs.Bool("plan", false, "print the machine-readable plan on stdout and the explanation on stderr")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(stderr, "affected: takes no arguments")
		return 2
	}
	root, err := filepath.Abs(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "affected: %v\n", err)
		return 1
	}
	in, err := load(ctx, root, *base)
	if err != nil {
		fmt.Fprintf(stderr, "affected: %v\n", err)
		return 1
	}
	p := makePlan(in)
	if *planOut {
		p.writePlan(stdout)
		p.writeExplain(stderr)
		return 0
	}
	p.writeExplain(stdout)
	return 0
}

// load gathers everything makePlan needs from the tree: the changed files, the package graph of each build and the
// facts the test code scan finds.
func load(ctx context.Context, root, base string) (input, error) {
	mb, files, err := changedFiles(ctx, root, base)
	if err != nil {
		return input{}, err
	}
	mod, err := modulePath(root)
	if err != nil {
		return input{}, err
	}
	graphs, err := loadGraphs(ctx, root, tagSets)
	if err != nil {
		return input{}, err
	}
	facts, err := scanTests(root, mod, graphs)
	if err != nil {
		return input{}, err
	}
	codeBuilds, err := scanCodeBuilds(root, mod, graphs)
	if err != nil {
		return input{}, err
	}
	gate, err := os.ReadFile(filepath.Join(root, "scripts", "precommit.sh"))
	if err != nil {
		return input{}, err
	}
	listed, err := hooksList(gate)
	if err != nil {
		return input{}, err
	}
	return input{base: base, mergeBase: mb, root: root, module: mod, changed: files, graphs: graphs, facts: facts,
		codeBuilds: codeBuilds, hooksListed: listed,
		hooksTagged: func(dir string) bool { return hooksTagged(filepath.Join(root, filepath.FromSlash(dir))) },
		exists: func(rel string) bool {
			_, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
			return err == nil
		}}, nil
}
