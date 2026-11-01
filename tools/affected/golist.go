// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// tagSets are the builds precommit vets (the first four) and tests (default, integration, tegotesthooks).
var tagSets = []string{"", "integration", "tegobpf", "integration,tegobpf", "tegotesthooks"}

// vetTagSets are the builds precommit vets.
var vetTagSets = tagSets[:4]

// testTagSets are the builds whose tests precommit runs.
var testTagSets = []string{"", "integration", "tegotesthooks"}

// listPkg is the part of `go list -json`'s output the selection reads.
type listPkg struct {
	ImportPath      string
	Dir             string
	Name            string
	ForTest         string
	Deps            []string
	GoFiles         []string
	CgoFiles        []string
	TestGoFiles     []string
	XTestGoFiles    []string
	EmbedFiles      []string
	TestEmbedFiles  []string
	XTestEmbedFiles []string
}

// pkg is one package of one build, its paths repo-relative with forward slashes.
type pkg struct {
	path       string          // import path
	dir        string          // repo-relative directory ("." for the root)
	main       bool            // package main
	deps       map[string]bool // the package's own transitive deps (import paths)
	testDeps   map[string]bool // its test binary's transitive deps, itself included; nil: no test files
	files      []string        // repo-relative non-test Go files this build compiles
	testFiles  []string        // repo-relative test files this build compiles
	embeds     []string        // repo-relative files the package's own code embeds
	testEmbeds []string        // repo-relative files its tests embed
}

// graph is one build's packages.
type graph struct {
	tags  string
	pkgs  map[string]*pkg // by import path
	byDir map[string]string
}

// basePath strips go list's test-variant suffix: "p [q.test]" is p recompiled for q's test binary.
func basePath(p string) string {
	if i := strings.Index(p, " ["); i >= 0 {
		return p[:i]
	}
	return p
}

func relSlash(root, p string) string {
	r, err := filepath.Rel(root, p)
	if err != nil {
		return filepath.ToSlash(p)
	}
	return filepath.ToSlash(r)
}

// parseList reads one build's `go list -e -test -json ./...` stream.
func parseList(tags, root string, r io.Reader) (*graph, error) {
	g := &graph{tags: tags, pkgs: map[string]*pkg{}, byDir: map[string]string{}}
	testMains := map[string][]string{}
	dec := json.NewDecoder(r)
	for {
		var lp listPkg
		if err := dec.Decode(&lp); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("go list -tags %q: %w", tags, err)
		}
		switch {
		case lp.ForTest != "":
			// A test variant: its files and deps are covered by the package's own entry and its test main.
		case strings.HasSuffix(lp.ImportPath, ".test"):
			testMains[strings.TrimSuffix(lp.ImportPath, ".test")] = lp.Deps
		default:
			dir := relSlash(root, lp.Dir)
			p := &pkg{path: lp.ImportPath, dir: dir, main: lp.Name == "main", deps: set(lp.Deps, basePath)}
			for _, f := range append(append([]string{}, lp.GoFiles...), lp.CgoFiles...) {
				p.files = append(p.files, joinRel(dir, f))
			}
			for _, f := range append(append([]string{}, lp.TestGoFiles...), lp.XTestGoFiles...) {
				p.testFiles = append(p.testFiles, joinRel(dir, f))
			}
			for _, f := range lp.EmbedFiles {
				p.embeds = append(p.embeds, joinRel(dir, f))
			}
			for _, f := range append(append([]string{}, lp.TestEmbedFiles...), lp.XTestEmbedFiles...) {
				p.testEmbeds = append(p.testEmbeds, joinRel(dir, f))
			}
			g.pkgs[p.path] = p
			g.byDir[dir] = p.path
		}
	}
	for path, deps := range testMains {
		p := g.pkgs[path]
		if p == nil || len(p.testFiles) == 0 {
			continue
		}
		p.testDeps = set(deps, basePath)
		p.testDeps[path] = true
	}
	return g, nil
}

func joinRel(dir, f string) string {
	if dir == "." {
		return f
	}
	return dir + "/" + f
}

func set(xs []string, norm func(string) string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[norm(x)] = true
	}
	return m
}

// loadGraphs runs go list for each build, concurrently (each is a read of the module, a few seconds). An integration
// build is listed twice and merged: cgo-free, as its tests run (gated_integration), and with go env's CGO_ENABLED, as
// its vet runs, so a file of either (`integration && !cgo`, `integration && cgo`) counts.
func loadGraphs(ctx context.Context, root string, sets []string) (map[string]*graph, error) {
	type job struct {
		tags string
		env  []string
	}
	var jobs []job
	for _, tags := range sets {
		jobs = append(jobs, job{tags: tags})
		if strings.Contains(tags, "integration") {
			jobs = append(jobs, job{tags: tags, env: []string{"CGO_ENABLED=0"}})
		}
	}
	listed := make([]*graph, len(jobs))
	errs := make([]error, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			args := []string{"list", "-e", "-test", "-json"}
			if j.tags != "" {
				args = append(args, "-tags", j.tags)
			}
			cmd := exec.CommandContext(ctx, goCmd(), append(args, "./...")...)
			cmd.Dir = root
			if j.env != nil {
				cmd.Env = append(os.Environ(), j.env...)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				errs[i] = fmt.Errorf("go list -tags %q %v: %v: %s", j.tags, j.env, err, stderr.String())
				return
			}
			listed[i], errs[i] = parseList(j.tags, root, bytes.NewReader(out))
		}()
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	graphs := make(map[string]*graph, len(sets))
	for i, j := range jobs {
		if g := graphs[j.tags]; g != nil {
			mergeGraph(g, listed[i])
		} else {
			graphs[j.tags] = listed[i]
		}
	}
	return graphs, nil
}

// mergeGraph adds b's packages, files and dependencies to a (the same build listed another way).
func mergeGraph(a, b *graph) {
	for ip, pb := range b.pkgs {
		pa := a.pkgs[ip]
		if pa == nil {
			a.pkgs[ip] = pb
			a.byDir[pb.dir] = ip
			continue
		}
		for d := range pb.deps {
			pa.deps[d] = true
		}
		if pb.testDeps != nil {
			if pa.testDeps == nil {
				pa.testDeps = map[string]bool{}
			}
			for d := range pb.testDeps {
				pa.testDeps[d] = true
			}
		}
		pa.files = union(pa.files, pb.files)
		pa.testFiles = union(pa.testFiles, pb.testFiles)
		pa.embeds = union(pa.embeds, pb.embeds)
		pa.testEmbeds = union(pa.testEmbeds, pb.testEmbeds)
	}
}

func union(a, b []string) []string {
	for _, x := range b {
		if !contains(a, x) {
			a = append(a, x)
		}
	}
	return a
}

func goCmd() string {
	if g := os.Getenv("GO"); g != "" {
		return g
	}
	return "go"
}

// modulePath reads the module line of root's go.mod.
func modulePath(root string) (string, error) {
	f, err := os.Open(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }() // read only: a close error loses nothing
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "module "); ok {
			return strings.TrimSpace(m), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("%s/go.mod has no module line", root)
}

// changedFiles lists the files that differ between the merge base of HEAD and base and the working tree,
// untracked files included, repo-relative and sorted; deleted files are listed too (they may own a package).
func changedFiles(ctx context.Context, root, base string) (string, []string, error) {
	mb, err := gitOut(ctx, root, "merge-base", "HEAD", base)
	if err != nil {
		return "", nil, err
	}
	mb = strings.TrimSpace(mb)
	diff, err := gitOut(ctx, root, "diff", "--name-only", "-z", "--no-renames", mb, "--")
	if err != nil {
		return "", nil, err
	}
	untracked, err := gitOut(ctx, root, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return "", nil, err
	}
	seen := map[string]bool{}
	var files []string
	for _, f := range strings.Split(diff+untracked, "\x00") {
		if f != "" && !seen[f] {
			seen[f] = true
			files = append(files, f)
		}
	}
	sort.Strings(files)
	return mb, files, nil
}

func gitOut(ctx context.Context, root string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", root}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}
