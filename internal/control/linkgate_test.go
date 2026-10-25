// SPDX-License-Identifier: Apache-2.0

// Package control holds the link gates of the two binaries (ADR 0100 (1a)): what each one links, read from
// `go list -deps` over its main package, the way the linker sees it. The dashboard's packages live below this
// directory.
package control

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const mod = "github.com/attention-span-ai/tego/"

// updateModules rewrites testdata/engine-modules.txt from the build: run it when a change to the engine's module
// set is meant, and say why in the commit.
var updateModules = flag.Bool("update-modules", false, "rewrite testdata/engine-modules.txt from ./cmd/tego's module set")

// tagSets are the builds the gates read: the plain one and the shipped one, with the tier-2 objects.
var tagSets = []string{"", "tegobpf"}

// goList runs `go list` from the module root with args and returns its output lines.
func goList(t *testing.T, args ...string) []string {
	t.Helper()
	cmd := exec.Command("go", append([]string{"list"}, args...)...) // go test puts its own go first on PATH
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %v: %v: %s", args, err, stderr.String())
	}
	return strings.Fields(string(out))
}

// deps is every package main links under tags.
func deps(t *testing.T, tags, main string) []string {
	t.Helper()
	return goList(t, "-tags="+tags, "-deps", main)
}

// banned reports the packages of pkgs under one of the prefixes; a prefix ending in "/" is a tree, one without is
// that package and its tree.
func banned(pkgs, prefixes []string) []string {
	var hit []string
	for _, p := range pkgs {
		for _, b := range prefixes {
			if p == strings.TrimSuffix(b, "/") || strings.HasPrefix(p, strings.TrimSuffix(b, "/")+"/") {
				hit = append(hit, p)
			}
		}
	}
	return hit
}

// TestEngineLinksNoControl: ./cmd/tego links nothing of the dashboard: no internal/control/**.
func TestEngineLinksNoControl(t *testing.T) {
	ban := []string{mod + "internal/control"}
	for _, tags := range tagSets {
		pkgs := deps(t, tags, "./cmd/tego")
		if hit := banned(pkgs, ban); len(hit) > 0 {
			t.Errorf("tags %q: ./cmd/tego links %v", tags, hit)
		}
		if !slices.Contains(pkgs, mod+"internal/handoff") || !slices.Contains(pkgs, mod+"internal/runtime") {
			t.Fatalf("tags %q: ./cmd/tego's deps lack internal/handoff or internal/runtime; the gate reads the wrong build", tags)
		}
	}
}

// TestControlLinksNoEngine: ./cmd/tego-control links no part of the engine, named by property: the runtime (the
// supervisor, the launcher, the enforcement backends), the policy core, the BPF objects, the engine's command line
// and doctor, and the two kernel libraries (cilium/ebpf, go-landlock).
func TestControlLinksNoEngine(t *testing.T) {
	ban := []string{mod + "internal/runtime", mod + "internal/policy", mod + "internal/bpf", mod + "internal/cli",
		mod + "internal/doctor", "github.com/cilium/ebpf", "github.com/landlock-lsm/go-landlock"}
	for _, tags := range tagSets {
		pkgs := deps(t, tags, "./cmd/tego-control")
		if hit := banned(pkgs, ban); len(hit) > 0 {
			t.Errorf("tags %q: ./cmd/tego-control links %v", tags, hit)
		}
		if !slices.Contains(pkgs, mod+"internal/control/cli") || !slices.Contains(pkgs, mod+"internal/handoff") {
			t.Fatalf("tags %q: ./cmd/tego-control's deps lack internal/control/cli or internal/handoff", tags)
		}
	}
}

// TestEngineModuleSetUnchanged: the modules ./cmd/tego links, in the shipped build, are the committed list
// testdata/engine-modules.txt, with their versions. A new module, or a version change, in the binary that runs
// under sudo is a reviewed change: rerun with -update-modules and say why in the commit.
func TestEngineModuleSetUnchanged(t *testing.T) {
	lines := goList(t, "-tags=tegobpf", "-deps", "-f", "{{with .Module}}{{if not .Main}}{{.Path}}@{{.Version}}{{end}}{{end}}", "./cmd/tego")
	slices.Sort(lines)
	got := slices.Compact(lines)
	path := filepath.Join("testdata", "engine-modules.txt")
	if *updateModules {
		body := "# The modules ./cmd/tego links (-tags tegobpf), one path@version per line, sorted. TestEngineModuleSetUnchanged\n" +
			"# holds the build to it; rewrite with go test ./internal/control -run TestEngineModuleSetUnchanged -update-modules.\n" +
			strings.Join(got, "\n") + "\n"
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			want = append(want, l)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("./cmd/tego links the modules\n%s\nwant %s's\n%s", strings.Join(got, "\n"), path, strings.Join(want, "\n"))
	}
}

// TestBannedFindsPlantedLinks tests the gates' matcher: a package in a banned tree, or the banned package itself, is
// found; a package whose name only starts like one is not.
func TestBannedFindsPlantedLinks(t *testing.T) {
	pkgs := []string{mod + "internal/runtime/launch", mod + "internal/runtimex", "github.com/cilium/ebpf", mod + "internal/cli",
		"github.com/cilium/ebpf/link", mod + "internal/clix"}
	got := banned(pkgs, []string{mod + "internal/runtime", "github.com/cilium/ebpf", mod + "internal/cli"})
	want := []string{mod + "internal/runtime/launch", "github.com/cilium/ebpf", mod + "internal/cli", "github.com/cilium/ebpf/link"}
	if !slices.Equal(got, want) {
		t.Fatalf("banned found %v, want %v", got, want)
	}
}
