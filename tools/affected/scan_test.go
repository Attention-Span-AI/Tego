// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestScanFindsTreeReaders: a test that walks the module is named, one that reaches a walk through a helper is
// named, one that reads nothing of the tree is not; a package-level read runs the whole package; module paths a
// test names are its binary closure, and existing paths it names are what it reads.
func TestScanFindsTreeReaders(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a/a_test.go", `package a

import (
	"io/fs"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestWalks(t *testing.T) {
	_ = filepath.WalkDir(filepath.Join("..", "x"), func(string, fs.DirEntry, error) error { return nil })
}

func readTree(t *testing.T) { _ = filepath.Join("..", "..") }

func TestThroughHelper(t *testing.T) { readTree(t) }

func BenchmarkWalk(b *testing.B) { _ = filepath.WalkDir(".", nil) }

func TestPlain(t *testing.T) {
	_ = exec.Command("go", "build", "-o", "x", "github.com/attention-span-ai/tego/cmd/tego")
	_ = "testdata/in.json"
}
`)
	write(t, root, "a/testdata/in.json", "{}")
	write(t, root, "b/b_test.go", `package b

import "testing"

var root = "../.."

func TestB(t *testing.T) {}
`)
	write(t, root, "internal/askclient/imports_test.go", `package askclient

import "testing"

func TestLedgerTargetSingleSource(t *testing.T) {}

func TestOther(t *testing.T) {}
`)
	known := map[string]string{"a": mod + "/a", "b": mod + "/b", "cmd/tego": mod + "/cmd/tego"}
	scan := func(dir string, files ...string) *pkgFacts {
		var ff []*fileFacts
		for _, f := range files {
			ff = append(ff, scanFile(filepath.Join(root, dir, f)))
		}
		return combine(root, mod, dir, ff, known)
	}
	a := scan("a", "a_test.go")
	if a.whole || !reflect.DeepEqual(sorted(a.tests), []string{"TestThroughHelper", "TestWalks"}) {
		t.Errorf("a: whole %v, tests %v; want TestThroughHelper and TestWalks only", a.whole, sorted(a.tests))
	}
	if !reflect.DeepEqual(a.builds, []string{mod + "/cmd/tego"}) {
		t.Errorf("a: builds %v", a.builds)
	}
	if !contains(a.paths, "a/testdata/in.json") {
		t.Errorf("a: paths %v lack a/testdata/in.json", a.paths)
	}
	if b := scan("b", "b_test.go"); !b.whole {
		t.Errorf("b: a package-level tree read did not run the whole package: %+v", b)
	}
	if s := scan("internal/askclient", "imports_test.go"); !reflect.DeepEqual(sorted(s.tests), []string{"TestLedgerTargetSingleSource"}) || s.whole {
		t.Errorf("askclient: the seed gave tests %v whole %v", sorted(s.tests), s.whole)
	}
}

// TestScanUnparsableFileRunsThePackage: a test file the scan cannot parse is not a reason to run fewer tests.
func TestScanUnparsableFileRunsThePackage(t *testing.T) {
	root := t.TempDir()
	write(t, root, "c/c_test.go", "package c\nfunc TestX(t *testing.T) {\n")
	f := combine(root, mod, "c", []*fileFacts{scanFile(filepath.Join(root, "c", "c_test.go"))}, nil)
	if !f.whole {
		t.Errorf("an unparsable file gave %+v", f)
	}
}

func TestIsTestName(t *testing.T) {
	for name, want := range map[string]bool{"TestX": true, "Test": true, "Testable": false, "TestMain": false,
		"FuzzViews": true, "ExampleRun": true, "helper": false, "Test_x": true} {
		if got := isTestName(name); got != want {
			t.Errorf("isTestName(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestScanCodeBuildsFindsHelpersThatBuild: a helper package's own code that names a module package (a binary it
// builds for the tests that import it) is found, its own path and test files aside.
func TestScanCodeBuildsFindsHelpersThatBuild(t *testing.T) {
	root := t.TempDir()
	write(t, root, "h/h.go", "package h\n\nconst bin = \""+mod+"/cmd/tego-control\"\nconst self = \""+mod+"/h\"\n")
	g := &graph{pkgs: map[string]*pkg{mod + "/h": {path: mod + "/h", dir: "h", files: []string{"h/h.go"}}}}
	got, err := scanCodeBuilds(root, mod, map[string]*graph{"": g})
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string][]string{mod + "/h": {mod + "/cmd/tego-control"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("scanCodeBuilds = %v, want %v", got, want)
	}
}

// TestModulePkgsExpandsPatterns: "./..." from the test's directory and an import path ending in "/..." name every
// package under it, a new one included; "./..." from the root is not the whole module.
func TestModulePkgsExpandsPatterns(t *testing.T) {
	known := map[string]string{
		"internal/runtime/capture": mod + "/internal/runtime/capture", "internal/runtime/capture/newsrc": mod + "/internal/runtime/capture/newsrc",
		"internal/runtime/capture/uprobe": mod + "/internal/runtime/capture/uprobe", "internal/doctor": mod + "/internal/doctor",
		"cmd/tego": mod + "/cmd/tego",
	}
	under := []string{mod + "/internal/runtime/capture", mod + "/internal/runtime/capture/newsrc", mod + "/internal/runtime/capture/uprobe"}
	for _, tc := range []struct {
		dir, lit string
		want     []string
	}{
		{"internal/runtime/capture", "./...", under},
		{"internal/doctor", mod + "/internal/runtime/capture/...", under},
		{"internal/doctor", "./internal/runtime/capture/...", under},
		{"internal/doctor", "./...", []string{mod + "/internal/doctor"}},
		{".", "./...", nil},
		{"internal/doctor", "./" + "cmd/tego", []string{mod + "/cmd/tego"}},
		{"internal/doctor", mod + "/cmd/tego", []string{mod + "/cmd/tego"}},
		{"internal/doctor", "go test ./...", nil},
	} {
		if got := modulePkgs(mod, tc.dir, tc.lit, known); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("modulePkgs(%q, %q) = %v, want %v", tc.dir, tc.lit, got, tc.want)
		}
	}
}

// TestScanFoldsJoinedLiterals: filepath.Join("mcp", "testdata", name) names mcp/testdata, which no single segment
// does, so a change there selects the test.
func TestScanFoldsJoinedLiterals(t *testing.T) {
	root := t.TempDir()
	write(t, root, "derive/mcp/testdata/stdio.jsonl", "{}\n")
	write(t, root, "derive/d_test.go", `package derive

import (
	"path/filepath"
	"testing"
)

func TestEvents(t *testing.T) { _ = filepath.Join("mcp", "testdata", t.Name()) }
`)
	f := combine(root, mod, "derive", []*fileFacts{scanFile(filepath.Join(root, "derive", "d_test.go"))}, nil)
	if !contains(f.paths, "derive/mcp/testdata") {
		t.Errorf("paths %v lack derive/mcp/testdata", f.paths)
	}
}

// TestScanSkipsAncestorPackages: a bare ".." chain resolves to a package above the test's own, which is not a read of
// everything under it; a file or directory it climbs to by name still is.
func TestScanSkipsAncestorPackages(t *testing.T) {
	root := t.TempDir()
	write(t, root, "rt/rt.go", "package rt\n")
	write(t, root, "rt/other/testdata/x.json", "{}")
	write(t, root, "rt/derive/d_test.go", `package derive

import (
	"path/filepath"
	"testing"
)

func TestUp(t *testing.T) {
	_ = filepath.Join("..", t.Name())
	_ = "../other/testdata/x.json"
}
`)
	known := map[string]string{"rt": mod + "/rt", "rt/derive": mod + "/rt/derive", "rt/other": mod + "/rt/other"}
	f := combine(root, mod, "rt/derive", []*fileFacts{scanFile(filepath.Join(root, "rt", "derive", "d_test.go"))}, known)
	if contains(f.paths, "rt") {
		t.Errorf("paths %v hold the ancestor package rt", f.paths)
	}
	if !contains(f.paths, "rt/other/testdata/x.json") {
		t.Errorf("paths %v lack rt/other/testdata/x.json", f.paths)
	}
	if !f.tests["TestUp"] {
		t.Errorf("TestUp, which climbs out by \"..\", is not a source scanner: %+v", f)
	}
}
