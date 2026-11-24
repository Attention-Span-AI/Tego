// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// embedLine is a //go:embed directive: its patterns follow, separated by spaces, each bare or quoted.
var embedLine = regexp.MustCompile(`^\s*//go:embed\s+(.+)$`)

// embedPatterns splits the patterns of one directive (bare, "double-quoted" or `raw`) and drops the all: prefix.
func embedPatterns(rest string) []string {
	var out []string
	for rest = strings.TrimSpace(rest); rest != ""; rest = strings.TrimSpace(rest) {
		var p string
		switch rest[0] {
		case '"', '`':
			end := strings.IndexByte(rest[1:], rest[0])
			if end < 0 {
				p, rest = rest[1:], ""
			} else {
				p, rest = rest[1:1+end], rest[end+2:]
			}
		default:
			end := strings.IndexAny(rest, " \t")
			if end < 0 {
				end = len(rest)
			}
			p, rest = rest[:end], rest[end:]
		}
		out = append(out, strings.TrimPrefix(p, "all:"))
	}
	return out
}

// underTestdata reports whether a pattern names a path in a testdata directory.
func underTestdata(pattern string) bool {
	for _, el := range strings.Split(filepath.ToSlash(pattern), "/") {
		if el == "testdata" {
			return true
		}
	}
	return false
}

// TestProductionCodeEmbedsNothingFromTestdata: the container image build (examples/container/Dockerfile.dockerignore)
// leaves every testdata folder out of its context, as does anything that ships only what the build needs, so a file
// a non-test Go file embeds from a testdata folder is missing there and the build fails ("no matching files found",
// found on 2026-11-19 with the dashboard's number inventory). Data the program reads at run time does not live in
// testdata. Test files may embed from testdata; build tags do not matter here, every non-test .go file is read.
func TestProductionCodeEmbedsNothingFromTestdata(t *testing.T) {
	root := filepath.Join("..", "..")
	seen := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "node_modules":
				return filepath.SkipDir // Go does not build a package in a testdata folder either
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, l := range strings.Split(string(b), "\n") {
			m := embedLine.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			seen++
			for _, p := range embedPatterns(m[1]) {
				if underTestdata(p) {
					rel, _ := filepath.Rel(root, path)
					t.Errorf("%s embeds %q, a path under testdata: move the data out of testdata (the image build leaves it out)", filepath.ToSlash(rel), p)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen == 0 {
		t.Error("found no //go:embed directive at all: the walk is not looking at the module")
	}
}

func TestEmbedPatternsAreSplitAndTestdataIsRecognised(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
		bad  bool
	}{
		{"testdata/a.json", []string{"testdata/a.json"}, true},
		{"x.o y.o", []string{"x.o", "y.o"}, false},
		{`"a b/c.txt" all:sample`, []string{"a b/c.txt", "sample"}, false},
		{"a.txt ../testdata/b.txt", []string{"a.txt", "../testdata/b.txt"}, true},
		{"inventory/testdata_not.json", []string{"inventory/testdata_not.json"}, false},
		{"v1/*.yaml hosts.yaml", []string{"v1/*.yaml", "hosts.yaml"}, false},
	} {
		got := embedPatterns(c.in)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%q: patterns %q, want %q", c.in, got, c.want)
		}
		bad := false
		for _, p := range got {
			bad = bad || underTestdata(p)
		}
		if bad != c.bad {
			t.Errorf("%q: under testdata = %v, want %v", c.in, bad, c.bad)
		}
	}
}
