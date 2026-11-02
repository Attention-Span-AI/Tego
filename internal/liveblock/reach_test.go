// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReachOf: an absolute program's file is said with every name it has (its hard links, as a multi-call program's
// applets are, and a link to it named otherwise), since the launcher matches its identity; a value that names nothing
// here is Missing, a bare name only when the PATH searched holds no program by it; a folder says nothing.
func TestReachOf(t *testing.T) {
	bin, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	box, one, data := filepath.Join(bin, "box"), filepath.Join(bin, "one"), filepath.Join(bin, "data")
	for p, mode := range map[string]os.FileMode{box: 0o755, one: 0o755, data: 0o644} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"ls", "cat", "sleep"} {
		if err := os.Link(box, filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	links := filepath.Join(bin, "links")
	if err := os.Mkdir(links, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, to := range map[string]string{"ls": box, "alias": one, "one": one} {
		if err := os.Symlink(to, filepath.Join(links, name)); err != nil {
			t.Fatal(err)
		}
	}
	path := "relative:" + links + "::" + bin
	for _, tc := range []struct {
		value string
		want  ExecReach
	}{
		{box, ExecReach{File: box, Names: 4}},
		{filepath.Join(bin, "ls"), ExecReach{File: filepath.Join(bin, "ls"), Names: 4}},
		{filepath.Join(links, "ls"), ExecReach{File: box, Names: 4, Renamed: true}},
		{filepath.Join(links, "alias"), ExecReach{File: one, Names: 1, Renamed: true}},
		{filepath.Join(links, "one"), ExecReach{File: one, Names: 1}},
		{one, ExecReach{File: one, Names: 1}},
		{filepath.Join(bin, "gone"), ExecReach{Missing: true}},
		{bin + "/", ExecReach{}},
		{bin, ExecReach{}},
		{"one", ExecReach{}},
		{"alias", ExecReach{}},
		{"data", ExecReach{Missing: true}}, // not a program: no execute bit
		{"crul", ExecReach{Missing: true}},
	} {
		if got := ReachOf(tc.value, path); got != tc.want {
			t.Errorf("ReachOf(%s) = %+v, want %+v", tc.value, got, tc.want)
		}
	}
	if got := ReachOf("crul", ""); got.Missing {
		t.Error("a bare name looked up on no PATH is Missing")
	}
	if got := ReachOf("one", "relative"); !got.Missing {
		t.Error("a relative PATH entry was searched")
	}
}
