// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpenLoopTimesRefusedOpensOnly (ADR 0043 C10): a plain PATH's loop opens and closes it; a !PATH's loop counts
// only EACCES, so a path the run let through, or one that is missing, fails the loop instead of timing the wrong
// answer.
func TestOpenLoopTimesRefusedOpensOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-000 file (CAP_DAC_OVERRIDE), so no open here is refused")
	}
	dir := t.TempDir()
	open := filepath.Join(dir, "open")
	shut := filepath.Join(dir, "shut")
	for p, mode := range map[string]os.FileMode{open: 0o644, shut: 0o000} {
		if err := os.WriteFile(p, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
	}
	if ns, err := openLoop(open, 2, 50, 10); err != nil || ns < 0 {
		t.Errorf("plain path: %d, %v", ns, err)
	}
	if ns, err := openLoop("!"+shut, 2, 50, 10); err != nil || ns < 0 {
		t.Errorf("refused path: %d, %v", ns, err)
	}
	for p, want := range map[string]string{
		"!" + open:                         "opened, want EACCES",
		"!" + filepath.Join(dir, "absent"): "want EACCES",
		shut:                               "permission denied",
	} {
		if _, err := openLoop(p, 1, 5, 5); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want an error with %q", p, err, want)
		}
	}
}

// TestBestOfRenamesBackAndForth: the rename loop's steps alternate A to B and B to A, so an even count leaves the
// directory where it started, and a failing step ends the loop with its error.
func TestBestOfRenamesBackAndForth(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.Mkdir(a, 0o755); err != nil {
		t.Fatal(err)
	}
	step := func(j int) error {
		if j%2 == 0 {
			return os.Rename(a, b)
		}
		return os.Rename(b, a)
	}
	if _, err := bestOf(3, 10, step); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a); err != nil {
		t.Errorf("after an even loop: %v", err)
	}
	if _, err := bestOf(1, 3, func(j int) error { return step(j + 1) }); err == nil {
		t.Error("a loop that starts at the missing end did not fail")
	}
}
