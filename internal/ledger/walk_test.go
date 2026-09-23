// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// asRoot makes the walk take its privileged branch for one test: links in a directory that is not
// root's alone are refused. plantedHome makes the home group-writable, so it is a directory someone
// else could change — what a user's home is to root — whether or not the test itself runs as root.
func asRoot(t *testing.T) {
	t.Helper()
	prev := actingAsRoot
	actingAsRoot = func() bool { return true }
	t.Cleanup(func() { actingAsRoot = prev })
}

// plantedHome is a home whose ~/.tego is a symlink to victim, the shape the review reproduced as
// root: root's append then created <victim>/chain.log holding the run's line.
func plantedHome(t *testing.T) (home, victim string) {
	t.Helper()
	base := t.TempDir()
	home, victim = filepath.Join(base, "home"), filepath.Join(base, "victim")
	for _, d := range []string{home, victim} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(home, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(home, ".tego")); err != nil {
		t.Fatal(err)
	}
	return home, victim
}

// TestRootRefusesASymlinkedStateDir: as root, the anchor's directory is reached one component at a
// time and a link in the user's home is refused (ErrLinkRefused), so neither Append, the up-front
// probe, nor MakeDirs writes through it. The victim directory stays empty.
func TestRootRefusesASymlinkedStateDir(t *testing.T) {
	asRoot(t)
	home, victim := plantedHome(t)
	anchor := filepath.Join(home, ".tego", ChainLogFile)
	if err := NewFileChainAnchor(anchor).Append(testRef.ID, record0ID(t)); !errors.Is(err, ErrLinkRefused) {
		t.Fatalf("Append through a symlinked ~/.tego: %v, want ErrLinkRefused", err)
	}
	if err := ProbeAnchor(anchor); !errors.Is(err, ErrLinkRefused) {
		t.Fatalf("ProbeAnchor through a symlinked ~/.tego: %v, want ErrLinkRefused", err)
	}
	if _, _, err := NewFileChainAnchor(anchor).Head(testRef.ID); !errors.Is(err, ErrLinkRefused) {
		t.Fatalf("Head through a symlinked ~/.tego: %v, want ErrLinkRefused", err)
	}
	if err := MakeDirs(filepath.Join(home, ".tego", "runs")); !errors.Is(err, ErrLinkRefused) {
		t.Fatalf("MakeDirs through a symlinked ~/.tego: %v, want ErrLinkRefused", err)
	}
	if err := MakeRunDir(filepath.Join(home, ".tego", "runs"), testRef.ID); !errors.Is(err, ErrLinkRefused) {
		t.Fatalf("MakeRunDir through a symlinked ~/.tego: %v, want ErrLinkRefused", err)
	}
	if entries, _ := os.ReadDir(victim); len(entries) != 0 {
		t.Fatalf("root wrote into the link's target: %v", entries)
	}
}

// TestUnprivilegedFollowsItsOwnLinks: a user's own link is theirs to make, and an unprivileged process
// can only reach through it what it could write anyway, so the walk follows it as the kernel does.
func TestUnprivilegedFollowsItsOwnLinks(t *testing.T) {
	prev := actingAsRoot
	actingAsRoot = func() bool { return false }
	t.Cleanup(func() { actingAsRoot = prev })
	home, victim := plantedHome(t)
	anchor := filepath.Join(home, ".tego", ChainLogFile)
	if err := ProbeAnchor(anchor); err != nil {
		t.Fatalf("ProbeAnchor through the user's own link: %v", err)
	}
	if st, err := os.Stat(filepath.Join(victim, ChainLogFile)); err != nil || st.Size() != 0 || st.Mode().Perm() != 0o600 {
		t.Fatalf("the probe should leave an empty 0600 chain.log: %v %v", st, err)
	}
	if err := MakeRunDir(filepath.Join(home, ".tego", "runs"), testRef.ID); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(victim, "runs", testRef.ID)); err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Fatalf("run directory: %v %v", st, err)
	}
}

// TestMakeRunDirNeverReuses: a run directory that exists is an error (os.ErrExist), and a name that is
// not one path component is refused before anything is made.
//
// Also pins record-ledger.md E24: a taken run directory is never reused.
func TestMakeRunDirNeverReuses(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	if err := MakeRunDir(root, testRef.ID); err != nil {
		t.Fatal(err)
	}
	if err := MakeRunDir(root, testRef.ID); !errors.Is(err, os.ErrExist) {
		t.Fatalf("a second MakeRunDir: %v, want os.ErrExist", err)
	}
	for _, bad := range []string{"", ".", "..", "a/b"} {
		if err := MakeRunDir(root, bad); err == nil {
			t.Errorf("MakeRunDir(%q) succeeded", bad)
		}
	}
}

// TestProbeAnchorRefusesWhatAppendWould: the probe opens the anchor as Append does, so every anchor
// Append would refuse at Close — a missing, file-shaped home; a directory where chain.log goes — is
// refused before the run instead.
func TestProbeAnchorRefusesWhatAppendWould(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "home")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ProbeAnchor(filepath.Join(file, ".tego", ChainLogFile)); err == nil {
		t.Fatal("a home that is a file: the probe succeeded")
	}
	if err := os.Mkdir(filepath.Join(dir, ChainLogFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ProbeAnchor(filepath.Join(dir, ChainLogFile)); err == nil {
		t.Fatal("a directory named chain.log: the probe succeeded")
	}
	good := filepath.Join(dir, "u", ".tego", ChainLogFile)
	if err := ProbeAnchor(good); err != nil {
		t.Fatal(err)
	}
	if err := NewFileChainAnchor(good).Append(testRef.ID, record0ID(t)); err != nil {
		t.Fatalf("Append after a probe: %v", err)
	}
	if head, ok, err := NewFileChainAnchor(good).Head(testRef.ID); err != nil || !ok || head != record0ID(t) {
		t.Fatalf("Head after a probe and an append: %q %v %v", head, ok, err)
	}
}

// record0ID is a well-formed event id for anchor lines the tests append by hand.
func record0ID(t *testing.T) string {
	t.Helper()
	return strings.Repeat("ab", record.IDLen/2)
}
