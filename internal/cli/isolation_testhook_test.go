// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestTestBuildRefusesTheRealTegoDirectory is identity-config.md R27's ledger half: a test build whose machine
// config puts the ledger root inside the invoking user's ~/.tego (the built-in default included, which is what a
// harness without a ledger_root gets), or whose anchor or own-log variable does, is refused, so `run`, `gc`,
// `stop` and the sweeps they start never end or anchor a run in the developer's own ledger.
func TestTestBuildRefusesTheRealTegoDirectory(t *testing.T) {
	home := t.TempDir()
	real := filepath.Join(home, ".tego")
	dirs := []string{real}
	scratch := t.TempDir()
	machine := func(root string) *config.Machine {
		m := &config.Machine{Home: home}
		m.LedgerRoot.Value = root
		return m
	}
	for _, c := range []struct {
		name         string
		root         string
		anchor, home string
		refused      bool
	}{
		{"the built-in root", config.DefaultLedgerRoot, filepath.Join(scratch, "chain.log"), scratch, true},
		{"a root inside it", filepath.Join(real, "runs"), filepath.Join(scratch, "chain.log"), scratch, true},
		{"the directory itself", real, filepath.Join(scratch, "chain.log"), scratch, true},
		{"a root of its own", filepath.Join(scratch, "ledger"), filepath.Join(scratch, "chain.log"), scratch, false},
		{"a sibling named alike", filepath.Join(home, ".tego-other", "runs"), filepath.Join(scratch, "chain.log"), scratch, false},
		{"the real anchor", filepath.Join(scratch, "ledger"), filepath.Join(real, "chain.log"), scratch, true},
		{"the real home as the own-log home", filepath.Join(scratch, "ledger"), filepath.Join(scratch, "chain.log"), home, true},
		{"no anchor and no own-log home", filepath.Join(scratch, "ledger"), "", "", false},
	} {
		err := testIsolationError(machine(c.root), dirs, c.anchor, c.home)
		if c.refused != errors.Is(err, ErrTestLedgerRoot) {
			t.Errorf("%s: refused %v, want %v (%v)", c.name, errors.Is(err, ErrTestLedgerRoot), c.refused, err)
		}
	}

	// A relative anchor or own-log home is the path it names from the working directory: started in the real
	// directory, "chain.log" is the real chain.log, and started in the real home, "." keeps tego.log in the real directory.
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger := filepath.Join(scratch, "ledger")
	t.Chdir(real)
	if err := testIsolationError(machine(ledger), dirs, "chain.log", ""); !errors.Is(err, ErrTestLedgerRoot) {
		t.Errorf("a relative anchor in the real directory was accepted: %v", err)
	}
	t.Chdir(home)
	if err := testIsolationError(machine(ledger), dirs, "", "."); !errors.Is(err, ErrTestLedgerRoot) {
		t.Errorf("a relative own-log home that is the real home was accepted: %v", err)
	}
	t.Chdir(scratch)
	if err := testIsolationError(machine(ledger), dirs, "chain.log", "."); err != nil {
		t.Errorf("a relative anchor and own-log home in a scratch directory were refused: %v", err)
	}

	// A link into the real directory is the real directory.
	link := filepath.Join(scratch, "link")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := testIsolationError(machine(filepath.Join(link, "runs")), dirs, "", ""); !errors.Is(err, ErrTestLedgerRoot) {
		t.Errorf("a ledger root reached through a link into it was accepted: %v", err)
	}
}

// TestTestBuildRefusesTheRealTegoDirectoryWithNoPasswdHome: on an account the passwd database
// names no home for, config.Resolve leaves Machine.Home empty and the commands resolve a "~/" ledger root against
// $HOME (internal/runtime LedgerRoot), which is the $HOME/.tego realtego.Dirs then names as real. The refusal
// resolves the root the same way, so the built-in or a declared "~/" root is refused there, and a root it cannot
// resolve at all is refused rather than passed.
func TestTestBuildRefusesTheRealTegoDirectoryWithNoPasswdHome(t *testing.T) {
	home := t.TempDir()
	dirs := []string{filepath.Join(home, ".tego")}
	scratch := t.TempDir()
	unnamed := func(root string) *config.Machine {
		m := &config.Machine{} // Home "": no passwd entry
		m.LedgerRoot.Value = root
		return m
	}
	t.Setenv("HOME", home)
	for _, c := range []struct {
		name    string
		root    string
		refused bool
	}{
		{"the built-in root", config.DefaultLedgerRoot, true},
		{"a declared ~/ root", "~/.tego/runs", true},
		{"a declared ~/ root of the directory itself", "~/.tego", true},
		{"a ~/ root outside it", "~/scratch-ledger", false},
		{"an absolute root of its own", filepath.Join(scratch, "ledger"), false},
	} {
		err := testIsolationError(unnamed(c.root), dirs, "", "")
		if c.refused != errors.Is(err, ErrTestLedgerRoot) {
			t.Errorf("%s: refused %v, want %v (%v)", c.name, errors.Is(err, ErrTestLedgerRoot), c.refused, err)
		}
	}

	// With $HOME unset too, a "~/" root names no directory this build can check: refused, never passed.
	t.Setenv("HOME", "")
	if err := testIsolationError(unnamed(config.DefaultLedgerRoot), nil, "", ""); !errors.Is(err, ErrTestLedgerRoot) {
		t.Errorf("a ~/ root with no passwd home and no $HOME was accepted: %v", err)
	}
	if err := testIsolationError(unnamed(filepath.Join(scratch, "ledger")), nil, "", ""); err != nil {
		t.Errorf("an absolute root of its own with no passwd home and no $HOME was refused: %v", err)
	}
}
