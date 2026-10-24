// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestReadRegularRefusesASwappedInLink: a link put in the file's place after readRegular's Lstat is not followed.
func TestReadRegularRefusesASwappedInLink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	secret := filepath.Join(dir, "secret")
	writeText(t, dir, "settings.json", "{}")
	writeText(t, dir, "secret", "PLANTED")
	t.Cleanup(func() { betweenStatAndOpen = func(string) {} })
	betweenStatAndOpen = func(p string) {
		if err := os.Remove(p); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(secret, p); err != nil {
			t.Error(err)
		}
	}
	data, err := readRegular(path)
	if strings.Contains(string(data), "PLANTED") || !errors.Is(err, errNotRegular) {
		t.Errorf("readRegular after a swap to a link: %q, %v", data, err)
	}
}

// TestReadRegularRefusesASwappedInFile: another file renamed into place after the Lstat is not read either.
func TestReadRegularRefusesASwappedInFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	writeText(t, dir, "settings.json", "{}")
	writeText(t, dir, "other", "PLANTED")
	t.Cleanup(func() { betweenStatAndOpen = func(string) {} })
	betweenStatAndOpen = func(p string) {
		if err := os.Rename(filepath.Join(dir, "other"), p); err != nil {
			t.Error(err)
		}
	}
	if data, err := readRegular(path); strings.Contains(string(data), "PLANTED") || err == nil {
		t.Errorf("readRegular after a rename into place: %q, %v", data, err)
	}
}

// TestReadRegularDoesNotWaitOnAFIFO: a FIFO swapped in after the Lstat neither blocks the read nor is read.
func TestReadRegularDoesNotWaitOnAFIFO(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	writeText(t, dir, "settings.json", "{}")
	t.Cleanup(func() { betweenStatAndOpen = func(string) {} })
	betweenStatAndOpen = func(p string) {
		if err := os.Remove(p); err != nil {
			t.Error(err)
		}
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Error(err)
		}
	}
	if _, err := readRegular(path); err == nil {
		t.Error("readRegular read a FIFO")
	}
}

// TestClaudeRulesRefuseALinkedClaudeFolder: a project's .claude that is a link is not read as the team's file.
func TestClaudeRulesRefuseALinkedClaudeFolder(t *testing.T) {
	root, elsewhere := t.TempDir(), t.TempDir()
	writeText(t, elsewhere, "settings.json", `{"permissions":{"allow":["Bash(PLANTED)"]}}`)
	if err := os.Symlink(elsewhere, filepath.Join(root, ".claude")); err != nil {
		t.Fatal(err)
	}
	rules, problems := ClaudeRules(Env{}, root)
	if len(rules) != 0 {
		t.Errorf("rules read through a linked .claude: %v", rules)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], ".claude is a link") {
		t.Errorf("problems %v", problems)
	}
}
