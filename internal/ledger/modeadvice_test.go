// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestModeAdviceNamesTheStateAndTheOneCommand (A48): a run directory, or a file in it, whose owner rights an agent took
// reads as "permission denied" everywhere. The reader says which path lacks which right, with its mode, and the one
// command that gives the owner's rights back: chmod -R u+rwX, which adds no group or other bit.
func TestModeAdviceNamesTheStateAndTheOneCommand(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads through any mode")
	}
	dir := filepath.Join(t.TempDir(), "r-0a0a0a0a-0000000000001-aaaaaa")
	if err := os.MkdirAll(filepath.Join(dir, BlobsDir), 0o700); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(dir, EventsFile)
	if err := os.WriteFile(events, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700); _ = os.Chmod(events, 0o600) })
	if a := ModeAdvice(dir); a != "" {
		t.Fatalf("a run directory with its owner rights has advice %q", a)
	}
	if err := os.Chmod(events, 0); err != nil {
		t.Fatal(err)
	}
	a := ModeAdvice(dir)
	if !strings.Contains(a, events+" has mode 0000, which lacks your read and write") || !strings.Contains(a, "chmod -R u+rwX '"+dir+"'") {
		t.Errorf("events taken: advice %q", a)
	}
	// Look for a widening in the advice's own words, not in the paths it names: the random temp directory's name can
	// hold "777" (or "g+"), which is no mode.
	if words := strings.NewReplacer(events, "", dir, "").Replace(a); strings.Contains(words, "g+") || strings.Contains(words, "o+") || strings.Contains(words, "777") {
		t.Errorf("the command widens beyond the owner: %q", a)
	}
	if _, err := OpenReader(dir); err == nil || !errors.Is(err, fs.ErrPermission) || !strings.Contains(err.Error(), "chmod -R u+rwX") {
		t.Errorf("OpenReader of a taken events file: %v, want a permission refusal that carries the command", err)
	}
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	a = ModeAdvice(dir)
	if !strings.Contains(a, dir+" has mode 0000, which lacks your read, write and search") || strings.Contains(a, EventsFile) {
		t.Errorf("directory taken: advice %q (nothing inside can be looked at through it)", a)
	}
	if _, err := OpenReader(dir); err == nil || !strings.Contains(err.Error(), "chmod -R u+rwX '"+dir+"'") {
		t.Errorf("OpenReader of a taken directory: %v, want the command", err)
	}
	if err := WithModeAdvice(dir, errors.New("other")); err == nil || strings.Contains(err.Error(), "chmod") {
		t.Errorf("an error that is no permission refusal got advice: %v", err)
	}
}
