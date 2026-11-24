// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRootLaunchedRunIsNamedForWhatItIs: a run folder the dashboard's user cannot open, owned by root, is said to be a
// run launched with sudo, on every page that quotes the read failure; the same refusal of a folder that is not root's, or
// for root itself, keeps the system's own words. Never a second path to the files.
func TestRootLaunchedRunIsNamedForWhatItIs(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can open the folder")
	}
	root := t.TempDir()
	id := "r-aaaa-0700-rootxx"
	t0 := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	writeRun(t, root, id, line(id, "a", 0, t0, "run_start", `"tier":"landlock","command":["sh"]`))
	if err := os.Chmod(filepath.Join(root, id), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(root, id), 0o755) }) //nolint:errcheck
	for _, c := range []struct {
		name  string
		uid   int
		ok    bool
		euid  int
		named bool
	}{
		{"owned by root, asked by a person", 0, true, 1000, true},
		{"owned by the person", 1000, true, 1000, false},
		{"owner unknown", 0, false, 1000, false},
		{"asked by root", 0, true, 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			defer SetRootRunSeams(func(string) (int, bool) { return c.uid, c.ok }, func() int { return c.euid })()
			snap, err := LoadNow(root)
			if err != nil {
				t.Fatal(err)
			}
			words := RootLaunchedWords(id)
			if got := strings.Contains(snap.ReadError, words); got != c.named {
				t.Errorf("snapshot read error %q; names the sudo run: %v, want %v", snap.ReadError, got, c.named)
			}
			if c.named && (strings.Contains(snap.ReadError, "permission denied") || strings.Contains(snap.ReadError, "lstat")) {
				t.Errorf("the words still quote the failed call: %q", snap.ReadError)
			}
			if !c.named && !strings.Contains(snap.ReadError, "permission denied") {
				t.Errorf("another case lost the system's words: %q", snap.ReadError)
			}
		})
	}
	t.Run("only a permission refusal", func(t *testing.T) {
		defer SetRootRunSeams(func(string) (int, bool) { return 0, true }, func() int { return 1000 })()
		if RootLaunched(root, id, errors.New("input/output error")) || RootLaunched(root, id, nil) {
			t.Error("a failure that is not a permission refusal is called a sudo run")
		}
		if !RootLaunched(root, id, &fs.PathError{Op: "lstat", Path: "x", Err: fs.ErrPermission}) {
			t.Error("a permission refusal on a root's folder is not called a sudo run")
		}
	})
}

// TestRootLaunchedWordsStateFacts: the three facts behind RootLaunched (a permission refusal, a caller that is not root,
// a folder root owns) do not show that a run is still going or who made the folder: a root-owned folder a sudo run left
// when it died, or one made by sudo cp, gets the same words. They say what is owned by whom and what a sudo run does, and
// never that the folder is root's "until it ends".
func TestRootLaunchedWordsStateFacts(t *testing.T) {
	w := RootLaunchedWords("r-aaaa-0000-xxxxxx")
	if !strings.Contains(w, "owned by root") || !strings.Contains(w, "launched with sudo") {
		t.Errorf("the words do not name the owner and the usual cause: %q", w)
	}
	if strings.Contains(w, "until it ends") || strings.Contains(w, "was launched with sudo") {
		t.Errorf("the words state a cause or a lifetime the record does not show: %q", w)
	}
}
