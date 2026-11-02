// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAnchorHeadsAnswersAsHead: one read of a chain.log answers, for every run asked about, what Head answers for it
// alone, whatever else the file holds: no file, an empty one, two heads for one run, a malformed line before or after
// a run's line, a repeated line, a torn tail, a link or a directory where the file should be. The file read is
// returned as stat'ed (none when there is no regular file to read), so a caller can tell when the answers go stale.
func TestAnchorHeadsAnswersAsHead(t *testing.T) {
	a, b := testRef.ID, runID(fixedStart.Add(time.Minute), "zz9zz9")
	absent := runID(fixedStart.Add(2*time.Minute), "zz8zz8")
	ha, hb, hx := strings.Repeat("ab", 32), strings.Repeat("cd", 32), strings.Repeat("ef", 32)
	runs := []string{a, b, absent, "not a run id"}
	for _, tc := range []struct {
		name string
		body string // "" with none set below: no file
		make func(t *testing.T, path string)
	}{
		{name: "no file"},
		{name: "empty", body: "\x00"},
		{name: "one line each", body: a + " " + ha + "\n" + b + " " + hb + "\n"},
		{name: "two heads for one run", body: a + " " + ha + "\n" + b + " " + hb + "\n" + a + " " + hx + "\n"},
		{name: "two heads, then a malformed line", body: a + " " + ha + "\n" + a + " " + hx + "\ngarbage\n" + b + " " + hb + "\n"},
		{name: "a malformed line first", body: "garbage\n" + a + " " + ha + "\n"},
		{name: "a malformed line after a run's", body: a + " " + ha + "\nr-x y\n" + b + " " + hb + "\n"},
		{name: "a repeated line", body: a + " " + ha + "\n" + b + " " + hb + "\n" + a + " " + ha + "\n"},
		{name: "a torn tail", body: a + " " + ha + "\n" + b + " " + hb[:7]},
		{name: "a link", make: func(t *testing.T, path string) {
			target := filepath.Join(t.TempDir(), "elsewhere")
			if err := os.WriteFile(target, []byte(a+" "+ha+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a directory", make: func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ChainLogFile)
			switch {
			case tc.make != nil:
				tc.make(t, path)
			case tc.body != "":
				if err := os.WriteFile(path, []byte(strings.TrimPrefix(tc.body, "\x00")), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			heads, fi := AnchorHeads(path, runs)
			for _, r := range runs {
				h, ok, err := NewFileChainAnchor(path).Head(r)
				got := heads[r]
				if got.Head != h || got.OK != ok || errString(got.Err) != errString(err) {
					t.Errorf("%s: AnchorHeads %q %v %v, Head %q %v %v", r, got.Head, got.OK, got.Err, h, ok, err)
				}
			}
			st, err := os.Lstat(path)
			regular := err == nil && st.Mode().IsRegular()
			if (fi != nil) != regular || fi != nil && (fi.Size() != st.Size() || !os.SameFile(fi, st)) {
				t.Errorf("the file as read: %v, want it exactly when a regular file is there (%v)", fi, st)
			}
		})
	}
}

// errString is err's text, "" for none.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
