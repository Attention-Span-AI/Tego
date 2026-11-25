// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// systemd writes an escaped dash in a unit name as the four characters
// backslash, x, 2, d. A backslash cannot be part of a file name in a Windows
// checkout, so the repository stores such a fixture file with the backslash
// spelled %5C (the manifests keep the real name), and the tests that rebuild a
// tree in a temporary folder give each file its real name again.
func storedFixtureName(name string) string {
	return strings.ReplaceAll(name, `\`, "%5C")
}

// requireEscapedNames fails unless the rebuilt tree under root holds exactly
// want files whose real path carries an escaped dash, and none with the stored
// spelling: a tree rebuilt from the stored names would present the code under
// test with different names than a real system does.
func requireEscapedNames(t *testing.T, root string, want int) {
	t.Helper()
	got := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(path, "%5C") {
			t.Errorf("fixture tree has a stored name, not the real one: %s", path)
		}
		if !d.IsDir() && strings.Contains(path[len(root):], `\x2d`) {
			got++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("rebuilt tree holds %d files with an escaped dash in their path, want %d", got, want)
	}
}

func TestStoredFixtureNameKeepsEveryOtherByte(t *testing.T) {
	if got := storedFixtureName(`usr/lib/a\x2db.service.d/20.conf`); got != "usr/lib/a%5Cx2db.service.d/20.conf" {
		t.Fatalf("stored name: %q", got)
	}
	if got := storedFixtureName("plain.service"); got != "plain.service" {
		t.Fatalf("plain name changed: %q", got)
	}
}

// A unit file whose real name carries an escaped dash is not a name the
// collector accepts: it is disclosed as a source that was not read, never
// dropped without a trace, and the plain unit next to it is still read. A tree
// that stored the name with %5C would present a plain-looking name instead and
// the disclosure below would not appear.
func TestEscapedDashUnitNameIsDisclosedNotSkipped(t *testing.T) {
	root := unitFixtureRoot(t)
	real := `my\x2dagent.service`
	writeSettings(t, root, real, []byte("[Service]\nExecStart=claude\n"))
	writeSettings(t, root, `my\x2dagent.service.d/20-reset.conf`, []byte("[Service]\nExecStart=\nExecStart=gemini\n"))
	writeSettings(t, root, "plain.service", []byte("[Service]\nExecStart=codex\n"))
	if _, err := os.Lstat(filepath.Join(root, real)); err != nil {
		t.Fatalf("the filesystem under the test cannot hold the escaped name: %v", err)
	}
	u := collectUnits(t.Context(), []string{root}, uint32(os.Getuid()), &contentBudget{remaining: 6 << 20})
	if len(u.Items) != 1 || u.Items[0].Name != "plain.service" {
		t.Fatalf("the plain unit beside an escaped name was not the only item: %+v", u.Items)
	}
	for _, source := range u.Sources {
		if source.Path == filepath.Join(root, real) {
			if source.State != "not-read" || source.Reason != "unsupported" {
				t.Fatalf("escaped unit name disclosed wrongly: %+v", source)
			}
			return
		}
	}
	t.Fatalf("escaped unit name left no source row: %+v", u.Sources)
}
