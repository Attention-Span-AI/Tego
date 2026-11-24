// SPDX-License-Identifier: Apache-2.0

package pricetable

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTable(t *testing.T, path, body string, stamp time.Time) {
	t.Helper()
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tmp, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// TestIdentitySeesEveryReplacement: a table replaced by rename, again and again within a second, to the same size, with
// the same modification time on every version, never has an identity an earlier version had; a file nobody touched keeps
// its identity, and one that appears or goes away changes it.
func TestIdentitySeesEveryReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prices.yaml")
	if got := Identity(path); got == "" {
		t.Fatal("a missing table has no identity")
	}
	missing := Identity(path)
	stamp := time.Now().Add(-time.Hour).Truncate(time.Second)
	seen := map[string]string{missing: "missing"}
	for _, body := range []string{"aaaa", "bbbb", "cccc", "aaaa", "bbbb", "aaaa"} {
		writeTable(t, path, body, stamp) // each version is a new file of the same size and stamp, and may reuse an inode
		id := Identity(path)
		if prev, dup := seen[id]; dup && prev != body {
			t.Fatalf("version %q has the identity of %q", body, prev)
		}
		if again := Identity(path); again != id {
			t.Fatalf("an untouched table changed its identity: %q then %q", id, again)
		}
		seen[id] = body
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got := Identity(path); got != missing {
		t.Errorf("a removed table is named %q, not as a missing one %q", got, missing)
	}
}

// TestIdentityUsesStampsOnceTheyCanBeTrusted: a file whose times are older than the racy window is named by its stamps
// alone (no read of it), and any change of size, inode or time moves the name; a file written just now is named by its
// content as well.
func TestIdentityUsesStampsOnceTheyCanBeTrusted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prices.yaml")
	stamp := time.Now().Add(-time.Hour)
	writeTable(t, path, "aaaa", stamp)
	later := time.Now().Add(time.Hour) // as if an hour had passed: the stamps are now old enough to trust
	old := identityAt(path, later)
	if identityAt(path, later) != old {
		t.Error("an old untouched file changed its identity")
	}
	if strings.Contains(old, "sha256:") {
		t.Errorf("an old file was read for its content: %q", old)
	}
	if now := Identity(path); !strings.Contains(now, "sha256:") {
		t.Errorf("a file written just now is named by its stamps alone: %q", now)
	}
	writeTable(t, path, "bbbbb", stamp) // another size
	if identityAt(path, later) == old {
		t.Error("a replacement of another size kept the identity")
	}
}
