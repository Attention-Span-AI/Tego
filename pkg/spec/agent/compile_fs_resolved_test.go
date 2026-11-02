// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUnenforcedDiagnosticNamesTheDeclaredWriteEntry holds the unenforced warning to E8's rule for
// every other diagnostic in this package: "Diagnostics name the declared path and its target when
// the two differ." Once the containment check moved onto the resolved subtree, the message carried
// the resolved write path alone — a string that appears nowhere in the author's contract, while the
// entry they must actually edit went unnamed.
func TestUnenforcedDiagnosticNamesTheDeclaredWriteEntry(t *testing.T) {
	f := newFixture(t)
	vault := filepath.Join(f.root, "vault")
	keys := filepath.Join(vault, "keys")
	if err := os.MkdirAll(keys, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.project, "data")
	if err := os.Symlink(vault, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	// fs.reads: direct keeps the target unenforced and says so; auto holds the run's reads and says that instead
	// (ADR 0069), naming the same two paths.
	for reads, code := range map[string]string{"direct": CodeUnenforced, "auto": CodeHeldReads} {
		_, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\ntier: landlock\nfs:\n  reads: " + reads + "\n  write: [\"data\"]\n  deny_read: [\"" + keys + "\"]\n"))
		var msg string
		for _, d := range ds {
			if d.Code == code {
				msg = d.Message
			}
		}
		if msg == "" {
			t.Fatalf("fs.reads: %s: no %s warning:\n%s", reads, code, render(ds))
		}
		if !strings.Contains(msg, link) {
			t.Errorf("fs.reads: %s: the warning never names the write entry as declared (%s):\n%s", reads, link, msg)
		}
		if !strings.Contains(msg, vault) {
			t.Errorf("fs.reads: %s: the warning never names the write entry's target (%s):\n%s", reads, vault, msg)
		}
	}
}

// TestEveryFSRuleCarriesResolved extends the existing Resolved check to the contract shape that had
// no write entry to resolve: `fs: {}` compiles a deny-all-writes rule at "/" (R6), and that rule was
// built as a bare literal with no Resolved. FSRule.Resolved is documented as "equal to Path whenever
// no component is a symlink", and every containment check reads it — an entry carrying "" compares
// against the empty string instead of against a path.
func TestEveryFSRuleCarriesResolved(t *testing.T) {
	f := newFixture(t)
	for _, src := range []string{
		"version: 0\nname: a\ncommand: [python]\nfs: {}\n",
		"version: 0\nname: a\ncommand: [python]\nfs:\n  write: []\n",
		"version: 0\nname: a\ncommand: [python]\n",
	} {
		rt, _ := f.compile(f.load(src))
		for _, r := range rt.FS {
			if r.Resolved == "" {
				t.Errorf("%q: %s entry %s has no Resolved path", src, r.Kind, r.Path)
			}
		}
	}
}

// TestUnixEntryCarriesResolved: a pathname unix: entry compiles with the place its symlinks lead to (NetRule.UnixResolved,
// ResolveUnixPlace: the resolution the run makes of it too), which
// a landed connect or datagram is matched against as the supervisor's decideResolved matches it. An abstract name
// has none.
func TestUnixEntryCarriesResolved(t *testing.T) {
	f := newSocketFixture(t, "project/lk/s.sock")
	real := filepath.Join(f.root, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.project, "lk")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nnet:\n  allow: [\"unix:" + link + "/s.sock\", \"unix:" +
		real + "/t.sock\", \"unix:@bus\"]\n"))
	want := map[string]string{link + "/s.sock": real + "/s.sock", real + "/t.sock": real + "/t.sock", "bus": ""}
	if len(rt.Net) != len(want) {
		t.Fatalf("%d net entries, want %d: %+v", len(rt.Net), len(want), rt.Net)
	}
	for _, r := range rt.Net {
		if w, ok := want[r.UnixPath]; !ok || r.UnixResolved != w {
			t.Errorf("unix entry %q: UnixResolved %q, want %q", r.UnixPath, r.UnixResolved, w)
		}
	}
}
