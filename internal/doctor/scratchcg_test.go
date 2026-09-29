// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestMakeScratchDirNeverReusesALeftoverOne: an empty leftover of this pid is replaced, one with content is an
// error, and no caller reuses it.
func TestMakeScratchDirNeverReusesALeftoverOne(t *testing.T) {
	root := t.TempDir()
	path, err := makeScratchDir(root, ".tego-doctor-")
	if err != nil || filepath.Base(path) != ".tego-doctor-"+strconv.Itoa(os.Getpid()) {
		t.Fatalf("fresh: %q, %v", path, err)
	}
	if again, err := makeScratchDir(root, ".tego-doctor-"); err != nil || again != path {
		t.Errorf("an empty leftover: %q, %v; want it made afresh", again, err)
	}
	if err := os.Mkdir(filepath.Join(path, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := makeScratchDir(root, ".tego-doctor-"); err == nil {
		t.Error("a leftover holding something was reused")
	}
}

// TestPlaneFixturesDoNotFollowTMPDIR: the probe's fixtures go under fixtureRoot, a 0700 directory, not under
// $TMPDIR, whose filesystem could lack hard links or be read-only and fault the probe.
func TestPlaneFixturesDoNotFollowTMPDIR(t *testing.T) {
	prev := fixtureRoot
	t.Cleanup(func() { fixtureRoot = prev })
	fixtureRoot = filepath.Join(t.TempDir(), "tego")
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "elsewhere"))
	base := fixtureBase()
	if base != fixtureRoot {
		t.Fatalf("base %q, want %q", base, fixtureRoot)
	}
	if st, err := os.Stat(base); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("fixtures directory: %v, %v; want 0700", st, err)
	}
}

// TestFanotifyFixtureDoesNotFollowTMPDIR: D8's directory is made under the fixtures root like the plane probe's,
// so a read-only or full $TMPDIR does not fail D8 for a reason that is not the kernel's.
func TestFanotifyFixtureDoesNotFollowTMPDIR(t *testing.T) {
	prev := fixtureRoot
	t.Cleanup(func() { fixtureRoot = prev })
	fixtureRoot = filepath.Join(t.TempDir(), "tego")
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing", "elsewhere"))
	dir, err := makeFanotifyDir()
	if err != nil {
		t.Fatalf("makeFanotifyDir: %v", err)
	}
	if filepath.Dir(dir) != fixtureRoot {
		t.Errorf("fixture %q, want it under %q", dir, fixtureRoot)
	}
}

// TestProbeFixtureDirsSweepAKilledProbesTree: a probe killed before its deferred removal leaves its fixture tree
// under /run/tego; the next probe of the same kind removes it once its pid is gone and it is stale, and keeps a
// live pid's, a recent one, its own pid's and another prefix's.
func TestProbeFixtureDirsSweepAKilledProbesTree(t *testing.T) {
	prev := fixtureRoot
	t.Cleanup(func() { fixtureRoot = prev })
	fixtureRoot = filepath.Join(t.TempDir(), "tego")
	if fixtureBase() != fixtureRoot {
		t.Fatal("fixture root not made")
	}
	const deadPID = 99999999 // above any pid_max
	old := time.Now().Add(-2 * fixtureStaleAge)
	mk := func(name string, mtime time.Time) string {
		p := filepath.Join(fixtureRoot, name)
		if err := os.MkdirAll(filepath.Join(p, "in", "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, prefix := range []string{planeScratchPrefix, fanotifyFixturePrefix} {
		other := planeScratchPrefix
		if prefix == other {
			other = fanotifyFixturePrefix
		}
		dead := mk(prefix+strconv.Itoa(deadPID)+"-123", old)
		legacy := mk(prefix+"4012345678", old) // an os.MkdirTemp name from before the pid naming
		keep := []string{
			mk(prefix+strconv.Itoa(os.Getppid())+"-1", old),   // a live pid
			mk(prefix+strconv.Itoa(deadPID)+"-2", time.Now()), // recent: maybe a live probe in another pid namespace
			mk(prefix+strconv.Itoa(os.Getpid())+"-3", old),    // this process's own
			mk(other+strconv.Itoa(deadPID)+"-4", old),         // another probe's kind
			mk(prefix+"x-5", old),                             // no pid
		}
		dir, err := makeFixtureDir(prefix)
		if err != nil {
			t.Fatal(err)
		}
		if want := prefix + strconv.Itoa(os.Getpid()) + "-"; !strings.HasPrefix(filepath.Base(dir), want) || filepath.Dir(dir) != fixtureRoot {
			t.Errorf("made %q, want %s… under %s", dir, want, fixtureRoot)
		}
		for _, p := range []string{dead, legacy} {
			if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s: a killed probe's tree was not swept (%v)", filepath.Base(p), err)
			}
		}
		for _, p := range keep {
			if _, err := os.Stat(p); err != nil {
				t.Errorf("%s was swept: %v", filepath.Base(p), err)
			}
		}
		if err := os.RemoveAll(fixtureRoot); err != nil || fixtureBase() == "" {
			t.Fatal(err)
		}
	}
}

// TestFanotifyFixtureFixNamesTheFixturesDirectory: D8's fixtures live under /run/tego, so the fix for a fixture it
// could not make, and the host-policy fix, name that directory and not $TMPDIR alone.
func TestFanotifyFixtureFixNamesTheFixturesDirectory(t *testing.T) {
	for name, fix := range map[string]string{"fixture": fanotifyFixtureFix, "host policy": fanotifyHostPolicyFix} {
		if !strings.Contains(fix, "/run/tego") || strings.Contains(fix, "(TMPDIR)") || strings.Contains(fix, "on $TMPDIR") {
			t.Errorf("the %s fix does not name /run/tego: %q", name, fix)
		}
	}
}
