// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	specid "github.com/attention-span-ai/tego/pkg/spec/identity"
)

// sharedTree lays out one library's pinned probes as files in a temporary directory, with the library's lock in
// a temporary state directory. The logic of the hold, the grace and the removal is the same on bpffs; only the
// kernel's detach, which an unlink of a real pin causes, is not here (shared_integration_test.go has it).
func sharedTree(t *testing.T) detachJob {
	t.Helper()
	j := detachJob{root: t.TempDir(), state: t.TempDir(), hash: "h1", key: "2-1497-abcd"}
	dir := filepath.Join(j.root, UprobePinDir, j.key)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"0", "1", "2"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(j.state, j.lockName()), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return j
}

// hold takes a shared hold on the library's lock, as a run that attached or adopted its probes holds it.
func hold(t *testing.T, j detachJob) *os.File {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(j.state, j.lockName()), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	return f
}

func libDir(j detachJob) string { return filepath.Join(j.root, UprobePinDir, j.key) }

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// TestTheLastHoldOutHandsTheProbesOnAndNoOtherDoes: of two runs holding one library, the first to leave hands
// nothing on, since the other still wants the probes; the last hands the library to the detacher exactly once
// and stamps the lock, which is where the grace counts from. The probes are still there when it has: their
// removal is the detacher's, never the leaving run's.
func TestTheLastHoldOutHandsTheProbesOnAndNoOtherDoes(t *testing.T) {
	j := sharedTree(t)
	var handed []detachJob
	detach := func(d detachJob) { handed = append(handed, d) }
	a := &libHold{f: hold(t, j), job: j, detach: detach}
	b := &libHold{f: hold(t, j), job: j, detach: detach}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(j.state, j.lockName()), old, old); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if len(handed) != 0 {
		t.Fatalf("the first run out handed the probes on while another run held them: %+v", handed)
	}
	before := time.Now().Add(-time.Second)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if len(handed) != 1 || handed[0] != j {
		t.Fatalf("handed %+v, want the library once", handed)
	}
	if !exists(libDir(j)) {
		t.Fatal("the leaving run removed the probes itself; that is the detacher's, off the run's path")
	}
	st, err := os.Stat(filepath.Join(j.state, j.lockName()))
	if err != nil {
		t.Fatal(err)
	}
	if st.ModTime().Before(before) {
		t.Fatalf("the lock's mtime %s was not stamped at the last run out", st.ModTime())
	}
	if err := b.Close(); err != nil || len(handed) != 1 {
		t.Fatalf("a second Close: %v, handed %d times", err, len(handed))
	}
}

// TestDetachAfterKeepsHeldProbesAndRemovesIdleOnes: the detacher leaves the probes of a library a run holds
// again, and removes those of one nobody holds, leaving no directory aside.
func TestDetachAfterKeepsHeldProbesAndRemovesIdleOnes(t *testing.T) {
	j := sharedTree(t)
	f := hold(t, j)
	if err := detachAfter(j, 0); err != nil {
		t.Fatal(err)
	}
	if !exists(libDir(j)) {
		t.Fatal("the detacher removed the probes of a library a run holds")
	}
	_ = f.Close()
	if err := detachAfter(j, 0); err != nil {
		t.Fatal(err)
	}
	if exists(libDir(j)) {
		t.Fatal("the probes of a library nobody holds are still pinned")
	}
	left, _ := os.ReadDir(filepath.Join(j.root, UprobePinDir))
	if len(left) != 0 {
		t.Fatalf("left behind %v", left)
	}
	if err := detachAfter(j, 0); err != nil {
		t.Fatalf("a second detacher of a library already gone: %v", err)
	}
}

// TestDetachAfterWaitsOutTheGraceFromTheLastStamp: the probes stay for the grace from the last run out's stamp,
// and a run that came and went meanwhile, moving the stamp, extends it: back-to-back runs adopt the probes
// rather than place them while the kernel is still detaching the old ones.
func TestDetachAfterWaitsOutTheGraceFromTheLastStamp(t *testing.T) {
	j := sharedTree(t)
	lock := filepath.Join(j.state, j.lockName())
	const grace = 300 * time.Millisecond
	now := time.Now()
	if err := os.Chtimes(lock, now, now); err != nil {
		t.Fatal(err)
	}
	done := make(chan time.Time, 1)
	go func() {
		_ = detachAfter(j, grace)
		done <- time.Now()
	}()
	time.Sleep(150 * time.Millisecond)
	if !exists(libDir(j)) {
		t.Fatal("the probes went before the grace was out")
	}
	moved := time.Now()
	if err := os.Chtimes(lock, moved, moved); err != nil {
		t.Fatal(err)
	}
	end := <-done
	if end.Before(moved.Add(grace)) {
		t.Fatalf("removed %s after the moved stamp, before its grace of %s", end.Sub(moved), grace)
	}
	if exists(libDir(j)) {
		t.Fatal("the probes are still pinned after the grace")
	}
}

// TestDetachMainTouchesOnlyALibraryOfABuildUnderTheTegoTree: the hidden command refuses any directory but a
// build's own pin directory under the bpf filesystem's tego tree and the verified /run/tego, and any hash or
// key that is not one path element, before it opens anything.
func TestDetachMainTouchesOnlyALibraryOfABuildUnderTheTegoTree(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"/tmp/x", "/run/tego", "h", "k", "2s"},
		{PinDir + "/h", "/tmp", "h", "k", "2s"},
		{PinDir + "/h", "/run/tego", "h", "../k", "2s"},
		{PinDir + "/../h", "/run/tego", "..", "k", "2s"},
		{PinDir + "/h", "/run/tego", "h", "k", "2h"},
		{PinDir + "/h", "/run/tego", "h", "k", "soon"},
		{PinDir + "/h", "/run/tego", "h/i", "k", "2s"},
	} {
		if got := DetachMain(args); got != specid.ExitUsage {
			t.Errorf("DetachMain(%q) = %d, want the usage error %d", args, got, specid.ExitUsage)
		}
	}
}

// TestLibKeyIsOnePathElementNamingTheFile: the key carries the (device, inode) and the build id, and is a name
// DetachMain accepts.
func TestLibKeyIsOnePathElementNamingTheFile(t *testing.T) {
	for _, id := range []identity{
		{Dev: 2, Ino: 1497, BuildID: "350c8a2c0a8e74b386ba7eef5f164594c2fe261a"},
		{Dev: 66305, Ino: 9},
		{Dev: 1, Ino: 2, BuildID: strings.Repeat("ab", 40)},
	} {
		k := libKey(id)
		if !pinName(k) || len(k) > 80 {
			t.Errorf("libKey(%+v) = %q", id, k)
		}
		other := id
		other.BuildID += "0"
		if id.BuildID != "" && len(id.BuildID) < 40 && libKey(other) == k {
			t.Errorf("two build ids share the key %q", k)
		}
	}
}

// TestSweepLibrariesRemovesOnlyOverdueUnheldProbes: a library's detacher can be killed inside its grace (with the
// launcher's cgroup, before it had its own), and its probes then stayed attached host-wide until a gc. The sweep
// a run's start, doctor and gc make removes a library no run holds whose grace is over, one with no lock at all,
// and a directory a detacher moved aside and left; it keeps one a run holds and one still inside its grace.
func TestSweepLibrariesRemovesOnlyOverdueUnheldProbes(t *testing.T) {
	pinRoot, state := t.TempDir(), t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	lib := func(hash, key string, stamped time.Duration, locked bool) string {
		t.Helper()
		dir := filepath.Join(pinRoot, hash, UprobePinDir, key)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "0"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if locked {
			lock := filepath.Join(state, detachJob{hash: hash, key: key}.lockName())
			if err := os.WriteFile(lock, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			at := now.Add(-stamped)
			if err := os.Chtimes(lock, at, at); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	overdue := lib("h1", "1-10-aa", time.Minute, true)
	unlocked := lib("h1", "1-11-bb", 0, false)
	aside := lib("h1", detachingPrefix+"1-12-cc-x", 0, false)
	graced := lib("h2", "1-13-dd", time.Second, true)
	held := lib("h2", "1-14-ee", time.Hour, true)
	f := hold(t, detachJob{root: filepath.Join(pinRoot, "h2"), state: state, hash: "h2", key: "1-14-ee"})
	defer f.Close()

	n, err := SweepLibraries(pinRoot, state, now)
	if err != nil {
		t.Fatalf("SweepLibraries: %v", err)
	}
	if n != 3 {
		t.Errorf("removed %d libraries, want 3", n)
	}
	for dir, gone := range map[string]bool{overdue: true, unlocked: true, aside: true, graced: false, held: false} {
		if _, err := os.Stat(dir); os.IsNotExist(err) != gone {
			t.Errorf("%s: gone %v, want %v", dir, os.IsNotExist(err), gone)
		}
	}
}
