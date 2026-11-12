// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// newTestFS roots a manager in a temporary directory: mkdir works, control files do not exist
// until the test writes them, which is exactly the missing-controller shape of case 31.
func newTestFS(t *testing.T) *FS {
	t.Helper()
	fs, err := NewAt(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fs.removeDelay = 5 * time.Millisecond
	return fs
}

// writeCtl replaces a control file the way the kernel does: in one rename, so a watcher reading
// concurrently sees either the old contents or the new ones. A plain os.WriteFile truncates first, and a
// read landing in that window sees a file with no populated line, which the watcher rightly calls
// malformed. Real cgroupfs never shows that state, so the test must not either.
func writeCtl(t *testing.T, c Cgroup, name, content string) {
	t.Helper()
	path := filepath.Join(c.Path, name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func TestNewAt(t *testing.T) {
	if _, err := NewAt(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing root must fail")
	}
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAt(f); err == nil {
		t.Fatal("a file is not a root")
	}
}

// Also pins runtime-launch.md E33: a cgroup path is never reused (ErrCgroupExists).
func TestCreate(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.Create("retriever", "r-abc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	want := filepath.Join(fs.Root(), "tego.slice", "tego-retriever.slice", "run-r-abc.scope")
	if c.Path != want {
		t.Fatalf("path %s want %s", c.Path, want)
	}
	if c.dir == nil {
		t.Fatal("no directory fd")
	}
	var st unix.Stat_t
	if err := unix.Fstat(dirNum(t, c), &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		t.Fatalf("fd is not a directory: %v", err)
	}
	if c.ID != st.Ino {
		t.Fatalf("ID %d want st_ino %d (fallback on a non-kernfs filesystem)", c.ID, st.Ino)
	}
	if id, err := fs.ID(Cgroup{Path: c.Path}); err != nil || id != st.Ino {
		t.Fatalf("ID by path = %d, %v; want %d", id, err, st.Ino)
	}
	// R: run ids are single-use; a second Create of the same scope is corruption.
	if _, err := fs.Create("retriever", "r-abc"); !errors.Is(err, ErrCgroupExists) || !errors.Is(err, unix.EEXIST) {
		t.Fatalf("second create: %v", err)
	}
	// A sibling run of the same agent shares the slices.
	c2, err := fs.Create("retriever", "r-def")
	if err != nil {
		t.Fatal(err)
	}
	_ = c2.Close()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close is idempotent: %v", err)
	}
}

func TestCreateBadNames(t *testing.T) {
	fs := newTestFS(t)
	tests := []struct{ agent, run string }{
		{"Bad Agent", "r-1"},
		{"", "r-1"},
		{"a", ""},
		{"a", "x/y"},
		{"a", ".."},
		{"a", "a\x00b"},
		// runtime-launch.md E17: no non-ASCII reaches a cgroup path, whatever the caller passes as an agent (the run id is minted ASCII by identity.NewRunID).
		{"agent-é", "r-1"},
	}
	for _, tc := range tests {
		if _, err := fs.Create(tc.agent, tc.run); !errors.Is(err, ErrBadName) {
			t.Errorf("Create(%q, %q) = %v, want ErrBadName", tc.agent, tc.run, err)
		}
	}
}

// Also pins runtime-launch.md E31: a missing control file is its own missing-controller error.
func TestSetLimitsMissingController(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.Create("a", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	// case 31: the control file does not exist because the controller was never delegated.
	err = fs.SetLimits(c, Limits{PidsMax: 5})
	var mc *MissingControllerError
	if !errors.As(err, &mc) {
		t.Fatalf("want *MissingControllerError, got %v", err)
	}
	if mc.Controller != "pids" || mc.Root != fs.Root() || !errors.Is(err, ErrControllerMissing) || !errors.Is(err, unix.ENOENT) {
		t.Fatalf("bad classification: %+v", mc)
	}
	if mc.Fix() == "" || mc.Error() == "" {
		t.Fatal("empty fix")
	}
	// Missing agrees before the write.
	if got := Missing(c, Limits{PidsMax: 5}); len(got) != 1 || got[0] != "pids" {
		t.Fatalf("Missing = %v", got)
	}
}

// Also pins runtime-launch.md E33: a partial SetLimits failure stops at the first missing file.
func TestSetLimitsWrites(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.Create("a", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	for _, name := range []string{"cpu.max", "cpu.weight", "memory.max", "memory.swap.max", "memory.high", "pids.max"} {
		writeCtl(t, c, name, "")
	}
	l := Limits{CPUMax: "200000 100000", CPUWeight: 50, MemoryMax: 1 << 20, MemoryHigh: 1 << 19, PidsMax: 64}
	if err := fs.SetLimits(c, l); err != nil {
		t.Fatal(err)
	}
	for _, f := range limitFiles(l) {
		got, err := os.ReadFile(filepath.Join(c.Path, f.Name))
		if err != nil || string(got) != f.Value {
			t.Fatalf("%s = %q, %v; want %q", f.Name, got, err, f.Value)
		}
	}
	// A partial failure stops at the first missing file (case 33) after writing the earlier ones.
	if err := os.Remove(filepath.Join(c.Path, "memory.high")); err != nil {
		t.Fatal(err)
	}
	writeCtl(t, c, "memory.max", "") // a control file replaces its value; a tmpfs file must be emptied first
	err = fs.SetLimits(c, Limits{MemoryMax: 7, MemoryHigh: 8, PidsMax: 9})
	var mc *MissingControllerError
	if !errors.As(err, &mc) || mc.Controller != "memory" {
		t.Fatalf("got %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(c.Path, "memory.max")); string(got) != "7" {
		t.Fatalf("memory.max = %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(c.Path, "pids.max")); string(got) != "64" {
		t.Fatalf("pids.max must not have been written after the failure: %q", got)
	}
}

// TestSetLimitsCapsSwapWithMemory: a memory cap writes memory.swap.max 0 beside memory.max, so the kernel
// OOM-kills an agent over its cap instead of swapping it out; a kernel that accounts no swap has no such file,
// and the cap is set without it.
func TestSetLimitsCapsSwapWithMemory(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.Create("a", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	writeCtl(t, c, "memory.max", "")
	writeCtl(t, c, "memory.swap.max", "")
	if err := fs.SetLimits(c, Limits{MemoryMax: 64 << 20}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(c.Path, "memory.swap.max")); string(got) != "0" {
		t.Fatalf("memory.swap.max = %q, want 0", got)
	}
	if err := os.Remove(filepath.Join(c.Path, "memory.swap.max")); err != nil {
		t.Fatal(err)
	}
	writeCtl(t, c, "memory.max", "")
	if err := fs.SetLimits(c, Limits{MemoryMax: 32 << 20}); err != nil {
		t.Fatalf("without swap accounting: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(c.Path, "memory.max")); string(got) != "33554432" {
		t.Fatalf("memory.max = %q", got)
	}
}

func TestClassify(t *testing.T) {
	fs := newTestFS(t)
	c := Cgroup{Path: "/x"}
	f := limitFile{Name: "cpu.max", Value: "1 2", Controller: "cpu"}
	if err := fs.classify(c, f, syscall.EINVAL); !errors.Is(err, ErrInvalidLimit) || !errors.Is(err, unix.EINVAL) {
		t.Fatalf("EINVAL: %v", err)
	}
	if err := fs.classify(c, f, syscall.EACCES); errors.Is(err, ErrInvalidLimit) || errors.Is(err, ErrControllerMissing) || !errors.Is(err, unix.EACCES) {
		t.Fatalf("EACCES: %v", err)
	}
	if err := fs.classify(c, f, errors.New("other")); err == nil {
		t.Fatal("other errors are wrapped, not dropped")
	}
}

func TestKillAndEvents(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.Create("a", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := fs.Kill(c); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("kill without cgroup.kill: %v", err)
	}
	writeCtl(t, c, "cgroup.kill", "")
	if err := fs.Kill(c); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(c.Path, "cgroup.kill")); string(got) != "1" {
		t.Fatalf("cgroup.kill = %q", got)
	}
	// OOM and pids counters: absent file reads as zero, present file is parsed.
	if oom, err := fs.OOMKilled(c); err != nil || oom {
		t.Fatalf("no memory.events: %v %v", oom, err)
	}
	writeCtl(t, c, "memory.events", "low 0\noom 1\noom_kill 2\n")
	writeCtl(t, c, "pids.events", "max 4\n")
	if oom, err := fs.OOMKilled(c); err != nil || !oom {
		t.Fatalf("oom: %v %v", oom, err)
	}
	if o, p, err := ReadLimitEvents(c); err != nil || o != 2 || p != 4 {
		t.Fatalf("ReadLimitEvents = %d %d %v", o, p, err)
	}
	writeCtl(t, c, "memory.events", "garbage\n")
	if _, err := fs.OOMKilled(c); err == nil {
		t.Fatal("a memory.events without oom_kill is an error, not false")
	}
}

func TestWaitEmpty(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.Create("a", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	// A cgroup that is already gone (no cgroup.events) is empty.
	if err := fs.WaitEmpty(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	writeCtl(t, c, "cgroup.events", "populated 0\nfrozen 0\n")
	emptyCtx, cancelEmpty := context.WithCancel(context.Background())
	cancelEmpty()
	if err := fs.WaitEmpty(emptyCtx, c); err != nil {
		t.Fatalf("already empty, even with an ended context: %v", err)
	}
	writeCtl(t, c, "cgroup.events", "populated invalid\n")
	if err := fs.WaitEmpty(context.Background(), c); err == nil {
		t.Fatal("malformed state must not be treated as empty")
	}
	writeCtl(t, c, "cgroup.events", "populated 1\nfrozen 0\n")
	if p, err := Populated(c); err != nil || !p {
		t.Fatalf("populated: %v %v", p, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := fs.WaitEmpty(ctx, c); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("still populated: %v", err)
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		// Atomically, as the kernel writes cgroup.events: os.WriteFile truncates first, so a watcher
		// reading in that window sees a file with no populated line and reports it as malformed.
		writeAtomic(filepath.Join(c.Path, "cgroup.events"), "populated 0\nfrozen 0\n")
	}()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	start := time.Now()
	if err := fs.WaitEmpty(ctx2, c); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v: neither inotify nor the poll fallback woke", d)
	}
}

func TestEvents(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.Create("a", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	writeCtl(t, c, "cgroup.events", "populated 1\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := fs.Events(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if v := <-ch; !v {
		t.Fatal("first value is the state at subscription (populated)")
	}
	writeCtl(t, c, "cgroup.events", "populated 0\n")
	waitState(t, ch, false, "transition to empty")
	writeCtl(t, c, "cgroup.events", "populated 1\n")
	waitState(t, ch, true, "transition back to populated")
	cancel()
	for range ch { //nolint:revive // drain until close
	}
}

// Also pins runtime-launch.md I8, E9, E40: a non-empty cgroup is retried and then ErrBusy, never forced; the
// agent slice stays.
func TestRemove(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.Create("a", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(c.Path, "child", "grandchild"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.Remove(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scope survived: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(c.Path)); err != nil {
		t.Fatalf("the agent slice must stay: %v", err)
	}
	// Removing an already removed scope is fine (the sweep may race the launcher).
	if err := fs.Remove(context.Background(), Cgroup{Path: c.Path}); err != nil {
		t.Fatal(err)
	}
	// case 9: a directory that stays non-empty (a regular file stands in for the stuck task) is
	// retried and then ErrBusy, never removed by force.
	c2, err := fs.Create("a", "r-2")
	if err != nil {
		t.Fatal(err)
	}
	writeCtl(t, c2, "cgroup.procs", "1\n")
	if err := fs.Remove(context.Background(), c2); !errors.Is(err, ErrBusy) {
		t.Fatalf("want ErrBusy, got %v", err)
	}
	// ctx cancellation ends the retry loop early.
	c3, err := fs.Create("a", "r-3")
	if err != nil {
		t.Fatal(err)
	}
	writeCtl(t, c3, "cgroup.procs", "1\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := fs.Remove(ctx, c3); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

// waitState waits for the watcher to report want. It drains intermediate values instead of demanding one
// per write: the watcher reports the cgroup's current state, and two writes close together are legitimately
// coalesced into a single wake, so asserting a value per write is a race, not a requirement.
func waitState(t *testing.T, ch <-chan bool, want bool, what string) {
	t.Helper()
	deadline := time.After(4 * time.Second)
	for {
		select {
		case v, ok := <-ch:
			if !ok {
				t.Fatalf("%s: the watcher closed before reporting %v", what, want)
			}
			if v == want {
				return
			}
		case <-deadline:
			t.Fatalf("%s: the watcher never reported %v", what, want)
		}
	}
}

// writeAtomic is writeCtl for a goroutine: it reports nothing, because the test it serves fails on the
// observable behaviour instead of on the write.
func writeAtomic(path, contents string) {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(contents), 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// staleFD is a descriptor number this process cannot have open, so close(2) on it is EBADF: what a
// Cgroup copy whose fd somebody else already closed looks like from inside Remove.
const staleFD = 1 << 30

// staleOwner is an owner of staleFD, whose Close is close(2)'s EBADF.
func staleOwner(t *testing.T) *sys.FD {
	t.Helper()
	fd, err := sys.Own(staleFD, nil)
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

// dirNum is c's directory descriptor number, read under a lease, for a test that checks what the number
// names or reuses it after the close.
func dirNum(t *testing.T, c Cgroup) int {
	t.Helper()
	n := -1
	if err := c.dir.Borrow(func(fd int) error { n = fd; return nil }); err != nil {
		t.Fatalf("the directory lends nothing: %v", err)
	}
	return n
}

// TestRemoveClosesAndRemovesIndependently is R18 applied to Remove's own two steps: the close and
// the rmdir. A descriptor that is already gone must not turn "remove the cgroup" into "leak the
// cgroup" — the error is still reported, but only after the scope is actually gone.
func TestRemoveClosesAndRemovesIndependently(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.Create("a", "r-stale")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	err = fs.Remove(context.Background(), Cgroup{Path: c.Path, dir: staleOwner(t)})
	if !errors.Is(err, unix.EBADF) {
		t.Fatalf("Remove with a stale fd = %v, want the close error reported", err)
	}
	if _, err := os.Stat(c.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the scope survived a close error: %v", err)
	}
}

// TestCloseOnceAcrossCopies: Remove takes a Cgroup by value, and the launcher, the limits watcher
// and the signal killer each keep a copy of the same run's value, so "closed by Remove" (doc.go)
// has to mean closed once in total, not once per copy. A second Close through a copy must not
// close(2) whatever the process was handed that descriptor number in the meantime.
func TestCloseOnceAcrossCopies(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.Create("a", "r-copy")
	if err != nil {
		t.Fatal(err)
	}
	stale := c // the value the caller keeps after handing a copy to Remove
	fd := dirNum(t, c)
	if err := fs.Remove(context.Background(), c); err != nil {
		t.Fatal(err)
	}

	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("victim"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := grabFD(t, fd, func() (int, error) { return unix.Open(victim, unix.O_RDONLY|unix.O_CLOEXEC, 0) })

	if err := stale.Close(); err != nil {
		t.Fatalf("Close through a second copy: %v", err)
	}
	var buf [6]byte
	if _, err := unix.Pread(got, buf[:], 0); err != nil {
		t.Fatalf("Close through a stale copy closed an unrelated descriptor: %v", err)
	}
	if string(buf[:]) != "victim" {
		t.Fatalf("descriptor %d reads %q", got, buf[:])
	}
}

// TestStaleCopyReadsItsOwnCgroup is the other half of the same ownership rule: once the fd is
// closed, every copy of the value resolves control files through Path. Reaching a reused
// descriptor number instead would read — and for cgroup.kill write — another cgroup's files.
func TestStaleCopyReadsItsOwnCgroup(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.Create("a", "r-fallback")
	if err != nil {
		t.Fatal(err)
	}
	writeCtl(t, c, "cgroup.events", "populated 1\n")
	decoy := t.TempDir()
	if err := os.WriteFile(filepath.Join(decoy, "cgroup.events"), []byte("populated 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	stale := c // a copy that outlives the fd, as the limits watcher's does
	fd := dirNum(t, c)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	grabFD(t, fd, func() (int, error) {
		return unix.Open(decoy, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	})

	populated, err := Populated(stale)
	if err != nil {
		t.Fatalf("Populated through a stale copy: %v", err)
	}
	if !populated {
		t.Fatal("Populated read the cgroup that inherited the descriptor number, not its own")
	}
}

// grabFD opens files with open until one lands on the freed descriptor number want (open(2) returns
// the lowest free fd, so this is the first one unless the runtime raced us for it) and returns it.
// Every other descriptor it opened is closed at the end of the test.
func grabFD(t *testing.T, want int, open func() (int, error)) int {
	t.Helper()
	for i := 0; i < 64; i++ {
		fd, err := open()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		if fd == want {
			return fd
		}
	}
	t.Skipf("descriptor %d was taken by the runtime before the test could reuse it", want)
	return -1
}

// TestMissingControllerFixPerRoot pins the two halves of case 31's "one-line fix": Delegate= is a
// property of service and scope units only (systemd.io/CGROUP_DELEGATION), so a root launcher
// rooted at the cgroup2 mount point has no unit to set it on and must not be sent to a
// user@.service.d/ drop-in that cannot affect its run.
//
// Also pins runtime-launch.md E31: the missing-controller fix names the delegation for the root in use.
func TestMissingControllerFixPerRoot(t *testing.T) {
	for _, priv := range []bool{false, true} {
		fs := newTestFS(t)
		fs.privileged = priv
		c, err := fs.Create("a", "r-1")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		var mc *MissingControllerError
		if err := fs.SetLimits(c, Limits{PidsMax: 5}); !errors.As(err, &mc) {
			t.Fatalf("want *MissingControllerError, got %v", err)
		}
		if mc.Privileged != priv {
			t.Fatalf("Privileged = %v, want %v", mc.Privileged, priv)
		}
		fix := mc.Fix()
		// Both roots keep the controller and the directory: that half was always right.
		if !strings.Contains(fix, "+pids") || !strings.Contains(fix, fs.Root()) {
			t.Fatalf("fix does not name the controller and the root: %q", fix)
		}
		if priv {
			if strings.Contains(fix, "user@.service.d") {
				t.Fatalf("root launcher sent to a user@.service.d drop-in: %q", fix)
			}
			if !strings.Contains(fix, "cgroup.subtree_control") {
				t.Fatalf("root launcher not told the lever that works: %q", fix)
			}
		} else if !strings.Contains(fix, "user@.service.d") {
			t.Fatalf("unprivileged launcher lost the delegation fix: %q", fix)
		}
		if !strings.Contains(mc.Error(), fix) {
			t.Fatalf("Error() must carry Fix(): %q", mc.Error())
		}
	}
}

// TestMissingControllerNamesTheLimitAndAWorkingFix: with tier 1 kept where a controller is missing (doctor's D3
// reports it rather than failing), this refusal is what a run with a limit on that controller meets, so it names
// the contract key, and its fix is one that works. On AlmaLinux 9.8 Delegate=cpu on user@.service made cpu
// available there, but the user manager did not enable it until its app.slice had a CPU weight (Fedora ships
// CPUWeight=100 on the user app.slice). A run with no limit writes no control file and is not refused.
func TestMissingControllerNamesTheLimitAndAWorkingFix(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.Create("a", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := fs.SetLimits(c, Limits{}); err != nil {
		t.Fatalf("a run with no limits needs no controller: %v", err)
	}
	for _, tc := range []struct {
		l          Limits
		controller string
		limit      string
		cpuFix     bool
	}{
		{Limits{CPUMax: "100000 100000"}, "cpu", "limits.cpu", true},
		{Limits{CPUWeight: 50}, "cpu", "limits.cpu_weight", true},
		{Limits{MemoryMax: 1 << 20}, "memory", "limits.memory", false},
		{Limits{MemoryHigh: 1 << 20}, "memory", "limits.memory_high", false},
		{Limits{PidsMax: 64}, "pids", "limits.pids", false},
	} {
		var mc *MissingControllerError
		if err := fs.SetLimits(c, tc.l); !errors.As(err, &mc) {
			t.Fatalf("%s: want *MissingControllerError, got %v", tc.limit, err)
		}
		msg := mc.Error()
		if mc.Controller != tc.controller || mc.Limit != tc.limit ||
			!strings.Contains(msg, "so "+tc.limit+" cannot be applied and the run is refused") {
			t.Errorf("%s: refusal does not name the limit: %s", tc.limit, msg)
		}
		if got := strings.Contains(msg, "CPUWeight=100") && strings.Contains(msg, "/etc/systemd/user/app.slice.d/"); got != tc.cpuFix {
			t.Errorf("%s: CPU weight step in the fix = %v, want %v: %s", tc.limit, got, tc.cpuFix, msg)
		}
		if !strings.Contains(msg, "/etc/systemd/system/user@.service.d/") || !strings.Contains(msg, "reboot") {
			t.Errorf("%s: fix lacks the delegation and the reboot: %s", tc.limit, msg)
		}
	}
}

// TestMissingCPUFixAtTheMountRootSurvivesSystemd: on a systemd host the cgroup2 mount root is the system manager's,
// and on AlmaLinux 9.8 the "+cpu" a root launcher was told to write there was gone after the next daemon-reload, so
// a root run with limits.cpu was refused again. A CPU weight on system.slice kept cpu on across a reboot there, so
// that is the fix for cpu; the direct write stays for a host without systemd, and for the other controllers.
func TestMissingCPUFixAtTheMountRootSurvivesSystemd(t *testing.T) {
	cpu := EnableFix([]string{ControllerCPU}, "/sys/fs/cgroup", true, nil)
	for _, want := range []string{"/etc/systemd/system/system.slice.d/", "CPUWeight=100", "reboot",
		"without systemd: echo '+cpu' > /sys/fs/cgroup/cgroup.subtree_control"} {
		if !strings.Contains(cpu, want) {
			t.Errorf("root's cpu fix lacks %q: %s", want, cpu)
		}
	}
	if strings.Contains(cpu, "user@.service.d") || strings.Contains(cpu, "app.slice") {
		t.Errorf("root's cpu fix names a user manager setting: %s", cpu)
	}
	if pids := EnableFix([]string{ControllerPids}, "/sys/fs/cgroup", true, nil); strings.Contains(pids, "system.slice") ||
		!strings.Contains(pids, "echo '+pids' > /sys/fs/cgroup/cgroup.subtree_control") {
		t.Errorf("root's pids fix: %s", pids)
	}
}

// TestKillNamesWhyItFailed separates ENOENT's two causes. Every supported host has had
// cgroup.kill since 5.14, so a Kill that lands after the scope is gone — which the signal killer's
// copy of the value can do at any moment, and does through Path once Remove has closed the fd —
// must not be reported as a kernel that is too old. Both stay ENOENT for errors.Is.
func TestKillNamesWhyItFailed(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.Create("a", "r-kill")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	// The scope exists and has no cgroup.kill: the kernel floor is the explanation.
	err = fs.Kill(c)
	if !errors.Is(err, unix.ENOENT) {
		t.Fatalf("missing cgroup.kill: %v", err)
	}
	if !strings.Contains(err.Error(), "5.14") {
		t.Fatalf("a scope with no cgroup.kill must still name the kernel floor: %v", err)
	}

	// The scope is gone: the same errno, a different cause.
	gone := Cgroup{Path: c.Path}
	if err := os.RemoveAll(c.Path); err != nil {
		t.Fatal(err)
	}
	err = fs.Kill(gone)
	if !errors.Is(err, unix.ENOENT) {
		t.Fatalf("kill of a removed scope: %v", err)
	}
	if strings.Contains(err.Error(), "5.14") {
		t.Fatalf("a removed scope was blamed on the kernel version: %v", err)
	}
	if !strings.Contains(err.Error(), "no longer exists") {
		t.Fatalf("the refusal must name the missing cgroup: %v", err)
	}
}

// TestSetLimitsWritesAMemoryHighAboveMax is runtime-launch.md E23: the package does no cross-field validation, so a
// memory.high above memory.max is written as given (the kernel accepts it; memory.max's OOM comes first).
func TestSetLimitsWritesAMemoryHighAboveMax(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.Create("a", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	for _, name := range []string{"memory.max", "memory.swap.max", "memory.high"} {
		writeCtl(t, c, name, "")
	}
	if err := fs.SetLimits(c, Limits{MemoryMax: 1 << 20, MemoryHigh: 1 << 22}); err != nil {
		t.Fatalf("SetLimits refused a memory.high above memory.max: %v", err)
	}
	for name, want := range map[string]string{"memory.max": "1048576", "memory.high": "4194304"} {
		if got, err := os.ReadFile(filepath.Join(c.Path, name)); err != nil || string(got) != want {
			t.Errorf("%s = %q, %v; want %q as given", name, got, err, want)
		}
	}
}
