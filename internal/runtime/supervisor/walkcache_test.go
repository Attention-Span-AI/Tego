// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// cacheLoop is a loop over the fake kernel whose walk cache holds /work/out as scanned with the symlink "sl" in
// it, a write entry at /work/out and a deny_read at /work/secrets, under record: full.
func cacheLoop(t *testing.T) (*Loop, *fakeKernel, *testSink) {
	t.Helper()
	f := newFake()
	f.scans = map[string]dirScan{"/work/out": {links: map[string]struct{}{"sl": {}}}}
	pol := testPolicy(nil, []agent.FSRule{
		{Path: "/work/out", Kind: agent.FSWrite, Raw: "./out/"},
		{Path: "/work/secrets", Kind: agent.FSDenyRead, Raw: "./secrets/"},
	}, nil)
	pol.Rules.Record = agent.RecordFull
	pol.Rules.Tier = backend.TierLandlock
	l, sink := newTestLoop(t, f, pol)
	return l, f, sink
}

// walks is how many FSTarget walks the fake kernel was asked for.
func (f *fakeKernel) walks() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.fsQueries)
}

// TestWalkCacheAnswersTheSpellingWithoutAWalk is R15b's fast path: a path whose directory the cache holds lands on
// its spelling there unless its final name is a symlink the syscall follows, and is answered with no walk; the
// directory is scanned once. A followed symlink is walked as before, and its line says where it lands.
func TestWalkCacheAnswersTheSpellingWithoutAWalk(t *testing.T) {
	l, f, sink := cacheLoop(t)
	const addr = 0x10000
	openat := nrFor(t, "openat")
	f.put(addr, cstr("/work/out/a.go"))
	for i := 0; i < 3; i++ {
		l.handle(notifFor(openat, 42, argCWD, addr, 0x241))
	}
	if f.walks() != 0 || f.scanned != 1 {
		t.Fatalf("walks %d, scans %d; want no walk and one scan", f.walks(), f.scanned)
	}
	for _, ev := range sink.all() {
		if ev.Verdict != record.VerdictAllow || ev.Rule != "fs.write[./out/]" {
			t.Fatalf("verdict/rule = %s/%s, want allow under the write entry", ev.Verdict, ev.Rule)
		}
	}

	// A read through the symlink the scan named is walked, and refused where it lands.
	const slAddr = 0x20000
	f.fsTargets["/work/out/sl"] = "/work/secrets/key"
	f.put(slAddr, cstr("/work/out/sl"))
	l.handle(notifFor(openat, 42, argCWD, slAddr, 0))
	if f.walks() != 1 {
		t.Fatalf("walks %d, want the followed symlink walked", f.walks())
	}
	if ev := sink.all()[3]; ev.Verdict != record.VerdictRefused || ev.Rule != "fs.deny_read[./secrets/]" {
		t.Errorf("read through the symlink: %s/%s, want refused under the deny_read", ev.Verdict, ev.Rule)
	}

	// O_NOFOLLOW decides on the link itself: its spelling, no walk.
	l.handle(notifFor(openat, 42, argCWD, slAddr, 0x241|unix.O_NOFOLLOW))
	if f.walks() != 1 {
		t.Errorf("walks %d, want an O_NOFOLLOW open answered from the cache", f.walks())
	}
}

// TestWalkCacheIsInvalidatedByTheRunsMutations holds the cache to the entries the kernel will see: every notified
// rename, unlink, rmdir, symlink or link empties it before it is answered, and a scan made while such a mutation
// may still be about to run is not kept, until the thread's next notification (or its thread) says it ran.
func TestWalkCacheIsInvalidatedByTheRunsMutations(t *testing.T) {
	l, f, _ := cacheLoop(t)
	const addr, addr2 = 0x10000, 0x11000
	openat := nrFor(t, "openat")
	open := func(tid int) { l.handle(notifFor(openat, tid, argCWD, addr, 0x241)) }
	f.put(addr, cstr("/work/out/a.go"))
	f.put(addr2, cstr("/work/out/b.go"))
	open(42)
	if f.scanned != 1 {
		t.Fatalf("scans %d, want 1", f.scanned)
	}

	// Thread 43 renames: the cache is emptied, and nothing is kept while the rename may be in flight.
	l.handle(notifFor(nrFor(t, "renameat"), 43, argCWD, addr, argCWD, addr2))
	n := f.scanned
	open(42)
	open(42)
	if f.scanned != n+2 {
		t.Fatalf("scans %d, want both opens rescanned while thread 43's rename is pending", f.scanned-n)
	}

	// Thread 43's next notification says the rename ran: the next scan is kept.
	n = f.scanned
	open(43)
	open(42)
	if f.scanned != n+1 {
		t.Fatalf("scans %d, want one scan kept once the rename ran", f.scanned-n)
	}

	// A thread gone after its mutation, or asleep in another syscall, is reaped once it has been pending a while.
	var asked int
	l.mayRun = func(int, int32) bool { asked++; return false }
	l.handle(notifFor(nrFor(t, "symlinkat"), 44, addr2, argCWD, addr))
	open(42)
	if asked != 0 {
		t.Fatalf("a fresh pending mutation was looked up (%d)", asked)
	}
	l.walks.mu.Lock()
	m := l.walks.pending[44]
	m.since = m.since.Add(-time.Second)
	l.walks.pending[44] = m
	l.walks.mu.Unlock()
	n = f.scanned
	open(42) // reaps thread 44 and keeps nothing: its scan raced with the mutation
	open(42) // scans and keeps
	open(42)
	if asked != 1 || f.scanned != n+2 {
		t.Errorf("asked %d, scans %d after reaping; want one lookup, then one scan kept", asked, f.scanned-n)
	}
}

// TestWalkCacheReapIsRateLimitedAndUnlocked: a thread that stays busy in userspace after its mutation stays
// pending, and every miss meanwhile reached reap. Its thread is looked up at most once per pendingCheck, not on
// every miss, and the /proc reads are made without the lock every notification takes.
func TestWalkCacheReapIsRateLimitedAndUnlocked(t *testing.T) {
	var c walkCache
	c.saw(44, 82, true)
	c.mu.Lock()
	m := c.pending[44]
	m.since = m.since.Add(-time.Second)
	c.pending[44] = m
	gen := c.gen
	c.mu.Unlock()
	asked, locked := 0, 0
	mayRun := func(int, int32) bool {
		asked++
		if !c.mu.TryLock() {
			locked++
		} else {
			c.mu.Unlock()
		}
		return true // running in userspace: still pending
	}
	t0 := time.Now()
	for i := 0; i < 15; i++ {
		c.keep("/work/out", gen, t0.Add(time.Duration(i)*time.Millisecond), dirScan{}, mayRun)
	}
	if asked != 1 {
		t.Fatalf("thread looked up %d times within pendingCheck, want once", asked)
	}
	c.keep("/work/out", gen, t0.Add(pendingCheck+time.Millisecond), dirScan{}, mayRun)
	if asked != 2 {
		t.Errorf("thread looked up %d times after pendingCheck, want twice", asked)
	}
	if locked != 0 {
		t.Fatalf("%d lookups ran with the cache's lock held", locked)
	}
	if len(c.dirs) != 0 {
		t.Error("a scan was kept while a mutation was pending")
	}

	// A thread that has run its mutation is reaped, unless a notification of its thread replaced the entry
	// while its /proc reads ran without the lock.
	c.keep("/work/out", gen, t0.Add(3*pendingCheck), dirScan{}, func(int, int32) bool {
		c.saw(44, 82, true) // the thread's next rename, notified meanwhile
		return false
	})
	c.mu.Lock()
	_, still := c.pending[44]
	c.mu.Unlock()
	if !still {
		t.Error("the replacing mutation was reaped by a lookup made for the one before it")
	}
}

// TestWalkCacheBigDirectoryStatsTheFinalName: a directory too large to read whole is kept without its symlinks,
// so an open that follows its final name asks the kernel for that name alone (a symlink goes to the walk), and
// one that does not asks nothing.
func TestWalkCacheBigDirectoryStatsTheFinalName(t *testing.T) {
	l, f, _ := cacheLoop(t)
	f.scans["/work/out"] = dirScan{big: true}
	f.finalLinks = map[string]bool{"/work/out/sl": true}
	for _, tc := range []struct {
		q     pathQuery
		ok    bool
		stats int
	}{
		{pathQuery{path: "/work/out/a.go", joined: "/work/out/a.go"}, true, 1},
		{pathQuery{path: "/work/out/sl", joined: "/work/out/sl"}, false, 2},
		{pathQuery{path: "/work/out/sl", joined: "/work/out/sl", nofollow: true}, true, 2},
	} {
		if _, ok := l.cachedTarget(tc.q); ok != tc.ok || f.finalStats != tc.stats {
			t.Errorf("%+v: answered %v after %d stats; want %v, %d", tc.q, ok, f.finalStats, tc.ok, tc.stats)
		}
	}
	if f.scanned != 1 {
		t.Errorf("scans %d, want the big directory kept", f.scanned)
	}
}

// TestWalkCacheExpires bounds what a change made outside the run, which no notification reports, can go unseen
// for: a kept directory is scanned again after walkCacheTTL.
func TestWalkCacheExpires(t *testing.T) {
	l, f, _ := cacheLoop(t)
	const addr = 0x10000
	f.put(addr, cstr("/work/out/a.go"))
	openat := nrFor(t, "openat")
	l.handle(notifFor(openat, 42, argCWD, addr, 0x241))
	l.walks.mu.Lock()
	d := l.walks.dirs["/work/out"]
	d.at = d.at.Add(-walkCacheTTL)
	l.walks.dirs["/work/out"] = d
	l.walks.mu.Unlock()
	l.handle(notifFor(openat, 42, argCWD, addr, 0x241))
	if f.scanned != 2 {
		t.Errorf("scans %d, want the expired directory scanned again", f.scanned)
	}
}

// TestWalkCacheKeepsOutShapesItCannotSay sends to the walk every query whose spelling cannot say where it lands:
// a ".." component, a trailing slash, a descriptor's own file.
func TestWalkCacheKeepsOutShapesItCannotSay(t *testing.T) {
	l, f, _ := cacheLoop(t)
	for _, q := range []pathQuery{
		{path: "/work/out/x/../a.go", joined: "/work/out/a.go"},
		{path: "/work/out/a.go/", joined: "/work/out/a.go"},
		{path: "a.go", joined: "/work/out/a.go", empty: true},
		{path: "", joined: "/work/out/a.go"},
	} {
		if _, ok := l.cachedTarget(q); ok {
			t.Errorf("%+v was answered from the cache", q)
		}
	}
	if f.scanned != 0 {
		t.Errorf("scans %d, want none", f.scanned)
	}
}

// TestScanDirOnTheRealKernel is Kernel.ScanDir: the symlinks of a directory reached with no symlink on the way,
// and a refusal for a directory reached through one and for procfs.
func TestScanDirOnTheRealKernel(t *testing.T) {
	dir := realDir(t, t.TempDir())
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"l1", "l2"} {
		if err := os.Symlink("d", filepath.Join(dir, l)); err != nil {
			t.Fatal(err)
		}
	}
	s, err := sysKernel{}.ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.links) != 2 {
		t.Errorf("links = %v, want l1 and l2", s.links)
	}
	if _, err := (sysKernel{}).ScanDir(filepath.Join(dir, "l1")); err == nil {
		t.Error("a directory reached through a symlink was scanned")
	}
	if _, err := (sysKernel{}).ScanDir("/proc/self/fd"); err == nil {
		t.Error("procfs was scanned")
	}
	for i := 0; i < scanDirMax; i++ {
		if err := os.WriteFile(filepath.Join(dir, "d", "f"+strconv.Itoa(i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if s, err := (sysKernel{}).ScanDir(filepath.Join(dir, "d")); err != nil || !s.big {
		t.Errorf("a directory of %d entries: %+v, %v; want big", scanDirMax+2, s, err)
	}
	if link, err := (sysKernel{}).FinalIsLink(filepath.Join(dir, "l1")); err != nil || !link {
		t.Errorf("FinalIsLink(l1) = %v, %v", link, err)
	}
	if link, err := (sysKernel{}).FinalIsLink(filepath.Join(dir, "none")); err != nil || link {
		t.Errorf("FinalIsLink(none) = %v, %v", link, err)
	}
	// FinalIsDir does not follow the final name, as a rename moves a symlink itself (decideMoveDest's REFER).
	for name, want := range map[string]bool{"d": true, "l1": false, "d/f0": false, "none": false} {
		if got, err := (sysKernel{}).FinalIsDir(filepath.Join(dir, name)); err != nil || got != want {
			t.Errorf("FinalIsDir(%s) = %v, %v; want %v", name, got, err, want)
		}
	}
}

// TestMutationMayRun reads /proc for a pending mutation's thread: one asleep in the syscall it was notified for may
// still run it, one asleep in another syscall has left it behind, and one that does not exist may not run it.
//
// The thread asked about is not the one asking. A thread that reads its own /proc/<tid>/syscall is answered with
// that read(2) (task_current_syscall reports the current task's syscall as it runs), and read's number is the
// architecture's: 0 on x86-64, which is why asking about this goroutine's own thread with nr 0 once passed there,
// and 63 on arm64, where the same question read as a thread gone to another syscall. The supervisor only ever asks
// about the run's threads, never its own.
func TestMutationMayRun(t *testing.T) {
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	tids := make(chan int, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread() // left locked: the thread ends with the goroutine
		tids <- unix.Gettid()
		var b [1]byte
		_, _ = unix.Read(p[0], b[:]) // asleep in read(2) on an empty pipe until its write end closes
	}()
	tid := <-tids
	defer func() {
		_ = unix.Close(p[1])
		<-done
		_ = unix.Close(p[0])
	}()
	// The thread is in other syscalls on its way (the channel send's futex): wait for it to sleep in the read.
	for deadline := time.Now().Add(10 * time.Second); syscallOf(t, tid) != unix.SYS_READ; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("thread %d did not sleep in read(2) within 10s", tid)
		}
	}
	if !mutationMayRun(tid, unix.SYS_READ) {
		t.Error("a thread asleep in the notified syscall was taken as done")
	}
	if mutationMayRun(tid, unix.SYS_UNLINKAT) {
		t.Error("a thread asleep in another syscall may still run the notified one")
	}
	if mutationMayRun(1<<30, unix.SYS_UNLINKAT) {
		t.Error("a thread that does not exist may still run")
	}
}

// syscallOf is the syscall number /proc/<tid>/syscall names for a blocked thread, or -1 for one it names none for
// (a running thread, one blocked outside a syscall).
func syscallOf(t *testing.T, tid int) int {
	t.Helper()
	b, err := os.ReadFile("/proc/" + strconv.Itoa(tid) + "/syscall")
	if err != nil {
		t.Fatal(err)
	}
	f, _, _ := strings.Cut(strings.TrimSpace(string(b)), " ")
	n, err := strconv.Atoi(f)
	if err != nil {
		return -1
	}
	return n
}

// TestWalkCacheSeesASymlinkTheRunPlants runs the cache over the real kernel's scans and walks: a file read once
// (its directory kept), then replaced by the run with a symlink into a deny_read — an unlink and a symlink, both
// notified — is read again through the symlink, and the line says refused where it lands, not the kept answer.
func TestWalkCacheSeesASymlinkTheRunPlants(t *testing.T) {
	root := realDir(t, t.TempDir())
	out, secrets := filepath.Join(root, "out"), filepath.Join(root, "secrets")
	for _, d := range []string{out, secrets} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	file, key := filepath.Join(out, "x"), filepath.Join(secrets, "key")
	for _, p := range []string{file, key} {
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f := newFake()
	f.realWalks = true
	pol := testPolicy(nil, []agent.FSRule{
		{Path: out, Kind: agent.FSWrite, Raw: "./out/"},
		{Path: secrets, Kind: agent.FSDenyRead, Raw: "./secrets/"},
	}, nil)
	pol.Rules.Record = agent.RecordFull
	pol.Rules.Tier = backend.TierLandlock
	l, sink := newTestLoop(t, f, pol)
	const addr, targetAddr = 0x10000, 0x20000
	f.put(addr, cstr(file))
	f.put(targetAddr, cstr(key))
	read := func() *record.Event {
		l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, addr, 0))
		all := sink.all()
		return all[len(all)-1]
	}
	if ev := read(); ev.Verdict != record.VerdictAllow {
		t.Fatalf("first read: %s/%s, want allow", ev.Verdict, ev.Rule)
	}
	if _, _, ok := l.walks.lookup(out, time.Now()); !ok {
		t.Fatal("the directory was not kept")
	}
	// The run replaces x with a symlink: each syscall is notified, then run by the kernel.
	l.handle(notifFor(nrFor(t, "unlinkat"), 42, argCWD, addr, 0))
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	l.handle(notifFor(nrFor(t, "symlinkat"), 42, targetAddr, argCWD, addr))
	if err := os.Symlink(key, file); err != nil {
		t.Fatal(err)
	}
	if ev := read(); ev.Verdict != record.VerdictRefused || ev.Rule != "fs.deny_read[./secrets/]" {
		t.Errorf("read through the planted symlink: %s/%s, want refused under the deny_read", ev.Verdict, ev.Rule)
	}
}

// TestWalkCacheIsOffWhenThePlaneTakesMutations: a run whose filter no longer notifies the fs mutations the decision
// plane decides (Options.PlaneFS, TIER3-PLAN T16) keeps no directory, since nothing would invalidate it: every
// notified path is walked, as the kernel will resolve it.
func TestWalkCacheIsOffWhenThePlaneTakesMutations(t *testing.T) {
	f := newFake()
	f.scans = map[string]dirScan{"/work/out": {}}
	pol := testPolicy(nil, []agent.FSRule{{Path: "/work/out", Kind: agent.FSWrite, Raw: "./out/"}}, nil)
	pol.Rules.Record = agent.RecordFull
	pol.Rules.Tier = backend.TierLandlock
	l, err := New(testListener(), pol, &testSink{}, Options{kernel: f, Workers: 1, PlaneFS: true})
	if err != nil {
		t.Fatal(err)
	}
	const addr = 0x10000
	openat := nrFor(t, "openat")
	f.put(addr, cstr("/work/out/a.go"))
	for i := 0; i < 3; i++ {
		l.handle(notifFor(openat, 42, argCWD, addr, 0x241))
	}
	if f.walks() != 3 || f.scanned != 0 {
		t.Fatalf("walks %d, scans %d; want every open walked and no scan", f.walks(), f.scanned)
	}
}
