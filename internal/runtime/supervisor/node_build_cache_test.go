// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNodeBuildCacheRewrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "node")
	if err := os.WriteFile(p, []byte("AAAA"), 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(p, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd) //nolint:errcheck // test owns the fd
	stat := func() unix.Stat_t {
		t.Helper()
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	before := stat()
	var c nodeBuildCache
	calls := 0
	read := func(st unix.Stat_t) [sha256.Size]byte {
		t.Helper()
		sum, ok := c.get(nodeKey(st), func() ([sha256.Size]byte, bool) {
			calls++
			return hashNodeBuild(fd, st)
		})
		if !ok {
			t.Fatal("stable file did not hash")
		}
		return sum
	}
	wantBefore := sha256.Sum256([]byte("AAAA"))
	for range 2 {
		if read(before) != wantBefore {
			t.Fatal("wrong executable digest")
		}
	}
	if calls != 1 {
		t.Fatal("unchanged executable did not reuse its digest")
	}
	// The guest's tmpfs timestamps can use the coarse kernel clock. Cross a
	// clock tick so this fixture really changes ctime, as the assertion checks.
	time.Sleep(20 * time.Millisecond)
	if n, err := unix.Pwrite(fd, []byte("BBBB"), 0); err != nil || n != 4 {
		t.Fatalf("rewrite: %d, %v", n, err)
	}
	// The attacker can restore mtime, but cannot restore ctime.
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, p, []unix.Timespec{before.Atim, before.Mtim}, 0); err != nil {
		t.Fatal(err)
	}
	after := stat()
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim == after.Ctim {
		t.Fatal("fixture must change only ctime among the cache key fields")
	}
	if read(after) != sha256.Sum256([]byte("BBBB")) || calls != 2 {
		t.Fatal("ctime-only rewrite reused the old executable digest")
	}
	if nodeBuildUnchanged(fd, before) || c.version(fd, before) != "" {
		t.Fatal("old observation remained valid after a rewrite")
	}
}

func TestNodeBuildCacheKeys(t *testing.T) {
	base := unix.Stat_t{Dev: 1, Ino: 2, Size: 3, Mtim: unix.Timespec{Sec: 4, Nsec: 5}, Ctim: unix.Timespec{Sec: 6, Nsec: 7}}
	for name, change := range map[string]func(*unix.Stat_t){
		"dev": func(s *unix.Stat_t) { s.Dev++ }, "ino": func(s *unix.Stat_t) { s.Ino++ },
		"size": func(s *unix.Stat_t) { s.Size++ }, "mtime-sec": func(s *unix.Stat_t) { s.Mtim.Sec++ },
		"mtime-nsec": func(s *unix.Stat_t) { s.Mtim.Nsec++ }, "ctime-sec": func(s *unix.Stat_t) { s.Ctim.Sec++ },
		"ctime-nsec": func(s *unix.Stat_t) { s.Ctim.Nsec++ },
	} {
		t.Run(name, func(t *testing.T) {
			other := base
			change(&other)
			if nodeKey(base) == nodeKey(other) {
				t.Fatal("cache key lost a required field")
			}
		})
	}
}

// Seed an inventoried digest to isolate a hit's revalidation from hashing. A
// stale caller must lose even a successful pin, not merely an unknown digest.
func TestNodeBuildCacheHitRevalidates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "node")
	if err := os.WriteFile(p, []byte("AAAA"), 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(p, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd) //nolint:errcheck // test owns the fd
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString("92181daccf61361e7c54d6404a3e2c2307a916d076492e3c0b388e6e5f86a854")
	if err != nil {
		t.Fatal(err)
	}
	var sum [sha256.Size]byte
	copy(sum[:], b)
	var c nodeBuildCache
	_, _ = c.get(nodeKey(before), func() ([sha256.Size]byte, bool) { return sum, true })
	if got := c.version(fd, before); got != "22.21.1" {
		t.Fatalf("seeded known digest: %q", got)
	}
	time.Sleep(20 * time.Millisecond) // cross the guest's coarse timestamp tick
	if n, err := unix.Pwrite(fd, []byte("BBBB"), 0); err != nil || n != 4 {
		t.Fatalf("rewrite: %d, %v", n, err)
	}
	if got := c.version(fd, before); got != "" {
		t.Fatalf("cache hit vouched for a stale fd observation: %q", got)
	}
	// A failed fstat must not turn a cached result into an attestation either.
	if got := c.version(-1, before); got != "" {
		t.Fatalf("cache hit vouched for an unreadable fd: %q", got)
	}
}

func TestNodeBuildCacheConcurrentAndBounded(t *testing.T) {
	var c nodeBuildCache
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	key := nodeBuildKey{id: fileID{1, 2}, size: 3}
	want := sha256.Sum256([]byte("digest miss is cached too"))
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			sum, ok := c.get(key, func() ([sha256.Size]byte, bool) {
				if calls.Add(1) == 1 {
					close(started)
				}
				<-release
				return want, true
			})
			if !ok || sum != want {
				t.Error("concurrent caller lost digest")
			}
		})
	}
	<-started
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("four concurrent execs hashed %d times", calls.Load())
	}
	for i := range maxNodeBuilds + 1 {
		k := key
		k.id.ino = uint64(i + 10)
		_, _ = c.get(k, func() ([sha256.Size]byte, bool) { return want, true })
	}
	if len(c.entries) != maxNodeBuilds || len(c.order) != maxNodeBuilds || c.entries[key] != nil {
		t.Fatal("executable churn escaped the cache bound or FIFO eviction")
	}
	bad := nodeBuildKey{}
	for range 2 {
		_, ok := c.get(bad, func() ([sha256.Size]byte, bool) { calls.Add(1); return want, false })
		if ok || c.entries[bad] != nil {
			t.Fatal("failed/unstable hash was retained")
		}
	}
	if calls.Load() != 3 {
		t.Fatal("failed hash was reused")
	}
}

func TestNodeBuildNoRulesDoesNotHash(t *testing.T) {
	p := filepath.Join(t.TempDir(), "node")
	if err := os.WriteFile(p, []byte("\x7fELF unpinned"), 0o700); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		t.Fatal(err)
	}
	q := pathQuery{tid: os.Getpid(), dirfd: atFDCWD, path: p}
	img, err := (sysKernel{}).ExecImage(q)
	if err != nil || len(img.head) != 0 || img.nodeVersion != "" {
		t.Fatalf("no command rules: %+v, %v", img, err)
	}
	contains := func() bool {
		nodeBuilds.mu.Lock()
		defer nodeBuilds.mu.Unlock()
		return nodeBuilds.entries[nodeKey(st)] != nil
	}
	if contains() {
		t.Fatal("no-rule exec hashed Node")
	}
	q.head = true
	if _, err := (sysKernel{}).ExecImage(q); err != nil || !contains() {
		t.Fatalf("command-rule exec did not attest Node: %v", err)
	}
}
