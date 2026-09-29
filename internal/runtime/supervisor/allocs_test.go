// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// parseSockaddr and nearestFS run on every notified connect and every notified path syscall of the run, and
// BenchmarkParseSockaddr and BenchmarkNearestFS show both allocating nothing. These tests hold them there, with
// each benchmark's own input: an allocation on either path is garbage per syscall the agent makes, which the
// benchmarks would only report and CI's bench gate only compares against the parent commit.

// TestParseSockaddrAllocatesNothing is BenchmarkParseSockaddr's parse.
func TestParseSockaddrAllocatesNothing(t *testing.T) {
	sa := sockaddrIn4("93.184.216.34", 443)
	if d := parseSockaddr(sa); !d.ok {
		t.Fatal("parse failed")
	}
	if n := testing.AllocsPerRun(100, func() { parseSockaddr(sa) }); n != 0 {
		t.Errorf("parseSockaddr makes %v allocations, want 0", n)
	}
}

// TestNearestFSAllocatesNothing is BenchmarkNearestFS's lookup.
func TestNearestFSAllocatesNothing(t *testing.T) {
	c := compile(testPolicy(nil, []agent.FSRule{
		{Path: "/work/proj", Kind: agent.FSWrite},
		{Path: "/work/proj/secrets", Kind: agent.FSDenyRead},
		{Path: "/home/u/.cache", Kind: agent.FSWrite},
	}, nil))
	const path = "/work/proj/src/main.go"
	if c.nearestFS(path) == nil {
		t.Fatal("no match")
	}
	if n := testing.AllocsPerRun(100, func() { c.nearestFS(path) }); n != 0 {
		t.Errorf("nearestFS makes %v allocations, want 0", n)
	}
}

// TestPathReadAllocatesOnce: a pathname read runs on every notified open, unlink, rename and exec. One whose NUL
// lies in the first page it reads is copied out of the reader's scratch buffer once, into the string; it was
// appended to a slice first, a second allocation per syscall. A clean absolute path joins to itself.
func TestPathReadAllocatesOnce(t *testing.T) {
	f := newFake()
	const addr = 0x1000
	f.put(addr, cstr("/work/proj/src/main.go"))
	r, _, _ := testReader(t, f)
	if s, cut := r.cstring(addr, pathMax); s != "/work/proj/src/main.go" || cut {
		t.Fatalf("cstring = %q, %v", s, cut)
	}
	if n := testing.AllocsPerRun(100, func() { r.cstring(addr, pathMax) }); n != 1 {
		t.Errorf("cstring makes %v allocations, want 1", n)
	}
	if n := testing.AllocsPerRun(100, func() { r.pathRaw(unix.AT_FDCWD, addr) }); n != 1 {
		t.Errorf("pathRaw makes %v allocations, want 1", n)
	}
}

// TestScanDirMakesNoGarbageBuffer: a scan runs on every walk-cache miss, and every notified mutation empties the
// cache, so during an install most fs notifications scan. Its 32 KiB getdents buffer does not escape and stays on
// the stack; a change that moved it to the heap (a larger size, or passing it somewhere it escapes) would be
// 32 KiB of garbage per scan, and fails this.
func TestScanDirMakesNoGarbageBuffer(t *testing.T) {
	dir := realDir(t, t.TempDir())
	if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("f", filepath.Join(dir, "l")); err != nil {
		t.Fatal(err)
	}
	scan := func() {
		if s, err := (sysKernel{}).ScanDir(dir); err != nil || len(s.links) != 1 {
			t.Fatalf("ScanDir = %+v, %v", s, err)
		}
	}
	scan()
	const n = 200
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < n; i++ {
		scan()
	}
	runtime.ReadMemStats(&after)
	if per := (after.TotalAlloc - before.TotalAlloc) / n; per > 4<<10 {
		t.Errorf("ScanDir allocates %d bytes a scan, want at most 4 KiB", per)
	}
}
