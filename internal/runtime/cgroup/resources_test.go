// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"os"
	"path/filepath"
	"testing"
)

// scope writes the named control files into a fresh directory and returns a Cgroup over it with no fd, so
// ReadResources resolves by path exactly as it does once a real scope's fd is closed.
func scope(t *testing.T, files map[string]string) Cgroup {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return Cgroup{Path: dir}
}

func valueOf(p *uint64) any {
	if p == nil {
		return nil
	}
	return *p
}

// TestReadResourcesTakesWhatTheKernelWrote pins run_end's resource line to the files a 6.17 cgroup with the
// cpu, memory and pids controllers has (record-ledger.md run_end.resources). Before, nothing read a peak or a
// usage file at all, so a run said nothing about what it used.
func TestReadResourcesTakesWhatTheKernelWrote(t *testing.T) {
	t.Parallel()
	c := scope(t, map[string]string{
		"memory.peak":   "73138176\n",
		"pids.peak":     "23\n",
		"cpu.stat":      "usage_usec 51234\nuser_usec 40000\nsystem_usec 11234\nnr_periods 9\nnr_throttled 2\nthrottled_usec 4100\nnr_bursts 0\nburst_usec 0\n",
		"memory.events": "low 0\nhigh 5\nmax 1\noom 0\noom_kill 0\noom_group_kill 0\n",
	})
	r, err := ReadResources(c)
	if err != nil {
		t.Fatalf("ReadResources: %v", err)
	}
	want := map[string]any{
		"memory.peak": uint64(73138176), "pids.peak": uint64(23), "usage_usec": uint64(51234),
		"user_usec": uint64(40000), "system_usec": uint64(11234), "nr_throttled": uint64(2),
		"throttled_usec": uint64(4100), "high": uint64(5), "max": uint64(1), "oom": uint64(0), "oom_kill": uint64(0),
	}
	got := map[string]any{
		"memory.peak": valueOf(r.MemoryPeak), "pids.peak": valueOf(r.PidsPeak), "usage_usec": valueOf(r.CPUUsageUsec),
		"user_usec": valueOf(r.CPUUserUsec), "system_usec": valueOf(r.CPUSystemUsec),
		"nr_throttled": valueOf(r.CPUNrThrottled), "throttled_usec": valueOf(r.CPUThrottledUsec),
		"high": valueOf(r.MemoryHigh), "max": valueOf(r.MemoryMax), "oom": valueOf(r.MemoryOOM),
		"oom_kill": valueOf(r.MemoryOOMKill),
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %v, want %v", k, got[k], w)
		}
	}
}

// TestReadResourcesLeavesTheUnknownAbsent is docs/VERSIONING.md §2 for these fields: a file the kernel does
// not have (memory.peak before 5.19, pids.peak before it arrived, a controller not delegated) or a key a file
// does not carry (cpu.stat's throttling keys without the cpu controller) is absent, never a zero a reader would
// take for "used nothing". A file that exists and cannot be read is an error, beside what could be read.
func TestReadResourcesLeavesTheUnknownAbsent(t *testing.T) {
	t.Parallel()
	c := scope(t, map[string]string{"cpu.stat": "usage_usec 10\nuser_usec 6\nsystem_usec 4\n"})
	r, err := ReadResources(c)
	if err != nil {
		t.Fatalf("missing files are not an error: %v", err)
	}
	if r.MemoryPeak != nil || r.PidsPeak != nil || r.CPUNrThrottled != nil || r.CPUThrottledUsec != nil ||
		r.MemoryHigh != nil || r.MemoryOOMKill != nil {
		t.Fatalf("absent files or keys read as values: %+v", r)
	}
	if valueOf(r.CPUUsageUsec) != uint64(10) || r.Empty() {
		t.Fatalf("cpu.stat's usage was not read: %+v", r)
	}
	if none, err := ReadResources(scope(t, nil)); err != nil || !none.Empty() {
		t.Fatalf("a directory with no control files: %+v, %v; want nothing and no error", none, err)
	}

	bad := scope(t, map[string]string{"memory.peak": "max\n", "pids.peak": "7\n"})
	if err := os.Mkdir(filepath.Join(bad.Path, "cpu.stat"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err = ReadResources(bad)
	if err == nil {
		t.Fatal("a malformed memory.peak and an unreadable cpu.stat were not reported")
	}
	if r.MemoryPeak != nil || r.CPUUsageUsec != nil || valueOf(r.PidsPeak) != uint64(7) {
		t.Fatalf("after two bad files: %+v; want only pids.peak", r)
	}

	// A key the kernel wrote with a value that is not a count is reported, not passed off as a kernel without
	// that counter; the file's other keys are still read.
	keyed := scope(t, map[string]string{
		"cpu.stat":      "usage_usec 12\nuser_usec x\nsystem_usec 5\n",
		"memory.events": "high 1\nmax 2\noom -1\noom_kill 0\n",
	})
	r, err = ReadResources(keyed)
	if err == nil {
		t.Fatal("a malformed cpu.stat user_usec and memory.events oom were not reported")
	}
	if r.CPUUserUsec != nil || r.MemoryOOM != nil {
		t.Fatalf("a malformed value was read as a count: %+v", r)
	}
	if valueOf(r.CPUUsageUsec) != uint64(12) || valueOf(r.CPUSystemUsec) != uint64(5) ||
		valueOf(r.MemoryMax) != uint64(2) || valueOf(r.MemoryOOMKill) != uint64(0) {
		t.Fatalf("the well-formed keys beside a malformed one were not read: %+v", r)
	}
}
