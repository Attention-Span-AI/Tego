// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// appliedScope is a scope on a temp directory whose control files exist, as cgroupfs has them.
func appliedScope(t *testing.T, files ...string) (*cgroup.FS, cgroup.Cgroup) {
	t.Helper()
	fs, err := cgroup.NewAt(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := fs.Create("a", "r-00000000-000000000000a-launch")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(c.Path, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		// The slices above the scope hold the same files, at no ceiling, as cgroupfs has them (GAPS N85); the root of the
		// tree, like the cgroup2 root, holds none.
		unlimited := map[string]string{"cpu.max": "max 100000", "memory.max": "max", "memory.high": "max", "pids.max": "max"}[f]
		if unlimited == "" {
			continue
		}
		for dir := filepath.Dir(c.Path); dir != fs.Root(); dir = filepath.Dir(dir) {
			if err := os.WriteFile(filepath.Join(dir, f), []byte(unlimited+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return fs, c
}

// TestLaunchRecordsTheLimitsItsScopeHolds (GAPS C221): a launch's run_start says which kernel limits held, read back from
// the scope after they were written, and not only the contract's words for them. A request that the kernel
// rounded to a page reads as the kernel holds it. A52 did this for a boundary adoption's cpu, cpu_weight and pids as
// written; a launch had nothing, and memory is new for both.
func TestLaunchRecordsTheLimitsItsScopeHolds(t *testing.T) {
	fs, c := appliedScope(t, "cpu.max", "cpu.weight", "memory.max", "memory.high", "pids.max")
	l := cgroup.Limits{CPUMax: "200000 100000", CPUWeight: 50, MemoryMax: 1_000_000, PidsMax: 64}
	if err := fs.SetLimits(c, l); err != nil {
		t.Fatal(err)
	}
	// The kernel stores memory.max in pages.
	if err := os.WriteFile(filepath.Join(c.Path, "memory.max"), []byte("999424\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &runner{log: slog.New(slog.DiscardHandler), cgm: fs}
	got := r.readAppliedLimits(c, l)
	n64, w, p := int64(999424), 50, 64
	want := &record.AppliedLimits{CPUMax: "200000 100000", CPUWeight: &w, PidsMax: &p, MemoryMax: &n64}
	if got == nil || got.CPUMax != want.CPUMax || *got.CPUWeight != w || *got.PidsMax != p || got.MemoryMax == nil ||
		*got.MemoryMax != n64 || got.MemoryHigh != nil {
		t.Fatalf("applied_limits = %+v, want %+v", got, want)
	}

	line := runStartLineWith(t, Deps{Labels: map[string]string{}, Environ: []string{}}, func(r *runner) { r.applied = got })
	e, err := record.Decode([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	var p0 record.RunStartPayload
	if err := e.DecodePayload(&p0); err != nil {
		t.Fatal(err)
	}
	if p0.RecordMinor != record.MinorEveryLaunch || p0.AppliedLimits == nil || p0.AppliedLimits.MemoryMax == nil || *p0.AppliedLimits.MemoryMax != n64 ||
		p0.AppliedLimits.CPUMax != "200000 100000" {
		t.Fatalf("run_start applied_limits = %+v at revision %d", p0.AppliedLimits, p0.RecordMinor)
	}

	// A run that wrote no limit has no block.
	if line := runStartLine(t, Deps{Labels: map[string]string{}, Environ: []string{}}); strings.Contains(line, "applied_limits") {
		t.Errorf("a run with no limit wrote applied_limits: %s", line)
	}
}

// TestLaunchLeavesOutALimitItCannotRecord: a limit the kernel holds as max is none, a file that cannot be read is left
// out (the log says so), and a value the record cannot hold never fails the run's start.
func TestLaunchLeavesOutALimitItCannotRecord(t *testing.T) {
	fs, c := appliedScope(t, "cpu.max", "memory.max") // pids.max is missing: unreadable
	l := cgroup.Limits{CPUMax: "max 100000", MemoryMax: 4096, PidsMax: 8}
	_ = fs.SetLimits(c, cgroup.Limits{CPUMax: "max 100000", MemoryMax: 4096})
	r := &runner{log: slog.New(slog.DiscardHandler), cgm: fs}
	got := r.readAppliedLimits(c, l)
	if got == nil || got.CPUMax != "max 100000" || got.MemoryMax == nil || *got.MemoryMax != 4096 || got.PidsMax != nil {
		t.Fatalf("applied_limits = %+v, want cpu.max and memory.max, no pids", got)
	}
	if err := os.WriteFile(filepath.Join(c.Path, "cpu.max"), []byte("garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := r.readAppliedLimits(c, l); got != nil {
		t.Errorf("a cpu.max the record cannot hold was kept: %+v", got)
	}
	if got := appliedRecord(cgroup.Applied{WrotePidsMax: true, PidsMax: -1, WroteMemoryMax: true, MemoryMax: -1}); got != nil {
		t.Errorf("limits the kernel holds as max were recorded: %+v", got)
	}
}
