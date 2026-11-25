// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ceiling writes one control file of an ancestor cgroup directory.
func ceiling(t *testing.T, dir, file, value string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(value+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestLaunchRecordsTheCeilingAnAncestorHolds: a run placed under a cgroup with a lower memory, pids or cpu
// ceiling than the one the launcher wrote is held to the lower one by the kernel, so run_start.applied_limits says the
// lower one and not only the scope's own file. The ceilings come from the whole chain up to the manager's root.
func TestLaunchRecordsTheCeilingAnAncestorHolds(t *testing.T) {
	fs, c := appliedScope(t, "cpu.max", "cpu.weight", "memory.max", "pids.max")
	l := cgroup.Limits{CPUMax: "200000 100000", CPUWeight: 50, MemoryMax: 1_000_000, PidsMax: 64}
	if err := fs.SetLimits(c, l); err != nil {
		t.Fatal(err)
	}
	slice := filepath.Dir(c.Path)
	top := filepath.Dir(slice)
	ceiling(t, slice, "pids.max", "max")
	ceiling(t, slice, "memory.max", "max")
	ceiling(t, top, "pids.max", "32")          // two levels up: the lowest
	ceiling(t, top, "memory.max", "500000")    // lower than the scope's 1 MB
	ceiling(t, top, "cpu.max", "50000 100000") // half a core against the scope's two
	ceiling(t, fs.Root(), "memory.max", "9000000")

	r := &runner{log: slog.New(slog.DiscardHandler), cgm: fs}
	got := r.readAppliedLimits(c, l)
	if got == nil || got.PidsMax == nil || *got.PidsMax != 32 || got.MemoryMax == nil || *got.MemoryMax != 500000 ||
		got.CPUMax != "50000 100000" || got.CPUWeight == nil || *got.CPUWeight != 50 || got.MemoryHigh != nil {
		t.Fatalf("applied_limits = %+v, want pids 32, memory 500000, cpu 50000 100000 (the ancestors' ceilings), weight 50", got)
	}
}

// TestLaunchSaysWhenAnAncestorCannotBeRead: a ceiling the launcher cannot read is not guessed. The member it
// would have bounded is left out of the record, and the log says which ancestor file and why.
func TestLaunchSaysWhenAnAncestorCannotBeRead(t *testing.T) {
	fs, c := appliedScope(t, "memory.max", "pids.max")
	l := cgroup.Limits{MemoryMax: 1_000_000, PidsMax: 64}
	if err := fs.SetLimits(c, l); err != nil {
		t.Fatal(err)
	}
	top := filepath.Dir(filepath.Dir(c.Path))
	ceiling(t, top, "pids.max", "not-a-number")
	ceiling(t, top, "memory.max", "max")
	var logbuf bytes.Buffer
	r := &runner{log: slog.New(slog.NewTextHandler(&logbuf, nil)), cgm: fs}
	got := r.readAppliedLimits(c, l)
	if got == nil || got.PidsMax != nil || got.MemoryMax == nil || *got.MemoryMax != 1_000_000 {
		t.Fatalf("applied_limits = %+v, want memory 1000000 and no pids (its ancestor cannot be read)", got)
	}
	if out := logbuf.String(); !strings.Contains(out, "pids.max") || !strings.Contains(out, "ancestor") {
		t.Errorf("the log does not name the ancestor file that could not be read: %s", out)
	}
	var _ = record.AppliedLimits{}
}
