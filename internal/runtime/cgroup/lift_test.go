// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLiftLimitsPutsEveryLimitBack: an adoption's release can leave processes in its scope (no cgroup takes them
// back), and they are no longer governed, so they keep no limit tego wrote: LiftLimits writes each file SetLimits can
// write back to the kernel's default, and a file the scope does not have (its controller not enabled) is no error.
func TestLiftLimitsPutsEveryLimitBack(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.CreateScope("a", "r-1", "adopt-r-1.scope")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	// The memory controller is not enabled here: its files are absent.
	for _, name := range []string{"cpu.max", "cpu.weight", "pids.max"} {
		writeCtl(t, c, name, "")
	}
	if err := fs.SetLimits(c, Limits{CPUMax: "50000 100000", CPUWeight: 20, PidsMax: 64}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cpu.max", "cpu.weight", "pids.max"} {
		writeCtl(t, c, name, "") // a tmpfs file keeps the tail of a longer old value; a control file does not
	}
	if err := fs.LiftLimits(c); err != nil {
		t.Fatalf("LiftLimits with the memory controller absent: %v", err)
	}
	for name, want := range map[string]string{"cpu.max": "max 100000", "cpu.weight": "100", "pids.max": "max"} {
		if got, err := os.ReadFile(filepath.Join(c.Path, name)); err != nil || string(got) != want {
			t.Errorf("%s = %q, %v; want %q", name, got, err, want)
		}
	}
	for _, name := range []string{"memory.max", "memory.high", fileSwapMax} {
		if _, err := os.Stat(filepath.Join(c.Path, name)); !os.IsNotExist(err) {
			t.Errorf("LiftLimits made %s: %v", name, err)
		}
	}
	// Every file limitFiles can write has its lift.
	lifted := map[string]bool{}
	for _, f := range liftFiles() {
		lifted[f.Name] = true
	}
	for _, f := range limitFiles(Limits{CPUMax: "1 100000", CPUWeight: 1, MemoryMaxSet: true, MemoryHighSet: true, PidsMaxSet: true}) {
		if !lifted[f.Name] {
			t.Errorf("%s is written by SetLimits and never lifted", f.Name)
		}
	}
	// A file that refuses the write is said, and the others are still lifted.
	if err := os.Remove(filepath.Join(c.Path, "cpu.weight")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(c.Path, "cpu.weight"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeCtl(t, c, "pids.max", "64")
	if err := fs.LiftLimits(c); err == nil {
		t.Error("a lift the kernel refused was not said")
	}
	if got, _ := os.ReadFile(filepath.Join(c.Path, "pids.max")); string(got) != "max" {
		t.Errorf("pids.max = %q after a refused cpu.weight lift; want it lifted all the same", got)
	}
}
