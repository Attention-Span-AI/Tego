// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProbeSwap is D9 (ADR 0038's 2026-09-24 note): a cgroup with the memory controller and no memory.swap.max,
// on a host with swap on, fails with the swap-accounting fix; swap accounted, or no swap, passes; a process
// with no memory-controlled cgroup to ask passes and says so. The cgroup directories and /proc/swaps are fakes.
func TestProbeSwap(t *testing.T) {
	mount := t.TempDir()
	leaf := filepath.Join(mount, "user.slice", "user-1000.slice", "session-2.scope")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		t.Fatal(err)
	}
	put := func(dir, name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	proc := []byte("0::/user.slice/user-1000.slice/session-2.scope\n")
	if got := memoryCgroup(mount, proc); got != "" {
		t.Fatalf("memoryCgroup = %q with no memory controller anywhere", got)
	}
	slice := filepath.Join(mount, "user.slice")
	put(slice, "memory.max") // the nearest memory-controlled cgroup is an ancestor
	if got := memoryCgroup(mount, proc); got != slice {
		t.Fatalf("memoryCgroup = %q, want %q", got, slice)
	}
	swapsOn := func() ([]byte, error) {
		return []byte("Filename Type Size Used Priority\n/dev/zram0 partition 8 0 100\n"), nil
	}
	swapsOff := func() ([]byte, error) { return []byte("Filename Type Size Used Priority\n"), nil }

	r := probeSwapIn(slice, swapsOn)
	if r.OK || r.ID != CheckSwap || !strings.Contains(r.Detail, "/dev/zram0") || !strings.Contains(r.Fix, "swapaccount") {
		t.Errorf("uncapped swap: %+v, want a failure naming the area with the swap-accounting fix", r)
	}
	if r := probeSwapIn(slice, swapsOff); !r.OK || r.Fix != "" {
		t.Errorf("no swap on: %+v, want ok", r)
	}
	put(slice, "memory.swap.max")
	if r := probeSwapIn(slice, swapsOn); !r.OK || !strings.Contains(r.Detail, "memory.swap.max present") {
		t.Errorf("swap accounted: %+v, want ok", r)
	}
	if r := probeSwapIn("", swapsOn); !r.OK || r.Detail == "" {
		t.Errorf("nothing to ask: %+v, want ok with a detail", r)
	}
}
