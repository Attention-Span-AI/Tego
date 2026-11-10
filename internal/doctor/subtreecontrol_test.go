// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestControllersResultReportsAnUnreadableSubtreeControl: a failed read of cgroup.subtree_control
// used to yield an empty controller list, which D3 reported as "missing cpu memory pids" with a
// Delegate= fix, losing the real errno.
func TestControllersResultReportsAnUnreadableSubtreeControl(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "cgroup.subtree_control")
	// A directory of that name makes the read fail (EISDIR) without needing privileges.
	if err := os.Mkdir(file, 0o755); err != nil {
		t.Fatal(err)
	}
	r := controllersResult(root, delegateFix, false)
	if r.OK || !strings.Contains(r.Detail, "read "+file) || strings.Contains(r.Detail, "missing") {
		t.Errorf("unreadable subtree_control misreported: %+v", r)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("cpu memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := controllersResult(root, delegateFix, false); !r.OK {
		t.Errorf("all three controllers enabled but D3 failed: %+v", r)
	}
}

// TestControllersResultMissingControllerKeepsTierOne: a fresh login on AlmaLinux 9.8 (systemd 252) gets a user
// manager that enables memory and pids but not cpu (GAPS B15). D3 failed there, so the machine had no tier at all
// and every enforced run was refused, a contract with no limit included. A controller a run's limits do not use
// is not needed: a run whose limits do use it is refused at start by SetLimits (runtime-launch.md case 31). So D3
// passes, tier 1 stays, and the line names the limits refused here and the fix that allows them, never the user@
// drop-in alone, which did not enable cpu there.
func TestControllersResultMissingControllerKeepsTierOne(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "cgroup.subtree_control")
	if err := os.WriteFile(file, []byte("memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := controllersResult(root, delegateFix, false)
	if !r.OK || r.Fix != "" {
		t.Fatalf("cpu alone missing took D3 (and tier 1) away: %+v", r)
	}
	for _, want := range []string{"controllers: memory pids", "not enabled: cpu,", "limits.cpu or limits.cpu_weight",
		"refused at start", "user@.service.d", "CPUWeight=100", "app.slice.d", "reboot"} {
		if !strings.Contains(r.Detail, want) {
			t.Errorf("D3 detail lacks %q: %s", want, r.Detail)
		}
	}
	for _, unwanted := range []string{"limits.memory", "limits.pids"} {
		if strings.Contains(r.Detail, unwanted) {
			t.Errorf("D3 names %s, whose controller is enabled: %s", unwanted, r.Detail)
		}
	}

	// The derivation reads this D3 as tier 1 available, and the summary is the plain tier line.
	st := state(func(st *probeState) {
		st.root = false
		st.byID[CheckCgroupV2] = r
		for i := range st.results {
			if st.results[i].ID == CheckCgroupV2 {
				st.results[i] = r
			}
		}
	})
	if p := st.probe(); !p[backend.TierLandlock] {
		t.Fatalf("tier landlock not offered with cpu alone missing: %v", p)
	}
	var out bytes.Buffer
	if err := st.report(nil, backend.TierLandlock).WriteText(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "\nok   cgroupv2: ") || !strings.Contains(out.String(), "\ntier: landlock\n") ||
		strings.Contains(out.String(), "required tier landlock is not available") {
		t.Errorf("doctor --require landlock with cpu alone missing:\n%s", out.String())
	}

	// Root at the cgroup2 mount root has no unit to set Delegate= on: its fix is system.slice's CPU weight under
	// systemd, and the subtree_control write without it.
	r = controllersResult(root, delegateFix, true)
	if !r.OK || !strings.Contains(r.Detail, "echo '+cpu' > "+root+"/cgroup.subtree_control") ||
		!strings.Contains(r.Detail, "/etc/systemd/system/system.slice.d/") || strings.Contains(r.Detail, "user@.service.d") {
		t.Errorf("root's D3 with cpu missing: %+v", r)
	}

	// Nothing enabled: every controller and every limit it applies is named.
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	r = controllersResult(root, delegateFix, false)
	if !r.OK || !strings.Contains(r.Detail, "not enabled: cpu memory pids,") ||
		!strings.Contains(r.Detail, "limits.cpu or limits.cpu_weight or limits.memory or limits.memory_high or limits.pids") {
		t.Errorf("D3 with no controller enabled: %+v", r)
	}
}
