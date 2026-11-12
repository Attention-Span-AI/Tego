// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
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
	r := controllersResult(root, delegateFix, false, nil)
	if r.OK || !strings.Contains(r.Detail, "read "+file) || strings.Contains(r.Detail, "missing") {
		t.Errorf("unreadable subtree_control misreported: %+v", r)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("cpu memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := controllersResult(root, delegateFix, false, nil); !r.OK {
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
	r := controllersResult(root, delegateFix, false, nil)
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
	r = controllersResult(root, delegateFix, true, nil)
	if !r.OK || !strings.Contains(r.Detail, "echo '+cpu' > "+root+"/cgroup.subtree_control") ||
		!strings.Contains(r.Detail, "/etc/systemd/system/system.slice.d/") || strings.Contains(r.Detail, "user@.service.d") {
		t.Errorf("root's D3 with cpu missing: %+v", r)
	}

	// Nothing enabled: every controller and every limit it applies is named.
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	r = controllersResult(root, delegateFix, false, nil)
	if !r.OK || !strings.Contains(r.Detail, "not enabled: cpu memory pids,") ||
		!strings.Contains(r.Detail, "limits.cpu or limits.cpu_weight or limits.memory or limits.memory_high or limits.pids") {
		t.Errorf("D3 with no controller enabled: %+v", r)
	}
}

// TestControllersResultNamesACeilingOnAMissingController: on a stock RHEL 9 host cpu is not enabled, and a limits.cpu
// ceiling in the machine config is every run's limit, so every tego run was refused at start (exit 125) while doctor
// said nothing of it (GAPS B15, measured 2026-11-10). D3 now names the ceiling, its file and line, that every run is
// refused, and the fix; it still passes, so the tier is unchanged. A ceiling whose controller is enabled, or one no
// controller applies (wall), is not named.
func TestControllersResultNamesACeilingOnAMissingController(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte("memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	etc := func(line int) config.Provenance {
		return config.Provenance{File: "/etc/tego/config.yaml", Line: line, Layer: config.LayerEtc}
	}
	ceilings := []config.Value{
		{Key: "limits.cpu", Value: "2", Source: etc(5), Ceiling: true},
		{Key: "limits.memory", Value: "8GiB", Source: etc(6), Ceiling: true},
		{Key: "limits.wall", Value: "8h", Source: etc(7), Ceiling: true},
	}
	r := controllersResult(root, delegateFix, false, ceilings)
	if !r.OK || r.Fix != "" {
		t.Fatalf("a ceiling on a missing controller took D3 (and tier 1) away: %+v", r)
	}
	for _, want := range []string{"limits.cpu=2 (/etc/tego/config.yaml:5)", "every tego run is refused at start",
		"until the controller is enabled or the ceiling is removed", "CPUWeight=100", "reboot"} {
		if !strings.Contains(r.Detail, want) {
			t.Errorf("D3 detail lacks %q: %s", want, r.Detail)
		}
	}
	for _, unwanted := range []string{"limits.memory=", "limits.wall"} {
		if strings.Contains(r.Detail, unwanted) {
			t.Errorf("D3 names %s, which no missing controller applies: %s", unwanted, r.Detail)
		}
	}
	// Ceilings on two missing controllers: both are named, and the line says controllers and ceilings (D5).
	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte("pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	two := controllersResult(root, delegateFix, false, ceilings)
	for _, want := range []string{"the ceilings limits.cpu=2 (/etc/tego/config.yaml:5), limits.memory=8GiB (/etc/tego/config.yaml:6)",
		"until the controllers are enabled or the ceilings are removed"} {
		if !strings.Contains(two.Detail, want) {
			t.Errorf("D3 detail lacks %q: %s", want, two.Detail)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte("memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// No ceiling on a missing controller: the line is the one it was.
	if got, was := controllersResult(root, delegateFix, false, ceilings[1:]), controllersResult(root, delegateFix, false, nil); got != was {
		t.Errorf("ceilings on enabled controllers changed D3:\n%+v\n%+v", got, was)
	}

	// The machine's ceilings reach D3 through the scope doctor.Run and ForRun build.
	var c calls
	ch := passingChecks(&c)
	var seen []config.Value
	ch.cgroup = func(_ int, cs []config.Value) Result { seen = cs; return Result{ID: CheckCgroupV2, OK: true} }
	scope{root: true, checks: ch, ceilings: ceilings}.run(context.Background())
	if len(seen) != len(ceilings) || seen[0] != ceilings[0] {
		t.Errorf("D3 was handed %v, want the machine's ceilings %v", seen, ceilings)
	}
}
