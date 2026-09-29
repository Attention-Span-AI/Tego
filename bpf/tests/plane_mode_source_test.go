// SPDX-License-Identifier: Apache-2.0

package bpftests

import (
	"path/filepath"
	"strings"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
)

// TestPlaneHooksDecideOnlyTheirModesRuns is enforce-plane R18, R22 and I6 in the source (TIER3-PLAN T6): right after the
// run-set miss, every body returns 0 for a run whose tego_run.plane is not its own mode's, so a run prepared for the
// fanotify fallback or in the other mode is never decided by rows it does not have (a slot with no rows map refuses
// every open, NOROWS). The mode is the macro's constant, TEGO_PLANE_RUN_MODE maps it onto enum tego_run_plane, and
// the Go mirror is internal/bpf RunPlaneOf.
func TestPlaneHooksDecideOnlyTheirModesRuns(t *testing.T) {
	t.Parallel()
	_, src := planeSource(t)
	def := macroDefinition(t, src, "TEGO_PLANE_RUN_MODE")
	if !strings.Contains(def, "(mode) == TEGO_PLANE_LSM ? TEGO_RUN_PLANE_LSM : TEGO_RUN_PLANE_FMOD_RET") {
		t.Errorf("TEGO_PLANE_RUN_MODE does not map the program's mode onto enum tego_run_plane: %s", def)
	}
	for name, body := range planeBodies(t) {
		if planeRunModeGuard(body) == nil {
			t.Errorf("%s: the run-set miss has no immediate own-mode check", name)
		}
	}
	events := read(t, filepath.Join(sourceDir, "include", "events.h"))
	for _, want := range []string{"TEGO_RUN_PLANE_NONE = 0,", "TEGO_RUN_PLANE_LSM = 1,", "TEGO_RUN_PLANE_FMOD_RET = 2,", "__u8  plane;"} {
		if !strings.Contains(events, want) {
			t.Errorf("events.h lacks %q", want)
		}
	}
	for m, want := range map[ebpfbindings.PlaneMode]uint8{ebpfbindings.PlaneLSM: 1, ebpfbindings.PlaneFmodRet: 2, "": 0} {
		if got := ebpfbindings.RunPlaneOf(m); got != want {
			t.Errorf("RunPlaneOf(%q) = %d, want %d", m, got, want)
		}
	}
}
