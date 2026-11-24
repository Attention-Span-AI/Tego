// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/doctor"
)

// TestPlaneProbesNoteReachesStderrAndTegoLog: a plane mode that two probes answered differently is said on a run's
// stderr and kept in tego.log (in this test binary's own home, never the developer's); `tego doctor` logs only.
func TestPlaneProbesNoteReachesStderrAndTegoLog(t *testing.T) {
	rep := &doctor.Report{Plane: &doctor.PlaneState{Modes: []doctor.PlaneModeResult{
		{Mode: bpfobj.PlaneLSM, Tested: true, Faulted: true,
			Detail: "probed twice with different answers, so the mode is not used in this run: lsm/key_permission differed",
			Probes: []doctor.PlaneProbeAnswer{{Probe: 1}, {Probe: 2, OK: true}}},
		{Mode: bpfobj.PlaneFmodRet, Tested: true, OK: true},
	}}}
	var stderr bytes.Buffer
	notePlaneProbes(&stderr, "tego run", rep)
	if !strings.Contains(stderr.String(), "tego run: note: decision plane, lsm mode: probed twice with different answers") ||
		strings.Contains(stderr.String(), "fmod_ret") {
		t.Errorf("stderr: %q", stderr.String())
	}
	notePlaneProbes(nil, "tego doctor", rep)
	notePlaneProbes(&stderr, "tego run", &doctor.Report{Plane: &doctor.PlaneState{Modes: []doctor.PlaneModeResult{{Mode: bpfobj.PlaneLSM, Tested: true}}}})
	log, err := os.ReadFile(filepath.Join(testHome, ".tego", "tego.log"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(log), "decision plane, lsm mode: probed twice with different answers"); n < 2 {
		t.Errorf("tego.log holds the note %d times, want the run's and the doctor's:\n%s", n, log)
	}
	if n := strings.Count(stderr.String(), "note:"); n != 1 {
		t.Errorf("stderr has %d notes, want 1 (a plane that was not retried says nothing)", n)
	}
}
