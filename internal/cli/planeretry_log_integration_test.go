// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf && tegotesthooks

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestIntegrationPlaneRetryIsInDoctorJSONTextAndTegoLog is the cli half of internal/doctor's
// TestIntegrationPlaneProbeRetryOnARealKernel, as root on a real kernel built with tegotesthooks: a plane mode whose
// first probe fails one row on its outside leg and whose second passes is Faulted, and `tego doctor` says so in its
// --json (plane.modes[].probes), in its text and in tego.log (this test binary's own home), and a run's note goes to
// its stderr; a mode that fails the same way twice and a mode that passes put no such line in the log. The wrapper
// test/vm's guest wrapper runs both.
func TestIntegrationPlaneRetryIsInDoctorJSONTextAndTegoLog(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the plane probe loads and attaches programs as root (CAP_BPF, CAP_SYS_ADMIN)")
	}
	if len(bpfobj.PlaneObjects()) == 0 {
		t.Skip("untagged: the plane probe loads decide.bpf.c's builds")
	}
	ctx := context.Background()
	const hook = "socket_create"
	force := func(m bpfobj.PlaneMode, how doctor.PlaneRowForce) {
		_, restore := doctor.PlaneRowForceForTest(m, hook, how)
		t.Cleanup(restore)
	}
	doctorJSON := func() (retryDoctorJSON, string) {
		t.Helper()
		var out, errb bytes.Buffer
		runDoctor(ctx, true, "", true, &out, &errb)
		var d retryDoctorJSON
		if err := json.Unmarshal(out.Bytes(), &d); err != nil {
			t.Fatalf("doctor --json: %v: %s%s", err, out.String(), errb.String())
		}
		return d, out.String()
	}
	tegoLog := func() string {
		b, err := os.ReadFile(filepath.Join(testHome, ".tego", "tego.log"))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		return string(b)
	}

	force("", doctor.PlaneRowForceNever)
	base, _ := doctorJSON()
	var target string
	for _, m := range base.Plane.Modes {
		if m.OK {
			target = m.Mode
			break
		}
	}
	if target == "" {
		t.Fatalf("no plane mode passes on this kernel, so none can be forced: %+v", base.Plane)
	}
	note := "decision plane, " + target + " mode: probed twice with different answers"
	if strings.Contains(tegoLog(), "probed twice") {
		t.Fatalf("tego.log holds a probed-twice line after an unforced run:\n%s", tegoLog())
	}

	// A mode that fails the same row on both probes is a failed mode: nothing is logged.
	force(bpfobj.PlaneMode(target), doctor.PlaneRowForceAlways)
	same, _ := doctorJSON()
	for _, m := range same.Plane.Modes {
		if m.Mode == target && (m.OK || m.Faulted || len(m.Probes) != 0) {
			t.Errorf("always failing: mode %s ok %v faulted %v probes %d, want a failed mode with no second answer", m.Mode, m.OK, m.Faulted, len(m.Probes))
		}
	}
	if strings.Contains(tegoLog(), "probed twice") {
		t.Errorf("a mode that failed the same way twice put a probed-twice line in tego.log:\n%s", tegoLog())
	}

	// A mode that fails its first probe only: doctor --json, the text and tego.log.
	force(bpfobj.PlaneMode(target), doctor.PlaneRowForceFirst)
	d, raw := doctorJSON()
	var seen bool
	for _, m := range d.Plane.Modes {
		if m.Mode != target {
			continue
		}
		seen = true
		if m.OK || !m.Faulted || len(m.Probes) != 2 || len(m.Probes[0].Programs) == 0 || len(m.Probes[0].Programs) != len(m.Probes[1].Programs) {
			t.Errorf("mode %s in --json: ok %v faulted %v with %d probe row sets, want Faulted with both: %s", m.Mode, m.OK, m.Faulted, len(m.Probes), raw)
		}
	}
	if !seen {
		t.Fatalf("--json has no plane mode %s: %s", target, raw)
	}
	if d.Plane.Selected == target {
		t.Errorf("--json selects the faulted mode %s", target)
	}
	if n := strings.Count(tegoLog(), "tego doctor: "+note); n != 1 {
		t.Errorf("tego.log holds %d lines %q after one doctor run, want 1:\n%s", n, note, tegoLog())
	}
	force(bpfobj.PlaneMode(target), doctor.PlaneRowForceFirst)
	var text, errb bytes.Buffer
	runDoctor(ctx, false, "", true, &text, &errb)
	for _, want := range []string{"probed twice with different answers", "first probe", "second probe", hook} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("tego doctor's text lacks %q:\n%s", want, text.String())
		}
	}
	if n := strings.Count(tegoLog(), "tego doctor: "+note); n != 2 {
		t.Errorf("tego.log holds %d lines after two doctor runs, want 2", n)
	}

	// A run's probe: the note on stderr and in tego.log, and no plane answer in the run-probe cache (the run's own
	// next probe meets the mode again).
	force(bpfobj.PlaneMode(target), doctor.PlaneRowForceFirst)
	m, _, err := loadMachine(config.TrustWarn)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := doctor.ForRun(ctx, m, backend.TierCgroup)
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	notePlaneProbes(&stderr, "tego run", rep)
	if !strings.Contains(stderr.String(), "tego run: note: "+note) {
		t.Errorf("the run's stderr lacks the note: %q", stderr.String())
	}
	if n := strings.Count(tegoLog(), "tego run: "+note); n != 1 {
		t.Errorf("tego.log holds %d run lines, want 1", n)
	}
}

// retryDoctorJSON is the part of `tego doctor --json` the test reads.
type retryDoctorJSON struct {
	Plane struct {
		Selected string
		Modes    []struct {
			Mode    string
			OK      bool
			Faulted bool
			Probes  []struct {
				Probe    int
				Programs []doctor.HookResult
			}
		}
	}
}
