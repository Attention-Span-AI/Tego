// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// stubStopRearm makes stop root or not and records its build passes, which fail with err; it is undone at the
// test's end.
func stubStopRearm(t *testing.T, root bool, err error) *int {
	t.Helper()
	calls := 0
	prevRoot, prevRearm := stopPrivileged, stopRearmBuilds
	t.Cleanup(func() { stopPrivileged, stopRearmBuilds = prevRoot, prevRearm })
	stopPrivileged = func() bool { return root }
	stopRearmBuilds = func(m *config.Machine) error {
		if m == nil {
			t.Error("the build pass was given no machine config: it needs bpf.linger")
		}
		calls++
		return err
	}
	return &calls
}

// TestStopRearmsTheBuildTimersAsRoot is ADR 0022 (4) and (8) in `tego stop` (limits-check-doctor-cli.md R29): a
// root stop, once the run has ended or is not running, starts the timer of every tier-2 build whose timer died, so
// a build left lingering with none is removed within its linger rather than at the next gc. It is one pass, after
// the stop, and it removes nothing on stop's own path.
func TestStopRearmsTheBuildTimersAsRoot(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	calls := stubStopRearm(t, true, nil)
	code, out, errs := run(t, "stop", id)
	if code != identity.ExitOK || !strings.Contains(out, id+": not running") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
	if *calls != 1 {
		t.Errorf("a root stop ran the build pass %d times, want once", *calls)
	}
}

// TestStopLeavesTheBuildsAloneUnprivileged: the pins and the timers are root's, as for gc; a user's stop does not
// try them, and a stop that fails before it stops anything (a run id that names no run) does not either.
func TestStopLeavesTheBuildsAloneUnprivileged(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	calls := stubStopRearm(t, false, nil)
	if code, _, errs := run(t, "stop", id); code != identity.ExitOK {
		t.Fatalf("exit %d (stderr %q)", code, errs)
	}
	if *calls != 0 {
		t.Errorf("an unprivileged stop ran the build pass %d times", *calls)
	}
	stopPrivileged = func() bool { return true }
	if code, _, _ := run(t, "stop", "r-3f9c2a1b-0dllq06ts7400-k7m2pq"); code != identity.ExitUsage {
		t.Fatalf("stop of no run: exit %d, want %d", code, identity.ExitUsage)
	}
	if *calls != 0 {
		t.Errorf("a stop of a run that does not exist ran the build pass %d times", *calls)
	}
}

// TestStopExitsZeroWhenTheBuildPassFails: the build pass is best effort; its failure is on stderr, and stop's exit
// is still the stop's (R29: 0 for a run stopped or not running).
func TestStopExitsZeroWhenTheBuildPassFails(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	stubStopRearm(t, true, errors.New("cgroup: start the build's linger timer: boom"))
	code, _, errs := run(t, "stop", id)
	if code != identity.ExitOK {
		t.Fatalf("exit %d, want 0 (stderr %q)", code, errs)
	}
	if !strings.Contains(errs, "tego stop: builds:") || !strings.Contains(errs, "boom") {
		t.Errorf("stderr %q does not say the build pass failed", errs)
	}
}
