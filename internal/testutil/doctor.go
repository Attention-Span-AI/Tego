// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"errors"
	"fmt"
	"os/exec"
	"testing"
)

// The exit statuses of `tego doctor --require <tier>` that say this machine does not offer the tier
// (pkg/spec/identity: ExitRequire, and ExitFinding when no tier at all can run). They are spelled here because this
// package imports nothing of the tree's; TestDoctorExitsMatchIdentity holds them to identity's.
const (
	doctorExitRequire = 211
	doctorExitFinding = 1
)

// DoctorOffers runs cmd, a `tego doctor --require <tier>` the caller built with its isolation, and says whether the
// machine offers the tier: true on exit 0, false on doctor's own "not offered" answers (211, or 1 when no tier can run
// at all). Any other end (a refused machine config, a usage error, a crash, a binary that did not start) is an error:
// it is no answer about the machine. Its output is returned either way, for the caller's message.
func DoctorOffers(cmd *exec.Cmd) (bool, []byte, error) {
	out, err := cmd.CombinedOutput()
	if err == nil {
		return true, out, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && (ee.ExitCode() == doctorExitRequire || ee.ExitCode() == doctorExitFinding) {
		return false, out, nil
	}
	return false, out, fmt.Errorf("%v: %w", cmd.Args, err)
}

// RequireTier skips the test when cmd, a `tego doctor --require <tier>`, answers that this machine does not offer
// tier, and fails it when doctor gives no answer at all (DoctorOffers): a harness fault is not a machine without the
// tier. Until 2026-10-16 the root tests skipped on any failure of that command, and a test build's refusal of the
// invoking user's own ~/.tego (exit 125) then hid some forty tier-2 end-to-end tests in the KVM root suites as
// "this machine offers no tier cgroup".
func RequireTier(t testing.TB, cmd *exec.Cmd, tier string) {
	t.Helper()
	offered, out, err := DoctorOffers(cmd)
	switch {
	case err != nil:
		t.Fatalf("tego doctor --require %s gave no answer about this machine: %v\n%s", tier, err, out)
	case !offered:
		t.Skipf("this machine offers no tier %s (tego doctor --require %s):\n%s", tier, tier, out)
	}
}
