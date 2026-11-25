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
//
// A command made by a case helper that sends its output to a file (Stdout and Stderr set) is read as well as one that
// has none: DoctorOffers collects the output itself, so it takes those two fields back, where exec would otherwise fail
// the call with "Stdout already set" and the answer would be "no answer about this machine" on a machine that has one.
func DoctorOffers(cmd *exec.Cmd) (bool, []byte, error) {
	cmd.Stdout, cmd.Stderr = nil, nil
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
// tier. Skipping on any failure of that command would let a test build's refusal of the invoking user's own ~/.tego
// (exit 125) hide tier-2 end-to-end tests in the KVM root suites as "this machine offers no tier cgroup".
func RequireTier(t testing.TB, cmd *exec.Cmd, tier string) {
	t.Helper()
	offered, out, err := DoctorOffers(cmd)
	switch {
	case err != nil:
		t.Fatalf("tego machine check --require %s gave no answer about this machine: %v\n%s", tier, err, out)
	case !offered:
		t.Skipf("this machine offers no tier %s (tego machine check --require %s):\n%s", tier, tier, out)
	}
}
