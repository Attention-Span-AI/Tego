// SPDX-License-Identifier: Apache-2.0

//go:build !tegotesthooks

package doctor

import (
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
)

// TestPlaneTestOutcomeIsTheIdentityInAProductBuild: without tegotesthooks the seam of a probe row's outside leg
// returns what doctor's own syscall answered, whatever the row, mode or answer.
func TestPlaneTestOutcomeIsTheIdentityInAProductBuild(t *testing.T) {
	for _, outcome := range []string{planePassed, planeRefused, "failed: operation not permitted"} {
		if got := planeTestOutcome(bpfobj.PlaneLSM, "socket_create", outcome); got != outcome {
			t.Errorf("outcome %q came back as %q", outcome, got)
		}
	}
}
