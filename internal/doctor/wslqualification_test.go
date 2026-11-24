// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bytes"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestWSLQualificationDoesNotPromiseReadiness: while this machine is WSL and the rule's gate holds there
// (peer.WSLGateHolds, the probe's wslHeld), doctor prints one warning per unproven containment row and does not say
// ready; where the gate is lifted (a test build's TEGO_TEST_WSL_RULE=on, or the commit that turns the rule on) and on
// ordinary Linux, it says nothing of WSL. Doctor reads no mark itself: held is the peer gate's answer, which holds on
// any one of WSL's marks and lifts only on two with the switch on (ADR 0100, amended 2026-11-19, round 5;
// TestWSLSwitchNeedsTwoMarks there), so a WSL release with the gate lifted is ready.
func TestWSLQualificationDoesNotPromiseReadiness(t *testing.T) {
	for _, c := range []struct {
		name, release string
		held          bool
	}{
		{"microsoft, gate holds", "6.18.58.1-microsoft-standard-WSL2", true},
		{"microsoft-release, gate lifted", "6.18.58.1-microsoft-standard-WSL2", false},
		{"ordinary", "6.17.0-test", false},
	} {
		release := c.name
		t.Run(c.name, func(t *testing.T) {
			var n calls
			checks := passingChecks(&n)
			checks.wslHeld = func() bool { return c.held }
			st := scope{reach: backend.TierLandlock, checks: checks}.run(t.Context())
			st.release = c.release
			rep := st.report(nil, "")
			var text bytes.Buffer
			if err := rep.WriteText(&text); err != nil {
				t.Fatal(err)
			}
			verdict, _ := rep.Verdict()
			if strings.Contains(release, "gate holds") {
				for _, row := range []string{"Windows launcher", "home-folder alias", "Windows drive", "GUI and audio sockets"} {
					if !strings.Contains(text.String(), "warning: WSL "+row+" containment has not been proven") {
						t.Errorf("missing pending row %q in %s", row, text.String())
					}
				}
				if !strings.Contains(text.String(), "WSL_INTEROP is omitted from enforcing runs") {
					t.Error("doctor does not explain the environment filter")
				}
				if rep.ExitCode() != identity.ExitFinding || strings.HasPrefix(verdict, "Ready:") {
					t.Errorf("unproved WSL qualified: exit=%d verdict=%q", rep.ExitCode(), verdict)
				}
				if rep.Tier != backend.TierLandlock {
					t.Errorf("qualification changed the measured kernel tier: %s", rep.Tier)
				}
			} else {
				if rep.ExitCode() != identity.ExitOK || !strings.HasPrefix(verdict, "Ready:") || strings.Contains(text.String(), "warning: WSL") {
					t.Errorf("ordinary Linux changed: exit=%d verdict=%q", rep.ExitCode(), verdict)
				}
			}
		})
	}
}
