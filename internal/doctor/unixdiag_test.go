// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"context"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestUnixDiagNoteOnEveryTier: on a kernel with no sock_diag for AF_UNIX every tier's unix sockets row says that a
// socket under an fs.write path is refused unix-origin-unread (supervisor R11a), after the row's own
// note where it has one; a kernel that answers, or a state where nobody asked, adds nothing.
func TestUnixDiagNoteOnEveryTier(t *testing.T) {
	no, yes := false, true
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		for _, tc := range []struct {
			name string
			diag *bool
			want bool
		}{{"missing", &no, true}, {"present", &yes, false}, {"not asked", nil, false}} {
			t.Run(string(tier)+"/"+tc.name, func(t *testing.T) {
				st := state(func(st *probeState) { st.unixDiag = tc.diag })
				_, notes := st.machineMatrix(tier)
				got := strings.Contains(notes[backend.CapUnixSockets], "unix-origin-unread")
				if got != tc.want {
					t.Fatalf("unix sockets note %q: names the refusal %t, want %t", notes[backend.CapUnixSockets], got, tc.want)
				}
				if tc.want && tier == backend.TierLandlock && !strings.Contains(notes[backend.CapUnixSockets], "Landlock ABI") {
					t.Fatalf("the row's own note was replaced: %q", notes[backend.CapUnixSockets])
				}
			})
		}
	}
}

// TestUnixDiagAskedByDoctorOnly: doctor's scope asks whether sock_diag for AF_UNIX works; a run's scope (ForRun's
// reach) does not, so a run's start pays nothing for it — its supervisor warns on its own.
func TestUnixDiagAskedByDoctorOnly(t *testing.T) {
	for _, reach := range []backend.Tier{"", backend.TierLandlock} {
		asked := 0
		var counts calls
		c := passingChecks(&counts)
		c.unixDiag = func() bool { asked++; return false }
		st := scope{reach: reach, checks: c, root: true}.run(context.Background())
		if want := reach == ""; (asked == 1) != want || (st.unixDiag != nil) != want {
			t.Fatalf("reach %q: asked %d times, state %v; want asked only by doctor", reach, asked, st.unixDiag)
		}
	}
}
