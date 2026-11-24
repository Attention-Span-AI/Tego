// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

func TestLocalRolesDashboardAttributionRequiresRevisionAndCompleteAnswer(t *testing.T) {
	const actor = `"actor":{"uid":0,"pid":42,"start_boot_ns":10,"user_namespace":4026531837,"source":"kernel-local-uid","role":"owner"}`
	for _, tc := range []struct {
		name     string
		minor    int
		decision string
		noFloor  bool // the run's run_start carries no local_approval_authority
		want     bool
	}{
		{"below-minor", 31, `"approved":true`, false, false}, {"valid", 37, `"approved":true`, false, true}, {"invalid-denial", 37, `"approved":false`, false, false}, {"invalid-approval", 37, `"approved":true,"answer_reason":"ask-timeout"`, false, false},
		// A line rewritten to claim root in a run that never started under the floor is not shown as root's.
		{"valid-line-without-the-floor", 37, `"approved":true`, true, false}, {"valid-line-without-the-floor-at-41", 41, `"approved":true`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := ledgerview.Event{Kind: "answer", RecordMinor: tc.minor, LocalFloor: !tc.noFloor, Raw: `{"by":"uid:0 pid:42",` + tc.decision + `,` + actor + `}`}
			if got := shownOp(e); strings.Contains(got, "role Owner") != tc.want {
				t.Fatalf("attribution: %s", got)
			}
			snap := &ledgerview.Snapshot{Runs: []*ledgerview.Run{{ID: "r-test", Kinds: map[string]int{"answer": 1}, Events: []ledgerview.Event{e}}}}
			answers := answersOf(snap, 10)
			if len(answers) != 1 || strings.Contains(answers[0].Word, "role Owner") != tc.want {
				t.Fatalf("history attribution: %+v", answers)
			}
		})
	}
}
