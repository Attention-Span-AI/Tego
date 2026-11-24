// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/testutil/answertest"
)

// TestDoctorPrintsRunMembership: doctor prints this process's own run-membership answer, with the seccomp mode the
// rule recorded outside the first cgroup namespace, as a fact and not a condition (the signed rule's fact 4c is
// removed). An outside answer that recorded nothing prints nothing, so ordinary Linux sees no new line.
func TestDoctorPrintsRunMembership(t *testing.T) {
	const filtered = "run membership (this process): unknown, no-user-manager; seccomp mode 2 (recorded, not judged)"
	for _, c := range []struct {
		name string
		a    runscope.Answer
		want string
	}{
		{"outside in the first namespace", answertest.Outside(), ""},
		{"a WSL shell under mirrored networking", answertest.Recorded(runscope.CauseNoUserManager, 2), filtered},
		{"inside a run", answertest.Inside(runscope.CauseGoverned), "run membership (this process): inside, governed"},
	} {
		if got := membershipLine(c.a); got != c.want {
			t.Errorf("%s: %q; want %q", c.name, got, c.want)
		}
	}

	old := selfAnswer
	t.Cleanup(func() { selfAnswer = old })
	selfAnswer = func() runscope.Answer { return answertest.Recorded(runscope.CauseNoUserManager, 2) }
	if _, out, _ := run(t, "doctor", "--no-scope"); !strings.Contains(out, "\n"+filtered+"\n") {
		t.Errorf("doctor's report does not carry the membership line:\n%s", out)
	}
	_, out, _ := run(t, "doctor", "--no-scope", "--json")
	var rep struct {
		RunMembership string `json:"run_membership"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil || rep.RunMembership != filtered {
		t.Errorf("doctor --json run_membership %q (%v); want %q", rep.RunMembership, err, filtered)
	}
	selfAnswer = answertest.Outside
	if _, out, _ := run(t, "doctor", "--no-scope"); strings.Contains(out, "run membership") {
		t.Errorf("an outside answer that recorded nothing printed a membership line:\n%s", out)
	}
}
