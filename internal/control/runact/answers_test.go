// SPDX-License-Identifier: Apache-2.0

package runact

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/testutil/answertest"
)

// The three answers a test gives a caller: outside every run; inside one (its cgroup path shows it); and unknown,
// as in a cgroup namespace that is not the machine's first one and has no proof.
func answerOutside() runscope.Answer { return answertest.Outside() }

func answerGoverned() runscope.Answer {
	return answertest.Inside(runscope.CauseGoverned)
}

func answerUnknown() runscope.Answer {
	return runscope.Unproven(runscope.CauseUserNamespace, nil)
}

// TestOnlyAnOutsideAnswerPermits walks the one table of answers (answertest.Rows) over this package's caller: a
// lift, a pause and an unblock are ErrGoverned on every row but outside, and SelfGoverned hands the answer on as it is.
func TestOnlyAnOutsideAnswerPermits(t *testing.T) {
	ctx := context.Background()
	defer func(f func() runscope.Answer) { selfAnswer = f }(selfAnswer)
	root, dir := liveDir(t, adjustableStart)
	holdRunLock(t, dir)
	for _, row := range answertest.Rows() {
		selfAnswer = row.Self
		if got := SelfGoverned(); got.Outside() != row.Permits {
			t.Errorf("%s: SelfGoverned().Outside() = %v", row.Name, got.Outside())
		}
		_, liftErr := Lift(ctx, root, liveRun, "read", "/srv/exports", time.Time{}, "cli")
		_, pauseErr := Pause(ctx, root, liveRun, true)
		_, unblockErr := Block(ctx, root, liveRun, "exec", "curl", false)
		for what, err := range map[string]error{"lift": liftErr, "pause": pauseErr, "unblock": unblockErr} {
			if governed := errors.Is(err, ErrGoverned); governed == row.Permits {
				t.Errorf("%s: %s refused as governed: %v (%v)", row.Name, what, governed, err)
			}
		}
	}
}
