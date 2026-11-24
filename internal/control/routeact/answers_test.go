// SPDX-License-Identifier: Apache-2.0

package routeact

import (
	"context"
	"errors"
	"testing"

	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/testutil/answertest"
)

// The two answers a test gives a caller by name: outside every run, and inside one (its cgroup path shows it). The
// rest of the table is answertest.Rows.
func answerOutside() runscope.Answer { return answertest.Outside() }

func answerGoverned() runscope.Answer {
	return answertest.Inside(runscope.CauseGoverned)
}

// TestOnlyAnOutsideAnswerPermits walks the one table of answers (answertest.Rows) over this package's caller: a
// route change is ErrGoverned on every row but outside.
func TestOnlyAnOutsideAnswerPermits(t *testing.T) {
	ctx := context.Background()
	for _, row := range answertest.Rows() {
		s, _ := fixture(t)
		s.governed = row.Self
		p, _ := s.Plan(run, endpoint, "corp")
		_, err := s.Set(ctx, run, endpoint, "corp", p.Ack)
		if governed := errors.Is(err, ErrGoverned); governed == row.Permits {
			t.Errorf("%s: a route change refused as governed: %v (%v)", row.Name, governed, err)
		}
	}
}
