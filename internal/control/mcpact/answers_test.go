// SPDX-License-Identifier: Apache-2.0

package mcpact

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
// loosening of a tool is ErrGoverned on every row but outside.
func TestOnlyAnOutsideAnswerPermits(t *testing.T) {
	ctx := context.Background()
	for _, row := range answertest.Rows() {
		s, _ := fixture(t, false)
		s.governed = row.Self
		p, _ := s.Plan(run, "files", "delete_file", "allow")
		_, err := s.Set(ctx, run, "files", "delete_file", "allow", p.Ack)
		if governed := errors.Is(err, ErrGoverned); governed == row.Permits {
			t.Errorf("%s: a loosening refused as governed: %v (%v)", row.Name, governed, err)
		}
	}
}
