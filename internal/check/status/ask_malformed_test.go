// SPDX-License-Identifier: Apache-2.0

package status

import (
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestStatusShowsMalformedAsks: a repeated ask id, an answer before its ask and an answer to an id never asked are named
// in the ledger anomalies in askpair's words, and a malformed answer retires nothing: the ask it names is still waiting.
func TestStatusShowsMalformedAsks(t *testing.T) {
	ask := func(w *ledger.Writer, id string) {
		appendEvent(w, record.KindAsk, record.AskPayload{AskID: id, Hold: "request"})
	}
	answer := func(w *ledger.Writer, id string) {
		appendEvent(w, record.KindAnswer, record.AnswerPayload{AskID: id, By: "human", AfterS: 1})
	}
	for _, c := range []struct {
		name     string
		body     func(w *ledger.Writer)
		pending  int
		anomaly  string // a phrase the anomalies say, "" for none
		repeated int
		unpaired int
	}{
		{"well formed", func(w *ledger.Writer) { ask(w, "a"); answer(w, "a") }, 0, "", 0, 0},
		{"a repeated ask id", func(w *ledger.Writer) { ask(w, "a"); ask(w, "a") }, 1, "an ask was recorded twice (1 line)", 1, 0},
		{"a repeat after the answer", func(w *ledger.Writer) { ask(w, "a"); answer(w, "a"); ask(w, "a") }, 0, "an ask was recorded twice (1 line)", 1, 0},
		{"an answer before its ask", func(w *ledger.Writer) { answer(w, "a"); ask(w, "a") }, 1, "an answer has no ask before it (1 line)", 0, 1},
		{"an answer to an id never asked", func(w *ledger.Writer) { ask(w, "a"); answer(w, "zz") }, 1, "an answer has no ask before it (1 line)", 0, 1},
		{"a second answer", func(w *ledger.Writer) { ask(w, "a"); answer(w, "a"); answer(w, "a") }, 0, "an answer has no ask before it (1 line)", 0, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := write(t, true, func(w *ledger.Writer) {
				runStart("1h")(w)
				appendEvent(w, record.KindSSLRequest, record.SSLRequestPayload{})
				c.body(w)
			}, nil)
			s := derive(t, dir, true, base.Add(time.Second), 0)
			if s.PendingApprovals != c.pending || s.RepeatedAsks != c.repeated || s.UnpairedAnswers != c.unpaired {
				t.Errorf("pending %d repeated %d unpaired %d; want %d %d %d", s.PendingApprovals, s.RepeatedAsks, s.UnpairedAnswers, c.pending, c.repeated, c.unpaired)
			}
			an := strings.Join(s.Anomalies(), "\n")
			if c.anomaly == "" && an != "" || !strings.Contains(an, c.anomaly) {
				t.Errorf("anomalies %q, want %q", an, c.anomaly)
			}
		})
	}
}
