// SPDX-License-Identifier: Apache-2.0

package status

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestApprovalStatusReadsMatchingAnswersAndLiveState(t *testing.T) {
	for _, tc := range []struct {
		name                string
		answer, ended, lost bool
		idle                time.Duration
		want                State
		pending             int
	}{
		{"waiting", false, false, false, time.Second, WaitingApproval, 2},
		{"one matching answer", true, false, false, time.Second, WaitingApproval, 1},
		{"ended", false, true, false, time.Second, Done, 0},
		{"lost", false, false, true, time.Second, Lost, 0},
		// A pending approval holds the stall clock (limits R4), so a wait past
		// stall_after is still waiting approval while the broker can still be
		// waiting: it answers by ask.timeout, at most 1h.
		{"waiting past stall_after", false, false, false, 90 * time.Minute, WaitingApproval, 2},
		// An ask unanswered past stall_after plus that bound outlived any broker
		// (a wedged or SIGSTOPped launcher): R9 reports it stalled again.
		{"pending ask outlived ask.timeout", false, false, false, 2 * time.Hour, Stalled, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var end *record.RunEndPayload
			if tc.ended {
				end = &record.RunEndPayload{Reason: record.RunEndExit}
			}
			dir := write(t, !tc.lost, func(w *ledger.Writer) {
				runStart("1h")(w)
				appendEvent(w, record.KindSSLRequest, record.SSLRequestPayload{})
				for _, id := range []string{"legacy-ask-1", "legacy-ask-2"} {
					appendEvent(w, record.KindAsk, record.AskPayload{AskID: id, Hold: "request"})
				}
				// An answer for some other ask cannot manufacture completion.
				appendEvent(w, record.KindAnswer, record.AnswerPayload{AskID: "unknown-ask", By: "human", AfterS: 1})
				if tc.answer {
					appendEvent(w, record.KindAnswer, record.AnswerPayload{AskID: "legacy-ask-1", By: "human", AfterS: 2})
				}
			}, end)
			s := derive(t, dir, !tc.ended && !tc.lost, base.Add(tc.idle), 0)
			if s.St != tc.want || s.PendingApprovals != tc.pending {
				t.Fatalf("state=%q pending=%d want %q/%d", s.St, s.PendingApprovals, tc.want, tc.pending)
			}
		})
	}
	// Older v1 answer fields still retire an ask without the additive approved
	// field written by the current broker.
	var pending pendingApprovals
	for _, ev := range []*record.Event{{Kind: record.KindAsk, Payload: []byte(`{"ask_id":"old-id","hold":"connect","future_optional":true}`)}, {Kind: record.KindAnswer, Payload: []byte(`{"ask_id":"old-id","by":"human","after_s":1}`)}} {
		if err := pending.add(ev); err != nil {
			t.Fatal(err)
		}
	}
	if len(pending) != 0 {
		t.Fatal("legacy answer left approval pending")
	}
}

func TestApprovalStatusRejectsMalformedAndBoundsPending(t *testing.T) {
	for _, tc := range []struct {
		kind    record.Kind
		payload string
	}{
		{record.KindAsk, `{"ask_id":"x","hold":"future"}`},
		{record.KindAsk, `{"ask_id":null,"hold":"connect"}`},
		{record.KindAsk, `{"ask_id":"x","ask_\u0069d":"y","hold":"connect"}`},
		{record.KindAsk, `{"ask_id":"x","hold":[]}`},
		{record.KindAnswer, `{"ask_id":"x","by":3,"after_s":1}`},
		{record.KindAnswer, `{"ask_id":"x","by":"human","after_s":-1}`},
		{record.KindAnswer, `{"ask_id":"x","by":"human","after_s":1,"approved":"yes"}`},
		{record.KindAnswer, `{"ask_id":"x","by":"human","after_s":1,"approved":null}`},
	} {
		var pending pendingApprovals
		if err := pending.add(&record.Event{Kind: tc.kind, Payload: []byte(tc.payload)}); err == nil || len(pending) != 0 {
			t.Fatalf("accepted %s: %v", tc.payload, err)
		}
	}
	var pending pendingApprovals
	for i := 0; i < 64; i++ {
		if err := pending.add(&record.Event{Kind: record.KindAsk, Payload: []byte(fmt.Sprintf(`{"ask_id":"ask-%d","hold":"connect"}`, i))}); err != nil {
			t.Fatal(err)
		}
	}
	err := pending.add(&record.Event{Kind: record.KindAsk, Payload: []byte(`{"ask_id":"overflow","hold":"connect"}`)})
	if err == nil || !strings.Contains(err.Error(), "64") || len(pending) != 64 {
		t.Fatalf("unbounded pending state len=%d err=%v", len(pending), err)
	}
	if err := pending.add(&record.Event{Kind: record.KindGap, Payload: []byte(`{"ask_id":"fabricated","hold":"connect"}`)}); err != nil || len(pending) != 64 {
		t.Fatal("unrelated record changed approval readiness")
	}
}

// TestApprovalStatusCountsAPendingFileOpen pins that a file-open approval's ask line, held as an open
// (ask-4), counts as pending like a network one rather than failing status as an unsupported hold.
func TestApprovalStatusCountsAPendingFileOpen(t *testing.T) {
	var pending pendingApprovals
	if err := pending.add(&record.Event{Kind: record.KindAsk, Payload: []byte(`{"ask_id":"q-1","hold":"open","op":"open","target":"/w/x"}`)}); err != nil || len(pending) != 1 {
		t.Fatalf("pending %d, err %v: want the open approval pending", len(pending), err)
	}
}
