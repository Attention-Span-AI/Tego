// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestLocalRolesRetryDoesNotClaimLaterOperation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		retryTID int
	}{
		{"same held operation", 42},
		{"another thread", 43},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var events []Event
			var prev string
			appendEvent := func(kind record.Kind, payload any, tid int) int32 {
				t.Helper()
				e := ledgertest.Event(t, kind, payload, func(e *record.Event) {
					e.TID = tid
					if kind == record.KindFS {
						e.Rule = "fs.ask[held/]"
						e.Verdict = record.VerdictAllow
						e.Authority = record.AuthorityHuman
						e.Attr = &record.Attribution{Confidence: record.ConfidenceUnattributed, Method: record.MethodNone}
					}
				})
				e.Seq, e.Prev = uint64(len(events)), prev
				b, err := e.MarshalLine()
				if err != nil {
					t.Fatal(err)
				}
				prev = e.ID
				ev := fromRecord(e)
				ev.Raw = string(b)
				events = append(events, ev)
				return int32(len(events) - 1) //nolint:gosec // five fixture events
			}
			ask := func(id string, tid int) {
				appendEvent(record.KindAsk, struct {
					record.AskPayload
					Op      string `json:"op"`
					Target  string `json:"target"`
					AskRule string `json:"ask_rule"`
				}{record.AskPayload{AskID: id, Hold: "open"}, "open", "/held/effect", "fs.ask[held/]"}, tid)
			}
			answer := func(id string, tid int) {
				appendEvent(record.KindAnswer, struct {
					record.AnswerPayload
					record.AnswerAuthority
					Approved bool `json:"approved"`
				}{record.AnswerPayload{AskID: id, By: "uid:0 pid:9", AfterS: 1}, record.AnswerAuthority{Actor: &record.LocalApprovalActor{UID: 0, PID: 9, StartBootNS: 10, UserNamespace: record.InitialUserNamespace, Source: "kernel-local-uid", Role: "owner"}}, true}, tid)
			}
			ask("q-first", 42)
			answer("q-first", 42)
			ask("q-retry", tc.retryTID)
			if tc.retryTID == 42 {
				answer("q-retry", 42)
			}
			effect := appendEvent(record.KindFS, record.FSPayload{Op: "open", Path: "/held/effect"}, 42)
			index := buildLineIndex("r-fixture", events)
			old := index.asks["q-first"]
			if tc.retryTID == 42 {
				if len(old.consequences) != 0 {
					t.Fatalf("rejected selection claimed retry effect: %v", old.consequences)
				}
				if got := index.askOf[effect]; got != "q-retry" {
					t.Fatalf("retry effect belongs to %q, want q-retry", got)
				}
			} else if len(old.consequences) != 1 || old.consequences[0] != effect {
				t.Fatalf("another thread's ask hid the original effect: %v", old.consequences)
			}
		})
	}
}
