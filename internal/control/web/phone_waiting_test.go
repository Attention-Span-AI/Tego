// SPDX-License-Identifier: Apache-2.0

package web

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// A directly rendered fragment has no global chrome, so the phone's waiting state
// comes from the page's own data and its explicit attention source.
func TestPhoneWaitingFollowsThePageData(t *testing.T) {
	two := []ledgerview.Ask{{}, {}}
	cut := attentionSource{PendingReason: reasonQueueCut}
	live := &ledgerview.Run{ID: numRichRun, Live: true, Pending: two}
	ended := &ledgerview.Run{ID: numRichRun, Pending: two}
	for _, tc := range []struct {
		name      string
		p         page
		short     string
		inContent bool
	}{
		{"overview known", page{Data: overviewData{Pending: two}}, "2", true},
		{"approvals cut", page{Data: approvalsData{Pending: two, AttentionSource: cut}}, "2+", true},
		{"live run cut", page{Data: runData{Run: live, AttentionSource: cut}}, "2+", true},
		{"ended run waits for nobody", page{Data: runData{Run: ended}}, "", false},
		{"run without a record", page{Data: runData{}}, "", false},
		{"global chrome wins", page{chrome: chrome{globalNumbersSet: true}, Data: runData{Run: live}}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.p.PhoneWaiting()
			if got.Short != tc.short && !(tc.short == "" && got.Short == "0") {
				t.Errorf("phone waiting short=%q want %q", got.Short, tc.short)
			}
			if got.Show != (tc.short != "") {
				t.Errorf("phone waiting show=%v for %q", got.Show, tc.short)
			}
			if in := tc.p.PhoneWaitingInContent(); in != tc.inContent {
				t.Errorf("waiting in content=%v want %v", in, tc.inContent)
			}
		})
	}
}
