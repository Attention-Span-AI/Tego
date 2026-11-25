// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestCheckReportsTheBuildRunStartNames: the check reads the tego build that ran the run from run_start, whichever build
// checks, and a caller that knows who must have made a receipt (`tego run`'s kept copy) holds the receipt's own
// receipt_by to it. The record's bytes are the source: a run_start naming another build gives another RecordBy.
func TestCheckReportsTheBuildRunStartNames(t *testing.T) {
	for name, ran := range map[string]MadeBy{
		"a release":  testBy,
		"a dirty":    {TegoVersion: "v0.1.2+dirty", Commit: testBy.Commit},
		"no commit":  {TegoVersion: "v0.1.2"},
		"no version": {Commit: testBy.Commit},
	} {
		t.Run(name, func(t *testing.T) {
			lines := boundRun()
			s := lines[0].payload.(record.RunStartPayload)
			s.TegoVersion, s.Commit = ran.TegoVersion, ran.Commit
			lines[0].payload = s
			p := boundPair(t, lines)
			for _, by := range []MadeBy{testBy, {TegoVersion: "v0.1.3", Commit: strings.Repeat("f", 40)}, {TegoVersion: "dev", Commit: "none"}} {
				res := checked(t, p, by)
				if res.RecordBy == nil || *res.RecordBy != ran {
					t.Errorf("checked by %s: RecordBy %+v, want %+v", by.TegoVersion, res.RecordBy, ran)
				}
				var js strings.Builder
				if err := res.JSON(&js); err != nil || strings.Contains(js.String(), "record_by") || strings.Contains(js.String(), "RecordBy") {
					t.Errorf("the check's JSON carries it: %v %s", err, js.String())
				}
			}
		})
	}
}

// TestCheckReportsTheRevisionRunStartOpens: RecordMinor is the record_minor of run_start whichever build checks (0 for
// a line that names none), is a caller's fact only and is never written into the check's JSON.
func TestCheckReportsTheRevisionRunStartOpens(t *testing.T) {
	for _, minor := range []int{0, 30, record.MinorEveryLaunch} {
		lines := boundRun()
		s := lines[0].payload.(record.RunStartPayload)
		s.RecordMinor = minor
		lines[0].payload = s
		p := boundPair(t, lines)
		for _, by := range []MadeBy{testBy, {TegoVersion: "v0.1.3", Commit: strings.Repeat("f", 40)}} {
			res := checked(t, p, by)
			if res.RecordMinor != minor {
				t.Errorf("revision %d, checked by %s: RecordMinor %d", minor, by.TegoVersion, res.RecordMinor)
			}
			var js strings.Builder
			if err := res.JSON(&js); err != nil || strings.Contains(js.String(), "record_minor") || strings.Contains(js.String(), "RecordMinor") {
				t.Errorf("the check's JSON carries it: %v %s", err, js.String())
			}
		}
	}
}

// TestCheckSaysWhenOnlyTheVersionIsNotRead: a receipt_v or binding version this tego does not read is VersionNotRead,
// and nothing else that makes a receipt unreadable is (a missing receipt_v, no binding, text).
func TestCheckSaysWhenOnlyTheVersionIsNotRead(t *testing.T) {
	cases := map[string]struct {
		edit func(m map[string]any)
		want bool
	}{
		"a later receipt version": {func(m map[string]any) { m["receipt_v"] = float64(2) }, true},
		"a later binding version": {func(m map[string]any) { obj(m, "binding")["v"] = float64(9) }, true},
		"no receipt version":      {func(m map[string]any) { delete(m, "receipt_v") }, false},
		"no binding":              {func(m map[string]any) { delete(m, "binding") }, false},
		"an unedited receipt":     {func(map[string]any) {}, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := boundPair(t, boundRun())
			editReceipt(t, p.receipt, c.edit)
			res := checked(t, p, testBy)
			if res.VersionNotRead() != c.want {
				t.Errorf("VersionNotRead %v, want %v (%+v)", res.VersionNotRead(), c.want, step(res, "receipt"))
			}
			if c.want && !strings.Contains(step(res, "receipt").Why, "this tego reads") {
				t.Errorf("the words: %q", step(res, "receipt").Why)
			}
		})
	}
}
