// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestOutcomeNamesTheSignalThatStartedTheStop: an escalated run whose reason is signal or stopped records the signal
// that started stop_grace (spec/record/v1 run_end). The receipt names that signal and the kill without inventing its
// trigger: `escalated` does not tell grace expiry apart from a second interrupt.
func TestOutcomeNamesTheSignalThatStartedTheStop(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  record.RunEndPayload
		want string
	}{
		{"stopped within the grace", record.RunEndPayload{Reason: "signal", Signal: 15}, "ended by signal 15"},
		{"escalated stop, trigger not recorded", record.RunEndPayload{Reason: "signal", Signal: 15, Escalated: true},
			"ended by signal 15, then killed by Tego"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := compute(t, []line{watchedStart(), {kind: record.KindRunEnd, at: time.Second, payload: tc.end}}, Options{})
			if got := rc.Outcome(); got != tc.want {
				t.Errorf("Outcome = %q, want %q", got, tc.want)
			}
			if rc.Escalated != tc.end.Escalated || rc.Signal != tc.end.Signal {
				t.Errorf("receipt signal %d escalated %v, want %d %v", rc.Signal, rc.Escalated, tc.end.Signal, tc.end.Escalated)
			}
			var js strings.Builder
			if err := rc.JSON(&js); err != nil || strings.Contains(js.String(), `"escalated"`) != tc.end.Escalated {
				t.Errorf("JSON escalated key = %v for escalated %v (%v)", strings.Contains(js.String(), `"escalated"`), tc.end.Escalated, err)
			}
		})
	}
}
