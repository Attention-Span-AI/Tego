// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestSharedTracingMakesCoverageUncertain(t *testing.T) {
	for _, why := range []string{"bpf-trampoline-miss/shared-build", "bpf-trampoline-counter-unavailable"} {
		t.Run(why, func(t *testing.T) {
			lines := pausedAndBlockedRun(line{kind: record.KindGap, at: 8 * time.Second,
				payload: record.GapPayload{What: record.GapRecord, Why: why, Count: 17}})
			lines[0] = start("forwarder", true)
			rc := compute(t, lines, Options{})
			words := coverageFields(rc)["record"]
			if rc.Coverage.Complete || !strings.Contains(words, "uncertain") || strings.Contains(words, "knows it missed") {
				t.Errorf("a shared counter cannot establish this run's loss: %+v", rc.Coverage)
			}
			if why == "bpf-trampoline-miss/shared-build" && (!strings.Contains(words, "17") ||
				!strings.Contains(words, "other runs or ungoverned tasks")) {
				t.Errorf("receipt discards the shared skip count's meaning: %q", words)
			}
			var text bytes.Buffer
			if err := rc.Text(&text); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(text.String(), "uncertain") || strings.Contains(text.String(), "17 events lost") {
				t.Errorf("receipt text overclaims: %s", text.String())
			}
		})
	}
}
