// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/gaps"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestGapJSONPreservesSharedSkippedExecutions(t *testing.T) {
	var tally gaps.Tally
	e := &record.Event{Kind: record.KindGap}
	if err := e.SetPayload(record.GapPayload{What: record.GapRecord, Why: gaps.SharedTracingSkip, Count: 17}); err != nil {
		t.Fatal(err)
	}
	tally.Add(e)
	body, err := json.Marshal(gapObjects(tally.Counts()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"lost":0`) || !strings.Contains(string(body), `"shared_skipped_executions":17`) {
		t.Fatalf("gap JSON loses counter scope: %s", body)
	}
}
