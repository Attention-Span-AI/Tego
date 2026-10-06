// SPDX-License-Identifier: Apache-2.0

package drift

import "testing"

// TestAggregateKeepsSSLRequestUse: two runs that each used their models[] entry only through the forwarder
// use it for the agent, so the aggregate reports nothing undone and no drift (R14, R17).
func TestAggregateKeepsSSLRequestUse(t *testing.T) {
	var reps []*Report
	for range 2 {
		lines := []map[string]any{runStartLine(), captureConnectLine(40001), sslRequestLine("anthropic"), runEndLine()}
		rep, err := Compute(readerOver(t, modelLedger(lines...)), modelTable(anthropicAt(modelPort)))
		if err != nil {
			t.Fatalf("compute: %v", err)
		}
		reps = append(reps, rep)
	}
	agg, err := Aggregate(reps)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if len(agg.Undone) != 0 || agg.Drifted() {
		t.Errorf("undone = %v, drifted = %v; want neither", agg.Undone, agg.Drifted())
	}
}
