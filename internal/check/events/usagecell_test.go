// SPDX-License-Identifier: Apache-2.0

package events

import "testing"

// TestUsageCellNeverWraps: a count at the top of the int range must not print as a negative number.
func TestUsageCellNeverWraps(t *testing.T) {
	p := map[string]any{"usage": map[string]any{"input": float64(1 << 63), "output": float64(5)}}
	if got, want := usageCell(p), "in=9223372036854776000 out=5"; got != want {
		t.Fatalf("usageCell = %q, want %q", got, want)
	}
	p = map[string]any{"usage": map[string]any{"input": float64(7), "output": float64(5)}}
	if got, want := usageCell(p), "in=7 out=5"; got != want {
		t.Fatalf("usageCell = %q, want %q", got, want)
	}
}
