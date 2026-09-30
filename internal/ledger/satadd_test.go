// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"math"
	"testing"
)

func TestSatAddHoldsAtMax(t *testing.T) {
	for _, tc := range []struct{ a, b, want uint64 }{
		{1, 2, 3}, {math.MaxUint64, 1, math.MaxUint64}, {1 << 63, 1 << 63, math.MaxUint64}, {math.MaxUint64, 0, math.MaxUint64},
	} {
		if got := SatAdd(tc.a, tc.b); got != tc.want {
			t.Errorf("SatAdd(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
