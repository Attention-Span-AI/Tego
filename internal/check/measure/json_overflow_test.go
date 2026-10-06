// SPDX-License-Identifier: Apache-2.0

package measure

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"
)

func TestJSONCostSurvivesLargeFiniteAndOverflowedEstimates(t *testing.T) {
	for _, tc := range []struct{ cost, want float64 }{
		{1.23456789, 1.234568}, {1e303, 1e303}, {math.MaxFloat64, math.MaxFloat64}, {math.Inf(1), math.MaxFloat64},
	} {
		cost, want := tc.cost, tc.want
		r := &Report{EstCostUSD: cost}
		var b bytes.Buffer
		if err := r.JSON(&b); err != nil {
			t.Fatalf("cost %g: %v", cost, err)
		}
		var got struct {
			Cost float64 `json:"est_cost_usd"`
		}
		if err := json.Unmarshal(b.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Cost != want {
			t.Errorf("cost %g encoded %g, want %g", cost, got.Cost, want)
		}
	}
}
