// SPDX-License-Identifier: Apache-2.0

package measure

import (
	"math"
	"strconv"
	"strings"
	"testing"
)

// TestCostTextShowsSmallCosts: a run that ended at its cost_usd limit of $0.002 by spending $0.002127 read
// "cost $0.00 est." in measure, as if it had been free, while its limit event said 0.002127 (the custom-agent
// POC, item 7). Below ten cents the amount now keeps two significant digits, down to a micro-dollar; from ten
// cents up it stays to the cent, so a large cost carries no noise.
func TestCostTextShowsSmallCosts(t *testing.T) {
	for _, tc := range []struct {
		v    float64
		want string
	}{
		{0, "$0.00"},
		{0.002127, "$0.0021"},
		{0.002, "$0.0020"},
		{0.05, "$0.050"},
		{0.0995, "$0.10"},
		{0.00995, "$0.010"},
		{0.094, "$0.094"},
		{0.1, "$0.10"},
		{0.277884, "$0.28"},
		{1.5, "$1.50"},
		{1234.5678, "$1234.57"},
		{0.000003, "$0.000003"},
		{0.0000123, "$0.000012"},
		{0.0000004, "<$0.000001"},
		// The decimals chosen and the digits printed come from one rounding: these once read "$0.000000" (a
		// nonzero amount shown as zero), "$0.0009", "$0.009", "$0.010", "$0.010", "$0.0010" and "$0.10", one
		// significant digit or rounded up past the amount.
		{5e-7, "<$0.000001"}, // its binary value is just under half a micro-dollar
		{4.9999999e-07, "<$0.000001"},
		{0.0000016, "$0.000002"}, // six decimals at most
		{0.00095, "$0.00095"},
		{0.0095, "$0.0095"},
		{0.0096, "$0.0096"},
		{0.0098, "$0.0098"},
		{0.00097, "$0.00097"},
		{0.096, "$0.096"},
		{0.0996, "$0.10"},
		{0.00996, "$0.010"},
		{math.Inf(1), "$+Inf"},
	} {
		if got := CostText(tc.v); got != tc.want {
			t.Errorf("CostText(%v) = %q, want %q", tc.v, got, tc.want)
		}
	}
	// Every amount from ten micro-dollars to ten cents reads within half a unit of its last printed digit, with
	// two significant digits (a carry to the next power of ten reads $0.010 or $0.10, still two).
	for v := 0.00001; v < 0.1; v *= 1.0007 {
		got := CostText(v)
		num := strings.TrimPrefix(got, "$")
		if digits := strings.TrimLeft(strings.ReplaceAll(num, ".", ""), "0"); len(digits) != 2 {
			t.Errorf("CostText(%v) = %q, want two significant digits", v, got)
		}
		printed, err := strconv.ParseFloat(num, 64)
		unit := math.Pow10(-(len(num) - strings.Index(num, ".") - 1))
		if err != nil || math.Abs(printed-v) > unit/2*(1+1e-9) {
			t.Errorf("CostText(%v) = %q, more than half a unit (%g) from the amount", v, got, unit)
		}
	}
	rep := &Report{EstCostUSD: 0.002127}
	if got := rep.Cost(); got != "$0.0021 est." {
		t.Errorf("Cost() = %q, want %q", got, "$0.0021 est.")
	}
}
