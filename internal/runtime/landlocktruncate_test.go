// SPDX-License-Identifier: Apache-2.0

package runtime

import "testing"

type saysTruncate bool

func (s saysTruncate) LandlockDecidesTruncate() bool { return bool(s) }

// TestLandlockDecidesTruncateIsFailClosed: the supervisor continues a notified truncate(2) only where the run's handle
// says its Landlock ruleset decides it (ABI 3). A handle that does not say, or says no, leaves the option false and the
// supervisor refuses, so a wiring slip over-refuses and never lets a file be emptied below ABI 3.
func TestLandlockDecidesTruncateIsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    any
		want bool
	}{
		{"a handle that says yes", saysTruncate(true), true},
		{"a handle that says no", saysTruncate(false), false},
		{"a handle that does not say", struct{}{}, false},
		{"no handle", nil, false},
	} {
		if got := landlockDecidesTruncate(tc.h); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
