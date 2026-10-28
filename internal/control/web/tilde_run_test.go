// SPDX-License-Identifier: Apache-2.0

package web

import "testing"

// TestTildeRunShortensAgainstTheRunsHome: the Deny notice names the token as the ask card does,
// ~/.config/telemetry/token, when the run's home is a demo's with/home and not the dashboard user's; a file of the
// run's project reads ./confidential/plan.md (the demo video's Allowed once notice).
func TestTildeRunShortensAgainstTheRunsHome(t *testing.T) {
	cases := []struct{ p, home, cwd, want string }{
		{"/s/with/home/.config/telemetry/token", "/s/with/home", "/s/with/proj", "~/.config/telemetry/token"},
		{"/s/with/proj/confidential/plan.md", "/s/with/home", "/s/with/proj", "./confidential/plan.md"},
		{"/s/with/homework/x", "/s/with/home", "", "/s/with/homework/x"},
		{"/elsewhere/x", "", "", "/elsewhere/x"},
	}
	for _, c := range cases {
		if got := runPathIn(c.p, c.home, c.cwd); got != c.want {
			t.Errorf("runPathIn(%q, %q, %q) = %q, want %q", c.p, c.home, c.cwd, got, c.want)
		}
	}
}
