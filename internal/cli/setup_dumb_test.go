// SPDX-License-Identifier: Apache-2.0

package cli

import "testing"

func guideDumbRoutes() []guidePTYRoute {
	return []guidePTYRoute{{"dumb", []guidePTYStep{
		{"Which agent do you want to supervise?", "1\n"},
		{"How do you want to log in to Claude Code?", "2\n"},
		{"Paste your Anthropic API key", "test-token\n"},
		{"Save the login for later sessions?", "2\n"},
		{"Which project should Claude Code work in?", "2\n"},
		{"Which rules should Claude Code follow?", "3\n"},
		{"Which rules?", "0\n"},
		{"Other hosts it may reach", ""},
	}}}
}

func TestGuideDumbInterrupt(t *testing.T) {
	for _, route := range guideDumbRoutes() {
		for _, target := range []int{0, 2, 7} {
			for _, how := range []string{"key", "signal", "term", "double"} {
				t.Run(route.steps[target].prompt+"/"+how, func(t *testing.T) { t.Parallel(); runGuidePTY(t, route, target, how, false) })
			}
		}
	}
}
