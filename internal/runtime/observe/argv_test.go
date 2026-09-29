// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"slices"
	"testing"
)

// TestSplitArgvKeepsEmptyArguments: each argument in the blob carries its own NUL, so only the last one's is
// trimmed and an empty argument, trailing or alone, stays in the recorded argv.
func TestSplitArgvKeepsEmptyArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		blob string
		want []string
	}{
		{"plain", "git\x00status\x00", []string{"git", "status"}},
		{"a trailing empty argument", "git\x00commit\x00-m\x00\x00", []string{"git", "commit", "-m", ""}},
		{"an empty argument inside", "tool\x00\x00x\x00", []string{"tool", "", "x"}},
		{"one empty argument", "\x00", []string{""}},
		{"no argv", "", nil},
		{"truncated inside the last argument", "git\x00comm", []string{"git", "comm"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := splitArgv(nil, []byte(tc.blob)); !slices.Equal(got, tc.want) {
				t.Errorf("splitArgv(%q) = %q, want %q", tc.blob, got, tc.want)
			}
		})
	}
}
