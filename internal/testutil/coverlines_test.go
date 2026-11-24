// SPDX-License-Identifier: Apache-2.0

package testutil

import "testing"

func TestStripCoverageDiagnostics(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"no diagnostics", "tego __reap: refused\n", "tego __reap: refused\n"},
		{"the unset warning", "tego __reap: refused\nwarning: GOCOVERDIR not set, no coverage data emitted\n", "tego __reap: refused\n"},
		{"both emit errors", "{\"accept\":38}\nerror: coverage meta-data emit failed: creating meta-data file /x/y: open /x/y: permission denied\n" +
			"error: coverage counter data emit failed: creating counter data file /x/z: open /x/z: permission denied\n", "{\"accept\":38}\n"},
		{"unterminated last line", "13\nwarning: GOCOVERDIR not set, no coverage data emitted", "13\n"},
		{"the program's own error is kept", "error: coverage of the plan is partial\nwarning: GOCOVERDIR is unset\n",
			"error: coverage of the plan is partial\nwarning: GOCOVERDIR is unset\n"},
		{"a line that only contains one is kept", "tego: warning: GOCOVERDIR not set, no coverage data emitted\n",
			"tego: warning: GOCOVERDIR not set, no coverage data emitted\n"},
	} {
		if got := string(stripCoverageDiagnostics([]byte(tc.in))); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
