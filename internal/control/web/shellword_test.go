// SPDX-License-Identifier: Apache-2.0

package web

import "testing"

// TestShellWord: the CLI twin of a live block quotes a value a shell would split or expand, and leaves a plain one.
func TestShellWord(t *testing.T) {
	for in, want := range map[string]string{
		"curl":             "curl",
		" /usr/bin/curl ":  "/usr/bin/curl",
		"example.com:443":  "example.com:443",
		"/tmp/my dir/":     "'/tmp/my dir/'",
		"/tmp/$HOME":       "'/tmp/$HOME'",
		"it's":             `'it'\''s'`,
		"":                 "''",
		"[::1]:80":         "'[::1]:80'",
		"/tmp/a;rm -rf /x": "'/tmp/a;rm -rf /x'",
	} {
		if got := shellWord(in); got != want {
			t.Errorf("shellWord(%q) = %q, want %q", in, got, want)
		}
	}
}
