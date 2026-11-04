// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSessionSocketSelector(t *testing.T) {
	for _, tc := range []struct {
		name, runtime string
		fallback      bool
	}{
		{"short", "/run/private", false},
		{"103 bytes", "/" + strings.Repeat("x", 80), false},
		{"104 bytes", "/" + strings.Repeat("x", 81), true},
		{"utf8 bytes", "/" + strings.Repeat("é", 41), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := filepath.Join(tc.runtime, "cc-socks", "9999999.sock")
			if tc.fallback {
				want = "/tmp/cc-socks-1000/9999999.sock"
			}
			if got, err := sessionSocketPath(tc.runtime, 1000, 9999999); err != nil || got != want {
				t.Fatalf("selector = %q, %v, want %q", got, err, want)
			}
		})
	}
}
