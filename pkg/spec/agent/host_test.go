// SPDX-License-Identifier: Apache-2.0

package agent

import "testing"

func TestCanonicalHost(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"api.anthropic.com", "api.anthropic.com"},
		{"API.Anthropic.COM", "api.anthropic.com"},
		{" api.anthropic.com ", "api.anthropic.com"},
		{"api.anthropic.com:443", "api.anthropic.com"},
		{"api.anthropic.com.", "api.anthropic.com"},
		{"API.anthropic.com.:8443", "api.anthropic.com"},
		{"api.anthropic.com:", "api.anthropic.com"},
		{"127.0.0.1", "127.0.0.1"},
		{"127.0.0.1:8080", "127.0.0.1"},
		{"::1", "::1"},
		{"[::1]", "::1"},
		{"[::1]:443", "::1"},
		{"2001:DB8::1", "2001:db8::1"},
		{"[2001:DB8::1]:8443", "2001:db8::1"},
		{"[fe80::1%eth0]:443", "fe80::1%eth0"},
		{"localhost.", "localhost"},
		{"Localhost:11434", "localhost"},
		{"0:0::1", "::1"},
		{"[0:0:0:0:0:0:0:1]:443", "::1"},
		{"::ffff:127.0.0.1", "127.0.0.1"},
		{"::ffff:7f00:1", "127.0.0.1"},
		{"[::FFFF:7F00:1]:8080", "127.0.0.1"},
		{"2001:0db8:0000::0001", "2001:db8::1"},
	} {
		if got := CanonicalHost(tc.in); got != tc.want {
			t.Errorf("CanonicalHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if got := CanonicalHost(CanonicalHost(tc.in)); got != tc.want {
			t.Errorf("CanonicalHost is not idempotent on %q: %q", tc.in, got)
		}
	}
}
