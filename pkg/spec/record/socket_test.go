// SPDX-License-Identifier: Apache-2.0

package record

import "testing"

func TestSocketTriple(t *testing.T) {
	for _, c := range []struct {
		fam, typ, proto int32
		want            string
	}{
		{2, 1, 132, "AF_INET SOCK_STREAM protocol 132"},
		{40, 1, 0, "AF_VSOCK SOCK_STREAM protocol 0"},
		{2, 1 | 0x80800, 6, "AF_INET SOCK_STREAM protocol 6"}, // SOCK_NONBLOCK|SOCK_CLOEXEC flags are dropped
		{45, 1, 0, "family 45 SOCK_STREAM protocol 0"},        // AF_MCTP: numbered, not named
		{1, 9, 0, "AF_UNIX type 9 protocol 0"},
		{17, 10, 3, "AF_PACKET SOCK_PACKET protocol 3"},
	} {
		if got := SocketTriple(c.fam, c.typ, c.proto); got != c.want {
			t.Errorf("SocketTriple(%d,%d,%d) = %q, want %q", c.fam, c.typ, c.proto, got, c.want)
		}
	}
}

// TestSocketOption is the refused setsockopt line's target (ADR 0018 (7)): TCP_ULP with the name as the kernel reads it
// (up to the first NUL, at most 15 bytes), quoted so a byte that is not printable stays readable, or "(name unread)"
// where the supervisor could not read it; any other option by its numbers.
func TestSocketOption(t *testing.T) {
	for _, c := range []struct {
		level, option int32
		name          []byte
		read          bool
		want          string
	}{
		{6, 31, []byte("smc"), true, `TCP_ULP "smc"`},
		{6, 31, []byte("tls\x00junk"), true, `TCP_ULP "tls"`},
		{6, 31, []byte("abcdefghijklmnopq"), true, `TCP_ULP "abcdefghijklmno"`},
		{6, 31, []byte("s\x01c"), true, `TCP_ULP "s\x01c"`},
		{6, 31, nil, true, `TCP_ULP ""`},
		{6, 31, nil, false, "TCP_ULP (name unread)"},
		{6, 1, nil, false, "setsockopt level 6 option 1"},
		{0, 31, []byte("smc"), true, "setsockopt level 0 option 31"},
	} {
		if got := SocketOption(c.level, c.option, c.name, c.read); got != c.want {
			t.Errorf("SocketOption(%d, %d, %q, %v) = %q, want %q", c.level, c.option, c.name, c.read, got, c.want)
		}
	}
}
