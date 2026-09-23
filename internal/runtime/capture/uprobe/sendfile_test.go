// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"slices"
	"testing"
)

// TestSendfileIsNeverHooked guards the decision recorded on SymSendfile and in R1. SSL_sendfile is
// exported by every OpenSSL 3.0+ libssl, so a binary carrying it is the ordinary case, and its arguments
// are (fd, offset, size, flags) rather than SSL_write's (buf, num): a probe placed on it by any of R1-R3's
// programs would read a file descriptor as a buffer pointer. Nothing this package produces may reference
// it — not a recorded offset, and not a probe.
func TestSendfileIsNeverHooked(t *testing.T) {
	t.Parallel()
	if slices.Contains(Symbols, SymSendfile) {
		t.Fatalf("SSL_sendfile is in Symbols: its arguments are not SSL_write's, and no program can read them")
	}
	const sendfileAt = 0x1300
	path := writeELF(t, elfOptions{
		Dynamic: map[string]uint64{SymWrite: 0x1100, SymSendfile: sendfileAt},
		BuildID: []byte{0x0f, 0x0e},
	})
	b, err := readBinary(path)
	if err != nil {
		t.Fatalf("readBinary: %v", err)
	}
	if b.Has(SymSendfile) {
		t.Errorf("the ELF reader recorded an offset for SSL_sendfile: %#x", b.Offsets[SymSendfile])
	}
	probes := probesFor(b)
	if len(probes) != 1 {
		t.Fatalf("probes = %v, want only the SSL_write one", probes)
	}
	for _, p := range probes {
		if p.Symbol == SymSendfile || p.Offset == sendfileAt {
			t.Errorf("a probe was placed on SSL_sendfile: %s", p)
		}
	}
}
