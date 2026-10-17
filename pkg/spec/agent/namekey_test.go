// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"encoding/binary"
	"strings"
	"testing"
)

// TestNameKeyVectors pins ADR 0043 D9's name key in both byte orders: the plane is built bpfel and bpfeb, and the
// kernel's key (bpf/decide_names.h) is FNV-1a over the name's words as its host loads them, so a big-endian host's
// launcher must write the key its kernel computes. The vectors were computed by a bytewise reference (each word's
// bytes shifted into place by hand); NameKeyIn must give them for both orders, and NameKey this host's, which the
// host's encoding/binary order names. The guest's TestPlaneNameEntriesDecide holds the little-endian kernel to the
// same keys, and bpf/tests TestNameKeyConstantsMatchGo holds the C constants to these.
func TestNameKeyVectors(t *testing.T) {
	t.Parallel()
	for _, v := range []struct {
		literal  string
		prefix   bool
		le, be   uint64
		foldedAs string
	}{
		{".env", false, 0x1986a807b79b0b7d, 0x03544ff68601b113, ".env"},
		{".env.", true, 0x59867ad9b79b09ca, 0x43544f371801af60, ".env."},
		{".ENV.Local", false, 0x24f8eef2fbbd91d6, 0x3359831d4cc99c2c, ".env.local"},
		{"secret.json", false, 0x0f1fe1ae31fe121c, 0x077d7da57f136be4, "secret.json"},
		{"config-key", true, 0x628b42fb7ed54273, 0x696be1e6583d94e4, "config-key"},
	} {
		le, ok1 := NameKeyIn(v.literal, v.prefix, false)
		be, ok2 := NameKeyIn(v.literal, v.prefix, true)
		if !ok1 || !ok2 || le != v.le || be != v.be {
			t.Errorf("NameKeyIn(%q, %v) = %#016x (LE), %#016x (BE), want %#016x, %#016x", v.literal, v.prefix, le, be, v.le, v.be)
		}
		if le == be {
			t.Errorf("%q: the two orders give one key, so the vector tests nothing of the order", v.literal)
		}
		native, _ := NameKey(v.literal, v.prefix)
		want := v.le
		if binary.NativeEndian.Uint16([]byte{0, 1}) == 1 {
			want = v.be
		}
		if native != want {
			t.Errorf("NameKey(%q) = %#016x on this host, want %#016x", v.literal, native, want)
		}
		if f, _ := NameKey(v.foldedAs, v.prefix); f != native {
			t.Errorf("NameKey(%q) differs from its folded spelling %q's: keys are over folded bytes", v.literal, v.foldedAs)
		}
		// Bit 63 is clear, bit 62 is the form, and no key is 0 (the config row's).
		if native == 0 || native&(1<<63) != 0 || (native&(1<<62) != 0) != v.prefix {
			t.Errorf("NameKey(%q, %v) = %#016x: bit 63 must be clear and bit 62 the form", v.literal, v.prefix, native)
		}
	}
	for _, bad := range []string{"", strings.Repeat("x", 256)} {
		if _, ok := NameKeyIn(bad, false, true); ok {
			t.Errorf("NameKeyIn(%d bytes) keyed a literal the kernel cannot carry", len(bad))
		}
	}
}
