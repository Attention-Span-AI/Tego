// SPDX-License-Identifier: Apache-2.0

package execpin

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// referenceVectors are the 64 published SipHash-2-4 vectors (Aumasson and Bernstein, "SipHash: a fast short-input
// PRF", Appendix A, and the reference implementation's vectors.h): the key is bytes 00..0f, vector i hashes bytes
// 00..i-1, and each digest is written as its 8 output bytes, low byte first.
var referenceVectors = [64]string{
	"310e0edd47db6f72", "fd67dc93c539f874", "5a4fa9d909806c0d", "2d7efbd796666785",
	"b7877127e09427cf", "8da699cd64557618", "cee3fe586e46c9cb", "37d1018bf50002ab",
	"6224939a79f5f593", "b0e4a90bdf82009e", "f3b9dd94c5bb5d7a", "a7ad6b22462fb3f4",
	"fbe50e86bc8f1e75", "903d84c02756ea14", "eef27a8e90ca23f7", "e545be4961ca29a1",
	"db9bc2577fcc2a3f", "9447be2cf5e99a69", "9cd38d96f0b3c14b", "bd6179a71dc96dbb",
	"98eea21af25cd6be", "c7673b2eb0cbf2d0", "883ea3e395675393", "c8ce5ccd8c030ca8",
	"94af49f6c650adb8", "eab8858ade92e1bc", "f315bb5bb835d817", "adcf6b0763612e2f",
	"a5c91da7acaa4dde", "716595876650a2a6", "28ef495c53a387ad", "42c341d8fa92d832",
	"ce7cf2722f512771", "e37859f94623f3a7", "381205bb1ab0e012", "ae97a10fd434e015",
	"b4a31508beff4d31", "81396229f0907902", "4d0cf49ee5d4dcca", "5c73336a76d8bf9a",
	"d0a704536ba93e0e", "925958fcd6420cad", "a915c29bc8067318", "952b79f3bc0aa6d4",
	"f21df2e41d4535f9", "87577519048f53a9", "10a56cf5dfcd9adb", "eb75095ccd986cd0",
	"51a9cb9ecba312e6", "96afadfc2ce666c7", "72fe52975a4364ee", "5a1645b276d592a1",
	"b274cb8ebf87870a", "6f9bb4203de7b381", "eaecb2a30b22a87f", "9924a43cc1315724",
	"bd838d3aafbf8db7", "0b1a2a3265d51aea", "135079a3231ce660", "932b2846e4d70666",
	"e1915f5cb1eca46c", "f325965ca16d629f", "575ff28e60381be5", "724506eb4c328a95",
}

// referenceKey and referenceMessage are the published vectors' key and message bytes (00..0f and 00..3f).
func referenceKey() Key {
	var k Key
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func referenceMessage() []byte {
	m := make([]byte, 64)
	for i := range m {
		m[i] = byte(i)
	}
	return m
}

func TestSum64MatchesTheReferenceVectors(t *testing.T) {
	k, m := referenceKey(), referenceMessage()
	for i, want := range referenceVectors {
		b, err := hex.DecodeString(want)
		if err != nil {
			t.Fatal(err)
		}
		if got := Sum64(k, m[:i]); got != binary.LittleEndian.Uint64(b) {
			t.Errorf("vector %d: Sum64 = %016x, want %s (bytes low first)", i, got, want)
		}
	}
}

// TestMACFramesDomainAndLength holds MAC to Sum64 over the framed input, and shows the frame separates what an
// unframed hash would not: the same bytes under two domains, and an input against its own extension.
func TestMACFramesDomainAndLength(t *testing.T) {
	k, m := referenceKey(), referenceMessage()
	for i := 0; i <= len(m); i++ {
		for _, d := range []byte{DomainCovered, DomainScript, DomainTail, DomainName, DomainPath} {
			framed := append([]byte{d, byte(i), 0, 0, 0}, m[:i]...)
			if got, want := MAC(k, d, m[:i]), Sum64(k, framed); got != want {
				t.Fatalf("MAC(domain %d, %d bytes) = %016x, want Sum64 of the framed input %016x", d, i, got, want)
			}
		}
	}
	if MAC(k, DomainCovered, []byte("git\x00")) == MAC(k, DomainScript, []byte("git\x00")) {
		t.Error("two domains share a MAC over the same bytes")
	}
	if MAC(k, DomainCovered, []byte("a\x00")) == MAC(k, DomainCovered, []byte("a\x00b\x00")) {
		t.Error("a prefix and its extension share a MAC")
	}
	var other Key
	other[0] = 1
	if MAC(k, DomainCovered, []byte("rm\x00")) == MAC(other, DomainCovered, []byte("rm\x00")) {
		t.Error("two keys share a MAC")
	}
}

// TestMACLongInputCrossesEveryAlignment covers the lengths the plane's chunked reader treats apart: within a word,
// across a 256-byte chunk, and the 128 KiB bound, each against the byte-at-a-time reference.
func TestMACLongInputCrossesEveryAlignment(t *testing.T) {
	k := referenceKey()
	buf := make([]byte, 128<<10)
	for i := range buf {
		buf[i] = byte(i*7 + i>>8)
	}
	for _, n := range []int{0, 1, 3, 7, 8, 9, 255, 256, 257, 511, 4093, len(buf)} {
		framed := append([]byte{DomainCovered, 0, 0, 0, 0}, buf[:n]...)
		binary.LittleEndian.PutUint32(framed[1:5], uint32(n))
		if got, want := MAC(k, DomainCovered, buf[:n]), Sum64(k, framed); got != want {
			t.Errorf("%d bytes: MAC %016x, framed Sum64 %016x", n, got, want)
		}
	}
}
