// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// TestDecode covers R15's codings, the raw-deflate fallback real servers force on us, and the stacked
// Content-Encoding list.
func TestDecode(t *testing.T) {
	const payload = "the quick brown fox jumps over the lazy dog, repeatedly and at length"
	rawDeflate := func(t *testing.T, b []byte) []byte {
		t.Helper()
		var out bytes.Buffer
		w, err := flate.NewWriter(&out, flate.DefaultCompression)
		if err != nil {
			t.Fatalf("flate writer: %v", err)
		}
		mustWrite(t, w, b)
		mustClose(t, w)
		return out.Bytes()
	}
	cases := []struct {
		name     string
		encoding string
		encode   func(*testing.T, []byte) []byte
	}{
		{"identity", "", func(_ *testing.T, b []byte) []byte { return b }},
		{"identity named", "identity", func(_ *testing.T, b []byte) []byte { return b }},
		{"gzip", "gzip", gzipBytes},
		{"gzip cased", "GZip", gzipBytes},
		{"deflate zlib", "deflate", zlibBytes},
		{"deflate raw", "deflate", rawDeflate},
		{"br", "br", brotliBytes},
		{"zstd", "zstd", zstdBytes},
		{"stacked", "gzip, br", func(t *testing.T, b []byte) []byte { return brotliBytes(t, gzipBytes(t, b)) }},
		{"spaces and identity", " gzip , identity ", gzipBytes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decode(tc.encode(t, []byte(payload)), tc.encoding, 0)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if string(got) != payload {
				t.Errorf("decode = %q, want %q", got, payload)
			}
		})
	}
}

// TestDecodeErrors covers what a malformed or unknown coding does: an error and whatever prefix decoded,
// never a panic (R15, R18).
func TestDecodeErrors(t *testing.T) {
	cases := []struct {
		name     string
		body     []byte
		encoding string
	}{
		{"unknown coding", []byte("hello"), "exotic"},
		{"gzip garbage", []byte("not a gzip stream at all"), "gzip"},
		{"zstd garbage", []byte("not a zstd frame"), "zstd"},
		{"empty gzip", nil, "gzip"},
		{"truncated gzip", gzipHalf(), "gzip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decode(tc.body, tc.encoding, 0)
			if err == nil {
				t.Fatalf("want an error")
			}
			if !errors.Is(err, ErrMalformed) {
				t.Errorf("error = %v, want ErrMalformed", err)
			}
		})
	}
}

// gzipHalf is a gzip stream cut in the middle, the shape of edge case #18.
func gzipHalf() []byte {
	var out bytes.Buffer
	w := newGzipWriterForTest(&out)
	_, _ = w.Write([]byte(strings.Repeat("compress me please ", 200)))
	_ = w.Close()
	b := out.Bytes()
	return b[:len(b)/2]
}

// TestEmptyDeflateBody is the degenerate body: zero bytes decode to zero bytes without an error.
func TestEmptyDeflateBody(t *testing.T) {
	got, err := decode(nil, "deflate", 0)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("decode = %q, want empty", got)
	}
}

// TestIsZlibHeader covers the sniff that tells RFC 1950 from a bare RFC 1951 stream.
func TestIsZlibHeader(t *testing.T) {
	cases := []struct {
		in   []byte
		want bool
	}{
		{[]byte{0x78, 0x9c}, true},
		{[]byte{0x78, 0x01}, true},
		{[]byte{0x78, 0xda}, true},
		{[]byte{0x78, 0x9d}, false}, // right method, wrong check
		{[]byte{0x1f, 0x8b}, false}, // gzip magic
		{[]byte{0x08, 0x3c}, false}, // FDICT set
		{[]byte{0x88, 0x1c}, false}, // CINFO 8
		{[]byte{0x00}, false},
		{nil, false},
	}
	for _, tc := range cases {
		if got := isZlibHeader(tc.in); got != tc.want {
			t.Errorf("isZlibHeader(%x) = %t, want %t", tc.in, got, tc.want)
		}
	}
}

// TestDecodeMaxBody covers the optional bound a caller may set on a decoded body; R14's default is no
// bound at all.
func TestDecodeMaxBody(t *testing.T) {
	body := gzipBytes(t, []byte(strings.Repeat("x", 4096)))
	got, err := decode(body, "gzip", 100)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 100 {
		t.Errorf("decode = %d bytes, want the 100-byte bound", len(got))
	}
}

// TestSplitEncodings covers the header splitter.
func TestSplitEncodings(t *testing.T) {
	cases := map[string][]string{
		"":                  nil,
		"identity":          nil,
		"gzip":              {"gzip"},
		" GZIP , br ":       {"gzip", "br"},
		"gzip,,identity,br": {"gzip", "br"},
	}
	for in, want := range cases {
		got := splitEncodings(in)
		if len(got) != len(want) {
			t.Errorf("splitEncodings(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("splitEncodings(%q) = %v, want %v", in, got, want)
				break
			}
		}
	}
}

// TestZstdWindowIsCappedBeforeItIsAllocated: a zstd frame header names the window its decoder must keep,
// and the decoder allocates that window before it decodes a byte of the frame. Left at the library's
// default the cap is 512 MiB, so a few bytes off the wire made the launcher allocate hundreds of MiB, once
// per body, outside every bound capture keeps. RFC 9659 §3 caps the "zstd" content coding at 8 MB; a frame
// declaring more is a decode error here (R15), and costs no more than the frame it came in.
func TestZstdWindowIsCappedBeforeItIsAllocated(t *testing.T) {
	magic := []byte{0x28, 0xb5, 0x2f, 0xfd}
	// One raw block holding one byte, marked last: three header bytes (Last_Block=1, Block_Type=raw,
	// Block_Size=1) and the byte.
	block := []byte{0x09, 0x00, 0x00, 'A'}
	frame := func(header ...byte) []byte {
		out := append(append([]byte{}, magic...), header...)
		return append(out, block...)
	}
	cases := []struct {
		name string
		body []byte
	}{
		// Frame_Header_Descriptor 0: a Window_Descriptor follows. Exponent 19, mantissa 0 is a
		// window of 1 << (10+19) = 512 MiB, the library's own ceiling.
		{"a declared 512 MiB window", frame(0x00, 19<<3)},
		// Single_Segment_Flag with an 8-byte Frame_Content_Size: the window is the content size,
		// here 400 MiB, which is under the library's ceiling and was allocated whole.
		{"a single segment of 400 MiB", frame(0xe0, 0, 0, 0, 0x19, 0, 0, 0, 0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			_, err := decode(tc.body, EncodingZstd, 0)
			runtime.ReadMemStats(&after)
			if !errors.Is(err, ErrMalformed) {
				t.Errorf("decode error = %v, want ErrMalformed: a window past RFC 9659's 8 MB is not a "+
					"body this package decodes", err)
			}
			if got := after.TotalAlloc - before.TotalAlloc; got > 2*ZstdMaxWindow {
				t.Errorf("a %d-byte frame allocated %d bytes, want at most %d: the window it declared "+
					"was allocated before it was refused", len(tc.body), got, 2*ZstdMaxWindow)
			}
		})
	}

	t.Run("a window at the cap still decodes", func(t *testing.T) {
		payload := bytes.Repeat([]byte("window "), 1<<20)
		var buf bytes.Buffer
		w, err := zstd.NewWriter(&buf, zstd.WithWindowSize(ZstdMaxWindow))
		if err != nil {
			t.Fatal(err)
		}
		mustWrite(t, w, payload)
		mustClose(t, w)
		got, err := decode(buf.Bytes(), EncodingZstd, 0)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("decoded %d bytes, want the %d encoded", len(got), len(payload))
		}
	})
}

// TestXGzipIsGzip: RFC 9110 §8.4.1.3 says a recipient SHOULD treat x-gzip as gzip, and the forwarder,
// which shares this table, always did.
func TestXGzipIsGzip(t *testing.T) {
	const payload = "an old server's name for gzip"
	got, err := decode(gzipBytes(t, []byte(payload)), "X-Gzip", 0)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(got) != payload {
		t.Errorf("decode = %q, want %q", got, payload)
	}
	if !SupportedEncoding("x-gzip") {
		t.Error("SupportedEncoding(x-gzip) = false")
	}
}

// TestAListPastMaxCodingsIsNotDecoded: a Content-Encoding list longer than MaxCodings is refused before
// any layer is opened, so the body is the wire's bytes and costs no decoder, however many layers the
// header names; a list at the cap still decodes. Decoded one after another, a thousand gzip layers were a
// thousand decoders and a thousand passes over the body, for a header of five bytes a layer.
func TestAListPastMaxCodingsIsNotDecoded(t *testing.T) {
	const payload = "a body under more codings than any server applies"
	wire := []byte(payload)
	names := make([]string, 1000)
	for i := range names {
		wire = gzipBytes(t, wire)
		names[i] = EncodingGzip
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got, err := decode(wire, strings.Join(names, ", "), 0)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrMalformed) {
		t.Errorf("decode error = %v, want ErrMalformed for a list of %d codings", err, len(names))
	}
	if !bytes.Equal(got, wire) {
		t.Errorf("decode kept %d bytes, want the %d the wire carried", len(got), len(wire))
	}
	if n := after.TotalAlloc - before.TotalAlloc; n > 1<<20 {
		t.Errorf("refusing a %d-layer list allocated %d bytes: its layers were opened", len(names), n)
	}

	stacked := []byte(payload)
	list := make([]string, MaxCodings)
	for i := range list {
		stacked = gzipBytes(t, stacked)
		list[i] = EncodingGzip
	}
	if got, err := decode(stacked, strings.Join(list, ","), 0); err != nil || string(got) != payload {
		t.Errorf("a list of %d codings: decode = %q, %v; want the payload", MaxCodings, got, err)
	}
}

func r2gzip(t *testing.T, in []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w, _ := gzip.NewWriterLevel(&b, gzip.BestCompression)
	_, _ = w.Write(in)
	_ = w.Close()
	return b.Bytes()
}

func r2brotli(t *testing.T, in []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := brotli.NewWriterLevel(&b, brotli.BestCompression)
	_, _ = w.Write(in)
	_ = w.Close()
	return b.Bytes()
}

// One 32 KiB capture chunk carries many small compressed requests; each decodes to MaxBody, none of it counted
// by the Budget, and all of them are live together in the slice one Feed returns.
func TestOneChunkDecodesManyBombs(t *testing.T) {
	zeros := make([]byte, DefaultMaxBody)
	variants := map[string][]byte{}
	variants["gzip, gzip"] = r2gzip(t, r2gzip(t, zeros))
	variants["br"] = r2brotli(t, zeros)
	for enc, body := range variants {
		t.Logf("%q: %d wire bytes decode to %d", enc, len(body), len(zeros))
	}
	enc := "br"
	body := variants[enc]
	if len(variants["gzip, gzip"]) < len(body) {
		enc, body = "gzip, gzip", variants["gzip, gzip"]
	}
	var chunk bytes.Buffer
	n := 0
	for {
		one := fmt.Sprintf("POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Encoding: %s\r\n"+
			"Content-Length: %d\r\n\r\n", enc, len(body))
		if chunk.Len()+len(one)+len(body) > 32<<10 || n == 6 {
			break
		}
		chunk.WriteString(one)
		chunk.Write(body)
		n++
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	a := NewAssembler(Options{})
	key := ConnKey{PidTgid: 1, SSLPtr: 1}
	msgs, err := a.Feed(key, DirRequest, Chunk{Data: chunk.Bytes(), Seq: 1})
	runtime.ReadMemStats(&after)
	live := uint64(0)
	for _, m := range msgs {
		live += uint64(len(m.Body))
	}
	t.Logf("%d requests in %d bytes: Feed returned %d messages holding %d MiB of decoded body; heap in use "+
		"%d -> %d MiB, TotalAlloc +%d MiB; budget used %d; err=%v", n, chunk.Len(), len(msgs), live>>20,
		before.HeapInuse>>20, after.HeapInuse>>20, (after.TotalAlloc-before.TotalAlloc)>>20, a.Budget().Used(), err)
	if live > uint64(a.Budget().Limit()) {
		t.Errorf("one 32 KiB chunk made the launcher hold %d MiB of decoded bodies, past the %d MiB budget "+
			"the uprobe path is meant to be bounded by", live>>20, a.Budget().Limit()>>20)
	}
	// What one call decodes is bounded together at one body's worth, the rest is cut and counted, and the reservations
	// go back when the call returns.
	if live > DefaultMaxBody {
		t.Errorf("one Feed handed back %d MiB of decoded bodies, more than one MaxBody", live>>20)
	}
	if got := gapCount(a.Gaps(), GapSizeCap); got < int64(n-1) {
		t.Errorf("size-cap gaps = %d, want one per body the allowance cut (%d): %v", got, n-1, a.Gaps())
	}
	if used := a.Budget().Used(); used != 0 {
		t.Errorf("budget still holds %d bytes after the Feed returned", used)
	}
	runtime.KeepAlive(msgs)
}

// A request R11 refuses is never decoded, and it is handed over as a refused line with no body.
func TestRefusedRequestIsNotDecoded(t *testing.T) {
	bomb := r2brotli(t, make([]byte, 8<<20))
	one := fmt.Sprintf("POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Encoding: br\r\n"+
		"Content-Length: %d\r\n\r\n", len(bomb))
	a := NewAssembler(Options{})
	var decodedBytes, refused int
	for i := 0; i < DefaultMaxPipeline+4; i++ {
		msgs, err := a.Feed(testKey, DirRequest, Chunk{Data: append([]byte(one), bomb...)})
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range msgs {
			if m.Refused {
				refused++
				if m.Body != nil || m.WireBytes != len(bomb) {
					t.Errorf("refused request kept %d body bytes, wire %d", len(m.Body), m.WireBytes)
				}
				continue
			}
			decodedBytes += len(m.Body)
		}
	}
	if refused != 4 {
		t.Errorf("refused = %d, want 4 past a depth of %d", refused, DefaultMaxPipeline)
	}
	if decodedBytes != DefaultMaxPipeline*8<<20 {
		t.Errorf("decoded %d bytes, want the %d queued requests' alone", decodedBytes, DefaultMaxPipeline)
	}
}
