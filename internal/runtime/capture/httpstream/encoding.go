// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// The content codings R15 names. Anything else is left encoded: the bytes still reach the blob, and
// ContentEncoding says what they are, which is strictly better than guessing.
const (
	EncodingIdentity = "identity"
	EncodingGzip     = "gzip"
	// EncodingXGzip is the name RFC 9110 §8.4.1.3 says a recipient SHOULD treat as gzip.
	EncodingXGzip   = "x-gzip"
	EncodingDeflate = "deflate"
	EncodingBrotli  = "br"
	EncodingZstd    = "zstd"
)

// ZstdMaxWindow is the largest zstd window this package decodes. RFC 9659 §3 bounds the "zstd" content
// coding at 8 MB so that a recipient's memory is not the sender's choice: without it the decoder library
// accepts a frame declaring a 512 MiB window and allocates that much history for a body of a few bytes.
// A frame over it is a decode error, handled like any other (R15: the decoded prefix is kept).
const ZstdMaxWindow = 8 << 20

// MaxCodings is the most content codings one Content-Encoding list may name for this package, or the
// forwarder, to undo it (R15). Each layer is a decoder with a window of its own — about 42 KB for gzip
// and deflate, up to 16 MiB for br, up to ZstdMaxWindow for zstd — and a header lists a layer in a few
// bytes, so without a cap the sender chooses the launcher's memory. The forwarder holds every layer open
// at once: thirty zstd layers in a 271-byte body allocated 270 MB there, and "gzip" repeated to fill the
// 1 MiB header limit is about 200k windows, 8.6 GB. One coding is what servers send, and two covers a
// proxy that compressed an already compressed body; curl and urllib3 stop at five, which at br's window
// is 80 MiB for one body. A longer list is undecodable, handled like a coding with no decoder here: the
// body is kept as the wire carried it.
const MaxCodings = 2

// Decoder wraps an encoded body. The returned reader is closed by the assembler whether or not it read to
// the end, so a decoder that owns goroutines (zstd) releases them on every path.
type Decoder func(r io.Reader) (io.ReadCloser, error)

// decoders is the fixed table of content codings this package understands. It is written once here and
// never mutated, so no lock guards it and no caller can teach the assembler a new coding at runtime. It is
// also the forwarder's table (Codings, Open): the two capture paths undo the same codings the same way,
// so R15's "blob(sha) hashes decoded content" names the same bytes whichever of them saw the exchange.
var decoders = map[string]Decoder{
	EncodingGzip:    newGzip,
	EncodingXGzip:   newGzip,
	EncodingDeflate: newDeflate,
	EncodingBrotli:  newBrotli,
	EncodingZstd:    newZstd,
}

// Codings are the content codings this package decodes, lowercased and sorted.
func Codings() []string {
	out := make([]string, 0, len(decoders))
	for name := range decoders {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Open wraps r in the decoder of one content coding. The name is matched case-insensitively; a coding
// with no decoder here is ErrMalformed, the same error the assembler records for it.
func Open(coding string, r io.Reader) (io.ReadCloser, error) {
	name := strings.ToLower(strings.TrimSpace(coding))
	newDec, ok := decoders[name]
	if !ok {
		return nil, fmt.Errorf("%w: unsupported content coding %q", ErrMalformed, name)
	}
	return newDec(r)
}

// SplitEncodings returns the codings a Content-Encoding header lists, lowercased, in the order they were
// applied, with identity dropped; they are undone from the right (RFC 9110 §8.4). A list longer than
// MaxCodings is returned whole, and it is the caller's to refuse.
func SplitEncodings(header string) []string { return splitEncodings(header) }

// SupportedEncoding reports whether Content-Encoding names a coding this package decodes. Identity and an
// absent header are supported trivially.
func SupportedEncoding(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == EncodingIdentity {
		return true
	}
	_, ok := decoders[name]
	return ok
}

// decoded is what decodeBudgeted produced and what it holds of the budget.
type decoded struct {
	out []byte
	// held is what out's array holds of the budget, which the caller gives back when it lets out go.
	held int64
	// limited is the output stopped at max with more still to decode.
	limited bool
	// starved is the output stopped short of max because the budget had no room for it (R15).
	starved bool
	err     error
}

// decodeBudgeted is decode with every array it makes reserved from b as it grows (R15). A body's
// decoded form was outside the budget: the wire bytes were counted and given back at completion, and the
// decode then allocated up to max with nobody counting — 106 bytes of brotli are 64 MiB of zeros, and one
// 32 KiB chunk carrying a few such requests made one Feed hand back hundreds of MiB, each under MaxBody and
// none of it in the budget that bounds the launcher. Here an array is taken from b before it exists; the
// budget short of what the output needs stops the decode where it is, and the prefix is kept, marked
// starved, which the caller counts as gap why=size-cap. An intermediate layer's array goes back once the
// next layer has read it; the final one's reservation is returned in held, for the caller to give back
// when the output is let go. b nil is max alone.
func decodeBudgeted(body []byte, encoding string, max int64, b *Budget) decoded {
	names := splitEncodings(encoding)
	if len(names) == 0 {
		return decoded{out: body}
	}
	if len(names) > MaxCodings {
		// Refused before any layer is opened, so the wire's bytes are what is kept. Here the layers
		// are decoded one after another and only one window is live at a time, but each layer is
		// still a decoder allocated and a pass over the body, one per name the sender listed.
		return decoded{out: body, err: fmt.Errorf("%w: %d content codings, more than the %d this package undoes",
			ErrMalformed, len(names), MaxCodings)}
	}
	out := decoded{out: body}
	for i := len(names) - 1; i >= 0; i-- {
		name := names[i]
		newDec, ok := decoders[name]
		if !ok {
			out.err = fmt.Errorf("%w: unsupported content coding %q", ErrMalformed, name)
			return out
		}
		dec, err := newDec(bytes.NewReader(out.out))
		if err != nil {
			out.err = fmt.Errorf("%w: %s: %w", ErrMalformed, name, err)
			return out
		}
		next := readBudgeted(dec, max, b)
		if cerr := dec.Close(); next.err == nil && cerr != nil {
			next.err = cerr
		}
		// The layer just read is let go: its array's reservation goes back. The wire body's is the
		// caller's, and out.held is zero for it.
		b.Give(out.held)
		out = decoded{out: next.out, held: next.held, limited: next.limited, starved: out.starved || next.starved}
		if next.err != nil {
			out.err = fmt.Errorf("%w: %s: %w", ErrMalformed, name, next.err)
			return out
		}
		if (next.limited || next.starved) && i > 0 {
			// A layer cut short is not the input the next layer expects: undoing it further would only
			// read the cut as a broken stream, so what is kept is the layer as far as it went.
			return out
		}
	}
	return out
}

// decodeChunk is the first array a decode asks the budget for; it doubles from there.
const decodeChunk = 32 << 10

// readBudgeted drains r into an array that grows by doubling, each array reserved from b before it exists
// and the one it replaces given back once copied, stopping at limit bytes when limit is positive. A read
// that reaches limit probes one byte further to tell a body that ends exactly there from one cut there.
func readBudgeted(r io.Reader, limit int64, b *Budget) decoded {
	var (
		buf  []byte
		held int64
	)
	for {
		if len(buf) == cap(buf) {
			size := int64(max(2*cap(buf), decodeChunk))
			if limit > 0 {
				size = min(size, limit)
			}
			if size <= int64(cap(buf)) {
				// At the limit: one byte more says whether the body goes on.
				var probe [1]byte
				n, err := io.ReadFull(r, probe[:])
				switch {
				case n == 1:
					return decoded{out: buf, held: held, limited: true}
				case err == io.EOF:
					return decoded{out: buf, held: held}
				default:
					return decoded{out: buf, held: held, err: err}
				}
			}
			got := size
			if b != nil {
				got = b.Take(size)
				if got <= int64(cap(buf)) {
					b.Give(got)
					return decoded{out: buf, held: held, starved: true}
				}
			}
			next := make([]byte, len(buf), got)
			copy(next, buf)
			if b != nil {
				b.Give(held)
				held = got
			}
			buf = next
		}
		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err == io.EOF {
			return decoded{out: buf, held: held}
		}
		if err != nil {
			return decoded{out: buf, held: held, err: err}
		}
	}
}

// splitEncodings returns the codings of a Content-Encoding header, lowercased, with identity dropped.
func splitEncodings(header string) []string {
	var out []string
	for _, part := range strings.Split(header, ",") {
		name := strings.ToLower(strings.TrimSpace(part))
		if name == "" || name == EncodingIdentity {
			continue
		}
		out = append(out, name)
	}
	return out
}

// newGzip decodes a gzip stream (RFC 1952).
func newGzip(r io.Reader) (io.ReadCloser, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	return zr, nil
}

// newDeflate decodes Content-Encoding: deflate. RFC 9110 §8.4.1.2 defines it as the zlib wrapper of
// RFC 1950, but enough servers send a bare RFC 1951 stream that a decoder which only accepts zlib loses
// real bodies; the two are told apart by zlib's own header check rather than by trying and retrying.
func newDeflate(r io.Reader) (io.ReadCloser, error) {
	br := bytes.NewBuffer(nil)
	peek := make([]byte, 2)
	n, err := io.ReadFull(r, peek)
	if err != nil && n == 0 {
		// Zero bytes decode to zero bytes: an empty body is not a truncated stream, and flate's
		// own reader would call it an unexpected EOF.
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	br.Write(peek[:n])
	joined := io.MultiReader(br, r)
	if n == 2 && isZlibHeader(peek) {
		// isZlibHeader rejects every header zlib.NewReader refuses, so this cannot fall back to
		// flate over a stream zlib's buffered reader already advanced.
		return zlib.NewReader(joined)
	}
	return flate.NewReader(joined), nil
}

// isZlibHeader reports whether the first two bytes are an RFC 1950 header: deflate compression method in
// the low nibble of CMF, a window size within 32 KiB (CINFO <= 7), no preset dictionary (FDICT clear) and a
// CMF/FLG pair that is a multiple of 31. zlib.NewReader refuses the rest after reading past the header, so the
// sniff must too.
func isZlibHeader(b []byte) bool {
	if len(b) < 2 || b[0]&0x0f != 8 || b[0]>>4 > 7 || b[1]&0x20 != 0 {
		return false
	}
	return (uint16(b[0])<<8|uint16(b[1]))%31 == 0
}

// newBrotli decodes a brotli stream (RFC 7932). Cloudflare serves br to any client that offers it, so this
// is not an exotic path (ARCHITECTURE §12).
func newBrotli(r io.Reader) (io.ReadCloser, error) {
	return io.NopCloser(brotli.NewReader(r)), nil
}

// newZstd decodes a zstd stream (RFC 8878); httpx on Python 3.14 offers it. Concurrency is pinned to one
// so the decoder owns no worker pool beyond the caller's own goroutine, and IOReadCloser's Close releases
// what it does own — this package never leaks a goroutine into a run (§9 "an owner and a Close").
//
// The window is capped at ZstdMaxWindow. The decoder allocates a frame's whole declared window (plus a
// block's headroom) before it decodes a byte of it, and for a single-segment frame that window is the
// declared content size, so the cap is what keeps a thirteen-byte header from costing the launcher half a
// gigabyte. With concurrency one the decoder checks both kinds of frame against the cap.
func newZstd(r io.Reader) (io.ReadCloser, error) {
	dec, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxWindow(ZstdMaxWindow))
	if err != nil {
		return nil, err
	}
	return dec.IOReadCloser(), nil
}
