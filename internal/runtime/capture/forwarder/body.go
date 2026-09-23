// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"io"
	"strings"

	"github.com/attention-span-ai/tego/internal/runtime/capture/httpstream"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

// The capture gap reasons this component can report, named here so a reader of the forwarder does not
// have to reach into derive for the closed set (R37).
const (
	GapH2        = derive.GapH2
	GapMalformed = derive.GapMalformed
	GapSizeCap   = derive.GapSizeCap
)

// decoders are the content codings this component undoes: capture/httpstream's, which owns the brotli and
// zstd dependencies, so the forwarder and the uprobe path decode the same codings the same way (R15). The
// table is built once here so that the decode itself and the memory reserved for its output (§3) are
// decided by the same fact: only a coding in here produces a second buffer.
var decoders = func() map[string]func(io.Reader) (io.Reader, error) {
	out := make(map[string]func(io.Reader) (io.Reader, error))
	for _, name := range httpstream.Codings() {
		out[name] = func(r io.Reader) (io.Reader, error) { return httpstream.Open(name, r) }
	}
	return out
}()

// decoderFor returns the decoder for a Content-Encoding header when this component can undo every coding
// it lists. A list is undone from the right, the last coding applied first (RFC 9110 §8.4), each decoder
// reading the output of the one inside it, so a stacked body still makes one decoded buffer. One coding
// with no decoder here means none is opened: a body half undone is neither the wire's bytes nor the
// content's.
//
// Every layer of a stack is open, with its window, until the decode ends, so a list longer than
// httpstream.MaxCodings is refused the same way: the decoder state outside the capture budget is then at
// most MaxCodings windows, never one per name a header can fit (§3).
func decoderFor(encoding string) (func(io.Reader) (io.Reader, error), bool) {
	names := httpstream.SplitEncodings(encoding)
	if len(names) == 0 || len(names) > httpstream.MaxCodings {
		return nil, false
	}
	opens := make([]func(io.Reader) (io.Reader, error), len(names))
	for i, name := range names {
		open, ok := decoders[name]
		if !ok {
			return nil, false
		}
		opens[i] = open
	}
	if len(opens) == 1 {
		return opens[0], true
	}
	return func(r io.Reader) (io.Reader, error) {
		var chain stackedDecoder
		for i := len(opens) - 1; i >= 0; i-- {
			next, err := opens[i](r)
			if err != nil {
				_ = chain.Close()
				return nil, err
			}
			chain.layers = append(chain.layers, next)
			r = next
		}
		chain.Reader = r
		return &chain, nil
	}, true
}

// stackedDecoder is a Content-Encoding list opened as one reader: the outermost layer is read, and Close
// closes every layer, since a zstd layer owns resources its Close releases whatever wraps it.
type stackedDecoder struct {
	io.Reader
	layers []io.Reader
}

// Close closes every layer that is a Closer, keeping the first error.
func (s *stackedDecoder) Close() error {
	var first error
	for _, l := range s.layers {
		if c, ok := l.(io.Closer); ok {
			if err := c.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

// identityEncoding reports whether the header names no coding at all: the wire bytes are then already the
// decoded ones, and nothing has to be undone.
func identityEncoding(encoding string) bool {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return true
	}
	return false
}

// decodeChunk is how much room a decode asks its buffer for at a time. A decoded size is not known until
// the decode ends, so the buffer starts at this and doubles, bounded by the limit and the budget.
const decodeChunk = 32 << 10

// decodeWith undoes a body's content codings, so that what the record stores and what derive parses are the
// decoded content while content_encoding still records what the wire used (R15). Whatever decoded before
// an error is kept, the way a truncated stream is (R15); a coding with no decoder here never reaches this
// function at all — its body is recorded as it came off the wire, which derive turns into decision:
// unparsed why=encoding instead of a parse of compressed noise.
//
// limit bounds the decoded output, which the cap on the captured input does not: DEFLATE expands by up to
// 1032:1, so a captured body of MaxBody bytes decodes to gigabytes of launcher heap — and only the child
// is cloned into the run's cgroup (docs/p0/runtime-launch.md §6 step 6, CLONE_INTO_CGROUP), so
// limits.memory never covers the process holding it. A decode stopped at the limit keeps its prefix and
// reports truncated, the shape any capped body already has: derive parses the prefix and says decision:
// unparsed why=schema (R14, R29), instead of the process dying and the run losing its run_end.
//
// The output is a held buffer reserved from b as it grows, on top of whatever reserves body: the decoder
// reads body until its output is complete, so both are live for the whole decode (§3). It is nil when
// nothing decoded, and the caller keeps body as it is.
//
// The output is cut short for one of two reasons, each its own result because each is its own gap. limited
// is the limit stopping the decode: the capture cap, counted as size-cap with the payload. broken is a
// decode that failed (R15's mid-stream decode error), which the caller counts as a gap why=malformed. A
// failure after some output is that output as decoded content cut short: ok and broken, the truncated
// prefix R15 gives it. It was returned as neither, so a gzip stream cut mid-way was recorded as a whole body
// with no gap at all. The two once shared one truncated result, which the caller read as the
// limit, so a broken stream was counted as size-cap on top of its malformed gap.
func decodeWith(b *budget, body []byte, limit int, open func(io.Reader) (io.Reader, error)) (
	out *held, ok, limited, broken bool,
) {
	if len(body) == 0 {
		return nil, true, false, false
	}
	r, err := open(bytes.NewReader(body))
	if err != nil {
		return nil, false, false, true
	}
	if c, isCloser := r.(io.Closer); isCloser {
		defer func() { _ = c.Close() }()
	}
	out = b.hold(limit)
	// The decoder itself may have inflated more than the buffer keeps into its own window, which is
	// bounded by that window and not by the body (§3 lists it outside the budget).
	extra, err := out.fill(r, decodeChunk)
	out.fit()
	switch {
	case extra != nil:
		return out, true, true, false
	case err == nil:
		return out, true, false, false
	case len(out.bytes()) == 0:
		out.drop()
		return nil, false, false, true
	}
	return out, true, false, true // a decoded prefix, and honestly not the whole body
}
