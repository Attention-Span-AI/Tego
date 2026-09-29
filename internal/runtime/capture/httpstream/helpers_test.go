// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"bytes"
	"io"
)

// decode strips the content codings of a complete body, outermost first — Content-Encoding lists them in
// the order they were applied, so they are undone from the right (RFC 9110 §8.4).
//
// The decoded prefix is returned with the error rather than thrown away: R15 wants the bytes that did
// decode written to the blob, the message marked Truncated and one gap why=malformed raised, which is the
// only way a body cut by R6's 128 KiB chunk cap (edge case #18) contributes anything at all.
//
// It is decodeBudgeted with no budget, for a test that bounds the output by max alone.
func decode(body []byte, encoding string, max int64) ([]byte, error) {
	d := decodeBudgeted(body, encoding, max, nil)
	return d.out, d.err
}

// readAll drains r, stopping at max bytes when max is positive. A body that hits the bound is not an error
// here: R14 sets no total body cap, and a caller that wants one passes it and reads Truncated.
func readAll(r io.Reader, max int64) ([]byte, error) {
	var buf bytes.Buffer
	var src = r
	if max > 0 {
		src = io.LimitReader(r, max)
	}
	_, err := buf.ReadFrom(src)
	return buf.Bytes(), err
}
