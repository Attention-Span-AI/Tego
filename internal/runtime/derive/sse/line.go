// SPDX-License-Identifier: Apache-2.0

// Package sse supplies the event-stream framing shared by capture and provider parsers.
package sse

import "bytes"

// CutLine splits on CRLF, LF or CR. terminated distinguishes a final partial line from a complete one.
// A caller reading chunks must skip one leading LF after a CR that ended the previous chunk.
func CutLine(b []byte) (line, rest []byte, terminated bool) {
	i := bytes.IndexAny(b, "\r\n")
	if i < 0 {
		return b, nil, false
	}
	line = b[:i]
	if b[i] == '\r' && i+1 < len(b) && b[i+1] == '\n' {
		i++
	}
	return line, b[i+1:], true
}

// SplitField reads a field with one optional leading space in its value. A colonless line is a field
// with an empty value; unknown fields are ignored by callers, as required by the event-stream format.
func SplitField(line []byte) (name, value []byte) {
	i := bytes.IndexByte(line, ':')
	if i < 0 {
		return line, nil
	}
	return line[:i], bytes.TrimPrefix(line[i+1:], []byte{' '})
}

// WithoutBOM removes the optional UTF-8 signature at the beginning of an event stream.
func WithoutBOM(b []byte) []byte { return bytes.TrimPrefix(b, []byte{0xef, 0xbb, 0xbf}) }
