// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"bytes"
	"fmt"
	"io"
)

// maxChunkSizeLine bounds one chunk-size line including its extensions. A size line is at most sixteen hex
// digits plus extensions; anything longer is a peer writing nonsense, and refusing it keeps a connection
// that never sends CRLF from buffering without bound.
const maxChunkSizeLine = 1024

// maxTrailerBytes bounds the trailer section after the last chunk, the same way R13 bounds the header block.
const maxTrailerBytes = 8 << 10

// chunkState is where a chunked body parser stands between two Feed calls. State is per connection, not per
// chunk event, which is what lets a size line split across two SSL_write calls reassemble (edge case #17).
type chunkState int

const (
	chunkSize  chunkState = iota // reading the size line
	chunkData                    // copying the declared number of bytes
	chunkCRLF                    // consuming the CRLF that ends a chunk's data
	chunkTrail                   // reading the trailer section after the last chunk
	chunkDone                    // the terminal chunk and its trailers are consumed
)

// chunkedReader decodes a Transfer-Encoding: chunked body incrementally (RFC 9112 §7.1). It holds no
// buffer of its own: the caller owns the unconsumed bytes and the decoded output, so nothing here can grow
// without the caller seeing it.
type chunkedReader struct {
	state chunkState
	// left is the bytes still to copy for the current chunk.
	left int64
	// trailerBytes counts the trailer section against maxTrailerBytes.
	trailerBytes int
}

// done reports whether the terminal chunk has been consumed.
func (c *chunkedReader) done() bool { return c.state == chunkDone }

// feed consumes as much of buf as it can, writing the decoded body bytes to out, a slice of buf at a time
// that out must not keep. It returns the number of bytes consumed; buf's remainder is a partial line or a
// partial chunk the caller keeps for the next call. An error is always ErrMalformed-wrapped and always
// terminal for that connection (R18).
func (c *chunkedReader) feed(buf []byte, out io.Writer) (int, error) {
	used := 0
	for used < len(buf) {
		if c.state == chunkDone {
			return used, nil
		}
		rest := buf[used:]
		switch c.state {
		case chunkSize:
			line, n, ok := takeLine(rest, maxChunkSizeLine)
			if !ok {
				if n < 0 {
					return used, fmt.Errorf("%w: chunk size line over %d bytes", ErrMalformed, maxChunkSizeLine)
				}
				return used, nil // wait for the rest of the line
			}
			size, err := parseChunkSize(line)
			if err != nil {
				return used, err
			}
			used += n
			c.left = size
			if size == 0 {
				c.state = chunkTrail
				continue
			}
			c.state = chunkData

		case chunkData:
			n := int64(len(rest))
			if n > c.left {
				n = c.left
			}
			_, _ = out.Write(rest[:n])
			c.left -= n
			used += int(n)
			if c.left == 0 {
				c.state = chunkCRLF
			}

		case chunkCRLF:
			// The CRLF may itself be split across two chunk events: consume what is there.
			if rest[0] == '\r' {
				if len(rest) == 1 {
					return used, nil
				}
				if rest[1] != '\n' {
					return used, fmt.Errorf("%w: chunk data not followed by CRLF", ErrMalformed)
				}
				used += 2
				c.state = chunkSize
				continue
			}
			if rest[0] == '\n' { // tolerate a bare LF, as every HTTP/1.1 parser in practice does
				used++
				c.state = chunkSize
				continue
			}
			return used, fmt.Errorf("%w: chunk data not followed by CRLF", ErrMalformed)

		case chunkTrail:
			line, n, ok := takeLine(rest, maxTrailerBytes-c.trailerBytes)
			if !ok {
				if n < 0 {
					return used, fmt.Errorf("%w: trailer section over %d bytes", ErrMalformed, maxTrailerBytes)
				}
				return used, nil
			}
			used += n
			c.trailerBytes += n
			if c.trailerBytes > maxTrailerBytes {
				return used, fmt.Errorf("%w: trailer section over %d bytes", ErrMalformed, maxTrailerBytes)
			}
			if len(line) == 0 {
				c.state = chunkDone
				return used, nil
			}
			if bytes.IndexByte(line, ':') < 0 {
				return used, fmt.Errorf("%w: trailer line without a colon", ErrMalformed)
			}

		default:
			return used, fmt.Errorf("%w: chunked parser in state %d", ErrMalformed, c.state)
		}
	}
	return used, nil
}

// parseChunkSize reads the hex size at the head of a chunk-size line, ignoring any chunk extensions after
// the first semicolon. A missing, over-wide or non-hex size is malformed (R18).
func parseChunkSize(line []byte) (int64, error) {
	if i := bytes.IndexByte(line, ';'); i >= 0 {
		line = line[:i]
	}
	line = bytes.TrimRight(line, " \t")
	if len(line) == 0 || len(line) > 16 {
		return 0, fmt.Errorf("%w: chunk size %q", ErrMalformed, clip(line))
	}
	var size int64
	for _, ch := range line {
		var d int64
		switch {
		case ch >= '0' && ch <= '9':
			d = int64(ch - '0')
		case ch >= 'a' && ch <= 'f':
			d = int64(ch-'a') + 10
		case ch >= 'A' && ch <= 'F':
			d = int64(ch-'A') + 10
		default:
			return 0, fmt.Errorf("%w: chunk size %q", ErrMalformed, clip(line))
		}
		// Sixteen hex digits cannot overflow int64 only because the length is already bounded above;
		// the top nibble still can, so the sign is checked rather than assumed.
		size = size<<4 | d
		if size < 0 {
			return 0, fmt.Errorf("%w: chunk size %q overflows", ErrMalformed, clip(line))
		}
	}
	return size, nil
}
