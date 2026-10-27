// SPDX-License-Identifier: Apache-2.0

package mcp

import "bytes"

// Result is what a piece of a stream named: the items, in wire order, and the messages that could not be read.
type Result struct {
	Items []Item
	// Malformed counts lines that were not a JSON-RPC 2.0 message, or a batch's members that were not.
	Malformed int
	// Oversize counts lines longer than MaxMessage, which were skipped unread.
	Oversize int
}

func (r *Result) add(items []Item, bad int) {
	r.Items = append(r.Items, items...)
	r.Malformed += bad
}

// Stdio reads the client's side of the stdio transport: the bytes written to the server's standard input, in which
// every message is one line and no message holds a newline (MCP 2025-06-18, Transports). Write takes the bytes as
// they come, in pieces of any size, and Close ends the stream. It holds at most MaxMessage bytes of one unfinished
// line; a longer line is skipped to its newline and counted, never buffered.
//
// A Stdio is not safe for concurrent use: one stream, one reader.
type Stdio struct {
	line []byte
	skip bool // inside a line already counted as oversize
}

// Write reads p, a further piece of the stream.
func (s *Stdio) Write(p []byte) Result {
	var r Result
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if s.skip {
			if i < 0 {
				return r
			}
			s.skip, p = false, p[i+1:]
			continue
		}
		if i < 0 {
			if len(s.line)+len(p) > MaxMessage {
				s.line, s.skip = s.line[:0], true
				r.Oversize++
				return r
			}
			s.line = append(s.line, p...)
			return r
		}
		switch {
		case len(s.line)+i > MaxMessage:
			r.Oversize++
		case len(s.line) == 0:
			s.readLine(&r, p[:i])
		default:
			s.line = append(s.line, p[:i]...)
			s.readLine(&r, s.line)
		}
		s.line, p = s.line[:0], p[i+1:]
	}
	return r
}

// Close ends the stream. An unfinished last line is one the writer cut short, which a server reads as nothing: it
// is counted as malformed, never read as the message it might have become.
func (s *Stdio) Close() Result {
	var r Result
	if len(trimSpace(s.line)) > 0 {
		r.Malformed++
	}
	s.line, s.skip = nil, false
	return r
}

// readLine reads one complete line. A blank one (a trailing "\r" of a CRLF writer included) is skipped.
func (s *Stdio) readLine(r *Result, line []byte) {
	line = trimSpace(line)
	if len(line) == 0 {
		return
	}
	r.add(Read(line))
}
