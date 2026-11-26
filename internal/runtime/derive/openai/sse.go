// SPDX-License-Identifier: Apache-2.0

package openai

import (
	"bytes"

	"github.com/attention-span-ai/tego/internal/runtime/derive/sse"
)

// frame is one SSE frame: the event name and the concatenated data payload.
type frame struct {
	name string
	data []byte
}

// scanSSE splits an event stream into frames and hands each to yield, stopping at yield's first error. Comments
// (`:` lines), `retry:` and `id:` directives and blank separators never reach a reader. It walks the body in place,
// one line at a time, as the Anthropic parser's does (the framing is the shared sse package's): CR, LF and CRLF all
// end a line, several `data:` lines of one frame are joined by newlines, a frame with one data line aliases the body
// instead of copying it, and wireSSE false also accepts the collected form's one JSON payload per line.
func scanSSE(body []byte, wireSSE bool, yield func(frame) error) error {
	var (
		name     string
		data     []byte
		haveData bool
		owned    bool // data is a copy this walk made, so appending to it cannot write into body
	)
	flush := func() error {
		f, dispatch := frame{name: name, data: data}, haveData
		name, data, haveData, owned = "", nil, false, false
		if !dispatch {
			return nil
		}
		return yield(f)
	}
	for rest := sse.WithoutBOM(body); len(rest) > 0; {
		var line []byte
		line, rest, _ = sse.CutLine(rest)
		switch {
		case len(line) == 0:
			if err := flush(); err != nil {
				return err
			}
		case line[0] == ':':
			// A comment, including a proxy heartbeat.
		case line[0] == '{' && !wireSSE:
			if err := flush(); err != nil {
				return err
			}
			if err := yield(frame{data: line}); err != nil {
				return err
			}
		default:
			field, value := sse.SplitField(line)
			switch string(field) {
			case "event":
				name = string(value)
			case "data":
				switch {
				case !haveData:
					data = value
				case !owned:
					data = append(bytes.Clone(data), '\n')
					data = append(data, value...)
					owned = true
				default:
					data = append(data, '\n')
					data = append(data, value...)
				}
				haveData = true
			}
		}
	}
	return flush()
}

// isStream reports whether the response body is an event stream: capture said so, the content type says so, or the
// bytes themselves open with an SSE field.
func isStream(sseFlag bool, contentType string, body []byte) bool {
	if sseFlag {
		return true
	}
	if bytes.HasPrefix(bytes.ToLower(bytes.TrimSpace([]byte(contentType))), []byte("text/event-stream")) {
		return true
	}
	body = bytes.TrimLeft(body, " \r\n\t")
	return bytes.HasPrefix(body, []byte("event:")) || bytes.HasPrefix(body, []byte("data:"))
}
