// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"bytes"
	"maps"

	"github.com/attention-span-ai/tego/internal/runtime/derive/sse"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// maxScanLine is the longest event-stream line a StreamUsageScanner holds while it waits for the line's end. The
// events it reads are small (message_start carries an empty content array, message_delta a stop reason and the
// usage). A larger frame is classified with bounded memory: known content is skipped; accounting or an
// ambiguous type makes the exchange's accounting incomplete.
const maxScanLine = 64 << 10

// StreamUsageScanner reads the token usage of a Messages API event stream off bytes written to it in any number
// of pieces, whatever a capture budget kept of the body (R27). The forwarder feeds it every byte it
// relays: the record's copy of a body is capped by MaxBody and by the run's capture budget, and without it a copy
// cut short left derive, and so a token or cost budget, no usage for a call the agent was answered in full. It
// holds one partial line at most, so its cost is per exchange and does not grow with the body. The zero value is
// ready; it is not safe for concurrent use.
//
// It is derive's own reading: each event is decoded as ParseStreamEvent decodes it, keys read
// exactly as written (keys.go), and folded as the assembler folds it (Usage.merge), each counter the larger of
// the values reported since the stream reports totals. A scanner of the forwarder's own decoded with
// encoding/json v1, which folds key case and lets the last match win, so "INPUT_TOKENS" was charged on the
// forwarder path and ignored on the uprobe path (capture-derive.md R29).
//
// It frames the stream as ParseStream does (scanSSE): `event:` and `data:` fields gathered into one frame up to
// its blank line, several `data:` lines joined by newlines, the collected form's one payload per `{` line,
// comments, `id:`/`retry:` and unknown fields passed over. CR, LF and CRLF all end lines, including
// CRLF split between writes. A frame's type is
// its payload's "type", or its `event:` name when the payload has none, whether written plainly or with JSON
// escapes. It reads
// message_start's message.usage and model and each message_delta's usage. Missing opening input or malformed
// accounting (including negative counters) leaves Incomplete sticky, even after a later valid output total.
// A delta without usage contributes no counters and is not final. Oversized frames are classified as above.
type StreamUsageScanner struct {
	// WireSSE selects wire framing before the first Write. Both capture paths select it: only data fields
	// contribute payloads, and JSON-looking unknown fields are ignored. The zero value retains legacy
	// collected-payload compatibility for callers that do not have wire framing metadata.
	WireSSE  bool
	line     []byte
	skipping bool // the line in progress passed maxScanLine and is being passed over
	// The frame in progress: its event name and data, whether it has a data field, and whether its data passed
	// maxScanLine.
	name, data     []byte
	inFrame, large bool
	frameType      eventTypeScanner // every data byte, even when the retained frame passes maxScanLine
	lineType       eventTypeScanner // collected JSON lines have a frame of their own
	typeData       bool
	lineMode       uint8 // 0 field prefix; 1 optional data space; 2 data; 3 collected JSON; 4 ignored; 5 event
	lineHead       int
	lineEvent      bool
	bomPrefix      int  // first-line signature bytes consumed; -1 once decided
	skipLF         bool // the previous write ended at a CR
	firstLine      bool // the optional stream signature has been consumed
	ended          bool // Result has read the last line
	started        bool // a readable message_start opened the exchange, even if its usage was incomplete
	seen           bool
	incomplete     bool // an accounting frame could not be read; later totals cannot restore lost counters
	final          bool // a message_delta carried usage: the output count is the message's, not message_start's placeholder
	model          string
	usage          Usage
}

// usageEvent is as much of a stream event as the StreamUsageScanner reads, decoded in one pass.
type usageEvent struct {
	Type    string `json:"type"`
	Message *struct {
		Model string `json:"model"`
		Usage *Usage `json:"usage"`
	} `json:"message"`
	Usage *Usage `json:"usage"`
}

var (
	scanMessageStart = []byte(`"` + EventMessageStart + `"`)
	scanMessageDelta = []byte(`"` + EventMessageDelta + `"`)
	scanError        = []byte(`"` + EventError + `"`)
	scanEscape       = []byte(`\u`)
)

// Write feeds the next bytes of the stream. It never fails.
func (s *StreamUsageScanner) Write(p []byte) (int, error) {
	n := len(p)
	if s.ended {
		return n, nil
	}
	for len(p) > 0 {
		if s.skipLF {
			s.skipLF = false
			if p[0] == '\n' {
				p = p[1:]
			}
			if len(p) == 0 {
				break
			}
		}
		line, rest, terminated := sse.CutLine(p)
		s.hold(line)
		if !terminated {
			break
		}
		s.skipLF = len(rest) == 0 && p[len(p)-1] == '\r'
		s.endLine()
		p = rest
	}
	return n, nil
}

// hold keeps part of the line in progress, unless it has grown past maxScanLine.
func (s *StreamUsageScanner) hold(p []byte) {
	s.trackLine(p)
	if s.skipping {
		return
	}
	if len(s.line)+len(p) > maxScanLine {
		s.line, s.skipping = s.line[:0], true
		return
	}
	s.line = append(s.line, p...)
}

// trackLine classifies oversized frames without retaining their content. SSE field prefixes are small;
// only data values (joined with newlines) and collected JSON lines reach the bounded JSON classifier.
func (s *StreamUsageScanner) trackLine(p []byte) {
	if !s.firstLine && s.bomPrefix >= 0 {
		const bom = "\xef\xbb\xbf"
		for len(p) > 0 && s.bomPrefix < len(bom) {
			if p[0] != bom[s.bomPrefix] {
				n := s.bomPrefix
				s.bomPrefix = -1
				s.trackLine([]byte(bom[:n]))
				break
			}
			s.bomPrefix++
			p = p[1:]
		}
		if s.bomPrefix == len(bom) {
			s.bomPrefix = -1
		} else if s.bomPrefix >= 0 {
			return
		}
	}
	for len(p) > 0 {
		switch s.lineMode {
		case 0:
			if s.lineHead == 0 && p[0] == '{' && !s.WireSSE {
				s.lineMode = 3
				continue
			}
			if s.lineHead == 0 {
				s.lineEvent = p[0] == 'e'
			}
			prefix := "data:"
			if s.lineEvent {
				prefix = "event:"
			}
			if p[0] != prefix[s.lineHead] {
				s.lineMode = 4
				return
			}
			s.lineHead++
			p = p[1:]
			if s.lineHead == len(prefix) {
				if s.lineEvent {
					s.lineMode = 5
					return
				}
				s.lineMode = 1
				if s.typeData {
					s.frameType.Write([]byte{'\n'})
				}
				s.typeData = true
			}
		case 1:
			if p[0] == ' ' {
				p = p[1:]
			}
			s.lineMode = 2
		case 2:
			s.frameType.Write(p)
			return
		case 3:
			s.lineType.Write(p)
			return
		default:
			return
		}
	}
}

// endLine reads the line in progress, which its newline (or the end of the stream) has completed.
func (s *StreamUsageScanner) endLine() {
	if s.skipping {
		switch s.lineMode {
		case 3:
			s.flush()
			s.incomplete = s.incomplete || !s.lineType.NonAccounting(nil)
		case 1, 2:
			s.inFrame, s.large = true, true
		case 5:
			// An event field replaces its predecessor even when it cannot be retained.
			s.name, s.incomplete = nil, true
		}
	} else {
		line := s.line
		if !s.firstLine {
			line = sse.WithoutBOM(line)
		}
		s.scan(line)
	}
	s.firstLine = true
	s.line, s.skipping = s.line[:0], false
	s.lineMode, s.lineHead, s.lineType = 0, 0, eventTypeScanner{}
	s.lineEvent = false
}

// scan reads one complete line as scanSSE does.
func (s *StreamUsageScanner) scan(line []byte) {
	switch {
	case len(line) == 0:
		s.flush()
	case line[0] == ':':
		// a comment
	case line[0] == '{' && !s.WireSSE:
		s.flush()
		s.event(nil, line)
	default:
		field, value := sse.SplitField(line)
		switch string(field) {
		case "event":
			s.name = append(s.name[:0], value...)
		case "data":
			if s.inFrame {
				s.data = append(s.data, '\n')
			}
			if len(s.data)+len(value) > maxScanLine {
				s.large, s.data = true, s.data[:0]
			} else if !s.large {
				s.data = append(s.data, value...)
			}
			s.inFrame = true
		default:
			// id, retry and unrecognized fields carry no provider data.
		}
	}
}

// flush reads the frame in progress, if any, and starts the next.
func (s *StreamUsageScanner) flush() {
	if s.inFrame && !s.large {
		s.event(s.name, s.data)
	} else if s.large && !s.frameType.NonAccounting(s.name) {
		s.incomplete = true
	}
	s.name, s.data, s.inFrame, s.large = s.name[:0], s.data[:0], false, false
	s.frameType, s.typeData = eventTypeScanner{}, false
}

// event reads one frame: name is its event field, data its payload.
func (s *StreamUsageScanner) event(name, data []byte) {
	// Only a frame that can be one of the two events is decoded: most of a stream is content deltas. A type
	// spelled with JSON escapes names neither plainly, so a payload holding an escape is decoded too.
	if !bytes.Equal(name, []byte(EventMessageStart)) && !bytes.Equal(name, []byte(EventMessageDelta)) && !bytes.Equal(name, []byte(EventError)) &&
		!bytes.Contains(data, scanMessageStart) && !bytes.Contains(data, scanMessageDelta) &&
		!bytes.Contains(data, scanError) &&
		!bytes.Contains(data, scanEscape) {
		return
	}
	if len(bytes.TrimSpace(data)) == 0 {
		if bytes.Equal(name, []byte(EventMessageStart)) || bytes.Equal(name, []byte(EventMessageDelta)) {
			s.incomplete = true
		}
		return
	}
	var ev usageEvent
	if unmarshal(data, &ev) != nil {
		s.incomplete = true
		return
	}
	typ := ev.Type
	if typ == "" {
		typ = string(name)
	}
	var u *Usage
	switch typ {
	case EventMessageStart:
		if ev.Message == nil || s.started || ev.Message.Usage != nil && ev.Message.Usage.validate() != nil {
			s.incomplete = true
			return
		}
		s.started = true
		if ev.Message.Usage == nil || !ev.Message.Usage.hasInput {
			s.incomplete = true
		}
		if ev.Message.Model != "" {
			s.model = ev.Message.Model
		}
		u = ev.Message.Usage
	case EventMessageDelta:
		// A readable opening message lets known later counters remain visible even when its input was
		// missing. Incomplete stays sticky, so a final output count never bounds the missing spend.
		if !s.started {
			s.incomplete = true
			return
		}
		u = ev.Usage
	}
	if !foldUsage(&s.usage, u) {
		if u != nil {
			s.incomplete = true
		}
		return
	}
	s.seen = true
	s.incomplete = s.incomplete || u.unboundedIterations
	s.final = s.final || (typ == EventMessageDelta && u.hasOutput)
}

// Incomplete reports whether a missing or unreadable accounting frame prevents the known counters from
// describing the whole exchange. It is sticky: a later output total says nothing about lost input/cache use.
func (s *StreamUsageScanner) Incomplete() bool { return s != nil && s.incomplete }

// foldUsage folds a reported usage into dst as the stream's totals so far, and reports whether it did: a usage
// absent or with a negative count is not folded. It is the one fold of a streamed usage report, the assembler's
// after a failure (usageOnly) and the StreamUsageScanner's.
func foldUsage(dst, u *Usage) bool {
	if u == nil || u.validate() != nil {
		return false
	}
	dst.merge(*u)
	return true
}

// Result is the usage the stream reported, nil when it reported none; the model message_start named; and whether
// the usage came with a message_delta, whose output count is the message's own rather than message_start's
// placeholder (R29).
//
// Result ends the stream: a last line with no newline is read, and the frame in progress with it, as ParseStream
// reads them, and a Write after it is ignored.
func (s *StreamUsageScanner) Result() (*record.Usage, string, bool) {
	if s == nil {
		return nil, "", false
	}
	if !s.ended {
		s.ended = true
		if len(s.line) > 0 || s.skipping {
			s.endLine()
		}
		s.flush()
	}
	if !s.seen {
		return nil, "", false
	}
	u := s.usage.Record()
	u.ServerTool = maps.Clone(u.ServerTool) // the record's own map, not the scanner's
	return &u, s.model, s.final
}
