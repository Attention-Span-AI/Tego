// SPDX-License-Identifier: Apache-2.0

package anthropic

import "encoding/json"

// eventTypeScanner classifies an oversized frame without holding its content. Only a whole JSON object
// with an unambiguous, known non-accounting type is safe to skip. The fixed stack and token storage also
// bound malformed input; an unusually deep object or long non-string scalar is conservatively unknown.
type eventTypeScanner struct {
	stack            [128]eventJSONState
	depth            int
	done, bad        bool
	inString, escape bool
	unicode          int
	key, hold, long  bool
	token            [128]byte // enough for a fully escaped known key or event type
	n                int
	scalar           bool
	matchType        bool
	types            int
	typ              string
	typeString       bool
}

type eventJSONState uint8

const (
	eventObjectFirst eventJSONState = iota
	eventObjectKey
	eventObjectColon
	eventObjectValue
	eventObjectAfter
	eventArrayFirst
	eventArrayValue
	eventArrayAfter
)

func (s *eventTypeScanner) Write(p []byte) {
	for _, c := range p {
		if s.bad {
			return
		}
		if s.inString {
			s.stringByte(c)
			continue
		}
		if s.scalar {
			if !mtDelimiter(c) {
				s.keep(c)
				continue
			}
			if s.long || !json.Valid(s.token[:s.n]) {
				s.bad = true
				return
			}
			s.scalar = false
		}
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if s.done {
			s.bad = true
			return
		}
		if s.depth == 0 {
			if c != '{' {
				s.bad = true
				return
			}
			s.push(eventObjectFirst)
			continue
		}
		state := &s.stack[s.depth-1]
		switch *state {
		case eventObjectFirst, eventObjectKey:
			if c == '}' && *state == eventObjectFirst {
				s.close()
				continue
			}
			if c != '"' {
				s.bad = true
				return
			}
			s.beginString(true)
		case eventObjectColon:
			if c != ':' {
				s.bad = true
				return
			}
			*state = eventObjectValue
		case eventObjectAfter:
			switch c {
			case ',':
				*state = eventObjectKey
			case '}':
				s.close()
			default:
				s.bad = true
			}
		case eventArrayAfter:
			switch c {
			case ',':
				*state = eventArrayValue
			case ']':
				s.close()
			default:
				s.bad = true
			}
		case eventArrayFirst:
			if c == ']' {
				s.close()
				continue
			}
			fallthrough
		case eventObjectValue, eventArrayValue:
			if *state == eventObjectValue {
				*state = eventObjectAfter
			} else {
				*state = eventArrayAfter
			}
			switch c {
			case '"':
				s.beginString(false)
			case '{':
				s.push(eventObjectFirst)
			case '[':
				s.push(eventArrayFirst)
			default:
				s.scalar, s.hold, s.long, s.n = true, true, false, 0
				s.keep(c)
			}
		}
	}
}

func (s *eventTypeScanner) push(state eventJSONState) {
	if s.depth == len(s.stack) {
		s.bad = true
		return
	}
	s.stack[s.depth] = state
	s.depth++
}

func (s *eventTypeScanner) close() {
	s.depth--
	s.done = s.depth == 0
}

func (s *eventTypeScanner) beginString(key bool) {
	s.inString, s.key, s.hold = true, key, s.depth == 1 && (key || s.matchType)
	s.n, s.long = 0, false
	s.keep('"')
}

func (s *eventTypeScanner) keep(c byte) {
	if !s.hold {
		return
	}
	if s.n == len(s.token) {
		s.long = true
		return
	}
	s.token[s.n] = c
	s.n++
}

func (s *eventTypeScanner) stringByte(c byte) {
	s.keep(c)
	switch {
	case s.unicode > 0:
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			s.bad = true
		}
		s.unicode--
	case s.escape:
		s.escape = false
		switch c {
		case 'u':
			s.unicode = 4
		case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
		default:
			s.bad = true
		}
	case c == '\\':
		s.escape = true
	case c == '"':
		s.inString = false
		var v string
		if s.hold && !s.long && json.Unmarshal(s.token[:s.n], &v) != nil {
			s.bad = true
			return
		}
		if s.key {
			s.stack[s.depth-1] = eventObjectColon
			if s.depth == 1 {
				s.matchType = v == "type"
				if s.matchType {
					s.types++
					if s.types > 1 {
						s.bad = true
					}
				}
			}
		} else if s.depth == 1 && s.matchType {
			s.typ = v
			s.typeString = !s.long
		}
	case c < 0x20:
		s.bad = true
	}
}

// NonAccounting allows the SSE event name as the type when the object omits type or names an empty string,
// matching ParseStreamEvent. A duplicate or unreadable type never falls back to the event name.
func (s *eventTypeScanner) NonAccounting(name []byte) bool {
	if s.bad || !s.done || s.types > 1 || s.types == 1 && !s.typeString {
		return false
	}
	typ := s.typ
	if typ == "" {
		typ = string(name)
	}
	switch typ {
	case EventContentBlockStart, EventContentBlockDelta, EventContentBlockStop, EventPing, EventMessageStop, EventError:
		return true
	}
	return false
}
