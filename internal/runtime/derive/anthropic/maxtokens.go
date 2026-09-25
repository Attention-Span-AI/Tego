// SPDX-License-Identifier: Apache-2.0

package anthropic

// MaxTokensScanner reads a Messages API request's top-level max_tokens off its body as the bytes go past,
// whatever capture kept of that body (R27). It is the one reading of max_tokens:
// derive's own (RequestMaxTokens) and both capture sources' (the forwarder's tee, httpstream's BodyScanner) are
// this code.
//
// ADR 0036 charges a stream cut before its final message_delta the request's max_tokens as output. A body
// kept only as a prefix (the forwarder's MaxBody, the uprobe path's byte budget) does not parse, so capture
// feeds every byte of the body to a MaxTokensScanner as it goes past; it holds at most one key's bytes and one
// number's digits, so its cost does not grow with the body, and inside nested values (the messages, where a
// large body's bytes are) it only looks for quotes and brackets.
//
// The rules are stated so that a bound is never read where the upstream could read another: max_tokens is
// the exact-case key of the top-level object, never a nested one; a second key equal to it but for case
// (Unicode folding included, as encoding/json matches), or a second exact one, leaves no bound (Go's
// encoding/json matches keys without regard to case and keeps the last, so {"max_tokens":64000,
// "MAX_TOKENS":1} bounded a cut stream by 1 on derive's own reading; R29); the value is a plain
// positive integer; and the body must be one whole JSON object. Anything else is no bound, never a guess.
//
// A request that declares a server-side tool (a tools[] entry whose "type" is not "custom": web_search, code
// execution) has no bound either. Those tools' per-request counts and the input their loop grows are reported
// only in the final message_delta a cut stream lost, so max_tokens as output is no upper bound on what it
// spent, and the exchange stays unmetered (ADR 0036 note 2026-09-30). The tools array is read as far as each
// entry's "type" key; a "tools" key twice or in another case, or a "type" that is not a plain string or is
// spelled in another case, counts as a server tool, the fail-closed reading. So does a top-level "mcp_servers"
// key in any case (the MCP connector, whose loop the API runs server-side and which has no tools[] entry).

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// mtKey is the one field the MaxTokensScanner reads.
const mtKey = "max_tokens"

// mtMaxKey is the longest raw key the MaxTokensScanner holds to compare: the longest key it recognises is mcp_servers,
// which with every byte \u-escaped is 66 bytes, so a longer key cannot decode to any of them.
const mtMaxKey = 6 * len("mcp_servers")

// mtMaxScalar is the longest scalar value of the top-level object the MaxTokensScanner holds for max_tokens; a longer
// one is no int anything accepts as max_tokens.
const mtMaxScalar = 18

// mtState is where the MaxTokensScanner is in the top-level object's grammar: { key : value , key : value }.
type mtState uint8

const (
	mtWantKey mtState = iota
	mtInKey
	mtWantColon
	mtWantValue
	mtInScalar // a number or literal value of the top-level object
	mtWantComma
)

// MaxTokensScanner reads max_tokens off a JSON object written to it in any number of pieces. The zero value is ready.
type MaxTokensScanner struct {
	depth    int // 0 before the object and after it, 1 inside it, more inside a nested value
	inString bool
	escape   bool
	want     mtState
	started  bool
	ended    bool
	bad      bool // the body is not one JSON object

	key     []byte
	keyLong bool
	match   bool // the value being read belongs to an exact max_tokens key
	scalar  []byte

	exact    int  // exact-case max_tokens keys
	variant  bool // a key equal to max_tokens but for case
	unusable bool // an exact max_tokens whose value is not a positive integer
	value    int

	// The reading of the tools array (server-tool detection): toolsKey says the next value is the exact "tools"
	// key's, tools counts those keys, inTools says the reader is inside its array, and tState is where it is in
	// the entry at depth 3.
	toolsKey   bool
	tools      int
	inTools    bool
	tState     toolState
	tType      bool // the entry's key just read is "type"
	tHold      bool // the string in progress at depth 3 is a tools entry's key or value, held in s.key
	serverTool bool // a server tool, or something that could be one
}

// toolState is where the reader is in one tools entry: { key : value , key : value }.
type toolState uint8

const (
	toolNone toolState = iota // not in an object entry
	toolKey
	toolColon
	toolValue
	toolAfter // a string value has ended; a comma starts the next key
)

// Write feeds the next bytes of the body. It never fails.
func (s *MaxTokensScanner) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 && !s.bad {
		switch {
		case s.inString:
			p = s.stringBytes(p)
			continue
		case s.depth > 1:
			// Inside a nested value only strings and brackets matter (and, in a tools entry's own object, the
			// colon and comma that say which string is a key and which a value).
			set := "\"{}[]"
			if s.inTools && s.depth == 3 {
				set = "\"{}[]:,"
			}
			i := bytes.IndexAny(p, set)
			if i < 0 {
				return n, nil
			}
			s.nested(p[i])
			p = p[i+1:]
			continue
		}
		s.top(p[0])
		p = p[1:]
	}
	return n, nil
}

// Result is the request's max_tokens, and whether the body stated one by the rules above.
func (s *MaxTokensScanner) Result() (int, bool) {
	if s == nil || s.bad || !s.ended || s.exact != 1 || s.variant || s.unusable || s.value <= 0 || s.serverTool {
		return 0, false
	}
	return s.value, true
}

// RequestMaxTokens reads max_tokens off a whole body by the MaxTokensScanner's rules. derive calls it only for a
// stream cut before its final message_delta, the one exchange the bound is charged to.
func RequestMaxTokens(body []byte) (int, bool) {
	var s MaxTokensScanner
	_, _ = s.Write(body)
	return s.Result()
}

// stringBytes consumes bytes inside a string, holding them when the string is a top-level key.
func (s *MaxTokensScanner) stringBytes(p []byte) []byte {
	holding := (s.depth == 1 && s.want == mtInKey) || s.tHold
	for len(p) > 0 {
		if s.escape {
			s.escape = false
			s.hold(holding, p[:1])
			p = p[1:]
			continue
		}
		i := bytes.IndexAny(p, "\"\\")
		if i < 0 {
			s.hold(holding, p)
			return nil
		}
		s.hold(holding, p[:i])
		if p[i] == '\\' {
			s.escape = true
			s.hold(holding, p[i:i+1])
			p = p[i+1:]
			continue
		}
		s.inString = false
		if holding {
			if s.tHold {
				s.tHold = false
				s.endToolString()
			} else {
				s.endKey()
			}
		}
		return p[i+1:]
	}
	return p
}

// hold keeps part of a top-level key, up to mtMaxKey.
func (s *MaxTokensScanner) hold(holding bool, p []byte) {
	if !holding || s.keyLong {
		return
	}
	if len(s.key)+len(p) > mtMaxKey {
		s.keyLong = true
		return
	}
	s.key = append(s.key, p...)
}

// endKey compares a finished top-level key with max_tokens, as a JSON parser would see it: escapes undone.
func (s *MaxTokensScanner) endKey() {
	s.want, s.match = mtWantColon, false
	if s.keyLong {
		return
	}
	k := s.key
	if bytes.IndexByte(k, '\\') >= 0 {
		var decoded string
		quoted := make([]byte, 0, len(k)+2)
		quoted = append(append(append(quoted, '"'), k...), '"')
		if json.Unmarshal(quoted, &decoded) != nil {
			s.bad = true
			return
		}
		k = []byte(decoded)
	}
	switch {
	case string(k) == mtKey:
		s.exact++
		s.match = true
	case bytes.EqualFold(k, []byte(mtKey)):
		s.variant = true
	case string(k) == "tools":
		s.tools++
		s.toolsKey = true
		s.serverTool = s.serverTool || s.tools > 1
	case bytes.EqualFold(k, []byte("tools")):
		s.serverTool = true
	case bytes.EqualFold(k, []byte("mcp_servers")):
		// The MCP connector runs its tool loop server-side: no tools[] entry, the same lost final report.
		s.serverTool = true
	}
}

// heldString is a string held in s.key, escapes undone; ok is false when it was too long to hold or is not valid.
func (s *MaxTokensScanner) heldString() (string, bool) {
	if s.keyLong {
		return "", false
	}
	if bytes.IndexByte(s.key, '\\') < 0 {
		return string(s.key), true
	}
	quoted := append(append([]byte{'"'}, s.key...), '"')
	var decoded string
	if json.Unmarshal(quoted, &decoded) != nil {
		return "", false
	}
	return decoded, true
}

// endToolString settles a key or value string held at depth 3 of the tools array.
func (s *MaxTokensScanner) endToolString() {
	v, ok := s.heldString()
	switch s.tState {
	case toolKey:
		s.tState, s.tType = toolColon, ok && v == "type"
		if !ok || (v != "type" && bytes.EqualFold([]byte(v), []byte("type"))) {
			// A key too long or malformed to compare could be type, and so could another case of it.
			s.tType, s.serverTool = true, true
		}
	case toolValue:
		if s.tType && (!ok || v != "custom") {
			s.serverTool = true
		}
		s.tState = toolAfter
	case toolNone, toolColon, toolAfter:
	}
}

// nested reads a quote or bracket inside a nested value.
func (s *MaxTokensScanner) nested(c byte) {
	switch c {
	case '"':
		s.inString = true
		if s.inTools && s.depth == 3 && (s.tState == toolKey || s.tState == toolValue) {
			s.tHold, s.key, s.keyLong = true, s.key[:0], false
		}
	case '{', '[':
		s.depth++
		if s.inTools && s.depth == 3 {
			s.tState = toolNone
			if c == '{' {
				s.tState = toolKey
			}
		} else if s.inTools && s.depth == 4 && s.tState == toolValue && s.tType {
			s.serverTool = true // a type that is an object or an array is no plain "custom"
		}
	case '}', ']':
		if s.inTools && s.depth == 3 && s.tState == toolValue && s.tType {
			s.serverTool = true // the entry ended on a type value that was no string
		}
		s.depth--
		if s.depth == 1 {
			s.want, s.inTools = mtWantComma, false
		}
	case ':':
		if s.tState == toolColon {
			s.tState = toolValue
		}
	case ',':
		if s.tState == toolValue && s.tType {
			s.serverTool = true // a type value that was no string
		}
		if s.tState != toolNone {
			s.tState = toolKey
		}
	}
}

// top reads one byte outside any string at depth 0 or 1.
func (s *MaxTokensScanner) top(c byte) {
	if s.want == mtInScalar {
		if !mtDelimiter(c) {
			if s.match && len(s.scalar) < mtMaxScalar+1 {
				s.scalar = append(s.scalar, c)
			}
			return
		}
		s.endScalar()
		s.want = mtWantComma
	}
	if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
		return
	}
	switch {
	case !s.started:
		if c != '{' {
			s.bad = true
			return
		}
		s.started, s.depth, s.want = true, 1, mtWantKey
		return
	case s.ended:
		s.bad = true // bytes after the object: not one JSON value
		return
	}
	switch s.want {
	case mtWantKey:
		switch c {
		case '"':
			s.inString, s.want, s.key, s.keyLong = true, mtInKey, s.key[:0], false
		case '}':
			s.end()
		default:
			s.bad = true
		}
	case mtWantColon:
		if c != ':' {
			s.bad = true
			return
		}
		s.want = mtWantValue
	case mtWantValue:
		s.startValue(c)
	case mtWantComma:
		switch c {
		case ',':
			s.want = mtWantKey
		case '}':
			s.end()
		default:
			s.bad = true
		}
	default:
		s.bad = true
	}
}

// startValue begins a value of the top-level object.
func (s *MaxTokensScanner) startValue(c byte) {
	if s.toolsKey {
		s.toolsKey = false
		switch {
		case c == '[':
			s.inTools = true
		case c != 'n': // null declares nothing; anything else is a tools value this reader cannot follow
			s.serverTool = true
		}
	}
	switch c {
	case '"':
		s.inString, s.want = true, mtWantComma
	case '{', '[':
		s.depth++
	default:
		s.want, s.scalar = mtInScalar, append(s.scalar[:0], c)
		return
	}
	if s.match {
		s.unusable = true // a string, an object or an array is no max_tokens
	}
}

// endScalar settles a number or literal value; only max_tokens's is read.
func (s *MaxTokensScanner) endScalar() {
	if !s.match {
		return
	}
	v, ok := positiveInt(s.scalar)
	if !ok {
		s.unusable = true
		return
	}
	s.value = v
}

// end is the top-level object's closing brace.
func (s *MaxTokensScanner) end() {
	s.depth, s.ended = 0, true
}

// mtDelimiter reports whether c ends a scalar value.
func mtDelimiter(c byte) bool {
	switch c {
	case ',', '}', ']', ' ', '\t', '\r', '\n', '"', '{', '[', ':':
		return true
	}
	return false
}

// positiveInt reads a JSON integer with no sign, fraction, exponent or leading zero, above zero.
func positiveInt(b []byte) (int, bool) {
	if len(b) == 0 || len(b) > mtMaxScalar || b[0] == '0' {
		return 0, false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	v, err := strconv.Atoi(string(b))
	return v, err == nil && v > 0
}
