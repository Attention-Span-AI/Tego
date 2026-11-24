// SPDX-License-Identifier: Apache-2.0

package bizrule

import (
	"bytes"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

type member struct {
	key   string
	value *value
}
type value struct {
	kind   byte
	text   string
	object []member
	array  []*value
}

func (v *value) get(key string) *value {
	if v != nil {
		for _, m := range v.object {
			if m.key == key {
				return m.value
			}
		}
	}
	return nil
}
func (v *value) is(kind byte) bool { return v != nil && v.kind == kind }
func (v *value) string() string {
	if v.is('s') {
		return v.text
	}
	return ""
}
func (v *value) fields(keys ...string) bool {
	if !v.is('{') || len(v.object) != len(keys) {
		return false
	}
	for _, key := range keys {
		if v.get(key) == nil {
			return false
		}
	}
	return true
}

type lexer struct {
	data      []byte
	pos       int
	canonical bool
}
type lexeme struct {
	kind byte
	text string
	raw  []byte
}

func (l *lexer) next() (lexeme, bool) {
	for l.pos < len(l.data) && bytes.IndexByte([]byte(" \t\r\n"), l.data[l.pos]) >= 0 {
		l.pos++
		l.canonical = false
	}
	if l.pos == len(l.data) {
		return lexeme{}, true
	}
	start := l.pos
	c := l.data[l.pos]
	l.pos++
	if bytes.IndexByte([]byte("{}[]:,"), c) >= 0 {
		return lexeme{kind: c}, true
	}
	if c == '"' {
		out := []byte{}
		for l.pos < len(l.data) {
			c = l.data[l.pos]
			l.pos++
			if c == '"' {
				raw := l.data[start:l.pos]
				if !bytes.Equal(raw, appendString(nil, string(out))) {
					l.canonical = false
				}
				for _, b := range out {
					if b < 32 || b > 126 {
						l.canonical = false
					}
				}
				return lexeme{kind: 's', text: string(out), raw: raw}, true
			}
			if c < 32 {
				return lexeme{}, false
			}
			if c != '\\' {
				out = append(out, c)
				continue
			}
			if l.pos == len(l.data) {
				return lexeme{}, false
			}
			c = l.data[l.pos]
			l.pos++
			switch c {
			case '"', '\\', '/':
				out = append(out, c)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r, ok := l.hexRune()
				if !ok {
					return lexeme{}, false
				}
				if r >= 0xd800 && r <= 0xdbff {
					if l.pos+2 > len(l.data) || l.data[l.pos] != '\\' || l.data[l.pos+1] != 'u' {
						return lexeme{}, false
					}
					l.pos += 2
					low, ok := l.hexRune()
					if !ok || low < 0xdc00 || low > 0xdfff {
						return lexeme{}, false
					}
					r = utf16.DecodeRune(r, low)
				} else if r >= 0xdc00 && r <= 0xdfff {
					return lexeme{}, false
				}
				out = utf8.AppendRune(out, r)
			default:
				return lexeme{}, false
			}
		}
		return lexeme{}, false
	}
	for _, literal := range []string{"true", "false", "null"} {
		if c == literal[0] {
			if start+len(literal) > len(l.data) || string(l.data[start:start+len(literal)]) != literal {
				return lexeme{}, false
			}
			l.pos = start + len(literal)
			return lexeme{kind: c, text: literal}, true
		}
	}
	if c != '-' && (c < '0' || c > '9') {
		return lexeme{}, false
	}
	l.pos = start
	if l.data[l.pos] == '-' {
		l.pos++
		if l.pos == len(l.data) {
			return lexeme{}, false
		}
	}
	if l.data[l.pos] == '0' {
		l.pos++
	} else {
		if l.data[l.pos] < '1' || l.data[l.pos] > '9' {
			return lexeme{}, false
		}
		for l.pos < len(l.data) && digit(l.data[l.pos]) {
			l.pos++
		}
	}
	if l.pos < len(l.data) && l.data[l.pos] == '.' {
		l.pos++
		d := l.pos
		for l.pos < len(l.data) && digit(l.data[l.pos]) {
			l.pos++
		}
		if d == l.pos {
			return lexeme{}, false
		}
	}
	if l.pos < len(l.data) && (l.data[l.pos] == 'e' || l.data[l.pos] == 'E') {
		l.pos++
		if l.pos < len(l.data) && (l.data[l.pos] == '+' || l.data[l.pos] == '-') {
			l.pos++
		}
		d := l.pos
		for l.pos < len(l.data) && digit(l.data[l.pos]) {
			l.pos++
		}
		if d == l.pos {
			return lexeme{}, false
		}
	}
	raw := l.data[start:l.pos]
	if !integer(string(raw)) {
		l.canonical = false
	}
	return lexeme{kind: 'i', text: string(raw), raw: raw}, true
}
func (l *lexer) hexRune() (rune, bool) {
	if l.pos+4 > len(l.data) {
		return 0, false
	}
	var r rune
	for range 4 {
		c := l.data[l.pos]
		l.pos++
		r *= 16
		switch {
		case c >= '0' && c <= '9':
			r += rune(c - '0')
		case c >= 'a' && c <= 'f':
			r += rune(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			r += rune(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return r, true
}
func digit(c byte) bool { return c >= '0' && c <= '9' }
func integer(s string) bool {
	if s == "0" {
		return true
	}
	if len(s) > 0 && s[0] == '-' {
		s = s[1:]
	}
	if len(s) == 0 || s[0] < '1' || s[0] > '9' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !digit(s[i]) {
			return false
		}
	}
	return true
}

// grammar validates the entire input before considering limits, duplicates or
// spelling (B053). Its explicit stack is bounded by the already bounded bytes,
// so even a deeply nested refusal cannot overflow the Go call stack.
func grammar(data []byte) (bool, bool, bool) {
	if !utf8.Valid(data) {
		return false, false, false
	}
	type frame struct {
		kind  byte
		phase byte
		count int
	}
	stack := []frame{{kind: 'r'}}
	l := lexer{data: data, canonical: true}
	limited := false
	for {
		tok, ok := l.next()
		if !ok {
			return false, false, false
		}
		f := &stack[len(stack)-1]
		if tok.kind == 0 {
			return len(stack) == 1 && f.phase == 1, limited, l.canonical
		}
		expectValue := false
		switch f.kind {
		case 'r':
			if f.phase != 0 {
				return false, false, false
			}
			f.phase = 1
			expectValue = true
		case '{':
			switch f.phase {
			case 0, 4:
				if tok.kind == '}' && f.phase == 0 {
					stack = stack[:len(stack)-1]
					continue
				}
				if tok.kind != 's' {
					return false, false, false
				}
				f.count++
				if f.count > 64 {
					limited = true
				}
				f.phase = 1
			case 1:
				if tok.kind != ':' {
					return false, false, false
				}
				f.phase = 2
			case 2:
				f.phase = 3
				expectValue = true
			case 3:
				if tok.kind == '}' {
					stack = stack[:len(stack)-1]
					continue
				}
				if tok.kind != ',' {
					return false, false, false
				}
				f.phase = 4
			}
		case '[':
			switch f.phase {
			case 0, 2:
				if tok.kind == ']' && f.phase == 0 {
					stack = stack[:len(stack)-1]
					continue
				}
				f.phase = 1
				expectValue = true
			case 1:
				if tok.kind == ']' {
					stack = stack[:len(stack)-1]
					continue
				}
				if tok.kind != ',' {
					return false, false, false
				}
				f.phase = 2
			}
		}
		if expectValue {
			switch tok.kind {
			case '{', '[':
				stack = append(stack, frame{kind: tok.kind})
				if len(stack)-1 > 16 {
					limited = true
				}
			case 's', 'i', 't', 'f', 'n':
			default:
				return false, false, false
			}
		}
	}
}

func parse(data []byte, bound int) (*value, string) {
	if len(data) > bound {
		return nil, "input.limit"
	}
	valid, limited, canonical := grammar(data)
	if !valid {
		return nil, "input.json"
	}
	if limited {
		return nil, "input.limit"
	}
	l := lexer{data: data, canonical: true}
	duplicate := false
	var read func() *value
	read = func() *value {
		tok, _ := l.next()
		v := &value{kind: tok.kind, text: tok.text}
		switch tok.kind {
		case '{':
			tok, _ = l.next()
			previous := ""
			keys := map[string]bool{}
			for tok.kind != '}' {
				if keys[tok.text] {
					duplicate = true
				}
				keys[tok.text] = true
				if tok.text <= previous || !keyLabel(tok.text) || len(tok.raw) == 0 || bytes.IndexByte(tok.raw, '\\') >= 0 {
					canonical = false
				}
				previous = tok.text
				key := tok.text
				_, _ = l.next()
				child := read()
				v.object = append(v.object, member{key, child})
				tok, _ = l.next()
				if tok.kind == ',' {
					tok, _ = l.next()
				}
			}
		case '[':
			// Empty arrays need one token of lookahead without consuming a child.
			saved := l.pos
			tok, _ = l.next()
			l.pos = saved
			if tok.kind == ']' {
				_, _ = l.next()
				break
			}
			for {
				v.array = append(v.array, read())
				tok, _ = l.next()
				if tok.kind == ']' {
					break
				}
			}
		}
		return v
	}
	v := read()
	if duplicate {
		return nil, "input.duplicate"
	}
	if !canonical {
		return nil, "input.canonical"
	}
	return v, ""
}
func keyLabel(s string) bool {
	if len(s) == 0 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || digit(c) || c == '_') {
			return false
		}
	}
	return true
}
func appendString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			dst = append(dst, '\\')
		}
		dst = append(dst, s[i])
	}
	return append(dst, '"')
}
func appendValue(dst []byte, v *value) []byte {
	switch v.kind {
	case 's':
		return appendString(dst, v.text)
	case '{':
		dst = append(dst, '{')
		for i, m := range v.object {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendString(dst, m.key)
			dst = append(dst, ':')
			dst = appendValue(dst, m.value)
		}
		return append(dst, '}')
	case '[':
		dst = append(dst, '[')
		for i, child := range v.array {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendValue(dst, child)
		}
		return append(dst, ']')
	default:
		return append(dst, v.text...)
	}
}
func unsigned(s string, max uint64, zero bool) (uint64, bool) {
	if len(s) == 0 || len(s) > 20 || !integer(s) || s[0] == '-' || (!zero && s == "0") {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil && n <= max
}
