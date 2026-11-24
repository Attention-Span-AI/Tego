// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/scan/catalog"
)

const manifestBytes = 1 << 20

// manifestStream never materializes a document or an ignored string. Only keys
// are decoded, transiently; duplicate detection retains their digests, not text.
type manifestStream struct {
	ctx           context.Context
	r             *bufio.Reader
	bytes, tokens int
}

func (s *manifestStream) byte() (byte, error) {
	if err := s.ctx.Err(); err != nil {
		return 0, err
	}
	b, err := s.r.ReadByte()
	if err != nil {
		return 0, err
	}
	s.bytes++
	if s.bytes > manifestBytes {
		return 0, errSize
	}
	return b, nil
}
func (s *manifestStream) peek() (byte, error) {
	if err := s.ctx.Err(); err != nil {
		return 0, err
	}
	b, e := s.r.Peek(1)
	if e != nil {
		return 0, e
	}
	return b[0], nil
}
func (s *manifestStream) space() error {
	for {
		b, e := s.peek()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
			return nil
		}
		if _, e = s.byte(); e != nil {
			return e
		}
	}
}
func (s *manifestStream) want(b byte) error {
	v, e := s.byte()
	if e != nil {
		return e
	}
	if v != b {
		return errSyntax
	}
	return nil
}
func (s *manifestStream) token() error {
	s.tokens++
	if s.tokens > 4096 {
		return errLimit
	}
	return s.ctx.Err()
}
func (s *manifestStream) quoted(keep bool) (string, error) {
	var out strings.Builder
	var consume func(rune)
	if keep {
		consume = func(r rune) { out.WriteRune(r) }
	}
	if e := s.jsonString(4096, consume); e != nil {
		return "", e
	}
	return out.String(), nil
}

// jsonString validates and decodes one scalar. A zero limit discards input up to
// the file bound. Only the bounded selected-string caller supplies a buffer.
func (s *manifestStream) jsonString(limit int, consume func(rune)) error {
	if e := s.want('"'); e != nil {
		return e
	}
	n := 0
	take := func() (byte, error) {
		b, e := s.byte()
		if e == io.EOF {
			return 0, errSyntax
		}
		n++
		if limit > 0 && n > limit {
			return 0, errLimit
		}
		return b, e
	}
	hex := func() (uint16, error) {
		var v uint16
		for range 4 {
			b, e := take()
			if e != nil {
				return 0, e
			}
			v <<= 4
			switch {
			case b >= '0' && b <= '9':
				v += uint16(b - '0')
			case b >= 'a' && b <= 'f':
				v += uint16(b - 'a' + 10)
			case b >= 'A' && b <= 'F':
				v += uint16(b - 'A' + 10)
			default:
				return 0, errSyntax
			}
		}
		return v, nil
	}
	for {
		b, e := take()
		if e != nil {
			return e
		}
		var r rune
		switch {
		case b == '"':
			return nil
		case b < 0x20:
			return errSyntax
		case b == '\\':
			esc, e := take()
			if e != nil {
				return e
			}
			switch esc {
			case '"', '\\', '/':
				r = rune(esc)
			case 'b':
				r = '\b'
			case 'f':
				r = '\f'
			case 'n':
				r = '\n'
			case 'r':
				r = '\r'
			case 't':
				r = '\t'
			case 'u':
				u, e := hex()
				if e != nil {
					return e
				}
				r = rune(u)
				if u >= 0xd800 && u <= 0xdbff {
					b, e = take()
					if e != nil {
						return e
					}
					if b != '\\' {
						return errSyntax
					}
					b, e = take()
					if e != nil {
						return e
					}
					if b != 'u' {
						return errSyntax
					}
					v, e := hex()
					if e != nil {
						return e
					}
					if v < 0xdc00 || v > 0xdfff {
						return errSyntax
					}
					r = 0x10000 + ((rune(u) - 0xd800) << 10) + rune(v) - 0xdc00
				} else if u >= 0xdc00 && u <= 0xdfff {
					return errSyntax
				}
			default:
				return errSyntax
			}
		case b >= 0x80:
			var raw [utf8.UTFMax]byte
			raw[0] = b
			i := 1
			for !utf8.FullRune(raw[:i]) && i < len(raw) {
				raw[i], e = take()
				if e != nil {
					return e
				}
				i++
			}
			var size int
			r, size = utf8.DecodeRune(raw[:i])
			if r == utf8.RuneError && size == 1 {
				return errSyntax
			}
		default:
			r = rune(b)
		}
		if consume != nil {
			consume(r)
		}
	}
}

// quotedMatch retains only a matching supplied name. Unknown keys, including
// long project paths, are compared transiently without materializing them.
func (s *manifestStream) quotedMatch(names ...string) (string, error) {
	possible := make([]bool, len(names))
	for i := range possible {
		possible[i] = true
	}
	offset := 0
	e := s.jsonString(0, func(r rune) {
		var raw [utf8.UTFMax]byte
		chunk := utf8.AppendRune(raw[:0], r)
		for i, name := range names {
			if possible[i] && (offset+len(chunk) > len(name) || name[offset:offset+len(chunk)] != string(chunk)) {
				possible[i] = false
			}
		}
		offset += len(chunk)
	})
	if e != nil {
		return "", e
	}
	for i, name := range names {
		if possible[i] && offset == len(name) {
			return name, nil
		}
	}
	return "", nil
}

// skipJSON validates ignored data with constant storage per nesting level.
// It charges bytes and depth, never selected tokens or duplicate-key maps.
func (s *manifestStream) skipJSON(depth int) error {
	if depth > 32 {
		return errLimit
	}
	if e := s.space(); e != nil {
		return e
	}
	b, e := s.peek()
	if e != nil {
		return e
	}
	switch b {
	case '{', '[':
		if _, e = s.byte(); e != nil {
			return e
		}
		close := byte(']')
		if b == '{' {
			close = '}'
		}
		if e = s.space(); e != nil {
			return e
		}
		c, e := s.peek()
		if e != nil {
			return e
		}
		if c == close {
			return s.want(close)
		}
		for {
			if b == '{' {
				if e = s.jsonString(0, nil); e != nil {
					return e
				}
				if e = s.space(); e != nil {
					return e
				}
				if e = s.want(':'); e != nil {
					return e
				}
			}
			if e = s.skipJSON(depth + 1); e != nil {
				return e
			}
			if e = s.space(); e != nil {
				return e
			}
			c, e = s.byte()
			if e != nil {
				return e
			}
			if c == close {
				return nil
			}
			if c != ',' {
				return errSyntax
			}
			if e = s.space(); e != nil {
				return e
			}
		}
	case '"':
		return s.jsonString(0, nil)
	case 't', 'f', 'n':
		literal := "null"
		switch b {
		case 't':
			literal = "true"
		case 'f':
			literal = "false"
		}
		for i := range literal {
			if e = s.want(literal[i]); e != nil {
				return e
			}
		}
		return nil
	default:
		return s.skipJSONNumber()
	}
}

func (s *manifestStream) skipJSONNumber() error {
	peek := func() (byte, error) {
		b, e := s.peek()
		if e == io.EOF {
			return 0, nil
		}
		return b, e
	}
	digits := func() error {
		n := 0
		for {
			b, e := peek()
			if e != nil {
				return e
			}
			if b < '0' || b > '9' {
				if n == 0 {
					return errSyntax
				}
				return nil
			}
			if _, e = s.byte(); e != nil {
				return e
			}
			n++
		}
	}
	b, e := peek()
	if e != nil {
		return e
	}
	if b == '-' {
		if _, e = s.byte(); e != nil {
			return e
		}
		b, e = peek()
		if e != nil {
			return e
		}
	}
	switch {
	case b == '0':
		if _, e = s.byte(); e != nil {
			return e
		}
	case b >= '1' && b <= '9':
		if e = digits(); e != nil {
			return e
		}
	default:
		return errSyntax
	}
	b, e = peek()
	if e != nil {
		return e
	}
	if b == '.' {
		if _, e = s.byte(); e != nil {
			return e
		}
		if e = digits(); e != nil {
			return e
		}
		b, e = peek()
		if e != nil {
			return e
		}
	}
	if b == 'e' || b == 'E' {
		if _, e = s.byte(); e != nil {
			return e
		}
		b, e = peek()
		if e != nil {
			return e
		}
		if b == '-' || b == '+' {
			if _, e = s.byte(); e != nil {
				return e
			}
		}
		return digits()
	}
	return nil
}

// value's selected mode is used only for a top-level dependency table. Every
// other subtree is validated and streamed without extracting its values.
func (s *manifestStream) value(depth int, mode int, found map[string]catalog.Dependency) error {
	if depth > 32 {
		return errLimit
	}
	if e := s.token(); e != nil {
		return e
	}
	if e := s.space(); e != nil {
		return e
	}
	b, e := s.peek()
	if e != nil {
		return e
	}
	switch b {
	case '{':
		if e = s.want('{'); e != nil {
			return e
		}
		seen := map[[32]byte]bool{}
		entries := 0
		if e = s.space(); e != nil {
			return e
		}
		b, e = s.peek()
		if e != nil {
			return e
		}
		if b == '}' {
			return s.want('}')
		}
		for {
			if e = s.token(); e != nil {
				return e
			}
			key, e := s.quoted(true)
			if e != nil {
				return e
			}
			h := sha256.Sum256([]byte(key))
			if seen[h] {
				return errSyntax
			}
			seen[h] = true
			entries++
			if mode == 2 && entries > 128 {
				return errLimit
			}
			if e = s.space(); e != nil {
				return e
			}
			if e = s.want(':'); e != nil {
				return e
			}
			if e = s.space(); e != nil {
				return e
			}
			next := 0
			if mode == 1 && (key == "dependencies" || key == "devDependencies" || key == "optionalDependencies" || key == "peerDependencies") {
				next = 2
				b, e = s.peek()
				if e != nil {
					return e
				}
				if b != '{' {
					return errSyntax
				}
			}
			if mode == 2 {
				b, e = s.peek()
				if e != nil {
					return e
				}
				if b != '"' {
					return errSyntax
				}
			}
			if e = s.value(depth+1, next, found); e != nil {
				return e
			}
			if mode == 2 {
				if d, ok := catalog.DependencyNamed("npm", key); ok {
					found[d.ID] = d
				}
			}
			if e = s.space(); e != nil {
				return e
			}
			b, e = s.byte()
			if e != nil {
				return e
			}
			if b == '}' {
				return nil
			}
			if b != ',' {
				return errSyntax
			}
			if e = s.space(); e != nil {
				return e
			}
		}
	case '[':
		if e = s.want('['); e != nil {
			return e
		}
		if e = s.space(); e != nil {
			return e
		}
		b, e = s.peek()
		if e != nil {
			return e
		}
		if b == ']' {
			return s.want(']')
		}
		for {
			if e = s.value(depth+1, 0, found); e != nil {
				return e
			}
			if e = s.space(); e != nil {
				return e
			}
			b, e = s.byte()
			if e != nil {
				return e
			}
			if b == ']' {
				return nil
			}
			if b != ',' {
				return errSyntax
			}
		}
	case '"':
		_, e = s.quoted(false)
		return e
	case 't', 'f', 'n':
		text := "null"
		if b == 't' {
			text = "true"
		}
		if b == 'f' {
			text = "false"
		}
		for i := range text {
			if e = s.want(text[i]); e != nil {
				return e
			}
		}
		return nil
	default:
		// Numbers are bounded transient grammar input, never retained observations.
		raw := make([]byte, 0, 32)
		for {
			b, e = s.peek()
			if e == io.EOF {
				break
			}
			if e != nil {
				return e
			}
			if !strings.ContainsRune("0123456789eE+.-", rune(b)) {
				break
			}
			if len(raw) == 4096 {
				return errLimit
			}
			b, e = s.byte()
			if e != nil {
				return e
			}
			raw = append(raw, b)
		}
		if len(raw) == 0 || !json.Valid(raw) {
			return errSyntax
		}
		return nil
	}
}
func parseJSONDependencies(ctx context.Context, r io.Reader) ([]catalog.Dependency, error) {
	s := manifestStream{ctx: ctx, r: bufio.NewReaderSize(io.LimitReader(r, manifestBytes+1), 4096)}
	if e := s.space(); e != nil {
		return nil, e
	}
	b, e := s.peek()
	if e != nil || b != '{' {
		return nil, errSyntax
	}
	found := map[string]catalog.Dependency{}
	if e = s.value(0, 1, found); e != nil {
		return nil, e
	}
	if e = s.space(); e != nil {
		return nil, e
	}
	if _, e = s.peek(); e != io.EOF {
		return nil, errSyntax
	}
	return orderedDependencies(found), nil
}
func orderedDependencies(found map[string]catalog.Dependency) []catalog.Dependency {
	out := []catalog.Dependency{}
	for _, d := range catalog.Dependencies() {
		if _, ok := found[d.ID]; ok {
			out = append(out, d)
		}
	}
	return out
}

// Requirements lines stay in the scanner's bounded input buffer. Names alone
// are normalized for lookup; specifiers, markers and comments are never copied.
func parseRequirements(ctx context.Context, r io.Reader) ([]catalog.Dependency, error) {
	s := bufio.NewScanner(io.LimitReader(r, manifestBytes+1))
	s.Buffer(make([]byte, 4096), 4097)
	found := map[string]catalog.Dependency{}
	total, lines, entries := 0, 0, 0
	for s.Scan() {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		line := s.Bytes()
		total += len(line) + 1
		lines++
		if total > manifestBytes {
			return nil, errSize
		}
		if lines > 4096 {
			return nil, errLimit
		}
		if !utf8.Valid(line) {
			return nil, errSyntax
		}
		p := requirementLine{b: line}
		p.space()
		if p.end() || p.b[p.i] == '#' {
			continue
		}
		entries++
		if entries > 128 {
			return nil, errLimit
		}
		name, ok := p.name()
		if !ok {
			return nil, errUnsupported
		}
		// PEP 503 normalization folds case and runs of '.', '_' and '-'.
		var normalized strings.Builder
		sep := false
		for _, c := range name {
			if c == '.' || c == '_' || c == '-' {
				if !sep {
					normalized.WriteByte('-')
				}
				sep = true
			} else {
				sep = false
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				normalized.WriteByte(c)
			}
		}
		p.space()
		if p.take('[') {
			for {
				p.space()
				if _, ok = p.name(); !ok {
					return nil, errSyntax
				}
				p.space()
				if p.take(']') {
					break
				}
				if !p.take(',') {
					return nil, errSyntax
				}
			}
			p.space()
		}
		parens := p.take('(')
		p.space()
		if !p.end() && strings.ContainsRune("<>=!~", rune(p.b[p.i])) {
			for {
				if !p.specifier() {
					return nil, errUnsupported
				}
				p.space()
				if !p.take(',') {
					break
				}
				p.space()
			}
		} else if parens {
			return nil, errSyntax
		}
		if parens {
			if !p.take(')') {
				return nil, errSyntax
			}
			p.space()
		}
		if p.take(';') {
			if !p.marker(0) {
				return nil, errUnsupported
			}
			p.space()
		}
		if !p.end() && p.b[p.i] != '#' {
			return nil, errUnsupported
		}
		if d, ok := catalog.DependencyNamed("python", normalized.String()); ok {
			found[d.ID] = d
		}
	}
	if s.Err() != nil {
		return nil, errSize
	}
	return orderedDependencies(found), nil
}

type requirementLine struct {
	b []byte
	i int
}

func (p *requirementLine) end() bool { return p.i == len(p.b) }
func (p *requirementLine) space() {
	for !p.end() && (p.b[p.i] == ' ' || p.b[p.i] == '\t' || p.b[p.i] == '\r') {
		p.i++
	}
}
func (p *requirementLine) take(b byte) bool {
	if !p.end() && p.b[p.i] == b {
		p.i++
		return true
	}
	return false
}
func alphaNum(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}
func (p *requirementLine) name() ([]byte, bool) {
	start := p.i
	for !p.end() && (alphaNum(p.b[p.i]) || p.b[p.i] == '.' || p.b[p.i] == '_' || p.b[p.i] == '-') {
		p.i++
	}
	return p.b[start:p.i], p.i > start && alphaNum(p.b[start]) && alphaNum(p.b[p.i-1])
}
func (p *requirementLine) specifier() bool {
	start := p.i
	for !p.end() && strings.ContainsRune("<>=!~", rune(p.b[p.i])) {
		p.i++
	}
	op := string(p.b[start:p.i])
	switch op {
	case "<", ">", "<=", ">=", "==", "!=", "~=", "===":
	default:
		return false
	}
	p.space()
	start = p.i
	for !p.end() && (alphaNum(p.b[p.i]) || strings.ContainsRune(".*+!_-", rune(p.b[p.i]))) {
		p.i++
	}
	return p.i > start
}
func (p *requirementLine) word(w string) bool {
	if len(p.b)-p.i < len(w) || string(p.b[p.i:p.i+len(w)]) != w {
		return false
	}
	end := p.i + len(w)
	if end < len(p.b) && (alphaNum(p.b[end]) || p.b[end] == '_') {
		return false
	}
	p.i = end
	return true
}
func (p *requirementLine) operand() bool {
	p.space()
	if p.end() {
		return false
	}
	if q := p.b[p.i]; q == '\'' || q == '"' {
		p.i++
		for !p.end() && p.b[p.i] != q {
			if p.b[p.i] < 0x20 || p.b[p.i] == '\\' {
				return false
			}
			p.i++
		}
		return p.take(q)
	}
	for _, w := range []string{"python_version", "python_full_version", "os_name", "sys_platform", "platform_release", "platform_system", "platform_version", "platform_machine", "platform_python_implementation", "implementation_name", "implementation_version", "extra"} {
		if p.word(w) {
			return true
		}
	}
	return false
}
func (p *requirementLine) marker(depth int) bool {
	if depth > 32 {
		return false
	}
	p.space()
	if p.take('(') {
		if !p.marker(depth + 1) {
			return false
		}
		p.space()
		if !p.take(')') {
			return false
		}
	} else {
		if !p.operand() {
			return false
		}
		p.space()
		start := p.i
		if p.word("not") {
			p.space()
			if !p.word("in") {
				return false
			}
		} else if !p.word("in") {
			for !p.end() && strings.ContainsRune("<>=!~", rune(p.b[p.i])) {
				p.i++
			}
			op := string(p.b[start:p.i])
			switch op {
			case "<", ">", "<=", ">=", "==", "!=", "~=", "===":
			default:
				return false
			}
		}
		if !p.operand() {
			return false
		}
	}
	p.space()
	if p.word("and") || p.word("or") {
		return p.marker(depth + 1)
	}
	return true
}
