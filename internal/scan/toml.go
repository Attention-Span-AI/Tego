// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bufio"
	"context"
	"crypto/sha256"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// tomlStream accepts ordinary tables, dotted/quoted keys, single-line strings,
// arrays and inline tables. Multiline strings and array tables are explicitly
// unsupported, including in ignored subtrees; a prefix is never salvaged.
type tomlStream struct{ manifestStream }

func (s *tomlStream) whitespace(lines bool) error {
	for {
		b, e := s.peek()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		if b == '#' {
			for {
				b, e = s.peek()
				if e == io.EOF {
					return nil
				}
				if e != nil {
					return e
				}
				if b == '\n' {
					break
				}
				if e = s.commentRune(); e != nil {
					return e
				}
			}
			if !lines {
				return nil
			}
			continue
		}
		if b == ' ' || b == '\t' || b == '\r' || lines && b == '\n' {
			if _, e = s.byte(); e != nil {
				return e
			}
			continue
		}
		return nil
	}
}

// Comments are discarded, but must still be valid UTF-8 text.
func (s *tomlStream) commentRune() error {
	b, e := s.byte()
	if e != nil {
		return e
	}
	if b < 0x20 && b != '\t' && b != '\r' {
		return errSyntax
	}
	if b < utf8.RuneSelf {
		return nil
	}
	var raw [utf8.UTFMax]byte
	raw[0] = b
	n := 1
	for !utf8.FullRune(raw[:n]) && n < len(raw) {
		raw[n], e = s.byte()
		if e != nil {
			return errSyntax
		}
		n++
	}
	r, size := utf8.DecodeRune(raw[:n])
	if r == utf8.RuneError && size == 1 {
		return errSyntax
	}
	return nil
}

func (s *tomlStream) string(keep bool) (string, error) {
	q, e := s.byte()
	if e != nil {
		return "", e
	}
	if q != '"' && q != '\'' {
		return "", errSyntax
	}
	var out strings.Builder
	n := 0
	for {
		b, e := s.byte()
		if e != nil {
			return "", errSyntax
		}
		n++
		if n > 4096 {
			return "", errLimit
		}
		if b == q {
			return out.String(), nil
		}
		if b < 0x20 || b == 0x7f {
			return "", errUnsupported
		}
		if b == '\\' && q == '"' {
			b, e = s.byte()
			if e != nil {
				return "", errSyntax
			}
			n++
			switch b {
			case 'b':
				b = '\b'
			case 't':
				b = '\t'
			case 'n':
				b = '\n'
			case 'f':
				b = '\f'
			case 'r':
				b = '\r'
			case '"', '\\':
			case 'u', 'U':
				width := 4
				if b == 'U' {
					width = 8
				}
				var v uint32
				for range width {
					c, e := s.byte()
					if e != nil {
						return "", errSyntax
					}
					n++
					v <<= 4
					switch {
					case c >= '0' && c <= '9':
						v += uint32(c - '0')
					case c >= 'a' && c <= 'f':
						v += uint32(c - 'a' + 10)
					case c >= 'A' && c <= 'F':
						v += uint32(c - 'A' + 10)
					default:
						return "", errSyntax
					}
				}
				if v > utf8.MaxRune || v >= 0xd800 && v <= 0xdfff {
					return "", errSyntax
				}
				if keep {
					out.WriteRune(rune(v))
				}
				continue
			default:
				return "", errSyntax
			}
		}
		if b >= 0x80 {
			var raw [4]byte
			raw[0] = b
			i := 1
			for !utf8.FullRune(raw[:i]) && i < 4 {
				raw[i], e = s.byte()
				if e != nil {
					return "", errSyntax
				}
				i++
				n++
			}
			r, k := utf8.DecodeRune(raw[:i])
			if r == utf8.RuneError && k == 1 {
				return "", errSyntax
			}
			if keep {
				out.Write(raw[:i])
			}
		} else if keep {
			out.WriteByte(b)
		}
	}
}
func (s *tomlStream) key() ([]string, error) {
	keys := []string{}
	bytes := 0
	for {
		if e := s.token(); e != nil {
			return nil, e
		}
		if e := s.whitespace(false); e != nil {
			return nil, e
		}
		b, e := s.peek()
		if e != nil {
			return nil, e
		}
		var key string
		if b == '"' || b == '\'' {
			key, e = s.string(true)
		} else {
			var out strings.Builder
			for {
				b, e = s.peek()
				if e == io.EOF {
					break
				}
				if e != nil {
					return nil, e
				}
				if !alphaNum(b) && b != '_' && b != '-' {
					break
				}
				_, e = s.byte()
				if e != nil {
					return nil, e
				}
				out.WriteByte(b)
				if out.Len() > 4096 {
					return nil, errLimit
				}
			}
			key = out.String()
			if key == "" {
				e = errSyntax
			}
		}
		if e != nil {
			return nil, e
		}
		bytes += len(key)
		if len(keys) > 0 {
			bytes++
		}
		if bytes > 4096 {
			return nil, errLimit
		}
		keys = append(keys, key)
		if len(keys) > 32 {
			return nil, errLimit
		}
		if e = s.whitespace(false); e != nil {
			return nil, e
		}
		b, e = s.peek()
		if e != nil {
			return nil, e
		}
		if b != '.' {
			return keys, nil
		}
		if _, e = s.byte(); e != nil {
			return nil, e
		}
	}
}
func (s *tomlStream) value(depth int, keep bool) (string, int, error) {
	if depth > 32 {
		return "", 0, errLimit
	}
	if e := s.token(); e != nil {
		return "", 0, e
	}
	if e := s.whitespace(false); e != nil {
		return "", 0, e
	}
	b, e := s.peek()
	if e != nil {
		return "", 0, e
	}
	if b == '"' || b == '\'' {
		v, e := s.string(keep)
		return v, 0, e
	}
	if b == '[' || b == '{' {
		_, e = s.byte()
		if e != nil {
			return "", 0, e
		}
		close := byte(']')
		if b == '{' {
			close = '}'
		}
		count := 0
		seen := map[[32]byte]bool{}
		for {
			if e = s.whitespace(b == '['); e != nil {
				return "", 0, e
			}
			c, e := s.peek()
			if e != nil {
				return "", 0, e
			}
			if c == close {
				_, e = s.byte()
				return "", count, e
			}
			count++
			if count > 128 {
				return "", 0, errLimit
			}
			if b == '{' {
				k, e := s.key()
				if e != nil {
					return "", 0, e
				}
				h := sha256.Sum256([]byte(strings.Join(k, "\x00")))
				if seen[h] {
					return "", 0, errSyntax
				}
				seen[h] = true
				if e = s.want('='); e != nil {
					return "", 0, e
				}
				if e = s.whitespace(false); e != nil {
					return "", 0, e
				}
			} else if keep && c != '"' && c != '\'' {
				return "", 0, errSyntax
			}
			if _, _, e = s.value(depth+1, false); e != nil {
				return "", 0, e
			}
			if e = s.whitespace(b == '['); e != nil {
				return "", 0, e
			}
			c, e = s.byte()
			if e != nil {
				return "", 0, e
			}
			if c == close {
				return "", count, nil
			}
			if c != ',' {
				return "", 0, errSyntax
			}
			if b == '{' {
				if e = s.whitespace(false); e != nil {
					return "", 0, e
				}
				c, e = s.peek()
				if e != nil || c == close {
					return "", 0, errSyntax
				}
			}
		}
	}
	var out strings.Builder
	for {
		b, e = s.peek()
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", 0, e
		}
		if strings.ContainsRune(" \t\r\n#,]}", rune(b)) {
			break
		}
		_, e = s.byte()
		if e != nil {
			return "", 0, e
		}
		out.WriteByte(b)
		if out.Len() > 4096 {
			return "", 0, errLimit
		}
	}
	v := out.String()
	if v == "true" || v == "false" {
		return "", 0, nil
	}
	if v == "" {
		return "", 0, errSyntax
	}
	// Unrecognised primitives refuse rather than guessing TOML syntax. Numbers
	// are transient tokens. Canonical spellings avoid accepting malformed forms.
	if i, e := strconv.ParseInt(v, 10, 64); e == nil && strconv.FormatInt(i, 10) == v {
		return "", 0, nil
	}
	return "", 0, errUnsupported
}
func parseMCPTOML(ctx context.Context, r io.Reader) ([]mcpServer, error) {
	s := tomlStream{manifestStream{ctx: ctx, r: bufio.NewReaderSize(io.LimitReader(r, manifestBytes+1), 4096)}}
	out := []mcpServer{}
	indices := map[string]int{}
	tables := map[[32]byte]bool{}
	seen := map[[32]byte]bool{}
	children := map[[32]byte]bool{}
	ensureServer := func(name string) (int, error) {
		if !serverName(name) {
			return 0, errUnsupported
		}
		if i, ok := indices[name]; ok {
			return i, nil
		}
		if len(out) >= 128 {
			return 0, errLimit
		}
		i := len(out)
		indices[name] = i
		out = append(out, mcpServer{Name: name, Transport: "unknown"})
		return i, nil
	}
	var section []string
	sectionBytes := 0
	for {
		if e := s.whitespace(true); e != nil {
			return nil, e
		}
		b, e := s.peek()
		if e == io.EOF {
			return out, nil
		}
		if e != nil {
			return nil, e
		}
		if b == '[' {
			if e = s.want('['); e != nil {
				return nil, e
			}
			section, e = s.key()
			if e != nil {
				return nil, e
			}
			if e = s.want(']'); e != nil {
				return nil, errUnsupported
			}
			sectionBytes = len(strings.Join(section, "\x00"))
			h := sha256.Sum256([]byte(strings.Join(section, "\x00")))
			if tables[h] || seen[h] {
				return nil, errSyntax
			}
			for n := 1; n < len(section); n++ {
				if seen[sha256.Sum256([]byte(strings.Join(section[:n], "\x00")))] {
					return nil, errSyntax
				}
			}
			tables[h] = true
			for n := 1; n < len(section); n++ {
				children[sha256.Sum256([]byte(strings.Join(section[:n], "\x00")))] = true
			}
			if len(section) >= 2 && section[0] == "mcp_servers" {
				if _, e = ensureServer(section[1]); e != nil {
					return nil, e
				}
			}
		} else {
			key, e := s.key()
			if e != nil {
				return nil, e
			}
			if e = s.want('='); e != nil {
				return nil, e
			}
			if e = s.whitespace(false); e != nil {
				return nil, e
			}
			keyBytes := len(strings.Join(key, "\x00"))
			if len(section) > 0 {
				keyBytes++
			}
			if sectionBytes+keyBytes > 4096 {
				return nil, errLimit
			}
			full := append(append([]string{}, section...), key...)
			h := sha256.Sum256([]byte(strings.Join(full, "\x00")))
			if seen[h] || tables[h] || children[h] {
				return nil, errSyntax
			}
			for n := 1; n < len(full); n++ {
				if seen[sha256.Sum256([]byte(strings.Join(full[:n], "\x00")))] {
					return nil, errSyntax
				}
			}
			seen[h] = true
			for n := 1; n < len(full); n++ {
				children[sha256.Sum256([]byte(strings.Join(full[:n], "\x00")))] = true
			}
			if full[0] == "mcp_servers" && len(full) < 3 {
				return nil, errUnsupported
			}
			selected := len(full) == 3 && full[0] == "mcp_servers"
			idx := -1
			if selected {
				idx, e = ensureServer(full[1])
				if e != nil {
					return nil, e
				}
			}
			field := ""
			if selected {
				field = full[2]
			}
			b, e = s.peek()
			if e != nil {
				return nil, e
			}
			keep := field == "command" || field == "args"
			if (field == "command" || field == "url") && b != '"' && b != '\'' || field == "args" && b != '[' {
				return nil, errSyntax
			}
			v, n, e := s.value(0, keep)
			if e != nil {
				return nil, e
			}
			if selected {
				switch field {
				case "command":
					if out[idx].Transport == "http" {
						return nil, errUnsupported
					}
					out[idx].Program = mcpProgram(v)
					out[idx].Transport = "stdio"
				case "url":
					if out[idx].Transport == "stdio" {
						return nil, errUnsupported
					}
					out[idx].Transport = "http"
					out[idx].Program = ""
				case "args":
					out[idx].Arguments = n
				}
			}
		}
		if e = s.whitespace(false); e != nil {
			return nil, e
		}
		b, e = s.byte()
		if e == io.EOF {
			return out, nil
		}
		if e != nil {
			return nil, e
		}
		if b != '\n' {
			return nil, errUnsupported
		}
	}
}
