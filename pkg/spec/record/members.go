// SPDX-License-Identifier: Apache-2.0

package record

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Strings reads the top-level members of one line that Decode would take as the named keys, each a JSON string, and
// returns their values in the order of keys ("" for a key the line does not carry). It is for a view that counts by
// a line's kind, rule or verdict (or a payload string such as command_rule) and must not pay for a full Decode of
// every line, and it reads the line as data and never as text: the order of the line's keys, the spaces between its
// tokens and an escaped spelling of a key or a value ("ru\u006ce", "a\"b") change nothing, which a search of the
// bytes for `"rule":"` cannot promise. A key inside a nested value is not a top-level member and is never read.
//
// It agrees with Decode on the lines it refuses for what it reads: a line that is not one valid JSON object, whose v
// is not 1 (a newer writer's line, or none), that carries an asked key twice, or whose asked common field (kind,
// rule, verdict ...) holds a value that is not a string, is an error wrapping ErrMalformedLine (ErrUnsupportedVersion
// for v), so a count that skips the lines Strings refuses skips the lines a full decode would for the same reason. A
// payload key that holds no string reads as "". It checks no key it was not asked for beyond the line being valid
// JSON, and applies none of Validate's semantic rules (kind set, required fields), as Decode does not either.
func Strings(line []byte, keys ...string) ([]string, error) {
	if len(keys) > 64 {
		return nil, fmt.Errorf("record: Strings reads at most 64 keys, got %d", len(keys))
	}
	line = bytes.TrimSuffix(line, []byte{'\n'})
	i := skipSpace(line, 0)
	if i >= len(line) || line[i] != '{' {
		return nil, fmt.Errorf("%w: not a JSON object", ErrMalformedLine)
	}
	if !json.Valid(line) {
		return nil, fmt.Errorf("%w: not valid JSON", ErrMalformedLine)
	}
	out := make([]string, len(keys))
	var seen uint64 // the asked keys met (at most 64, as every caller asks a handful)
	haveV := false
	i = skipSpace(line, i+1)
	for first := true; i < len(line) && line[i] != '}'; first = false {
		if !first {
			if line[i] != ',' {
				return nil, fmt.Errorf("%w: expected ',' at offset %d", ErrMalformedLine, i)
			}
			i = skipSpace(line, i+1)
		}
		keyEnd := scanString(line, i)
		if keyEnd < 0 || line[i] != '"' {
			return nil, fmt.Errorf("%w: expected a string key at offset %d", ErrMalformedLine, i)
		}
		keyTok := line[i:keyEnd]
		i = skipSpace(line, keyEnd)
		if i >= len(line) || line[i] != ':' {
			return nil, fmt.Errorf("%w: expected ':' after a key", ErrMalformedLine)
		}
		i = skipSpace(line, i+1)
		end := scanValue(line, i)
		if end < 0 {
			return nil, fmt.Errorf("%w: a value is unterminated", ErrMalformedLine)
		}
		val := line[i:end]
		i = skipSpace(line, end)
		k, isV := -1, false
		switch {
		case keyIs(keyTok, "v"):
			isV = true
		default:
			for j := range keys {
				if keyIs(keyTok, keys[j]) {
					k = j
					break
				}
			}
		}
		switch {
		case isV:
			if haveV {
				return nil, fmt.Errorf("%w: duplicate key %q", ErrMalformedLine, "v")
			}
			haveV = true
			if v, err := parseInt(val); err != nil || v != Version {
				if err == nil && v > Version {
					return nil, fmt.Errorf("%w: %w: v=%s", ErrUnsupportedVersion, ErrNewerVersion, val)
				}
				return nil, fmt.Errorf("%w: v=%s", ErrUnsupportedVersion, val)
			}
		case k >= 0:
			if seen&(1<<k) != 0 {
				return nil, fmt.Errorf("%w: duplicate key %q", ErrMalformedLine, keys[k])
			}
			seen |= 1 << k
			s, err := unquote(val)
			switch {
			case err == nil:
				out[k] = s
			case IsCommonField(keys[k]):
				return nil, fmt.Errorf("%w: %s: %w", ErrMalformedLine, keys[k], err)
			} // a payload key that holds no string reads as absent, as a payload that Decode does not look into
		}
	}
	if i >= len(line) {
		return nil, fmt.Errorf("%w: %w", ErrMalformedLine, errors.New("unexpected end of object"))
	}
	if !haveV {
		return nil, fmt.Errorf("%w: missing v", ErrUnsupportedVersion)
	}
	return out, nil
}

// keyIs reports whether the key token tok (quotes included) spells name, with or without escapes. A name is plain
// ASCII, so an escaped spelling of it is longer than the name (every escape of a name's character is six bytes), and a
// token shorter than the name plus its quotes spells none.
func keyIs(tok []byte, name string) bool {
	switch n := len(tok) - 2; {
	case n < len(name):
		return false
	case n == len(name):
		return string(tok[1:len(tok)-1]) == name
	case bytes.IndexByte(tok, '\\') < 0:
		return false
	}
	s, err := unquote(tok)
	return err == nil && sanitizeUTF8(s) == name
}
