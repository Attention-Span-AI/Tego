// SPDX-License-Identifier: Apache-2.0

package record

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// objectFields splits one JSON object into its fields with values kept as compact raw bytes, keys sorted
// lexicographically by bytes. Duplicate keys and trailing data are errors. Keys arrive UTF-8-sanitized from
// scanKey, so the key compared and sorted here is the key the writer emits (E18, I9). It validates the bytes
// once with json.Valid and then scans them once more without building a tree (the hot path of MarshalLine and
// Decode).
// The error is not yet wrapped with a sentinel; callers add the one that fits their layer.
func objectFields(raw []byte) ([]field, error) {
	i := skipSpace(raw, 0)
	if i >= len(raw) || raw[i] != '{' {
		return nil, errors.New("not a JSON object")
	}
	// One validation pass over the whole object; the scanner below then only bounds keys and values.
	if !json.Valid(raw) {
		return nil, errors.New("not valid JSON")
	}
	i = skipSpace(raw, i+1)
	var fields []field
	for i < len(raw) && raw[i] != '}' {
		if len(fields) > 0 {
			if raw[i] != ',' {
				return nil, fmt.Errorf("expected ',' at offset %d", i)
			}
			i = skipSpace(raw, i+1)
		}
		key, next, err := scanKey(raw, i)
		if err != nil {
			return nil, err
		}
		i = skipSpace(raw, next)
		if i >= len(raw) || raw[i] != ':' {
			return nil, fmt.Errorf("expected ':' after key %q", key)
		}
		i = skipSpace(raw, i+1)
		end := scanValue(raw, i)
		if end < 0 {
			return nil, fmt.Errorf("value of %q is unterminated", key)
		}
		fields = append(fields, field{key: key, val: compactValue(raw[i:end])})
		i = skipSpace(raw, end)
	}
	if i >= len(raw) {
		return nil, errors.New("unexpected end of object")
	}
	if skipSpace(raw, i+1) != len(raw) {
		return nil, errors.New("trailing data after the object")
	}
	// Sorted first, so a duplicate is a neighbour: one pass instead of comparing every key with every
	// earlier one, which was quadratic in the keys of a line a tamperer writes (E16). SortStableFunc keeps
	// the first of two equal keys first, so the error names the key as before.
	slices.SortStableFunc(fields, func(a, b field) int { return strings.Compare(a.key, b.key) })
	for j := 1; j < len(fields); j++ {
		if fields[j].key == fields[j-1].key {
			return nil, fmt.Errorf("duplicate key %q", fields[j].key)
		}
	}
	return fields, nil
}

// skipSpace returns the index of the first non-whitespace byte at or after i.
func skipSpace(raw []byte, i int) int {
	for i < len(raw) && (raw[i] == ' ' || raw[i] == '\n' || raw[i] == '\r' || raw[i] == '\t') {
		i++
	}
	return i
}

// scanKey parses the object key starting at raw[i] and returns it, UTF-8-sanitized, with the index after its
// closing quote.
//
// The sanitization is not cosmetic and not deferred to the writer: a key is a dictionary key, and objectFields
// deduplicates, sorts and splices on it while canonical writes it through writeJSONString, which sanitizes
// (E18). Comparing the raw bytes but writing the sanitized ones let two keys that differ only in invalid UTF-8
// through as distinct, then collapsed them into one key on the line: MarshalLine emitted a line carrying the
// same key twice that Decode then rejected as malformed, breaking I9 and leaving that line -- and every line
// after it in the run -- unreadable. Sanitizing here makes such keys one key everywhere, so they are caught by
// the duplicate check at encode time instead. Value strings get no such treatment: they have no structural
// role, and Decode must report what the line actually holds.
func scanKey(raw []byte, i int) (string, int, error) {
	if i >= len(raw) || raw[i] != '"' {
		return "", 0, fmt.Errorf("expected a string key at offset %d", i)
	}
	end := scanString(raw, i)
	if end < 0 {
		return "", 0, errors.New("unterminated object key")
	}
	key, err := unquote(raw[i:end])
	if err != nil {
		return "", 0, fmt.Errorf("object key: %w", err)
	}
	return sanitizeUTF8(key), end, nil
}

// scanString returns the index after the closing quote of the string starting at raw[i], or -1.
func scanString(raw []byte, i int) int {
	for j := i + 1; j < len(raw); j++ {
		switch raw[j] {
		case '\\':
			j++
		case '"':
			return j + 1
		}
	}
	return -1
}

// scanValue returns the index after the JSON value starting at raw[i], tracking nesting and strings, or -1.
// It bounds the value only; json.Valid on the slice decides whether it is well formed.
func scanValue(raw []byte, i int) int {
	if i >= len(raw) {
		return -1
	}
	switch raw[i] {
	case '"':
		return scanString(raw, i)
	case '{', '[':
		depth := 0
		for j := i; j < len(raw); j++ {
			switch raw[j] {
			case '"':
				if j = scanString(raw, j) - 1; j < 0 {
					return -1
				}
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return j + 1
				}
			}
		}
		return -1
	}
	j := i
	for j < len(raw) && raw[j] != ',' && raw[j] != '}' && raw[j] != ']' && raw[j] != ' ' && raw[j] != '\n' &&
		raw[j] != '\r' && raw[j] != '\t' {
		j++
	}
	return j
}

// unquote decodes a JSON string token (quotes included) taken from an object objectFields validated. Strings
// without escapes are sliced, not decoded.
func unquote(tok []byte) (string, error) {
	if len(tok) < 2 || tok[0] != '"' || tok[len(tok)-1] != '"' {
		return "", errors.New("not a JSON string")
	}
	if bytes.IndexByte(tok, '\\') < 0 {
		return string(tok[1 : len(tok)-1]), nil
	}
	var s string
	if err := json.Unmarshal(tok, &s); err != nil {
		return "", err
	}
	return s, nil
}

// compactValue removes insignificant whitespace from a nested JSON value and replaces invalid UTF-8 by U+FFFD
// (E18). Scalars and strings carry no removable whitespace and are returned as they are. The input was
// validated by json.Valid, so json.Compact cannot fail; the defensive fallback keeps the original bytes rather
// than dropping a value.
//
// It sanitizes through sanitizeUTF8 rather than strings.ToValidUTF8 because the latter collapses a whole run of
// invalid bytes into a single U+FFFD while writeJSONString replaces each byte: the same two bytes in a payload
// value and in a common field would otherwise render differently on one line. JSON structure is ASCII, so
// replacement can only ever touch the inside of a string.
func compactValue(val []byte) []byte {
	b := val
	if len(val) > 0 && (val[0] == '{' || val[0] == '[') && bytes.ContainsAny(val, " \n\r\t") {
		var out bytes.Buffer
		if err := json.Compact(&out, val); err == nil {
			b = out.Bytes()
		}
	}
	if !utf8.Valid(b) {
		b = []byte(sanitizeUTF8(string(b)))
	}
	return b
}

// sanitizeUTF8 replaces every byte of s that is not part of a well-formed UTF-8 sequence with U+FFFD, one
// replacement per byte. It is the package's only UTF-8 repair, and its mapping is exactly the one
// writeJSONString applies while writing a string (E18), so a string that has passed through it is written
// unchanged. A valid string is returned without allocating.
func sanitizeUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteRune(utf8.RuneError)
			i++
			continue
		}
		b.WriteString(s[i : i+size])
		i += size
	}
	return b.String()
}

// parseUint parses a non-negative JSON integer token.
func parseUint(tok []byte) (uint64, error) {
	return strconv.ParseUint(string(tok), 10, 64)
}

// parseInt parses a JSON integer token.
func parseInt(tok []byte) (int, error) {
	v, err := strconv.ParseInt(string(tok), 10, 0)
	return int(v), err
}

// parseTime parses a JSON string token holding an RFC 3339 timestamp.
func parseTime(tok []byte) (time.Time, error) {
	s, err := unquote(tok)
	if err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339Nano, s)
}
