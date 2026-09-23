// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// HeadersField is the payload key the redaction stage filters: an object of header name to value, as capture
// and the forwarder record it on ssl_request and ssl_response events.
const HeadersField = "headers"

// PathField is the payload key holding an ssl_request's HTTP request target, the second place on a captured
// request where a credential can appear (RedactTarget).
const PathField = "path"

// RedactedValue replaces a query parameter's value. It is not the empty string, which a request could have
// sent for real, so a reader can tell a removed value from an absent one.
const RedactedValue = "redacted"

// AllowedHeaders is the R9 allow-list: the only header names that ever reach disk, compared case-insensitively.
var AllowedHeaders = []string{"anthropic-version", "request-id", "content-type", "user-agent", "traceparent", "tracestate"}

// DeniedHeaders are the credential headers R9 names explicitly. The allow-list already excludes them; they
// are listed so the guarantee is stated in code and tested by name.
var DeniedHeaders = []string{"x-api-key", "authorization", "cookie", "proxy-authorization"}

// RecordedHeaders is the part of h a capture source places in an ssl_request or ssl_response payload:
// AllowedHeaders alone, keyed as that list spells them, a repeated field's values joined on ", " as RFC 9110
// §5.3 combines them. It is nil when none is present. Both capture paths call it, so they record one set of
// names and no credential is ever placed in an event, not even one Redact would remove (I5).
func RecordedHeaders(h http.Header) map[string]string {
	var out map[string]string
	for _, name := range AllowedHeaders {
		vs := h.Values(name)
		if len(vs) == 0 {
			continue
		}
		if out == nil {
			out = make(map[string]string, len(AllowedHeaders))
		}
		out[name] = strings.Join(vs, ", ")
	}
	return out
}

var allowedHeaders = func() map[string]struct{} {
	m := make(map[string]struct{}, len(AllowedHeaders))
	for _, h := range AllowedHeaders {
		m[h] = struct{}{}
	}
	return m
}()

// RedactStage is the R9 pipeline stage: it applies Redact and then calls next. internal/runtime composes it
// ahead of SplitBlobsStage and Append for every record mode (I2).
func RedactStage(next Sink) Sink {
	return func(e *record.Event) error {
		if err := Redact(e); err != nil {
			return err
		}
		return next(e)
	}
}

// RedactStage is the method form of the package-level RedactStage, so a pipeline reads
// Compose(stampRule, attributeStep, w.RedactStage, w.SplitBlobsStage)(w.Append) as the design names it.
func (w *Writer) RedactStage(next Sink) Sink { return RedactStage(next) }

// Redact filters captured headers and projects request targets onto a fixed set of public API routes.
// It does not discover secrets embedded in bodies or allowed header values.
//
// The headers object keeps only AllowedHeaders, keyed in lower case; every other header, credentials first
// among them, is dropped regardless of casing or duplication. A headers value that is not an object is
// dropped whole: an unknown shape is never persisted.
//
// Captured request targets and HTTP decision/refusal paths additionally go
// through RedactTarget, including credentials carried in resource identifiers.
//
// Both apply to every source alike ("on the loopback leg too"). An event with neither field is left
// byte-identical, and so is one whose fields hold nothing to remove.
//
// Only the top level of the payload is walked (topLevelMembers), and only the headers and path values are
// decoded. An ssl_request still carries its whole body inline here, up to 64 MiB, because the blob split runs
// after this stage; decoding it to find two small fields cost a full parse per request, and a second one when
// the body quoted the word headers. A rewrite splices the redacted members into the payload as written, so
// the body is copied once and never re-encoded. The walk bounds values without validating them: a payload
// that is not valid JSON is refused whole downstream (the blob split's decode, MarshalLine's json.Valid), so
// nothing Redact passes over unread reaches disk.
func Redact(e *record.Event) error {
	if len(e.Payload) == 0 {
		return nil
	}
	// The substring checks are only a shortcut for the common payload. A key can be spelled with JSON escapes
	// ("headers"), which they cannot see and MarshalLine still writes to disk as a plain "headers", so a
	// payload holding any \u escape always goes through the walk below, which sees the decoded keys. A key
	// can also be spelled in another case ("Headers", "PATH"), and readers decode with encoding/json, which
	// matches a field name case-insensitively, so the checks fold case too (containsKeyFold). Only a \u
	// escape can spell a letter, so any other backslash (an argv's quote, a body's newline) leaves every
	// key's letters in the bytes containsKeyFold scans and is no reason to walk.
	escaped := bytes.Contains(e.Payload, []byte(`\u`))
	hasHeaders := escaped || containsKeyFold(e.Payload, HeadersField)
	// HTTP decision paths and their refused companion targets share the captured
	// request's resource-path privacy rule. Filesystem/socket evidence stays exact.
	hasTarget := e.Kind == record.KindSSLRequest && (escaped || containsKeyFold(e.Payload, PathField))
	mayHTTPAction := (e.Kind == record.KindNet || e.Kind == record.KindRefused) && (escaped || containsKeyFold(e.Payload, "op"))
	if !hasHeaders && !hasTarget && !mayHTTPAction {
		return nil
	}
	members, err := topLevelMembers(e.Payload)
	if err != nil {
		return fmt.Errorf("ledger: redact: %w", err)
	}
	targetField := PathField
	if mayHTTPAction {
		// Any decoded spelling counts, duplicates included; a later duplicate
		// operation must not hide an HTTP target from privacy filtering.
		for _, m := range members {
			if !strings.EqualFold(m.key, "op") {
				continue
			}
			var op string
			if json.Unmarshal(m.val, &op) == nil && op == "http_request" {
				hasTarget = true
				if e.Kind == record.KindRefused {
					targetField = "target"
				}
				break
			}
		}
	}
	changed := false
	// Every spelling a reader would take for the field is redacted where it stands, duplicates included: a
	// reader keeps one of them by its order in the line, and each is made safe to keep.
	// A headers object that already holds only allow-listed, lower-case names is left as written, so an ssl
	// event whose producer recorded RecordedHeaders is not rewritten, body and all, for nothing.
	for i := range members {
		m := &members[i]
		switch {
		case strings.EqualFold(m.key, HeadersField):
			kept, same := filterHeaders(m.val)
			switch {
			case len(kept) == 0:
				m.drop = true
			case m.key == HeadersField && same:
				continue
			default:
				b, err := marshalPayload(kept)
				if err != nil {
					return fmt.Errorf("ledger: redact: %w", err)
				}
				m.repl = b
			}
			changed = true
		case hasTarget && strings.EqualFold(m.key, targetField):
			ok, err := redactPath(m)
			if err != nil {
				return err
			}
			changed = changed || ok
		}
	}
	if !changed {
		return nil
	}
	e.Payload = spliceMembers(e.Payload, members)
	return nil
}

// member is one top-level field of a payload: its decoded key, the bytes from its key's opening quote to the
// end of its value (raw), and its value (val). Redact sets drop to remove it or repl to replace its value.
type member struct {
	key      string
	raw, val []byte
	repl     []byte
	drop     bool
}

// topLevelMembers splits the JSON object payload into its top-level members without decoding their values:
// a string value, however long, is skipped by searching for its closing quote. Keys are decoded, escapes and
// all, since a key is what Redact matches. It errors on a payload whose structure it cannot bound (not an
// object, an unterminated value, trailing data); it does not validate what lies inside a value.
func topLevelMembers(raw []byte) ([]member, error) {
	i := skipJSONSpace(raw, 0)
	if i >= len(raw) || raw[i] != '{' {
		return nil, errors.New("payload is not a JSON object")
	}
	i = skipJSONSpace(raw, i+1)
	var out []member
	for i < len(raw) && raw[i] != '}' {
		if len(out) > 0 {
			if raw[i] != ',' {
				return nil, fmt.Errorf("expected ',' at offset %d", i)
			}
			i = skipJSONSpace(raw, i+1)
		}
		if i >= len(raw) || raw[i] != '"' {
			return nil, fmt.Errorf("expected a string key at offset %d", i)
		}
		start := i
		end := skipJSONString(raw, i)
		if end < 0 {
			return nil, fmt.Errorf("unterminated key at offset %d", i)
		}
		var key string
		if err := json.Unmarshal(raw[i:end], &key); err != nil {
			return nil, fmt.Errorf("key at offset %d: %w", i, err)
		}
		i = skipJSONSpace(raw, end)
		if i >= len(raw) || raw[i] != ':' {
			return nil, fmt.Errorf("expected ':' after key %q", key)
		}
		i = skipJSONSpace(raw, i+1)
		vend := skipJSONValue(raw, i)
		if vend <= i {
			return nil, fmt.Errorf("value of %q is unterminated", key)
		}
		out = append(out, member{key: key, raw: raw[start:vend], val: raw[i:vend]})
		i = skipJSONSpace(raw, vend)
	}
	if i >= len(raw) {
		return nil, errors.New("unexpected end of object")
	}
	if skipJSONSpace(raw, i+1) != len(raw) {
		return nil, errors.New("trailing data after the object")
	}
	return out, nil
}

// spliceMembers writes the object members describe: a kept member as it was written, a replaced member as
// its key bytes and its new value, a dropped member not at all. Whitespace between members is not kept.
func spliceMembers(raw []byte, members []member) []byte {
	size := len(raw)
	for _, m := range members {
		size += len(m.repl) // a redacted value can be longer than the one it replaces: one allocation, not a regrow
	}
	out := make([]byte, 0, size)
	out = append(out, '{')
	n := 0
	for _, m := range members {
		if m.drop {
			continue
		}
		if n > 0 {
			out = append(out, ',')
		}
		n++
		if m.repl == nil {
			out = append(out, m.raw...)
			continue
		}
		out = append(out, m.raw[:skipJSONString(m.raw, 0)]...)
		out = append(out, ':')
		out = append(out, m.repl...)
	}
	return append(out, '}')
}

// skipJSONSpace returns the index of the first byte at or after i that is not JSON whitespace.
func skipJSONSpace(raw []byte, i int) int {
	for i < len(raw) && (raw[i] == ' ' || raw[i] == '\n' || raw[i] == '\r' || raw[i] == '\t') {
		i++
	}
	return i
}

// skipJSONString returns the index after the closing quote of the string whose opening quote is raw[i], or
// -1. It jumps from quote to quote (bytes.IndexByte), and a quote preceded by an odd run of backslashes is
// escaped, so a long body costs a memchr, not a byte-at-a-time walk.
func skipJSONString(raw []byte, i int) int {
	for j := i + 1; j < len(raw); {
		q := bytes.IndexByte(raw[j:], '"')
		if q < 0 {
			return -1
		}
		j += q
		bs := 0
		for k := j - 1; k > i && raw[k] == '\\'; k-- {
			bs++
		}
		if bs%2 == 0 {
			return j + 1
		}
		j++
	}
	return -1
}

// skipJSONValue returns the index after the JSON value starting at raw[i], tracking nesting and strings, or
// -1. It bounds the value only.
func skipJSONValue(raw []byte, i int) int {
	if i >= len(raw) {
		return -1
	}
	switch raw[i] {
	case '"':
		return skipJSONString(raw, i)
	case '{', '[':
		depth := 0
		for j := i; j < len(raw); j++ {
			switch raw[j] {
			case '"':
				if j = skipJSONString(raw, j) - 1; j < 0 {
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

// redactPath rewrites m's path value and reports whether it changed. A path that is not a string is a shape
// the ledger does not know how to inspect, so it is dropped rather than persisted unexamined, exactly as a
// headers value of an unknown shape is.
func redactPath(m *member) (bool, error) {
	var target string
	if err := json.Unmarshal(m.val, &target); err != nil {
		m.drop = true
		return true, nil
	}
	red := RedactTarget(target)
	if red == target {
		return false, nil
	}
	b, err := marshalPayload(red)
	if err != nil {
		return false, fmt.Errorf("ledger: redact: %w", err)
	}
	m.repl = b
	return true, nil
}

// containsKeyFold reports whether payload may hold name as a key in any casing encoding/json accepts. It looks
// for a '"' followed by name folded over ASCII case and a closing '"', except that a final 'k' or 's' and the
// quote are left off the pattern: those two are the only ASCII letters with a non-ASCII fold (U+212A KELVIN
// SIGN, U+017F LATIN SMALL LETTER LONG S), so a key spelled "headerſ" is still found. A match is only a
// reason to walk the payload, so a false one costs time, never safety. A quote preceded by a backslash is
// skipped: in valid JSON a key's opening quote follows '{', ',' or whitespace, never a backslash, so an
// escaped quote inside a body ("say \"headers\"") starts no match.
func containsKeyFold(payload []byte, name string) bool {
	pat := name + `"`
	if last := name[len(name)-1] | 0x20; last == 'k' || last == 's' {
		pat = name[:len(name)-1]
	}
	for i := bytes.IndexByte(payload, '"'); i >= 0; {
		rest := payload[i+1:]
		if (i == 0 || payload[i-1] != '\\') && len(rest) >= len(pat) && asciiEqualFold(rest[:len(pat)], pat) {
			return true
		}
		j := bytes.IndexByte(rest, '"')
		if j < 0 {
			return false
		}
		i += 1 + j
	}
	return false
}

// asciiEqualFold reports whether b equals s with ASCII letters compared case-insensitively.
func asciiEqualFold(b []byte, s string) bool {
	for i := 0; i < len(s); i++ {
		c, d := b[i], s[i]
		if c == d {
			continue
		}
		if lc := c | 0x20; lc != d|0x20 || lc < 'a' || lc > 'z' {
			return false
		}
	}
	return true
}

// RedactTarget projects a request target onto a small, fixed vocabulary. Only the exact static routes
// below survive; every other path, including resource IDs and unknown API paths, becomes /redacted. Any
// query becomes ?redacted in its entirety: a name or bare flag can contain a credential as readily as a
// value, irrespective of its length. Absolute-form authorities and fragments never survive.
//
// This is a record policy, not credential detection. Forwarding and derive consume the original target
// before the ledger stage, so reducing recorded metadata does not change routing or metering. The result
// is idempotent and contains no client-chosen target text outside the fixed route vocabulary.
func RedactTarget(target string) string {
	target, _, _ = strings.Cut(target, "#")
	path, _, query := strings.Cut(target, "?")
	if i := authorityStart(path); i >= 0 {
		if slash := strings.IndexByte(path[i:], '/'); slash >= 0 {
			path = path[i+slash:]
		} else {
			path = "/"
		}
	}
	switch path {
	case "*", "/", "/v1/messages", "/v1/messages/count_tokens", "/v1/chat/completions",
		"/v1/responses", "/v1/models", "/v1/files", "/v1/messages/batches":
	default:
		path = "/" + RedactedValue
	}
	if query {
		return path + "?" + RedactedValue
	}
	return path
}

// authorityStart returns the index just past the "//" of an absolute-form target's authority, or -1 when the
// target has no authority. A scheme is one ALPHA followed by ALPHA / DIGIT / '+' / '-' / '.' (RFC 3986 §3.1).
func authorityStart(target string) int {
	c := strings.Index(target, "://")
	if c <= 0 {
		return -1
	}
	for i := 0; i < c; i++ {
		ch := target[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z':
		case i > 0 && (ch >= '0' && ch <= '9' || ch == '+' || ch == '-' || ch == '.'):
		default:
			return -1
		}
	}
	return c + 3
}

// filterHeaders keeps the allow-listed entries of a headers object. When two casings of one allowed name are
// present the lexically first original key wins, so the result is deterministic. A non-object yields nothing.
// same reports that the object already was its own result: every decoded key allow-listed and in lower case.
func filterHeaders(raw json.RawMessage) (kept map[string]json.RawMessage, same bool) {
	var headers map[string]json.RawMessage
	if err := json.Unmarshal(raw, &headers); err != nil {
		return nil, false
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	kept = map[string]json.RawMessage{}
	same = true
	for _, k := range keys {
		name := strings.ToLower(k)
		if _, allowed := allowedHeaders[name]; !allowed {
			same = false
			continue
		}
		if name != k {
			same = false
		}
		if _, dup := kept[name]; !dup {
			kept[name] = headers[k]
		}
	}
	return kept, same
}

// marshalPayload is json.Marshal without the HTML escaping: the producers encode their events that way
// (forwarder/event.go), so a payload this package rewrites keeps '&', '<', '>' and U+2028/9 as written.
func marshalPayload(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
