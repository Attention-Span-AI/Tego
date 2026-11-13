// SPDX-License-Identifier: Apache-2.0

package record

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"
)

// Sentinel errors of the codec. Every error returned by this package wraps one of them (%w), so callers test
// with errors.Is through any further wrapping.
var (
	// errMalformedObject distinguishes the JSON/object/unique-key gate from field validation so a malformed
	// suffix is reported before a stale digest, without parsing the same object twice in Chain.Add.
	errMalformedObject = errors.New("record: malformed JSON object")
	// ErrInvalidEvent is returned when an Event violates the v1 rules (docs/p0/record-ledger.md §2.1).
	ErrInvalidEvent = errors.New("record: invalid event")
	// ErrUnsupportedVersion is returned by Decode when v is missing or not 1 (R5).
	ErrUnsupportedVersion = errors.New("record: unsupported record version")
	// ErrNewerVersion is returned by Decode, beside ErrUnsupportedVersion, when v is an integer greater than
	// Version: a line a newer binary wrote. The views skip it with a warning and --verify still checks its link
	// in the chain (Chain.AddNewer); v 0, a negative or a non-integer v, and a missing v are not newer.
	ErrNewerVersion = errors.New("record: newer record version than this reader")
	// ErrPayloadFieldCollision is returned when a payload key is one of the common field names (E25).
	ErrPayloadFieldCollision = errors.New("record: payload field collides with a common field")
	// ErrMalformedLine is returned by Decode and VerifyLine when the bytes are not one JSON object.
	ErrMalformedLine = errors.New("record: malformed line")
	// ErrMalformedTimestamp identifies a timestamp refused by the record profile. Chain checks report this
	// malformed record before a stale digest, and framing must never discard it as a torn tail.
	ErrMalformedTimestamp = errors.New("record: malformed timestamp")
	// ErrIDMismatch is returned by VerifyLine when the id does not equal the digest of the line (R2).
	ErrIDMismatch = errors.New("record: id does not match line bytes")
	// ErrCorruptChain is returned by Chain when seq is not gapless or prev does not name the previous id (I3, I4).
	ErrCorruptChain = errors.New("record: hash chain broken")
)

// IDLen is the length of an event id: sha256 as lowercase hex.
const IDLen = 64

// zeroID is the frozen v1 digest placeholder, independent of exported compatibility values.
const zeroID = "0000000000000000000000000000000000000000000000000000000000000000"

// ZeroID is the placeholder that stands in for id while the digest is computed (R2).
// Assigning it does not change the codec's canonical bytes or verification.
var ZeroID = zeroID

// commonFields lists the common field names in canonical order (R1). Every other key on a line is payload.
var commonFields = [...]string{
	"v", "seq", "id", "prev", "ts", "mono_ns", "run", "agent", "pid", "tid", "cgroup", "kind", "source",
	"rule", "verdict", "authority", "reason", "attribution",
}

// IsCommonField reports whether key is one of the eighteen common field names of R1.
func IsCommonField(key string) bool {
	for _, f := range commonFields {
		if f == key {
			return true
		}
	}
	return false
}

// IsSharedField reports whether key is rule or reason: the two common fields the frozen wire format also
// names inside a payload (refused carries rule and reason, run_end carries reason; spec/record/v1/README.md).
// A shared key is written once, in its canonical slot; MarshalLine lifts it from Payload into Event.Rule or
// Event.Reason and Decode mirrors it back, so both views of an event stay complete.
func IsSharedField(key string) bool { return key == "rule" || key == "reason" }

// IsReservedField reports whether key is a common field a payload may never carry (E25): every common field
// except the two shared ones.
func IsReservedField(key string) bool { return IsCommonField(key) && !IsSharedField(key) }

// field is one key/value pair of a JSON object with its value kept as compact raw bytes.
type field struct {
	key string
	val []byte
}

// MarshalLine encodes e canonically, computes e.ID and returns the exact bytes a ledger writes for this event
// (without the "\n" terminator, which is framing, not content).
//
// R1: keys are written in the fixed order v seq id prev ts mono_ns run agent pid tid cgroup kind source rule
// verdict authority reason attribution, then the payload keys sorted; zero-value optional fields are dropped.
// R2: id = hex(sha256(line)) where line is this same serialization with id set to 64 zero characters; the returned bytes
// carry the real id at the same offset, so VerifyLine recomputes the digest by zeroing it again.
// R3: Payload is a JSON object spliced into the top level, its keys sorted; nested values are kept verbatim.
// E18: invalid UTF-8 in any string is replaced by U+FFFD, one per byte, never written raw and never an error --
// except in a payload key, where two keys that differ only in invalid bytes are one key once sanitized and so
// are rejected as a duplicate (ErrInvalidEvent) rather than written twice onto one line.
//
// MarshalLine validates e first (Validate) and never writes a partial line: on error the returned slice is nil
// and e.ID is unchanged.
func (e *Event) MarshalLine() ([]byte, error) { return e.marshalLine(-1) }

// MarshalLineAt is MarshalLine for a line of a ledger at revision minor (its run_start's record_minor), validated by
// ValidateAt's rules rather than Validate's alone: what a ledger Writer encodes, so a field malformed or below its
// revision is never written. minor is not negative.
func (e *Event) MarshalLineAt(minor int) ([]byte, error) {
	if minor < 0 {
		return nil, fmt.Errorf("%w: record_minor %d", ErrInvalidEvent, minor)
	}
	return e.marshalLine(minor)
}

// marshalLine is MarshalLine, and with minor 0 or more MarshalLineAt.
func (e *Event) marshalLine(minor int) ([]byte, error) {
	payload, shared, err := payloadFields(e.Payload)
	if err != nil {
		return nil, err
	}
	lifted := *e
	if err := shared.liftInto(&lifted); err != nil {
		return nil, err
	}
	if err := lifted.Validate(); err != nil {
		return nil, err
	}
	if minor >= 0 {
		if err := lifted.validateMVP(minor, payload); err != nil {
			return nil, err
		}
	}
	line, idOff := lifted.canonical(payload)
	sum := sha256.Sum256(line)
	// The second serialization of R2 differs from the first only in the id value, which has the same length as
	// zeroID; patching it in place yields byte-identical output (asserted by TestMarshalLinePatchEqualsReserialize).
	e.ID = hex.EncodeToString(sum[:])
	e.Rule, e.Reason = lifted.Rule, lifted.Reason
	copy(line[idOff:idOff+IDLen], e.ID)
	return line, nil
}

// sharedFields holds the rule and reason values found inside a payload object.
type sharedFields struct {
	rule, reason string
}

// liftInto moves the payload's shared keys onto e. A value already on e must match; a mismatch is a collision
// because the line has room for exactly one rule and one reason (E25).
func (s sharedFields) liftInto(e *Event) error {
	if s.rule != "" {
		if e.Rule != "" && e.Rule != s.rule {
			return fmt.Errorf("%w: payload rule %q, event rule %q", ErrPayloadFieldCollision, s.rule, e.Rule)
		}
		e.Rule = s.rule
	}
	if s.reason != "" {
		if e.Reason != "" && string(e.Reason) != s.reason {
			return fmt.Errorf("%w: payload reason %q, event reason %q", ErrPayloadFieldCollision, s.reason, e.Reason)
		}
		e.Reason = Reason(s.reason)
	}
	return nil
}

// canonical serializes e with zeroID in the id position and returns the bytes and the offset of the id value.
func (e *Event) canonical(payload []field) ([]byte, int) {
	w := lineWriter{}
	w.buf.Grow(512 + len(e.Payload))
	w.buf.WriteByte('{')
	w.number("v", strconv.Itoa(e.V))
	w.number("seq", strconv.FormatUint(e.Seq, 10))
	w.key("id")
	w.buf.WriteByte('"')
	idOff := w.buf.Len()
	w.buf.WriteString(zeroID)
	w.buf.WriteByte('"')
	w.str("prev", e.Prev)
	w.str("ts", e.TS.UTC().Format(time.RFC3339Nano))
	w.number("mono_ns", strconv.FormatUint(e.MonoNS, 10))
	w.str("run", e.Run)
	w.str("agent", e.Agent)
	w.number("pid", strconv.Itoa(e.PID))
	w.number("tid", strconv.Itoa(e.TID))
	w.number("cgroup", strconv.FormatUint(e.Cgroup, 10))
	w.str("kind", string(e.Kind))
	w.str("source", string(e.Source))
	if e.Rule != "" {
		w.str("rule", e.Rule)
	}
	if e.Verdict != "" {
		w.str("verdict", string(e.Verdict))
	}
	if e.Authority != "" {
		w.str("authority", string(e.Authority))
	}
	if e.Reason != "" {
		w.str("reason", string(e.Reason))
	}
	if e.Attr != nil {
		w.key("attribution")
		w.attribution(e.Attr)
	}
	for _, f := range payload {
		w.key(f.key)
		w.buf.Write(f.val)
	}
	w.buf.WriteByte('}')
	return w.buf.Bytes(), idOff
}

// lineWriter builds one canonical line. It is the only place that knows the wire syntax.
type lineWriter struct {
	buf bytes.Buffer
	n   int
}

func (w *lineWriter) key(k string) {
	if w.n > 0 {
		w.buf.WriteByte(',')
	}
	w.n++
	writeJSONString(&w.buf, k)
	w.buf.WriteByte(':')
}

func (w *lineWriter) number(k, v string) {
	w.key(k)
	w.buf.WriteString(v)
}

func (w *lineWriter) str(k, v string) {
	w.key(k)
	writeJSONString(&w.buf, v)
}

// attribution writes the attribution object in its fixed order: thread, step, tool_use_id (each omitted when zero), then
// confidence and method, always present (R8).
func (w *lineWriter) attribution(a *Attribution) {
	w.buf.WriteByte('{')
	first := true
	put := func(k string) {
		if !first {
			w.buf.WriteByte(',')
		}
		first = false
		writeJSONString(&w.buf, k)
		w.buf.WriteByte(':')
	}
	if a.Thread != "" {
		put("thread")
		writeJSONString(&w.buf, a.Thread)
	}
	if a.Step != 0 {
		put("step")
		w.buf.WriteString(strconv.Itoa(a.Step))
	}
	if a.ToolUseID != "" {
		put("tool_use_id")
		writeJSONString(&w.buf, a.ToolUseID)
	}
	put("confidence")
	writeJSONString(&w.buf, a.Confidence)
	put("method")
	writeJSONString(&w.buf, a.Method)
	w.buf.WriteByte('}')
}

const hexDigits = "0123456789abcdef"

// writeJSONString writes s as a JSON string with the escaping encoding/json uses when HTML escaping is off:
// '"', '\\', control characters (\n \r \t short forms, \u00XX otherwise) and U+2028/U+2029. Invalid UTF-8
// sequences become U+FFFD, one per byte (E18).
//
// It writes the replacement character itself, where encoding/json writes the six-character "\ufffd" escape,
// because the escape is not a fixed point of the codec: Decode hands back the U+FFFD rune, which this writer
// then emits raw, so a second serialization of a decoded line would not reproduce the first one and I9's
// byte-for-byte round trip would fail on any string holding an invalid byte. Both spellings are the same JSON
// string; only this one survives a round trip.
func writeJSONString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= 0x20 && c != '"' && c != '\\' {
				i++
				continue
			}
			buf.WriteString(s[start:i])
			switch c {
			case '"', '\\':
				buf.WriteByte('\\')
				buf.WriteByte(c)
			case '\n':
				buf.WriteString(`\n`)
			case '\r':
				buf.WriteString(`\r`)
			case '\t':
				buf.WriteString(`\t`)
			default:
				buf.WriteString(`\u00`)
				buf.WriteByte(hexDigits[c>>4])
				buf.WriteByte(hexDigits[c&0xF])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			buf.WriteString(s[start:i])
			buf.WriteRune(utf8.RuneError)
			i += size
			start = i
			continue
		}
		if r == ' ' || r == ' ' {
			buf.WriteString(s[start:i])
			buf.WriteString(`\u202`)
			buf.WriteByte(hexDigits[r&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	buf.WriteString(s[start:])
	buf.WriteByte('"')
}

// payloadFields parses a payload object into sorted fields, rejecting reserved keys (E25), duplicate keys and
// anything that is not exactly one JSON object. The shared keys rule and reason are removed from the fields
// and returned separately; they must be JSON strings. A nil or empty payload yields no fields.
func payloadFields(raw []byte) ([]field, sharedFields, error) {
	var shared sharedFields
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, shared, nil
	}
	fields, err := objectFields(raw)
	if err != nil {
		return nil, shared, fmt.Errorf("%w: payload: %w", ErrInvalidEvent, err)
	}
	kept := fields[:0]
	for _, f := range fields {
		switch {
		case IsReservedField(f.key):
			return nil, shared, fmt.Errorf("%w: %q", ErrPayloadFieldCollision, f.key)
		case IsSharedField(f.key):
			var v string
			if err := json.Unmarshal(f.val, &v); err != nil {
				return nil, shared, fmt.Errorf("%w: payload %s must be a string: %w", ErrInvalidEvent, f.key, err)
			}
			if f.key == "rule" {
				shared.rule = v
			} else {
				shared.reason = v
			}
		default:
			kept = append(kept, f)
		}
	}
	return kept, shared, nil
}

// Decode parses one line (with or without its "\n" terminator) into an Event.
//
// R5: v is checked first and anything but 1 is ErrUnsupportedVersion, an integer v above 1 ErrNewerVersion too; unknown top-level keys are never an error.
// Every key that is not a reserved common field becomes part of Payload, rebuilt as a compact object with sorted
// keys (the shared keys rule and reason appear both on the Event and in Payload), so MarshalLine(Decode(line))
// reproduces a canonical line byte for byte (I9) even when a newer v1 writer added an optional field this binary
// does not know. Decode checks structure and types only; Validate applies the semantic rules (kind set, action
// fields, attribution presence).
func Decode(line []byte) (*Event, error) {
	line = bytes.TrimSuffix(line, []byte{'\n'})
	fields, err := objectFields(line)
	if err != nil {
		return nil, fmt.Errorf("%w: %w: %w", ErrMalformedLine, errMalformedObject, err)
	}
	e := &Event{}
	vi := slices.IndexFunc(fields, func(f field) bool { return f.key == "v" })
	if vi < 0 {
		return nil, fmt.Errorf("%w: missing v", ErrUnsupportedVersion)
	}
	if v, err := parseInt(fields[vi].val); err != nil || v != Version {
		if err == nil && v > Version {
			return nil, fmt.Errorf("%w: %w: v=%s", ErrUnsupportedVersion, ErrNewerVersion, fields[vi].val)
		}
		return nil, fmt.Errorf("%w: v=%s", ErrUnsupportedVersion, fields[vi].val)
	}
	e.V = Version
	if err := e.decodeCommon(fields); err != nil {
		return nil, err
	}
	e.Payload = joinPayload(fields)
	return e, nil
}

// decodeCommon fills the common fields from the sorted fields; every always-present field must exist (R1) and
// each value must have its declared type.
func (e *Event) decodeCommon(fields []field) error {
	const alwaysPresent = 12
	// A refused timestamp keeps its malformed-line reason even when the digest or another field is bad.
	for _, f := range fields {
		if f.key == "ts" {
			var err error
			e.TS, err = parseTime(f.val)
			if err != nil {
				return fmt.Errorf("%w: ts: %w: %w", ErrMalformedLine, ErrMalformedTimestamp, err)
			}
		}
	}
	present := 0
	for _, f := range fields {
		var err error
		switch f.key {
		case "v":
			continue // gated by Decode before anything else
		case "seq":
			e.Seq, err = parseUint(f.val)
		case "id":
			e.ID, err = unquote(f.val)
		case "prev":
			e.Prev, err = unquote(f.val)
		case "ts":
			// Already checked above, before other fields.
		case "mono_ns":
			e.MonoNS, err = parseUint(f.val)
		case "run":
			e.Run, err = unquote(f.val)
		case "agent":
			e.Agent, err = unquote(f.val)
		case "pid":
			e.PID, err = parseInt(f.val)
		case "tid":
			e.TID, err = parseInt(f.val)
		case "cgroup":
			e.Cgroup, err = parseUint(f.val)
		case "kind":
			err = unquoteInto((*string)(&e.Kind), f.val)
		case "source":
			err = unquoteInto((*string)(&e.Source), f.val)
		case "rule":
			e.Rule, err = unquote(f.val)
			present--
		case "verdict":
			err = unquoteInto((*string)(&e.Verdict), f.val)
			present--
		case "authority":
			err = unquoteInto((*string)(&e.Authority), f.val)
			present--
		case "reason":
			err = unquoteInto((*string)(&e.Reason), f.val)
			present--
		case "attribution":
			err = json.Unmarshal(f.val, &e.Attr)
			present--
		default:
			continue
		}
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrMalformedLine, f.key, err)
		}
		present++
	}
	if present != alwaysPresent {
		return fmt.Errorf("%w: %d of the %d always-present fields", ErrMalformedLine, present, alwaysPresent)
	}
	return nil
}

// unquoteInto decodes a JSON string token into dst.
func unquoteInto(dst *string, tok []byte) error {
	s, err := unquote(tok)
	if err != nil {
		return err
	}
	*dst = s
	return nil
}

// joinPayload rebuilds the payload object from every non-reserved field, keys already sorted; nil when none.
func joinPayload(fields []field) json.RawMessage {
	var buf bytes.Buffer
	n := 0
	for _, f := range fields {
		if IsReservedField(f.key) {
			continue
		}
		if n == 0 {
			buf.WriteByte('{')
		} else {
			buf.WriteByte(',')
		}
		n++
		writeJSONString(&buf, f.key)
		buf.WriteByte(':')
		buf.Write(f.val)
	}
	if n == 0 {
		return nil
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

// canonicalPrefix is what every canonical line starts with, up to the seq digits.
const canonicalPrefix = `{"v":1,"seq":`

// VerifyLine recomputes the digest of a canonical line (R2) and returns the id it carries. It errors with
// ErrMalformedLine when the line is not canonical (the id is not the third key or not 64 hex characters) and
// with ErrIDMismatch when the stored id differs from the digest. The line may carry its "\n" terminator.
func VerifyLine(line []byte) (string, error) {
	line = bytes.TrimSuffix(line, []byte{'\n'})
	if !bytes.HasPrefix(line, []byte(canonicalPrefix)) {
		return "", fmt.Errorf("%w: not a canonical line", ErrMalformedLine)
	}
	return verifyDigest(line, len(canonicalPrefix))
}

// verifyDigest is VerifyLine past the prefix: line[:i] is the line up to its seq digits, and the id must follow
// them as the third key.
func verifyDigest(line []byte, i int) (string, error) {
	start := i
	for i < len(line) && line[i] >= '0' && line[i] <= '9' {
		i++
	}
	const idKey = `,"id":"`
	if i == start || !bytes.HasPrefix(line[i:], []byte(idKey)) {
		return "", fmt.Errorf("%w: id is not the third key", ErrMalformedLine)
	}
	off := i + len(idKey)
	if off+IDLen+1 > len(line) || line[off+IDLen] != '"' || !isHex(line[off:off+IDLen]) {
		return "", fmt.Errorf("%w: id is not %d hex characters", ErrMalformedLine, IDLen)
	}
	id := string(line[off : off+IDLen])
	zeroed := make([]byte, len(line))
	copy(zeroed, line)
	copy(zeroed[off:off+IDLen], zeroID)
	sum := sha256.Sum256(zeroed)
	if want := hex.EncodeToString(sum[:]); want != id {
		return id, fmt.Errorf("%w: stored %s, computed %s", ErrIDMismatch, id, want)
	}
	return id, nil
}

// IsID reports whether s has the shape of an event id (IDLen lowercase hex characters).
func IsID(s string) bool { return len(s) == IDLen && isHex([]byte(s)) }

func isHex(b []byte) bool {
	for _, c := range b {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
