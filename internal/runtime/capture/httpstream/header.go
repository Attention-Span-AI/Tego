// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// maxStartLine bounds a request or status line on its own, before the header block's own cap applies.
const maxStartLine = 8 << 10

// takeLine splits one CRLF- or LF-terminated line off the head of buf. It returns the line without its
// terminator, the number of bytes consumed, and whether a whole line was found. When no terminator is
// present the consumed count is zero (wait for more bytes) or -1 (the line already exceeds max, which is
// the caller's cue to fail rather than buffer without bound).
func takeLine(buf []byte, max int) ([]byte, int, bool) {
	return takeLineFrom(buf, 0, max)
}

// takeLineFrom is takeLine for a buf whose first from bytes are already known to hold no '\n': the search
// starts there, so a line arriving a byte at a time is scanned once rather than once per byte (R13).
func takeLineFrom(buf []byte, from, max int) ([]byte, int, bool) {
	if from < 0 || from > len(buf) {
		from = 0
	}
	i := bytes.IndexByte(buf[from:], '\n')
	if i >= 0 {
		i += from
	}
	if i < 0 {
		if max > 0 && len(buf) > max {
			return nil, -1, false
		}
		if max <= 0 && len(buf) > 0 {
			return nil, -1, false
		}
		return nil, 0, false
	}
	if max > 0 && i+1 > max {
		return nil, -1, false
	}
	line := buf[:i]
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	return line, i + 1, true
}

// transferCodings lists the codings a Transfer-Encoding names besides chunked, in the order listed. They are
// undone after the chunks are, like a Content-Encoding that was applied after the content's own.
func transferCodings(h http.Header) []string {
	var out []string
	for _, v := range h.Values("Transfer-Encoding") {
		for _, coding := range strings.Split(v, ",") {
			coding = strings.ToLower(strings.TrimSpace(coding))
			if coding == "" || coding == "chunked" {
				continue
			}
			out = append(out, coding)
		}
	}
	return out
}

// clip shortens a byte slice for an error message so a malformed line cannot fill a log line.
func clip(b []byte) string {
	const max = 48
	s := strings.ToValidUTF8(string(b), "�")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// requestLine is a parsed request line.
type requestLine struct {
	Method, Path, Proto string
}

// parseRequestLine reads "METHOD SP request-target SP HTTP/1.x" (RFC 9112 §3.1). An HTTP/2 version on the
// line is reported as ErrHTTP2 so the caller gaps with why=h2 instead of why=malformed.
func parseRequestLine(line []byte) (requestLine, error) {
	var out requestLine
	if len(line) > maxStartLine {
		return out, fmt.Errorf("%w: request line over %d bytes", ErrMalformed, maxStartLine)
	}
	sp := bytes.IndexByte(line, ' ')
	if sp <= 0 {
		return out, fmt.Errorf("%w: request line %q", ErrMalformed, clip(line))
	}
	rest := line[sp+1:]
	sp2 := bytes.LastIndexByte(rest, ' ')
	if sp2 <= 0 {
		return out, fmt.Errorf("%w: request line %q", ErrMalformed, clip(line))
	}
	out.Method, out.Path, out.Proto = string(line[:sp]), string(rest[:sp2]), string(rest[sp2+1:])
	if !isToken(out.Method) {
		return out, fmt.Errorf("%w: request method %q", ErrMalformed, clip([]byte(out.Method)))
	}
	if err := checkProto(out.Proto); err != nil {
		return out, err
	}
	if out.Path == "" {
		return out, fmt.Errorf("%w: empty request target", ErrMalformed)
	}
	return out, nil
}

// statusLine is a parsed status line.
type statusLine struct {
	Proto  string
	Status int
	Reason string
}

// parseStatusLine reads "HTTP/1.x SP status SP reason" (RFC 9112 §4). The reason phrase is optional, as it
// has been since RFC 7230.
func parseStatusLine(line []byte) (statusLine, error) {
	var out statusLine
	if len(line) > maxStartLine {
		return out, fmt.Errorf("%w: status line over %d bytes", ErrMalformed, maxStartLine)
	}
	sp := bytes.IndexByte(line, ' ')
	if sp <= 0 {
		return out, fmt.Errorf("%w: status line %q", ErrMalformed, clip(line))
	}
	out.Proto = string(line[:sp])
	if err := checkProto(out.Proto); err != nil {
		return out, err
	}
	rest := bytes.TrimLeft(line[sp+1:], " ")
	code := rest
	if sp2 := bytes.IndexByte(rest, ' '); sp2 >= 0 {
		code, out.Reason = rest[:sp2], strings.ToValidUTF8(string(bytes.TrimLeft(rest[sp2+1:], " ")), "�")
	}
	n, err := strconv.Atoi(string(code))
	if err != nil || n < 100 || n > 599 {
		return out, fmt.Errorf("%w: status code %q", ErrMalformed, clip(code))
	}
	out.Status = n
	return out, nil
}

// checkProto accepts HTTP/1.0 and HTTP/1.1 and nothing else. HTTP/2 and HTTP/3 are ErrHTTP2 — the traced
// connection is not one this reassembler may guess at (R17) — and anything else is malformed.
func checkProto(proto string) error {
	switch proto {
	case "HTTP/1.1", "HTTP/1.0":
		return nil
	}
	if strings.HasPrefix(proto, "HTTP/2") || strings.HasPrefix(proto, "HTTP/3") {
		return fmt.Errorf("%w: %s on the wire", ErrHTTP2, proto)
	}
	return fmt.Errorf("%w: protocol %q", ErrMalformed, clip([]byte(proto)))
}

// isToken reports whether s is an RFC 9110 §5.6.2 token: the only shape a method or a field name may have.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !tokenChar[s[i]] {
			return false
		}
	}
	return true
}

// tokenChar is the tchar set of RFC 9110 §5.6.2, built once at initialization.
var tokenChar = func() [256]bool {
	var t [256]bool
	for c := byte('0'); c <= '9'; c++ {
		t[c] = true
	}
	for c := byte('a'); c <= 'z'; c++ {
		t[c] = true
	}
	for c := byte('A'); c <= 'Z'; c++ {
		t[c] = true
	}
	for _, c := range []byte("!#$%&'*+-.^_`|~") {
		t[c] = true
	}
	return t
}()

// addHeaderLine appends one field line to h. A continuation line (obs-fold, RFC 9112 §5.2) extends the
// previous field's value rather than failing, because a traced process is not ours to reject; a line
// without a colon is malformed (R18).
//
// Field values are kept as bytes until they land in http.Header, so a non-ASCII value from a client that
// ignores RFC 9110's Latin-1 rule survives losslessly (edge case #23).
func addHeaderLine(h http.Header, last string, line []byte) (string, error) {
	if line[0] == ' ' || line[0] == '\t' {
		if last == "" {
			return "", fmt.Errorf("%w: continuation line with no field before it", ErrMalformed)
		}
		vals := h[last] // last is already canonical, so this is the field's own value slice
		if len(vals) == 0 {
			return "", fmt.Errorf("%w: continuation line with no value before it", ErrMalformed)
		}
		vals[len(vals)-1] += " " + string(bytes.Trim(line, " \t"))
		return last, nil
	}
	i := bytes.IndexByte(line, ':')
	if i <= 0 {
		return "", fmt.Errorf("%w: header line %q", ErrMalformed, clip(line))
	}
	name := string(line[:i])
	if !isToken(name) {
		return "", fmt.Errorf("%w: header name %q", ErrMalformed, clip(line[:i]))
	}
	value := string(bytes.Trim(line[i+1:], " \t"))
	name = http.CanonicalHeaderKey(name)
	h[name] = append(h[name], value)
	return name, nil
}

// bodyFraming is how a message's body is delimited, decided once the header block ends (R10).
type bodyFraming int

const (
	framingNone    bodyFraming = iota // no body at all
	framingLength                     // Content-Length bytes
	framingChunked                    // Transfer-Encoding: chunked
	framingClose                      // until the connection closes (responses only)
)

// framing applies RFC 9112 §6.3's message-body-length rules to a parsed header block.
//
// Content-Length together with Transfer-Encoding is the request-smuggling ambiguity of §6.3 ("Transfer-
// Encoding overrides Content-Length ... might indicate an attempt to perform request smuggling ... ought to
// be handled as an error"): this package treats it as malformed rather than picking a winner (R18, edge
// case #21). Two Content-Length values that disagree are the same ambiguity and the same answer.
func framing(h http.Header, isResponse bool, status int, headMethod bool) (bodyFraming, int64, error) {
	te := h.Values("Transfer-Encoding")
	cl := h.Values("Content-Length")
	chunked := false
	last := ""
	for _, v := range te {
		for _, coding := range strings.Split(v, ",") {
			coding = strings.TrimSpace(coding)
			if coding == "" {
				continue
			}
			last = coding
			if strings.EqualFold(coding, "chunked") {
				chunked = true
			}
		}
	}
	if chunked && !strings.EqualFold(last, "chunked") {
		// RFC 9112 §6.1: chunked, when present, is the final coding. Anything after it is a body this
		// package cannot frame, so it is malformed rather than read as chunked.
		return framingNone, 0, fmt.Errorf("%w: Transfer-Encoding %q does not end in chunked", ErrMalformed, strings.Join(te, ","))
	}
	if len(te) > 0 && len(cl) > 0 {
		return framingNone, 0, fmt.Errorf("%w: Content-Length with Transfer-Encoding (RFC 9112 §6.3)", ErrMalformed)
	}
	if len(te) > 0 && !chunked {
		return framingNone, 0, fmt.Errorf("%w: Transfer-Encoding %q without chunked", ErrMalformed, strings.Join(te, ","))
	}
	// A 1xx, 204 or 304 response and any response to HEAD carry no body whatever the headers say.
	if isResponse && (status < 200 || status == http.StatusNoContent || status == http.StatusNotModified || headMethod) {
		return framingNone, 0, nil
	}
	if chunked {
		return framingChunked, 0, nil
	}
	if len(cl) > 0 {
		n, err := parseContentLength(cl)
		if err != nil {
			return framingNone, 0, err
		}
		if n == 0 {
			return framingNone, 0, nil
		}
		return framingLength, n, nil
	}
	if isResponse {
		return framingClose, 0, nil
	}
	return framingNone, 0, nil
}

// parseContentLength reads the single non-negative value every Content-Length header must agree on.
func parseContentLength(values []string) (int64, error) {
	var first int64 = -1
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				return 0, fmt.Errorf("%w: empty Content-Length", ErrMalformed)
			}
			n, err := strconv.ParseInt(part, 10, 63)
			if err != nil || n < 0 || !allDigits(part) {
				return 0, fmt.Errorf("%w: Content-Length %q", ErrMalformed, clip([]byte(part)))
			}
			if first >= 0 && n != first {
				return 0, fmt.Errorf("%w: Content-Length values disagree (RFC 9112 §6.3)", ErrMalformed)
			}
			first = n
		}
	}
	if first < 0 {
		return 0, fmt.Errorf("%w: empty Content-Length", ErrMalformed)
	}
	return first, nil
}

// allDigits reports whether s is RFC 9110's 1*DIGIT: ParseInt alone also takes a sign ("+5", "-0").
func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// isEventStream reports whether a header block declares a server-sent event stream (R16).
func isEventStream(h http.Header) bool {
	ct := h.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "text/event-stream")
}

// upgradesToH2 reports whether a 101 response hands the connection to HTTP/2 (h2c). Any other upgrade
// leaves a connection this reassembler cannot follow either, but only h2 is the gap R17 names.
func upgradesToH2(h http.Header) bool {
	for _, v := range h.Values("Upgrade") {
		for _, tok := range strings.Split(v, ",") {
			switch strings.ToLower(strings.TrimSpace(tok)) {
			case "h2", "h2c":
				return true
			}
		}
	}
	return false
}
