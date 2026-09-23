// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

// hopByHop are the RFC 7230 §6.1 connection-scoped headers, which a forwarder removes rather than
// passes on; everything Connection itself names is removed too (R20).
var hopByHop = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection", // not in §6.1's list, but connection-scoped by the same rule and widely sent
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// Identity headers the forwarder writes (spec/identity/RUN-IDENTITY.md "Headers added by the forwarder").
const (
	HeaderRun         = "X-Tego-Run"
	HeaderTraceparent = "traceparent"
	HeaderTracestate  = "tracestate"
)

// credentialHeaders are the headers whose value is a credential. The forwarder forwards them untouched
// and never holds one: it hashes the value where a retry key needs identity, and no field of this
// package's types ever carries the value itself (I5).
var credentialHeaders = []string{"X-Api-Key", "Authorization"}

// maxTracestateMembers is the W3C ceiling: past 32 members the right-most are dropped (R20).
const maxTracestateMembers = 32

// copyHeader copies src into dst, dropping the hop-by-hop headers and everything Connection names (R20).
// Everything else is forwarded byte for byte, values and repeats included.
func copyHeader(dst, src http.Header) {
	drop := make(map[string]struct{}, len(hopByHop)+4)
	for _, h := range hopByHop {
		drop[http.CanonicalHeaderKey(h)] = struct{}{}
	}
	for _, v := range src.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				drop[http.CanonicalHeaderKey(name)] = struct{}{}
			}
		}
	}
	for name, values := range src {
		if _, skip := drop[http.CanonicalHeaderKey(name)]; skip {
			continue
		}
		for _, v := range values {
			dst.Add(name, v)
		}
	}
}

// headerAcceptEncoding is the one end-to-end header the forwarder does not pass on byte for byte (R20).
const headerAcceptEncoding = "Accept-Encoding"

// offeredCodings are the codings whose decoder state is small and fixed. br and zstd can be decoded,
// but their stream-selected windows are too large to advertise for every concurrent response.
var offeredCodings = map[string]bool{"gzip": true, "x-gzip": true, "deflate": true, "identity": true}

// narrowAcceptEncoding retains supported offers and their weights. Identity is the fallback only when
// the client accepts it. A positive wildcard can supply gzip when identity is refused. False means the
// client's offer has no supported representation, so the listener must answer 406 without forwarding.
func narrowAcceptEncoding(values []string) (string, bool) {
	var kept []string
	weights := make(map[string]float64)
	for _, v := range values {
		for _, member := range strings.Split(v, ",") {
			member = strings.TrimSpace(member)
			coding, params, _ := strings.Cut(member, ";")
			coding = strings.ToLower(strings.TrimSpace(coding))
			if coding == "" {
				continue
			}
			q := 1.0
			if params != "" {
				// Invalid weights cannot establish that the client accepts a representation.
				key, value, ok := strings.Cut(strings.TrimSpace(params), "=")
				parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
				if !ok || !strings.EqualFold(strings.TrimSpace(key), "q") || err != nil || !(parsed >= 0 && parsed <= 1) {
					q = 0
				} else {
					q = parsed
				}
			}
			if prior, exists := weights[coding]; !exists || q < prior {
				weights[coding] = q
			}
			if offeredCodings[coding] {
				kept = append(kept, member)
			}
		}
	}
	identity := true
	if q, explicit := weights["identity"]; explicit {
		identity = q > 0
	} else if q, wildcard := weights["*"]; wildcard && q == 0 {
		identity = false
	}
	acceptable := identity
	for coding, q := range weights {
		if offeredCodings[coding] && q > 0 {
			acceptable = true
		}
	}
	if !acceptable {
		if wildcard := weights["*"]; wildcard > 0 {
			for _, coding := range []string{"gzip", "deflate"} {
				if _, explicit := weights[coding]; !explicit {
					kept = append(kept, coding+";q="+strconv.FormatFloat(wildcard, 'f', -1, 64))
					acceptable = true
					break
				}
			}
		}
	}
	if !acceptable {
		return "", false
	}
	if _, explicit := weights["identity"]; !identity && !explicit {
		// Removing *;q=0 must not restore the implicit acceptance of identity upstream.
		kept = append(kept, "identity;q=0")
	}
	if len(kept) == 0 {
		return "identity", true
	}
	return strings.Join(kept, ", "), true
}

// trace is the identity a forwarded request carries and an ssl_request records.
type trace struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	Flags        string
}

// newTrace derives the trace headers for one request from the client's own, per RUN-IDENTITY.md.
//
// A client that sent no traceparent, or an invalid one, gets a fresh trace id derived from the run id
// (the first 16 bytes of its sha256 — the run id itself never travels inside traceparent) and its
// tracestate is discarded. A client that sent a valid one keeps its trace id and flags; only the parent
// id is replaced, and the id it sent is recorded as parent_span_id.
func newTrace(runID string, in http.Header, rnd io.Reader) (trace, error) {
	span, err := newSpanID(rnd)
	if err != nil {
		return trace{}, err
	}
	if p, ok := parseTraceparent(in.Get(HeaderTraceparent)); ok {
		return trace{TraceID: p.TraceID, SpanID: span, ParentSpanID: p.SpanID, Flags: p.Flags}, nil
	}
	return trace{TraceID: traceIDFor(runID), SpanID: span, Flags: "01"}, nil
}

// header is the traceparent value this trace writes.
func (t trace) header() string {
	return "00-" + t.TraceID + "-" + t.SpanID + "-" + t.Flags
}

// fresh reports whether this trace started here rather than continuing the client's.
func (t trace) fresh() bool { return t.ParentSpanID == "" }

// traceIDFor is the run's own trace id: the first 16 bytes of sha256(run id), hex.
func traceIDFor(runID string) string {
	sum := sha256.Sum256([]byte(runID))
	return hex.EncodeToString(sum[:16])
}

// newSpanID returns 8 fresh random bytes, hex, never all zero (W3C forbids an all-zero span id).
func newSpanID(rnd io.Reader) (string, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	var b [8]byte
	for attempt := 0; attempt < 4; attempt++ {
		if _, err := io.ReadFull(rnd, b[:]); err != nil {
			return "", err
		}
		if b != [8]byte{} {
			return hex.EncodeToString(b[:]), nil
		}
	}
	// Four all-zero draws is a broken source, not luck; make the id valid rather than emit one the
	// W3C spec calls invalid.
	b[7] = 1
	return hex.EncodeToString(b[:]), nil
}

// parseTraceparent reads a client's traceparent by derive's rule, the one both capture paths share (R20).
func parseTraceparent(v string) (trace, bool) {
	traceID, spanID, flags, ok := derive.ParseTraceparent(v)
	if !ok {
		return trace{}, false
	}
	return trace{TraceID: traceID, SpanID: spanID, Flags: flags}, true
}

// tracestateFor builds the outgoing tracestate: any prior tego member removed first — a nested tego
// run or a spoofed header could otherwise leave two — then tego=<run id> prepended, then anything past
// 32 members dropped from the right (R20). A fresh trace discards whatever the client sent.
func tracestateFor(runID, in string, fresh bool) string {
	members := []string{"tego=" + runID}
	if !fresh {
		for _, m := range strings.Split(in, ",") {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			if key, _, ok := strings.Cut(m, "="); ok && strings.TrimSpace(key) == "tego" {
				continue // the prior member, removed as its own step
			}
			members = append(members, m)
		}
	}
	if len(members) > maxTracestateMembers {
		members = members[:maxTracestateMembers]
	}
	return strings.Join(members, ",")
}

// credential returns the sha256 of the request's credential header value, or the hash of the empty
// string when it carries none. The value itself is never returned, stored or logged (I5).
func credential(h http.Header) [32]byte {
	for _, name := range credentialHeaders {
		if v := h.Get(name); v != "" {
			return sha256.Sum256([]byte(v))
		}
	}
	return sha256.Sum256(nil)
}

// recordedHeaders are the headers that may reach a payload: the ledger's own R9 allow-list, applied here
// too so no credential is ever placed in an event, not even one a later stage would have removed (I5).
func recordedHeaders(h http.Header) map[string]string { return ledger.RecordedHeaders(h) }
