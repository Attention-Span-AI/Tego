// SPDX-License-Identifier: Apache-2.0

package derive

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Message is one reassembled HTTP/1.1 message: a request or a response, with its body already decoded
// (R15), including the framing of a server-sent-event response. It is the transport-neutral form both
// capture paths produce — the uprobe path through capture/httpstream, the forwarder from its own
// net/http round trip — so a Parser never learns which one saw the bytes (§1, I11).
//
// Body holds the decoded bytes. Decoded reports whether the decode actually happened: a capture that met
// a Content-Encoding it cannot undo hands the wire bytes through with Decoded false, which a Parser turns
// into decision: unparsed why=encoding rather than a parse of compressed noise (R29).
type Message struct {
	// Request fields.
	Method string
	Path   string
	Proto  string
	// Response fields.
	Status int

	Header          http.Header
	Body            []byte
	ContentEncoding string // what the wire used, before Body was decoded
	SSE             bool   // text/event-stream: Body holds the event stream, not one JSON document
	// WireSSE says Body retains SSE fields and separators, as both capture paths do. False also accepts
	// legacy collected JSON payloads, so a caller holding an older representation can still derive it.
	WireSSE   bool
	RetryOf   string // the original request id when this is a client retry (R23)
	Truncated bool   // a capture cap cut the body short (R6, R14)
	Decoded   bool   // Body is the decoded representation of ContentEncoding
}

// Meta is what the capture source knows about an exchange that the bytes themselves do not say: which run
// and process produced it, when, which declared endpoint it went to, and which step it belongs to. Every
// event a Dispatcher returns carries these common fields, so a derived event is indistinguishable from
// one the capture source emitted itself (the "identical in shape" rule of §1).
type Meta struct {
	Run   string
	Agent string
	PID   int
	TID   int
	// Lane is record.Event.Lane: the forwarder's stand-in for a tid it cannot know (R34).
	Lane   uint64
	Cgroup uint64
	Source record.Source // forwarder | ssl
	TS     time.Time
	MonoNS uint64

	// Provider and Host are the dispatch keys, in that order (R25): the declared models[] provider
	// first, the upstream host as the fallback. Content is never sniffed.
	Provider string
	Host     string
	// Port is the destination port when the capture source knows it, 0 when it does not. Only a declared
	// HTTP MCP server is matched by it (WithMCP), since two servers may share a host.
	Port int

	// Binary names the process for a gap event, when the caller knows it.
	Binary string
}

// Route names an exchange for an operator's detail: the method and the path, with no query, whose values the
// ledger's redaction would otherwise have to find again, and at most 128 bytes of path.
func Route(method, target string) string {
	if i := strings.IndexAny(target, "?#"); i >= 0 {
		target = target[:i]
	}
	if len(target) > 128 {
		target = target[:128] + "..."
	}
	return strings.TrimSpace(method + " " + target)
}

// SplitTarget reads a request target as RFC 9112 §3.2 does. Origin-form ("/v1/messages?x") and asterisk-form
// ("*") come back as they are, with no authority: the Host header names the host. Absolute-form
// ("https://api.anthropic.com/v1/messages") comes back as its origin-form path and query and the URL's own
// authority, which a server uses in place of any Host header (§3.2.2). ok is false for any other target
// (authority-form, a relative path, a URL with no host or with a scheme other than http and https): what it
// reaches is unknown, and it must never be classified as an endpoint that spends nothing (R10). The authority
// is returned as written, port included; hosts are compared normalized downstream.
func SplitTarget(target string) (authority, path string, ok bool) {
	if strings.HasPrefix(target, "/") || target == "*" {
		return "", target, true
	}
	u, err := url.Parse(target)
	if err != nil || u.Opaque != "" || u.Host == "" {
		return "", target, false
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return "", target, false
	}
	return u.Host, u.RequestURI(), true
}

// event builds one event with the common fields of this exchange.
func (m Meta) event(kind record.Kind) *record.Event {
	src := m.Source
	if src == "" {
		src = record.SourceSSL
	}
	return &record.Event{
		V:      record.Version,
		TS:     m.TS,
		MonoNS: m.MonoNS,
		Run:    m.Run,
		Agent:  m.Agent,
		PID:    m.PID,
		TID:    m.TID,
		Lane:   m.Lane,
		Cgroup: m.Cgroup,
		Kind:   kind,
		Source: src,
	}
}
