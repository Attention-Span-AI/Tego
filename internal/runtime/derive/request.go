// SPDX-License-Identifier: Apache-2.0

package derive

import "github.com/attention-span-ai/tego/pkg/spec/record"

// RequestReader is a Parser that can read, off a model request alone, the tool_use ids whose results the request
// reports (capture-derive R42). ok is false when it could not read them with certainty; ids is then nil.
type RequestReader interface {
	ToolResults(req *Message) (ids []string, ok bool)
}

// RequestReading is what derive reads off a request before any answer, for the attribute stage: whether it is a
// model host's side traffic (R40), and the tool results it reports when it could be read (R42).
type RequestReading struct {
	Side        bool
	ToolResults []string
	// Read says ToolResults is the request's reading, which may be none; without it the request was not read.
	Read bool
}

// Apply writes the reading onto the ssl_request a capture source built: side when set, and tool_results, an empty
// list for a request read with none, left unset for a request not read.
func (r RequestReading) Apply(p *record.SSLRequestPayload) {
	if p == nil {
		return
	}
	p.Side = r.Side
	if r.Read {
		ids := r.ToolResults
		if ids == nil {
			ids = []string{}
		}
		p.ToolResults = &ids
	}
}

// ReadRequest reads what a request says alone (R40, R42). Dispatch is the same as Handle's (R25): a declared HTTP MCP
// server's request and a host no parser claims are not read. On a parser's host, a path the parser calls silent is
// side traffic and opens no step; any other request is read for its tool results when the parser can read them. A
// panic in the reader is recovered (§7's failure table) and leaves the request not read, which the attribute stage
// takes as one that may have reported any result the run was waiting on: every window of the run, and every window a
// reply in a step opened before it asks for, is of unknown state, neither kept open nor closed on a guess (R42).
func (d *Dispatcher) ReadRequest(req *Message, meta Meta) (r RequestReading) {
	if req == nil {
		return r
	}
	if _, ok := d.mcpServerOf(meta); ok {
		return r
	}
	p, ok := d.Parser(meta.Provider, meta.Host)
	if !ok {
		return r
	}
	if s, ok := p.(SilentPaths); ok && s.Silent(req.Method, req.Path) {
		r.Side = true
		return r
	}
	rr, ok := p.(RequestReader)
	if !ok {
		return r
	}
	defer func() {
		if v := recover(); v != nil {
			d.logPanic("request reader "+p.Provider(), v)
			r = RequestReading{}
		}
	}()
	r.ToolResults, r.Read = rr.ToolResults(req)
	return r
}
