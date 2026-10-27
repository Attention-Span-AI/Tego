// SPDX-License-Identifier: Apache-2.0

package derive

import (
	"errors"

	"github.com/attention-span-ai/tego/internal/runtime/derive/mcp"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// MCP transports, the closed set of an mcp line's transport (spec/record/v1).
const (
	MCPTransportStdio = "stdio"
	MCPTransportHTTP  = "http"
)

// Option configures a Dispatcher.
type Option func(*Dispatcher)

// WithMCP gives the dispatcher the contract's HTTP MCP servers (agent-contract.md R16a): an exchange whose host
// and port are one server's URL, and which no models[] entry claims, is that server's, and is read for the
// session's start and its tool calls (capture-derive.md R41) instead of being an exchange no parser reads. A
// stdio server or a URL ParseMCPURL refuses is left out; compile refused the second already.
func WithMCP(servers []agent.MCPServer) Option {
	return func(d *Dispatcher) {
		for _, s := range servers {
			if s.URL == "" || len(s.Command) > 0 {
				continue
			}
			if ep, err := agent.ParseMCPURL(s.URL); err == nil {
				d.mcp = append(d.mcp, mcpServer{name: s.Name, ep: ep})
			}
		}
	}
}

type mcpServer struct {
	name string
	ep   agent.MCPEndpoint
}

// mcpServerOf names the declared HTTP MCP server an exchange went to. Dispatch is by where the exchange went,
// never by its body (R25): its host and port must be the URL's, and a models[] provider that claimed the host
// keeps it (a contract that declares both on one host is warned of at compile). A capture source that does not
// know the port matches nothing.
func (d *Dispatcher) mcpServerOf(meta Meta) (string, bool) {
	if len(d.mcp) == 0 || meta.Provider != "" || meta.Port == 0 {
		return "", false
	}
	host := agent.CanonicalHost(meta.Host)
	for _, s := range d.mcp {
		if s.ep.Host == host && s.ep.Port == meta.Port {
			return s.name, true
		}
	}
	return "", false
}

// HandleRequest derives what a request says alone, for a source that reads it as it is captured rather than
// with its response: a declared HTTP MCP server's initialize and tool calls (mcpRequest, capture-derive R41),
// stamped with meta, which is the request's own time and writing thread. A call is then recorded whether or not
// its answer ever comes, and in the step it was made in, however long the tool ran. ok is false for every other
// exchange, which Handle derives with its response. A source that took an exchange here passes it to Handle no
// more: its lines are written, and an answer adds nothing to them. A nil req is no exchange.
func (d *Dispatcher) HandleRequest(req *Message, meta Meta) (Result, bool) {
	server, ok := d.mcpServerOf(meta)
	if !ok || req == nil {
		return Result{}, false
	}
	return d.mcpRequest(server, req, meta), true
}

// readMCPRequest is the request reader mcpRequest calls; a test swaps it for one that panics.
var readMCPRequest = mcp.ReadHTTPRequest

// mcpRequest is mcpExchange with the recover parse puts around a parser (§7's failure table: a derive panic is
// recovered in the Dispatcher). A panic in derive/mcp or in MCPEvents is a bug FuzzRead should have found; it must
// still never end the run's capture, so it becomes the one unparsed decision, why=schema, that an unreadable body
// derives; the panic and its stack go to tego's own log (WithLogger), never the ledger.
func (d *Dispatcher) mcpRequest(server string, req *Message, meta Meta) (res Result) {
	defer func() {
		if r := recover(); r != nil {
			res = d.unparsed(meta, mcp.Version, WhySchema)
			d.logPanic("the MCP reader", r)
		}
	}()
	return d.mcpExchange(server, req, meta)
}

// mcpExchange derives one request to a declared HTTP MCP server: an mcp line for the client's initialize (the
// connection, as a stdio server's exec is its start) and one per tools/call, in wire order, read from the request
// alone (mcp.ReadHTTPRequest). A request body nothing can read, or a batch member, is one decision: unparsed beside
// them (R29), why=encoding when capture could not undo its Content-Encoding. An MCP server spends no model tokens,
// so nothing here is unmetered.
func (d *Dispatcher) mcpExchange(server string, req *Message, meta Meta) Result {
	res := Result{Facts: Facts{ParserVersion: mcp.Version}}
	var why string
	if req.ContentEncoding != "" && !req.Decoded {
		why = WhyEncoding
	} else {
		r, err := readMCPRequest(req.Method, req.Body, req.Truncated)
		switch {
		case errors.Is(err, mcp.ErrUnreadable):
			why = WhySchema
		case r.Malformed > 0:
			why = WhySchema
			fallthrough
		default:
			res.Events = MCPEvents(server, MCPTransportHTTP, r.Items, meta)
		}
	}
	if why != "" {
		res.Facts.Decisions = []Decision{{Unparsed: true, Why: why}}
		res.Events = append(res.Events, res.Facts.Decisions[0].event(meta))
	}
	return res
}

// MCPEvents turns what a client sent one declared server into mcp lines: transport http or stdio, rule
// mcp[<server>], verdict observed — no mechanism of the run decided the message, it was read off the wire after
// the connection or the start a rule admitted — and authority rule. A tools/call names its tool; an initialize
// names none and is recorded only on http, since a stdio server's start is already its exec's line
// (internal/runtime/supervisor emitMCP). Attribution is left to the pipeline's attribute stage, which numbers the
// line into the step it fell in by time (E28a); until then it is unattributed.
func MCPEvents(server, transport string, items []mcp.Item, meta Meta) []*record.Event {
	out := make([]*record.Event, 0, len(items))
	for _, it := range items {
		if it.Kind == mcp.KindInitialize && transport != MCPTransportHTTP {
			continue
		}
		ev := meta.event(record.KindMCP)
		ev.Rule = agent.MCPRule(server)
		ev.Verdict = record.VerdictObserved
		ev.Authority = record.AuthorityRule
		ev.Attr = record.Unattributed()
		// SetPayload cannot fail for this struct: strings and a string slice.
		_ = ev.SetPayload(record.MCPPayload{Name: server, Transport: transport, Tool: it.Tool})
		out = append(out, ev)
	}
	return out
}
