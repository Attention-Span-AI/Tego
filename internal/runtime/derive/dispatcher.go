// SPDX-License-Identifier: Apache-2.0

package derive

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Dispatcher routes one captured exchange to the Parser that owns its provider, and turns whatever comes
// back — facts, decisions, or a body nobody could read — into events. It holds no per-run state; a
// Dispatcher is safe for concurrent use by every capture source of a run.
type Dispatcher struct {
	byProvider map[string]Parser
	byHost     map[string]Parser
	mcp        []mcpServer  // the contract's HTTP MCP servers (WithMCP)
	logger     *slog.Logger // tego's own log, for a recovered panic (WithLogger); nil discards it
}

// WithLogger gives the dispatcher tego's own log, which a recovered parser or MCP reader panic and its stack are
// written to (§7's failure table: never the ledger). Without it they are discarded.
func WithLogger(l *slog.Logger) Option { return func(d *Dispatcher) { d.logger = l } }

// logPanic writes a recovered panic of what to the own log, with the stack it unwound.
func (d *Dispatcher) logPanic(what string, r any) {
	if d.logger != nil {
		d.logger.Error("derive: recovered a panic; the exchange is recorded unparsed", "in", what, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
	}
}

// Result is what one exchange derived: the facts its ssl_response carries and the events that follow it.
// Events are already in the order they must reach the ledger (decisions in wire order, R30).
type Result struct {
	Facts  Facts
	Events []*record.Event
}

// NewDispatcher registers the parsers, first registration winning a contested provider or host. Two
// declared models sharing one upstream host therefore resolve to whichever parser registered first, the
// stated P0 limit of edge case #33.
func NewDispatcher(parsers []Parser, opts ...Option) *Dispatcher {
	d := &Dispatcher{
		byProvider: make(map[string]Parser, len(parsers)),
		byHost:     make(map[string]Parser, len(parsers)),
	}
	for _, p := range parsers {
		if p == nil {
			continue
		}
		if name := strings.ToLower(p.Provider()); name != "" {
			if _, dup := d.byProvider[name]; !dup {
				d.byProvider[name] = p
			}
		}
		for _, h := range p.Hosts() {
			h = agent.CanonicalHost(h)
			if h == "" {
				continue
			}
			if _, dup := d.byHost[h]; !dup {
				d.byHost[h] = p
			}
		}
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

// Parser returns the parser that owns provider, or failing that host (R25: dispatch is by the declared
// provider and the upstream host, never by sniffing the body), scoped to host when it reads hosts
// differently (HostScoped).
func (d *Dispatcher) Parser(provider, host string) (Parser, bool) {
	p, ok := d.byProvider[strings.ToLower(provider)]
	if !ok {
		p, ok = d.byHost[agent.CanonicalHost(host)]
	}
	if !ok {
		return nil, false
	}
	if hs, scoped := p.(HostScoped); scoped {
		p = hs.ForHost(agent.CanonicalHost(host))
	}
	return p, true
}

// HostScoped is a Parser whose reading of an exchange depends on which of its hosts the exchange went to:
// the Anthropic parser reads its own host's paths outside /v1 as spending nothing, and a declared gateway's
// as paths it does not read (R25).
type HostScoped interface {
	ForHost(host string) Parser
}

// Handle derives one exchange.
//
// A nil resp is valid: it is a request still in flight when the run ended, or one whose upstream never
// answered, and it derives exactly one gap what=capture why=malformed (§4, §7). A body no parser can read
// derives exactly one decision: unparsed with a why, never an error (R29). The returned error is
// reserved for a caller bug — a nil req — and wraps ErrNoRequest. An exchange with a declared HTTP MCP
// server is read from its request alone (mcpRequest), so a missing response loses none of it; a source that
// read the request as it was captured (HandleRequest) does not pass the exchange here as well.
func (d *Dispatcher) Handle(req, resp *Message, meta Meta) (Result, error) {
	if req == nil {
		return Result{}, fmt.Errorf("%w: run %s", ErrNoRequest, meta.Run)
	}
	if server, ok := d.mcpServerOf(meta); ok {
		res := d.mcpRequest(server, req, meta)
		if resp == nil {
			res.Events = append(res.Events, GapEvent(meta, GapMalformed, 0))
		}
		return res, nil
	}
	if resp == nil {
		return Result{
			Facts:  Facts{ParserVersion: NoParser},
			Events: []*record.Event{GapEvent(meta, GapMalformed, 0)},
		}, nil
	}
	parser, ok := d.Parser(meta.Provider, meta.Host)
	if !ok {
		res := d.unparsed(meta, NoParser, WhySchema)
		// A declared models[] entry with no parser is a model endpoint whose spend nothing reads; a host no
		// entry declares (the uprobe path sees every TLS peer of the run) is not a model call at all.
		res.Facts.Unmetered = meta.Provider != "" && Success(resp.Status)
		return res, nil
	}
	facts, err := d.parse(parser, req, resp)
	if err != nil {
		res := d.unparsed(meta, parser.Version(), whyOf(err))
		// A parser claimed the exchange and could not read it: on a successful answer that is spend the
		// facts do not count (R25). An error answer spent nothing whatever its body says.
		res.Facts.Unmetered = Success(resp.Status)
		return res, nil
	}
	if facts.ParserVersion == "" {
		facts.ParserVersion = parser.Version()
	}
	events := make([]*record.Event, 0, len(facts.Decisions))
	for _, dec := range facts.Decisions {
		events = append(events, dec.event(meta))
	}
	return Result{Facts: facts, Events: events}, nil
}

// parse calls the parser with a recover in place. A parser panic is a bug its fuzz target should have
// found; it must still never take the run down, so it becomes the same unparsed decision a malformed
// body produces, the panic value carried in the error and never in the ledger (§7).
func (d *Dispatcher) parse(p Parser, req, resp *Message) (facts Facts, err error) {
	defer func() {
		if r := recover(); r != nil {
			d.logPanic("parser "+p.Provider(), r)
			err = fmt.Errorf("%w: parser %s panicked: %v", ErrSchema, p.Provider(), r)
		}
	}()
	return p.Parse(req, resp)
}

// unparsed is the single decision R29 requires for a body derive could not read.
func (d *Dispatcher) unparsed(meta Meta, version, why string) Result {
	dec := Decision{Unparsed: true, Why: why}
	return Result{
		Facts:  Facts{ParserVersion: version, Decisions: []Decision{dec}},
		Events: []*record.Event{dec.event(meta)},
	}
}

// Success reports whether an HTTP status is a 2xx, the only answers a model call is billed for.
func Success(status int) bool { return status >= 200 && status <= 299 }

// whyOf maps a parser's error onto the closed why set. Anything a parser did not classify is schema,
// the closest of the three for a structural surprise (R29).
func whyOf(err error) string {
	switch {
	case errors.Is(err, ErrEncoding):
		return WhyEncoding
	case errors.Is(err, ErrH2):
		return WhyH2
	default:
		return WhySchema
	}
}
