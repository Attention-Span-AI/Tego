// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/modelroutes"
	"github.com/attention-span-ai/tego/pkg/policy/modelroute"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// RoutePoll is how often a run's forwarder rereads its route overlay when no request does (ADR 0127): a person's change
// is in force for the next request at once, since every request of a routed endpoint stats the overlay, and its ledger
// line is written within this interval when the agent sends nothing.
const RoutePoll = 500 * time.Millisecond

// router is a run's model routes (ADR 0127), shared by every listener of its Manager: the routed endpoints as the
// contract declares them, the overlay as the forwarder last read it, and one upstream leg per route used. Nil on a run
// whose contract declares no route, which leaves every code path as it was.
type router struct {
	endpoints map[string]agent.ModelEndpoint // declared authority -> the models[] entry, routes and all
	logger    *slog.Logger
	// newTransport builds a route's upstream leg; nil is buildRouteTransport. Tests replace it.
	newTransport func(*Listener, modelroute.Route) http.RoundTripper
	// read reads the overlay; nil is modelroutes.Read. Tests replace it.
	read func(dir, run string) (*modelroutes.Overlay, error)

	mu         sync.Mutex
	dir, run   string
	emitter    *Listener            // the run's first listener: writes a change line no owner or asking listener can
	owners     map[string]*Listener // routed authority -> the listener serving it, which writes its change lines
	sig        modelroutes.Signature
	loaded     bool
	overlay    *modelroutes.Overlay
	serial     uint64
	warnedSig  modelroutes.Signature
	transports map[string]http.RoundTripper // authority + " " + route name -> its leg

	stop chan struct{}
	wg   sync.WaitGroup
}

// newRouter is the run's router over models, nil when none declares a route.
func newRouter(models []agent.ModelEndpoint, logger *slog.Logger) *router {
	var rt *router
	for _, m := range models {
		if len(m.Routes) == 0 {
			continue
		}
		if rt == nil {
			rt = &router{endpoints: map[string]agent.ModelEndpoint{}, logger: logger, transports: map[string]http.RoundTripper{},
				overlay: modelroutes.New("")}
		}
		m.Host = agent.CanonicalHost(m.Host)
		if m.Port == 0 {
			m.Port = 443
		}
		rt.endpoints[m.ModelAuthority()] = m
	}
	if rt != nil && rt.logger == nil {
		rt.logger = slog.New(slog.DiscardHandler)
	}
	return rt
}

// routes reports whether the listener's endpoint declares routes: only then does a request of it consult the router.
func (rt *router) routes(l *Listener) bool {
	if rt == nil {
		return false
	}
	_, ok := rt.endpoints[l.authority()]
	return ok
}

// bind ties the router to the run: its directory (the overlay's home), its id, and its listeners, each of which writes
// the change lines of the routed endpoint it serves (contract validation allows one models[] entry per routed
// authority, so there is one such listener). The overlay there is read at once: a route a person set between the run's
// directory appearing and this read (a script that sets a route as soon as the run starts) is put in force with a line
// of its own, taken from the overlay's entry, so no request goes by a route no line put in force.
func (rt *router) bind(dir, run string, listeners ...*Listener) {
	rt.mu.Lock()
	rt.dir, rt.run = dir, run
	rt.owners = make(map[string]*Listener, len(rt.endpoints))
	for _, l := range listeners {
		if _, routed := rt.endpoints[l.authority()]; routed && rt.owners[l.authority()] == nil {
			rt.owners[l.authority()] = l
		}
	}
	if len(listeners) > 0 {
		rt.emitter = listeners[0]
	}
	rt.overlay = modelroutes.New(run)
	rt.mu.Unlock()
	rt.refresh(true, nil)
}

// start polls the overlay every RoutePoll until stopAndWait, so a change is recorded while the agent sends nothing.
func (rt *router) start() {
	rt.mu.Lock()
	if rt.stop != nil {
		rt.mu.Unlock()
		return
	}
	rt.stop = make(chan struct{})
	stop := rt.stop
	rt.mu.Unlock()
	rt.wg.Add(1)
	go func() {
		defer rt.wg.Done()
		t := time.NewTicker(RoutePoll)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				rt.refresh(false, nil)
			}
		}
	}()
}

// stopAndWait ends the poll and drops the route legs' idle connections. Safe without start.
func (rt *router) stopAndWait() {
	rt.mu.Lock()
	stop := rt.stop
	rt.stop = nil
	rt.mu.Unlock()
	if stop != nil {
		close(stop)
	}
	rt.wg.Wait()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, t := range rt.transports {
		if c, ok := t.(interface{ CloseIdleConnections() }); ok {
			c.CloseIdleConnections()
		}
	}
}

// refresh rereads the overlay when its signature moved, and writes one gap line per change it put in force, in serial
// order. The routes in force are then compared with those before: an endpoint whose route moved with no change line
// to say so (the overlay removed, or replaced by one whose serial went down or started again, or a change naming a
// route the contract does not declare) gets a line of its own, so the ledger never shows a request go by a route no
// line put in force. An overlay that is not trusted or not valid keeps the routes last read in force, and is said once
// per state in the forwarder's log; any other read error (EMFILE, a read cut short) is retried on the next request or
// poll, so a person's change is not left unapplied while the dashboard shows it. first is bind's read: no change is
// replayed, and each endpoint the overlay already puts off direct gets the line the comparison writes.
//
// by is the listener whose request read the change, nil for the poll and bind. Each line goes out through writeChange.
func (rt *router) refresh(first bool, by *Listener) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.dir == "" {
		return
	}
	sig := modelroutes.Stat(rt.dir)
	if rt.loaded && sig == rt.sig && !first {
		return
	}
	read := rt.read
	if read == nil {
		read = modelroutes.Read
	}
	o, err := read(rt.dir, rt.run)
	switch {
	case errors.Is(err, os.ErrNotExist):
		o = modelroutes.New(rt.run)
	case err != nil:
		if sig != rt.warnedSig {
			rt.warnedSig = sig
			rt.logger.Warn("forwarder: the run's model routes cannot be read; the routes read last stay in force",
				"run", rt.run, "err", err)
		}
		if errors.Is(err, modelroutes.ErrUntrusted) || errors.Is(err, modelroutes.ErrInvalid) {
			rt.sig, rt.loaded = sig, true // this file stays unread until it changes
		}
		return
	}
	before := rt.inForce(rt.overlay)
	changes := o.Since(rt.serial)
	if o.Serial < rt.serial || first {
		// A replaced overlay: its numbers are not this run's sequence; or the run's first read, which starts from
		// direct and replays no history. The comparison below says what is in force.
		changes = nil
	}
	rt.overlay, rt.sig, rt.loaded, rt.serial = o, sig, true, o.Serial
	said := map[string]string{} // endpoint -> the route its last line put in force
	for _, c := range changes {
		m, ok := rt.endpoints[c.Model]
		if !ok {
			continue // an endpoint of no routed models[] entry: nothing of this run changed
		}
		r, declared := modelroute.Resolve(m, c.RouteAfter())
		if !declared {
			rt.logger.Warn("forwarder: the run's model routes name a route the contract does not declare; the endpoint stays on its own",
				"run", rt.run, "model", c.Model, "route", c.RouteAfter())
			continue
		}
		rt.writeChange(by, c, r)
		said[c.Model] = r.Name
	}
	after := rt.inForce(o)
	for _, auth := range slices.Sorted(maps.Keys(after)) {
		was, ok := said[auth]
		if !ok {
			was = before[auth]
		}
		if after[auth] == was {
			continue
		}
		r, _ := modelroute.Resolve(rt.endpoints[auth], after[auth])
		rt.writeChange(by, rt.unnumbered(o, auth, r), r)
	}
}

// writeChange writes the line of change c, which puts r in force, through the listener serving c's endpoint, so it is
// queued ahead of that endpoint's request lines that go by r: each listener has its own queue, and a line written
// through another could reach the ledger after them. A closing owner takes no more lines (emitOpen); the line then goes
// through by, the listener whose request read the change and which cannot have flushed while that request's handler
// runs (Listener.Close joins its handlers first), or else the run's first listener. When none is open the run is
// ending: the owner serves no further request, so nothing goes by r unrecorded. Called with rt.mu held.
func (rt *router) writeChange(by *Listener, c modelroutes.Change, r modelroute.Route) {
	if owner := rt.owners[c.Model]; owner != nil && owner.emitOpen(owner.routeChangeEvent(c, r)) {
		return
	}
	if by != nil {
		by.emit(by.routeChangeEvent(c, r))
		return
	}
	if rt.emitter != nil {
		rt.emitter.emitOpen(rt.emitter.routeChangeEvent(c, r))
	}
}

// inForce is the route each routed endpoint takes under o, resolved against the contract.
func (rt *router) inForce(o *modelroutes.Overlay) map[string]string {
	out := make(map[string]string, len(rt.endpoints))
	for auth, m := range rt.endpoints {
		live := ""
		if e, ok := o.Lookup(auth); ok {
			live = e.Route
		}
		r, _ := modelroute.Resolve(m, live)
		out[auth] = r.Name
	}
	return out
}

// unnumbered is the change that put r in force for auth under o when no change line said so: the overlay's own entry
// for the endpoint (who set it, its serial, when) when it holds one for r; with no entry, the overlay's last change of
// the endpoint back to direct when it kept one; or else a revert to direct no change numbered, serial 0 (record-ledger
// revision 27): the overlay removed, or naming a route the contract does not declare.
func (rt *router) unnumbered(o *modelroutes.Overlay, auth string, r modelroute.Route) modelroutes.Change {
	e, ok := o.Lookup(auth)
	if ok && e.Route == r.Name {
		return modelroutes.Change{Serial: e.Serial, Op: modelroutes.OpSet, Model: auth, Route: e.Route, By: e.By, At: e.At}
	}
	if !ok {
		for i := len(o.Changes) - 1; i >= 0; i-- {
			if c := o.Changes[i]; c.Model == auth {
				if c.RouteAfter() == r.Name {
					return c
				}
				break
			}
		}
	}
	return modelroutes.Change{Op: modelroutes.OpClear, Model: auth, At: time.Now().UTC(),
		By: "forwarder: the overlay no longer names a declared route for this endpoint"}
}

// current is where model's next request goes, the overlay reread first when it moved; l is the listener asking, which
// writes any change line the reread puts in force.
func (rt *router) current(l *Listener, m agent.ModelEndpoint) modelroute.Route {
	rt.refresh(false, l)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	live := ""
	if e, ok := rt.overlay.Lookup(m.ModelAuthority()); ok {
		live = e.Route
	}
	r, _ := modelroute.Resolve(m, live)
	return r
}

// leg is the upstream leg of route r for listener l, built once and kept for the run.
func (rt *router) leg(l *Listener, r modelroute.Route) http.RoundTripper {
	key := l.authority() + " " + r.Name
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if t, ok := rt.transports[key]; ok {
		return t
	}
	build := rt.newTransport
	if build == nil {
		build = buildRouteTransport
	}
	t := build(l, r)
	rt.transports[key] = t
	return t
}

// buildRouteTransport is a route's upstream leg: the listener's own construction (NewTransport, no environment proxy,
// the 1 MiB response header bound) with SNI and certificate verification pinned to the route's host, dialing only
// addresses the run's resolved-address policy admits (validatedDial); plaintext for a tls: false route, which
// validation allows only on this machine's loopback.
func buildRouteTransport(l *Listener, r modelroute.Route) http.RoundTripper {
	t := NewTransport(r.Host)
	t.DialContext = newValidatedDial(agent.ModelEndpoint{Host: r.Host, Port: r.Port}, l.opts.DeniedResolved, l.opts.Resolver,
		l.opts.routeDial, l.opts.resolveSem).DialContext
	if !r.TLS {
		t.TLSClientConfig, t.ForceAttemptHTTP2 = nil, false
		t.DialContext = loopbackOnly(t.DialContext)
	}
	return t
}

// errPlaintextOffLoopback is a tls: false route whose host resolved to an address off this machine.
var errPlaintextOffLoopback = errors.New("forwarder: a plaintext model route reached an address that is not this machine's loopback")

// loopbackOnly holds a plaintext route to this machine by the address it connected to, not by its host's name (ADR
// 0127 §1): a resolver that sends localhost to DNS, or an answer that is not loopback, would otherwise have the prompts
// and an injected key cross the network in the clear. The check is on the connection's own remote address, so no
// lookup the dial made can differ from what is checked.
func loopbackOnly(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if ap, perr := netip.ParseAddrPort(c.RemoteAddr().String()); perr != nil || !ap.Addr().Unmap().IsLoopback() {
			_ = c.Close() // refused before a byte is written
			return nil, fmt.Errorf("%w: %s", errPlaintextOffLoopback, c.RemoteAddr())
		}
		return c, nil
	}
}

// routeChoice is the route one request takes, chosen once before its credential check: its upstream URL, Host header
// and leg. Nil on a listener whose endpoint declares no route.
type routeChoice struct {
	route    modelroute.Route
	upstream *url.URL
	host     string
	leg      http.RoundTripper
}

// chooseRoute is the route of the request about to be decided; nil when the endpoint declares none. The direct route
// uses the listener's own upstream and leg, so a routed endpoint at direct forwards exactly as an unrouted one.
func (l *Listener) chooseRoute() *routeChoice {
	if !l.routes.routes(l) {
		return nil
	}
	m := l.routes.endpoints[l.authority()]
	r := l.routes.current(l, m)
	if r.IsDirect() {
		return &routeChoice{route: r, upstream: l.upstream, host: l.hostHeader(), leg: l.transport}
	}
	scheme, defaultPort := "https", 443
	if !r.TLS {
		scheme, defaultPort = "http", 80
	}
	host := r.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]" // an IPv6 literal, as hostHeader writes it
	}
	if r.Port != defaultPort {
		host = net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
	}
	return &routeChoice{route: r, upstream: &url.URL{Scheme: scheme, Host: net.JoinHostPort(r.Host, strconv.Itoa(r.Port))},
		host: host, leg: l.routes.leg(l, r)}
}

// taken is the route as a line records it; nil for no choice.
func (c *routeChoice) taken() *record.RouteTaken {
	if c == nil {
		return nil
	}
	return c.route.Taken()
}

// routeName is the name of the route c chose: "" for no choice (an endpoint without routes), direct for the endpoint's
// own upstream.
func routeName(c *routeChoice) string {
	if c == nil {
		return ""
	}
	return c.route.Name
}

// authority is the listener's declared upstream, host:port, in the canonical form validation compares a
// credential's allow entries with (agent.ModelEndpoint.ModelAuthority): API.Example.com. and api.example.com are one.
func (l *Listener) authority() string {
	m := l.model
	if m.Port == 0 {
		m.Port = 443
	}
	return m.ModelAuthority()
}

// authorityOf is where a request goes: the route's backend, or the listener's declared endpoint without a choice.
func (l *Listener) authorityOf(c *routeChoice) string {
	if c == nil {
		return l.authority()
	}
	return c.route.Authority()
}

// routeMoved reports whether the endpoint's route is no longer the one c chose. forward asks it of a request that waited
// for an approval, which is then not sent, rather than sent where the person has just stopped sending the endpoint's
// requests.
func (l *Listener) routeMoved(c *routeChoice) bool {
	if c == nil {
		return false
	}
	return l.routes.current(l, l.routes.endpoints[l.authority()]).Name != c.route.Name
}

// refuseRoutedTunnel refuses a CONNECT or an upgrade the compiled proxy policy would serve while the endpoint is on a
// route other than its own: a tunnel goes to the declared endpoint's address, so serving it would go around the route a
// person chose. The refusal is a net line (R26: a mapped error is an event, never only a status code), refused net-http
// under models[<endpoint>].routes, naming the route in force, as the proxy's own refusals are recorded
// (protocolDecision). It reports whether it answered.
func (l *Listener) refuseRoutedTunnel(w http.ResponseWriter, r *http.Request, pid int) bool {
	if l.opts.Proxy == nil || (r.Method != http.MethodConnect && !hasUpgrade(r)) || !l.routes.routes(l) {
		return false
	}
	c := l.chooseRoute()
	if c == nil || c.route.IsDirect() {
		return false
	}
	op, path := "websocket", r.URL.EscapedPath()
	if r.Method == http.MethodConnect {
		op, path = "connect_tunnel", ""
	}
	authority := l.authority()
	ev := l.event(record.KindNet, l.opts.Clock.Now(), l.opts.Clock.Mono())
	ev.PID, ev.TID, ev.Rule, ev.Authority = pid, pid, record.ModelRouteRule(authority), record.AuthorityRule
	ev.Verdict, ev.Reason = record.VerdictRefused, record.ReasonNetHTTP
	_ = ev.SetPayload(record.NetPayload{Op: op, Proto: "tcp", Dst: authority, Host: l.model.Host, HTTPAuthority: authority,
		Method: r.Method, Path: path, Mechanism: "forwarder", Route: c.taken()})
	l.emit(ev)
	closeHTTPUpload(w, r)
	http.Error(w, fmt.Sprintf("Tego: this model endpoint is routed to %s (%s); a tunnel or an upgraded connection follows no route",
		c.route.Name, c.route.Authority()), http.StatusForbidden)
	return true
}

// routeChangeEvent is the gap line of one route change put in force (ADR 0127, record minor 27).
func (l *Listener) routeChangeEvent(c modelroutes.Change, r modelroute.Route) *record.Event {
	ev := l.event(record.KindGap, l.opts.Clock.Now(), l.opts.Clock.Mono())
	_ = ev.SetPayload(record.GapPayload{What: record.GapEnforce, Why: record.GapModelRouteChanged, // fixed types: cannot fail
		ModelRoute: &record.ModelRouteChange{Model: c.Model, Route: r.Name, Authority: r.Authority(), By: c.By,
			Serial: c.Serial, At: c.At}})
	return ev
}

// emitRouteMoved writes the net line of a request held for approval and not sent because its endpoint's route moved
// meanwhile (ADR 0127 §4, R26: a mapped error is an event, never only a status code): refused model-route-changed under
// models[<endpoint>].routes, naming the route it would have taken.
func (l *Listener) emitRouteMoved(r *http.Request, pid int, via *routeChoice) {
	ev := l.event(record.KindNet, l.opts.Clock.Now(), l.opts.Clock.Mono())
	ev.PID, ev.TID, ev.Rule, ev.Authority = pid, pid, record.ModelRouteRule(l.authority()), record.AuthorityRule
	ev.Verdict, ev.Reason = record.VerdictRefused, record.ReasonModelRouteChanged
	authority := l.authorityOf(via)
	_ = ev.SetPayload(record.NetPayload{Op: "http_request", Proto: "http", Dst: authority, Host: l.model.Host,
		HTTPAuthority: authority, Method: r.Method, Path: r.URL.EscapedPath(), Route: via.taken()})
	l.emit(ev)
}
