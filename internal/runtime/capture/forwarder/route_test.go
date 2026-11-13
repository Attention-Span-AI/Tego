// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/modelroutes"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/policy/modelroute"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// routeHarness is a listener whose endpoint declares two routes: alt, a second TLS upstream, and plain, a plaintext one
// on loopback reached through the production leg (buildRouteTransport). Each upstream counts its requests and keeps the
// Host and x-api-key it saw.
type routeHarness struct {
	*harness
	dir               string
	alt, plain        *httptest.Server
	altHost           string
	direct, altHits   atomic.Int64
	plainHits         atomic.Int64
	seenHost, seenKey chan string
}

func okBody(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","model":"m","content":[],"usage":{"input_tokens":1,"output_tokens":1}}`)
}

func newRouteHarness(t *testing.T, opts Options) *routeHarness {
	t.Helper()
	rh := &routeHarness{dir: t.TempDir(), seenHost: make(chan string, 16), seenKey: make(chan string, 16)}
	note := func(r *http.Request) {
		rh.seenHost <- r.Host
		rh.seenKey <- r.Header.Get("X-Api-Key")
	}
	rh.alt = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rh.altHits.Add(1)
		note(r)
		okBody(w)
	}))
	t.Cleanup(rh.alt.Close)
	rh.plain = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rh.plainHits.Add(1)
		note(r)
		okBody(w)
	}))
	t.Cleanup(rh.plain.Close)
	rh.harness = newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		rh.direct.Add(1)
		note(r)
		okBody(w)
	}, opts)
	altHost, altPort := hostPort(t, rh.alt.Listener.Addr().String())
	plainHost, plainPort := hostPort(t, rh.plain.Listener.Addr().String())
	rh.altHost = rh.alt.Listener.Addr().String()
	off := false
	l := rh.listener
	l.model.Routes = []agent.ModelRoute{{Name: "alt", Host: altHost, Port: altPort},
		{Name: "plain", Host: plainHost, Port: plainPort, TLS: &off}}
	rt := newRouter([]agent.ModelEndpoint{l.model}, nil)
	altTransport := rh.alt.Client().Transport
	rt.newTransport = func(l *Listener, r modelroute.Route) http.RoundTripper {
		if r.Name == "alt" {
			return altTransport // the test upstream's certificate; plain takes the production leg
		}
		return buildRouteTransport(l, r)
	}
	l.routes = rt
	rt.bind(rh.dir, testRun.ID, l)
	t.Cleanup(rt.stopAndWait)
	return rh
}

// set puts route in force for the listener's endpoint, as `tego route set` would ("" or direct clears).
func (rh *routeHarness) set(t *testing.T, route string) {
	t.Helper()
	if _, err := modelroutes.Update(context.Background(), rh.dir, testRun.ID, func(o *modelroutes.Overlay) (bool, error) {
		return o.Set(rh.listener.authority(), route, "uid:1000 pid:1 cli", time.Now())
	}); err != nil {
		t.Fatal(err)
	}
}

func (rh *routeHarness) send(t *testing.T, header http.Header) (int, string) {
	t.Helper()
	resp := rh.post("/v1/messages", []byte(`{"model":"m","max_tokens":1,"messages":[]}`), header)
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

// routeOf is the route an ssl_request line names, nil for none.
func routeOf(t *testing.T, ev *record.Event) *record.RouteTaken {
	t.Helper()
	return payloadOf[record.SSLRequestPayload](t, ev).Route
}

// delivered returns once every line l has queued so far has reached its sink. A handler queues its lines and answers
// the client without waiting for the ledger (capture-derive.md I1), so a client can hold its answer while the lines
// its request wrote are still in the queue: a check of the sink after a response waits for the queue, not a clock.
func delivered(l *Listener) { l.emitq.flush(5 * time.Second) }

// routeChanges are the model-route-changed lines emitted so far.
func routeChanges(t *testing.T, s *fakeSink) []record.ModelRouteChange {
	t.Helper()
	var out []record.ModelRouteChange
	for _, ev := range s.of(record.KindGap) {
		p := payloadOf[record.GapPayload](t, ev)
		if p.Why == record.GapModelRouteChanged && p.ModelRoute != nil {
			if p.What != record.GapEnforce || ev.Source != record.SourceForwarder {
				t.Errorf("route change line %+v %+v", ev, p)
			}
			out = append(out, *p.ModelRoute)
		}
	}
	return out
}

// TestRouteSwitchBothWays: a run starts on its endpoint (route direct on the line); a person's switch sends the next
// request to the route's backend with its Host, and the line names the route; a revert sends the next one back; every
// change put in force is one model-route-changed line in serial order; a plaintext loopback route goes through the
// production leg.
func TestRouteSwitchBothWays(t *testing.T) {
	rh := newRouteHarness(t, Options{})
	own := rh.listener.authority()
	if code, _ := rh.send(t, nil); code != http.StatusOK || rh.direct.Load() != 1 {
		t.Fatalf("direct: %d, %d upstream", code, rh.direct.Load())
	}
	<-rh.seenKey
	if h := <-rh.seenHost; h != rh.listener.hostHeader() {
		t.Errorf("direct Host %q", h)
	}
	rh.set(t, "alt")
	if code, _ := rh.send(t, nil); code != http.StatusOK || rh.altHits.Load() != 1 || rh.direct.Load() != 1 {
		t.Fatalf("alt: %d, direct %d alt %d", code, rh.direct.Load(), rh.altHits.Load())
	}
	<-rh.seenKey
	if h := <-rh.seenHost; h != rh.altHost {
		t.Errorf("alt Host %q, want %q", h, rh.altHost)
	}
	rh.set(t, "plain")
	if code, _ := rh.send(t, nil); code != http.StatusOK || rh.plainHits.Load() != 1 {
		t.Fatalf("plain: %d, %d", code, rh.plainHits.Load())
	}
	<-rh.seenKey
	<-rh.seenHost
	rh.set(t, modelroute.Direct)
	if code, _ := rh.send(t, nil); code != http.StatusOK || rh.direct.Load() != 2 {
		t.Fatalf("back: %d, direct %d", code, rh.direct.Load())
	}
	reqs := rh.sink.waitFor(t, record.KindSSLRequest, 4)
	want := []string{"direct", "alt", "plain", "direct"}
	for i, ev := range reqs[:4] {
		r := routeOf(t, ev)
		if r == nil || r.Name != want[i] {
			t.Fatalf("request %d route %+v, want %s", i, r, want[i])
		}
		if p := payloadOf[record.SSLRequestPayload](t, ev); p.Host != rh.listener.Model().Host {
			t.Errorf("request %d host %q: the line names the declared endpoint", i, p.Host)
		}
	}
	if r := routeOf(t, reqs[1]); r.Authority != rh.altHost {
		t.Errorf("alt authority %q", r.Authority)
	}
	ch := routeChanges(t, rh.sink)
	if len(ch) != 3 {
		t.Fatalf("%d change lines, want 3: %+v", len(ch), ch)
	}
	for i, w := range []string{"alt", "plain", "direct"} {
		if ch[i].Route != w || ch[i].Model != own || ch[i].Serial != uint64(i+1) || ch[i].By != "uid:1000 pid:1 cli" {
			t.Errorf("change %d = %+v", i, ch[i])
		}
	}
	if ch[2].Authority != own {
		t.Errorf("revert authority %q, want %q", ch[2].Authority, own)
	}
	for _, ev := range rh.sink.all() {
		b, err := ev.MarshalLineAt(record.Minor)
		if err != nil {
			t.Errorf("%s line not valid at %d: %v (%s)", ev.Kind, record.Minor, err, b)
		}
	}
}

// TestRouteCarriesTheAgentsOwnKey: a route moves the whole request, so a key the agent holds itself reaches the backend
// the endpoint is on, TLS or plaintext, whatever its name: no allow list stands in the way with no key layer. The route
// pages, the y/N of `tego route set` and docs/user/model-routes.md say so (ADR 0127 §5); a change here changes them.
func TestRouteCarriesTheAgentsOwnKey(t *testing.T) {
	const key = "sk-ant-own-key-of-the-agent"
	rh := newRouteHarness(t, Options{})
	for _, route := range []string{"alt", "plain"} {
		rh.set(t, route)
		if code, body := rh.send(t, http.Header{"X-Api-Key": {key}}); code != http.StatusOK {
			t.Fatalf("route %s: %d %s", route, code, body)
		}
		<-rh.seenHost
		if got := <-rh.seenKey; got != key {
			t.Fatalf("route %s: the backend saw key %q", route, got)
		}
	}
	if rh.altHits.Load() != 1 || rh.plainHits.Load() != 1 || rh.direct.Load() != 0 {
		t.Fatalf("hits: alt %d, plain %d, direct %d", rh.altHits.Load(), rh.plainHits.Load(), rh.direct.Load())
	}
}

// TestRouteOverlayNamingAnUndeclaredRouteStaysDirect: a hand-written overlay naming a route the contract does not
// declare sends nothing anywhere new, and records no change.
func TestRouteOverlayNamingAnUndeclaredRouteStaysDirect(t *testing.T) {
	rh := newRouteHarness(t, Options{})
	rh.set(t, "evil")
	if code, _ := rh.send(t, nil); code != http.StatusOK || rh.direct.Load() != 1 || rh.altHits.Load()+rh.plainHits.Load() != 0 {
		t.Fatalf("%d: direct %d", code, rh.direct.Load())
	}
	if r := routeOf(t, rh.sink.waitFor(t, record.KindSSLRequest, 1)[0]); r == nil || r.Name != "direct" {
		t.Fatalf("route %+v", r)
	}
	if ch := routeChanges(t, rh.sink); len(ch) != 0 {
		t.Fatalf("change lines %+v", ch)
	}
}

// TestRouteUnreadableOverlayKeepsTheLastRoutes: an overlay that cannot be read (here one another user could write)
// keeps the routes last read in force.
func TestRouteUnreadableOverlayKeepsTheLastRoutes(t *testing.T) {
	rh := newRouteHarness(t, Options{})
	rh.set(t, "alt")
	if code, _ := rh.send(t, nil); code != http.StatusOK || rh.altHits.Load() != 1 {
		t.Fatalf("alt: %d", code)
	}
	if err := os.Chmod(filepath.Join(rh.dir, modelroutes.FileName), 0o666); err != nil {
		t.Fatal(err)
	}
	if code, _ := rh.send(t, nil); code != http.StatusOK || rh.altHits.Load() != 2 {
		t.Fatalf("after the overlay became untrusted: %d, alt %d", code, rh.altHits.Load())
	}
}

// TestRouteOffPathUnchanged: a listener of an endpoint that declares no route never consults a router and writes no
// route on its lines, even beside a routed endpoint in the same run.
func TestRouteOffPathUnchanged(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) { okBody(w) }, Options{})
	other := agent.ModelEndpoint{Provider: "openai", Host: "api.openai.com", Port: 443,
		Routes: []agent.ModelRoute{{Name: "corp", Host: "proxy.example", Port: 443}}}
	h.listener.routes = newRouter([]agent.ModelEndpoint{other}, nil)
	if h.listener.chooseRoute() != nil {
		t.Fatal("an unrouted endpoint chose a route")
	}
	resp := h.post("/v1/messages", []byte(`{}`), nil)
	_ = resp.Body.Close()
	ev := h.sink.waitFor(t, record.KindSSLRequest, 1)[0]
	if strings.Contains(string(ev.Payload), `"route"`) {
		t.Fatalf("an unrouted request names a route: %s", ev.Payload)
	}
	if newRouter([]agent.ModelEndpoint{{Host: "h", Port: 1}}, nil) != nil {
		t.Fatal("a router for models with no route")
	}
}

// TestManagerPollsRouteChanges: a Manager whose contract declares routes binds the router at Start, writes a change's
// line within RoutePoll with no request at all, and stops its poll at Stop.
func TestManagerPollsRouteChanges(t *testing.T) {
	model := agent.ModelEndpoint{Provider: "anthropic", Host: "api.anthropic.com", Port: 443,
		Routes: []agent.ModelRoute{{Name: "corp", Host: "proxy.example", Port: 8443}}}
	m, err := NewManager([]agent.ModelEndpoint{model}, Options{Clock: newClock(), Rand: &countingRand{}})
	if err != nil {
		t.Fatal(err)
	}
	if m.routes == nil || m.listeners[0].routes != m.routes {
		t.Fatal("no router")
	}
	dir := t.TempDir()
	sink := &fakeSink{}
	run := source.RunRef{ID: testRun.ID, Agent: "a", Dir: dir}
	if err := m.Start(context.Background(), run, sink); err != nil {
		t.Fatal(err)
	}
	if _, err := modelroutes.Update(context.Background(), dir, run.ID, func(o *modelroutes.Overlay) (bool, error) {
		return o.Set("api.anthropic.com:443", "corp", "uid:1 pid:2 dashboard", time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(routeChanges(t, sink)) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	ch := routeChanges(t, sink)
	if len(ch) != 1 || ch[0].Route != "corp" || ch[0].Authority != "proxy.example:8443" || ch[0].By != "uid:1 pid:2 dashboard" {
		t.Fatalf("changes %+v", ch)
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	m.routes.mu.Lock()
	stopped := m.routes.stop == nil
	m.routes.mu.Unlock()
	if !stopped {
		t.Fatal("the poll is still running")
	}
}

// TestRouteMovedWhileHeldIsNotSent: a request held for a person's approval whose endpoint is moved to another route
// while it waits is answered 503 and sent nowhere, neither where it was going nor to the new route, and the refusal is a
// net line (R26): refused model-route-changed under models[<endpoint>].routes, naming the route it would have taken.
func TestRouteMovedWhileHeldIsNotSent(t *testing.T) {
	var direct, alt atomic.Int64
	altUp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { alt.Add(1); okBody(w) }))
	t.Cleanup(altUp.Close)
	dir := t.TempDir()
	var l *Listener
	var sink *fakeSink
	var targets []string
	// The approval moves the route by writing its file, which a busy disk can make take longer than askHarness's 1 s.
	l, sink = askHarnessWithin(t, 4096, askBudget(t), func(ctx context.Context, q ask.Request) (ask.Decision, error) {
		targets = append(targets, q.Target)
		if _, err := modelroutes.Update(ctx, dir, testRun.ID, func(o *modelroutes.Overlay) (bool, error) {
			return o.Set(l.authority(), "alt", "uid:1 pid:2 cli", time.Now())
		}); err != nil {
			return ask.Decision{}, err
		}
		return ask.Decision{Approved: true}, nil
	}, func(w http.ResponseWriter, _ *http.Request) { direct.Add(1); okBody(w) })
	altHost, altPort := hostPort(t, altUp.Listener.Addr().String())
	l.model.Routes = []agent.ModelRoute{{Name: "alt", Host: altHost, Port: altPort}}
	rt := newRouter([]agent.ModelEndpoint{l.model}, nil)
	rt.newTransport = func(*Listener, modelroute.Route) http.RoundTripper { return altUp.Client().Transport }
	l.routes = rt
	rt.bind(dir, testRun.ID, l)
	t.Cleanup(rt.stopAndWait)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Post(l.BaseURL()+"/allowed", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(b), "route changed while the request waited for approval") {
		t.Fatalf("held request: %d %s", resp.StatusCode, b)
	}
	if direct.Load()+alt.Load() != 0 {
		t.Fatalf("sent anyway: direct %d alt %d", direct.Load(), alt.Load())
	}
	delivered(l) // the refusal line was queued before the 503 was written
	var refused *record.Event
	for _, ev := range sink.of(record.KindNet) {
		if ev.Reason == record.ReasonModelRouteChanged {
			refused = ev
		}
	}
	if refused == nil || refused.Verdict != record.VerdictRefused || refused.Rule != record.ModelRouteRule(l.authority()) {
		t.Fatalf("no refusal line: %+v", refused)
	}
	if p := payloadOf[record.NetPayload](t, refused); p.Route == nil || p.Route.Name != "direct" || p.Dst != l.authority() ||
		p.Method != http.MethodPost || p.Path != "/allowed" {
		t.Fatalf("refusal payload %+v", p)
	}
	// The next request goes by the new route (another body: the broker coalesces a repeat of the same request).
	resp, err = (&http.Client{Timeout: 5 * time.Second}).Post(l.BaseURL()+"/allowed", "application/json", strings.NewReader(`{"n":2}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || alt.Load() != 1 || direct.Load() != 0 {
		t.Fatalf("next request: %d %s, direct %d alt %d", resp.StatusCode, b, direct.Load(), alt.Load())
	}
	// The person approving is shown where the request goes: the endpoint alone on direct, and the route and its
	// backend once the endpoint is on alt.
	wantAlt := l.authority() + " via alt (" + altUp.Listener.Addr().String() + ") POST /allowed"
	if len(targets) != 2 || targets[0] != l.authority()+" POST /allowed" || targets[1] != wantAlt {
		t.Fatalf("ask targets %q, want [%q %q]", targets, l.authority()+" POST /allowed", wantAlt)
	}
}

// TestRouteMovedWhileReadIsSentByItsChosenRoute: a request no approval held goes by the route chosen when it arrived,
// which its credential check decided for, even when the route moves while its body is read; it is not refused, and
// its line names the route it took. The next request takes the new route.
func TestRouteMovedWhileReadIsSentByItsChosenRoute(t *testing.T) {
	rh := newRouteHarness(t, Options{})
	// An overlay that exists and keeps the endpoint on direct, so the request's route choice reads it, which the hook
	// below sees: the route is chosen before the body is read.
	rh.set(t, "plain")
	rh.set(t, "direct")
	chosen := make(chan struct{}, 4)
	rh.listener.routes.mu.Lock()
	rh.listener.routes.read = func(dir, run string) (*modelroutes.Overlay, error) {
		chosen <- struct{}{}
		return modelroutes.Read(dir, run)
	}
	rh.listener.routes.mu.Unlock()
	body := `{"model":"m","max_tokens":1,"messages":[]}`
	c, err := net.Dial("tcp", strings.TrimPrefix(rh.listener.BaseURL(), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := fmt.Fprintf(c, "POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body[:10]); err != nil {
		t.Fatal(err)
	}
	select {
	case <-chosen:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never chose its route")
	}
	rh.set(t, "alt") // while its body is still being read
	if _, err := io.WriteString(c, body[10:]); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || rh.direct.Load() != 1 || rh.altHits.Load() != 0 {
		t.Fatalf("%d: direct %d alt %d", resp.StatusCode, rh.direct.Load(), rh.altHits.Load())
	}
	if r := routeOf(t, rh.sink.waitFor(t, record.KindSSLRequest, 1)[0]); r == nil || r.Name != "direct" {
		t.Fatalf("route %+v", r)
	}
	for _, ev := range rh.sink.of(record.KindNet) {
		if ev.Reason == record.ReasonModelRouteChanged {
			t.Fatalf("a request no approval held was refused: %+v", ev)
		}
	}
	if code, _ := rh.send(t, nil); code != http.StatusOK || rh.altHits.Load() != 1 {
		t.Fatalf("next: %d alt %d", code, rh.altHits.Load())
	}
}

// TestRouteLowerSerialOverlayIsRecorded: an overlay replaced by one whose serial is lower (removed, then set again
// within one poll) still writes a line for the route it puts in force, from its own entry; a removed overlay reverts
// the endpoint to direct with a line of serial 0 (no change numbered it); and no request goes by a route no line put
// in force.
func TestRouteLowerSerialOverlayIsRecorded(t *testing.T) {
	rh := newRouteHarness(t, Options{})
	for _, r := range []string{"alt", "plain", "direct"} {
		rh.set(t, r)
		if code, _ := rh.send(t, nil); code != http.StatusOK {
			t.Fatalf("%s: %d", r, code)
		}
	}
	delivered(rh.listener)
	if ch := routeChanges(t, rh.sink); len(ch) != 3 {
		t.Fatalf("changes %+v", ch)
	}
	if err := os.Remove(filepath.Join(rh.dir, modelroutes.FileName)); err != nil {
		t.Fatal(err)
	}
	rh.set(t, "alt") // a new file: serial 1, below the 3 the forwarder last read
	if code, _ := rh.send(t, nil); code != http.StatusOK || rh.altHits.Load() != 2 {
		t.Fatalf("after the reset: %d alt %d", code, rh.altHits.Load())
	}
	delivered(rh.listener)
	ch := routeChanges(t, rh.sink)
	if len(ch) != 4 || ch[3].Route != "alt" || ch[3].Serial != 1 || ch[3].Authority != rh.altHost || ch[3].By != "uid:1000 pid:1 cli" {
		t.Fatalf("after the reset: changes %+v", ch)
	}
	if err := os.Remove(filepath.Join(rh.dir, modelroutes.FileName)); err != nil {
		t.Fatal(err)
	}
	if code, _ := rh.send(t, nil); code != http.StatusOK || rh.direct.Load() != 2 {
		t.Fatalf("after the removal: %d direct %d", code, rh.direct.Load())
	}
	delivered(rh.listener)
	ch = routeChanges(t, rh.sink)
	if len(ch) != 5 || ch[4].Route != "direct" || ch[4].Serial != 0 || ch[4].Authority != rh.listener.authority() ||
		!strings.HasPrefix(ch[4].By, "forwarder:") {
		t.Fatalf("after the removal: changes %+v", ch)
	}
	// Every request line's route was put in force by a line before it.
	inForce := "direct"
	for _, ev := range rh.sink.all() {
		switch ev.Kind {
		case record.KindGap:
			if p := payloadOf[record.GapPayload](t, ev); p.ModelRoute != nil {
				inForce = p.ModelRoute.Route
			}
		case record.KindSSLRequest:
			if r := routeOf(t, ev); r == nil || r.Name != inForce {
				t.Fatalf("a request went by %+v with %s in force", r, inForce)
			}
		}
	}
}

// TestRouteTransientReadErrorIsRetried: an overlay read that fails for a reason other than distrust or an invalid
// file (EMFILE here) is retried on the next request, rather than leaving the person's change unapplied until the file
// changes again; an untrusted file is not reread until it changes (TestRouteUnreadableOverlayKeepsTheLastRoutes).
func TestRouteTransientReadErrorIsRetried(t *testing.T) {
	rh := newRouteHarness(t, Options{})
	var fail atomic.Bool
	rh.listener.routes.mu.Lock()
	rh.listener.routes.read = func(dir, run string) (*modelroutes.Overlay, error) {
		if fail.CompareAndSwap(true, false) {
			return nil, syscall.EMFILE
		}
		return modelroutes.Read(dir, run)
	}
	rh.listener.routes.mu.Unlock()
	fail.Store(true)
	rh.set(t, "alt")
	if code, _ := rh.send(t, nil); code != http.StatusOK || rh.direct.Load() != 1 {
		t.Fatalf("the failed read: %d direct %d", code, rh.direct.Load())
	}
	if code, _ := rh.send(t, nil); code != http.StatusOK || rh.altHits.Load() != 1 {
		t.Fatalf("the retry: %d alt %d", code, rh.altHits.Load())
	}
	delivered(rh.listener)
	if ch := routeChanges(t, rh.sink); len(ch) != 1 || ch[0].Route != "alt" {
		t.Fatalf("changes %+v", ch)
	}
}

// waitChanges waits for n model-route-changed lines on s and returns them.
func waitChanges(t *testing.T, s *fakeSink, n int) []record.ModelRouteChange {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for len(routeChanges(t, s)) < n && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	return routeChanges(t, s)
}

// TestRouteChangeLineGoesThroughTheEndpointsListener: a change is written through the listener serving its endpoint,
// whichever listener's request or the poll read it, so it is queued ahead of that endpoint's request lines that go by
// the new route; once that listener is closing the line goes through the asking listener instead, never behind the
// closed one's final flush.
func TestRouteChangeLineGoesThroughTheEndpointsListener(t *testing.T) {
	ok := func(w http.ResponseWriter, _ *http.Request) { okBody(w) }
	h1, h2 := newHarness(t, ok, Options{}), newHarness(t, ok, Options{})
	h1.listener.model.Routes = []agent.ModelRoute{{Name: "corp", Host: "proxy.example", Port: 8443}}
	h2.listener.model.Routes = []agent.ModelRoute{{Name: "corp", Host: "proxy.example", Port: 9443}}
	rt := newRouter([]agent.ModelEndpoint{h1.listener.model, h2.listener.model}, nil)
	h1.listener.routes, h2.listener.routes = rt, rt
	dir := t.TempDir()
	rt.bind(dir, testRun.ID, h1.listener, h2.listener)
	t.Cleanup(rt.stopAndWait)
	set := func(route string) {
		t.Helper()
		if _, err := modelroutes.Update(context.Background(), dir, testRun.ID, func(o *modelroutes.Overlay) (bool, error) {
			return o.Set(h2.listener.authority(), route, "uid:1 pid:2 cli", time.Now())
		}); err != nil {
			t.Fatal(err)
		}
	}
	set("corp")
	rt.refresh(false, h1.listener) // a request of h1's endpoint reads h2's endpoint's change
	if ch := waitChanges(t, h2.sink, 1); len(ch) != 1 || ch[0].Model != h2.listener.authority() || ch[0].Route != "corp" {
		t.Fatalf("the endpoint's listener wrote %+v", ch)
	}
	if ch := routeChanges(t, h1.sink); len(ch) != 0 {
		t.Fatalf("the asking listener wrote %+v", ch)
	}
	if err := h2.listener.Close(); err != nil {
		t.Fatal(err)
	}
	set("direct")
	rt.refresh(false, h1.listener)
	if ch := waitChanges(t, h1.sink, 1); len(ch) != 1 || ch[0].Model != h2.listener.authority() || ch[0].Route != "direct" {
		t.Fatalf("with the endpoint's listener closed, the asking listener wrote %+v", ch)
	}
	if ch := routeChanges(t, h2.sink); len(ch) != 1 {
		t.Fatalf("a line went through the closed listener: %+v", ch)
	}
}

// TestRouteSetBeforeBindIsRecorded: a route a person set before the forwarder's first read (a script that sets one as
// soon as the run's directory appears) is put in force with a line of its own, taken from the overlay's entry, so the
// first request's route was put in force by a line before it; an overlay that keeps every endpoint on direct writes
// none.
func TestRouteSetBeforeBindIsRecorded(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) { okBody(w) }, Options{})
	h.listener.model.Routes = []agent.ModelRoute{{Name: "corp", Host: "proxy.example", Port: 8443}}
	dir := t.TempDir()
	if _, err := modelroutes.Update(context.Background(), dir, testRun.ID, func(o *modelroutes.Overlay) (bool, error) {
		return o.Set(h.listener.authority(), "corp", "uid:1 pid:2 cli", time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	rt := newRouter([]agent.ModelEndpoint{h.listener.model}, nil)
	h.listener.routes = rt
	rt.bind(dir, testRun.ID, h.listener)
	t.Cleanup(rt.stopAndWait)
	ch := waitChanges(t, h.sink, 1)
	if len(ch) != 1 || ch[0].Route != "corp" || ch[0].Authority != "proxy.example:8443" || ch[0].Serial != 1 || ch[0].By != "uid:1 pid:2 cli" {
		t.Fatalf("changes at bind %+v", ch)
	}

	other := newHarness(t, func(w http.ResponseWriter, _ *http.Request) { okBody(w) }, Options{})
	other.listener.model.Routes = h.listener.model.Routes
	quiet := t.TempDir()
	if _, err := modelroutes.Update(context.Background(), quiet, testRun.ID, func(o *modelroutes.Overlay) (bool, error) {
		if _, err := o.Set(other.listener.authority(), "corp", "uid:1 pid:2 cli", time.Now()); err != nil {
			return false, err
		}
		return o.Set(other.listener.authority(), "direct", "uid:1 pid:2 cli", time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	rt2 := newRouter([]agent.ModelEndpoint{other.listener.model}, nil)
	other.listener.routes = rt2
	rt2.bind(quiet, testRun.ID, other.listener)
	t.Cleanup(rt2.stopAndWait)
	time.Sleep(50 * time.Millisecond)
	if ch := routeChanges(t, other.sink); len(ch) != 0 {
		t.Fatalf("an overlay on direct wrote %+v at bind", ch)
	}
}

// TestRouteCoalescedRetryAfterASwitchGetsItsOwnApproval: a repeat of a held request (same sender, body and headers, as
// an SDK retry after a timeout) that arrives after a person moved the endpoint does not join the held one's approval,
// whose card showed another destination: it is asked on its own, with a card naming its route, and goes there once
// approved; the held one is refused for its moved route.
func TestRouteCoalescedRetryAfterASwitchGetsItsOwnApproval(t *testing.T) {
	var direct, alt atomic.Int64
	altUp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { alt.Add(1); okBody(w) }))
	t.Cleanup(altUp.Close)
	dir := t.TempDir()
	asked := make(chan string, 4)
	release := make(chan struct{})
	// The first request stays held while the test moves the route (a file write) and a second request is asked.
	l, _ := askHarnessWithin(t, 4096, askBudget(t), func(ctx context.Context, q ask.Request) (ask.Decision, error) {
		asked <- q.Target
		select {
		case <-release:
			return ask.Decision{Approved: true}, nil
		case <-ctx.Done():
			return ask.Decision{}, ctx.Err()
		}
	}, func(w http.ResponseWriter, _ *http.Request) { direct.Add(1); okBody(w) })
	altHost, altPort := hostPort(t, altUp.Listener.Addr().String())
	l.model.Routes = []agent.ModelRoute{{Name: "alt", Host: altHost, Port: altPort}}
	rt := newRouter([]agent.ModelEndpoint{l.model}, nil)
	rt.newTransport = func(*Listener, modelroute.Route) http.RoundTripper { return altUp.Client().Transport }
	l.routes = rt
	rt.bind(dir, testRun.ID, l)
	t.Cleanup(rt.stopAndWait)
	type answer struct {
		code int
		body string
	}
	post := func() <-chan answer {
		out := make(chan answer, 1)
		go func() {
			resp, err := (&http.Client{Timeout: 5 * time.Second}).Post(l.BaseURL()+"/allowed", "application/json", strings.NewReader("{}"))
			if err != nil {
				out <- answer{body: err.Error()}
				return
			}
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			out <- answer{resp.StatusCode, string(b)}
		}()
		return out
	}
	next := func() string {
		t.Helper()
		select {
		case target := <-asked:
			return target
		case <-time.After(3 * time.Second):
			close(release)
			t.Fatal("no approval was asked")
			return ""
		}
	}
	first := post()
	held := next()
	if _, err := modelroutes.Update(context.Background(), dir, testRun.ID, func(o *modelroutes.Overlay) (bool, error) {
		return o.Set(l.authority(), "alt", "uid:1 pid:2 cli", time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	retry := post()
	retried := next()
	close(release)
	a, b := <-first, <-retry
	wantAlt := l.authority() + " via alt (" + altUp.Listener.Addr().String() + ") POST /allowed"
	if held != l.authority()+" POST /allowed" || retried != wantAlt {
		t.Fatalf("cards %q and %q, want %q", held, retried, wantAlt)
	}
	if a.code != http.StatusServiceUnavailable || !strings.Contains(a.body, "route changed") {
		t.Fatalf("the held request: %d %s", a.code, a.body)
	}
	if b.code != http.StatusOK || alt.Load() != 1 || direct.Load() != 0 {
		t.Fatalf("the retry: %d %s, direct %d alt %d", b.code, b.body, direct.Load(), alt.Load())
	}
}

// TestRoutedTunnelRefusalIsRecorded: under net.proxy, a CONNECT or an upgrade to an endpoint on a route other than its
// own is refused, and the refusal is a net line (R26), refused net-http under models[<endpoint>].routes, naming the
// route in force; the route was put in force at the run's start by the line bind writes for an overlay set before it.
func TestRoutedTunnelRefusalIsRecorded(t *testing.T) {
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = up.Close() })
	host, port := hostPort(t, up.Addr().String())
	model := agent.ModelEndpoint{Host: host, Port: port, Routes: []agent.ModelRoute{{Name: "corp", Host: "proxy.example", Port: 8443}}}
	p := compiledProtocols(t, model, &agent.ProxyPolicy{Connect: []string{up.Addr().String()}})
	m, err := NewManager([]agent.ModelEndpoint{model}, Options{Proxy: p})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop() })
	id, err := liveCgroupID()
	if err != nil {
		t.Skipf("actual peer admission needs cgroup identity: %v", err)
	}
	dir := t.TempDir()
	authority := model.ModelAuthority()
	if _, err := modelroutes.Update(context.Background(), dir, testRun.ID, func(o *modelroutes.Overlay) (bool, error) {
		return o.Set(authority, "corp", "uid:1 pid:2 cli", time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	run := testRun
	run.Dir, run.CgroupID, run.Contract = dir, id, &agent.RuleTable{Record: agent.RecordSummary, Proxy: p}
	sink := &fakeSink{}
	if err := m.Start(context.Background(), run, sink); err != nil {
		t.Fatal(err)
	}
	l := m.Listeners()[0]
	if ch := waitChanges(t, sink, 1); len(ch) != 1 || ch[0].Route != "corp" {
		t.Fatalf("changes %+v", ch)
	}
	for _, tc := range []struct{ op, request string }{
		{"connect_tunnel", connectRequest(up.Addr().String())},
		{"websocket", "GET /ws HTTP/1.1\r\nHost: " + up.Addr().String() + "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
			"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"},
	} {
		_, _, resp := protocolConn(t, l, tc.request, nil)
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(b), "routed to corp") {
			t.Fatalf("%s: %d %s", tc.op, resp.StatusCode, b)
		}
		var line *record.Event
		deadline := time.Now().Add(3 * time.Second)
		for line == nil && time.Now().Before(deadline) {
			for _, ev := range sink.of(record.KindNet) {
				if payloadOf[record.NetPayload](t, ev).Op == tc.op {
					line = ev
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		if line == nil || line.Verdict != record.VerdictRefused || line.Reason != record.ReasonNetHTTP ||
			line.Rule != record.ModelRouteRule(authority) {
			t.Fatalf("%s: line %+v", tc.op, line)
		}
		if p := payloadOf[record.NetPayload](t, line); p.Route == nil || p.Route.Name != "corp" || p.Route.Authority != "proxy.example:8443" ||
			p.Dst != authority {
			t.Fatalf("%s: payload %+v", tc.op, p)
		}
	}
}

// addrConn is a net.Conn that reports remote as its peer.
type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.remote }

// TestPlaintextRouteDialsLoopbackOnly: a tls: false route's leg refuses a connection whose peer is not this machine's
// loopback, whatever name led there (a resolver that sends localhost to DNS), and keeps one that is.
func TestPlaintextRouteDialsLoopbackOnly(t *testing.T) {
	for _, tc := range []struct {
		remote string
		ok     bool
	}{{"127.0.0.1:11434", true}, {"[::1]:11434", true}, {"[::ffff:127.0.0.1]:11434", true}, {"203.0.113.5:11434", false},
		{"[2001:db8::1]:11434", false}} {
		var closed atomic.Bool
		dial := loopbackOnly(func(context.Context, string, string) (net.Conn, error) {
			a, b := net.Pipe()
			t.Cleanup(func() { _ = b.Close() })
			ap := netip.MustParseAddrPort(tc.remote)
			return addrConn{Conn: closeNote{a, &closed}, remote: net.TCPAddrFromAddrPort(ap)}, nil
		})
		c, err := dial(context.Background(), "tcp", "localhost:11434")
		if tc.ok != (err == nil) || (err != nil && !errors.Is(err, errPlaintextOffLoopback)) {
			t.Fatalf("%s: %v", tc.remote, err)
		}
		if c != nil {
			_ = c.Close()
		} else if !closed.Load() {
			t.Fatalf("%s: the refused connection was left open", tc.remote)
		}
	}
}

// closeNote notes its Close.
type closeNote struct {
	net.Conn
	closed *atomic.Bool
}

func (c closeNote) Close() error { c.closed.Store(true); return c.Conn.Close() }

// TestPlaintextRouteLegChecksLoopback: the production leg of a tls: false route (buildRouteTransport) holds the
// connection to this machine's loopback: a localhost route whose resolver answers with an address off this machine,
// which validatedDial keeps for a localhost name, is refused by the leg's own check before a byte is written.
func TestPlaintextRouteLegChecksLoopback(t *testing.T) {
	for _, tc := range []struct {
		answer string
		ok     bool
	}{{"203.0.113.5", false}, {"127.0.0.1", true}} {
		var closed atomic.Bool
		h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) { okBody(w) }, Options{})
		h.listener.opts.Resolver = fixedResolver{netip.MustParseAddr(tc.answer)}
		h.listener.opts.routeDial = func(_ context.Context, _, addr string) (net.Conn, error) {
			a, b := net.Pipe()
			t.Cleanup(func() { _ = b.Close() })
			return addrConn{Conn: closeNote{a, &closed}, remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(addr))}, nil
		}
		off := false
		r, declared := modelroute.Resolve(agent.ModelEndpoint{Host: "h", Port: 443,
			Routes: []agent.ModelRoute{{Name: "local", Host: "localhost", Port: 11434, TLS: &off}}}, "local")
		if !declared || r.TLS {
			t.Fatalf("route %+v", r)
		}
		tr, isTransport := buildRouteTransport(h.listener, r).(*http.Transport)
		if !isTransport {
			t.Fatal("the route leg is not an *http.Transport")
		}
		c, err := tr.DialContext(context.Background(), "tcp", "localhost:11434")
		if tc.ok != (err == nil) || (err != nil && !errors.Is(err, errPlaintextOffLoopback)) {
			t.Fatalf("%s: %v", tc.answer, err)
		}
		if c != nil {
			_ = c.Close()
		} else if !closed.Load() {
			t.Fatalf("%s: the refused connection was left open", tc.answer)
		}
	}
}

// fixedResolver answers every lookup with its addresses.
type fixedResolver []netip.Addr

func (r fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r, nil
}
