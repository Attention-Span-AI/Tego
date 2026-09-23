// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/policy/httppolicy"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Loopback is the only address a listener binds, and a plaintext loopback URL is never negotiated up to
// h2 by a client (R19).
//
// It bounds the listener to this host and to nothing further: a loopback socket is still reachable by
// every process on the machine, of any uid and any cgroup, and by a cross-origin POST from a page in the
// developer's browser. The run's Landlock and cgroup rules constrain the agent, not the rest of the
// machine, so which peer may be served is a question this listener answers for itself, per connection,
// in peer.go (R19a, CVE-2025-52882).
const Loopback = "127.0.0.1"

// HelloPath is the path a harness health-checks before its first call; the forwarder answers it itself,
// whether or not the upstream is reachable (R22).
const HelloPath = "/api/hello"

// DefaultMaxBody is how much of one body capture keeps in memory for the record and for derive. Bytes
// beyond it are still forwarded byte for byte — the cap bounds what is captured, never what is sent.
const DefaultMaxBody = 8 << 20

// ReadHeaderTimeout bounds a request's headers on the inbound loopback side. It, the request body's deadlines
// below and DefaultIdleTimeout between requests are the timeouts the forwarder imposes, all on that side: a
// response must never be cut short by a ceiling below the client's own (R27).
const ReadHeaderTimeout = 30 * time.Second

// DefaultBodyIdleTimeout is how long a request body may go without a byte before the forwarder stops reading
// it. A body's capture array is reserved as its bytes arrive, but a body that stops arriving
// still holds what it has, and the connection with it: net/http sets no deadline on a body once the headers
// are read, and ReadHeaderTimeout covers the headers alone. An SDK writes its request body in one go, so a
// gap this long is a peer that is not sending. The deadline is lifted when the body has been read, so it
// never touches the response, which R27 leaves to the client's own ceiling.
const DefaultBodyIdleTimeout = 30 * time.Second

// DefaultBodyTimeout is the longest a request body may take from its first read to its end, however steadily
// its bytes arrive (R27). The idle deadline is per gap, so a body sent quickly to just under MaxBody and
// then one byte every 29 s met it forever, and held its capture-budget reservation, and the connection, for as
// long as the agent liked. Ten minutes is far past any body an SDK writes: the Messages API refuses a request
// over 32 MB, and 32 MB takes about 4.5 minutes even through a 1 Mbit/s uplink (the upstream leg reads the body
// past MaxBody as it arrives, so the uplink is what paces it); a local agent writing to loopback finishes in
// well under a second. A body still arriving at ten minutes is answered as a stalled one is.
const DefaultBodyTimeout = 10 * time.Minute

// requestChunk is the first array a request body of declared length is read into; the array doubles from
// there up to the declared length (R27). A body that fits is read into one array of its own size.
const requestChunk = 64 << 10

// streamChunk is the read size of the response pump. Each read is written and flushed before the next
// one, which is what makes an event stream arrive as it is produced (R21).
const streamChunk = 32 << 10

// Deriver turns one captured exchange into the facts an ssl_response carries and the events that follow
// it. *derive.Dispatcher is the implementation; a nil Deriver disables derivation, and the forwarder
// still records the exchange.
type Deriver interface {
	Handle(req, resp *derive.Message, meta derive.Meta) (derive.Result, error)
}

// requestReader is a Deriver that also reads what a request says alone (derive.Dispatcher.ReadRequest): whether it
// is the model host's side traffic, and the tool results a model turn reports, which the request line carries for
// the attribute stage (capture-derive R40, R42).
type requestReader interface {
	ReadRequest(req *derive.Message, meta derive.Meta) derive.RequestReading
}

// Options configure a Listener. The zero value is usable: it binds a loopback port, records bodies, and
// derives nothing.
type Options struct {
	// HTTPPolicy is an immutable policy for every declared upstream listener.
	// Nil preserves ordinary capture-only forwarding.
	HTTPPolicy *httppolicy.Policy
	// Proxy enables explicitly compiled additional protocols and fixed ceilings.
	Proxy *agent.CompiledProxyPolicy
	// Resolver and DeniedResolved govern the host-side upstream lookup. The
	// default transport dials only the addresses it validated from that lookup.
	Resolver       agent.Resolver
	DeniedResolved []netip.Prefix
	resolveSem     chan struct{}
	// routeDial is the connection a route's upstream leg makes once validatedDial chose the address; nil dials the
	// network. Tests replace it to reach the plaintext leg's loopback check with a peer off this machine.
	routeDial   dialContext
	askRequests *requestAsks
	tunnelSem   chan struct{}
	// tcpDiag is the run's exact peer lookup, which a kernel without TCP sock_diag turns off once for every listener
	// (Manager sets one for all of them); nil makes one for this listener.
	tcpDiag *tcpDiag
	// Transport is the upstream leg; nil builds the TLS transport of the model's own host.
	Transport http.RoundTripper
	// Listen overrides the bind address; "" is 127.0.0.1:0 (R19).
	Listen string
	// Clock supplies both timestamps; nil is the system clock. The retry window and the step windows
	// key off the monotonic reading, which NTP never steps (#25).
	Clock ledger.Clock
	// Rand supplies span ids; nil is crypto/rand.
	Rand io.Reader
	// Deriver is the provider dispatch; nil records without deriving.
	Deriver Deriver
	// Logger receives what is not itself an event; nil discards it.
	Logger *slog.Logger
	// Bodies records request and response bodies in the event payloads; false is record: summary.
	Bodies bool
	// MaxBody caps what capture keeps of one body; 0 is DefaultMaxBody.
	MaxBody int
	// MaxCaptureBytes caps the arrays capture holds between them, counted by capacity: every body in
	// flight, every decoded form, and every event's copy of a body until the collector finds it
	// unreachable, which is after the ledger writer is done with it; 0 is DefaultMaxCaptureBytes. No
	// cgroup covers the launcher, so this is what keeps an agent from growing its heap through
	// capture. It is not the launcher's whole heap: §3 lists what else capture costs, and the collector
	// lets the heap run past what is live (GOGC). A value below one exchange at its largest
	// (5 × MaxBody, newBudget) is raised to that floor.
	MaxCaptureBytes int
	// BodyIdleTimeout bounds the wait for a request body's next byte; 0 is DefaultBodyIdleTimeout.
	BodyIdleTimeout time.Duration
	// BodyTimeout bounds a request body's whole read, first byte to last; 0 is DefaultBodyTimeout.
	BodyTimeout time.Duration
	// RetryEntries and RetryTTL size the retry-attach cache; zero values are R24's defaults.
	RetryEntries int
	RetryTTL     time.Duration
	// IdleTimeout closes a keep-alive connection idle this long between requests; 0 is DefaultIdleTimeout.
	IdleTimeout time.Duration
	// MaxConns caps the connections one listener holds open at once; 0 is DefaultMaxConns.
	MaxConns int
	// WriteStallTimeout is how long one write of a response to the client may make no progress before the
	// exchange gives its record copy back to the capture budget; 0 is DefaultWriteStallTimeout.
	WriteStallTimeout time.Duration
	// Activity is told, at most once per activityGrain, that a response or tunnel relayed bytes, with the
	// Clock's monotonic reading: the run's stall check counts model traffic in flight as activity in every
	// record mode (limits R4, R21). Nil reports nothing. A Manager shares one meter across its listeners;
	// the runtime sets it through Manager.SetStreamActivity.
	Activity func(monoNS uint64)
	// Credentials is nil (keylayer.go): every header is forwarded as the agent sent it.
	Credentials KeyLayer
}

// maxBodyOf is Options.MaxBody with its documented zero meaning filled in. NewListener normalizes its own
// copy, but the budget Manager shares across a run's listeners is sized from the caller's Options before
// any listener exists, and newBudget's floor is stated in terms of MaxBody ("floor one exchange", §3's
// resource table). Reading the raw zero there computes a floor of nothing, so a run that configures
// MaxCaptureBytes and leaves MaxBody at its default ends up with a budget below the single body MaxBody
// promises to keep — which is the arithmetic the floor exists to rule out.
func maxBodyOf(opts Options) int {
	if opts.MaxBody <= 0 {
		return DefaultMaxBody
	}
	return opts.MaxBody
}

// Listener is one loopback listener bound to one declared models[] entry (R19). It forwards plaintext
// in and TLS out, rewriting only Host and SNI, and emits the same ssl_request/ssl_response pair the
// uprobe path emits for the same call.
type Listener struct {
	acceptReady        chan error
	serving            atomic.Bool
	model              agent.ModelEndpoint
	upstream           *url.URL
	transport          http.RoundTripper
	websocketTransport http.RoundTripper
	tunnelDial         dialContext
	tunnels            map[*proxyTunnel]struct{}
	tunnelCtx          context.Context
	tunnelCancel       context.CancelFunc
	opts               Options
	ln                 net.Listener
	srv                *http.Server
	retries            *retryCache
	budget             *budget
	// lanes numbers each peer process's turns in flight, the thread a turn is keyed by (R34); one
	// per run's Manager, shared by its listeners like the budget.
	lanes *lanes
	// activity reports relayed chunks to the run's stall check (Options.Activity); nil when nothing
	// listens. One per run's Manager, shared by its listeners like the budget, and set before Serve.
	activity *activityMeter
	// creds is the run's key layer, started (Options.Credentials); nil when the run has none. One per run's Manager,
	// shared by its listeners like the budget.
	creds keyInjector
	// routes is the run's model routes (ADR 0127); nil when no models[] entry declares one. One per run's Manager,
	// shared by its listeners like the budget; a listener whose own endpoint declares none never consults it.
	routes *router

	// handlers counts the ServeHTTP goroutines net/http started, so Close can join them: srv.Close
	// closes the connections but never waits for the handlers running on them (#28, I4).
	handlers sync.WaitGroup

	// peers decides which local process may be served (R19a); refused counts the requests turned away,
	// which is not a capture gap and so has no place in the run's gap report (see refusePeer).
	peers   peerAdmitter
	refused atomic.Int64
	// forgetPeer tells the admitter a connection has closed (procAdmitter.forget); nil is nothing to tell.
	forgetPeer func(peer, local netip.AddrPort)
	// overCap counts the connections closed at the cap (capListener), for logging only the first.
	overCap atomic.Int64
	// unforwarded counts the requests forward gave up before they went upstream, for logging only the first at
	// warn level (logUnforwarded).
	unforwarded atomic.Int64

	mu sync.Mutex
	// closed is set by Close, under mu, before it joins the handlers; ServeHTTP reads it and counts
	// itself into handlers in the same critical section, so every Add happens before Close's Wait and a
	// request dispatched after that is turned away rather than emitting behind the run's drain.
	closed   bool
	run      source.RunRef
	sink     source.Sink
	inflight map[string]*exchange
	gaps     map[string]int64

	// emitq hands events to sink off the handler's path (I1).
	emitq *emitQueue

	closeOnce sync.Once
	closeErr  error
}

// NewListener binds the loopback socket for one models[] entry. Binding happens here, before a run
// starts, because the base URL the run's environment carries has to exist before the agent execs
// (spec/identity/RUN-IDENTITY.md).
func NewListener(model agent.ModelEndpoint, opts Options) (*Listener, error) {
	if model.Host == "" {
		return nil, fmt.Errorf("%w: models entry without a host", ErrListener)
	}
	port := model.Port
	if port == 0 {
		port = 443
	}
	model.Host = agent.CanonicalHost(model.Host)
	if opts.HTTPPolicy != nil && !opts.HTTPPolicy.Covers(httppolicy.Authority(model.Host, port)) {
		return nil, fmt.Errorf("%w: HTTP policy does not cover model listener", ErrListener)
	}
	if opts.Proxy != nil && !opts.Proxy.Covers(httppolicy.Authority(model.Host, port)) {
		return nil, fmt.Errorf("%w: proxy policy does not cover model listener", ErrListener)
	}
	if opts.HTTPPolicy != nil {
		if _, enabled := opts.Proxy.Connect(httppolicy.Authority(model.Host, port)); enabled {
			return nil, fmt.Errorf("%w: opaque CONNECT bypasses HTTP method/path policy", ErrListener)
		}
	}
	upstream := &url.URL{Scheme: "https", Host: net.JoinHostPort(model.Host, fmt.Sprint(port))}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Clock == nil {
		opts.Clock = ledger.SystemClock{}
	}
	if opts.Rand == nil {
		opts.Rand = rand.Reader
	}
	opts.MaxBody = maxBodyOf(opts)
	if opts.BodyIdleTimeout <= 0 {
		opts.BodyIdleTimeout = DefaultBodyIdleTimeout
	}
	if opts.BodyTimeout <= 0 {
		opts.BodyTimeout = DefaultBodyTimeout
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = DefaultIdleTimeout
	}
	if opts.MaxConns <= 0 {
		opts.MaxConns = DefaultMaxConns
	}
	if opts.WriteStallTimeout <= 0 {
		opts.WriteStallTimeout = DefaultWriteStallTimeout
	}
	addr := opts.Listen
	if addr == "" {
		addr = net.JoinHostPort(Loopback, "0")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%w: bind %s: %w", ErrListener, addr, err)
	}
	l := &Listener{
		model:     model,
		upstream:  upstream,
		transport: opts.Transport,
		opts:      opts,
		ln:        ln,
		retries:   newRetryCache(opts.RetryEntries, opts.RetryTTL),
		budget:    newBudget(opts.MaxCaptureBytes, opts.MaxBody),
		lanes:     newLanes(),
		activity:  newActivityMeter(opts.Activity, opts.Clock),
		inflight:  make(map[string]*exchange),
		gaps:      make(map[string]int64),
		tunnels:   make(map[*proxyTunnel]struct{}),
	}
	l.emitq = newEmitQueue(func(n int64) { l.note(GapEmitQueueFull, n) }, l.emitsLost)
	if opts.Credentials != nil {
		if l.creds, err = opts.Credentials.start(opts.Rand); err != nil {
			_ = ln.Close()
			return nil, err
		}
	}
	l.tunnelCtx, l.tunnelCancel = context.WithCancel(context.Background())
	if l.opts.tcpDiag == nil {
		l.opts.tcpDiag = newTCPDiag(l.opts.Logger)
	}
	admitter := newProcAdmitterOn(l.opts.tcpDiag)
	l.peers, l.forgetPeer = admitter.admit, admitter.forget
	l.ln = &capListener{Listener: ln, max: int64(opts.MaxConns), maxOutsiders: DefaultMaxOutsiders,
		resolve: l.resolveConn, refuse: l.refuseOverCap, turnAway: l.turnAwayOutsider, closed: l.connClosed}
	l.tunnelDial = newValidatedDial(model, opts.DeniedResolved, opts.Resolver, nil, opts.resolveSem).DialContext
	if l.transport == nil {
		transport := NewTransport(model.Host)
		transport.DialContext = l.tunnelDial
		l.transport = transport
	}
	if opts.Proxy != nil {
		if l.opts.tunnelSem == nil {
			l.opts.tunnelSem = make(chan struct{}, int(opts.Proxy.Bounds().MaxStreams))
		}
		l.websocketTransport = websocketRoundTripper(l.transport)
	}
	l.srv = &http.Server{
		Handler: l,
		// Go's built-in OPTIONS * handler runs before our handler/admission.
		DisableGeneralOptionsHandler: opts.HTTPPolicy != nil || opts.Proxy != nil,
		ReadHeaderTimeout:            ReadHeaderTimeout,
		// Between requests only: net/http applies it while a keep-alive connection waits for its next request
		// line, never to a request or a response, so R27 is untouched.
		IdleTimeout: opts.IdleTimeout,
		ErrorLog:    slog.NewLogLogger(opts.Logger.Handler(), slog.LevelDebug),
		// One peer admission per connection rather than per request (R19a): the decision reads
		// /proc, and a keep-alive connection carrying a whole conversation pays for it once. An accepted
		// connection's verdict is the one capListener decided it under before reading it.
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if cc, ok := c.(*cappedConn); ok {
				return context.WithValue(ctx, peerVerdictKey{}, cc.verdict)
			}
			return context.WithValue(ctx, peerVerdictKey{}, new(peerVerdict))
		},
	}
	configureDownstreamProtocols(l.srv, opts.Proxy)
	return l, nil
}

// NewTransport is the upstream leg of one listener: TLS to the model's own host, with SNI and
// certificate verification pinned to it (R20), no environment proxy on the upstream side, and no
// response ceiling of its own (R27).
//
// A response's headers are bounded at the 1 MiB net/http already holds a request's to (the listener's
// http.Server leaves MaxHeaderBytes at http.DefaultMaxHeaderBytes). The Transport's own default is ten
// times that, and a response event carries the upstream's allow-listed headers outside the capture budget
// (§3), so the one figure §3 gives for an event's own fields holds for both halves of an exchange. The
// HTTP/2 leg takes its header-list limit from the same field, plus net/http's small per-field allowance.
func NewTransport(host string) *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:        &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           32,
		MaxIdleConnsPerHost:    8,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: http.DefaultMaxHeaderBytes,
	}
}

// hostHeader is the Host the upstream leg carries: the declared host, with the port appended when it is
// not the default for TLS, which is what RFC 9110 §7.2 asks for and what a virtual-hosted upstream needs
// to route the call (R20).
func (l *Listener) hostHeader() string {
	if l.model.Port == 0 || l.model.Port == 443 {
		// Model hosts are canonicalized without brackets. IPv6 literals
		// still require brackets in an HTTP authority even with no port.
		if strings.Contains(l.model.Host, ":") {
			return "[" + l.model.Host + "]"
		}
		return l.model.Host
	}
	return net.JoinHostPort(l.model.Host, fmt.Sprint(l.model.Port))
}

// Addr is the bound loopback address.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// AddrPort is the same address in the form the run's net rules are built from: the enforcement tier has
// to admit this endpoint, because once capture is active it is the agent's only route to the model (R38),
// and no compiled contract could have named it — the port exists only once this socket is bound.
// ok is false for a listener whose address is not a TCP endpoint, which the loopback bind above rules out
// but which is not worth a panic.
func (l *Listener) AddrPort() (netip.AddrPort, bool) {
	ta, isTCP := l.ln.Addr().(*net.TCPAddr)
	if !isTCP {
		return netip.AddrPort{}, false
	}
	ap := ta.AddrPort()
	// A v4 address read back through a sockaddr can carry the v4-in-v6 wrapper; the run compares it
	// against what the agent passes to connect(2), which is unwrapped.
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

// BaseURL is the plaintext URL a harness variable points at.
func (l *Listener) BaseURL() string { return "http://" + l.ln.Addr().String() }

// Model is the declared entry this listener serves.
func (l *Listener) Model() agent.ModelEndpoint { return l.model }

// Bind attaches the run and the sink the listener emits into. It is called once, before Serve.
func (l *Listener) Bind(run source.RunRef, sink source.Sink) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.run, l.sink = run, sink
}

// Serve accepts until ctx is cancelled or Close is called; a closed listener is not an error.
func (l *Listener) Serve(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = l.Close()
		case <-done:
		}
	}()
	ln := l.ln
	if l.acceptReady != nil {
		ln = &readyListener{Listener: ln, l: l}
	}
	err := l.srv.Serve(ln)
	l.serving.Store(false)
	close(done)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Close stops the listener and closes every exchange still in flight: a request whose response never
// arrived is one gap, never a silent absence (I4, #28). It is idempotent.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		if l.tunnelCancel != nil {
			l.tunnelCancel()
		}
		l.closeErr = l.srv.Close()
		if errors.Is(l.closeErr, net.ErrClosed) || errors.Is(l.closeErr, http.ErrServerClosed) {
			l.closeErr = nil
		}
		// srv.Close closes only the listeners Serve was handed. NewListener bound the socket before that, so a
		// listener never served (Manager.Stop without Start, a NewManager that failed on a later entry) would
		// otherwise keep its port bound and accepting into the kernel's backlog until the process exits.
		if err := l.ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) && l.closeErr == nil {
			l.closeErr = err
		}
		// srv.Close closed the connections but did not wait for the handlers running on them, and
		// each of those can still emit an event or count a gap. They are joined here, before the
		// claim below, so that Manager.Stop returns only once nothing can enqueue behind the run's
		// drain (R8 of docs/p0/runtime-launch.md, I4). Closing the connection cancels every
		// handler's request context, which aborts its RoundTrip, so the wait is short. A connection
		// net/http had already read a request from can still dispatch a handler after srv.Close; closed
		// turns it away, and set under the lock it orders every handler's Add before the Wait.
		l.mu.Lock()
		l.closed = true
		tunnels := make([]*proxyTunnel, 0, len(l.tunnels))
		for tunnel := range l.tunnels {
			tunnels = append(tunnels, tunnel)
		}
		l.mu.Unlock()
		for _, tunnel := range tunnels {
			tunnel.close()
		}
		if l.opts.askRequests != nil {
			if err := l.opts.askRequests.Close(); err != nil && l.closeErr == nil {
				l.closeErr = err
			}
		}
		l.joinHandlers()
		// Claiming the whole set under the lock is what keeps a request that is finishing right
		// now from being recorded twice: exactly one of Close and finish wins each exchange.
		l.mu.Lock()
		pending := make([]*exchange, 0, len(l.inflight))
		for _, x := range l.inflight {
			pending = append(pending, x)
		}
		l.inflight = make(map[string]*exchange)
		l.mu.Unlock()
		for _, x := range pending {
			l.derive(x, nil)
		}
		// Every line queued so far reaches the sink before Close returns, so nothing is emitted behind the
		// run's drain (I4); a sink that takes none of them within closeDrain has the rest counted as dropped.
		l.emitq.flush(closeDrain)
		if t, ok := l.transport.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
		if t, ok := l.websocketTransport.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
	})
	return l.closeErr
}

// closeDrain bounds the join in Close. A handler whose connection is closed and whose request context is
// cancelled returns at once, so this is a ceiling on a case that should not arise, not a wait anyone pays
// for: a handler that somehow will not return must not hold the run open past its shutdown either.
var closeDrain = 5 * time.Second // a variable so a test can outlast it

// joinHandlers waits for the in-flight ServeHTTP goroutines, up to closeDrain.
func (l *Listener) joinHandlers() {
	done := make(chan struct{})
	go func() {
		l.handlers.Wait()
		close(done)
	}()
	timer := time.NewTimer(closeDrain)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		l.opts.Logger.Warn("forwarder: handlers still running at close",
			"run", l.runRef().ID, "host", l.model.Host)
	}
}

// Gaps reports what this listener could not carry, for the run's gap report, ordered by reason so two runs of
// the same shape write their gap lines in the same order, as every other source's report is.
func (l *Listener) Gaps() []source.Gap {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]source.Gap, 0, len(l.gaps))
	for why, n := range l.gaps {
		out = append(out, source.Gap{What: record.GapCapture, Why: why, Binary: l.model.Host, Count: n})
	}
	slices.SortFunc(out, func(a, b source.Gap) int { return strings.Compare(a.Why, b.Why) })
	return out
}

// ServeHTTP admits the peer (R19a), answers the health check locally, refuses what is not HTTP/1.1
// plaintext, and forwards everything else.
func (l *Listener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Close joins these goroutines before the run's pipeline drains (R8 of docs/p0/runtime-launch.md):
	// an event emitted or a gap counted after the drain has no reader left, and I4 does not allow a
	// capture shortfall to end as silence. A handler that starts once Close has begun joining is served
	// nothing: it would count itself in concurrently with the Wait and emit after the flush.
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		if l.opts.HTTPPolicy != nil || l.opts.Proxy != nil {
			closeHTTPConnection(w)
		}
		http.Error(w, "the listener is closing", http.StatusServiceUnavailable)
		return
	}
	l.handlers.Add(1)
	l.mu.Unlock()
	defer l.handlers.Done()
	// Before anything else, R22's local answer included: a connection this listener cannot place inside
	// the run is served nothing, because everything below it either writes the run's ledger or spends
	// the run's capture budget on the caller's behalf (R19a).
	pid, err := l.admitPeer(r)
	if err != nil {
		l.refusePeer(w, r, err)
		return
	}
	if l.creds != nil && l.creds.refuseTunnel(l, w, r, pid) {
		return
	}
	if l.refuseRoutedTunnel(w, r, pid) {
		return
	}
	if l.serveExtraProtocol(w, r, pid) {
		return
	}
	if (l.opts.HTTPPolicy != nil || l.opts.Proxy != nil) && !l.httpDecision(w, r, pid) {
		return
	}
	switch {
	case r.Method == "PRI" && r.RequestURI == "*":
		// An h2 preface on a plaintext loopback listener: a client that ignored R19. Nothing of it
		// can be reassembled, so it is recorded as the one thing it is (R17, R37).
		l.reportGap(GapH2)
		http.Error(w, "http/2 is not spoken on this listener", http.StatusBadRequest)
	case l.opts.HTTPPolicy == nil && r.Method == http.MethodHead && strings.TrimSuffix(r.URL.Path, "/") == HelloPath:
		l.hello(w, r)
	case r.Method == http.MethodConnect:
		// A tunnel has no upstream mapping here: this listener is bound to one declared endpoint.
		l.reject(w, http.StatusBadRequest, "connect is not forwarded")
	default:
		l.forward(w, r, pid)
	}
}

// hello is R22's local answer: 200 with an empty body, no upstream contact. Any body the client sent is
// drained and discarded — the answer depends on the method and the path alone (#30). The drain is under the
// same idle and total deadlines as any other request body (R27a): a body that stops arriving ends the drain
// rather than holding the handler and its connection until the peer hangs up.
func (l *Listener) hello(w http.ResponseWriter, r *http.Request) {
	if src := l.guardedBody(w, r); src != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(src, int64(l.opts.MaxBody)))
	}
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusOK)
}

// reject answers the client and records the refusal as an event: a mapped error is never only a status
// code (R26).
func (l *Listener) reject(w http.ResponseWriter, status int, msg string) {
	l.reportGap(GapMalformed)
	http.Error(w, msg, status)
}

// logUnforwarded logs why a request forward gave up before it went upstream: the gap reject counts says only
// malformed, and the cause (a body past its deadline, an idle one, a client gone or short of its Content-Length,
// the entropy source, the outbound request) is here. The run's process chooses how often this happens, so only the
// first is logged at warn level, as refusePeer's refusals are.
func (l *Listener) logUnforwarded(msg string, r *http.Request, pid int, err error) {
	n := l.unforwarded.Add(1)
	args := []any{"run", l.runRef().ID, "host", l.model.Host, "pid", pid, "method", r.Method, "path", r.URL.Path,
		"count", n, "err", err}
	if n == 1 {
		l.opts.Logger.Warn(msg, args...)
	} else {
		l.opts.Logger.Debug(msg, args...)
	}
}

// forward is the whole proxy path: read the request, add the identity headers, record the request,
// stream the response, record the response and whatever derive read out of it. pid is the run's process that
// holds the connection, as admission resolved it: the exchange's lines carry it, and the turn is keyed by it
// and a lane (lanes; R34).
func (l *Listener) forward(w http.ResponseWriter, r *http.Request, pid int) {
	// ADR 0127: the route is chosen first.
	via := l.chooseRoute()
	var grant keyGrant
	if l.creds != nil {
		var ok bool
		if grant, ok = l.creds.check(l, w, r, pid, via); !ok {
			return
		}
	}
	if offer := r.Header.Values(headerAcceptEncoding); len(offer) > 0 {
		if _, ok := narrowAcceptEncoding(offer); !ok {
			// No body is read and no upstream request is made. Avoid net/http draining an unread body.
			closeHTTPUpload(w, r)
			l.reject(w, http.StatusNotAcceptable, "no acceptable response encoding is supported")
			return
		}
	}
	x, err := l.readRequest(w, r, pid)
	if err != nil {
		closeHTTPUpload(w, r)
		l.logUnforwarded("forwarder: the request could not be read", r, pid, err)
		l.reject(w, http.StatusBadRequest, "the request body could not be read")
		return
	}
	x.pid, x.via = pid, via
	w, finishAsk, ok := l.askExchange(w, r, pid, x)
	if !ok {
		return
	}
	defer finishAsk()
	if x.asked && l.routeMoved(via) {
		// A person moved the endpoint while this request waited for their approval: it is not sent where they stopped
		// sending its requests, nor to a route the approval did not show. A request not held goes by the route chosen
		// when it arrived, which its credential check decided for, as a request already streaming does (ADR 0127 §4).
		l.budget.give(x.held)
		x.held = 0
		if x.guard != nil {
			x.guard.retire()
		}
		closeHTTPUpload(w, r)
		l.emitRouteMoved(r, pid, via)
		http.Error(w, "Tego: this model endpoint's route changed while the request waited for approval; send it again",
			http.StatusServiceUnavailable)
		return
	}
	if l.creds != nil {
		if grant, ok = l.creds.check(l, w, r, pid, via); !ok {
			l.budget.give(x.held)
			x.held = 0
			if x.guard != nil {
				x.guard.retire()
			}
			return
		}
	}
	// From here the rest of the body is read by the upstream leg's own goroutine: a failure there is
	// recorded, and marked on the reply below, on this goroutine, before a status is written. It can
	// still be reading when this returns (the upstream answered before the body ended), and must not use
	// the connection then.
	x.guard.handOff()
	defer x.guard.retire()
	out, err := l.outbound(r, x)
	if err != nil {
		// This exchange never reaches derive, which is where what it holds of the capture budget
		// would otherwise go back.
		l.budget.give(x.held)
		x.held = 0
		x.guard.markClose(w)
		l.logUnforwarded("forwarder: the upstream request could not be prepared", r, pid, err)
		l.reject(w, http.StatusBadGateway, "the request could not be prepared")
		return
	}
	// The value goes into the outbound copy alone: r.Header, which the record, the retry key and the ask read, keeps
	// the stand-in.
	if l.creds != nil {
		out = l.creds.inject(l, out, grant, r, pid, via)
	}
	x.lane = l.lanes.acquire(x.pid, x.id, x.retryOf)
	l.track(x)
	if x.sent == nil {
		l.emitRequest(x)
	} // else the upstream leg's read of the whole body emits it, or derive does (sentCounter)

	leg := l.transport
	if via != nil {
		leg = via.leg
	}
	resp, err := leg.RoundTrip(out)
	if err != nil {
		l.opts.Logger.Warn("forwarder: upstream failed", "run", l.runRef().ID, "host", l.model.Host, "route", via.taken(), "err", err)
		x.guard.markClose(w)
		http.Error(w, "upstream unreachable", statusFor(err))
		l.markNeverSent(x, dialFailed(err))
		l.finish(x, nil)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if l.opts.HTTPPolicy != nil && resp.StatusCode == http.StatusSwitchingProtocols {
		x.guard.markClose(w)
		closeHTTPUpload(w, r)
		l.reportGap(GapMalformed)
		http.Error(w, "upstream protocol upgrade is unsupported", http.StatusBadGateway)
		l.finish(x, nil)
		return
	}
	l.stream(w, resp, x)
}

// upstreamResult is what the response pump saw.
type upstreamResult struct {
	status    int
	header    http.Header
	encoding  string
	body      []byte // what capture kept, decoded when this component can decode it (R15)
	decoded   bool
	sse       bool
	truncated bool
	// scanned and scannedModel are the usage and model an event stream reported, read off every byte relayed
	// whatever the record's copy kept (anthropic.StreamUsageScanner, R27); nil when it reported none.
	scanned      *record.Usage
	scannedModel string
	// scannedFinal is the stream's message_delta having been among the bytes relayed, so scanned's output
	// count is the message's own rather than message_start's placeholder (R27).
	scannedFinal      bool
	scannedIncomplete bool
	scannedAccounting bool
	// sizeCut is the body kept short by the capture budget or the decode limit, the gap why=size-cap; a
	// body truncated otherwise has had its gap counted where it was cut.
	sizeCut bool
	// wireSize is the body's length as the relay read it, before any content coding this component undoes:
	// every byte read of it, or its declared length when that is more (a relay the client or the upstream cut
	// short). A gzip net/http's Transport offered and undid itself, for a client that offered no coding, is
	// counted decoded, as the client receives it. A line whose body is a prefix carries it as wire_size
	// (record-ledger §2.2).
	wireSize int64
	// upstreamFailed is the upstream's body read failing after the status line was relayed: the agent's
	// connection is then aborted once the exchange is recorded, never ended cleanly (R26).
	upstreamFailed bool
	held           int // bytes of the capture budget body is holding (§3)
	ended          time.Time
	endedMono      uint64
}

// stream writes the response as it arrives and then records the exchange it ends. An upstream that failed
// once streaming had started has no status left to send, so the agent's connection is closed rather than
// ended: returning normally would have net/http write the terminating chunk, and the agent would take a
// truncated turn for a whole one (R26). The exchange is recorded first; http.ErrAbortHandler is the
// server's own way to drop the connection without logging a panic.
func (l *Listener) stream(w http.ResponseWriter, resp *http.Response, x *exchange) {
	x.guard.markClose(w)
	r := l.relay(w, resp)
	failed := r.upstreamFailed
	l.finish(x, r)
	if failed {
		panic(http.ErrAbortHandler)
	}
}

// relay writes the response as it arrives: status and headers first, then every chunk written and
// flushed before the next read. Nothing is buffered, so an event stream reaches the agent at the pace
// the model produces it (R21). A copy for the record is taken on the way past, capped, and returned
// with what it holds of the capture budget.
func (l *Listener) relay(w http.ResponseWriter, resp *http.Response) *upstreamResult {
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	flusher := http.NewResponseController(w)
	_ = flusher.Flush()

	// The record's copy is reserved from the capture budget as its array grows, so a stream holds only
	// what it has kept and a response with no end in sight cannot hold more than one body's worth (§3).
	// A declared length is reserved up front as one array of that size, the way a request's is.
	captured := l.budget.hold(l.opts.MaxBody)
	if n := resp.ContentLength; n > 0 {
		// Reserved ahead of the bytes: a short grant here loses none of them, and the writes that
		// follow ask again for what they hold.
		captured.growFor(int(min(n, int64(l.opts.MaxBody))), 0)
	}
	// The usage of an event stream is read off every byte relayed, apart from the copy and its budget
	// (R27). Only a stream this component does not have to decode is scanned: a compressed event
	// stream is not what the Messages API sends. Only the Anthropic parser's exchanges are scanned
	// (wireScanned).
	var scan *anthropic.StreamUsageScanner
	wireScanned := l.wireScanned()
	if wireScanned && isEventStream(resp.Header) && identityEncoding(resp.Header.Get("Content-Encoding")) {
		scan = &anthropic.StreamUsageScanner{WireSSE: true}
	}
	var (
		// trunc is the record's copy being a prefix of the body; cut is the budget or the decode limit
		// having made it one, which is the gap why=size-cap setPayload counts. A copy cut short by the
		// client leaving, the upstream failing or a broken decode is counted here as malformed instead.
		trunc, cut bool
		// upFailed is the upstream's read failing before its EOF (R26, stream).
		upFailed bool
		// wire counts the body's bytes read from the upstream (upstreamResult.wireSize).
		wire int64
		buf  = make([]byte, streamChunk)
		// stall gives the record's copy back when a write to the client makes no progress (R27).
		stall    = stallGuard{after: l.opts.WriteStallTimeout, captured: captured}
		released bool
	)
	defer stall.stop() // its timer, whichever way the loop ends
	for {
		n, rerr := resp.Body.Read(buf)
		wire += int64(n)
		if n > 0 {
			// The model produced bytes: the run is waiting on it, not stalled (limits R4), whatever the
			// record mode, and before the write that may block on a client not reading.
			l.activity.chunk()
			stall.arm()
			_, werr := w.Write(buf[:n])
			if werr == nil {
				_ = flusher.Flush()
			}
			if stall.disarm() {
				released = true
				// The copy was given back while the client was not reading. It ends where it was and the
				// relay carries on: kept short by the budget, in effect, so it is the same size-cap gap and
				// derive's size-cut rules decide whether the exchange is still metered.
				trunc, cut = true, true
			}
			if werr != nil {
				// The rest of the response is never read, so the record's copy is a prefix of it, and is
				// marked so: it was handed to derive and recorded as a whole body.
				l.opts.Logger.Debug("forwarder: client went away", "run", l.runRef().ID, "err", werr)
				l.note(GapMalformed, 1)
				trunc = true
				break
			}
			if scan != nil {
				_, _ = scan.Write(buf[:n])
			}
			// The first chunk kept short ends the record's copy, so the copy stays a prefix of the
			// body. Room the budget frees later must not resume it: the chunks after the cut would
			// follow the bytes before it with the gap closed up, a body the wire never carried,
			// which blob(sha) and derive would then vouch for.
			if !trunc && captured.write(buf[:n]) < n {
				trunc, cut = true, true
			}
		}
		if rerr != nil {
			if !errors.Is(rerr, io.EOF) {
				// Once streaming has started there is no late status to send: the connection is
				// simply closed, and the shortfall is recorded (R26).
				l.opts.Logger.Warn("forwarder: response ended early", "run", l.runRef().ID, "err", rerr)
				l.note(GapMalformed, 1)
				trunc, upFailed = true, true
			}
			break
		}
	}
	captured.fit()
	encoding := resp.Header.Get("Content-Encoding")
	kept, decoded, capped := captured, identityEncoding(encoding), false
	// A copy the stall guard gave back is empty, and is not decoded: a decoder handed nothing would report the
	// empty body as a broken coding.
	if open, has := decoderFor(encoding); has && !released {
		// Only a coding this component undoes makes a second buffer, and that buffer is what the
		// record keeps from here on: the compressed bytes it replaced go back once it is complete.
		//
		// The decoded form is reserved as a buffer of its own, never out of the compressed bytes'
		// reservation: decodeWith reads from those bytes until its output is complete, so both arrays
		// are live for the whole decode, and the budget is over every array capture holds (§3).
		// Lending the one reservation to both would leave the decoded array uncounted while it is
		// read, up to one body per compressed response in flight, and that uncounted memory is the
		// OOM the budget exists to prevent. So at a full budget the decoded buffer cannot grow at all
		// and the record keeps none of the decoded body, marked truncated and counted as gap
		// why=size-cap: exhaustion keeps less of a body, and here less is nothing. The decoder's own
		// state is not counted: a 32 KiB flate window and its tables, about 42 KB per gzip or deflate
		// layer whatever the budget grants. That is per-exchange overhead like the pump's streamChunk
		// buffer above, and it does not grow with the body. A br or zstd layer holds up to the window
		// its stream declares instead (16 MiB, or the 8 MiB httpstream caps zstd at), which is why
		// outbound never offers those codings: only an upstream that answers in a coding the request
		// did not offer gets one decoded here (narrowAcceptEncoding, §3). Every layer of a stacked
		// coding is open for the whole decode, and decoderFor refuses a list of more than
		// httpstream.MaxCodings, so one exchange's decoder state is at most that many windows.
		out, ok, limited, broken := decodeWith(l.budget, captured.bytes(), l.opts.MaxBody, open)
		if out != nil {
			captured.drop()
			kept = out
		}
		decoded, capped = ok, limited
		switch {
		case broken && trunc:
			// The compressed copy was already a prefix — cut by the budget or the decode limit (the size-cap
			// gap setPayload counts), or by the client leaving or the upstream failing (the malformed gap
			// counted where it was cut) — so a stream that ends mid-codeword is that cut, not a second fault:
			// the decoded prefix is kept, truncated, and the shortfall stays one gap (R15).
			l.opts.Logger.Debug("forwarder: a cut response copy decoded to a prefix", "run", l.runRef().ID,
				"encoding", encoding)
		case broken:
			// The decoded prefix is recorded, truncated, and the decode error is a gap why=malformed.
			l.opts.Logger.Warn("forwarder: response body did not decode", "run", l.runRef().ID, "encoding", encoding)
			l.note(GapMalformed, 1)
			trunc = true
		}
	}
	// A complete decoded compressed stream gets the same accounting validation as the wire stream.
	if wireScanned && scan == nil && decoded && !trunc && !capped && isEventStream(resp.Header) {
		scan = &anthropic.StreamUsageScanner{WireSSE: true}
		_, _ = scan.Write(kept.bytes())
	}
	scanned, scannedModel, scannedFinal := scan.Result()
	return &upstreamResult{
		scanned:           scanned,
		scannedModel:      scannedModel,
		scannedFinal:      scannedFinal,
		scannedIncomplete: scan.Incomplete(),
		scannedAccounting: scan != nil,
		status:            resp.StatusCode,
		header:            resp.Header,
		encoding:          encoding,
		body:              kept.bytes(),
		decoded:           decoded,
		sse:               isEventStream(resp.Header),
		truncated:         trunc || capped,
		sizeCut:           cut || capped,
		wireSize:          max(wire, resp.ContentLength),
		upstreamFailed:    upFailed,
		held:              kept.reserved(),
		ended:             l.opts.Clock.Now(),
		endedMono:         l.opts.Clock.Mono(),
	}
}

// finish records the end of an exchange: the ssl_response and whatever derive read, or — when no
// response ever arrived — the one gap that says so (§7). An exchange Close already claimed is left
// alone, so a run that ends while a response is arriving records it once, not twice.
func (l *Listener) finish(x *exchange, r *upstreamResult) {
	if !l.claim(x) {
		// Close recorded this exchange and returned what the request held; the response buffer this
		// caller built after that is its own to return, or the race leaks the budget for the rest
		// of the run (§3).
		if r != nil {
			l.budget.give(r.held)
		}
		return
	}
	l.derive(x, r)
}

// derive runs the provider dispatch and emits what it produced. With no Deriver the exchange is still
// recorded; with one, the ssl_response carries the model, the usage and the parser version, and the
// decisions follow it in wire order.
func (l *Listener) derive(x *exchange, r *upstreamResult) {
	// A tracked exchange reaches here exactly once, because finish's claim() and Close's taking of the
	// in-flight set make sure only one of them derives it, and this is where its request and response
	// buffers go back. Not every reservation reaches here: forward gives back the request of an exchange
	// whose outbound leg failed, which was never tracked, and finish gives back a response it built after
	// Close had already derived the exchange without one. Each is returned where it is dropped, and
	// budget.give lists every caller. The buffers do not outlive this call; the events' copies of their
	// bodies do, which is why each copy has a reservation of its own that outlasts this one (§3).
	defer func() {
		l.budget.give(x.held)
		if r != nil {
			l.budget.give(r.held)
		}
		// The turn is recorded, so its lane is free for the process's next one (lanes).
		l.lanes.release(x.pid, x.lane)
	}()
	// The request line comes before anything of its response. It is already written unless its length is
	// being counted (sentCounter) and the upstream leg has not finished reading it: then it is written now,
	// with what was sent so far.
	l.emitRequest(x)
	var (
		facts  derive.Facts
		events []*record.Event
		// placeholder is facts.Usage's output being message_start's placeholder, from the wire scanner.
		placeholder bool
	)
	if l.opts.Deriver != nil {
		res, err := l.opts.Deriver.Handle(x.requestMessage(), r.message(), l.meta(x, r))
		if err != nil {
			l.opts.Logger.Error("forwarder: derive refused the exchange", "run", l.runRef().ID, "err", err)
		} else {
			facts, events = res.Facts, res.Events
		}
		if r != nil && r.scanned != nil && (facts.Usage == nil || r.truncated ||
			(r.scannedFinal && (facts.Usage.OutputBound || facts.Unmetered))) {
			// The stream's own report of its usage, read off every byte relayed, is what counts when the
			// record's copy was cut short or could not be read (R27): the usage is known, so the
			// exchange is metered whatever the unparsed decision beside it says of the body. It is known only
			// if the stream's message_delta was among those bytes, or derive already charged the output's
			// bound: a stream the wire itself ended after message_start reported a placeholder output, and
			// derive's verdict on it (a bound, or unmetered with no max_tokens to bound it by) stands.
			// A whole copy can still leave derive short of the message_delta the wire carried —
			// derive stops reading a stream at its first line it cannot parse, the scanner reads every
			// message_delta line — and the count seen on the wire then replaces derive's bound, or its
			// verdict of no bound, as it does for a cut copy (limits-check-doctor-cli.md R1 (m)).
			// derive's own count is the message's when it read the final message_delta: a usage it neither
			// bounded nor left unmetered.
			derivedFinal := facts.Usage != nil && !facts.Usage.OutputBound && !facts.Unmetered
			facts.Usage = mergeUsage(facts.Usage, r.scanned, r.scannedFinal)
			if facts.Model == "" {
				facts.Model = r.scannedModel
			}
			switch {
			case r.scannedFinal || facts.Usage.OutputBound:
				facts.Unmetered = false
			case !derivedFinal:
				// Neither reading saw the message's output count: the scanner's is message_start's
				// placeholder, never a count to charge. It takes the max_tokens bound below, or the exchange
				// is unmetered (limits-check-doctor-cli.md R1 (m), (c)).
				placeholder = true
			}
		}
		if r != nil {
			// derive could not bound a cut stream for want of the request's max_tokens: read it off the bytes
			// the upstream leg took, or off the kept body when that is whole but did not parse (ADR 0036 (1)).
			mt, ok := x.maxTokens.result()
			if x.maxTokens == nil && !x.truncated && (facts.Unmetered || placeholder) {
				mt, ok = anthropic.RequestMaxTokens(x.body)
			}
			anthropic.BoundCutStream(&facts, mt, ok, r.status)
			if placeholder && !facts.Usage.OutputBound && derive.Success(r.status) {
				facts.Usage, facts.Unmetered = boundPlaceholder(facts.Usage, mt, ok)
			}
		}
		if r != nil && r.scannedAccounting {
			// The wire scanner sees past capture caps. Its incomplete verdict is applied after every
			// output bound: max_tokens cannot recover missing input or cache accounting.
			facts.IncompleteUsage = r.scannedIncomplete
			if r.scannedIncomplete && derive.Success(r.status) && !l.silent(x) {
				facts.Unmetered = true
				l.note(GapMalformed, 1)
			}
		}

		if r != nil && r.sizeCut && r.scanned == nil && derive.Success(r.status) && !l.silent(x) {
			// A successful answer whose record copy the capture budget or the decode limit cut, with no usage
			// read off the wire beside it: what the body said past the cut, a stream's closing usage above
			// all, is in nothing derive read. The scanner reads only an identity-coded stream, so a gzip or
			// deflate stream cut after message_start reached here with message_start's usage alone and passed
			// as metered (R27). A path the deriver calls silent spends nothing whatever its answer, so a cut
			// there is not reported. This is the uprobe path's SizeCut rule (docs/p0/limits-check-doctor-cli.md R1 (d)).
			facts.Unmetered = true
		}
	}
	if r != nil {
		l.emit(l.responseEvent(x, r, facts))
	} else if l.opts.Deriver == nil {
		// Without a Deriver nobody else will say that this request was never answered.
		events = append(events, l.gapEvent(GapMalformed, l.opts.Clock.Now(), l.opts.Clock.Mono()))
	}
	// A gap among these is written here, as it happens, and so is not counted for the run's gap report
	// too: that report is written at run_end as gap lines of its own (runtime's emitSourceGaps), and a gap
	// in both was two lines for one shortfall.
	for _, ev := range events {
		l.emit(ev)
	}
	if r == nil {
		// Whatever the verdict on spend, and on a silent path too, no ssl_response will end this request's
		// step: the step tracker stops counting its thread in flight, as the uprobe path tells it for a
		// request it gives up on (capture-derive.md R33).
		l.reportAbandoned(x.pair)
	}
	switch {
	case facts.Unmetered:
		// A model call whose spend nothing could read: a run with a token or cost budget ends here
		// (docs/p0/limits-check-doctor-cli.md R1).
		l.reportUnmetered(derive.Route(x.method, x.path) + ": usage unreadable")
	case r == nil && !x.neverSent && !l.silent(x):
		// A request to the model host that got no byte of an answer: the upstream failed or went away, the
		// client left, or the run ended first. The upstream may have read the prompt and spent on it all
		// the same, and nothing will say how much, so it is reported unmetered as the uprobe path reports a
		// request its connection ended without answering (ADR 0037). Exempt are a leg that never connected,
		// of which no byte left, and a path the deriver calls silent (a health check, telemetry, token
		// counting), which spends nothing whatever its answer (ADR 0037 amendment 2026-09-24).
		l.reportUnmetered(derive.Route(x.method, x.path) + ": no response")
	}
}

// silent reports that the Deriver calls x's path one that spends nothing (derive.SilentPaths). A Deriver that
// cannot say leaves every unanswered request reported.
func (l *Listener) silent(x *exchange) bool {
	d, ok := l.opts.Deriver.(interface {
		Silent(provider, host, method, target string) bool
	})
	return ok && d.Silent(l.model.Provider, l.model.Host, x.method, x.path)
}

// meta is the exchange context derive needs: the run, the process and lane of the turn (R34), the
// declared provider and host that choose the parser (R25), and the timestamps of the response — or of now,
// when no response ever arrived. The step is left at zero: derive's own step tracker numbers the turn from
// the event stream (E28a).
func (l *Listener) meta(x *exchange, r *upstreamResult) derive.Meta {
	ts, mono := l.opts.Clock.Now(), l.opts.Clock.Mono()
	if r != nil {
		ts, mono = r.ended, r.endedMono
	}
	run := l.runRef()
	return derive.Meta{
		Run: run.ID, Agent: run.Agent, Cgroup: run.CgroupID, PID: x.pid, Lane: x.lane,
		Source: record.SourceForwarder, TS: ts, MonoNS: mono,
		Provider: l.model.Provider, Host: l.model.Host, Binary: l.model.Host,
	}
}

// message is the response in the form derive reads; nil stays nil (a request that was never answered).
func (r *upstreamResult) message() *derive.Message {
	if r == nil {
		return nil
	}
	return &derive.Message{
		Status:          r.status,
		Header:          r.header,
		Body:            r.body,
		ContentEncoding: r.encoding,
		SSE:             r.sse,
		WireSSE:         r.sse,
		Truncated:       r.truncated,
		Decoded:         r.decoded,
	}
}

// retryOf names the request this attempt repeats, or "" for a first attempt (R23).
//
// The hash match is the primary signal: a client retry replays the same method, path, body and
// credential. The SDK's own counter is the secondary one, and when it says "retry" but no key matches —
// a client that changed the body between attempts — the most recent request of this process on this
// listener is named, which is what an SDK retry actually repeats. Both look only among pid's requests: a
// retry is a repeat by the same caller, and another process of the run on the same credential is not it.
// A count of 0, a negative or a non-numeric value is a first attempt, never tagged (#29).
func (l *Listener) retryOf(pid int, key RetryKey, h http.Header, mono uint64) string {
	if id, ok := l.retries.lookup(pid, key, mono); ok {
		return id
	}
	return l.retryByCount(pid, h, mono)
}

// retryByCount is the secondary signal on its own, for a request whose key cannot answer: the SDK says
// this attempt is a retry, so what it repeats is pid's most recent request on this listener. A count of 0, a
// negative or a non-numeric value is a first attempt, never tagged (#29).
func (l *Listener) retryByCount(pid int, h http.Header, mono uint64) string {
	if n, ok := RetryCount(h); ok && n > 0 {
		if id, ok := l.retries.recent(pid, mono); ok {
			return id
		}
	}
	return ""
}

// statusFor maps an upstream failure onto the status the agent sees (R26). A dial or TLS failure is a
// 502; a timeout before any byte of the response existed is a 504. Once streaming has started there is
// no status left to send, which stream handles by closing.
func statusFor(err error) int {
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return http.StatusGatewayTimeout
	}
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

// dialFailed reports an upstream leg that never connected: net/http's Transport returns its dialer's error as a
// *net.OpError whose Op is "dial", and on that path no byte of the request has been written. Any other failure,
// a TLS handshake's included, is not told apart, and is treated as a request the upstream may have read.
func dialFailed(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial"
}

// readBody reads a body into a held buffer, up to its limit and as far as the budget lets it grow, then
// trims the array to what was read. It reports how much it kept and hands back the remainder unread when
// the body is larger than that: capture is bounded, forwarding is not.
func readBody(r io.Reader, into *held, chunk int) (size int64, truncated bool, rest io.Reader, err error) {
	if r == nil {
		return 0, false, nil, nil
	}
	extra, err := into.fill(r, chunk)
	if err != nil {
		return int64(len(into.bytes())), false, nil, fmt.Errorf("forwarder: read request body: %w", err)
	}
	into.fit()
	body := into.bytes()
	if extra == nil {
		return int64(len(body)), false, nil, nil
	}
	// The byte read past the cap to detect the overflow belongs to the forwarded stream.
	return int64(len(body)), true, io.MultiReader(bytes.NewReader(extra), r), nil
}

// newExchangeID is the id an ssl_request carries and a retry names: run-scoped, unguessable and short.
func newExchangeID(rnd io.Reader) (string, error) {
	var b [8]byte
	if _, err := io.ReadFull(rnd, b[:]); err != nil {
		return "", fmt.Errorf("forwarder: exchange id: %w", err)
	}
	return "fx-" + hex.EncodeToString(b[:]), nil
}

// isEventStream reports whether the response is server-sent events.
func isEventStream(h http.Header) bool {
	return strings.HasPrefix(strings.ToLower(h.Get("Content-Type")), "text/event-stream")
}

// emitRequest writes an exchange's ssl_request line once, whichever of forward, the upstream leg's read of
// a counted body, and derive comes first.
func (l *Listener) emitRequest(x *exchange) {
	x.requestOnce.Do(func() { l.emit(l.requestEvent(x)) })
}

// sentCounter counts a request body of undeclared length as the upstream leg reads it, and writes the
// exchange's ssl_request once the leg has read it all or closed it. Such a body larger than MaxBody was
// recorded with the size capture kept rather than what the client sent: the line is written
// before the round trip for every other request, when the length is the declared one, but a chunked body's
// length exists only once its last byte has gone. net/http's Transport closes a request body when it is done
// with it, which is the end here when the upstream answered before reading the whole body.
type sentCounter struct {
	r    io.Reader
	n    atomic.Int64
	done func()
}

// Read counts what the upstream leg reads.
func (c *sentCounter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	if err == io.EOF {
		c.done()
	}
	return n, err
}

// Close is the Transport done with the body.
func (c *sentCounter) Close() error {
	c.done()
	return nil
}

// track keeps the set of requests whose response has not arrived, so Close can turn each one into the
// gap that explains it (#28).
func (l *Listener) track(x *exchange) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.inflight[x.id] = x
}

// markNeverSent sets x.neverSent while x is still in flight, under the lock Close takes the in-flight set
// with: once Close has taken x it may be deriving it, reading the field, and x is no longer this caller's to
// write (a handler that outlasted closeDrain). Close's derive then counts the exchange as sent, which fails
// closed.
func (l *Listener) markNeverSent(x *exchange, v bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.inflight[x.id]; ok {
		x.neverSent = v
	}
}

// claim takes one exchange out of that set, reporting whether this caller is the one that got it.
func (l *Listener) claim(x *exchange) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.inflight[x.id]; !ok {
		return false
	}
	delete(l.inflight, x.id)
	return true
}

// note counts one gap for the run's gap report, which the run writes at run_end (Gaps). A gap written as
// its own line as it happens (reportGap, derive's events) is not noted as well.
func (l *Listener) note(why string, n int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gaps[why] += n
}

// reportGap emits a gap: the two shortfalls the handler itself sees (an h2 preface, a request it will not
// forward) are events, not only statuses (R26). It is written once, as it happens, and not also counted for
// the run's gap report, which would write it again at run_end.
func (l *Listener) reportGap(why string) {
	l.emit(l.gapEvent(why, l.opts.Clock.Now(), l.opts.Clock.Mono()))
}

// emit queues one event for the sink and returns at once: the run's capture lane waits for room while the
// ledger is behind, and no handler may wait with it (I1). The queue drops and counts past its bound (emitQueue).
func (l *Listener) emit(ev *record.Event) {
	sink := l.sinkRef()
	if sink == nil || ev == nil {
		return
	}
	l.emitq.put(emitItem{sink: sink, ev: ev})
}

// emitOpen emits ev unless the listener is closing, and reports whether it did. It counts itself in as a handler does
// (ServeHTTP), so a line another listener's goroutine writes through this one is queued before Close's final flush, or
// not at all: never behind the run's drain (R8 of docs/p0/runtime-launch.md, I4).
func (l *Listener) emitOpen(ev *record.Event) bool {
	l.mu.Lock()
	if l.closed || l.sink == nil {
		l.mu.Unlock()
		return false
	}
	l.handlers.Add(1)
	l.mu.Unlock()
	defer l.handlers.Done()
	l.emit(ev)
	return true
}

// reportUnmetered queues a report of one exchange whose spend no budget can count (source.ReportUnmetered),
// behind the lines of that exchange.
func (l *Listener) reportUnmetered(why string) {
	sink := l.sinkRef()
	if sink == nil {
		return
	}
	l.emitq.put(emitItem{sink: sink, unmetered: why})
}

// emitsLost is the listener's first dropped event: whatever it was, it may have been the line that carried an
// exchange's spend, so the run is told its spend is no longer counted (limits-check-doctor-cli.md R1 (s)).
func (l *Listener) emitsLost(sink source.Sink) {
	l.opts.Logger.Warn("forwarder: emit queue full; dropping capture events",
		"run", l.runRef().ID, "host", l.model.Host, "size", emitQueueSize)
	source.ReportUnmetered(sink, 1, l.model.Host+" emit queue full: a capture event was dropped, "+
		"so a model exchange's spend may be uncounted")
}

// reportAbandoned queues word for the sink that pair's response will never come (source.ReportAbandoned).
func (l *Listener) reportAbandoned(pair uint64) {
	sink := l.sinkRef()
	if sink == nil || pair == 0 {
		return
	}
	l.emitq.put(emitItem{sink: sink, abandon: pair})
}

// sinkRef is the sink Bind attached; nil until then.
func (l *Listener) sinkRef() source.Sink {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sink
}

// runRef is the run this listener serves; the zero value until Bind.
func (l *Listener) runRef() source.RunRef {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.run
}
