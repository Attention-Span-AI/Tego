// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/policy/httppolicy"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Name is the source name a Manager reports to the run facade.
const Name = "forwarder"

// Manager owns one Listener per declared models[] entry and is the run's forwarder capture source. It
// binds every socket at construction, so the run's environment can name the base URLs before the agent
// execs, and closes them all when the run ends (§3 "dies with the run, correctly").
type Manager struct {
	listeners []*Listener
	// routes is the run's model routes (ADR 0127), nil when no models[] entry declares one.
	routes *router

	mu      sync.Mutex
	started bool
	closed  bool
	done    chan struct{}
	errs    []error
	// stopped are the upstream hosts of listeners whose Serve failed while the run went on (Gaps).
	stopped []string
}

// NewManager builds a listener per models[] entry. Two entries naming the same upstream get two
// listeners, each with its own base URL, because a harness variable points at exactly one. For the same
// reason two entries of one provider cannot both be reached through the variables: Vars points them at
// the entry declared first, and the later entry's listener, still bound and admitted, is logged here as
// one no variable names.
func NewManager(models []agent.ModelEndpoint, opts Options) (*Manager, error) {
	if opts.Proxy != nil {
		seen := map[string]bool{}
		for _, model := range models {
			port := model.Port
			if port == 0 {
				port = 443
			}
			authority := httppolicy.Authority(agent.CanonicalHost(model.Host), port)
			if seen[authority] || !opts.Proxy.Covers(authority) {
				return nil, fmt.Errorf("%w: ambiguous or uncovered proxy listener", ErrListener)
			}
			seen[authority] = true
		}
		if len(seen) != len(opts.Proxy.Authorities()) {
			return nil, fmt.Errorf("%w: missing declared proxy listener", ErrListener)
		}
	}
	if opts.HTTPPolicy != nil {
		seen := make(map[string]bool, len(models))
		for _, model := range models {
			port := model.Port
			if port == 0 {
				port = 443
			}
			authority := httppolicy.Authority(agent.CanonicalHost(model.Host), port)
			if seen[authority] || !opts.HTTPPolicy.Covers(authority) {
				return nil, fmt.Errorf("%w: ambiguous or uncovered HTTP listener", ErrListener)
			}
			seen[authority] = true
		}
		if len(seen) != len(opts.HTTPPolicy.Authorities()) {
			return nil, fmt.Errorf("%w: missing declared HTTP policy listener", ErrListener)
		}
	}
	m := &Manager{done: make(chan struct{})}
	// One capture budget across the run's listeners rather than one each: what §3 bounds is the
	// launcher's own heap, and a per-listener bound would multiply it by however many models[] entries
	// the contract happened to declare. Assigned before Start, so no listener is serving yet.
	shared := newBudget(opts.MaxCaptureBytes, maxBodyOf(opts))
	// One set of lanes for the same reason: a process's turns to two providers at once are two turns in
	// flight, and derive must see two threads (R34).
	sharedLanes := newLanes()
	// One activity meter as well: the stall check needs one report per grain for the run, not one per listener.
	sharedActivity := newActivityMeter(opts.Activity, opts.Clock)
	if opts.resolveSem == nil {
		opts.resolveSem = make(chan struct{}, 8)
	}
	if opts.Proxy != nil && opts.tunnelSem == nil {
		opts.tunnelSem = make(chan struct{}, int(opts.Proxy.Bounds().MaxStreams))
	}
	// One exact peer lookup for the run: a kernel without TCP sock_diag is found, and logged, once.
	if opts.tcpDiag == nil {
		opts.tcpDiag = newTCPDiag(opts.Logger)
	}
	// One set of stand-ins for the run: the variable the agent holds names one stand-in, whichever listener it is sent to.
	var creds keyInjector
	if opts.Credentials != nil {
		var err error
		if creds, err = opts.Credentials.start(randOf(opts)); err != nil {
			return nil, err
		}
	}
	// One router for the run: a person's route change names an endpoint, whichever listener its requests arrive on.
	routes := newRouter(models, opts.Logger)
	m.routes = routes
	pinned := pinnedListen(opts.Listen)
	for i, model := range models {
		o := opts
		if i > 0 && pinned {
			// A pinned forwarder.listen names one socket, and only one listener can hold it. The first
			// entry takes it; each later entry binds an ephemeral port on the same loopback host, which
			// its base-URL variables name as they would any other, so a second model keeps its capture
			// and its route rather than costing the run every listener (R19).
			host, _, _ := net.SplitHostPort(opts.Listen)
			o.Listen = net.JoinHostPort(host, "0")
		}
		l, err := NewListener(model, o)
		if err != nil {
			_ = m.closeAll()
			return nil, err
		}
		l.budget = shared
		l.lanes = sharedLanes
		l.activity = sharedActivity
		if creds != nil {
			l.creds = creds
		}
		l.routes = routes
		if opts.HTTPPolicy != nil || opts.Proxy != nil {
			l.acceptReady = make(chan error, 1)
		}
		m.listeners = append(m.listeners, l)
	}
	if pinned && len(m.listeners) > 1 {
		m.listeners[0].opts.Logger.Warn("forwarder: forwarder.listen pins one port and models[] declares "+
			"more than one entry; the first entry's listener holds the pinned port and the rest bind ephemeral ones",
			"listen", opts.Listen, "entries", len(m.listeners))
	}
	for _, l := range m.shadowed() {
		l.opts.Logger.Warn("forwarder: models[] declares this provider more than once; its base-URL "+
			"variables name the first entry's listener, and nothing the run installs points at this one",
			"provider", l.Model().Provider, "host", l.Model().Host, "listener", l.BaseURL())
	}
	return m, nil
}

// Listeners are the bound listeners, in the order the contract declared them.
func (m *Manager) Listeners() []*Listener { return m.listeners }

// Name is the source name (source.Source).
func (m *Manager) Name() string { return Name }

// ConfigureAsk binds one approval and replay coordinator before any listener
// serves the run. Reconfiguration would discard pending identities and is refused.
func (m *Manager) ConfigureAsk(rt *agent.RuleTable, request func(context.Context, ask.Request) (ask.Decision, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started || m.closed || len(m.listeners) == 0 {
		return ask.ErrUnavailable
	}
	for _, l := range m.listeners {
		if l.opts.askRequests != nil {
			return ask.ErrUnavailable
		}
	}
	coordinator, err := newRequestAsks(rt, request)
	if err != nil {
		return err
	}
	for _, l := range m.listeners {
		l.opts.askRequests = coordinator
	}
	return nil
}

// SetStreamActivity tells the run's stall check of every chunk a response relay or a tunnel carries, at most once
// per activityGrain, with the listeners' monotonic reading (runtime.StreamActivityReporter, limits R4). It must be
// called before Start, which the runtime does when the run has a stall budget; once the manager has started or
// closed it does nothing, so a handler never reads a meter being replaced.
func (m *Manager) SetStreamActivity(fn func(monoNS uint64)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started || m.closed || len(m.listeners) == 0 {
		return
	}
	meter := newActivityMeter(fn, m.listeners[0].opts.Clock)
	for _, l := range m.listeners {
		l.activity = meter
	}
}

// Start binds the run and serves every listener, returning as soon as the goroutines are running
// (source.Source). Each stops on ctx cancellation or Stop, whichever comes first.
func (m *Manager) Start(ctx context.Context, run source.RunRef, sink source.Sink) error {
	if sink == nil {
		return fmt.Errorf("%w: nil sink for run %s", ErrListener, run.ID)
	}
	if run.Contract != nil {
		for _, l := range m.listeners {
			if err := l.opts.Proxy.ValidateLimits(run.Contract.Limits); err != nil {
				return fmt.Errorf("%w: %w", ErrListener, err)
			}
		}
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return fmt.Errorf("%w: run %s", ErrStopped, run.ID)
	}
	if m.started {
		m.mu.Unlock()
		return fmt.Errorf("%w: run %s", ErrAlreadyStarted, run.ID)
	}
	m.started = true
	m.mu.Unlock()

	var wg sync.WaitGroup
	for _, l := range m.listeners {
		l.Bind(run, sink)
	}
	if m.routes != nil && len(m.listeners) > 0 {
		// Before any listener serves: the first request reads the routes the run starts with.
		m.routes.bind(run.Dir, run.ID, m.listeners...)
		m.routes.start()
	}
	for _, l := range m.listeners {
		wg.Add(1)
		go func(l *Listener) {
			defer wg.Done()
			if err := l.Serve(ctx); err != nil {
				// The listener is closed and its model endpoint refuses the agent from here on. That is
				// said now, in the log, and in the record as a gap naming the upstream (R37), not held
				// back as an error only Stop returns, which the run writes to its log and no further.
				l.opts.Logger.Error("forwarder: listener stopped serving; the agent's calls to this model "+
					"endpoint are refused for the rest of the run", "run", run.ID, "host", l.Model().Host,
					"listener", l.BaseURL(), "err", err)
				m.mu.Lock()
				m.errs = append(m.errs, fmt.Errorf("forwarder: %s: %w", l.Model().Host, err))
				m.stopped = append(m.stopped, l.Model().Host)
				m.mu.Unlock()
			}
		}(l)
	}
	go func() {
		wg.Wait()
		close(m.done)
	}()
	if len(m.listeners) > 0 && (m.listeners[0].opts.HTTPPolicy != nil || m.listeners[0].opts.Proxy != nil) {
		for _, l := range m.listeners {
			// Binding alone is insufficient: prove Accept works before the agent is
			// released. This private connection sends no request and no policy event.
			c, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
			if err == nil {
				_ = c.Close()
			}
			if err == nil {
				select {
				case err = <-l.acceptReady:
				case <-ctx.Done():
					err = ctx.Err()
				case <-time.After(time.Second):
					err = fmt.Errorf("HTTP listener did not accept startup probe")
				}
			}
			if err != nil {
				if m.routes != nil {
					m.routes.stopAndWait()
				}
				_ = m.closeAll()
				return fmt.Errorf("%w: HTTP policy listener startup: %w", ErrListener, err)
			}
		}
	}
	return nil
}

// HTTPPolicyReady attests that every listener has the exact immutable policy
// requested by the run and has actually accepted, rather than merely bound.
func (m *Manager) HTTPPolicyReady(p *httppolicy.Policy) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p == nil || !m.started || m.closed || len(m.listeners) == 0 || len(m.errs) != 0 {
		return false
	}
	for _, l := range m.listeners {
		if l.opts.HTTPPolicy != p || !l.serving.Load() {
			return false
		}
	}
	return true
}

// ProxyPolicyReady proves the exact compiled protocol policy is actively served.
func (m *Manager) ProxyPolicyReady(p *agent.CompiledProxyPolicy) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p == nil || !m.started || m.closed || len(m.listeners) == 0 || len(m.errs) != 0 {
		return false
	}
	for _, l := range m.listeners {
		if l.opts.Proxy != p || !l.serving.Load() {
			return false
		}
	}
	return true
}

// Stop closes every listener and waits for the serving goroutines. A request still in flight becomes
// one gap rather than a silent half-exchange (#28). It is safe to call without Start.
func (m *Manager) Stop() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	if m.routes != nil {
		// Before the listeners close: a route change the poll reads queues its line ahead of their final flush.
		m.routes.stopAndWait()
	}
	err := m.closeAll()
	m.mu.Lock()
	started := m.started
	m.mu.Unlock()
	if started {
		<-m.done
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil && len(m.errs) > 0 {
		err = m.errs[0]
	}
	return err
}

// Gaps reports every listener's shortfalls for the run's gap report (source.Source), and one
// mechanism-unavailable gap naming the upstream host of each listener that stopped serving mid-run (R37).
func (m *Manager) Gaps() []source.Gap {
	var out []source.Gap
	for _, l := range m.listeners {
		out = append(out, l.Gaps()...)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, host := range m.stopped {
		out = append(out, source.Gap{What: record.GapCapture, Why: derive.GapMechanismUnavailable, Binary: host})
	}
	return out
}

// closeAll closes every listener, keeping the first error.
func (m *Manager) closeAll() error {
	var first error
	for _, l := range m.listeners {
		if err := l.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Vars are the base-URL variables the run installs for its harnesses, keyed by variable name
// (spec/identity/RUN-IDENTITY.md; identity.Env.ForwarderVars takes exactly this map). A provider with
// no known variable contributes none: the harness then reaches its upstream directly and net.allow
// refuses it, which is visible rather than silent (ARCHITECTURE §12, R38).
//
// A variable holds one URL, so a provider declared twice gets the first declared entry's: the contract's
// order decides, and every call of Vars answers the same. Letting the later entry overwrite the earlier
// one made the answer depend on how many entries followed, with nothing to say one had been dropped.
func (m *Manager) Vars() map[string]string {
	out := make(map[string]string, len(m.listeners))
	for _, l := range m.listeners {
		for _, name := range ProviderVars(l.Model().Provider) {
			if _, taken := out[name]; !taken {
				out[name] = l.BaseURL() + providerPrefix(l.Model().Provider)
			}
		}
	}
	if len(m.listeners) > 0 && m.listeners[0].creds != nil {
		for k, v := range m.listeners[0].creds.vars(m.listeners) {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// randOf is the Options' entropy source, crypto/rand when it names none.
func randOf(opts Options) io.Reader {
	if opts.Rand != nil {
		return opts.Rand
	}
	return rand.Reader
}

// shadowed are the listeners every one of whose variables an earlier models[] entry already claimed, so
// that Vars names none of them. It asks about variables rather than provider names because two spellings
// of one provider ("google", "gemini") share theirs.
func (m *Manager) shadowed() []*Listener {
	claimed := make(map[string]bool)
	var out []*Listener
	for _, l := range m.listeners {
		names := ProviderVars(l.Model().Provider)
		free := false
		for _, name := range names {
			free = free || !claimed[name]
			claimed[name] = true
		}
		if len(names) > 0 && !free {
			out = append(out, l)
		}
	}
	return out
}

// Endpoints are the bound loopback addresses, in the order the contract declared the models. The run
// admits exactly these through the enforcement tier before the agent execs: the supervisor refuses every
// destination no net entry names, and Landlock's ABI-4 port rules are built from the same table, so a
// forwarder nobody admitted is a forwarder the agent cannot reach (R38, ARCHITECTURE §12).
//
// It is the counterpart of Vars(): the run asks this source for its own ports rather than being handed a
// copy of them, because an ephemeral port copied twice is exactly the pair that drifts apart.
func (m *Manager) Endpoints() []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(m.listeners))
	for _, l := range m.listeners {
		if ap, ok := l.AddrPort(); ok {
			out = append(out, ap)
		}
	}
	return out
}

// ProviderVars are the environment variables that point one provider's harnesses at a forwarder.
//
// Codex is the gap: RUN-IDENTITY.md routes it through a generated config.toml under CODEX_HOME rather
// than a variable, and codex-cli 0.155.1 does ignore OPENAI_BASE_URL. identity.CodexConfig renders that
// file from the OPENAI_BASE_URL value Vars carries; writing it under the run's runtime directory, pointing
// CODEX_HOME at it and granting Codex write access there belong to the launcher and the enforcement tier
// (docs/p0/capture-derive.md R19b), so this table names only what a variable can carry. The table is
// identity's (ProviderBaseURLVars), the one Compile's env-runtime-reserved warning reads too.
func ProviderVars(provider string) []string { return identity.ProviderBaseURLVars(provider) }

// providerPrefix is the path a provider's SDKs expect on the end of the base URL their variable holds.
// The OpenAI SDKs, and Codex's openai_base_url, take the API root including its version ("the default
// is https://api.openai.com/v1") and append /chat/completions or /responses to it; the listener forwards
// the path it receives unchanged, so a variable without /v1 sent every call to a path the upstream does
// not serve. Anthropic's and Gemini's SDKs append their own versioned paths to a bare origin.
func providerPrefix(provider string) string {
	if strings.EqualFold(strings.TrimSpace(provider), "openai") {
		return "/v1"
	}
	return ""
}

// ensure the Manager is a run source, and the loopback source the run installs into the agent's
// environment and admits through the enforcement tier, at compile time.
var (
	_ source.Source         = (*Manager)(nil)
	_ source.LoopbackSource = (*Manager)(nil)
)

// pinnedListen reports whether a forwarder.listen address names a fixed port, one only a single listener
// can bind. "" and port 0 are ephemeral; an address that does not parse is left for NewListener to refuse.
func pinnedListen(addr string) bool {
	if addr == "" {
		return false
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n != 0
}
