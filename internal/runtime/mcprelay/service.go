// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/mcptools"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/policy/mcptool"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Name is the source's name.
const Name = "mcp-relay"

// DefaultPoll is how often the service reads the run's live switches (ADR 0126 §4: every 500 ms and on every
// tools/call).
const DefaultPoll = 500 * time.Millisecond

// The transports a relayed server speaks (record.MCPPayload.Transport).
const (
	TransportStdio = "stdio"
	TransportHTTP  = "http"
)

// Server is one relayed mcp[] entry: the contract's name, its declared command (stdio) or URL (http), and its tools
// lists.
type Server struct {
	Name    string
	Command []string
	URL     string
	Rules   mcptool.Rules
}

// AskFunc asks a person on the run's broker (runtime.askRequest).
type AskFunc func(context.Context, ask.Request) (ask.Decision, error)

// Options configure a Service.
type Options struct {
	// Servers are the relayed servers; New refuses none.
	Servers []Server
	// Exe is the tego executable the client config names for the shim; "" is os.Executable.
	Exe string
	// Logger receives the service's own notes; nil discards them.
	Logger *slog.Logger
	// Poll is the overlay poll interval; 0 is DefaultPoll.
	Poll time.Duration
	// Now and Mono are the clocks lines are stamped with; nil is the system's.
	Now  func() time.Time
	Mono func() uint64

	// admit places a control connection's peer; nil is procAdmit. Tests replace it.
	admit admitter
	// stillShim is the gate's look at an admitted shim; nil is procStillShim. Tests replace it.
	stillShim shimCheck
	// read reads the run's overlay; nil is mcptools.Read. Tests replace it.
	read func(dir, run string) (*mcptools.Overlay, error)
}

// Service is the run's MCP relay.
type Service struct {
	opts    Options
	servers map[string]Server
	ctl     net.Listener
	https   []*httpRelay

	mu      sync.Mutex
	run     source.RunRef
	sink    source.Sink
	ask     AskFunc
	overlay *mcptools.Overlay
	sig     mcptools.Signature
	warned  mcptools.Signature // the overlay last warned of, so a retry every poll does not repeat it
	serial  uint64
	pending map[int]pendingStart // admitted shim pid -> what it may start, not yet started
	seen    mcptools.Seen
	conns   map[*stdioConn]struct{}
	cfgPath string
	stopped bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// pendingStart is one admitted shim's start, not yet made: the server its hello named, and what admitting it proved.
type pendingStart struct {
	server string
	shim   admission
	pid    int
	child  *sys.FD // pinned before the shim releases its child to exec
	bound  bool    // the shim acknowledged this PID after its waiting stage exec
	stage  *StageRequest
}

// New binds the control listener (and one HTTP relay listener per relayed url server) on loopback, so the ports
// exist before the run starts (source.LoopbackSource).
func New(opts Options) (*Service, error) {
	if len(opts.Servers) == 0 {
		return nil, errors.New("mcprelay: no relayed server")
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Poll <= 0 {
		opts.Poll = DefaultPoll
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Mono == nil {
		opts.Mono = monoNow
	}
	if opts.admit == nil {
		opts.admit = procAdmit
	}
	if opts.stillShim == nil {
		opts.stillShim = procStillShim
	}
	if opts.read == nil {
		opts.read = mcptools.Read
	}
	if opts.Exe == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("mcprelay: own executable: %w", err)
		}
		opts.Exe = exe
	}
	s := &Service{opts: opts, servers: map[string]Server{}, pending: map[int]pendingStart{}, seen: mcptools.Seen{},
		conns: map[*stdioConn]struct{}{}}
	for _, sv := range opts.Servers {
		if _, dup := s.servers[sv.Name]; dup || !mcptools.ValidName(sv.Name) || (len(sv.Command) == 0) == (sv.URL == "") {
			return nil, fmt.Errorf("mcprelay: server %q is not one stdio command or one url", sv.Name)
		}
		s.servers[sv.Name] = sv
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("mcprelay: control listener: %w", err)
	}
	s.ctl = ln
	for _, sv := range opts.Servers {
		if sv.URL == "" {
			continue
		}
		h, err := newHTTPRelay(s, sv)
		if err != nil {
			s.closeListeners()
			return nil, err
		}
		s.https = append(s.https, h)
	}
	return s, nil
}

func (s *Service) closeListeners() {
	_ = s.ctl.Close()
	for _, h := range s.https {
		h.close()
	}
}

// Name is the source's name.
func (s *Service) Name() string { return Name }

// ConfigureMCPAsk gives the service the run's broker. Without it, a tool the rules ask about is refused
// ask-unavailable.
func (s *Service) ConfigureMCPAsk(fn func(context.Context, ask.Request) (ask.Decision, error)) {
	s.mu.Lock()
	s.ask = fn
	s.mu.Unlock()
}

// Endpoints are the loopback listeners the run admits: the control listener and each HTTP relay.
func (s *Service) Endpoints() []netip.AddrPort {
	out := []netip.AddrPort{addrPort(s.ctl.Addr())}
	for _, h := range s.https {
		out = append(out, addrPort(h.ln.Addr()))
	}
	return out
}

func addrPort(a net.Addr) netip.AddrPort {
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}

// UseRuntimeDir writes the run's MCP client config into dir (the run's runtime directory, readable by the agent),
// before Vars is read. A run with no runtime directory gets no TEGO_MCP_CONFIG.
func (s *Service) UseRuntimeDir(dir string) error {
	if dir == "" {
		s.opts.Logger.Warn("mcp relay: the run has no runtime directory, so no TEGO_MCP_CONFIG file is written")
		return nil
	}
	p, err := writeClientConfig(dir, s.opts.Exe, s.Servers(), s.httpURLs())
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cfgPath = p
	s.mu.Unlock()
	return nil
}

// Vars are the variables the run gives the agent: the control listener and the client config file.
func (s *Service) Vars() map[string]string {
	out := map[string]string{EnvRelay: s.ctl.Addr().String()}
	s.mu.Lock()
	if s.cfgPath != "" {
		out[EnvConfig] = s.cfgPath
	}
	s.mu.Unlock()
	return out
}

// Servers are the relayed servers, in contract order.
func (s *Service) Servers() []Server { return slices.Clone(s.opts.Servers) }

// Start begins serving: the control listener, the HTTP relays and the overlay poll.
func (s *Service) Start(ctx context.Context, run source.RunRef, sink source.Sink) error {
	s.mu.Lock()
	s.run, s.sink = run, sink
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()
	s.loadOverlay(true)
	s.wg.Add(2)
	go s.acceptLoop()
	go s.pollLoop()
	for _, h := range s.https {
		h.start()
	}
	return nil
}

// Stop closes the listeners and every shim connection; a shim whose connection drops kills its server.
func (s *Service) Stop() error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	cancel := s.cancel
	conns := make([]*stdioConn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.closeListeners()
	for _, c := range conns {
		c.close()
	}
	s.wg.Wait()
	return nil
}

// Gaps is nothing: the relay covers what it relays, and reports no shortfall at run_end.
func (s *Service) Gaps() []source.Gap { return nil }

// Relayed is the supervisor's gate (ADR 0126 §4): only the child pinned before its exec can consume the admitted
// shim's one start. A live pidfd keeps p.pid bound to that process, even if the shim's parent relationship changes.
// A sibling forked before the shim's exec cannot consume it. The admitted shim must still pass procStillShim.
func (s *Service) Relayed(server string, callerPID int) bool {
	s.mu.Lock()
	var p pendingStart
	for shim, pending := range s.pending {
		if pending.pid == callerPID && pending.child != nil && pending.bound && pending.server == server {
			p = pending
			delete(s.pending, shim)
			break
		}
	}
	s.mu.Unlock()
	if p.child == nil {
		return false
	}
	defer func() { _ = p.child.Close() }()
	if !s.opts.stillShim(p.shim) {
		return false
	}
	exited, err := sys.PollPidfdFD(p.child, 0)
	return err == nil && !exited
}

// bindChild runs while the shim's child is waiting to exec. The trusted shim reports the PID proc.Start returned,
// before it can reap the child. On registration failure the shim closes its admitted connection before reaping,
// so procStillShim fails before that PID can be reused. Pinning here and checking liveness after the proc reads
// binds the successful registration to that child.
// The parent check admits a registration; it is never the authority for a later server exec.
func (s *Service) bindChild(shim admission, pid int) bool {
	if pid <= 0 || ppidOf(pid) != shim.pid || !s.opts.stillShim(shim) {
		return false
	}
	s.mu.Lock()
	p, ok := s.pending[shim.pid]
	if ok && p.shim == shim && p.child != nil {
		// A constrained stage was already pinned while its first exec was held. Registration confirms the same
		// child; it cannot replace that identity with a sibling or a recycled PID.
		exited, err := sys.PollPidfdFD(p.child, 0)
		if p.pid != pid || p.bound || s.stopped || err != nil || exited {
			s.mu.Unlock()
			return false
		}
		p.bound = true
		s.pending[shim.pid] = p
		s.mu.Unlock()
		return true
	}
	s.mu.Unlock()
	child, err := sys.PidfdOpenProcessFD(pid)
	if err != nil {
		return false
	}
	keep := false
	defer func() {
		if !keep {
			_ = child.Close()
		}
	}()
	if ppidOf(pid) != shim.pid || !s.opts.stillShim(shim) {
		return false
	}
	if exited, err := sys.PollPidfdFD(child, 0); err != nil || exited {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok = s.pending[shim.pid]
	if !ok || p.shim != shim || p.child != nil || s.stopped {
		return false
	}
	p.pid, p.child, p.bound = pid, child, true
	s.pending[shim.pid] = p
	keep = true
	return true
}

// clearPending releases the child's pidfd on disconnect, failed exec or a completed start. The admission comparison
// keeps an old connection's cleanup from removing another connection's start.
func (s *Service) clearPending(shim admission) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.pending[shim.pid]; ok && p.shim == shim {
		delete(s.pending, shim.pid)
		_ = p.child.Close()
	}
}

// IsRelayed reports whether server is behind this relay.
func (s *Service) IsRelayed(server string) bool {
	_, ok := s.servers[server]
	return ok
}

func (s *Service) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ctl.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveStdio(c)
		}()
	}
}

func (s *Service) pollLoop() {
	defer s.wg.Done()
	t := time.NewTicker(s.opts.Poll)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			s.loadOverlay(false)
		}
	}
}

// loadOverlay rereads the run's overlay when its signature moved, and writes one gap line per change put in force.
// An overlay that cannot be read keeps the last good one in force. Only a file refused for what it is stays unread
// until it changes: any other read error (EMFILE, EIO) is retried, or a Deny written then would not be put in force for
// the rest of the run. first reads without writing lines: the run starts with what is there.
func (s *Service) loadOverlay(first bool) {
	s.mu.Lock()
	dir, run := s.run.Dir, s.run.ID
	s.mu.Unlock()
	if dir == "" {
		return
	}
	sig := mcptools.Stat(dir)
	s.mu.Lock()
	same := sig == s.sig && !first
	s.mu.Unlock()
	if same {
		return
	}
	o, err := s.opts.read(dir, run)
	switch {
	case errors.Is(err, os.ErrNotExist):
		o = mcptools.New(run)
	case err != nil:
		s.mu.Lock()
		warn := s.warned != sig
		s.warned = sig
		if errors.Is(err, mcptools.ErrUntrusted) || errors.Is(err, mcptools.ErrInvalid) {
			s.sig = sig
		}
		s.mu.Unlock()
		if warn {
			s.opts.Logger.Warn("mcp relay: the run's live MCP switches cannot be read; the last ones read stay in force", "err", err)
		}
		return
	}
	s.mu.Lock()
	changes := o.Since(s.serial)
	s.overlay, s.sig, s.serial = o, sig, o.Serial
	s.mu.Unlock()
	if first {
		return
	}
	for _, c := range changes {
		if _, ok := s.servers[c.Server]; ok {
			s.emitChange(c)
		}
	}
}

// decide is the decision for server's tool now: the overlay is reread first when it moved.
func (s *Service) decide(server, tool string) mcptool.Result {
	s.loadOverlay(false)
	s.mu.Lock()
	live := ""
	if e, ok := s.overlay.Lookup(server, tool); ok {
		live = e.Decision
	}
	s.mu.Unlock()
	return mcptool.Decide(s.servers[server].Rules, live, server, tool)
}

// denied is the tools/list filter of server: a tool decided deny now.
func (s *Service) denied(server string) func(string) bool {
	return func(tool string) bool { return s.decide(server, tool).Decision == mcptool.Deny }
}

// noteSeen merges a tools/list's names into the seen file.
func (s *Service) noteSeen(server string, names []string) {
	s.mu.Lock()
	grew := s.seen.Merge(server, names)
	dir := s.run.Dir
	snapshot := mcptools.Seen{}
	for k, v := range s.seen {
		snapshot[k] = slices.Clone(v)
	}
	s.mu.Unlock()
	if grew && dir != "" {
		if err := mcptools.WriteSeen(dir, snapshot); err != nil {
			s.opts.Logger.Warn("mcp relay: write the tools seen", "err", err)
		}
	}
}

// askPerson holds one call on the broker. It returns whether a person approved it and, when not, the reason.
func (s *Service) askPerson(ctx context.Context, server, tool, rule string, pid int) (bool, string) {
	s.mu.Lock()
	fn := s.ask
	s.mu.Unlock()
	if fn == nil {
		return false, ask.ReasonUnavailable
	}
	d, err := fn(ctx, ask.Request{Op: OpMCPTool, Target: server + " " + tool, Rule: rule, Hold: "request", PID: pid, TID: pid})
	if err == nil && d.Approved {
		return true, ""
	}
	if d.Reason == "" {
		d.Reason = ask.ReasonUnavailable
	}
	return false, d.Reason
}

// OpMCPTool is the ask op of a held tools/call.
const OpMCPTool = "mcp_tool"

// emitCall writes one tools/call decision: an mcp line, source proxy.
func (s *Service) emitCall(pid int, server, transport, tool, rule string, verdict record.Verdict, authority record.Authority, reason string) {
	s.mu.Lock()
	run, sink := s.run, s.sink
	s.mu.Unlock()
	if sink == nil {
		return
	}
	ev := &record.Event{V: record.Version, TS: s.opts.Now(), MonoNS: s.opts.Mono(), Run: run.ID, Agent: run.Agent,
		Cgroup: run.CgroupID, PID: pid, Kind: record.KindMCP, Source: record.SourceProxy, Rule: rule, Verdict: verdict,
		Authority: authority, Reason: record.Reason(reason),
		Attr: &record.Attribution{Confidence: record.ConfidenceUnattributed, Method: record.MethodNone}}
	if err := ev.SetPayload(record.MCPPayload{Name: server, Transport: transport, Tool: tool}); err != nil {
		return
	}
	sink.Emit(ev)
}

// emitChange writes the gap line of one live change put in force.
func (s *Service) emitChange(c mcptools.Change) {
	s.mu.Lock()
	run, sink := s.run, s.sink
	s.mu.Unlock()
	if sink == nil {
		return
	}
	ev := changeEvent(c)
	if ev == nil {
		return
	}
	ev.V, ev.TS, ev.MonoNS, ev.Run, ev.Agent, ev.Cgroup = record.Version, s.opts.Now(), s.opts.Mono(), run.ID, run.Agent, run.CgroupID
	sink.Emit(ev)
}

func monoNow() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Nano())
}
