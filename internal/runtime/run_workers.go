// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"

	"errors"
	"fmt"

	"net/netip"
	"os"
	"path/filepath"

	"slices"

	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/dns"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/source"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/internal/runtime/limits"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/agent"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// startWorkers is §4.1 step 8: the pipeline, the supervisor's notify loop and every source.
// Shutdown cancels and joins them, subject to the bounded source-stop handling in stopSources.
// The loop must be watching the listener before the ack releases the child, so this returns only
// once it reports itself armed (R7).
func (r *runner) startWorkers(ctx context.Context) error {
	r.runQueue() // the queue prepareEnforcement handed the tier: its events are drained here too
	terminal := ledger.Sink(r.writer.Append)
	if r.deps.Sink != nil {
		sink := r.deps.Sink
		terminal = func(ev *record.Event) error { sink.Emit(ev); return nil }
	}
	r.newBudget()
	r.wireStreamActivity()
	r.wireKernelActivity()
	r.pipe = newPipeline(r.queue, terminal, r.writer.RedactStage, r.writer.SplitBlobsStage,
		runStamp{PID: os.Getpid(), TID: syscall.Gettid(), Cgroup: r.cg.ID},
		r.attributeStage(), budgets(r.budget, r.deps.Clock), r.log, r.writer.AppendBatch)
	if r.deps.Sink != nil {
		r.pipe.pairWrite = nil
	}
	r.pipe.onLedgerFail = r.ledgerFailed
	r.pipe.onCaptureLost = r.captureLost
	r.runPipeline(ctx)

	// The supervisor may wait on this (kernelConnects), so it closes on every return below, the ones that
	// fail included; only a run that started every source can have a recorder that reads.
	r.kernelDecided = make(chan struct{})
	started := false
	defer func() { r.decideKernelRecord(started) }()
	if err := r.startDNSBroker(ctx); err != nil {
		return err
	}
	if err := r.startAsk(ctx); err != nil {
		return err
	}
	if err := r.startNotifyLoop(ctx); err != nil {
		return err
	}
	ref := r.ref()
	for _, s := range r.allSources() {
		// Model traffic has a lane of its own, which waits for room: a dropped ssl_response is spend the budgets
		// never see. The tier's kernel recorder has LaneKernel and the fanotify listener LaneListener (neither waits);
		// LaneDefault carries only the run's own lines and gaps.
		sink := r.queue.Lane(LaneKernel)
		if slices.Contains(r.deps.Capture, s) {
			// A capture source also reports model spend it could not count, which ends a budgeted run
			// (ReportUnmetered, R1).
			sink = meteredLane{Sink: r.queue.Lane(LaneCapture), r: r}
		}
		if err := s.Start(ctx, ref, sink); err != nil {
			return fmt.Errorf("runtime: start source %s: %w", s.Name(), err)
		}
		r.sources = append(r.sources, s)
	}
	// Every source has started and the agent is not yet released: a budget capture was to meter and cannot
	// fails the run here, before run_start, rather than letting it spend unmetered (R32).
	if err := r.refuseUnmeteredBudget(); err != nil {
		return err
	}
	// So does a budget the contract declares that nothing was ever going to count (R32).
	if err := r.refuseUncountedBudget(); err != nil {
		return err
	}
	if err := r.requireHTTPPolicy(); err != nil {
		return err
	}
	// A worker (the enforce listener) that died while the sources started cancelled ctx: nothing above looks
	// again, and the run must fail here, before run_start, not release the agent (§7).
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.startTracking(ctx); err != nil {
		return err
	}
	started = true
	return nil
}

// dnsRefreshTick is how often the resolver set checks whether any host entry's TTL has expired. It is a
// poll interval, not a re-resolution interval: the set only looks up an entry whose own TTL is due.
const dnsRefreshTick = 5 * time.Second

// unixGranter is a tier-2 or tier-3 handle that can grant the run's kernel one connect of an approved abstract unix
// name (cgroup's Handle.GrantUnix, supervisor R11c), by the socket's cookie. A handle without it leaves
// supervisor.Options.GrantUnix nil, and the supervisor then refuses such a name ask-unavailable at a root tier.
type unixGranter interface {
	GrantUnix(done <-chan struct{}, cookie uint64, name []byte) (supervisor.Revoke, error)
}

// denyReadSnapshotter is the tier-1 handle's deny_read enumeration as Prepare froze it (landlock.Handle.DenyReadSnapshot):
// whether the ruleset refuses a read of a resolved path the contract allows, nil when it enumerated nothing.
type denyReadSnapshotter interface {
	DenyReadSnapshot() func(path string) bool
}

// connectGranter is a tier-2 or tier-3 handle that can grant the run's kernel one connect of an approved TCP or UDP
// destination (cgroup's Handle.GrantConnect, supervisor R13d). A handle without it leaves supervisor.Options.GrantConnect
// nil, and the supervisor then refuses such a connect ask-unavailable at a root tier.
type connectGranter interface {
	GrantConnect(done <-chan struct{}, fd int, dst netip.AddrPort, proto string) (supervisor.Revoke, error)
}

// datagramGranter is a tier-2 or tier-3 handle that can grant the run's kernel one addressed UDP datagram of an
// approved destination (cgroup's Handle.GrantDatagram, supervisor R13d). A handle without it leaves
// supervisor.Options.GrantDatagram nil, and the supervisor then refuses such a datagram ask-unavailable at a root
// tier before anyone is asked.
type datagramGranter interface {
	GrantDatagram(done <-chan struct{}, cookie uint64, domain int, dst netip.AddrPort) (supervisor.Revoke, error)
}

// startNotifyLoop starts the supervisor's loop over the notify fd taken from the child stage and returns
// only once the loop owns the listener (R7). Until it does, the child is blocked in the kernel on its own
// execve with nobody to answer it, so this waits on the loop's readiness rather than guessing.
func (r *runner) startNotifyLoop(ctx context.Context) error {
	// An Adjustable run starts only where every path a fence entry covers reaches this loop (ADR 0125 decision 6),
	// so it is checked before the early return of a tier with no filter, which would leave the fence wide open.
	if err := r.checkAdjustable(); err != nil {
		return err
	}
	if r.notifyFD == nil {
		return nil // a tier with no seccomp filter: nothing notifies
	}
	// The supervisor decides connects against the contract's net entries with their live IP sets, and
	// allows the machine's resolvers on port 53 (SEMANTICS §5). The set re-resolves host entries on TTL
	// in the background, keeping the previous addresses when a lookup fails, so a transient DNS outage
	// does not revoke grants under the default unlimited-stale policy; explicit max_stale expires them. The set is given the run's resolved-address check (refreshDenied: the
	// table's, with the machine's ranges, and this host's own addresses), so what it hands a tier's kernel
	// rows (refreshDNS) holds no address the contract refuses for the name in any agent-contract R18 class.
	// The supervisor applies the same check, with its own snapshot of this host's addresses, to every
	// destination it matches.
	opts := r.dnsOptions
	if r.rt.DNS.MaxStale != nil {
		stale := time.Duration(*r.rt.DNS.MaxStale)
		opts.MaxStale = &stale
	}
	if opts.ResolvedDenied == nil {
		opts.ResolvedDenied = refreshDenied(r.rt, r.hostSnapshot())
	}
	tick := r.dnsTick
	if tick <= 0 {
		tick = dnsRefreshTick
	}
	// The set renews a max_stale-bounded grant a tick plus a lookup ahead of its deadline, so it must know
	// the tick that polls it (dns.Options.RefreshEvery).
	opts.RefreshEvery = tick
	resolvers := dns.NewSet(r.rt.Net, r.runResolvers(), opts)
	r.dnsSet = resolvers
	r.group.Go("dns", func() error { return r.refreshDNS(ctx, resolvers, tick) })
	policy := &supervisor.Policy{
		Rules:    r.rt,
		Resolver: resolvers,
		RunID:    string(r.id),
		Agent:    string(r.agentID),
		Record:   r.rt.Record,
		Observe:  recordsOnly(r.handle),
	}
	if r.cg.Path != "" {
		_, policy.Cgroup = splitCgroupPath(r.cg.Path)
	}
	// The supervisor's own lane, which waits for room rather than let a flooding agent choose what the ledger
	// loses (Queue).
	supOpts := supervisor.Options{Log: r.log}
	// The run's live blocks (internal/liveblock, MinorLiveBlock): polled from the run directory, refused by the
	// supervisor on top of the contract.
	if r.dir != "" {
		blocks, err := r.startLiveBlocks(ctx)
		if err != nil {
			return err
		}
		supOpts.LiveBlocks = blocks.Load
		r.group.Go("liveblock", func() error { return r.watchLiveBlocks(ctx, blocks) })
		r.markPauseReader() // only now does a pause written to the overlay reach a launcher that applies it
		r.markRealReader()  // only now may a writer store a block's real path (VersionReal) for this run
	}
	supOpts.Ask = r.askRequest
	supOpts.AskResolver = r.startAskDNS(ctx, opts, tick)
	if grant, ok := r.handle.(connectGranter); ok {
		supOpts.GrantConnect = grant.GrantConnect
	}
	if grant, ok := r.handle.(unixGranter); ok {
		supOpts.GrantUnix = grant.GrantUnix
	}
	if grant, ok := r.handle.(datagramGranter); ok {
		supOpts.GrantDatagram = grant.GrantDatagram
	}
	if r.askRelays != nil {
		supOpts.FirstWrite = func(_ context.Context, req ask.Request, dst netip.AddrPort, ipv6 bool, fd int, refused func() string) (netip.AddrPort, func(), error) {
			return r.askRelays.Reserve(r.askCtx, req, dst, ipv6, fd, refused)
		}
	}
	// Under record: off the supervisor keeps only refusals, so the budget watcher would see no activity from an
	// agent busy with allowed work, and its stall check killed it (R4): every answered notification is
	// activity instead.
	if r.budget != nil && r.rt.Record == agent.RecordOff {
		budget, clock := r.budget, r.deps.Clock
		supOpts.Activity = func() { budget.Touch(clock.MonoNS()) }
	}
	// A line's mono_ns is its notification's receipt (supervisor.md R23a), so a syscall the supervisor relayed for a
	// long time, which ends when its line is written, would count as activity at its start: a 50 s relay followed by
	// 10 s idle tripped stall_after 60s. A notification finished past the soft ceiling touches the watcher at its
	// finish (supervisor.Options.Late).
	if r.budget != nil {
		supOpts.Late = r.budget.Touch
	}
	// A connect the supervisor continues is the agent's own, and the tier's kernel recorder records it too
	// (security_socket_connect): one line per connect is the recorder's whenever it reads this run, and the
	// supervisor's otherwise (supervisor.md R7). Under record: off neither keeps an allowed connect.
	if r.kernelRecord != nil && r.rt.Record != agent.RecordOff {
		supOpts.KernelConnects = r.kernelConnects(ctx)
	}
	// A filesystem action the recorder's hooks see is the recorder's line, with the LSM chain's verdict, whenever
	// it reads this run, under record: off too, where it keeps the refusals (supervisor.md R7a).
	if r.kernelRecord != nil {
		supOpts.KernelFS = r.kernelConnects(ctx)
	}
	// With the kernel decision plane deciding execs, a continued exec's one line is the kernel's: the plane's
	// refusal or the exec record named by the plane's rule (supervisor.md R7a, TIER3-PLAN T9).
	if r.kernelRecord != nil && r.planeExecs() {
		supOpts.KernelExecs = r.kernelConnects(ctx)
	}
	if r.kernelRecord != nil && r.planeDecides() {
		supOpts.KernelExecHandoff = r.kernelExecHandoff(ctx)
	}
	// A run whose slot the tier pinned has every exec the supervisor continues carry its pin (ADR 0048 (3) P2).
	supOpts.ExecPinner, supOpts.ExecPinKey = execPinner(r.handle)
	// With fs mutations left unnotified to the plane, nothing would invalidate the supervisor's walk cache.
	supOpts.PlaneFS = r.planeFS
	// With a plane deciding the run, a chmod beneath a deny_write target is the kernel's to refuse (step B): this
	// loop refuses the ones it is notified of by the same rule, so the line and the verdict are one (supervisor
	// Options.PlaneAttrs).
	supOpts.PlaneAttrs = r.planeDecides()
	// A person's alternate is never delivered from the run's runtime directories either (ADR 0057 D2): they are
	// tego's own state, though the compiled table does not name them.
	supOpts.OwnState = runtimeOwnState()
	supOpts.MCPRelayed = r.mcpRelayedGate() // nil unless an MCP relay runs (ADR 0126 §4 "The gate")
	supOpts.MCPStage = r.mcpStageGrant()
	// The run's own runtime directory is the run's to read (its reason file, its CODEX_HOME): a held read there is not
	// refused as tego's own state (ADR 0069 D3 (d)). Named as the deputy's pins name it, resolved.
	if r.runtimeDir != "" {
		supOpts.RuntimeDir = r.runtimeDir
		if real, err := filepath.EvalSymlinks(r.runtimeDir); err == nil {
			supOpts.RuntimeDir = real
		}
	}
	// A read the tier-1 ruleset refuses because its deny_read enumeration froze at launch is refused and recorded as
	// such, never recorded allow. Only the tier-1 handle keeps the snapshot; a records-only run enforces nothing.
	if s, ok := r.handle.(denyReadSnapshotter); ok && !policy.Observe {
		supOpts.DenyReadSnapshot = s.DenyReadSnapshot()
	}
	if h, ok := r.handle.(interface{ BuiltinSocketDirectories() map[[2]uint64]string }); ok && !policy.Observe {
		supOpts.BuiltinDirectories = h.BuiltinSocketDirectories()
	}
	// The open deputy completes the gate's escalating fs opens in the run (ADR 0041 Stage B, gate.completion: held).
	if r.deputy != nil {
		supOpts.Deputy = r.deputy
	}
	supOpts.KernelBindHandoff = r.kernelBindHandoff(ctx)
	supOpts.KernelListenHandoff = r.kernelListenHandoff(ctx)
	// At tier 2 the run's connect4/6 decides the connects the supervisor relays too, and a refusal of its own
	// fails one with EPERM: the supervisor reads why from the tier, so the line is the kernel's refusal
	// (enforce-cgroup-observe.md R5).
	if kn, ok := r.handle.(enforce.KernelNetReader); ok {
		supOpts.KernelNet = kn.KernelNet
	}
	// The run's own programs decide an addressed datagram's destination on the kernel's copy of its address, and
	// refuse one with their own errno: the supervisor refuses such a datagram itself, with that errno, so its one
	// line is the refusal rather than a best-effort line beside the kernel's (supervisor.md R13b,
	// enforce-cgroup-observe.md R7). The attachments are fixed by now: Prepare and Attach ran in setup.
	if kd, ok := r.handle.(enforce.KernelDatagramReader); ok {
		u, d := kd.KernelDatagrams()
		supOpts.KernelDatagrams = supervisor.KernelDatagrams{Unix: u, UDP: d}
	}
	// The listener moves into supervisor.New, which owns it on every path from the call on: Run closes it
	// once, as its shutdown step, and New closes it itself when it fails (ADR 0023 C7). The field is cleared
	// before the call, so the move is a value move and runtime-launch.md §9's "every fd is closed exactly
	// once, on exactly one code path" holds by construction: releaseKernelState closes the listener only on
	// the paths that never reached this line. A second closer could not reach another file anyway, since an
	// owner closes its number once, but this one never tries.
	listener := r.notifyFD
	r.notifyFD = nil
	loop, err := supervisor.New(listener, policy, r.queue.Lane(LaneSupervisor), supOpts)
	if err != nil {
		return fmt.Errorf("runtime: supervisor: %w", err)
	}
	r.sup = loop
	r.nameKernelConnects(loop.ContinuedNet)
	r.superviseKernelRecord(loop.ContinuedFS)
	// The open deputy's own opens are the supervisor's held opens, whose lines it writes: the recorder drops the
	// deputy's records, named by its pid and start time (supervisor.md R7a, keepDeputy).
	if r.deputy != nil {
		if s, ok := r.kernelRecord.(DeputySkipper); ok {
			s.SetSkipProcess(uint32(r.deputy.PID()), r.deputyStart)
		}
	}
	r.superviseKernelExec(loop.ContinuedExec)
	r.superviseKernelListeners(loop)
	// An exec whose image's open tier 2's listener refuses is the supervisor's line (supervisor.md R7a).
	if s, ok := r.handle.(enforce.SupervisorExecLines); ok {
		s.SetSupervisorExecLines(loop.ExecLine)
	}
	ended := make(chan error, 1)
	r.group.Go("supervisor", func() error {
		err := loop.Run(ctx)
		ended <- err
		if err == nil && loop.Started() && r.rt.Adjustable() {
			err = r.adjustableLoopEnded(ctx)
		}
		return err
	})
	select {
	case err := <-ended:
		// A loop that returned before the run even started leaves the child blocked on its execve
		// forever; there is no run to fold this into yet, so it is a startup failure.
		if err == nil {
			err = errors.New("the loop returned before the run started")
		}
		return fmt.Errorf("runtime: supervisor: %w", err)
	case <-loop.Armed():
		if loop.Started() {
			return nil
		}
		// Armed also closes when Run returns without ever owning the listener, so that a caller is
		// never stranded — which means a failed start makes both this case and `ended` ready at
		// once, and Go picks among ready cases at random. Taking this branch on its own would let
		// prepare succeed and the child exec with nothing answering its notifications: every
		// notified syscall would meet a closed listener, and the run would claim an enforcement
		// tier it does not have. The loop has returned, so its error is on its way to `ended`.
		select {
		case err := <-ended:
			if err == nil {
				err = errors.New("the loop returned before it armed")
			}
			return fmt.Errorf("runtime: supervisor: %w", err)
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-ctx.Done():
		return ctx.Err()
	}
}

// startLiveBlocks is the run's live blocks as the supervisor first loads them: the overlay's first poll, compiled into
// the first Set. An Adjustable run's fence is in the launcher's memory before that poll, so its refusals are in that
// Set: every fence entry is refused before the agent's first instruction (ADR 0125 decision 5). A Locked run has no
// fence and no key, and starts exactly as before. An Adjustable run whose first Set does not hold every fence refusal
// does not start (fenceInForce).
func (r *runner) startLiveBlocks(ctx context.Context) (*liveBlocks, error) {
	blocks := &liveBlocks{}
	if r.rt.Adjustable() {
		fence, err := r.seedFence()
		if err != nil {
			return nil, err
		}
		blocks.fence = fence
	}
	r.pollLiveBlocks(ctx, blocks)
	if err := fenceInForce(blocks); err != nil {
		return nil, err
	}
	return blocks, nil
}

// fenceInForce is nil when b has no fence, or when its Set holds every refusal the fence gives. It is the start's own
// check that the first poll put the fence in force, whatever path through pollLiveBlocks it took: an overlay
// unreadable at the run's start once stored no Set, and the run started with every fence entry open. Defence in depth: pollLiveBlocks stores on the first poll in every case.
func fenceInForce(b *liveBlocks) error {
	if b.fence == nil {
		return nil
	}
	want, got := len(b.fence.Refusals()), b.Load().Fenced()
	if got < want {
		return fmt.Errorf("%w: the first live Set holds %d of the fence's %d refusals, so a fence entry would be open "+
			"from the run's start (ADR 0125 decision 5)", ErrLiveStart, got, want)
	}
	return nil
}

// refreshDNS is the run's DNS worker: every tick it re-resolves the host entries whose TTL has passed (as
// dns.Set.Run does), and whenever the addresses the set gives the tier (dns.Set.Refreshed, through the run's
// refreshDenied) differ from the ones it last handed a tier whose kernel rows hold them (enforce.NetRefresher),
// it hands the table with the new ones: after a refresh that moved an entry's addresses, and after a change in
// this host's own addresses that moves one of an entry's addresses into or out of the refused ones. It compares
// grant deadlines too: a successful same-address lookup renews a bounded hostname's kernel authorization.
// A resolution-time change alone does not rewrite an unbounded grant. It checks once as it starts as well,
// against the table Prepare wrote the rows from (rowsTable), so a host address that
// changed in between moves them at once. Tier 2's connect4/6 decides every connect the supervisor relays, so
// rows left at run start's addresses refused with EPERM each connect to an address a host rotated to, while the
// supervisor admitted it and the ledger recorded it allowed (enforce-cgroup-observe §6 E7). A refresh the tier
// fails is retried on the next tick; meanwhile its rows refuse the new addresses, which is the fail-closed side,
// and lookup failures retain addresses only until an explicitly bounded stale lifetime expires, as the
// supervisor's set does (R8a).
func (r *runner) refreshDNS(ctx context.Context, set *dns.Set, every time.Duration) error {
	if every <= 0 {
		every = dns.DefaultInterval
	}
	refresher, _ := r.handle.(enforce.NetRefresher)
	handed := r.rowsNet
	if handed == nil {
		handed = r.rt.Net
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for first := true; ; first = false {
		if !first {
			select {
			case <-ctx.Done():
				return nil
			case <-t.C:
			}
			if err := set.Refresh(ctx); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		}
		if refresher == nil {
			continue
		}
		next := *r.rt
		next.Net = set.Refreshed(r.rt.Net)
		if sameNetRows(handed, next.Net) {
			continue
		}
		if err := refresher.RefreshNet(&next); err != nil {
			r.log.Warn("run: the tier's network rows did not follow the run's address set; retrying next tick", "err", err)
			continue
		}
		handed = next.Net
	}
}

// sameNetRows includes the hostname grant deadlines enforced by kernel rows.
// A successful lookup can renew a deadline without changing any address. An
// unbounded grant still avoids rewrites when only its resolution time changes.
func sameNetRows(a, b []agent.NetRule) bool {
	if !sameNetAddrs(a, b) {
		return false
	}
	for i := range a {
		if !a[i].ExpiresAt.Equal(b[i].ExpiresAt) {
			return false
		}
	}
	return true
}

// resolverEndpoints is the set R14's port-53 exception covers: the machine config's `resolver` list
// when it names servers, and /etc/resolv.conf's nameservers, read now, only for `resolver: auto`
// (spec/config/v0; identity-config.md E28). An explicit list replaces the file rather than adding to
// it, because the operator who wrote one chose where this run's DNS may go; reading resolv.conf anyway
// would admit UDP/53 to hosts the configuration never named. An explicit empty list is a machine with
// no resolver exception at all, which falls through to ordinary net.allow matching (E32).
//
// A server on a port other than 53 is kept, and warned about: the supervisor's exception is for port
// 53 only (R14), so traffic to that server is refused unless a net.allow entry names it.
func (r *runner) resolverEndpoints() []netip.AddrPort {
	m := r.deps.Config
	if m == nil {
		return dns.MachineResolvers(true, nil)
	}
	servers := dns.MachineResolvers(m.Resolver.Value.Auto, m.Resolver.Value.Servers)
	if m.Resolver.Value.Auto {
		return servers
	}
	for _, s := range servers {
		if s.Port() != dns.ResolverPort {
			r.log.Warn("run: resolver is not on port 53; the resolver exception does not cover it",
				"resolver", s.String(), "source", m.Resolver.Source.String())
		}
	}
	return servers
}

// newBudget builds this run's budget watcher (limits-check-doctor-cli.md §2, R1-R6). It is created
// before the pipeline because it is one of the pipeline's stages, and it is created for every run:
// a contract with no budgets leaves every dimension unasked (ResolvedLimits.Bounded is false), which the
// watcher reads as unbounded, so the wiring has one shape and the contract alone decides whether anything
// can trip. A zero is not that case: a dimension bounded at 0 is the tightest budget and trips (E16).
//
// The sink is the run's own queue, so the limit event takes the pipeline every other event takes —
// stamped, redacted and appended exactly once — and limits never touches the ledger itself. It is
// the queue's BudgetSink rather than the queue: the limit event goes to a slot of its own that the
// pipeline reads first, because the ordinary channel drops when full, and a run killed for a budget
// must never end with run_end reason=limit and no line naming the ceiling.
//
// WithPriceGap passes on the gap emitPriceGap writes after run_start, so the watcher does not
// record the same missing table again on the first response (E15: one gap).
func (r *runner) newBudget() {
	opts := []limits.Option{limits.WithLogger(r.log), limits.WithOnBreach(r.onBreach),
		limits.WithOnUnmetered(r.captureUnmetered), limits.WithPriceGap(r.deps.PriceGap), limits.WithHeld(r.held)}
	if publish := r.openActivity(); publish != nil {
		opts = append(opts, limits.WithActivityPublisher(publish))
	}
	if r.writer != nil {
		opts = append(opts, limits.WithLedgerCeiling(r.ledgerCeiling(), r.writer.LedgerBytes))
	}
	r.budget = limits.NewWatcher(r.rt.Limits, r.deps.Prices, r.cgm, r.cg, r.deps.Clock, r.queue.BudgetSink(), opts...)
}

// ledgerCeiling is the machine's record.max_run_bytes, 0 for none: the run is ended as a limit, which=ledger_bytes,
// once its events.jsonl and blobs hold that many bytes (limits.WithLedgerCeiling), and run_start.limits.ledger_bytes records
// it (record.MinorLedgerCap).
func (r *runner) ledgerCeiling() int64 {
	if m := r.deps.Config; m != nil && m.Record.MaxRunBytes.Bounded {
		return int64(m.Record.MaxRunBytes.Value)
	}
	return 0
}

// openActivity makes the run directory's activity sidecar and returns what the watcher publishes to it
// (limits-check-doctor-cli.md R9): the activity its stall check counted without a ledger line — a supervisor
// answer or a kernel sample under record: off, a relayed model chunk in any mode — which `status` reads beside the
// ledger so that it measures the idle the watcher kills on. A sidecar that cannot be made is logged and the run
// goes on: status then reads the ledger alone, as it did before the sidecar existed. A publish that fails is
// logged once.
func (r *runner) openActivity() func(monoNS uint64) {
	if r.writer == nil {
		return nil
	}
	a, err := r.writer.OpenActivity()
	if err != nil {
		r.log.Warn("run: no activity sidecar; status reads idle from the ledger alone", "err", err)
		return nil
	}
	r.activity = a
	failed := false
	return func(monoNS uint64) {
		if err := a.Publish(monoNS); err != nil && !failed {
			failed = true // the watcher's goroutine alone calls this
			r.log.Warn("run: publish activity; status may read this run as idle", "err", err)
		}
	}
}

// closeActivity closes the activity sidecar once the watcher that publishes to it has stopped. The file stays:
// status ignores it once the run's lock is free.
func (r *runner) closeActivity() {
	if r.activity == nil {
		return
	}
	if err := r.activity.Close(); err != nil {
		r.log.Warn("run: close activity sidecar", "err", err)
	}
	r.activity = nil
}

// wireStreamActivity hands each capture source that relays model traffic the watcher's Touch, before any source
// starts (limits-check-doctor-cli.md R4): a response that streams for longer than stall_after has a line at its two
// ends and none between, so the run was killed for stalling while its model was still answering, in every record
// mode. A run with no stall budget wires nothing, since no stall check reads it.
func (r *runner) wireStreamActivity() {
	if r.budget == nil || r.rt == nil || !r.rt.Limits.Bounded(agent.BudgetStallAfter) {
		return
	}
	for _, s := range r.captureSources() {
		if a, ok := s.(StreamActivityReporter); ok {
			a.SetStreamActivity(r.budget.Touch)
		}
	}
}

// wireKernelActivity has the watcher pull the run's activity stamp at each Tick (limits-check-doctor-cli.md R4): the
// stamp the BPF programs keep at the run's slot for what the record keeps no line or sample of, an allowed open, file
// operation or connect under record: off and a TLS call that moved bytes in any mode (tego_activity). The backend
// stamps a run only when stall_after bounds it (bpf.RunActivity), so nothing is wired otherwise. A recorder that has
// not found the run's slot answers 0, which the watcher takes for no activity; one whose ring could not be opened
// still answers the stamp.
func (r *runner) wireKernelActivity() {
	if r.budget == nil || r.rt == nil || !r.rt.Limits.Bounded(agent.BudgetStallAfter) {
		return
	}
	if s, ok := r.kernelRecord.(ActivityStamper); ok {
		r.budget.AddActivity(s.LastActivity)
	}
}

// askWaiting is the budget watcher's held hook: an agent blocked on a human
// approval is waiting on Tego, not stalled (limits R4). The broker is set by
// startAsk before the watcher's goroutine starts.
func (r *runner) askWaiting() bool { return r.askBroker.Waiting() }

// onBreach is what a crossed budget tells the facade (§4 trip): this run's terminal reason is
// `limit`, which r.ending turns into run_end reason=limit and, by R11 of the exit table, exit 124.
// The watcher has already appended the limit event naming the ceiling and is about to kill the
// cgroup, so nothing is done here but the decision: the agent's own wait status, whatever SIGKILL
// makes of it, must not stand in for a run the budget ended.
func (r *runner) onBreach(b limits.Breach) {
	if r.setTerminal(identity.ReasonLimit) {
		r.log.Info("run: budget crossed", "breach", b.String())
	}
}

// startBudgetClock hands the watcher the run's monotonic origin. run_start is written by the ledger
// writer directly rather than through the queue, so the watcher never sees it, and §2's StartMonoNS
// would otherwise stay zero until the agent's first syscall — or forever, for a tier with no
// notifications at all, leaving R3's wall ceiling unable to fire on a run that produces no events.
// The event exists only to carry that reading; it is never written anywhere.
func (r *runner) startBudgetClock() {
	if r.budget == nil {
		return
	}
	r.budget.Observe(&record.Event{Kind: record.KindRunStart, Source: record.SourceSupervisor,
		MonoNS: r.deps.Clock.MonoNS()})
}

// releaseSignals ends the subscription subscribeSignals made, once.
func (r *runner) releaseSignals() {
	if r.unnotify != nil {
		r.unnotify()
		r.unnotify = nil
	}
}

// subscribeSignals starts queueing the signals of §6 for this run. os/signal buffers into the
// channel, so a signal delivered before the handler goroutine exists is still handled, once.
func (r *runner) subscribeSignals() {
	if r.deps.Signals != nil {
		r.signalCh = r.deps.Signals
		return
	}
	ch, stop := launch.Notify()
	r.signalCh, r.unnotify = ch, stop
}

// startWatchers is §4.1 step 11: the signal rules and the cgroup watcher, both bound to the run's
// group so shutdown stops them.
func (r *runner) startWatchers(ctx context.Context) {
	var stdinTTY bool
	_ = sys.FileDo(os.Stdin, func(fd int) error { stdinTTY = sys.IsTerminal(fd); return nil })
	if r.deps.StdinIsTTY != nil {
		stdinTTY = *r.deps.StdinIsTTY
	}
	h, err := launch.NewSignalHandler(r.child, cgroup.Killer{Manager: r.cgm, Cgroup: r.cg},
		launch.SignalPolicy{
			StopGrace: r.stopGrace, StdinIsTTY: stdinTTY,
			StopRequested: func() bool { return StopRequested(r.dir) },
			// `tego stop --grace` asks for its own stop_grace through the marker (R9).
			RequestedGrace: func() time.Duration { return StopRequestGrace(r.dir) },
		})
	if err != nil {
		r.log.Error("run: signal handler", "err", err)
	} else {
		r.signals = h
		signals := r.signalCh
		if r.dir != "" && r.cg.Path != "" && signals != nil {
			// A paused run is thawed before a stop signal reaches it (livepause.go, record.MinorLiveControl).
			signals = r.thawOnStop(ctx, signals)
		}
		r.group.Go("signals", func() error { return h.Run(ctx, signals) })
	}
	r.group.Go("cgroup", func() error { return r.watchCgroup(ctx) })
	// Descendants the subreaper adopted stay charged to pids.current until they are waited for.
	r.group.Go("reap", func() error { return r.child.RunReaper(ctx) })
	// The budget watcher's own goroutine is what crosses the two ceilings no event announces, wall
	// and the stall gap (R3, R4). It is an ordinary member of the run's group, so it stops when the
	// run does and shutdown joins it like every other worker (§9 "Goroutine ownership").
	r.group.Go("limits", func() error { return r.budget.Run(ctx) })
}

// watchCgroup turns the two counters this package owns into a terminal reason (R10, R11): an
// oom_kill increase means the kernel already killed a task for the memory cap, a pids.events max
// increase means a fork was refused and the run is killed at once because a refused fork rarely
// surfaces as a clean exit.
func (r *runner) watchCgroup(ctx context.Context) error {
	baseOOM, basePids := r.limitBase.oom, r.limitBase.pids
	if !r.limitBase.ok {
		var err error
		if baseOOM, basePids, err = cgroup.ReadLimitEvents(r.cg); err != nil {
			r.cgroupEventsGap()
			return nil
		}
	}
	t := time.NewTicker(limitPollInterval)
	defer t.Stop()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			oom, pids, err := cgroup.ReadLimitEvents(r.cg)
			if err != nil {
				// A control file that no longer exists is not an error (it reads as zero), so
				// this is a transient read the next tick repeats: one bad read must never end
				// the run's only oom and pids detection. A file that keeps failing is given up
				// on, once and loudly, rather than spinning against it.
				failures++
				if failures >= maxLimitReadFailures {
					r.cgroupEventsGap()
					return nil
				}
				continue
			}
			failures = 0
			switch {
			case pids > basePids:
				r.setTerminal(identity.ReasonPids)
				if err := r.cgm.Kill(r.cg); err != nil {
					r.log.Warn("run: kill after pids cap", "err", err)
				}
				return nil
			case oom > baseOOM:
				r.setTerminal(identity.ReasonOOM)
				baseOOM = oom // keep polling: R11's kill still applies after an oom_kill
			}
		}
	}
}

// GapCgroupEventsUnavailable is the why of the gap what=record watchCgroup records when it gives up on the run
// cgroup's memory.events and pids.events (ADR 0020 (5)): from there the run's oom and pids reasons go unseen, which
// the record says rather than a line in tego's own log alone (ADR 0015).
const GapCgroupEventsUnavailable = "cgroup-events-unavailable"

// cgroupEventsGap records watchCgroup's giving up.
func (r *runner) cgroupEventsGap() {
	r.emitGap(source.Gap{What: record.GapRecord, Why: GapCgroupEventsUnavailable})
}

// finalLimitCheck is R10/R11's last reading, taken once the tree is empty and before run_end is decided: a
// main process the kernel OOM-kills, or a tree that meets pids.max and exits, empties the cgroup well inside
// one limitPollInterval, and shutdown then cancels watchCgroup before it has read either counter.
func (r *runner) finalLimitCheck() {
	if r.cgm == nil || r.cg.Path == "" || r.child == nil || !r.limitBase.ok {
		return
	}
	oom, pids, err := cgroup.ReadLimitEvents(r.cg)
	if err != nil {
		r.log.Warn("run: final read of the cgroup counters", "err", err)
		return
	}
	switch {
	case pids > r.limitBase.pids:
		r.setTerminal(identity.ReasonPids)
	case oom > r.limitBase.oom:
		r.setTerminal(identity.ReasonOOM)
	}
}

// runPipeline starts the pipeline goroutine in the run's group (§4.1 step 8) and records when it returns.
func (r *runner) runPipeline(ctx context.Context) {
	done := make(chan struct{})
	r.pipeDone = done
	// A group worker's failure cancels ctx, and the tree is then killed and reaped for up to two timeouts before
	// shutdown starts pumping again; a pipeline that stopped with ctx left the lanes unread over that window and
	// dropped a dying tree's exits as channel-full. Its context is cut from ctx's cancellation and ended by
	// stopPipeline.
	pctx, stop := context.WithCancel(context.WithoutCancel(ctx))
	r.pipeStop = stop
	r.group.Go("pipeline", func() error {
		defer close(done)
		return r.pipe.run(pctx, r.started)
	})
}
