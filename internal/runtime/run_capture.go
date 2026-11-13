// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"math"
	"net/netip"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// admitLoopback is the table this run enforces: the compiled one plus one net.allow entry per bound
// loopback capture listener.
//
// The compiler could not have written these entries. A forwarder listener takes an ephemeral port
// (capture-derive.md R19), so the port exists only once the socket is bound, which happens when the
// caller constructs the source — before Run. Without the entries the forwarder is unreachable: the
// supervisor refuses every destination no rule names, and Landlock's ABI-4 rules are one port each off
// this same table. R38 is what the pair buys: the loopback port is the route to the model, and a harness
// that ignores its base-URL variable is refused at the upstream rather than quietly unobserved.
//
// The compiled table is never mutated (agent.RuleTable I4) — this builds a new one, the way a TTL refresh
// does — and it is built here so every later reader, the enforcement backend included, sees one table.
func admitLoopback(rt *agent.RuleTable, sources []source.Source) *agent.RuleTable {
	var rules []agent.NetRule
	for _, s := range sources {
		ls, ok := s.(source.LoopbackSource)
		if !ok {
			continue
		}
		for _, ap := range ls.Endpoints() {
			if !ap.IsValid() || ap.Port() == 0 {
				continue
			}
			rules = append(rules, agent.NetRule{
				Raw:     ap.String(),
				Host:    ap.Addr().String(),
				Port:    int(ap.Port()),
				Proto:   agent.ProtoTCP,
				Verdict: agent.VerdictAllow,
				IPs:     []netip.Addr{ap.Addr()},
				Static:  true,
				// A grant the runtime makes on its own authority, not a declared entry: the rule
				// name reaching the ledger is net.capture[<addr>], so a reader sees both that the
				// destination is a capture listener and which one, and drift does not count the
				// agent's own model traffic as something the contract failed to declare
				// (agent.IsRuntimeRule).
				Runtime: agent.CaptureGrant,
			})
		}
	}
	if len(rules) == 0 {
		return rt
	}
	out := *rt
	out.Net = append(append(make([]agent.NetRule, 0, len(rt.Net)+len(rules)), rt.Net...), rules...)
	return &out
}

// emitCaptureGaps records what the caller's capture selection already knows it cannot cover
// (capture.Select's second return), as the first gaps of the run. A mechanism this binary does not carry
// is one gap event, never a silence (capture-derive.md §8 I4); what each source could not cover while it
// ran is a separate report, written by emitSourceGaps at the other end of the run.
//
// The fallback is for a caller that wired neither a source nor a gap while the contract asked for
// capture: that is a caller bug, and the ledger says so in the one place a reader will look. It is
// written in R37's closed set like every other capture gap — the mode the contract compiled to is the
// mechanism that is unavailable — so a reader filtering on the set never meets a value outside it.
func (r *runner) emitCaptureGaps() {
	for _, g := range r.deps.CaptureGaps {
		if g.What == "" {
			g.What = record.GapCapture
		}
		r.emitGap(g)
	}
	// Only a capture gap counts: startKernelRecord's what=record gap says nothing about capture.
	captureGaps := 0
	for _, g := range r.deps.CaptureGaps {
		if g.What == "" || g.What == record.GapCapture {
			captureGaps++
		}
	}
	want := string(r.rt.Capture)
	if want != string(agent.CaptureOff) && len(r.captureSources()) == 0 && captureGaps == 0 {
		r.emitGap(source.Gap{What: record.GapCapture, Why: derive.GapMechanismUnavailable, Binary: want})
	}
}

// emitPriceGap records that this run has no price table, once, right after run_start (E15, R32).
// The caller loaded the table and printed the warning; this is the ledger's half of it, and it is
// written whether or not the run ever sees an ssl_response, because what it says is that no cost
// ceiling could be enforced at all — not that one response could not be priced. The budget watcher
// is told the same reason (newBudget), so this is the run's only whole-table gap.
func (r *runner) emitPriceGap() {
	if r.deps.PriceGap == "" {
		return
	}
	r.emitGap(source.Gap{What: record.GapRecord, Why: r.deps.PriceGap})
}

// emitBudgetUnmeteredGaps records, right after run_start, each tokens, cost_usd or repeats budget that no
// capture source meters: run_start.capture is off (captureMode), because the contract or the machine turned
// capture off, or the forwarder had no models: endpoint to listen for and the uprobe source did not run. Such
// a budget never trips, and the run said so only through a capture gap that names no budget (limits-check-doctor-cli.md R32).
// A budget the contract declares never gets here: refuseUncountedBudget refused the run before run_start, so the
// gap is for a budget a machine ceiling alone imposes.
func (r *runner) emitBudgetUnmeteredGaps() {
	if r.rt == nil || r.captureMode() != string(agent.CaptureOff) {
		return
	}
	for _, b := range []struct {
		set  agent.BudgetSet
		name string
	}{{agent.BudgetTokens, "tokens"}, {agent.BudgetCostUSD, "cost_usd"}, {agent.BudgetRepeats, "repeats"}} {
		if r.rt.Limits.Bounded(b.set) {
			r.emitGap(source.Gap{What: record.GapRecord, Why: GapBudgetUnmetered, Binary: b.name})
		}
	}
}

// allSources is every producer this run owns, in start order. The kernel recorder joins the list
// only once the enforcement handle has named its ring buffer, which is after Prepare, so it lives on
// the runner rather than in Deps. It starts before the capture sources, and through recorderFirst: a
// follower it drives may only capture once the recorder has decided to read (kernelhook.go).
func (r *runner) allSources() []source.Source {
	var out []source.Source
	if r.deps.Observe != nil {
		out = append(out, r.deps.Observe)
	}
	if r.kernelRecord != nil {
		out = append(out, recorderFirst{Source: r.kernelRecord, r: r})
	}
	return append(append(out, r.deps.Capture...), r.deps.Extra...)
}

// captureSources are the run's model-traffic producers, the only ones that raise ssl_request and
// ssl_response: capture.Select's forwarder and uprobe sources, which the caller wires into
// Deps.Capture.
//
// It is deliberately not allSources(). Deps.Observe and r.kernelRecord are the tier's own eBPF
// recorders and produce fs/net/exec events only, so a run that has one of those and no capture source
// still has no model turn to derive a step from and nothing to satisfy the contract's `capture:`
// with. Asking allSources() instead is how a tier-2 run with `capture: off` came to claim
// attribution method `time` on every action, and how one with `capture: full` and no source wired
// came to record no capture gap at all.
func (r *runner) captureSources() []source.Source { return r.deps.Capture }

// allSources is the same list before a runner exists, which is where the loopback admission reads it
// (newRunner builds the enforced table from it).
func allSources(deps Deps) []source.Source {
	var out []source.Source
	if deps.Observe != nil {
		out = append(out, deps.Observe)
	}
	return append(append(out, deps.Capture...), deps.Extra...)
}

// ref is what sources and backends are told about the run.
func (r *runner) ref() source.RunRef {
	ref := source.RunRef{ID: string(r.id), Agent: string(r.agentID), Dir: r.dir, RuntimeDir: r.runtimeDir,
		CgroupID: r.cg.ID, Contract: r.rt}
	if r.writer != nil {
		ref.BlobBytes = r.writer.BlobBytes()
	}
	return ref
}

// startKernelRecord builds the tier's own recorder now that its ring buffer has a name (§4.1 step 3).
//
// A tier that writes no ring buffer, or a build with no factory, leaves it nil and the run records a
// gap instead: a run whose kernel record is absent must say so, because a silence reads the same as a
// run where nothing happened (P0-DESIGN §6). A factory that fails is the same case — the tier is still
// enforcing, and losing its record is not a reason to fail the run.
func (r *runner) startKernelRecord(h api.Handle) {
	kr, ok := h.(enforce.KernelRecorder)
	if !ok {
		return // tier 1: the supervisor is the only producer and writes events directly
	}
	if r.deps.ObserveFactory == nil {
		r.deps.CaptureGaps = append(r.deps.CaptureGaps, source.Gap{
			What: record.GapRecord, Why: GapKernelRecordUnavailable, Count: 1,
		})
		return
	}
	src, err := r.deps.ObserveFactory(kr.BPFHash())
	if err != nil || src == nil {
		if err != nil {
			r.log.Warn("runtime: kernel record unavailable", "err", err)
		}
		r.deps.CaptureGaps = append(r.deps.CaptureGaps, source.Gap{
			What: record.GapRecord, Why: GapKernelRecordUnavailable, Count: 1,
		})
		return
	}
	r.kernelRecord = src
	handPreparedMounts(h, src)
	if tracker, ok := src.(TrackingFailureReporter); ok {
		tracker.SetTrackingFailure(r.failTracking)
	}
	r.followKernelRecord(kr.BPFHash(), src)
	// Under record: off the recorder keeps no line for an allowed exec, open or connect, so the budget watcher saw a
	// tier-2 agent busy with allowed work as idle, and its stall check killed it (R4). Each of the run's samples is
	// activity instead, as each notification the supervisor answers is at tier 1. The budget is made later
	// (startWorkers), before any source starts. Under off the kernel writes a sample only for an exec, a process's
	// exit and a refusal: an allowed open (read or write), path change or connect returns before reserving one
	// (trace_proc's tego_recording checks) and stamps the run's slot of tego_activity instead when a stall_after
	// bounds the run, which the watcher pulls through the recorder's LastActivity (wireKernelActivity), so one the
	// decision plane decides without notifying the supervisor is activity too (it was none, and compile warned it).
	// What the supervisor is notified of, a connect, a send, an exec, and an open or path
	// change the contract's gate or ask entries keep notified, is activity through its own hook (startWorkers)
	// whatever this recorder writes.
	if a, ok := src.(ActivityReporter); ok && r.rt != nil && r.rt.Record == agent.RecordOff {
		a.SetActivity(func(monoNS uint64) {
			if r.budget != nil {
				r.budget.Touch(monoNS)
			}
		})
	}
}

// TrackingFailureReporter is a recorder that detects loss of enforcement membership.
// The handler is installed before sources start.
type TrackingFailureReporter interface{ SetTrackingFailure(func(error)) }

// KernelReading is a kernel recorder that can say whether it still reads the run's ring: false once its
// drain has failed (observe.Recorder.Reading), from which point its gap says the record is incomplete.
type KernelReading interface {
	Reading() bool
}

// decideKernelRecord publishes whether the run's kernel recorder reads this run's ring, once startWorkers has
// started the run's sources (started) or failed to, and releases every kernelConnects waiting on it.
func (r *runner) decideKernelRecord(started bool) {
	r.kernelReads = started && r.kernelRecord != nil && !kernelRecordInert(r.kernelRecord)
	close(r.kernelDecided)
}

// kernelConnects is the supervisor's Options.KernelConnects: whether the run's kernel recorder writes the
// line of an IP connect the agent makes itself. The supervisor asks after it has answered the connect, and
// the answer waits for startWorkers to have started the recorder, which it does just after the supervisor's
// loop: until then nobody knows whether the recorder will read this run (kernelRecordInert), and a
// connect answered in that window must keep one line either way. A cancelled run answers false, so the
// supervisor keeps its own line rather than wait on a start that will not come.
func (r *runner) kernelConnects(ctx context.Context) func() bool {
	decided, rec := r.kernelDecided, r.kernelRecord
	return func() bool {
		if decided == nil {
			return false // nothing will decide: the supervisor keeps its own line
		}
		// A decision already made wins over a cancelled run: when both are ready select picks at random, and
		// picking the cancellation would have the supervisor write its line beside the recorder's.
		select {
		case <-decided:
		default:
			select {
			case <-decided:
			case <-ctx.Done():
				return false
			}
		}
		if !r.kernelReads {
			return false
		}
		if kr, ok := rec.(KernelReading); ok {
			return kr.Reading()
		}
		return true
	}
}

// ContinuedNetNamer is a kernel recorder that names the IP connects the supervisor continues with the
// supervisor's own lookup (observe.Recorder.SetContinuedNet).
type ContinuedNetNamer interface {
	SetContinuedNet(fn func(ap netip.AddrPort, proto string) (rule, host string, v record.Verdict, ok bool))
}

// nameKernelConnects hands the run's kernel recorder the supervisor's lookup for a connect it continues
// (supervisor.Loop.ContinuedNet). The supervisor writes no line for such a connect while the recorder reads
// (kernelConnects), so the recorder's is the connect's only line and must name it as the supervisor's would
// have: net.resolver for a DNS query, the capture listener's grant, the resolved-address check's refusals
// (supervisor.md R7, enforce-cgroup-observe §5 R5). Called once the loop exists and before any source starts.
func (r *runner) nameKernelConnects(fn func(ap netip.AddrPort, proto string) (rule, host string, v record.Verdict, ok bool)) {
	if n, ok := r.kernelRecord.(ContinuedNetNamer); ok {
		n.SetContinuedNet(fn)
	}
}

// ContinuedFSNamer is a kernel recorder that names a filesystem action the supervisor continued and left to its
// line with the supervisor's own naming, and writes no exec line of its own (observe.Recorder.SetContinuedFS,
// SetSupervisorExecs).
type ContinuedFSNamer interface {
	SetContinuedFS(fn func(tid int, op, name, name2 string, at uint64) (path, path2, rule string, v record.Verdict, reason record.Reason, ok bool))
	SetSupervisorExecs(on bool)
}

// ContinuedExecNamer accepts bounded naming metadata for terminal kernel exec
// outcomes. Readiness is distinct from Reading: callbacks are wired before the
// source starts, and the supervisor waits for its startup decision separately.
type ContinuedExecNamer interface {
	SetContinuedExec(func(tid, pid int, startNS, at uint64) (supervisor.ExecNaming, bool))
	SetExecResults(bool)
	ExecHandoverReady() bool
}

func (r *runner) superviseKernelExec(fn func(tid, pid int, startNS, at uint64) (supervisor.ExecNaming, bool)) {
	r.superviseExecPins()
	if n, ok := r.kernelRecord.(ContinuedExecNamer); ok {
		n.SetContinuedExec(fn)
		coverage, ok := r.handle.(enforce.ExecOutcomeReporter)
		on := ok && coverage.ExecOutcomes() && r.planeDecides()
		n.SetExecResults(on)
		if on {
			if owner, ok := r.kernelRecord.(interface{ SetSupervisorExecs(bool) }); ok {
				owner.SetSupervisorExecs(false)
			}
		}
	}
}

func (r *runner) kernelExecHandoff(ctx context.Context) func() bool {
	reading := r.kernelConnects(ctx)
	return func() bool {
		n, ok := r.kernelRecord.(ContinuedExecNamer)
		return ok && n.ExecHandoverReady() && reading()
	}
}

// superviseKernelRecord hands the run's kernel recorder the supervisor's naming of the fs actions it leaves to
// the recorder's line, and tells it whether the supervisor writes every exec's line (supervisor.md R7a): it does
// unless the kernel decision plane decides the run's execs, and it names the plane's mode. Called once the loop
// exists and before any source starts.
func (r *runner) superviseKernelRecord(fn func(tid int, op, name, name2 string, at uint64) (supervisor.FSNaming, bool)) {
	r.handListenerToKernelRecord()
	n, ok := r.kernelRecord.(ContinuedFSNamer)
	if !ok {
		return
	}
	n.SetContinuedFS(func(tid int, op, name, name2 string, at uint64) (string, string, string, record.Verdict, record.Reason, bool) {
		f, ok := fn(tid, op, name, name2, at)
		return f.Path, f.Path2, f.Rule, f.Verdict, f.Reason, ok
	})
	if enriched, ok := r.kernelRecord.(interface {
		SetContinuedFSInfo(func(int, string, string, string, uint64) (supervisor.FSNaming, bool))
	}); ok {
		enriched.SetContinuedFSInfo(fn)
	}
	n.SetSupervisorExecs(!r.planeExecs())
	if p, ok := r.kernelRecord.(DecisionPlaneNamer); ok {
		if dp, ok := r.handle.(enforce.DecisionPlaneReporter); ok {
			mode, _ := dp.DecisionPlane()
			p.SetDecisionPlane(mode)
		}
	}
}

// DecisionPlaneNamer is a kernel recorder that names the kernel decision plane's mode on the lines whose verdict
// the plane gave (observe.Recorder.SetDecisionPlane).
type DecisionPlaneNamer interface {
	SetDecisionPlane(mode string)
}

// decisionPlane is run_start's decision_plane (enforce-plane R19, I7): the mode a tier with the plane seam decides
// in, record.DecisionPlaneFanotify for one on the listener (tier cgroup's fallback), "" for a tier with no plane.
func (r *runner) decisionPlane() string {
	dp, ok := r.handle.(enforce.DecisionPlaneReporter)
	if !ok {
		return ""
	}
	if mode, _ := dp.DecisionPlane(); mode != "" {
		return mode
	}
	return record.DecisionPlaneFanotify
}

// planeDecides reports whether a kernel decision plane mode decides this run's fs actions
// (enforce.DecisionPlaneReporter).
func (r *runner) planeDecides() bool {
	dp, ok := r.handle.(enforce.DecisionPlaneReporter)
	if !ok {
		return false
	}
	mode, _ := dp.DecisionPlane()
	return mode != ""
}

// planeExecs reports whether the run's kernel decision plane decides its execs (enforce.DecisionPlaneReporter):
// then the kernel writes each continued exec's one line and the supervisor none (supervisor.md R7a).
func (r *runner) planeExecs() bool {
	dp, ok := r.handle.(enforce.DecisionPlaneReporter)
	if !ok {
		return false
	}
	mode, execs := dp.DecisionPlane()
	return mode != "" && execs
}

// ActivityReporter is a kernel recorder that can report the run's activity it keeps no line for
// (observe.Recorder.SetActivity).
type ActivityReporter interface {
	SetActivity(fn func(monoNS uint64))
}

// ActivityStamper is a kernel recorder that reads the run's activity stamp, the newest action the BPF programs saw
// the run make that no line or sample carries (observe.Recorder.LastActivity): a CLOCK_MONOTONIC reading, 0 for
// none. The watcher pulls it at each Tick under a stall budget (wireKernelActivity).
type ActivityStamper interface {
	LastActivity() uint64
}

// StreamActivityReporter is a capture source that relays model traffic and can report the bytes it carries as
// activity, at a grain of its own (forwarder.Manager.SetStreamActivity): in every record mode, where
// ActivityReporter is record: off's. fn is the budget watcher's Touch; the source calls it with its own
// CLOCK_MONOTONIC reading.
type StreamActivityReporter interface {
	SetStreamActivity(fn func(monoNS uint64))
}

// attributeStage is the pipeline's attribute step (§4.1 step 4), and which one it is depends on whether
// this run can see the model's turn structure at all.
//
// With a capture source running, derive.Steps folds each ssl_request and ssl_response into a per-thread
// step and attributes every action to the turn it fell in (R33-R36): the M2 half of P0-DESIGN §5's
// "Attribution: none (M1) → time (M2)". It is the honest method precisely because it refuses to guess
// between two concurrent turns and says unattributed instead.
//
// With no capture there is nothing to derive from. Running the time method anyway would label every
// action "unattributed by time", claiming a method that had no input; method none says what actually
// happened, which is that no attribution was attempted.
//
// "No capture" is captureSources(), not every producer: the tier's own kernel recorder raises fs, net
// and exec events and never an ssl_request, so it can no more feed derive.Steps than nothing can.
func (r *runner) attributeStage() Stage {
	if len(r.captureSources()) == 0 {
		return nil // newPipeline falls back to method none
	}
	s := derive.NewSteps(modelHosts(r.rt)...)
	r.steps = s
	r.followExits(s)
	return s.Stage
}

// modelHosts are the declared models[] hosts, which are the only ones whose requests open a step. A
// contract with none leaves the list empty, and then every ssl_request opens one — which is what the
// forwarder produces, since a listener only ever serves a declared entry.
func modelHosts(rt *agent.RuleTable) []string {
	if rt == nil || rt.Contract == nil {
		return nil
	}
	out := make([]string, 0, len(rt.Contract.Models))
	for _, m := range rt.Contract.Models {
		if m.Host != "" {
			out = append(out, m.Host)
		}
	}
	return out
}

// captureMode is the capture this run really has, read off the mechanisms that were started rather than
// the mode the contract compiled to. The two differ in the ordinary case: rt.Capture is resolved against
// the machine's ceiling, not against the tier that ran, so an auto contract on an unbounded machine
// compiles to uprobe and then runs at tier 1 with the forwarder alone. A started uprobe source is capture:
// uprobe (the forwarder beside it belongs to that mode, capture-derive.md §4), the forwarder alone is
// capture: forwarder, and nothing started is off. What the contract wanted and did not get is a selection
// gap, written right after run_start, so a reader never has to guess why the two disagree.
//
// Only captureSources() count, for the reason that function gives: the tier's kernel recorder raises no
// ssl event, and counting it is how a tier-2 run with no capture source came to claim capture. Of those,
// only the ones whose mechanism runs count (startedCapture): an uprobe source that could not load its
// capture object starts without error and captures nothing. Sources are matched by name, which
// capture.Select keeps equal to the mode each one provides; a capture source with any other name is
// nothing the CLI wires, and is taken at the contract's word because no truer name exists for it.
func (r *runner) captureMode() string {
	mode := agent.CaptureOff
	for _, s := range r.startedCapture() {
		switch m := agent.CaptureMode(s.Name()); m {
		case agent.CaptureUprobe:
			return string(m)
		case agent.CaptureForwarder:
			mode = m
		default:
			if mode == agent.CaptureOff {
				mode = r.rt.Capture
			}
		}
	}
	return string(mode)
}

// emitSourceGaps records what each source could not cover, as the last events before run_end.
func (r *runner) emitSourceGaps() {
	for _, s := range r.sources {
		for _, g := range s.Gaps() {
			r.emitGapNow(g)
		}
	}
}

// emitPlaneGaps records the kernel decision plane's fail-closed counters of the run's slot (enforce-plane §2.8): one
// gap what=enforce line per counter that is not zero, naming the plane's mode, as the last lines before run_end. It
// runs once the run's cgroup has emptied, so no process of the run can still count, and before the handle's Detach,
// which runs after run_end and whose next Prepare of the slot zeroes them. A slot it cannot read is one
// GapPlaneCountersUnread line with no count. A run with no plane mode has no counters of its own.
func (r *runner) emitPlaneGaps() {
	dp, ok := r.handle.(enforce.DecisionPlaneReporter)
	if !ok {
		return
	}
	mode, _ := dp.DecisionPlane()
	cr, ok := r.handle.(enforce.PlaneCounterReporter)
	if mode == "" || !ok {
		return
	}
	counts, err := cr.PlaneCounters()
	if err != nil {
		r.log.Warn("run: read the decision plane's counters", "err", err)
		r.emitGapNow(source.Gap{What: record.GapEnforce, Why: record.GapPlaneCountersUnread, DecisionPlane: mode})
		return
	}
	for _, c := range counts {
		if c.Count == 0 {
			continue
		}
		n := int64(math.MaxInt32)
		if c.Count < uint64(n) {
			n = int64(c.Count)
		}
		r.emitGapNow(source.Gap{What: record.GapEnforce, Why: c.Why, Count: n, DecisionPlane: mode})
	}
}

// emitGap queues a gap event; used before the pipeline is draining.
func (r *runner) emitGap(g source.Gap) {
	if ev := gapEvent(g); ev != nil && r.queue != nil {
		r.queue.Emit(ev)
	}
}

// emitGapNow writes a gap through the stage chain directly: the producers have stopped and the
// queue is drained, so there is no goroutine left to pick it up.
func (r *runner) emitGapNow(g source.Gap) {
	if ev := gapEvent(g); ev != nil && r.pipe != nil {
		r.pipe.handle(ev)
	}
}

// gapEvent builds one gap event.
func gapEvent(g source.Gap) *record.Event {
	ev := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor}
	if err := ev.SetPayload(record.GapPayload{What: g.What, Why: g.Why, Binary: g.Binary, Count: int(g.Count),
		DecisionPlane: g.DecisionPlane}); err != nil {
		return nil
	}
	return ev
}

// ListenerDevicesSetter receives the devices actually marked for ordinary entries.
type ListenerDevicesSetter interface{ SetListenerDevices(func(dev uint64) bool) }

// handPreparedMounts keeps recorder attribution on the facts used by Prepare,
// including adoption, whose sources start without the ordinary launch path.
func handPreparedMounts(h api.Handle, src source.Source) {
	if mounts, ok := h.(enforce.MountTableReporter); ok {
		if dst, ok := src.(interface {
			SetMountTable(*agent.MountTable, error)
		}); ok {
			dst.SetMountTable(mounts.MountTable())
		}
	}
}

func (r *runner) handListenerToKernelRecord() {
	s, ok := r.kernelRecord.(ListenerDevicesSetter)
	if !ok {
		return
	}
	rep, ok := r.handle.(enforce.ListenerDevicesReporter)
	if !ok {
		return
	}
	if marked, ok := rep.ListenerDevices(); ok {
		s.SetListenerDevices(marked)
	}
}
