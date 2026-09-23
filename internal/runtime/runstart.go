// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// GapUnprivilegedTier is the gap a run writes when the reads SEMANTICS §7 promises as individual events —
// every read of a deny_read or fs.watch path — cannot reach its record (FEATURES E56).
const GapUnprivilegedTier = "unprivileged-tier"

// capabilityLine is run_start.capabilities: what this run could do, one entry per row of
// spec/backend/CAPABILITIES.md in pkg/spec/backend's spelling, false included (docs/p0/record-ledger.md
// §2.2). The row the tier advertises is a claim about the tier; this is the claim about the run, which is
// what "the runtime degrades by matrix, never silently" (FEATURES S5) needs a reader to be able to see. A
// false is a statement written into a hash-chained record, so each row is either the enforcement handle's
// own answer or set here from what this run did.
//
// It starts from the handle's own set when the handle reports one (enforce.Reporter), because that set is
// already narrowed by what Prepare found: a deny_read entry left unenforced under a writable parent
// (enforce-landlock.md R4), the Landlock ABI the kernel offered (R19), the unix entries the tier-2 handle
// leaves to tier 1 (enforce-cgroup-observe.md R7). A handle that reports nothing falls back to the backend's
// row. Then the rows only this package can answer are set from the run itself:
//
//   - capture.model_traffic is true exactly when run_start.capture, the same captureMode value passed in
//     here, is not off. It is set rather than narrowed, because the observe row is empty and an observe run
//     with a forwarder does capture.
//   - An observe run records through tier 1's filter and supervisor (supervisor.md R30), so its record rows
//     are tier 1's; its empty row speaks only for enforcement.
//   - record: off keeps refusals and nothing else (supervisor events.go recording(), the kernel's
//     TEGO_RECORD_OFF), so none of the record rows holds.
//   - Reads are cleared when they cannot reach the record at all (readsUnrecorded).
//   - net.http_rules is true only for this run's started policy-bearing forwarder.
//   - The rows no contract this binary loads can ask for are false on every run (notInThisPhase).
//   - gate.net_completion is the supervisor's relay (ADR 0041 D6), so it holds only while a started supervisor
//     answers the run's notifications, as ask does.
//   - fs.protected_write_targets holds exactly where a kernel decision plane mode decides the run (planeDecides):
//     the same reading run_start.best_effort's deny_write/default takes from decision_plane, so the row and the
//     cell can never disagree (ADR 0041 D7).
func (r *runner) capabilityLine(capture string) map[string]bool {
	var set backend.Set
	if rep, ok := r.handle.(enforce.Reporter); ok {
		set = rep.Capabilities()
	} else {
		set = r.deps.Enforce.Capabilities()
	}
	set = set.Clone()
	if set == nil {
		set = backend.Set{}
	}
	set[backend.CapCaptureModel] = capture != string(agent.CaptureOff)
	set[backend.CapNetHTTPRules] = r.httpPolicyReady()
	// The supervisor owns the notify fd before run_start. The runner's old fd
	// number is cleared at that transfer and cannot describe live readiness.
	set[backend.CapAsk] = r.rt.AskConfig != nil && r.askBroker.Available() && r.sup != nil && r.sup.Started() && r.deps.Enforce.Tier() != backend.TierObserve && !recordsOnly(r.handle)
	set[backend.CapGateNetCompletion] = set.Has(backend.CapGateNetCompletion) && r.sup != nil && r.sup.Started() && !recordsOnly(r.handle)
	// ADR 0041 Stage B: the gate's opens are completed on the object scored only where the contract chose held
	// completion and its open deputy serves the run's supervisor; the deputy's degrade leaves them best effort. A deputy
	// started only for held reads (ADR 0069) holds no gate open: the row reads the gate's own key, never the deputy alone.
	set[backend.CapGateFSOpenCompletion] = r.deputy != nil && r.rt.GateOpensHeld() && r.sup != nil && r.sup.Started() && !recordsOnly(r.handle)
	set[backend.CapProtectedWriteTargets] = r.planeDecides()
	// Held reads (ADR 0069): the run's open deputy completes every read-capable open and its floor refuses a deny_read
	// inside a write entry, and a file a name rule covers made during the run, on the object reached. Without them
	// neither holds at tier landlock, whatever the tier's column says; a moved or hard-linked target is never caught
	// there (the matrix's own false).
	if r.readsHeldServed() {
		set[backend.CapReadDeny] = true
		set[backend.CapReadDenyNested] = true
		set[backend.CapReadDenyCreatedLater] = true
	} else if t := r.deps.Enforce.Tier(); t == backend.TierLandlock || t == backend.TierObserve || recordsOnly(r.handle) {
		set[backend.CapReadDenyNested] = false
		set[backend.CapReadDenyCreatedLater] = false
	}
	net := r.networkGuarantees()
	set[backend.CapTCPDestinationKernel] = net.TCPDestination
	set[backend.CapUDPByDestination] = net.UDPDestination
	set[backend.CapUnixDestinationKernel] = net.UnixDestination
	set[backend.CapSocketFamilies] = net.SocketFamilies
	set[backend.CapHostSocketsRefused] = set.Has(backend.CapHostSocketsRefused) && r.rt.HostSocketsRefused() && r.sup != nil && r.sup.Started() && !recordsOnly(r.handle)
	if r.deps.Enforce.Tier() == backend.TierObserve {
		tier1 := backend.Matrix(backend.TierLandlock)
		for _, c := range recordRows {
			set[c] = tier1.Has(c)
		}
	}
	if r.rt.Record == agent.RecordOff {
		for _, c := range recordRows {
			set[c] = false
		}
	}
	if r.readsUnrecorded() {
		set[backend.CapRecordReads] = false
	}
	for _, c := range notInThisPhase {
		set[c] = false
	}
	all := backend.AllCapabilities()
	out := make(map[string]bool, len(all))
	for _, c := range all {
		out[string(c)] = set.Has(c)
	}
	return out
}

// recordRows are the matrix rows about what the record keeps rather than what is enforced: the ones the
// record mode and the recording mechanism decide, which is why capabilityLine sets them from the run.
var recordRows = []backend.Capability{backend.CapRecordExecOpenNet, backend.CapRecordReads, backend.CapLogAllowed}

// notInThisPhase are rows a tier's column marks present that no run of this binary can use, because
// the only way to ask for them is a contract field the loader refuses as not yet supported (agent-contract
// R2): containers: rootless is what the
// namespace-sandbox row needs, and the containers a daemon creates are governed by docker:, P1, and adopted
// only by E42's run-set membership, P2. "true when this run could do it" is false for these rows. The static
// matrix keeps them, because it describes the tier, and TestNotInThisPhaseIsRefusedByTheLoader fails the day
// the loader accepts one of these fields, which is the day its row has to leave this list.
var notInThisPhase = []backend.Capability{
	backend.CapAdoptedContainers, backend.CapNamespaceSandbox,
}

// startedCapture is captureSources() without the sources whose mechanism is not running although their Start
// returned nil. captureMode reads it, and writeRunStart hands that one value to both run_start.capture and the
// capability line's capture row, so the two cannot disagree.
//
// A source that follows the kernel record (KernelFollower) is also left out when no recorder reads for this
// run: nothing then hands it an exec or an open, so it attaches nothing whatever its own Start decided.
// recorderFirst withdraws such a follower before it starts, and its own gap then says so; this is the same
// statement made from the recorder's side, so run_start cannot claim a follower's capture whatever order the
// two were started in.
func (r *runner) startedCapture() []source.Source {
	driven := r.kernelRecord != nil && !kernelRecordInert(r.kernelRecord)
	var out []source.Source
	for _, s := range r.captureSources() {
		if mechanismUnavailable(s) {
			continue
		}
		if _, follows := s.(source.KernelFollower); follows && !driven {
			continue
		}
		out = append(out, s)
	}
	return out
}

// mechanismUnavailable reports whether s has already said, in its own gaps, that its mechanism is not running
// for this run: gap what=capture why=mechanism-unavailable with s's own name as the binary (capture-derive.md
// R37). A source may start and still be in that state, because a capture object the kernel will not load is
// one gap and never a failed run (§4): the uprobe source's Start returns nil with no kernel record to follow
// or a collection that will not load, and records exactly this gap. So a nil error from Start is no evidence
// that anything captures. Without this check run_start would claim capture: uprobe for a run whose only uprobe
// line is the gap, written at run end, saying it never ran.
//
// The gap is asked for rather than an extra method, because it is the one statement every capture source
// already makes (Source.Gaps) and the ledger will carry either way; run_start agreeing with it is the point.
func mechanismUnavailable(s source.Source) bool {
	for _, g := range s.Gaps() {
		if (g.What == "" || g.What == record.GapCapture) && g.Why == derive.GapMechanismUnavailable &&
			g.Binary == s.Name() {
			return true
		}
	}
	return false
}

// readsHeldServed reports whether this run holds its read opens (fs.reads, ADR 0069): its table holds them at its tier
// and its open deputy serves a started supervisor.
func (r *runner) readsHeldServed() bool {
	return r.rt.ReadsHeld() && r.deputy != nil && r.sup != nil && r.sup.Started() && !recordsOnly(r.handle)
}

// readsUnrecorded reports whether this run's read-opens never reach its record: tier 1's filter was built
// without them (tier1ReadsUnnotified), or the tier records reads from a kernel ring buffer that nothing is
// draining and the tier-1 filter it inherits was built without them too. Nothing drains the ring when no
// recorder was built, which startKernelRecord has reported as a gap of its own, and when the recorder
// started but reads nothing, which its own kernel-record-unavailable gap says (kernelRecordInert): it could
// not name the run's slot or open the run's ring (enforce-cgroup-observe.md §2 "Run scope"). The inherited filter notifies read-opens under record: full, as tier 1's does, and the supervisor
// records them then with or without the ring.
//
// It is the reads row alone. Exec, write-open and connect reach the supervisor through the inherited filter
// at every record mode (enforce-landlock.md R15, enforce-cgroup-observe.md §5 R1), so a tier-2 run whose
// ring nobody drains still records them, and record.exec_open_connect stays the tier's answer.
func (r *runner) readsUnrecorded() bool {
	if r.tier1ReadsUnnotified() {
		return true
	}
	_, kernel := r.handle.(enforce.KernelRecorder)
	drained := r.kernelRecord != nil && !kernelRecordInert(r.kernelRecord)
	return kernel && !drained && r.deps.Observe == nil && r.rt.Record != agent.RecordFull
}

// kernelRecordInert reports whether a kernel recorder that started has already said, in its own gaps, that it
// reads nothing for this run: gap what=record why=kernel-record-unavailable. Its Start returns nil in that
// state, as a capture source's does for mechanism-unavailable (mechanismUnavailable), because a record the
// tier cannot give this run is a gap and never a failed run.
func kernelRecordInert(s source.Source) bool {
	for _, g := range s.Gaps() {
		if g.What == record.GapRecord && g.Why == GapKernelRecordUnavailable {
			return true
		}
	}
	return false
}

// tier1ReadsUnnotified reports whether the run's only record of an open is tier 1's seccomp filter and that
// filter was built without read-opens. It notifies them only under record: full, because notifying every
// read is exactly what makes that mode slow (enforce-landlock.md R9-R13, SEMANTICS §7). An observe run
// installs the same filter with the same switch and no Landlock ruleset, so the same is true of it. A run that
// holds its reads (ADR 0069), has an fs.ask_read entry or notifies them for the reason channel (ADR 0077) is
// notified of every open, but its supervisor writes no line for an allowed read unless the record mode keeps reads
// (heldQuiet, quietRead), so for its record the answer is the same: only a refused read is a line.
func (r *runner) tier1ReadsUnnotified() bool {
	switch r.deps.Enforce.Tier() {
	case backend.TierLandlock, backend.TierObserve:
		return r.rt.Record != agent.RecordFull
	case backend.TierCgroup, backend.TierBPFLSM, backend.TierAuto:
	}
	return false
}

// emitWatchedReadGap writes gap what=record why=unprivileged-tier once, right after run_start, when this run
// has paths whose every read SEMANTICS §7 promises to record individually and cannot record any of them
// (E56). Without it a deny_read or fs.watch path read under record: summary reads, in the ledger, exactly
// like a path nobody touched — and so does a read Landlock refused, since that refusal happens inside a
// syscall the filter never notified, unless the run notifies reads for the reason channel (ADR 0077).
//
// The filter cannot be narrowed to the watched paths instead: classic BPF sees openat's path argument as a
// pointer, never as the string it points to, so the only way tier 1 sees a watched read is to be told of
// every read, which is record: full. The built-in deny_read entries count like declared ones — the secret
// paths are the reads a reader of the record looks for first.
func (r *runner) emitWatchedReadGap() {
	if !r.tier1ReadsUnnotified() || !watchesReads(r.rt, r.readsHeldServed(), r.reasonReadsServed()) {
		return
	}
	r.emitGap(source.Gap{What: record.GapRecord, Why: GapUnprivilegedTier})
}

// watchesReads reports whether the table has a path whose reads are always individual events (SEMANTICS §7):
// a deny_read entry, declared or built in, or an fs.watch entry. Where the run holds its reads (held), every read of a
// deny_read target is refused by the supervisor with its line (ADR 0069), so only a watch entry counts; where it
// notifies them for the reason channel (reason, ADR 0077), every read of a target the Landlock ruleset enforces is a
// refused line, so a deny_read entry counts only while the ruleset leaves it unenforced (enforce-landlock R4), whose
// allowed reads stay unrecorded.
func watchesReads(rt *agent.RuleTable, held, reason bool) bool {
	for _, f := range rt.FS {
		if f.Kind == agent.FSDenyRead && !held && (!reason || f.Unenforced) || f.Kind == agent.FSWatch {
			return true
		}
	}
	return false
}

// reasonReadsServed reports whether this run notifies every read open for the reason channel (ADR 0077): its table
// does at its tier and a started supervisor answers the notifications.
func (r *runner) reasonReadsServed() bool {
	return r.rt.ReasonReadsNotified() && r.sup != nil && r.sup.Started() && !recordsOnly(r.handle)
}
