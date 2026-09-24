// SPDX-License-Identifier: Apache-2.0

package status

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/attention-span-ai/tego/internal/check/gaps"
	"github.com/attention-span-ai/tego/internal/check/resources"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// State is the run state a reader derives (P0-DESIGN §5, docs/p0/limits-check-doctor-cli.md R7-R12).
type State string

// The states, in the order Derive checks them; the first match wins.
const (
	// Done is a finished run: nobody holds the lock and run_end is on disk.
	Done State = "done"
	// NeverStarted is a run with no ledger line and nobody holding its lock: its launcher stopped, or died,
	// before run_start (an unwind that abandoned it, §6 case 1). Nothing ran, so there is nothing to end, and
	// the sweep treats it as empty (ledger.StateEmpty); it is not a finding.
	NeverStarted State = "never started"
	// Lost is a run whose launcher died without writing run_end; the sweep will end it.
	Lost State = "lost"
	// Stalled is a live run that has recorded nothing for stall_after.
	Stalled State = "stalled"
	// WaitingModel is a live run with a model request that has no response yet.
	WaitingModel State = "waiting model"
	// WaitingTool is a live run whose last model response asked for a tool and has not been
	// followed by another request.
	WaitingTool State = "waiting tool"
	// WaitingApproval is a live run with a recorded ask and no matching answer.
	WaitingApproval State = "waiting approval"
	// Running is a live run doing something else.
	Running State = "running"
)

// askAnswerBound is the longest ask.timeout a policy can declare (spec/policy/SEMANTICS.md §6, enforced by
// pkg/spec/agent's ask parser): run_start does not record the run's own, so status bounds a pending
// approval's precedence over R9 by it.
const askAnswerBound = time.Hour

// DefaultStallAfter is the machine default a run's own compiled stall_after falls back to when
// run_start carries no stall_after at all (R12); a declared "0s" is a budget, not an absence.
const DefaultStallAfter = time.Hour

// Snapshot is one run's state and the facts behind it (docs/p0/limits-check-doctor-cli.md §2).
type Snapshot struct {
	Run, Agent string
	// St is the derived state.
	St State
	// Since is the wall time of the event or check that produced this state.
	Since time.Time
	// SinceMonoNS is that event's monotonic reading, so a reader can tell a wall-clock step from
	// real elapsed time (§6 case 7).
	SinceMonoNS uint64
	// Step is the highest step seen on an attribution or a decision, as measure's Steps (R18).
	Step int
	// LastDecision and LastEvent are the events the state was read from; nil when there are none.
	LastDecision, LastEvent *record.Event
	// ExitReason and ExitCode are set only when St is Done.
	ExitReason string
	ExitCode   int
	// LockHeld is what the caller's lock probe said.
	LockHeld bool
	// Events is the number of complete events the ledger held.
	Events int
	// PendingApprovals counts bounded, unanswered asks while the run is live.
	PendingApprovals int
	// Idle is how long the run has recorded nothing, measured at now.
	Idle time.Duration
	// IdleClock names the clock Idle was measured on: ClockMonotonic for a live run, ClockWall when the
	// monotonic readings are not comparable (see idle).
	IdleClock string
	// IdleFrom names what Idle was measured from: IdleFromLedger, the newest non-gap line, or IdleFromActivity,
	// the launcher's activity sidecar when it is newer, which holds the activity the budget watcher counted
	// without a line (R9). The sidecar is read only while the lock is held.
	IdleFrom string
	// StallAfter is the ceiling Idle was compared against, and StallAfterSource says whether it
	// came from the run's own run_start.limits or from the machine default (R12).
	StallAfter       time.Duration
	StallAfterSource string
	// Gaps is every gap event the run recorded, grouped by what and why: the gap line (R34). It
	// qualifies the state above rather than changing it — a run that lost events is still running
	// or done — so it never enters state().
	Gaps []gaps.Count
	// Tier and Capabilities are run_start's tier and capability line (record-ledger.md §2.2), which
	// CapabilityLine renders (R-cap). Capabilities is nil for a ledger written before the line existed.
	Tier         string
	Capabilities map[string]bool
	// SkippedNewer is how many lines of a newer record version the reader skipped (ledger.Reader.
	// SkipNewerVersions), for the caller's one warning; never part of the state.
	SkippedNewer int
	// TegoVersion is run_start's tego_version: the binary that ran the run, never the one reading it
	// (limits-check-doctor-cli.md §6 case 9). "" before run_start.
	TegoVersion string
	// RunCommandGrant is run_start's run_command_grant: the file the command given on tego run's command
	// line was granted as for the whole run, "" when none was (agent-contract.md R8).
	RunCommandGrant string
	// BestEffort is run_start's best_effort: the run's disclosed best-effort cells (ADR 0041 D1, D7), nil
	// when it had none or its ledger predates the field.
	BestEffort []string
	// Ended is whether a run_end line is on disk, whatever the lock says: a run whose teardown is slow has
	// written it and is not Done yet (§6 case 4). Resources is that run_end's resources object (R-res), nil
	// while there is no run_end and when the run_end carries none; ResourcesLine renders both.
	// ResourcesRecorded is the same object as the ledger holds it, keys this binary does not know included,
	// for JSON.
	Ended             bool
	Resources         *record.Resources
	ResourcesRecorded json.RawMessage
	// LedgerBytes is the size of the run's events.jsonl when DeriveDir read it, 0 when it did not (Derive alone).
	// LedgerCeiling is run_start.limits.ledger_bytes, the machine's record.max_run_bytes the run started under, 0 for
	// none (record.MinorLedgerCap). LedgerLine renders both.
	LedgerBytes, LedgerCeiling int64
	// ExtraRunEnds is the number of run_end lines after the first, which a healthy writer never produces
	// (§6 case 5): the first by chain order is the run's end, and Anomalies names the rest.
	ExtraRunEnds int
}

// Anomalies are the ledger anomalies the snapshot met (§6 case 5), one line each, for the warning a CLI
// prints and --json's ledger_anomalies. Nil for a healthy ledger.
func (s *Snapshot) Anomalies() []string {
	if s.ExtraRunEnds == 0 {
		return nil
	}
	return []string{fmt.Sprintf("%d run_end lines; the first by chain order is the run's end and the other %d are ignored",
		s.ExtraRunEnds+1, s.ExtraRunEnds)}
}

// Sources of the stall_after ceiling.
const (
	SourceRunStart = "run_start"
	SourceMachine  = "machine-default"
)

// The clocks Idle can be measured on.
const (
	// ClockMonotonic is R4's measurement: now.MonoNS - LastEventMonoNS.
	ClockMonotonic = "monotonic"
	// ClockWall is the fallback for a run whose monotonic readings cannot be compared with this host's.
	ClockWall = "wall"
)

// What Idle was measured from (Snapshot.IdleFrom).
const (
	// IdleFromLedger is the newest non-gap line's mono_ns, R4's "last event" as the ledger has it.
	IdleFromLedger = "ledger"
	// IdleFromActivity is the run's activity sidecar (ledger.ActivityFile): activity the watcher's stall check
	// counted with no line for it — a supervisor answer or a kernel sample under record: off, a relayed model
	// chunk in any mode — so status measures the idle the watcher kills on.
	IdleFromActivity = "activity"
)

// Option configures Derive.
type Option func(*options)

type options struct {
	mono func() uint64
	ctx  context.Context
}

// ctxEvery is how many ledger lines Derive reads between looks at its context, the cadence events and
// measure use (limits-check-doctor-cli.md R29).
const ctxEvery = 1024

// WithContext makes Derive give up with the context's error, checked every ctxEvery lines, so a signal
// that cancelled it ends a read of a large ledger.
func WithContext(ctx context.Context) Option { return func(o *options) { o.ctx = ctx } }

// WithMonoNow replaces the CLOCK_MONOTONIC reading Idle is measured against. Tests script it; nothing in the
// product does.
func WithMonoNow(fn func() uint64) Option { return func(o *options) { o.mono = fn } }

// Derive reads one run and reports its state (R7-R12, checked in that order, first match wins).
//
// lockHeld is the caller's own flock probe — "live" is the lock and nothing else (invariant 1), and
// checking it before run_end is what keeps a run whose teardown is slow from ever reading as done
// too early (§6 case 4). now is the wall clock the idle time is measured against; stallAfter of 0
// means "take the run's own compiled ceiling from run_start.limits, else DefaultStallAfter".
//
// Idle is measured on the monotonic clock whenever the readings are comparable, per R4
// ("stall = now.MonoNS - LastEventMonoNS"), and falls back to the wall clock otherwise; IdleClock on the
// snapshot says which was used. See idle for why the fallback is never the case R9 decides.
func Derive(r *ledger.Reader, lockHeld bool, now time.Time, stallAfter time.Duration, opts ...Option) (*Snapshot, error) {
	if r == nil {
		return nil, fmt.Errorf("status: no reader")
	}
	o := options{mono: ledger.SystemClock{}.Mono}
	for _, opt := range opts {
		opt(&o)
	}
	s := &Snapshot{LockHeld: lockHeld, StallAfter: stallAfter, StallAfterSource: SourceRunStart}
	var (
		runEnd *record.RunEndPayload
		// openRequest is R10's "a request newer than the last response"; toolPending is R11's
		// "the last decision asked for a tool and no request followed it".
		//
		// R10's two halves qualify one request and together come to exactly this bool: a response is
		// always recorded after the request it answers, so a request newer than the last response is
		// by construction one that no ssl_response shares a request_id with. Keying R10 on the ids
		// instead would not be the same rule but a worse one, because nothing retires the id of a
		// request that was never answered: the forwarder writes ssl_request before the upstream leg
		// and no ssl_response at all when that leg fails, so one failed call would pin the run to
		// "waiting model" for every later poll, and tier 2 reads the request's id and the response's
		// out of different header sets, where a provider's own id routinely differs from the
		// client's. TestDeriveOverlappingModelRequests pins all of that.
		openRequest  bool
		toolPending  bool
		declaredIdle time.Duration
		// stallDeclared tells a run_start stall_after of "0s" from none at all: 0 is the tightest
		// budget and limits.Watcher enforces it (E16), so it must not fall back to the machine's hour.
		stallDeclared bool
		gapTally      gaps.Tally
		// costBudget is whether run_start declared a cost_usd budget: the only thing a missing price table breaks.
		costBudget bool
		// activity is the largest mono_ns of a non-gap line and when it was stamped: R4's "last event" as
		// limits.Watcher reads it, which skips gap lines (they record tego's own losses, not the agent's
		// activity) and takes the largest reading, since lines are not in mono_ns order along seq
		// (record-ledger.md §4 Append). Taken from the last line, idle disagreed with the watcher's stall
		// check in both directions.
		activityMono uint64
		activityTS   time.Time
		approvals    pendingApprovals
	)
	for e, err := range r.Iter() {
		if err != nil {
			return nil, fmt.Errorf("status: read run: %w", err)
		}
		if o.ctx != nil && s.Events%ctxEvery == 0 {
			if err := o.ctx.Err(); err != nil {
				return nil, err
			}
		}
		s.Events++
		if err := approvals.add(e); err != nil {
			return nil, fmt.Errorf("status: decode approvals: %w", err)
		}
		s.Run, s.Agent = e.Run, e.Agent
		s.LastEvent = e
		gapTally.Add(e)
		if e.Kind != record.KindGap && e.MonoNS > activityMono {
			activityMono, activityTS = e.MonoNS, e.TS
		}
		if e.Attr != nil && e.Attr.Step > s.Step {
			s.Step = e.Attr.Step
		}
		switch e.Kind {
		case record.KindRunStart:
			var p record.RunStartPayload
			if err := e.DecodePayload(&p); err != nil {
				return nil, fmt.Errorf("status: decode run_start: %w", err)
			}
			s.Tier, s.Capabilities, s.RunCommandGrant = p.Tier, p.Capabilities, p.RunCommandGrant
			s.BestEffort = p.BestEffort
			s.TegoVersion = p.TegoVersion
			costBudget = p.Limits != nil && p.Limits.CostUSD != nil
			if p.Limits != nil && p.Limits.LedgerBytes != nil {
				s.LedgerCeiling = *p.Limits.LedgerBytes
			}
			if p.Limits != nil && p.Limits.StallAfter != "" {
				if d, err := time.ParseDuration(p.Limits.StallAfter); err == nil {
					declaredIdle, stallDeclared = max(d, 0), true
				}
			}
		case record.KindSSLRequest:
			openRequest, toolPending = true, false
		case record.KindSSLResponse:
			openRequest = false
		case record.KindDecision:
			var p record.DecisionPayload
			if err := e.DecodePayload(&p); err != nil {
				return nil, fmt.Errorf("status: decode decision: %w", err)
			}
			s.LastDecision = e
			if p.Step > s.Step {
				s.Step = p.Step // R18: the model's own turn counter, as measure reads it
			}
			toolPending = p.Tool != "" || p.ToolUseID != ""
		case record.KindRunEnd:
			if runEnd != nil {
				s.ExtraRunEnds++ // §6 case 5: two run_end lines, the first by chain order wins, reported
				continue
			}
			var p record.RunEndPayload
			if err := e.DecodePayload(&p); err != nil {
				return nil, fmt.Errorf("status: decode run_end: %w", err)
			}
			runEnd = &p
			s.ResourcesRecorded = resources.Recorded(e)
		}
	}
	if s.StallAfter == 0 {
		s.StallAfter, s.StallAfterSource = declaredIdle, SourceRunStart
		if !stallDeclared {
			s.StallAfter, s.StallAfterSource = DefaultStallAfter, SourceMachine
		}
	}
	switch {
	case activityMono > 0:
		s.Since, s.SinceMonoNS = activityTS, activityMono
	case s.LastEvent != nil:
		s.Since, s.SinceMonoNS = s.LastEvent.TS, s.LastEvent.MonoNS
	default:
		if info, err := os.Stat(filepath.Join(r.Dir(), ledger.EventsFile)); err == nil {
			s.Since = info.ModTime() // §6 case 1: an empty ledger's grace window runs from the file
		}
	}
	nowMono := o.mono()
	s.IdleFrom = IdleFromLedger
	// R9 with the activity sidecar: what the watcher counted without a line is as much its last activity as a
	// line is. The reading is a monotonic one from the live writer's boot, so it is compared only under the lock
	// (idle's argument) and only when the clock has reached it; Since is its wall-clock equivalent at now.
	if s.LockHeld {
		if v, ok := ledger.ReadActivity(r.Dir()); ok && v > s.SinceMonoNS && v <= nowMono {
			s.Since, s.SinceMonoNS, s.IdleFrom = now.Add(-time.Duration(nowMono-v)), v, IdleFromActivity
		}
	}
	s.Idle, s.IdleClock = idle(s, s.LockHeld, nowMono, now)
	s.Gaps = statusGaps(gapTally.Counts(), costBudget)
	if s.LockHeld && runEnd == nil {
		s.PendingApprovals = len(approvals)
	}
	s.St = state(s, runEnd, openRequest, toolPending)
	if runEnd != nil && s.St == Done {
		s.ExitReason, s.ExitCode = runEnd.Reason, runEnd.ExitCode
		// Older sweepers omitted exit_code for an orphan, whose decoded zero
		// would imply success. Interpret it as launcher failure without changing
		// the stored ledger, its hash, or any explicit nonzero terminal code.
		if runEnd.Reason == record.RunEndOrphaned && s.ExitCode == 0 {
			s.ExitCode = identity.ExitLauncher
		}
	}
	if runEnd != nil {
		s.Ended, s.Resources = true, runEnd.Resources
	}
	s.SkippedNewer = r.SkippedNewer()
	return s, nil
}

// ResourcesLine renders the snapshot's resource peaks as one line (docs/p0/limits-check-doctor-cli.md R-res):
// what the run's cgroup said the run used, read from its run_end, each key the record lacks "unknown" and
// never 0. A run with no run_end yet says it has none until it ends, because the runtime reads them once, at
// shutdown. Like CapabilityLine it is read from the record, never measured now: the cgroup is gone by then.
func ResourcesLine(s *Snapshot) string { return resources.Line(s.Resources, s.Ended) }

// idle is how long the run has recorded nothing, and which clock says so.
//
// R4 measures it monotonically and R9 compares the result with stall_after. The wall clock cannot do that
// job: an NTP correction or a laptop resuming from suspend steps it forward, which would report a healthy
// agent as stalled, and a backward step makes now.Sub(Since) negative, which would report a stalled one as
// running. The limits watcher already uses MonoNS to decide whether to kill a run for a stall, so a
// wall-clock status would disagree with the enforcement acting on the same run.
//
// A monotonic reading is comparable only within one boot of one host, and that is exactly the case where
// the answer matters: the lock is held by a live process on this host, so its readings came from this boot.
// For a run whose lock is gone the ledger may have been written on another boot or copied from another
// machine, so idle falls back to the wall clock, where it is a display figure only. R9 never runs on a run
// that is done or lost.
func idle(s *Snapshot, lockHeld bool, nowMono uint64, now time.Time) (time.Duration, string) {
	// A zero MonoNS is E20's "unknown", and nowMono under SinceMonoNS means the two readings are not from
	// one boot: neither can be subtracted. Without the lock the writer is gone and the ledger may come from
	// another boot or host, where a reading that happens to be lower than this boot's clock means nothing.
	if lockHeld && s.SinceMonoNS != 0 && nowMono >= s.SinceMonoNS {
		return time.Duration(nowMono - s.SinceMonoNS), ClockMonotonic
	}
	if s.Since.IsZero() {
		return 0, ClockWall
	}
	d := now.Sub(s.Since)
	if d < 0 {
		d = 0 // the wall clock stepped back behind the event; no elapsed time has been observed
	}
	return d, ClockWall
}

// state applies R7-R12 in order, first match wins.
func state(s *Snapshot, runEnd *record.RunEndPayload, openRequest, toolPending bool) State {
	switch {
	case !s.LockHeld && runEnd != nil: // R7
		return Done
	case !s.LockHeld && s.Events == 0: // §6 case 1: nobody holds the lock and nothing was ever recorded
		return NeverStarted
	case !s.LockHeld: // R8: nobody holds the lock and the run never ended itself
		return Lost
	case s.PendingApprovals > 0 && s.Idle < s.StallAfter+askAnswerBound:
		// Before R9: a pending human approval holds the stall clock, as the
		// limits watcher's (R4). The broker answers every ask by ask.timeout,
		// and the watcher kills stall_after after that answer, so an ask still
		// unanswered past both cannot be a live wait (a wedged or stopped
		// launcher): R9 below calls it stalled.
		return WaitingApproval
	case s.Idle >= s.StallAfter: // R9
		return Stalled
	case openRequest: // R10
		return WaitingModel
	case toolPending: // R11
		return WaitingTool
	}
	return Running // R12
}

// DeriveAll reports every run under ledgerRoot, oldest first by the mint time in the run id, whatever its
// host prefix (spec/identity R1, ledger.CompareRunIDs). One unreadable or corrupt run never hides the others (§6 case 8): its
// error is reported through the returned error, and every run that could be read is still returned.
func DeriveAll(ctx context.Context, ledgerRoot string, now time.Time) ([]*Snapshot, error) {
	entries, err := os.ReadDir(ledgerRoot)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil // no run has ever been recorded here
		}
		return nil, fmt.Errorf("status: read ledger root: %w", err)
	}
	var (
		out  []*Snapshot
		errs []error
	)
	for _, e := range entries {
		if !e.IsDir() || !ledger.IsRunID(e.Name()) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err // interrupted: the caller reports that, not a partial listing
		}
		dir := filepath.Join(ledgerRoot, e.Name())
		s, err := DeriveDir(ctx, dir, now)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			errs = append(errs, fmt.Errorf("%s: %w", e.Name(), err))
			continue
		}
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b *Snapshot) int { return ledger.CompareRunIDs(a.Run, b.Run) })
	return out, errors.Join(errs...)
}

// DeriveDir opens one run directory and derives its state, the lock probed after the reader is opened
// (§4, §6 E3). A run that died before run_start has no run id in its ledger, so it carries its directory's
// name. DeriveAll and the CLI's named-run path both come through here, so the open and probe order that
// makes status correct is written once.
func DeriveDir(ctx context.Context, dir string, now time.Time) (*Snapshot, error) {
	r, err := ledger.OpenReader(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	held, err := LockHeld(dir)
	if err != nil {
		return nil, err
	}
	s, err := Derive(r, held, now, 0, WithContext(ctx))
	if err != nil {
		return nil, err
	}
	if s.Run == "" {
		s.Run = filepath.Base(dir)
	}
	// After the read, so the size is at least what was read; a ledger still growing is larger by now.
	if st, err := os.Stat(filepath.Join(dir, ledger.EventsFile)); err == nil {
		s.LedgerBytes = st.Size()
	}
	return s, nil
}

// LedgerLine is the ledger line under status's table: how large the run's events.jsonl is, and the
// record.max_run_bytes ceiling that ends the run as a limit when it reaches it, or "no ceiling".
func LedgerLine(s *Snapshot) string {
	if s.LedgerCeiling > 0 {
		return humanBytes(s.LedgerBytes) + " of " + humanBytes(s.LedgerCeiling) + " (record.max_run_bytes)"
	}
	return humanBytes(s.LedgerBytes) + ", no ceiling"
}

// humanBytes renders n in the largest binary unit it reaches, with one decimal: 900 B, 1.5 MiB.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	v, i := float64(n)/unit, 0
	for v >= unit && i < 4 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.1f %ciB", v, "KMGTP"[i])
}

// DeriveBorn is the snapshot of a run directory that has no events.jsonl yet (§6 case 8): its launcher
// has made the directory and taken the lock but not created the ledger, or died in that window. It is
// the empty-ledger answer of Derive: never started when nobody holds the lock, running while one does.
func DeriveBorn(dir string, now time.Time) (*Snapshot, error) {
	held, err := LockHeld(dir)
	if err != nil {
		return nil, err
	}
	s := &Snapshot{Run: filepath.Base(dir), LockHeld: held, StallAfter: DefaultStallAfter, StallAfterSource: SourceMachine,
		IdleFrom: IdleFromLedger}
	s.Idle, s.IdleClock = idle(s, held, 0, now)
	s.St = state(s, nil, false, false)
	return s, nil
}

// LockHeld probes a run's lock without blocking and without taking it: flock(LOCK_SH|LOCK_NB) fails
// with EWOULDBLOCK exactly while a launcher holds LOCK_EX (invariant 1, R1). A run directory with no
// lock file counts as free (§6 E27). It is ledger.LockHeld, the one hardened probe (a FIFO planted as the
// lock hung `tego status` in the open, and a link aimed a root status's flock at any file, R22).
func LockHeld(dir string) (bool, error) { return ledger.LockHeld(dir) }

// gapNoPriceTable is the why of the gap a run records when no price table loaded (limits.GapNoPriceTable; the read
// side does not import the runtime, and a test in internal/cli keeps the two spelled alike).
const gapNoPriceTable = "no-price-table"

// statusGaps is the gap line status shows: every gap the run recorded, except record/no-price-table for a run with
// no cost_usd budget, which no price table would have served (tokens are counted without one). The gap stays in the
// ledger and in tego measure; only the status line is quiet about it (G10).
func statusGaps(cs []gaps.Count, costBudget bool) []gaps.Count {
	if costBudget {
		return cs
	}
	return slices.DeleteFunc(cs, func(c gaps.Count) bool { return c.What == record.GapRecord && c.Why == gapNoPriceTable })
}
