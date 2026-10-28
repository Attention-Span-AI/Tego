// SPDX-License-Identifier: Apache-2.0

package livestatus

import (
	"encoding/json"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// State is a live block's claim on its run now.
type State string

// The states, in the order Status decides them.
const (
	// Ended: the run has ended, so the block refuses nothing any more.
	Ended State = "ended"
	// RecordedOnly: the run is only watched (tier observe); its supervisor records what the block names and lets it
	// go on.
	RecordedOnly State = "recorded_only"
	// Waiting: the block is in the run's overlay, but the run's launcher has not yet recorded putting it in force.
	Waiting State = "waiting"
	// Partial: a path block the launcher put in force on a run whose supervisor does not see plain read opens, so it
	// refuses changes (writes, renames, deletes, opens for writing) but a plain read still goes through.
	Partial State = "partial"
	// InForce: the launcher recorded putting the block in force; the supervisor refuses what it names.
	InForce State = "in_force"
	// Dormant: a block unblocked for a while (its From is still ahead, ADR 0125 decision 4): it refuses nothing
	// until From. StatusAt decides it.
	Dormant State = "dormant"
	// Expired: a block whose time limit (its Until) has passed: it refuses nothing any more, though the overlay keeps
	// it for a while. StatusAt decides it.
	Expired State = "expired"
)

// The sentences, one per state. They have no subject (the page names the block) and name no engine part.
const (
	SentenceEnded        = "Ended with the run: it no longer refuses anything"
	SentenceRecordedOnly = "Recorded, not enforced: this run is only watched"
	SentenceWaiting      = "Waiting for the run to put it in force (about a second)"
	SentencePartial      = "Refuses changes now; reads are not seen in this run"
	SentenceInForce      = "In force: tego refuses it until the run ends"
	// SentenceInForceUntil is SentenceInForce for a block with a time limit.
	SentenceInForceUntil = "In force: tego refuses it until its time limit ends"
	SentenceDormant      = "Unblocked for a while: it refuses nothing until then"
	SentenceExpired      = "Ended by its time limit: it no longer refuses anything"
)

// The kinds Status knows, liveblock's. A write block refuses changes, which the supervisor of an enforcing run sees
// unless a kernel decision plane decides them (Facts.KernelDecidesChanges: tier 3's plane answers write opens,
// truncates and the named mutations in the kernel, with no notification, so a write block placed there refuses only
// what still reaches the supervisor), so it is decided as exec and net are; so is a read block, which is placed only on
// a run that sees its reads (runact.Block and `tego block` refuse one elsewhere, since it would refuse nothing there).
// A read or write block is placed only on a run whose launcher knows those kinds (Facts.NarrowKinds).
const (
	KindExec  = "exec"
	KindNet   = "net"
	KindPath  = "path"
	KindRead  = "read"
	KindWrite = "write"
)

// Facts is what a run's record says about how it can enforce a live block.
type Facts struct {
	// Observe is a run that only watches: run_start's tier is observe (tego watch, --observe).
	Observe bool
	// ReadsSeen is a run whose supervisor sees every read open: run_start's fs_reads says held, or reads_notified
	// says notified (record: full, an fs.read gate, an fs.ask_read entry, held reads, reason.reads). A path block
	// refuses reads only on such a run.
	ReadsSeen bool
	// Ended is a run whose run_end was read.
	Ended bool
	// RecordMinor is run_start's record_minor: the revision of the launcher that writes the run's ledger and reads its
	// overlay. 0 when run_start says none or could not be read.
	RecordMinor int
	// KernelDecidesChanges is a run whose run_start names a decision plane that decides fs changes in the kernel
	// (decision_plane lsm or fmod_ret): there a write open, a truncate or a rename the plane answers never reaches the
	// supervisor, so a write block cannot be promised to refuse it.
	KernelDecidesChanges bool
	// Timed is a run whose launcher reads a time limit on a live block or unblock and records its end
	// (record.MinorLiveModes, ADR 0125): an older launcher refuses the whole overlay once it holds one.
	Timed bool
	// Adjustable is a run whose run_start says live_mode adjustable (ADR 0125): its fence entries may be lifted and
	// restored while it runs. False is a Locked run.
	Adjustable bool
	// Fence is an Adjustable run's fence as its run_start lists it; nil on a Locked run.
	Fence []record.LiveFenceEntry
}

// NarrowKinds reports whether the run's launcher knows the read and write live blocks (record.MinorLiveControl). An
// older launcher fails to read an overlay holding one, keeps the blocks it last read and ignores every later change
// until that block is removed, so such a block is never placed on its run.
func (f Facts) NarrowKinds() bool { return f.RecordMinor >= record.MinorLiveControl }

// Result is a live block's state and the sentence that says it.
type Result struct {
	State    State  `json:"state"`
	Sentence string `json:"sentence"`
}

// Status is the claim of a live block of kind (exec, net, path, read or write) on a run with facts f: serial is the overlay serial
// of the change that added the block (the overlay's own serial when that change is no longer listed), confirmed the
// highest serial the run's launcher recorded putting in force. The first rule that matches decides:
//   - an ended run: Ended;
//   - a watched run: RecordedOnly, since its supervisor continues every action it would refuse;
//   - a serial the launcher has not confirmed (confirmed < serial): Waiting;
//   - a path block on a run that does not see its reads: Partial;
//   - otherwise InForce.
//
// An unknown kind is decided as exec and net are.
func Status(kind string, f Facts, serial, confirmed uint64) Result {
	switch {
	case f.Ended:
		return Result{Ended, SentenceEnded}
	case f.Observe:
		return Result{RecordedOnly, SentenceRecordedOnly}
	case confirmed < serial:
		return Result{Waiting, SentenceWaiting}
	case kind == KindPath && !f.ReadsSeen:
		return Result{Partial, SentencePartial}
	}
	return Result{InForce, SentenceInForce}
}

// StatusAt is Status for a block that may carry a time limit (liveblock.Entry's From and Until, ADR 0125 decision 4),
// judged at now. The first rule that matches decides:
//   - an ended run: Ended; a watched run: RecordedOnly (as Status);
//   - until set and now at or past it: Expired;
//   - from set and now before it: Dormant;
//   - otherwise Status, saying "until its time limit ends" for an in-force block with an until.
//
// now is the wall clock of whoever shows the state. The launcher judges each limit on its wall clock and on
// CLOCK_BOOTTIME, ending a block only when both have passed its until and an unblock as soon as either has passed its
// from. So after a clock step this may say Expired or Dormant while the run still refuses, never the reverse: every
// InForce or Partial it gives is one the launcher enforces too (once confirmed).
func StatusAt(kind string, f Facts, serial, confirmed uint64, now, from, until time.Time) Result {
	switch {
	case f.Ended || f.Observe:
		return Status(kind, f, serial, confirmed)
	case !until.IsZero() && !now.Before(until):
		return Result{Expired, SentenceExpired}
	case !from.IsZero() && now.Before(from):
		return Result{Dormant, SentenceDormant}
	}
	r := Status(kind, f, serial, confirmed)
	if r.State == InForce && !until.IsZero() {
		r.Sentence = SentenceInForceUntil
	}
	return r
}

// Refuses reports whether a block in state s refuses at least part of what it names now.
func (s State) Refuses() bool { return s == InForce || s == Partial }

// FromStart is the facts a run_start payload gives (Ended is left false: run_end says that).
func FromStart(p *record.RunStartPayload) Facts {
	if p == nil {
		return Facts{}
	}
	f := facts(p.Tier, p.FSReads, p.ReadsNotified, p.DecisionPlane)
	f.RecordMinor = p.RecordMinor
	f.live(p.LiveMode, p.LiveFence)
	return f
}

// live sets the facts of the run's time limits and mode from its record_minor, live_mode and live_fence. A run is
// Adjustable only when its revision knows the mode and it lists its fence: a line that says less is Locked, the
// claim that promises least.
func (f *Facts) live(mode string, fence *record.LiveFence) {
	f.Timed = f.RecordMinor >= record.MinorLiveModes
	if f.Timed && mode == record.LiveModeAdjustable && fence != nil {
		f.Adjustable = true
		f.Fence = fence.Entries
	}
}

// InFence is the fence entry of kind on value (normalized as a live block's), if the run's fence lists one.
func (f Facts) InFence(kind, value string) (record.LiveFenceEntry, bool) {
	for _, e := range f.Fence {
		if e.Kind == kind && e.Value == value {
			return e, true
		}
	}
	return record.LiveFenceEntry{}, false
}

// FromStartJSON is FromStart of a run_start payload as the ledger holds it (record.Event.Payload). A payload that does
// not decode gives no facts: an enforcing run that does not see its reads, the claim that promises least.
func FromStartJSON(raw []byte) Facts {
	var p struct {
		Tier          string                `json:"tier"`
		FSReads       *record.FSReads       `json:"fs_reads"`
		ReadsNotified *record.ReadsNotified `json:"reads_notified"`
		RecordMinor   int                   `json:"record_minor"`
		DecisionPlane string                `json:"decision_plane"`
		LiveMode      string                `json:"live_mode"`
		LiveFence     *record.LiveFence     `json:"live_fence"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return Facts{}
	}
	f := facts(p.Tier, p.FSReads, p.ReadsNotified, p.DecisionPlane)
	f.RecordMinor = p.RecordMinor
	f.live(p.LiveMode, p.LiveFence)
	return f
}

func facts(tier string, fs *record.FSReads, rn *record.ReadsNotified, plane string) Facts {
	return Facts{
		Observe:              backend.Tier(tier) == backend.TierObserve,
		ReadsSeen:            (fs != nil && fs.Reads == record.FSReadsHeld) || (rn != nil && rn.Notified),
		KernelDecidesChanges: plane == record.DecisionPlaneLSM || plane == record.DecisionPlaneFmodRet,
	}
}
