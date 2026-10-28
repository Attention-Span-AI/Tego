// SPDX-License-Identifier: Apache-2.0

package record

import (
	jsonv2 "encoding/json/v2"
	"slices"
	"strings"
)

// The live changes' fields ValidateAt checks on a gap line (MinorLiveBlock, MinorLiveControl).
const (
	liveBlockKey   = "live_block"
	liveControlKey = "live_control"
)

// liveBlockWhys maps each gap why that records a live block's change, a time limit's end or a fence entry's change to
// the op its live_block carries.
var liveBlockWhys = map[string]string{GapLiveBlockAdded: LiveOpAdd, GapLiveBlockRemoved: LiveOpRemove,
	GapLiveBlockExpired: LiveOpExpire, GapLiveUnblockExpired: LiveOpExpire, GapLiveRuleLifted: LiveOpLift,
	GapLiveRuleRestored: LiveOpRestore, GapLiveLiftExpired: LiveOpExpire, GapLiveLiftRefused: LiveOpLift}

// liveFenceWhys are the whys whose live_block names a fence entry, under a live.fence[...] rule.
var liveFenceWhys = map[string]bool{GapLiveRuleLifted: true, GapLiveRuleRestored: true, GapLiveLiftExpired: true,
	GapLiveLiftRefused: true}

// liveExpireWhys are the whys of a time limit's end, whose live_block carries the until that passed.
var liveExpireWhys = map[string]bool{GapLiveBlockExpired: true, GapLiveUnblockExpired: true, GapLiveLiftExpired: true}

// liveFenceKinds are the kinds a fence entry may be of (ADR 0125 decision 2).
var liveFenceKinds = [...]string{LiveKindRead, LiveKindNet, LiveKindExec}

// liveRefusals are LiveBlockChange.Refused's values.
var liveRefusals = [...]string{LiveRefusedMAC, LiveRefusedOutsideFence, LiveRefusedLocked, LiveRefusedUntil}

// LiveFenceRule is the rule a refusal by a fence entry of kind on value, and an action allowed only because it is
// lifted, carry: live.fence[<kind>:<value>], the record's own copy of internal/liveblock's FenceRule.
func LiveFenceRule(kind, value string) string { return "live.fence[" + kind + ":" + value + "]" }

// LiveLiftRule is the rule a live-lift-refused line carries when the lift names no fence entry of the run:
// live.lift[<kind>:<value>], the request (refused locked or outside-fence, and mac for a lift outside the fence), so
// no line names a live.fence[...] rule run_start.live_fence does not list. The record's own copy of internal/liveblock's
// LiftRule.
func LiveLiftRule(kind, value string) string { return "live.lift[" + kind + ":" + value + "]" }

// liveControlWhys maps each gap why that records a pause or a resume to the op its live_control carries.
var liveControlWhys = map[string]string{GapRunPaused: LiveOpPause, GapPauseFailed: LiveOpPause,
	GapRunResumed: LiveOpResume, GapResumeFailed: LiveOpResume}

// liveKindMinor is the revision each live block kind was added at.
var liveKindMinor = map[string]int{LiveKindExec: MinorLiveBlock, LiveKindNet: MinorLiveBlock, LiveKindPath: MinorLiveBlock,
	LiveKindRead: MinorLiveControl, LiveKindWrite: MinorLiveControl}

// liveBlockKinds is every live block kind, in the order they were added.
var liveBlockKinds = [...]string{LiveKindExec, LiveKindNet, LiveKindPath, LiveKindRead, LiveKindWrite}

// LiveBlockKinds lists every live block kind, in the order they were added. Editing it does not change validation.
var LiveBlockKinds = slices.Clone(liveBlockKinds[:])

// LiveRule is the rule a refusal under a live block of kind on value carries, live.block[<kind>:<value>]: the
// record's own copy of internal/liveblock's spelling, which LiveBlockChange.Rule must equal.
func LiveRule(kind, value string) string { return "live.block[" + kind + ":" + value + "]" }

// validateLiveRule refuses a rule of a live block kind added after the ledger's revision [below-minor]: a
// live.block[read:...] or live.block[write:...] rule below MinorLiveControl.
func validateLiveRule(rule string, minor int) error {
	if minor < MinorLiveModes && (strings.HasPrefix(rule, "live.fence[") || strings.HasPrefix(rule, "live.lift[")) {
		return fieldErr("below-minor", "rule", "a %s...] rule is added at record_minor %d, the ledger is at %d",
			rule[:strings.IndexByte(rule, '[')+1], MinorLiveModes, minor)
	}
	if minor >= MinorLiveControl || !strings.HasPrefix(rule, "live.block[") {
		return nil
	}
	kind, _, ok := strings.Cut(strings.TrimPrefix(rule, "live.block["), ":")
	if ok && liveKindMinor[kind] == MinorLiveControl {
		return fieldErr("below-minor", "rule", "a live block of kind %q is added at record_minor %d, the ledger is at %d",
			kind, liveKindMinor[kind], minor)
	}
	return nil
}

// validateLiveGap is ValidateAt's check of a gap line's live changes, on fields, the line's payload members, in a
// ledger at revision minor:
//   - a why of a pause or resume (run-paused, run-resumed, pause-failed, resume-failed) or a live_control below
//     MinorLiveControl, and a live block of kind read or write below it, are refused [below-minor];
//   - live_control is on a gap what=enforce of one of those whys and only there, every such line has one, with the
//     op its why names (pause, or resume) and a serial of 1 or more [live-control];
//   - live_block is on a gap what=enforce why live-block-added or live-block-removed and only there, every such
//     line has one, with the op its why names (add, or remove), a kind of LiveBlockKinds, a value, the rule
//     live.block[<kind>:<value>] and a serial of 1 or more [live-block] (LiveBlockKinds);
//   - a member a case-insensitive reader would take for live_block or live_control, or for one of their members, but
//     spelt otherwise is refused [field-case], and so is a null, a repeated name or a value of the wrong type inside
//     either, by the code of the field it is under.
//
// by and at are not checked: the launcher copies them from the run's overlay, whose writer is the run's user, and a
// line refused here would be a change the ledger never records. For the same reason a field the ledger Writer moved
// to a blob (R10: live_block_blob or live_control_blob, for a change past ledger.BlobThreshold) stands for the field
// and is not read. A gap with neither field and none of those whys passes as Validate has it.
func validateLiveGap(minor int, fields []field) error {
	var what, why string
	var block, control []byte
	var blockMoved, controlMoved bool
	for _, fl := range fields {
		switch {
		case fl.key == "what":
			_ = jsonv2.Unmarshal(fl.val, &what) // not a string: Validate does not hold what's type, and "" matches no rule
		case fl.key == "why":
			_ = jsonv2.Unmarshal(fl.val, &why) // as what
		case fl.key == liveBlockKey:
			block = fl.val
		case fl.key == liveControlKey:
			control = fl.val
		case fl.key == liveBlockKey+"_blob":
			blockMoved = true
		case fl.key == liveControlKey+"_blob":
			controlMoved = true
		case foldEqual(fl.key, liveBlockKey):
			return fieldErr("field-case", "gap."+liveBlockKey, "the key %q is not spelt %q", fl.key, liveBlockKey)
		case foldEqual(fl.key, liveControlKey):
			return fieldErr("field-case", "gap."+liveControlKey, "the key %q is not spelt %q", fl.key, liveControlKey)
		}
	}
	controlOp, isControl := liveControlWhys[why]
	if isControl && minor < MinorLiveControl {
		return fieldErr("below-minor", "gap.why", "why %q is added at record_minor %d, the ledger is at %d", why,
			MinorLiveControl, minor)
	}
	if err := validateLiveControl(minor, what, why, controlOp, isControl, control, controlMoved); err != nil {
		return err
	}
	blockOp, isBlock := liveBlockWhys[why]
	if isBlock && blockOp != LiveOpAdd && blockOp != LiveOpRemove && minor < MinorLiveModes {
		return fieldErr("below-minor", "gap.why", "why %q is added at record_minor %d, the ledger is at %d", why,
			MinorLiveModes, minor)
	}
	return validateLiveBlock(minor, what, why, blockOp, isBlock, block, blockMoved)
}

// validateLiveControl checks a gap's live_control, raw (nil when absent; moved when the Writer moved it to a blob),
// against its what and why.
func validateLiveControl(minor int, what, why, op string, isControl bool, raw []byte, moved bool) error {
	const f = "gap." + liveControlKey
	if raw == nil {
		if isControl && !moved {
			return fieldErr("live-control", f, "a why %q line without %s", why, liveControlKey)
		}
		return nil
	}
	var c LiveControlChange
	if err := decodeField(f, raw, &c); err != nil {
		return err
	}
	if err := belowMinor(f, true, minor, MinorLiveControl); err != nil {
		return err
	}
	switch {
	case !isControl:
		return fieldErr("live-control", f, "on a gap why %q, not one of a pause or a resume", why)
	case what != GapEnforce:
		return fieldErr("live-control", f, "on a gap what %q, not %q", what, GapEnforce)
	case c.Op != op:
		return fieldErr("live-control", f+".op", "%q on a why %q line, which records op %q", c.Op, why, op)
	case c.Serial == 0:
		return fieldErr("live-control", f+".serial", "0: an overlay numbers its changes from 1")
	}
	return nil
}

// validateLiveBlock checks a gap's live_block, raw (nil when absent; moved when the Writer moved it to a blob),
// against its what and why.
func validateLiveBlock(minor int, what, why, op string, isBlock bool, raw []byte, moved bool) error {
	const f = "gap." + liveBlockKey
	if raw == nil {
		if isBlock && !moved {
			return fieldErr("live-block", f, "a why %q line without %s", why, liveBlockKey)
		}
		return nil
	}
	var c LiveBlockChange
	if err := decodeField(f, raw, &c); err != nil {
		return err
	}
	if err := belowMinor(f+".until", !c.Until.IsZero(), minor, MinorLiveModes); err != nil {
		return err
	}
	if err := belowMinor(f+".refused", c.Refused != "", minor, MinorLiveModes); err != nil {
		return err
	}
	fence := liveFenceWhys[why]
	kinds := liveBlockKinds[:]
	if fence {
		kinds = liveFenceKinds[:]
	}
	switch {
	case !isBlock:
		return fieldErr("live-block", f, "on a gap why %q, not one of a live block's or a fence entry's", why)
	case what != GapEnforce:
		return fieldErr("live-block", f, "on a gap what %q, not %q", what, GapEnforce)
	case c.Op != op:
		return fieldErr("live-block", f+".op", "%q on a why %q line, which records op %q", c.Op, why, op)
	case !slices.Contains(kinds, c.Kind):
		return fieldErr("live-block", f+".kind", "%q is not one of %s", c.Kind, strings.Join(kinds, ", "))
	}
	// Only revision 24's kinds are held to their revision: below 21 no line names live_block, which this check does not
	// add.
	if err := belowMinor(f+".kind", liveKindMinor[c.Kind] == MinorLiveControl, minor, MinorLiveControl); err != nil {
		return err
	}
	rule := LiveRule(c.Kind, c.Value)
	if fence {
		rule = LiveFenceRule(c.Kind, c.Value)
	}
	if why == GapLiveLiftRefused && c.Rule == LiveLiftRule(c.Kind, c.Value) {
		// A refused lift that names no fence entry is written under the request's rule, live.lift[...]. Both
		// spellings stand at this revision, whatever the refusal: a launcher built before this form (the first one at record
		// minor 26) wrote every refused lift under live.fence[...], so a reader of either build's ledger
		// takes both, and the two builds agree on what a valid line is.
		rule = c.Rule
	}
	switch {
	case c.Value == "":
		return fieldErr("live-block", f+".value", "empty: a live block names what it blocks")
	case c.Rule != rule:
		return fieldErr("live-block", f+".rule", "%q, not %q", c.Rule, rule)
	case c.Serial == 0:
		return fieldErr("live-block", f+".serial", "0: an overlay numbers its changes from 1")
	case liveExpireWhys[why] && c.Until.IsZero():
		return fieldErr("live-block", f+".until", "absent on a why %q line, which records the limit that passed", why)
	case why == GapLiveLiftRefused && !slices.Contains(liveRefusals[:], c.Refused):
		return fieldErr("live-block", f+".refused", "%q is not one of %s", c.Refused, strings.Join(liveRefusals[:], ", "))
	case why != GapLiveLiftRefused && c.Refused != "":
		return fieldErr("live-block", f+".refused", "on a why %q line; only %q says why a lift was refused", why, GapLiveLiftRefused)
	}
	return nil
}

// validateLiveMode checks run_start's live_mode and live_fence (ADR 0125): neither below MinorLiveModes
// [below-minor]; both or neither, live_mode only "adjustable" [live-mode]; and the fence's digest 64 lower-case hex
// digits, at most MaxLiveFence entries, each of kind read, net or exec, with a value of at most MaxLiveFenceValue
// bytes, a source deny or new, the rule live.fence[<kind>:<value>] and a name only on an exec entry of source deny
// [live-fence].
func (p *RunStartPayload) validateLiveMode() error {
	const mf, ff = "run_start.live_mode", "run_start.live_fence"
	if err := belowMinor(mf, p.LiveMode != "", p.RecordMinor, MinorLiveModes); err != nil {
		return err
	}
	if err := belowMinor(ff, p.LiveFence != nil, p.RecordMinor, MinorLiveModes); err != nil {
		return err
	}
	switch {
	case p.LiveMode == "" && p.LiveFence == nil:
		return nil
	case p.LiveMode != LiveModeAdjustable:
		return fieldErr("live-mode", mf, "%q, not %q (a Locked run writes neither field)", p.LiveMode, LiveModeAdjustable)
	case p.LiveFence == nil:
		return fieldErr("live-mode", mf, "written without live_fence; the two are written together")
	}
	fe := p.LiveFence
	switch {
	case !sha256Hex.MatchString(fe.SHA256):
		return fieldErr("live-fence", ff+".sha256", "%q is not 64 lower-case hex digits", fe.SHA256)
	case fe.Entries == nil:
		return fieldErr("live-fence", ff+".entries", "absent; an empty fence is []")
	case len(fe.Entries) > MaxLiveFence:
		return fieldErr("live-fence", ff+".entries", "%d entries, more than %d", len(fe.Entries), MaxLiveFence)
	}
	seen := make(map[string]bool, len(fe.Entries))
	for _, e := range fe.Entries {
		switch {
		case !slices.Contains(liveFenceKinds[:], e.Kind):
			return fieldErr("live-fence", ff+".entries.kind", "%q is not one of %s", e.Kind, strings.Join(liveFenceKinds[:], ", "))
		case e.Value == "":
			return fieldErr("live-fence", ff+".entries.value", "empty: a fence entry names what it may allow")
		case len(e.Value) > MaxLiveFenceValue:
			return fieldErr("live-fence", ff+".entries.value", "%d bytes, more than %d", len(e.Value), MaxLiveFenceValue)
		case e.Source != LiveFenceSourceDeny && e.Source != LiveFenceSourceNew:
			return fieldErr("live-fence", ff+".entries.source", "%q, not %q or %q", e.Source, LiveFenceSourceDeny, LiveFenceSourceNew)
		case e.Rule != LiveFenceRule(e.Kind, e.Value):
			return fieldErr("live-fence", ff+".entries.rule", "%q, not %q", e.Rule, LiveFenceRule(e.Kind, e.Value))
		case e.Name != "" && (e.Kind != LiveKindExec || e.Source != LiveFenceSourceDeny || strings.Contains(e.Name, "/")):
			return fieldErr("live-fence", ff+".entries.name", "%q on a %s entry of source %s; a name is the bare program name of an exec entry of source deny", e.Name, e.Kind, e.Source)
		case seen[e.Rule]:
			return fieldErr("live-fence", ff+".entries", "%q listed twice", e.Rule)
		}
		seen[e.Rule] = true
	}
	return nil
}
