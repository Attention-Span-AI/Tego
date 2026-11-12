// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// The overlay file's versions, its "v" key. Encode writes the lowest one that holds the content, so an overlay that
// uses nothing newer is byte for byte what the base build wrote. A reader refuses a version it does not know (an
// older one: as invalid), keeps the blocks it last read and never rewrites the file, so no field it does not know is
// ever dropped without notice (ADR 0125).
const (
	// Version is the first: blocks, their adds and removes, pause and resume.
	Version = 1
	// VersionTimed adds time limits: an entry's until and from, and a change's until (ADR 0125 decision 4).
	VersionTimed = 2
	// VersionModes adds the ops of an Adjustable run's fence, lift and restore, with a lift's MAC (ADR 0125 decision
	// 3 and 5).
	VersionModes = 3
	// VersionReal adds an entry's real, the path a path, read or write block's value led to through a link when the
	// writer resolved it (Entry.Real). It is written only to a run whose launcher made the mark that it reads it
	// (TakesReal), so a launcher that predates it never meets it; a writer that predates it refuses the file instead of
	// dropping the real path without notice.
	VersionReal = 4
	// VersionLink adds an entry's match, an exec block that refuses what the running contract grants under the
	// exec.allow entry at its value only (Entry.Match, MatchLink). It is written only to a run whose launcher made the
	// mark that it reads it (TakesLink): a launcher that predates it would refuse the whole file and ignore every later
	// change, so the writer places the whole-file block there instead, which refuses more, never less.
	VersionLink = 5
)

// Bounds on one overlay. The writer refuses a block past MaxBlocks and keeps the newest MaxChanges changes; the
// reader refuses a file past MaxFileBytes.
const (
	MaxBlocks    = 64
	MaxChanges   = 256
	MaxFileBytes = 1 << 20
)

// The change operations: a block's add and remove, and the run's pause and resume (record.MinorLiveControl).
const (
	OpAdd    = "add"
	OpRemove = "remove"
	// OpPause asks the launcher to freeze the run's cgroup (cgroup.freeze): every process of the run stops where it
	// is until a resume. A pause names no kind and no value.
	OpPause = "pause"
	// OpResume asks the launcher to thaw the run's cgroup. It undoes a pause and nothing else.
	OpResume = "resume"
	// OpLift asks the launcher of an Adjustable run to allow a fence entry (ADR 0125 decision 3: a lift of a contract
	// refusal, or a grant of new access), optionally until a limit. It carries a MAC under the run's key (LiftMAC);
	// the launcher alone decides whether it takes effect, and it never touches Blocks.
	OpLift = "lift"
	// OpRestore asks the launcher to refuse a lifted fence entry again. It narrows, so it carries no MAC.
	OpRestore = "restore"
)

// Change is one add, remove, pause or resume, in the order the writer made them: what the launcher records in the
// run's ledger.
type Change struct {
	// Serial numbers the overlay's changes from 1, one per change, never reused.
	Serial uint64 `json:"serial"`
	Op     string `json:"op"`
	// Kind and Value are the block an add or a remove names; a pause and a resume name none and leave them out.
	Kind  Kind      `json:"kind,omitempty"`
	Value string    `json:"value,omitempty"`
	By    string    `json:"by"`
	At    time.Time `json:"at"`
	// Until is the change's time limit: when an add's block ends, when a remove's block refuses again, when a lift
	// ends. Zero is no end.
	Until time.Time `json:"until,omitzero"`
	// MAC is a lift's HMAC under the run's key (LiftMAC); empty on every other op.
	MAC string `json:"mac,omitempty"`
}

// Rule is the rule name of the block the change adds or removes, or of the fence entry a lift or a restore names.
func (c Change) Rule() string {
	if c.Fence() {
		return FenceRule(c.Kind, c.Value)
	}
	return Rule(c.Kind, c.Value)
}

// Control reports whether the change is a pause or a resume rather than a block's add or remove.
func (c Change) Control() bool { return c.Op == OpPause || c.Op == OpResume }

// Fence reports whether the change is a lift or a restore of a fence entry.
func (c Change) Fence() bool { return c.Op == OpLift || c.Op == OpRestore }

// Overlay is live-block.json: the run's live blocks now, and the changes that made them, newest last.
type Overlay struct {
	V   int    `json:"v"`
	Run string `json:"run"`
	// Serial is the last change's serial; 0 for an overlay no change was made to.
	Serial  uint64   `json:"serial"`
	Blocks  []Entry  `json:"blocks"`
	Changes []Change `json:"changes"`
	// Paused asks the launcher to hold the run frozen (OpPause) until a resume clears it (OpResume). The launcher
	// writes a gap run-paused or pause-failed once it has applied it. A binary that predates it refuses the file
	// (Validate refuses an op it does not know), records live-block-unreadable and leaves the run running: a pause
	// it cannot read is never half applied.
	Paused bool `json:"paused,omitempty"`
}

// New is an empty overlay of run.
func New(run string) *Overlay {
	return &Overlay{V: Version, Run: run, Blocks: []Entry{}, Changes: []Change{}}
}

// Find is the block of kind on value (normalized), if the overlay holds one.
func (o *Overlay) Find(kind Kind, value string) (Entry, bool) {
	key := Key(kind, value)
	for _, e := range o.Blocks {
		if e.Key() == key {
			return e, true
		}
	}
	return Entry{}, false
}

// Add adds a block of kind on value, normalized, with no end, recording the change; it reports false (and changes
// nothing) when the overlay already holds that block in force with no end. It is AddUntil with a zero until.
func (o *Overlay) Add(kind Kind, value, by string, at time.Time) (Change, bool, error) {
	return o.AddUntil(kind, value, by, at, time.Time{})
}

// AddUntil adds a block of kind on value, normalized, that ends by itself at until (zero: no end), recording the
// change with its until; a set until is held to CheckUntil (with checkSlack, see there). A held block keeps its Real.
//
// A block only narrows: an add on a block the overlay already holds never shortens it. The block it leaves refuses
// from now on (its From is cleared) until the later of the two ends, where no end is the latest; the change records
// that end, not the one asked for. It reports false (and changes nothing) when the held block is in force and already
// ends no sooner, so "Block now for 1h" on a row blocked with no end, or an add from inside a run (which runact allows,
// because an add narrows), can never cut short an operator's block. Shortening one is an unblock (Remove or
// RemoveUntil), the loosening path, which is refused inside a run.
func (o *Overlay) AddUntil(kind Kind, value, by string, at, until time.Time) (Change, bool, error) {
	return o.add(kind, value, "", by, at, until)
}

// AddLink adds a block of kind on value, normalized, with no end, that matches by link (MatchLink): it refuses what
// the running contract grants under the exec.allow entry at value (Set.MatchExec). It is the block the rules editor
// derives from that entry removed, which refuses what the entry granted the run and leaves the rest to the contract.
// A value that cannot match by link (a bare name, a folder, another kind) is added as Add adds it. It only narrows,
// as AddUntil does: a held block that matches the whole file keeps doing so, and a held link block is left as it is.
// The caller writes it only to a run whose launcher reads it (TakesLink).
func (o *Overlay) AddLink(kind Kind, value, by string, at time.Time) (Change, bool, error) {
	return o.add(kind, value, MatchLink, by, at, time.Time{})
}

// add is AddUntil with the match asked for (Entry.Match): a held block keeps the wider of its own match and the one
// asked, where "" (the whole file) is the wider.
func (o *Overlay) add(kind Kind, value, match, by string, at, until time.Time) (Change, bool, error) {
	v, err := Normalize(kind, value)
	if err != nil {
		return Change{}, false, err
	}
	if !linkable(kind, v) {
		match = ""
	}
	resolved := ""
	at, until = at.UTC().Round(time.Millisecond), until.UTC()
	if !until.IsZero() {
		if err := checkUntilSlack(at, until); err != nil {
			return Change{}, false, err
		}
	}
	i := slices.IndexFunc(o.Blocks, func(e Entry) bool { return e.Key() == Key(kind, v) })
	if i >= 0 {
		until = laterEnd(o.Blocks[i].Until, until)
		if o.Blocks[i].Real != "" {
			resolved = o.Blocks[i].Real
		}
		if o.Blocks[i].Match == "" {
			match = "" // a block that refuses the whole file is never narrowed to one name of it
		}
	}
	switch {
	case i >= 0 && o.Blocks[i].From.IsZero() && o.Blocks[i].Until.Equal(until) && o.Blocks[i].Real == resolved && o.Blocks[i].Match == match:
		return Change{}, false, nil
	case i >= 0:
		o.Blocks[i] = Entry{Kind: kind, Value: v, By: by, At: at, Until: until, Real: resolved, Match: match}
	case len(o.Blocks) >= MaxBlocks:
		return Change{}, false, fmt.Errorf("%w: the run already has %d live blocks, the most it may hold", ErrInvalid, MaxBlocks)
	default:
		o.Blocks = append(o.Blocks, Entry{Kind: kind, Value: v, By: by, At: at, Until: until, Real: resolved, Match: match})
	}
	return o.record(Change{Op: OpAdd, Kind: kind, Value: v, By: by, At: at, Until: until}), true, nil
}

// SetReal sets resolved (RealPath) as the Real of the held block of kind on value, normalized, so the Set refuses
// both spellings, and reports whether it changed the overlay. It only narrows, so it records no change: the block's
// add has its line already, and a change carries no Real. It does nothing, and reports false, on a block the overlay
// does not hold, on an exec or net block, on a resolved that is not a normalized path other than the value, and on a
// block that already has a Real: a spelling is never dropped or replaced.
//
// The writer adds the block with its value alone first, so it is in force at once, and resolves its real path after,
// with a budget (RealPath), in a second Update.
func (o *Overlay) SetReal(kind Kind, value, resolved string) bool {
	v, err := Normalize(kind, value)
	if err != nil || kind.Access() == 0 || resolved == "" {
		return false
	}
	if r, err := Normalize(kind, resolved); err != nil || r != resolved || r == v {
		return false // not a spelling the Set could match: the value alone, as before Real
	}
	i := slices.IndexFunc(o.Blocks, func(e Entry) bool { return e.Key() == Key(kind, v) })
	if i < 0 || o.Blocks[i].Real != "" {
		return false
	}
	o.Blocks[i].Real = resolved
	return true
}

// laterEnd is the later of two block ends, where zero (no end) is the latest.
func laterEnd(a, b time.Time) time.Time {
	if a.IsZero() || b.IsZero() {
		return time.Time{}
	}
	if a.After(b) {
		return a
	}
	return b
}

// Remove removes the block of kind on value, normalized, recording the change; it reports false (and changes
// nothing) when the overlay holds no such block. It is RemoveUntil with a zero until.
func (o *Overlay) Remove(kind Kind, value, by string, at time.Time) (Change, bool, error) {
	return o.RemoveUntil(kind, value, by, at, time.Time{})
}

// RemoveUntil removes the block of kind on value, normalized, until until, recording the change with its until: the
// block is kept dormant with From at until, refuses nothing before then and refuses again from then on, and the
// launcher writes its live-unblock-expired line. A zero until removes it for the rest of the run, as Remove does, and
// so does an until at or after the block's own end (it would never refuse again). It reports false (and changes
// nothing) when the overlay holds no such block, or holds it dormant until the same instant.
func (o *Overlay) RemoveUntil(kind Kind, value, by string, at, until time.Time) (Change, bool, error) {
	v, err := Normalize(kind, value)
	if err != nil {
		return Change{}, false, err
	}
	at, until = at.UTC().Round(time.Millisecond), until.UTC()
	if !until.IsZero() {
		if err := checkUntilSlack(at, until); err != nil {
			return Change{}, false, err
		}
	}
	i := slices.IndexFunc(o.Blocks, func(e Entry) bool { return e.Key() == Key(kind, v) })
	if i < 0 {
		return Change{}, false, nil
	}
	e := &o.Blocks[i]
	if !until.IsZero() && !e.Until.IsZero() && !until.Before(e.Until) {
		until = time.Time{} // the block ends before the unblock would: it is simply gone
	}
	if until.IsZero() {
		o.Blocks = slices.Delete(o.Blocks, i, i+1)
		return o.record(Change{Op: OpRemove, Kind: kind, Value: v, By: by, At: at}), true, nil
	}
	if e.From.Equal(until) {
		return Change{}, false, nil
	}
	e.From = until
	return o.record(Change{Op: OpRemove, Kind: kind, Value: v, By: by, At: at, Until: until}), true, nil
}

// Pause asks for the run to be frozen, recording the change; it reports false (and changes nothing) when the overlay
// already asks for that.
func (o *Overlay) Pause(by string, at time.Time) (Change, bool) {
	if o.Paused {
		return Change{}, false
	}
	o.Paused = true
	return o.record(Change{Op: OpPause, By: by, At: at.UTC().Round(time.Millisecond)}), true
}

// Resume asks for a paused run to be thawed, recording the change; it reports false (and changes nothing) when the
// overlay asks for no pause. It lifts the pause only: every live block stays as it is.
func (o *Overlay) Resume(by string, at time.Time) (Change, bool) {
	if !o.Paused {
		return Change{}, false
	}
	o.Paused = false
	return o.record(Change{Op: OpResume, By: by, At: at.UTC().Round(time.Millisecond)}), true
}

// record numbers c with the overlay's next serial and appends it, keeping the newest MaxChanges.
func (o *Overlay) record(c Change) Change {
	o.Serial++
	c.Serial = o.Serial
	o.Changes = append(o.Changes, c)
	if len(o.Changes) > MaxChanges {
		o.Changes = slices.Delete(o.Changes, 0, len(o.Changes)-MaxChanges)
	}
	return c
}

// Since is the changes after serial, oldest first, and how many of them the overlay no longer holds (it keeps the
// newest MaxChanges).
func (o *Overlay) Since(serial uint64) (changes []Change, lost uint64) {
	for _, c := range o.Changes {
		if c.Serial > serial {
			changes = append(changes, c)
		}
	}
	if o.Serial > serial {
		if missing := o.Serial - serial - uint64(len(changes)); missing > 0 {
			lost = missing
		}
	}
	return changes, lost
}

// Encode is the overlay's file bytes, after Validate, at the lowest version that holds them (MinVersion), which it
// sets as o.V.
func (o *Overlay) Encode() ([]byte, error) {
	if o != nil {
		o.V = o.MinVersion()
	}
	if err := o.Validate(o.Run); err != nil {
		return nil, err
	}
	b, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// MinVersion is the lowest version that holds o: VersionLink when an entry has a Match, VersionReal when an entry has a
// Real, VersionModes when a change it lists is a lift or a restore, VersionTimed when an entry or a change has an until
// or a from, Version otherwise.
func (o *Overlay) MinVersion() int {
	for _, e := range o.Blocks {
		if e.Match != "" {
			return VersionLink
		}
	}
	for _, e := range o.Blocks {
		if e.Real != "" {
			return VersionReal
		}
	}
	v := Version
	for _, c := range o.Changes {
		if c.Fence() {
			return VersionModes
		}
		if !c.Until.IsZero() {
			v = VersionTimed
		}
	}
	for _, e := range o.Blocks {
		if !e.Until.IsZero() || !e.From.IsZero() {
			v = VersionTimed
		}
	}
	return v
}

// Decode reads an overlay's file bytes and validates them against run ("" accepts any run).
func Decode(b []byte, run string) (*Overlay, error) {
	if len(b) > MaxFileBytes {
		return nil, fmt.Errorf("%w: overlay of %d bytes, more than %d", ErrInvalid, len(b), MaxFileBytes)
	}
	var o Overlay
	d := json.NewDecoder(bytes.NewReader(b))
	if err := d.Decode(&o); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if d.More() {
		return nil, fmt.Errorf("%w: data after the overlay", ErrInvalid)
	}
	if err := o.Validate(run); err != nil {
		return nil, err
	}
	return &o, nil
}

// Validate checks what a reader relies on: the version, the run, every entry and change normalized and of a known
// kind, no block twice, at most MaxBlocks blocks and MaxChanges changes, change serials rising to Serial, a pause or
// a resume naming no block, and Paused agreeing with the last pause or resume the overlay still lists (or, when it
// lists none and dropped none, false). From VersionTimed, an entry or a change may carry an until after its at, and an
// entry a from before its until; from VersionModes, a change may be a lift (a fence kind, a MAC of 64 lower-case hex
// digits) or a restore (a fence kind, no MAC and no until); from VersionReal, an entry may carry a real path; from
// VersionLink, an exec entry on an absolute program path may carry the match MatchLink. Nothing newer than its version
// is accepted in a file.
func (o *Overlay) Validate(run string) error {
	switch {
	case o == nil:
		return fmt.Errorf("%w: no overlay", ErrInvalid)
	case o.V < Version || o.V > VersionLink:
		return fmt.Errorf("%w: overlay version %d, want %d to %d", ErrInvalid, o.V, Version, VersionLink)
	case run != "" && o.Run != run:
		return fmt.Errorf("%w: overlay of run %q, want %q", ErrInvalid, o.Run, run)
	case len(o.Blocks) > MaxBlocks:
		return fmt.Errorf("%w: %d blocks, more than %d", ErrInvalid, len(o.Blocks), MaxBlocks)
	case len(o.Changes) > MaxChanges:
		return fmt.Errorf("%w: %d changes, more than %d", ErrInvalid, len(o.Changes), MaxChanges)
	}
	seen := map[string]bool{}
	for _, e := range o.Blocks {
		if err := normalized(e.Kind, e.Value); err != nil {
			return err
		}
		if seen[e.Key()] {
			return fmt.Errorf("%w: %s blocked twice", ErrInvalid, e.Key())
		}
		seen[e.Key()] = true
		if err := o.realOf(e); err != nil {
			return err
		}
		if err := o.matchOf(e); err != nil {
			return err
		}
		if err := o.timed(e.Key(), e.At, e.Until, e.From); err != nil {
			return err
		}
	}
	var last uint64
	control := ""
	for _, c := range o.Changes {
		switch c.Op {
		case OpAdd, OpRemove:
			if err := normalized(c.Kind, c.Value); err != nil {
				return err
			}
		case OpPause, OpResume:
			if c.Kind != "" || c.Value != "" || !c.Until.IsZero() {
				return fmt.Errorf("%w: a %s names no block and no time limit (kind %q, value %q)", ErrInvalid, c.Op, c.Kind, c.Value)
			}
			control = c.Op
		case OpLift, OpRestore:
			if err := o.fenceChange(c); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: change op %q", ErrInvalid, c.Op)
		}
		if c.MAC != "" && c.Op != OpLift {
			return fmt.Errorf("%w: a %s carries no MAC", ErrInvalid, c.Op)
		}
		if err := o.timed(fmt.Sprintf("change %d", c.Serial), c.At, c.Until, time.Time{}); err != nil {
			return err
		}
		if c.Serial <= last || c.Serial > o.Serial {
			return fmt.Errorf("%w: change serial %d out of order (after %d, overlay at %d)", ErrInvalid, c.Serial, last, o.Serial)
		}
		last = c.Serial
	}
	if control != "" && o.Paused != (control == OpPause) {
		return fmt.Errorf("%w: paused is %t, but the last change of it was a %s", ErrInvalid, o.Paused, control)
	}
	// A pause is always a change: an overlay that lists every change it made (none dropped) and no pause cannot ask
	// for one, so the launcher never freezes a run with no line of who asked.
	if control == "" && o.Paused && uint64(len(o.Changes)) == o.Serial {
		return fmt.Errorf("%w: paused is true, but no pause is among its %d changes", ErrInvalid, len(o.Changes))
	}
	return nil
}

// timed checks what, at at, with an until and a from: neither below VersionTimed, an until after at, and a from
// before the until when both are set.
func (o *Overlay) timed(what string, at, until, from time.Time) error {
	switch {
	case until.IsZero() && from.IsZero():
		return nil
	case o.V < VersionTimed:
		return fmt.Errorf("%w: %s has a time limit, which a version %d overlay cannot hold", ErrInvalid, what, o.V)
	case !until.IsZero() && !until.After(at):
		return fmt.Errorf("%w: %s ends at %s, not after %s", ErrInvalid, what, until.Format(time.RFC3339Nano), at.Format(time.RFC3339Nano))
	case !until.IsZero() && !from.IsZero() && !from.Before(until):
		return fmt.Errorf("%w: %s refuses again at %s, not before it ends at %s", ErrInvalid, what,
			from.Format(time.RFC3339Nano), until.Format(time.RFC3339Nano))
	}
	return nil
}

// fenceChange checks a lift or a restore: not below VersionModes, of a fence kind, normalized, and a lift with a MAC
// of 64 lower-case hex digits, a restore with neither MAC nor until.
func (o *Overlay) fenceChange(c Change) error {
	if o.V < VersionModes {
		return fmt.Errorf("%w: a %s, which a version %d overlay cannot hold", ErrInvalid, c.Op, o.V)
	}
	if !slices.Contains(FenceKinds, c.Kind) {
		return fmt.Errorf("%w: a %s of kind %q, not read, net or exec", ErrInvalid, c.Op, c.Kind)
	}
	if err := normalized(c.Kind, c.Value); err != nil {
		return err
	}
	if c.Op == OpRestore {
		if c.MAC != "" || !c.Until.IsZero() {
			return fmt.Errorf("%w: a restore carries no MAC and no time limit", ErrInvalid)
		}
		return nil
	}
	if !hexMAC(c.MAC) {
		return fmt.Errorf("%w: a lift's MAC is not 64 lower-case hex digits", ErrInvalid)
	}
	return nil
}

// hexMAC reports whether s is 64 lower-case hex digits, an HMAC-SHA256 as LiftMAC spells it.
func hexMAC(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// realOf checks an entry's Real: none, or, from VersionReal, on a path, read or write block a normalized path other
// than its value.
func (o *Overlay) realOf(e Entry) error {
	switch {
	case e.Real == "":
		return nil
	case o.V < VersionReal:
		return fmt.Errorf("%w: %s carries a real path, which a version %d overlay cannot hold", ErrInvalid, e.Key(), o.V)
	case e.Kind.Access() == 0:
		return fmt.Errorf("%w: %s carries a real path, which only a path, read or write block may", ErrInvalid, e.Key())
	case e.Real == e.Value:
		return fmt.Errorf("%w: %s carries its own value as its real path", ErrInvalid, e.Key())
	}
	return normalized(e.Kind, e.Real)
}

// matchOf checks an entry's Match: none, or, from VersionLink, MatchLink on an exec block of an absolute program path.
func (o *Overlay) matchOf(e Entry) error {
	switch {
	case e.Match == "":
		return nil
	case o.V < VersionLink:
		return fmt.Errorf("%w: %s carries a match, which a version %d overlay cannot hold", ErrInvalid, e.Key(), o.V)
	case e.Match != MatchLink:
		return fmt.Errorf("%w: %s carries the match %q, not %q", ErrInvalid, e.Key(), e.Match, MatchLink)
	case !linkable(e.Kind, e.Value):
		return fmt.Errorf("%w: %s matches by link, which only an exec block on an absolute program path may", ErrInvalid, e.Key())
	}
	return nil
}

// normalized refuses a value that is not its own normal form, so two spellings of one block cannot both be held.
func normalized(kind Kind, value string) error {
	v, err := Normalize(kind, value)
	if err != nil {
		return err
	}
	if v != value {
		return fmt.Errorf("%w: %s value %q is not normalized (%q)", ErrInvalid, kind, value, v)
	}
	return nil
}
