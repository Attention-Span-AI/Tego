// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// fenceUnreadableBy is the by of the restore lines a broken overlay causes: no person asked for them.
const fenceUnreadableBy = "tego: the live overlay could not be read"

// fenceSeedBy is the by of a fence refusal: the contract placed it, before the agent's first instruction.
const fenceSeedBy = "contract"

// liveFence is an Adjustable run's fence as its launcher holds it (ADR 0125 decision 5): which fence entries are
// lifted, and until when. It is the only state that loosens anything. The overlay carries requests; a lift is put in
// force only once its MAC checks under the run's key and it names an entry of the compiled fence; and every line about
// a lift is written here from what took effect, never from the writer's change list. It implements fenceHook. The
// launcher's poll (pollLiveBlocks, expireLive) is its only caller, so it holds no lock.
type liveFence struct {
	run   string
	key   []byte
	start time.Time
	// entries are the fence's entries in the contract's order.
	entries []fenceEntry
	// index finds an entry by liveblock.Key of its kind and value.
	index map[string]int
	// lifts are the entries now allowed, by liveblock.Key.
	lifts map[string]lift
	emit  func(why string, count int, c *record.LiveBlockChange)
}

// fenceEntry is one entry of the compiled fence.
type fenceEntry struct {
	kind  liveblock.Kind
	value string
	// names are an exec entry's other names the kernel layers run because the entry is granted: the program name an
	// exec.deny entry named (agent.LiveEntry.Name) and the tool's helper images (agent.LiveEntry.Images). Each is
	// refused with the entry, under the entry's rule, until a lift.
	names []string
}

// key is the entry's liveblock.Key.
func (fe fenceEntry) key() string { return liveblock.Key(fe.kind, fe.value) }

// lift is one fence entry allowed until its until (zero: the rest of the run), pinned on BOOTTIME when first seen.
type lift struct {
	until  time.Time
	pin    time.Duration
	pinned bool
	by     string
	serial uint64
}

// newLiveFence is the fence of an Adjustable table with every entry refused and nothing lifted. Each value, and each
// other name of an exec entry, must be what liveblock.Normalize makes of it, the form every overlay request names it
// by: one that is not is refused, so a lift can never miss the entry it means, nor the refusal the action, by a
// spelling.
func newLiveFence(live *agent.LiveTable, run string, key []byte, start time.Time,
	emit func(string, int, *record.LiveBlockChange)) (*liveFence, error) {
	f := &liveFence{run: run, key: key, start: start.UTC().Round(time.Millisecond), index: map[string]int{},
		lifts: map[string]lift{}, emit: emit}
	if live == nil {
		return f, nil
	}
	for _, e := range live.Entries {
		kind := liveblock.Kind(e.Kind)
		if v, err := liveblock.Normalize(kind, e.Value); err != nil || v != e.Value {
			return nil, fmt.Errorf("live fence: entry %s:%s is not in the form the live overlay names it (%v)", e.Kind, e.Value, err)
		}
		fe := fenceEntry{kind: kind, value: e.Value}
		if _, dup := f.index[fe.key()]; dup {
			continue
		}
		if kind == liveblock.KindExec {
			others := append([]string(nil), e.Images...)
			if e.Name != "" {
				others = append(others, e.Name)
			}
			for _, n := range others {
				if v, err := liveblock.Normalize(liveblock.KindExec, n); err != nil || v != n {
					return nil, fmt.Errorf("live fence: exec entry %s names program %q, which the live overlay cannot name (%v)", e.Value, n, err)
				}
				if n != e.Value {
					fe.names = append(fe.names, n)
				}
			}
		}
		f.index[fe.key()] = len(f.entries)
		f.entries = append(f.entries, fe)
	}
	return f, nil
}

// Apply is fenceHook.Apply: each change in serial order or, with unreadable, every lift dropped.
func (f *liveFence) Apply(_ context.Context, now liveblock.Clock, changes []liveblock.Change, unreadable bool) bool {
	if unreadable {
		changed := false
		for _, fe := range f.entries {
			l, ok := f.lifts[fe.key()]
			if !ok {
				continue
			}
			delete(f.lifts, fe.key())
			changed = true
			f.line(record.GapLiveRuleRestored, record.LiveOpRestore, fe.kind, fe.value, fenceUnreadableBy, l.serial,
				now.Wall, time.Time{}, "")
		}
		return changed
	}
	changed := false
	for _, c := range changes {
		switch c.Op {
		case liveblock.OpLift:
			changed = f.lift(c, now) || changed
		case liveblock.OpRestore:
			k := liveblock.Key(c.Kind, c.Value)
			if _, ok := f.lifts[k]; !ok {
				continue // not lifted: it already refuses
			}
			delete(f.lifts, k)
			changed = true
			f.line(record.GapLiveRuleRestored, record.LiveOpRestore, c.Kind, c.Value, c.By, c.Serial, c.At, time.Time{}, "")
		}
	}
	return changed
}

// lift applies one lift change. It is refused, with its line, when its MAC does not check under the run's key, it
// names no fence entry, or its limit has already come; otherwise it is put in force with its line, unless the same
// lift already is. The line is queued before Apply returns, so before the loosened Set is stored.
func (f *liveFence) lift(c liveblock.Change, now liveblock.Clock) bool {
	k := liveblock.Key(c.Kind, c.Value)
	_, inFence := f.index[k]
	refused := ""
	switch {
	case !liveblock.LiftMACOK(f.key, f.run, c):
		refused = record.LiveRefusedMAC
	case !inFence:
		refused = record.LiveRefusedOutsideFence
	case !c.Until.IsZero() && liveblock.Begun(c.Until, 0, false, now):
		refused = record.LiveRefusedUntil
	}
	if refused != "" {
		f.line(record.GapLiveLiftRefused, record.LiveOpLift, c.Kind, c.Value, c.By, c.Serial, c.At, c.Until, refused)
		return false
	}
	l := lift{until: c.Until.UTC(), by: c.By, serial: c.Serial}
	if !l.until.IsZero() {
		l.pin, l.pinned = now.Pin(l.until), true
	}
	if old, ok := f.lifts[k]; ok && old.until.Equal(l.until) {
		return false // the same lift is in force: nothing changes, and its line was written when it took effect
	}
	f.line(record.GapLiveRuleLifted, record.LiveOpLift, c.Kind, c.Value, c.By, c.Serial, c.At, c.Until, "")
	f.lifts[k] = l
	return true
}

// Tick is fenceHook.Tick: every lift whose limit has come on either clock ends, with its live-lift-expired line. The
// Set already refused again at the instant, since Refusals gives such a lift's entry From its until.
func (f *liveFence) Tick(_ context.Context, now liveblock.Clock) bool {
	changed := false
	for _, fe := range f.entries {
		l, ok := f.lifts[fe.key()]
		if !ok || l.until.IsZero() || !liveblock.Begun(l.until, l.pin, l.pinned, now) {
			continue
		}
		delete(f.lifts, fe.key())
		changed = true
		f.line(record.GapLiveLiftExpired, record.LiveOpExpire, fe.kind, fe.value, l.by, l.serial, now.Wall, l.until, "")
	}
	return changed
}

// Refusals is fenceHook.Refusals. Every entry not lifted refuses from the run's start. A lift with a limit refuses
// again from its until (From), so the Set refuses at the exact instant on either clock, before Tick writes its line.
// A lift with no end refuses nothing. An exec entry's other names refuse with it, under its rule (Entry.FenceOf).
func (f *liveFence) Refusals() []liveblock.Entry {
	out := make([]liveblock.Entry, 0, len(f.entries))
	for _, fe := range f.entries {
		l, lifted := f.lifts[fe.key()]
		if lifted && l.until.IsZero() {
			continue
		}
		e := liveblock.Entry{Kind: fe.kind, Value: fe.value, By: fenceSeedBy, At: f.start, Fence: true}
		if lifted {
			e.From = l.until
		}
		out = append(out, e)
		for _, n := range fe.names {
			o := e
			o.Value, o.FenceOf = n, fe.value
			out = append(out, o)
		}
	}
	return out
}

// Pins is fenceHook.Pins: the BOOTTIME pin of every lift's until, keyed as the Set looks a From up (DeadlineKey of
// the refusal's key), for each other name of an exec entry too.
func (f *liveFence) Pins() map[string]time.Duration {
	var out map[string]time.Duration
	for _, fe := range f.entries {
		l, ok := f.lifts[fe.key()]
		if !ok || !l.pinned {
			continue
		}
		if out == nil {
			out = map[string]time.Duration{}
		}
		out[liveblock.DeadlineKey(fe.key(), l.until)] = l.pin
		for _, n := range fe.names {
			out[liveblock.DeadlineKey(liveblock.Key(fe.kind, n), l.until)] = l.pin
		}
	}
	return out
}

// line queues one gap line about a fence entry, under its rule live.fence[<kind>:<value>], or about a refused lift
// that names none, under the request's rule (RefusedRule).
func (f *liveFence) line(why, op string, kind liveblock.Kind, value, by string, serial uint64, at, until time.Time, refused string) {
	if f.emit == nil {
		return
	}
	f.emit(why, 0, &record.LiveBlockChange{Op: op, Kind: string(kind), Value: value,
		Rule: f.RefusedRule(kind, value), By: by, Serial: serial, At: at.UTC().Round(time.Millisecond),
		Until: until, Refused: refused})
}

// RefusedRule is fenceHook.RefusedRule: live.fence[<kind>:<value>] for one of the run's fence entries, and
// live.lift[<kind>:<value>] for anything else, which no run_start.live_fence lists.
func (f *liveFence) RefusedRule(kind liveblock.Kind, value string) string {
	if _, ok := f.index[liveblock.Key(kind, value)]; ok {
		return liveblock.FenceRule(kind, value)
	}
	return liveblock.LiftRule(kind, value)
}

// checkAdjustable is ADR 0125 decision 6 for an Adjustable run, nil for every other. The run starts only with a run
// directory (the overlay and the run's key live there), as a run and not an --observe run (an adoption is refused
// before it gets here, refuseAdjustable), with a supervisor that serves it and io_uring off (compile refuses it too), at a tier LiveTierCheck allows, with no
// notification its decision plane decides in the kernel instead, and, with read entries in the fence, with its read
// opens held, so a read fence refusal holds on the object the deputy opened.
func (r *runner) checkAdjustable() error {
	if !r.rt.Adjustable() {
		return nil
	}
	tier := r.rt.Tier
	if r.deps.Enforce != nil {
		tier = r.deps.Enforce.Tier()
	}
	observe := recordsOnly(r.handle)
	refuse := func(why string) error { return fmt.Errorf("%w: %s (ADR 0125 decision 6)", ErrLiveStart, why) }
	switch {
	case r.dir == "":
		return refuse("the run has no run directory, so there is no live overlay and no key for a lift")
	case observe:
		return refuse("an --observe run enforces nothing, so it has no live refusal to lift")
	case r.notifyFD == nil:
		return refuse("no supervisor serves the run at tier " + string(tier) + ", so nothing would refuse the fence's entries")
	case r.rt.Contract != nil && r.rt.Contract.IOUring:
		return refuse("io_uring: true lets a ring's connects and opens pass the supervisor, so a fence entry could be " +
			"reached with no lift")
	}
	if !liveAnyTier() {
		if err := agent.LiveTierCheck(tier, observe); err != nil {
			return fmt.Errorf("%w: %w", ErrLiveStart, err)
		}
	}
	if r.planeFS {
		return refuse("the decision plane decides notifications the supervisor would otherwise see, so a fence entry " +
			"could be reached where Tego's live layer cannot refuse it")
	}
	if !runDirDenied(r.rt, r.dir) {
		return refuse("the run directory " + r.dir + " lies under no enforced built-in deny_read entry (the ledger " +
			"root is readable to the run, compile's ledger-readable warning), so the agent could read the run's key; " +
			"give ledger_root a directory of its own, outside the project, HOME and every write entry")
	}
	for _, e := range r.rt.Live.Entries {
		if e.Kind == agent.LiveKindRead && !r.rt.ReadsHeldAt(tier) {
			return refuse("the fence has read entries but the run does not hold its read opens at tier " + string(tier) +
				", so a read fence refusal could be raced with a symlink")
		}
	}
	return nil
}

// runDirDenied reports whether dir, the run directory that holds the run's live-key, lies at or beneath a built-in
// deny_read entry the table enforces: Tego's own state, which compile read-denies (R6a) unless the ledger root also
// holds something the run needs (CodeLedgerReadable), when it stays readable. ADR 0125's argument that the agent
// cannot lift its own rules rests on the key being out of every run's reach, so an Adjustable run does not start
// without it.
func runDirDenied(rt *agent.RuleTable, dir string) bool {
	if rt == nil || dir == "" {
		return false
	}
	at := []string{filepath.Clean(dir)}
	if rd, err := filepath.EvalSymlinks(dir); err == nil && rd != at[0] {
		at = append(at, rd)
	}
	for _, f := range rt.FS {
		if f.Kind != agent.FSDenyRead || !f.BuiltIn || f.Unenforced {
			continue
		}
		for _, p := range []string{f.Path, f.Resolved} {
			if p == "" || !filepath.IsAbs(p) {
				continue
			}
			p = filepath.Clean(p)
			for _, d := range at {
				if d == p || strings.HasPrefix(d, strings.TrimSuffix(p, "/")+"/") {
					return true
				}
			}
		}
	}
	return false
}

// seedFence makes an Adjustable run's fence, every entry refused, and its key (liveblock.WriteKey, mode 0600 in the
// run directory, which the agent cannot read): a lift is put in force only when its MAC checks under that key.
func (r *runner) seedFence() (*liveFence, error) {
	f, err := newLiveFence(r.rt.Live, string(r.id), nil, time.Now(), r.emitLiveGap)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLiveStart, err)
	}
	if f.key, err = liveblock.WriteKey(r.dir); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLiveStart, err)
	}
	return f, nil
}

// errLiveLoopEnded ends an Adjustable run whose supervisor loop stopped while the run's processes still ran.
var errLiveLoopEnded = errors.New("the supervisor stopped while the run's processes still ran; an Adjustable run " +
	"ends then, since its live refusals are the supervisor's (ADR 0125 decision 5)")

// loopEndSettle bounds how long adjustableLoopEnded waits for the run's processes to be gone after its loop returned.
var loopEndSettle = 2 * time.Second

// adjustableLoopEnded is what an Adjustable run does when its supervisor loop returned nil after it started while the
// run goes on (ctx alive). A listener hangs up when the last task under the filter exits, so the loop returning is
// normally the end of the run, and the run's cgroup soon holds nothing but the open deputy. If it still holds another
// process after loopEndSettle, the loop stopped under a live run: the error fails the run's group, which cancels the
// run and kills its cgroup (awaitExit), so no process lives on with a fence nothing refuses. A loop that returns an
// error already ends every run that way, Locked included.
func (r *runner) adjustableLoopEnded(ctx context.Context) error {
	deadline := time.Now().Add(loopEndSettle)
	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	for {
		if ctx.Err() != nil || r.runGone() {
			return nil
		}
		if time.Now().After(deadline) {
			return errLiveLoopEnded
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// runGone reports whether the run's cgroup holds no process but the open deputy. A run with no cgroup to read is not
// known to be gone (fail closed).
func (r *runner) runGone() bool {
	if r.cg.Path == "" {
		return false
	}
	pid := ""
	if r.deputy != nil {
		pid = strconv.Itoa(r.deputy.PID())
	}
	return onlyProcess(r.cg.Path, pid)
}
