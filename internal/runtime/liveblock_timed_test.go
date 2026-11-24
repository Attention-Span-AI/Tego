// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// gapPayloads drains r's queue: each line's payload, one per line.
func gapPayloads(t *testing.T, r *runner) []byte {
	t.Helper()
	r.queue.Close()
	var out []byte
	for ev := range r.queue.C() {
		out = append(out, ev.Payload...)
		out = append(out, '\n')
	}
	return out
}

func updateOverlay(t *testing.T, dir, run string, fn func(o *liveblock.Overlay) error) {
	t.Helper()
	if _, err := liveblock.Update(context.Background(), dir, run, func(o *liveblock.Overlay) (bool, error) {
		return true, fn(o)
	}); err != nil {
		t.Fatal(err)
	}
}

// TestPlainBlockLinesGolden is the Locked-unchanged test of the launcher (ADR 0125): plain adds and removes, with no
// time limit, give the gap lines the base build gave, byte for byte (testdata/liveblock_lines_golden.jsonl, captured
// from master 9d29e3a78).
func TestPlainBlockLinesGolden(t *testing.T) {
	r := pauseRunner(t)
	b := &liveBlocks{}
	ctx := context.Background()
	at := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		if _, _, err := o.Add(liveblock.KindExec, "/bin/ls", "uid:1000 pid:7 cli", at); err != nil {
			return err
		}
		_, _, err := o.Add(liveblock.KindPath, "/srv/x", "uid:1000 pid:8 dashboard", at.Add(time.Second))
		return err
	})
	r.pollLiveBlocks(ctx, b)
	r.pollLiveBlocks(ctx, b)
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, _, err := o.Remove(liveblock.KindExec, "/bin/ls", "uid:1000 pid:9 cli", at.Add(time.Minute))
		return err
	})
	r.pollLiveBlocks(ctx, b)
	got := gapPayloads(t, r)
	golden := filepath.Join("testdata", "liveblock_lines_golden.jsonl")
	if os.Getenv("TEGO_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("plain block lines\n%s\nwant (the base build's)\n%s", got, want)
	}
}

// liveLines drains r's queue for its live_block gap lines, decoded, in order.
func liveLines(t *testing.T, r *runner) []record.GapPayload {
	t.Helper()
	r.queue.Close()
	var got []record.GapPayload
	for ev := range r.queue.C() {
		var p record.GapPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.LiveBlock != nil {
			got = append(got, p)
		}
	}
	return got
}

// timedFixture writes the overlay of TestTimedBlockAndUnblockExpire (a block that ends at end, an unblock that
// ends at end, both set at at) and steps the launcher's clocks (liveNow) by hand: wall and BOOTTIME start at at and
// the boot it fell in, and the returned step moves both to d after at. The limits are short, set straight in the file:
// AddUntil refuses less than a minute. The returned clock is restored by a t.Cleanup, so a failed assertion leaves
// nothing behind.
func timedFixture(t *testing.T, r *runner, at, end time.Time) (step func(d time.Duration)) {
	t.Helper()
	real := liveblock.ReadClock()
	now := liveblock.Clock{Wall: at, Boot: real.Boot, BootID: real.BootID}
	old := liveNow
	liveNow = func() liveblock.Clock { return now }
	t.Cleanup(func() { liveNow = old })
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		o.Blocks = []liveblock.Entry{
			{Kind: liveblock.KindExec, Value: "/bin/ls", By: "uid:1 pid:2 cli", At: at, Until: end},
			{Kind: liveblock.KindNet, Value: "192.0.2.7:443", By: "uid:1 pid:3 dashboard", At: at, From: end},
		}
		o.Changes = []liveblock.Change{
			{Serial: 1, Op: liveblock.OpAdd, Kind: liveblock.KindExec, Value: "/bin/ls", By: "uid:1 pid:2 cli", At: at, Until: end},
			{Serial: 2, Op: liveblock.OpAdd, Kind: liveblock.KindNet, Value: "192.0.2.7:443", By: "uid:1 pid:3 dashboard", At: at},
			{Serial: 3, Op: liveblock.OpRemove, Kind: liveblock.KindNet, Value: "192.0.2.7:443", By: "uid:1 pid:4 cli", At: at, Until: end},
		}
		o.Serial = 3
		return nil
	})
	boot0 := real.Boot
	return func(d time.Duration) { now.Wall, now.Boot = at.Add(d), boot0+d }
}

// TestTimedBlockAndUnblockExpire: a block with a limit refuses until the instant and an unblock with a limit
// refuses nothing until it; once both instants pass, the stored Set has stopped and started refusing, and each
// limit's end has exactly one line, carrying the until that passed, the serial and by of the change that set it, and
// the rule of the block. No host speed decides it. The launcher's clocks are the test's own (liveNow), and the Set
// judges a match on the real clock (liveblock's own clock tests step that one), so each side is built so that the real
// clock cannot disagree with what the test asserts however slow the host is: before the limit, the instants are an
// hour ahead of the real time and nothing waits for them; after it, they are already behind the real time when the
// test starts.
func TestTimedBlockAndUnblockExpire(t *testing.T) {
	ap := netip.MustParseAddrPort("192.0.2.7:443")
	ctx := context.Background()
	t.Run("before the limit", func(t *testing.T) {
		r := pauseRunner(t)
		b := &liveBlocks{}
		at := time.Now().UTC().Round(time.Millisecond)
		end := at.Add(time.Hour)
		timedFixture(t, r, at, end)
		r.pollLiveBlocks(ctx, b)
		if _, ok := b.Load().MatchExec([]string{"/bin/ls"}, liveblock.FileID{}, false, nil); !ok {
			t.Fatal("a block with a limit to come does not refuse")
		}
		if _, ok := b.Load().MatchInet(ap, "", nil); ok {
			t.Fatal("a block unblocked until a limit to come refuses")
		}
		for _, p := range liveLines(t, r) {
			if p.Why == record.GapLiveBlockExpired || p.Why == record.GapLiveUnblockExpired {
				t.Fatalf("a limit that has not come has an end line: %q", p.Why)
			}
		}
	})
	t.Run("after the limit", func(t *testing.T) {
		r := pauseRunner(t)
		b := &liveBlocks{}
		at := time.Now().UTC().Round(time.Millisecond).Add(-10 * time.Second)
		end := at.Add(1200 * time.Millisecond)
		step := timedFixture(t, r, at, end)
		r.pollLiveBlocks(ctx, b)
		step(1250 * time.Millisecond)
		r.pollLiveBlocks(ctx, b)
		r.pollLiveBlocks(ctx, b) // each end is recorded once
		if _, ok := b.Load().MatchExec([]string{"/bin/ls"}, liveblock.FileID{}, false, nil); ok {
			t.Fatal("a block past its limit still refuses")
		}
		if b.Load().HasExec() {
			// Has* are structural: an ended block left in would go on refusing every exec the supervisor could not walk.
			t.Fatal("a block past its limit is still compiled in")
		}
		if e, ok := b.Load().MatchInet(ap, "", nil); !ok || e.Rule() != "live.block[net:192.0.2.7:443]" {
			t.Fatal("a block whose unblock ended does not refuse again")
		}
		var whys []string
		for _, p := range liveLines(t, r) {
			whys = append(whys, p.Why)
			c := p.LiveBlock
			switch p.Why {
			case record.GapLiveBlockExpired:
				if c.Op != "expire" || c.Rule != "live.block[exec:/bin/ls]" || !c.Until.Equal(end) || c.Serial != 1 || c.By != "uid:1 pid:2 cli" {
					t.Errorf("expired line %+v", c)
				}
			case record.GapLiveUnblockExpired:
				if c.Op != "expire" || c.Rule != "live.block[net:192.0.2.7:443]" || !c.Until.Equal(end) || c.Serial != 3 || c.By != "uid:1 pid:4 cli" {
					t.Errorf("unblock-expired line %+v", c)
				}
			case record.GapLiveBlockAdded:
				if c.Serial == 1 && !c.Until.Equal(end) {
					t.Errorf("the timed add's line has no until: %+v", c)
				}
			case record.GapLiveBlockRemoved:
				if !c.Until.Equal(end) {
					t.Errorf("the timed remove's line has no until: %+v", c)
				}
			}
		}
		want := []string{record.GapLiveBlockAdded, record.GapLiveBlockAdded, record.GapLiveBlockRemoved,
			record.GapLiveBlockExpired, record.GapLiveUnblockExpired}
		if !slices.Equal(whys, want) {
			t.Fatalf("lines %q, want %q", whys, want)
		}
	})
}

// TestExpiryWaitsForBothClocks: with the wall clock stepped past a block's limit but BOOTTIME short of its pin, the
// launcher writes no expiry yet; once BOOTTIME reaches the pin it writes one.
func TestExpiryWaitsForBothClocks(t *testing.T) {
	r := pauseRunner(t)
	b := &liveBlocks{}
	ctx := context.Background()
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	now := liveblock.Clock{Wall: t0, Boot: time.Hour}
	old := liveNow
	liveNow = func() liveblock.Clock { return now }
	t.Cleanup(func() { liveNow = old })
	end := t0.Add(2 * time.Hour)
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, _, err := o.AddUntil(liveblock.KindPath, "/srv/x", "uid:1 pid:2 cli", t0, end)
		return err
	})
	r.pollLiveBlocks(ctx, b)
	now = liveblock.Clock{Wall: end.Add(time.Hour), Boot: time.Hour + time.Hour} // wall stepped forward
	r.pollLiveBlocks(ctx, b)
	now.Boot = 3 * time.Hour // BOOTTIME reaches the pin
	r.pollLiveBlocks(ctx, b)
	var whys []string
	for _, p := range liveLines(t, r) {
		whys = append(whys, p.Why)
	}
	if want := []string{record.GapLiveBlockAdded, record.GapLiveBlockExpired}; !slices.Equal(whys, want) {
		t.Fatalf("lines %q, want %q", whys, want)
	}
}

// TestLiftOnLockedRunIsRefused: a lift in the overlay of a run with no fence gets one live-lift-refused {locked} and
// loosens nothing; a restore gets no line.
func TestLiftOnLockedRunIsRefused(t *testing.T) {
	r := pauseRunner(t)
	b := &liveBlocks{}
	ctx := context.Background()
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		if _, _, err := o.Add(liveblock.KindExec, "/usr/bin/psql", "uid:1 pid:2 cli", time.Now()); err != nil {
			return err
		}
		if _, err := o.Lift(liveblock.KindExec, "/usr/bin/psql", "uid:1 pid:3 cli", time.Now(), time.Time{}, make([]byte, 32)); err != nil {
			return err
		}
		_, err := o.Restore(liveblock.KindNet, "api.stripe.com:443", "uid:1 pid:4 cli", time.Now())
		return err
	})
	r.pollLiveBlocks(ctx, b)
	r.pollLiveBlocks(ctx, b)
	if _, ok := b.Load().MatchExec([]string{"/usr/bin/psql"}, liveblock.FileID{}, false, nil); !ok {
		t.Fatal("a lift on a Locked run loosened its live block")
	}
	lines := liveLines(t, r)
	if len(lines) != 2 || lines[1].Why != record.GapLiveLiftRefused {
		t.Fatalf("lines %+v, want an add and one live-lift-refused", lines)
	}
	c := lines[1].LiveBlock
	if c.Op != "lift" || c.Refused != record.LiveRefusedLocked || c.Rule != "live.lift[exec:/usr/bin/psql]" || c.Serial != 2 {
		t.Fatalf("refused lift line %+v", c)
	}
}

// fakeFence is a fence that refuses one entry until a lift and records what it was handed.
type fakeFence struct {
	lifted     bool
	unreadable int
	ticks      int
	got        []liveblock.Change
}

func (f *fakeFence) Apply(_ context.Context, _ liveblock.Clock, changes []liveblock.Change, unreadable bool) bool {
	was := f.lifted
	if unreadable {
		f.unreadable++
		f.lifted = false
	}
	for _, c := range changes {
		f.lifted = c.Op == liveblock.OpLift
	}
	f.got = append(f.got, changes...)
	return was != f.lifted
}

func (f *fakeFence) Tick(context.Context, liveblock.Clock) bool { f.ticks++; return false }

func (f *fakeFence) Refusals() []liveblock.Entry {
	if f.lifted {
		return nil
	}
	return []liveblock.Entry{{Kind: liveblock.KindRead, Value: "/srv/exports", Fence: true}}
}

func (f *fakeFence) Pins() map[string]time.Duration { return nil }

func (f *fakeFence) RefusedRule(kind liveblock.Kind, value string) string {
	return liveblock.FenceRule(kind, value)
}

// TestFenceSeam: the poll hands lifts to the fence, puts its refusals in force under live.fence[...], and calls it
// unreadable when the overlay is removed, so the refusal comes back (fail closed).
func TestFenceSeam(t *testing.T) {
	r := pauseRunner(t)
	f := &fakeFence{}
	b := &liveBlocks{fence: f}
	ctx := context.Background()
	r.pollLiveBlocks(ctx, b)
	if e, ok := b.Load().MatchPath("/srv/exports/q3.csv", liveblock.AccessRead); !ok || e.Rule() != "live.fence[read:/srv/exports]" {
		t.Fatalf("the fence's refusal is not in force: %+v %v", e, ok)
	}
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, err := o.Lift(liveblock.KindRead, "/srv/exports", "uid:1 pid:2 cli", time.Now(), time.Time{}, make([]byte, 32))
		return err
	})
	r.pollLiveBlocks(ctx, b)
	if _, ok := b.Load().MatchPath("/srv/exports/q3.csv", liveblock.AccessRead); ok {
		t.Fatal("a lift the fence applied did not loosen the set")
	}
	if err := os.Remove(filepath.Join(r.dir, liveblock.FileName)); err != nil {
		t.Fatal(err)
	}
	r.pollLiveBlocks(ctx, b)
	if _, ok := b.Load().MatchPath("/srv/exports/q3.csv", liveblock.AccessRead); !ok || f.unreadable != 1 {
		t.Fatalf("a removed overlay kept the lift (unreadable calls %d)", f.unreadable)
	}
	if f.ticks != 3 {
		t.Fatalf("the fence was ticked %d times in 3 polls", f.ticks)
	}
}

// TestLostChangesDropLifts: when changes were trimmed from the overlay between two polls, a restore among them never
// reaches the fence, so the poll drops every lift first (fail closed) and then applies the changes that survived.
func TestLostChangesDropLifts(t *testing.T) {
	r := pauseRunner(t)
	f := &fakeFence{}
	b := &liveBlocks{fence: f}
	ctx := context.Background()
	r.pollLiveBlocks(ctx, b)
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		for range liveblock.MaxChanges + 1 {
			if _, err := o.Lift(liveblock.KindRead, "/srv/exports", "uid:1 pid:2 cli", time.Now(), time.Time{}, make([]byte, 32)); err != nil {
				return err
			}
		}
		return nil
	})
	r.pollLiveBlocks(ctx, b)
	if f.unreadable != 1 {
		t.Fatalf("lost changes called the fence unreadable %d times, want 1", f.unreadable)
	}
	if !f.lifted {
		t.Fatal("the changes that survived were not applied after the lifts were dropped")
	}
	var lost bool
	for _, p := range liveLinesAll(t, r) {
		lost = lost || p.Why == record.GapLiveBlockLost
	}
	if !lost {
		t.Fatal("no live-block-lost line")
	}
}

// liveLinesAll drains r's queue for every gap line, decoded, in order.
func liveLinesAll(t *testing.T, r *runner) []record.GapPayload {
	t.Helper()
	r.queue.Close()
	var got []record.GapPayload
	for ev := range r.queue.C() {
		var p record.GapPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		got = append(got, p)
	}
	return got
}

// TestLiftReplayAfterRemoval: a lift copied from an overlay that was removed, with its serial and MAC, never reaches
// the fence a second time; it gets one live-lift-refused {mac}. A new lift in the new file, at a serial the old one
// used, does reach it, and the new file's blocks get their lines.
func TestLiftReplayAfterRemoval(t *testing.T) {
	r := pauseRunner(t)
	f := &fakeFence{}
	b := &liveBlocks{fence: f}
	ctx := context.Background()
	path := filepath.Join(r.dir, liveblock.FileName)
	r.pollLiveBlocks(ctx, b)
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, err := o.Lift(liveblock.KindRead, "/srv/exports", "uid:1 pid:2 cli", time.Now(), time.Time{}, make([]byte, 32))
		return err
	})
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r.pollLiveBlocks(ctx, b)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	r.pollLiveBlocks(ctx, b)
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	r.pollLiveBlocks(ctx, b)
	if f.lifted || len(f.got) != 1 {
		t.Fatalf("the replayed lift reached the fence: handed %+v, lifted %v", f.got, f.lifted)
	}
	if _, ok := b.Load().MatchPath("/srv/exports/q3.csv", liveblock.AccessRead); !ok {
		t.Fatal("a replayed lift loosened the set")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	r.pollLiveBlocks(ctx, b)
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		if _, err := o.Lift(liveblock.KindRead, "/srv/exports", "uid:1 pid:3 cli", time.Now(), time.Time{}, make([]byte, 32)); err != nil {
			return err
		}
		_, _, err := o.Add(liveblock.KindExec, "/usr/bin/psql", "uid:1 pid:3 cli", time.Now())
		return err
	})
	r.pollLiveBlocks(ctx, b)
	if !f.lifted || len(f.got) != 2 || f.got[1].Serial != 1 {
		t.Fatalf("a new lift at a reused serial did not reach the fence: %+v", f.got)
	}
	var refused, added int
	for _, p := range liveLinesAll(t, r) {
		switch {
		case p.Why == record.GapLiveLiftRefused && p.LiveBlock.Refused == record.LiveRefusedMAC && p.LiveBlock.Serial == 1:
			refused++
		case p.Why == record.GapLiveBlockAdded && p.LiveBlock.Serial == 2:
			added++
		}
	}
	if refused != 1 || added != 1 {
		t.Fatalf("%d live-lift-refused {mac} and %d add lines, want 1 and 1", refused, added)
	}
}

// TestOverlayReplacedBetweenPolls: an overlay removed and written again between two polls, with a lower serial or a
// different change at the serial last read, is a new file: the fence drops every lift (fail closed), a run that had
// blocks gets live-block-unreadable, and the new file's changes get their lines.
func TestOverlayReplacedBetweenPolls(t *testing.T) {
	for _, n := range []int{1, 2} { // the new file's changes: fewer than the old serial, and as many
		r := pauseRunner(t)
		f := &fakeFence{}
		b := &liveBlocks{fence: f}
		ctx := context.Background()
		updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
			if _, _, err := o.Add(liveblock.KindExec, "/usr/bin/psql", "uid:1 pid:2 cli", time.Now()); err != nil {
				return err
			}
			_, err := o.Lift(liveblock.KindRead, "/srv/exports", "uid:1 pid:2 cli", time.Now(), time.Time{}, make([]byte, 32))
			return err
		})
		r.pollLiveBlocks(ctx, b)
		if !f.lifted {
			t.Fatal("the lift did not reach the fence")
		}
		if err := os.Remove(filepath.Join(r.dir, liveblock.FileName)); err != nil {
			t.Fatal(err)
		}
		updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
			for i := range n {
				if _, _, err := o.Add(liveblock.KindNet, "h"+string(rune('a'+i))+".example:443", "uid:1 pid:4 cli", time.Now()); err != nil {
					return err
				}
			}
			return nil
		})
		r.pollLiveBlocks(ctx, b)
		if f.lifted || f.unreadable != 1 {
			t.Fatalf("n=%d: a replaced overlay kept the lift (unreadable calls %d)", n, f.unreadable)
		}
		var unreadable, added int
		for _, p := range liveLinesAll(t, r) {
			switch p.Why {
			case record.GapLiveBlockUnreadable:
				unreadable++
			case record.GapLiveBlockAdded:
				added++
			}
		}
		if unreadable != 1 || added != 1+n {
			t.Fatalf("n=%d: %d unreadable and %d add lines, want 1 and %d", n, unreadable, added, 1+n)
		}
	}
}

// TestWriterPinHoldsABlockThroughAWallStep: the launcher holds a block by the pin its writer kept with the limit (ADR
// 0125 decision 4, amendment 2026-11-18), so a wall clock stepped forward before the launcher first reads the block
// does not end it: it refuses until BOOTTIME reaches the pin, and writes its expiry line then. Pinning at first sight,
// after the step, put the pin in the past and ended the block at once.
func TestWriterPinHoldsABlockThroughAWallStep(t *testing.T) {
	r := pauseRunner(t)
	b := &liveBlocks{}
	ctx := context.Background()
	at := time.Now()
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, _, err := o.AddUntil(liveblock.KindPath, "/srv/x", "uid:1 pid:2 cli", at, at.Add(2*time.Hour))
		return err
	})
	o, err := liveblock.Read(r.dir, string(r.id))
	if err != nil || len(o.Blocks) != 1 {
		t.Fatalf("overlay %+v, %v", o, err)
	}
	e := o.Blocks[0]
	if e.Boot == "" {
		t.Log("this machine names no boot, so the writer kept no pin: there is none to hold the block by")
		return
	}
	// First sight: the wall clock is 25 h past the limit, BOOTTIME an hour short of the writer's pin.
	now := liveblock.Clock{Wall: e.Until.Add(25 * time.Hour), Boot: e.UntilBoot - time.Hour, BootID: e.Boot}
	old := liveNow
	liveNow = func() liveblock.Clock { return now }
	t.Cleanup(func() { liveNow = old })
	r.pollLiveBlocks(ctx, b)
	if !b.Load().HasPath() {
		t.Fatal("a forward wall step ended a block before its BOOTTIME pin: the launcher compiled it out")
	}
	// A write at that reading keeps the entry, and the launcher goes on holding it.
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, _, err := o.Add(liveblock.KindExec, "/bin/ls", "uid:1 pid:3 cli", time.Now())
		return err
	})
	r.pollLiveBlocks(ctx, b)
	if !b.Load().HasPath() {
		t.Fatal("the block left the launcher's Set after a write")
	}
	now.Boot = e.UntilBoot // BOOTTIME reaches the pin
	r.pollLiveBlocks(ctx, b)
	if b.Load().HasPath() {
		t.Fatal("the block outlived both clocks")
	}
	var whys []string
	for _, p := range liveLines(t, r) {
		whys = append(whys, p.Why)
	}
	if want := []string{record.GapLiveBlockAdded, record.GapLiveBlockAdded, record.GapLiveBlockExpired}; !slices.Equal(whys, want) {
		t.Fatalf("lines %q, want %q", whys, want)
	}
}

// TestPinAndDoneMapsStayBoundedOverALongRun: a 24/7 run whose live blocks carry a time limit each makes a new
// limit (so a new pin and a new expiry mark) every time one is placed and ends. The launcher keeps a pin and a mark only
// while a block of the overlay it last read carries that limit, so over a long run the two maps hold what the overlay
// holds, not one key per limit ever seen; and each limit's end is still recorded exactly once, so no mark was dropped
// early (a mark dropped while its ended block is still in the file would write its expiry line again).
func TestPinAndDoneMapsStayBoundedOverALongRun(t *testing.T) {
	const limits = 1500
	ctx := context.Background()
	r := pauseRunner(t)
	r.queue = NewQueue(limits * 4)
	b := &liveBlocks{}
	at := time.Now().UTC().Round(time.Millisecond).Add(-3 * time.Hour)
	real := liveblock.ReadClock()
	now := liveblock.Clock{Wall: at, Boot: real.Boot, BootID: real.BootID}
	old := liveNow
	liveNow = func() liveblock.Clock { return now }
	t.Cleanup(func() { liveNow = old })
	step := func(d time.Duration) { now.Wall, now.Boot = now.Wall.Add(d), now.Boot+d }

	peakPins, peakDone := 0, 0
	for i := range limits {
		end := now.Wall.Add(3 * time.Second)
		updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
			o.Serial++
			o.Blocks = []liveblock.Entry{{Kind: liveblock.KindExec, Value: "/bin/ls", By: "uid:1 pid:2 cli", At: now.Wall, Until: end}}
			o.Changes = []liveblock.Change{{Serial: o.Serial, Op: liveblock.OpAdd, Kind: liveblock.KindExec, Value: "/bin/ls",
				By: "uid:1 pid:2 cli", At: now.Wall, Until: end}}
			return nil
		})
		r.pollLiveBlocks(ctx, b)
		step(4 * time.Second) // the limit ends
		r.pollLiveBlocks(ctx, b)
		r.pollLiveBlocks(ctx, b) // an ended block still in the file: its end is not recorded again
		peakPins, peakDone = max(peakPins, len(b.pins)), max(peakDone, len(b.done))
		if i == limits-1 {
			break
		}
	}
	if peakPins > 2 || peakDone > 2 {
		t.Errorf("over %d limits the launcher held up to %d pins and %d expiry marks; want what the overlay holds (one)", limits, peakPins, peakDone)
	}
	// The overlay is removed: nothing it held is kept.
	if err := os.Remove(filepath.Join(r.dir, liveblock.FileName)); err != nil {
		t.Fatal(err)
	}
	r.pollLiveBlocks(ctx, b)
	if len(b.pins) != 0 || len(b.done) != 0 {
		t.Errorf("after the overlay was removed: %d pins, %d marks, want none", len(b.pins), len(b.done))
	}
	expired := 0
	for _, p := range liveLinesAll(t, r) {
		if p.Why == record.GapLiveBlockExpired {
			expired++
		}
	}
	if expired != limits {
		t.Errorf("%d expiry lines for %d limits: each end is recorded exactly once", expired, limits)
	}
}

// TestAnEndedBlockStillListedKeepsItsPinAndMarkWhenTheOverlayChanges: a block whose limit has ended stays in the file a day.
// While it is listed, another change to the overlay (a second block) is read and pruned against: the ended block's pin
// and its expiry mark must survive, or its end would be written again and its pin derived anew.
func TestAnEndedBlockStillListedKeepsItsPinAndMarkWhenTheOverlayChanges(t *testing.T) {
	ctx := context.Background()
	r := pauseRunner(t)
	b := &liveBlocks{}
	at := time.Now().UTC().Round(time.Millisecond).Add(-time.Hour)
	end := at.Add(3 * time.Second)
	real := liveblock.ReadClock()
	now := liveblock.Clock{Wall: at, Boot: real.Boot, BootID: real.BootID}
	old := liveNow
	liveNow = func() liveblock.Clock { return now }
	t.Cleanup(func() { liveNow = old })
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		o.Serial = 1
		o.Blocks = []liveblock.Entry{{Kind: liveblock.KindExec, Value: "/bin/ls", By: "uid:1 pid:2 cli", At: at, Until: end}}
		o.Changes = []liveblock.Change{{Serial: 1, Op: liveblock.OpAdd, Kind: liveblock.KindExec, Value: "/bin/ls", By: "uid:1 pid:2 cli", At: at, Until: end}}
		return nil
	})
	r.pollLiveBlocks(ctx, b)
	now.Wall, now.Boot = now.Wall.Add(4*time.Second), now.Boot+4*time.Second // the limit ends
	r.pollLiveBlocks(ctx, b)
	key := liveblock.DeadlineKey("exec:/bin/ls", end)
	if _, ok := b.pins[key]; !ok || !b.done[key] {
		t.Fatalf("before the overlay changes: pin held %v, mark %v", ok, b.done[key])
	}
	pin := b.pins[key]
	// The overlay changes while the ended block is still listed.
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		o.Serial = 2
		o.Blocks = append(o.Blocks, liveblock.Entry{Kind: liveblock.KindExec, Value: "/bin/cat", By: "uid:1 pid:2 cli", At: now.Wall})
		o.Changes = append(o.Changes, liveblock.Change{Serial: 2, Op: liveblock.OpAdd, Kind: liveblock.KindExec, Value: "/bin/cat", By: "uid:1 pid:2 cli", At: now.Wall})
		return nil
	})
	now.Wall, now.Boot = now.Wall.Add(time.Second), now.Boot+time.Second // the wall clock moves on
	r.pollLiveBlocks(ctx, b)
	r.pollLiveBlocks(ctx, b)
	if p, ok := b.pins[key]; !ok || p != pin || !b.done[key] {
		t.Errorf("after it: pin %v (held %v, was %v), mark %v; the ended block is still listed and keeps both", p, ok, pin, b.done[key])
	}
	expired := 0
	for _, p := range liveLinesAll(t, r) {
		if p.Why == record.GapLiveBlockExpired {
			expired++
		}
	}
	if expired != 1 {
		t.Errorf("%d expiry lines for one limit, want 1", expired)
	}
}
