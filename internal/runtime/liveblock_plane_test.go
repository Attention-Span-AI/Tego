// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
)

// fakeBlockWriter is a plane slot's live-block rows as planeBlocks writes them: every call in order, the rows held, and
// a fill that fails a row whose descriptor names fail.
type fakeBlockWriter struct {
	calls  []string
	states []bpf.PlaneBlockState
	rows   map[blockKey]enforce.PlaneBlockFill
	// full makes every write fill fail with ErrPlaneBlockFull; stateErr every SetState.
	full     bool
	stateErr error
	// onFill runs once, at the first Fill that writes rows, before it takes them: a move or a creation racing the fill.
	onFill func()
}

func (f *fakeBlockWriter) SetState(st bpf.PlaneBlockState) error {
	if f.stateErr != nil {
		return f.stateErr
	}
	f.calls = append(f.calls, "state")
	f.states = append(f.states, st)
	return nil
}

func (f *fakeBlockWriter) Fill(rows []enforce.PlaneBlockFill) ([]enforce.PlaneBlockResult, error) {
	if f.rows == nil {
		f.rows = map[blockKey]enforce.PlaneBlockFill{}
	}
	out := make([]enforce.PlaneBlockResult, len(rows))
	if f.onFill != nil && len(rows) > 0 && !rows[0].Delete {
		hook := f.onFill
		f.onFill = nil
		hook()
	}
	for i, r := range rows {
		var st unix.Stat_t
		if err := r.FD.Fstat(&st); err != nil {
			out[i].Err = err // a descriptor closed before its fill
			continue
		}
		if st.Ino != r.Ino {
			out[i].Err = errors.New("descriptor names another inode")
			continue
		}
		k := blockKey{name: r.Name, dev: uint64(st.Dev), ino: st.Ino, nameKey: r.NameKey} //nolint:unconvert // Dev's type differs by platform
		switch {
		case r.Delete:
			f.calls = append(f.calls, "delete")
			delete(f.rows, k)
		case f.full:
			f.calls = append(f.calls, "full")
			out[i].Err = enforce.ErrPlaneBlockFull
		default:
			f.calls = append(f.calls, "put")
			f.rows[k] = r
		}
	}
	return out, nil
}

func statKey(t *testing.T, p string) blockKey {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		t.Fatal(err)
	}
	return blockKey{dev: uint64(st.Dev), ino: st.Ino} //nolint:unconvert // Dev's type differs by platform
}

func nameKey(t *testing.T, dir, name string) blockKey {
	t.Helper()
	k := statKey(t, dir)
	nk, ok := bpf.PlaneBlockNameKey(name)
	if !ok {
		t.Fatal("no name key")
	}
	return blockKey{name: true, dev: k.dev, ino: k.ino, nameKey: nk}
}

// TestPlaneBlocksKeyWhatThePathNames is the rows a write block, a read block on a missing name and a block through a
// link ask the plane for (ADR 0124, amendment 2026-11-21): the object the path leads to as the target (SELF|BENEATH,
// the block's id in its class and as its guard), every directory and link on the way as a guard (its own move refused),
// the missing name as a name row in the directory it would be made in; and the state written on before any row goes in.
// Removing the blocks deletes every row and only then writes the state off.
func TestPlaneBlocksKeyWhatThePathNames(t *testing.T) {
	root := t.TempDir()
	blk := filepath.Join(root, "proj", "blk")
	if err := os.MkdirAll(filepath.Join(blk, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "proj"), filepath.Join(root, "via")); err != nil {
		t.Fatal(err)
	}
	w := &fakeBlockWriter{}
	rules := &liveRules{}
	p := newPlaneBlocks(w, rules, nil, true, nil)
	now := liveblock.Clock{Wall: time.Now(), Boot: time.Hour}
	entries := []liveblock.Entry{
		{Kind: liveblock.KindWrite, Value: blk},
		{Kind: liveblock.KindRead, Value: filepath.Join(root, "proj", "absent.txt")},
		{Kind: liveblock.KindPath, Value: filepath.Join(root, "via", "blk", "sub")},
		{Kind: liveblock.KindExec, Value: "/bin/true"},       // not a file block
		{Kind: liveblock.KindRead, Value: root, Fence: true}, // the contract's, already in the plane's rows
	}
	p.sync(entries, nil, nil, nil, now)
	if len(w.calls) == 0 || w.calls[0] != "state" || w.states[0].On == 0 || w.states[0].Names == 0 {
		t.Fatalf("calls %v, states %+v: the state must say on (and names) before the first row", w.calls, w.states)
	}
	idW, idR, idP := p.ids[entries[0].Key()], p.ids[entries[1].Key()], p.ids[entries[2].Key()]
	if idW == 0 || idR == 0 || idP == 0 || len(p.ids) != 3 {
		t.Fatalf("ids %v: one per file block, none for the exec block or the fence entry", p.ids)
	}
	for id, e := range map[uint16]liveblock.Entry{idW: entries[0], idR: entries[1], idP: entries[2]} {
		if r, ok := rules.rule(id); !ok || r != e.Rule() {
			t.Errorf("id %d names %q, want %q", id, r, e.Rule())
		}
	}
	rows := w.rows
	tgt := rows[statKey(t, blk)]
	if tgt.Write != idW || tgt.Guard != idW || tgt.Flags&(bpf.PlaneBlockSelf|bpf.PlaneBlockBeneath) != bpf.PlaneBlockSelf|bpf.PlaneBlockBeneath || tgt.Read != 0 {
		t.Errorf("the write block's target row %+v, want write and guard %d, SELF|BENEATH", tgt, idW)
	}
	sub := rows[statKey(t, filepath.Join(blk, "sub"))]
	if sub.Read != idP || sub.Write != idP || sub.Flags&bpf.PlaneBlockSelf == 0 {
		t.Errorf("the path block's target row (through the link) %+v, want read and write %d", sub, idP)
	}
	link := rows[statKey(t, filepath.Join(root, "via"))]
	if link.Guard != idP || link.Read != 0 || link.Write != 0 || link.Flags != 0 {
		t.Errorf("the link the path block runs through is %+v, want a guard of %d", link, idP)
	}
	proj := rows[statKey(t, filepath.Join(root, "proj"))]
	if proj.Guard == 0 || proj.Read != 0 || proj.Write != 0 || proj.Flags != 0 {
		t.Errorf("the folder above the blocks is %+v, want a guard only", proj)
	}
	for _, d := range []string{root, filepath.Dir(root)} {
		if _, ok := rows[statKey(t, d)]; !ok {
			t.Errorf("%s, above the blocks, is no guard", d)
		}
	}
	if _, ok := rows[statKey(t, "/")]; ok {
		t.Error("the root is keyed: it can be neither moved nor removed")
	}
	name := rows[nameKey(t, filepath.Join(root, "proj"), "absent.txt")]
	if name.Read != idR || !name.Name {
		t.Errorf("the missing name's row %+v, want a name row with read %d", name, idR)
	}
	// Synced again with nothing changed, nothing is written.
	calls := len(w.calls)
	p.sync(entries, nil, nil, nil, now)
	if len(w.calls) != calls {
		t.Errorf("an unchanged sync wrote %v", w.calls[calls:])
	}
	// The name now exists: the next sync keys the file, and the name row stays with the block (a block keeps what it
	// keyed until it is removed), so the file cannot be removed and made again unkeyed.
	if err := os.WriteFile(filepath.Join(root, "proj", "absent.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	p.sync(entries, nil, nil, nil, now)
	if f, ok := w.rows[statKey(t, filepath.Join(root, "proj", "absent.txt"))]; !ok || f.Read != idR {
		t.Errorf("the name that came to exist is not keyed by its object: %+v", f)
	}
	if _, ok := w.rows[nameKey(t, filepath.Join(root, "proj"), "absent.txt")]; !ok {
		t.Error("the name row went once the file existed")
	}
	// Every block removed: every row deleted, then the state off.
	calls = len(w.calls)
	p.sync(entries[3:], nil, nil, nil, now)
	if len(w.rows) != 0 {
		t.Errorf("%d rows left after every block was removed", len(w.rows))
	}
	tail := w.calls[calls:]
	if len(tail) == 0 || tail[len(tail)-1] != "state" || slices.Index(tail, "state") != len(tail)-1 {
		t.Errorf("removal calls %v: every delete first, the state last", tail)
	}
	if st := w.states[len(w.states)-1]; st.On != 0 || st.Names != 0 {
		t.Errorf("the state after the last block went is %+v, want off", st)
	}
	if len(p.applied) != 0 {
		t.Errorf("%d descriptors still held", len(p.applied))
	}
}

// TestPlaneBlocksOverflowRefusesTheClassWhole: a row the slot's map has no room for is refused whole by its class
// (overflow, named by the block), set before the run is told the block is in force; a block's path the walk cannot
// resolve (a loop of links) overflows too. A state that cannot be written ends the run.
func TestPlaneBlocksOverflowRefusesTheClassWhole(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := &fakeBlockWriter{full: true}
	p := newPlaneBlocks(w, &liveRules{}, nil, true, nil)
	now := liveblock.Clock{Wall: time.Now(), Boot: time.Hour}
	e := liveblock.Entry{Kind: liveblock.KindWrite, Value: filepath.Join(root, "d")}
	p.sync([]liveblock.Entry{e}, nil, nil, nil, now)
	st := w.states[len(w.states)-1]
	if st.Over&bpf.PlaneBlockWrite == 0 || st.OverWrite != p.ids[e.Key()] || st.Over&bpf.PlaneBlockRead != 0 {
		t.Errorf("state %+v after every row failed, want the write class in overflow named by the block", st)
	}
	// A loop of links: the walk gives up, and the block's classes overflow.
	if err := os.Symlink("loop2", filepath.Join(root, "loop1")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("loop1", filepath.Join(root, "loop2")); err != nil {
		t.Fatal(err)
	}
	w2 := &fakeBlockWriter{}
	p2 := newPlaneBlocks(w2, &liveRules{}, nil, true, nil)
	loop := liveblock.Entry{Kind: liveblock.KindRead, Value: filepath.Join(root, "loop1", "x")}
	p2.sync([]liveblock.Entry{loop}, nil, nil, nil, now)
	if st := w2.states[0]; st.Over&bpf.PlaneBlockRead == 0 || st.OverRead != p2.ids[loop.Key()] {
		t.Errorf("state %+v for a path that loops, want the read class in overflow", st)
	}
	var ended error
	w3 := &fakeBlockWriter{stateErr: errors.New("map write failed")}
	p3 := newPlaneBlocks(w3, &liveRules{}, nil, true, func(err error) { ended = err })
	p3.sync([]liveblock.Entry{e}, nil, nil, nil, now)
	if ended == nil || w3.rows != nil {
		t.Errorf("a state that cannot be written: ended %v, rows %v; want the run ended and no row written", ended, w3.rows)
	}
}

// TestPlaneBlocksDormantBlockWaitsForItsPin: a dormant block (an unblock for a while, ADR 0125 decision 4) keys its rows
// with its from's CLOCK_BOOTTIME pin, so the kernel refuses again at that instant; once begun, or where the launcher's
// boot clock is not the kernel's, its rows refuse now.
func TestPlaneBlocksDormantBlockWaitsForItsPin(t *testing.T) {
	root := t.TempDir()
	now := liveblock.Clock{Wall: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC), Boot: time.Hour}
	from := now.Wall.Add(10 * time.Minute)
	e := liveblock.Entry{Kind: liveblock.KindWrite, Value: root, From: from}
	pins := map[string]time.Duration{liveblock.DeadlineKey(e.Key(), from): now.Boot + 10*time.Minute}
	for _, tc := range []struct {
		name   string
		bootOK bool
		now    liveblock.Clock
		want   uint64
	}{
		{"dormant", true, now, uint64(now.Boot + 10*time.Minute)},
		{"begun", true, liveblock.Clock{Wall: from.Add(time.Second), Boot: now.Boot + 11*time.Minute}, 0},
		{"another boot clock", false, now, 0},
	} {
		w := &fakeBlockWriter{}
		p := newPlaneBlocks(w, &liveRules{}, nil, tc.bootOK, nil)
		p.sync([]liveblock.Entry{e}, nil, nil, pins, tc.now)
		if r := w.rows[statKey(t, root)]; r.From != tc.want || r.Write == 0 {
			t.Errorf("%s: the target row %+v, want from %d", tc.name, r, tc.want)
		}
	}
}

// TestPlaneBlocksUnblockForAWhileLoosensKeyedRows: the unblock for a while is always of a block already in force, whose
// rows the kernel holds with from 0. The sync that sees its from must rewrite those rows with the pin (the block's held
// objects take the block's instant, never the stale in-force one), and the sync after the instant puts them in force
// again. A second block in force on the same object keeps that object refused: the earlier instant of two blocks wins.
func TestPlaneBlocksUnblockForAWhileLoosensKeyedRows(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "f.txt")
	if err := os.WriteFile(f, []byte("f"), 0o644); err != nil {
		t.Fatal(err)
	}
	now := liveblock.Clock{Wall: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC), Boot: time.Hour}
	from := now.Wall.Add(10 * time.Minute)
	pin := now.Boot + 10*time.Minute
	inForce := liveblock.Entry{Kind: liveblock.KindWrite, Value: f}
	dormant := inForce
	dormant.From = from
	pins := map[string]time.Duration{liveblock.DeadlineKey(dormant.Key(), from): pin}
	w := &fakeBlockWriter{}
	p := newPlaneBlocks(w, &liveRules{}, nil, true, nil)
	p.sync([]liveblock.Entry{inForce}, nil, nil, nil, now)
	if r := w.rows[statKey(t, f)]; r.From != 0 || r.Write == 0 {
		t.Fatalf("the block in force: target row %+v, want a write id and from 0", r)
	}
	p.sync([]liveblock.Entry{dormant}, nil, nil, pins, now)
	for k, r := range w.rows {
		if r.From != uint64(pin) {
			t.Errorf("after the unblock for a while the row %+v holds from %d, want the pin %d", k, r.From, uint64(pin))
		}
	}
	begun := liveblock.Clock{Wall: from.Add(time.Second), Boot: pin + time.Second}
	p.sync([]liveblock.Entry{dormant}, nil, nil, pins, begun)
	for k, r := range w.rows {
		if r.From != 0 {
			t.Errorf("after the instant the row %+v holds from %d, want 0 (in force)", k, r.From)
		}
	}
	// Another block in force on the same file: the file's row stays in force while the first is dormant.
	other := liveblock.Entry{Kind: liveblock.KindRead, Value: f}
	w2 := &fakeBlockWriter{}
	p2 := newPlaneBlocks(w2, &liveRules{}, nil, true, nil)
	p2.sync([]liveblock.Entry{inForce, other}, nil, nil, nil, now)
	p2.sync([]liveblock.Entry{dormant, other}, nil, nil, pins, now)
	if r := w2.rows[statKey(t, f)]; r.From != 0 {
		t.Errorf("a file another block holds in force: target row %+v, want from 0", r)
	}
}

// TestPlaneBlocksRunOutOfIDsRefuseTheClassWhole: a run gives each block an id once (bpf.PlaneBlockIDMax of them, 14 bits
// of a rule index), and the block that finds none left cannot be named in a row, so its classes are refused whole,
// named by the last id, while every block that has an id stays keyed. The blocks it displaced keep their rows and the
// class is released once the block is removed.
func TestPlaneBlocksRunOutOfIDsRefuseTheClassWhole(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"a", "b", "c"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	now := liveblock.Clock{Wall: time.Now(), Boot: time.Hour}
	w := &fakeBlockWriter{}
	rules := &liveRules{}
	p := newPlaneBlocks(w, rules, nil, true, nil)
	p.next = bpf.PlaneBlockIDMax - 2 // two ids left
	a := liveblock.Entry{Kind: liveblock.KindWrite, Value: filepath.Join(root, "a")}
	b := liveblock.Entry{Kind: liveblock.KindRead, Value: filepath.Join(root, "b")}
	c := liveblock.Entry{Kind: liveblock.KindWrite, Value: filepath.Join(root, "c")}
	p.sync([]liveblock.Entry{a, b}, nil, nil, nil, now)
	if st := w.states[len(w.states)-1]; st.Over != 0 || st.OverRead != 0 || st.OverWrite != 0 {
		t.Fatalf("state %+v with an id for each block, want no overflow", st)
	}
	if ida, idb := p.ids[a.Key()], p.ids[b.Key()]; ida != bpf.PlaneBlockIDMax-1 || idb != bpf.PlaneBlockIDMax {
		t.Fatalf("ids %d and %d, want the last two (%d, %d)", ida, idb, bpf.PlaneBlockIDMax-1, bpf.PlaneBlockIDMax)
	}
	p.sync([]liveblock.Entry{a, b, c}, nil, nil, nil, now)
	st := w.states[len(w.states)-1]
	if st.Over != bpf.PlaneBlockWrite || st.OverWrite != bpf.PlaneBlockIDMax || st.OverRead != 0 {
		t.Errorf("state %+v with no id left for a write block, want the write class in overflow named by %d", st, bpf.PlaneBlockIDMax)
	}
	if _, ok := p.ids[c.Key()]; ok {
		t.Errorf("the block that found no id was given one: %v", p.ids)
	}
	if _, ok := rules.rule(0); ok {
		t.Error("a rule is named for id 0")
	}
	for _, e := range []liveblock.Entry{a, b} {
		if _, ok := w.rows[statKey(t, e.Value)]; !ok {
			t.Errorf("the block %s that has an id lost its row when another found none", e.Value)
		}
	}
	// Known limit, stated: the overflow is named by the last id, which is also the last block's own, so a refusal
	// naming it may be that block's or the overflow's; the rule the recorder gives it is that block's.
	if r, ok := rules.rule(bpf.PlaneBlockIDMax); !ok || r != b.Rule() {
		t.Errorf("rule of id %d is %q, want the last block's %q", bpf.PlaneBlockIDMax, r, b.Rule())
	}
	// The block removed, the class is no longer refused whole.
	p.sync([]liveblock.Entry{a, b}, nil, nil, nil, now)
	if st := w.states[len(w.states)-1]; st.Over != 0 || st.OverWrite != 0 {
		t.Errorf("state %+v after the block that found no id was removed, want no overflow", st)
	}
}

// liftFixture is a folder, a file in it, a clock and the pins of an unblock for a while at two instants.
type liftFixture struct {
	root, f string
	now     liveblock.Clock
}

func newLiftFixture(t *testing.T) liftFixture {
	t.Helper()
	root := t.TempDir()
	f := filepath.Join(root, "f.txt")
	if err := os.WriteFile(f, []byte("f"), 0o644); err != nil {
		t.Fatal(err)
	}
	return liftFixture{root: root, f: f, now: liveblock.Clock{Wall: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC), Boot: time.Hour}}
}

// lift is e lifted for d from the fixture's now, and the pin map that gives its instant.
func (x liftFixture) lift(e liveblock.Entry, d time.Duration) (liveblock.Entry, map[string]time.Duration, uint64) {
	e.From = x.now.Wall.Add(d)
	pin := x.now.Boot + d
	return e, map[string]time.Duration{liveblock.DeadlineKey(e.Key(), e.From): pin}, uint64(pin)
}

// TestPlaneBlocksLiftOneOfTwoBlocksOnAKey: a block lifted for a while never loosens a row another block in force also
// needs. A folder block in force over a file block lifted for a while: the folder's row and every guard row keep from 0,
// and only the row that belongs to the lifted block alone takes the pin.
func TestPlaneBlocksLiftOneOfTwoBlocksOnAKey(t *testing.T) {
	x := newLiftFixture(t)
	folder := liveblock.Entry{Kind: liveblock.KindWrite, Value: x.root}
	file := liveblock.Entry{Kind: liveblock.KindWrite, Value: x.f}
	lifted, pins, pin := x.lift(file, 10*time.Minute)
	for _, order := range []string{"folder first", "file first"} {
		w := &fakeBlockWriter{}
		p := newPlaneBlocks(w, &liveRules{}, nil, true, nil)
		inForce := []liveblock.Entry{folder, file}
		during := []liveblock.Entry{folder, lifted}
		if order == "file first" {
			inForce = []liveblock.Entry{file, folder}
			during = []liveblock.Entry{lifted, folder}
		}
		p.sync(inForce, nil, nil, nil, x.now)
		p.sync(during, nil, nil, pins, x.now)
		fk, dk := statKey(t, x.f), statKey(t, x.root)
		if len(w.rows) < 3 {
			t.Fatalf("%s: %d rows, want the file, the folder and the guards above it", order, len(w.rows))
		}
		for k, r := range w.rows {
			want := uint64(0)
			if k == fk {
				want = pin
			}
			if r.From != want {
				t.Errorf("%s: row %+v (folder %v, file %v) holds from %d, want %d", order, k, k == dk, k == fk, r.From, want)
			}
		}
		if r := w.rows[fk]; r.Write != p.ids[file.Key()] || r.Write == 0 {
			t.Errorf("%s: the lifted file's row %+v, want the file block's write id", order, r)
		}
		if r := w.rows[dk]; r.Write != p.ids[folder.Key()] || r.Write == 0 {
			t.Errorf("%s: the folder's row %+v, want the folder block's write id and from 0", order, r)
		}
	}
}

// TestPlaneBlocksLiftedWriteBesideReadInForce: a read block in force and a write block lifted for a while on one file
// share the file's row, which keeps from 0 and carries the read id. Known limit, stated: the row has one from for read,
// write and guard together and merge keeps the write id the lifted block gave, so the kernel keeps refusing writes
// there during the window; it never refuses less than the block in force asks.
func TestPlaneBlocksLiftedWriteBesideReadInForce(t *testing.T) {
	x := newLiftFixture(t)
	read := liveblock.Entry{Kind: liveblock.KindRead, Value: x.f}
	write := liveblock.Entry{Kind: liveblock.KindWrite, Value: x.f}
	lifted, pins, _ := x.lift(write, 10*time.Minute)
	w := &fakeBlockWriter{}
	p := newPlaneBlocks(w, &liveRules{}, nil, true, nil)
	p.sync([]liveblock.Entry{read, write}, nil, nil, nil, x.now)
	p.sync([]liveblock.Entry{read, lifted}, nil, nil, pins, x.now)
	r := w.rows[statKey(t, x.f)]
	if r.From != 0 {
		t.Errorf("the shared row %+v holds from %d, want 0", r, r.From)
	}
	if r.Read == 0 || r.Read != p.ids[read.Key()] {
		t.Errorf("the shared row %+v, want the read block's id %d", r, p.ids[read.Key()])
	}
	if r.Write != p.ids[write.Key()] || r.Write == 0 {
		t.Errorf("the shared row %+v, want the lifted write block's id %d too (writes stay refused in the window)", r, p.ids[write.Key()])
	}
}

// TestPlaneBlocksLiftedThenBlockedAgainBeforeTheWindowEnds: a block lifted for a while and put back in force before the
// instant reads from 0 at the next sync, and stays so after the instant.
func TestPlaneBlocksLiftedThenBlockedAgainBeforeTheWindowEnds(t *testing.T) {
	x := newLiftFixture(t)
	file := liveblock.Entry{Kind: liveblock.KindWrite, Value: x.f}
	lifted, pins, pin := x.lift(file, 10*time.Minute)
	w := &fakeBlockWriter{}
	p := newPlaneBlocks(w, &liveRules{}, nil, true, nil)
	p.sync([]liveblock.Entry{file}, nil, nil, nil, x.now)
	p.sync([]liveblock.Entry{lifted}, nil, nil, pins, x.now)
	if r := w.rows[statKey(t, x.f)]; r.From != pin {
		t.Fatalf("lifted: the file's row %+v, want from %d", r, pin)
	}
	soon := liveblock.Clock{Wall: x.now.Wall.Add(time.Minute), Boot: x.now.Boot + time.Minute}
	p.sync([]liveblock.Entry{file}, nil, nil, nil, soon)
	for k, r := range w.rows {
		if r.From != 0 {
			t.Errorf("blocked again: the row %+v holds from %d, want 0", k, r.From)
		}
	}
	after := liveblock.Clock{Wall: lifted.From.Add(time.Second), Boot: time.Duration(pin) + time.Second}
	p.sync([]liveblock.Entry{file}, nil, nil, nil, after)
	for k, r := range w.rows {
		if r.From != 0 {
			t.Errorf("after the old instant: the row %+v holds from %d, want 0", k, r.From)
		}
	}
}

// TestPlaneBlocksLiftedTwiceTakesTheLatestInstant: lifting a block a second time, for a longer or a shorter while, gives
// the rows the new instant at the next sync (a block's own rows follow its current from, not the earlier of the two).
// Pinned so that a change of that rule is noticed.
func TestPlaneBlocksLiftedTwiceTakesTheLatestInstant(t *testing.T) {
	x := newLiftFixture(t)
	file := liveblock.Entry{Kind: liveblock.KindWrite, Value: x.f}
	for _, tc := range []struct {
		name          string
		first, second time.Duration
	}{
		{"later then earlier", 20 * time.Minute, 5 * time.Minute},
		{"earlier then later", 5 * time.Minute, 20 * time.Minute},
	} {
		w := &fakeBlockWriter{}
		p := newPlaneBlocks(w, &liveRules{}, nil, true, nil)
		p.sync([]liveblock.Entry{file}, nil, nil, nil, x.now)
		e1, pins1, pin1 := x.lift(file, tc.first)
		p.sync([]liveblock.Entry{e1}, nil, nil, pins1, x.now)
		if r := w.rows[statKey(t, x.f)]; r.From != pin1 {
			t.Errorf("%s: after the first lift the row %+v holds from %d, want %d", tc.name, r, r.From, pin1)
		}
		e2, pins2, pin2 := x.lift(file, tc.second)
		p.sync([]liveblock.Entry{e2}, nil, nil, pins2, x.now)
		for k, r := range w.rows {
			if r.From != pin2 {
				t.Errorf("%s: after the second lift the row %+v holds from %d, want %d", tc.name, k, r.From, pin2)
			}
		}
	}
}

// TestPlaneBlocksMovedObjectOfABlockInForceStaysRefused: a block in force keeps the object it keyed wherever it has
// moved; another block lifted for a while on that object's new name must not loosen the row.
func TestPlaneBlocksMovedObjectOfABlockInForceStaysRefused(t *testing.T) {
	for _, order := range []string{"moved name's block first", "block in force first"} {
		x := newLiftFixture(t)
		g := filepath.Join(x.root, "g.txt")
		named := liveblock.Entry{Kind: liveblock.KindWrite, Value: x.f}
		other := liveblock.Entry{Kind: liveblock.KindWrite, Value: g}
		lifted, pins, _ := x.lift(other, 10*time.Minute)
		w := &fakeBlockWriter{}
		p := newPlaneBlocks(w, &liveRules{}, nil, true, nil)
		p.sync([]liveblock.Entry{named}, nil, nil, nil, x.now)
		ino := statKey(t, x.f)
		if err := os.Rename(x.f, g); err != nil {
			t.Fatal(err)
		}
		inForce := []liveblock.Entry{named, other}
		during := []liveblock.Entry{named, lifted}
		if order == "moved name's block first" {
			inForce = []liveblock.Entry{other, named}
			during = []liveblock.Entry{lifted, named}
		}
		p.sync(inForce, nil, nil, nil, x.now)
		p.sync(during, nil, nil, pins, x.now)
		if statKey(t, g) != ino {
			t.Fatalf("%s: the moved file is not the keyed inode", order)
		}
		r := w.rows[ino]
		if r.From != 0 || r.Write == 0 {
			t.Errorf("%s: the moved object's row %+v, want from 0 and a write id", order, r)
		}
	}
}
