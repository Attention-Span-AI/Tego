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
