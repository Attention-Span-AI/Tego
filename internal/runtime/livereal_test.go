// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestLauncherReadsARealPath: the launcher makes the run directory's real-path mark, so writers
// store a block's real path for its run, and it reads a version 4 overlay holding one and refuses beneath both
// spellings under the value's rule.
func TestLauncherReadsARealPath(t *testing.T) {
	r := pauseRunner(t)
	if liveblock.TakesReal(r.dir) {
		t.Fatal("a run directory has the mark before its launcher made it")
	}
	r.markRealReader()
	if !liveblock.TakesReal(r.dir) {
		t.Fatal("the launcher made no real-path mark")
	}
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		if _, _, err := o.Add(liveblock.KindPath, "/home/u/link/secret", "uid:1 pid:3 cli", time.Now()); err != nil {
			return err
		}
		o.SetReal(liveblock.KindPath, "/home/u/link/secret", "/data/secret")
		return nil
	})
	b := &liveBlocks{}
	r.pollLiveBlocks(context.Background(), b)
	if b.last == nil || b.last.V != liveblock.VersionReal {
		t.Fatalf("overlay read %+v: want the version %d file read", b.last, liveblock.VersionReal)
	}
	for _, p := range []string{"/home/u/link/secret/k", "/data/secret/k"} {
		e, ok := b.Load().MatchPath(p, liveblock.AccessRead)
		if !ok || e.Rule() != "live.block[path:/home/u/link/secret]" {
			t.Fatalf("MatchPath(%q) = %+v %v, want refused under the value's rule", p, e, ok)
		}
	}
}

// TestLauncherBlocksEveryOtherName (ADR 0011, amended 2026-11-19, round 5; review F7): when the launcher first sees a
// path, read or write block it asks the mount table for the file's other names (liveOtherNames, agent.OtherNames:
// compile's computation) and the set refuses the file under each, under the value's rule; it asks once per value, and
// a later poll reuses what it learnt.
func TestLauncherBlocksEveryOtherName(t *testing.T) {
	asked := map[string]int{}
	prev := liveOtherNames
	liveOtherNames = func(p string) ([]string, string) {
		asked[p]++
		if p == "/home/u/notes" {
			return []string{"/mnt/wslg/distro/home/u/notes"}, ""
		}
		return nil, ""
	}
	t.Cleanup(func() { liveOtherNames = prev })
	r := pauseRunner(t)
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, _, err := o.Add(liveblock.KindRead, "/home/u/notes", "uid:1 pid:3 cli", time.Now())
		return err
	})
	b := &liveBlocks{}
	r.pollLiveBlocks(context.Background(), b)
	for _, p := range []string{"/home/u/notes/a", "/mnt/wslg/distro/home/u/notes/a"} {
		e, ok := b.Load().MatchPath(p, liveblock.AccessRead)
		if !ok || e.Rule() != "live.block[read:/home/u/notes]" {
			t.Fatalf("MatchPath(%q) = %+v %v, want refused under the value's rule", p, e, ok)
		}
	}
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, _, err := o.Add(liveblock.KindWrite, "/srv/other", "uid:1 pid:3 cli", time.Now())
		return err
	})
	r.pollLiveBlocks(context.Background(), b)
	if asked["/home/u/notes"] != 1 {
		t.Errorf("the mount table was asked %d times for one block's value; want once", asked["/home/u/notes"])
	}
	if _, ok := b.Load().MatchPath("/mnt/wslg/distro/home/u/notes/a", liveblock.AccessRead); !ok {
		t.Error("a later poll dropped the other name a block took when it was added")
	}
}

// TestLiveBlockSaysWhenItsNamesAreShort (round 6, review G3): a path, read or write block whose file's other names the
// mount table could not all list still refuses every name it did list, and says so on a gap line
// (live-block-partial: the value and the reason), once per block, again after a remove and a new add; a block whose list
// was whole has none, and neither has a block of another kind.
func TestLiveBlockSaysWhenItsNamesAreShort(t *testing.T) {
	prev := liveOtherNames
	liveOtherNames = func(p string) ([]string, string) {
		switch p {
		case "/home/u/notes":
			return []string{"/mnt/wslg/distro/home/u/notes"}, `mount "/srv/x" has an unlinked directory root`
		case "/home/u/whole":
			return []string{"/mnt/wslg/distro/home/u/whole"}, ""
		}
		return nil, ""
	}
	t.Cleanup(func() { liveOtherNames = prev })
	r := pauseRunner(t)
	b := &liveBlocks{}
	ctx := context.Background()
	add := func(kind liveblock.Kind, v string) {
		updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
			_, _, err := o.Add(kind, v, "uid:1 pid:3 cli", time.Now())
			return err
		})
		r.pollLiveBlocks(ctx, b)
	}
	add(liveblock.KindRead, "/home/u/notes")
	add(liveblock.KindWrite, "/home/u/whole")
	add(liveblock.KindExec, "/usr/bin/curl")
	add(liveblock.KindWrite, "/srv/other")
	// Still refuses every name that was listed.
	if e, ok := b.Load().MatchPath("/mnt/wslg/distro/home/u/notes/a", liveblock.AccessRead); !ok || e.Rule() != "live.block[read:/home/u/notes]" {
		t.Fatalf("the listed other name is not refused: %+v %v", e, ok)
	}
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, _, err := o.Remove(liveblock.KindRead, "/home/u/notes", "uid:1 pid:3 cli", time.Now())
		return err
	})
	r.pollLiveBlocks(ctx, b)
	add(liveblock.KindRead, "/home/u/notes")
	var partial []string
	for _, p := range liveLinesAll(t, r) {
		if p.Why == record.GapLiveBlockPartial {
			if p.What != record.GapEnforce {
				t.Errorf("partial line what = %q", p.What)
			}
			partial = append(partial, p.Binary)
		}
	}
	want := `/home/u/notes: the mount table could not list every name of this file: mount "/srv/x" has an unlinked directory root`
	if len(partial) != 2 || partial[0] != want || partial[1] != want {
		t.Errorf("partial lines = %q, want the one text twice (once per add of the block, none for the whole list or other kinds)", partial)
	}
}
