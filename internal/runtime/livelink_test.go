// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
)

// TestLauncherReadsALinkBlock: the launcher makes the run directory's link mark, so the dashboard's "Also apply now"
// places a block that matches by link on its run, and it reads the version 5 overlay holding one: the block refuses
// what the contract grants under the entry at its value (the supervisor's grant, stood in for here by one that
// grants ls under ls's entry only), and leaves another hard link of the same file (sleep beside ls, as a multi-call
// program's applets are) to the contract. The launcher resolves the value's identity, for a contract with no entry
// there.
func TestLauncherReadsALinkBlock(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ls, sleep := filepath.Join(dir, "ls"), filepath.Join(dir, "sleep")
	if err := os.WriteFile(ls, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // an executable fixture
		t.Fatal(err)
	}
	if err := os.Link(ls, sleep); err != nil {
		t.Skipf("hard link: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Stat(ls, &st); err != nil {
		t.Fatal(err)
	}
	id := liveblock.FileID{Dev: st.Dev, Ino: st.Ino}

	r := pauseRunner(t)
	if liveblock.TakesLink(r.dir) {
		t.Fatal("a run directory has the mark before its launcher made it")
	}
	r.markLinkReader()
	if !liveblock.TakesLink(r.dir) {
		t.Fatal("the launcher made no link mark")
	}
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, _, err := o.AddLink(liveblock.KindExec, ls, "uid:1 pid:3 dashboard", time.Now())
		return err
	})
	b := &liveBlocks{}
	r.pollLiveBlocks(context.Background(), b)
	if b.last == nil || b.last.V != liveblock.VersionLink {
		t.Fatalf("overlay read %+v: want the version %d file read", b.last, liveblock.VersionLink)
	}
	// grantOf is the contract exec.allow [ls, sleep] on an exec of the file reached at at: ls's entry grants it there.
	grantOf := func(at string) liveblock.Grant {
		return func(v string) (bool, bool) { return v == ls || v == sleep, v == at }
	}
	if e, ok := b.Load().MatchExec([]string{ls}, id, true, grantOf(ls)); !ok || e.Rule() != "live.block[exec:"+ls+"]" {
		t.Fatalf("ls: %+v %v, want refused under its block", e, ok)
	}
	if _, ok := b.Load().MatchExec([]string{sleep}, id, true, grantOf(sleep)); ok {
		t.Fatal("sleep, another name of the same file, was refused by a block placed from a rules change")
	}
	if _, ok := b.Load().MatchExec([]string{sleep}, id, true, nil); !ok {
		t.Fatal("with no entry at the value the block must refuse the whole file, by the identity the launcher resolved")
	}

	// A person's block by the same path widens it to the whole file: sleep is refused too.
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, _, err := o.Add(liveblock.KindExec, ls, "uid:1 pid:4 cli", time.Now())
		return err
	})
	r.pollLiveBlocks(context.Background(), b)
	if _, ok := b.Load().MatchExec([]string{sleep}, id, true, grantOf(sleep)); !ok {
		t.Fatal("a person's block on ls must refuse every name of its file")
	}
}
