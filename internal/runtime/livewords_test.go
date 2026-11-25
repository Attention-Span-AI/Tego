// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"testing"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestLauncherReadsACommandWordBlock: the launcher makes the run directory's words mark (so the writers place a block on
// a command's words on this run, and refuse a run without it), reads the version 6 overlay holding one into the Set the
// supervisor decides on (a command is no program block: MatchExec never names it), and writes the gap lines of its add
// and its removal, which the record accepts at the current revision with the words as the value and the rule
// live.block[exec:<words>].
func TestLauncherReadsACommandWordBlock(t *testing.T) {
	r := pauseRunner(t)
	if liveblock.TakesWords(r.dir) {
		t.Fatal("a run directory has the mark before its launcher made it")
	}
	r.markWordsReader()
	if !liveblock.TakesWords(r.dir) || liveblock.TakesLink(r.dir) {
		t.Fatal("the launcher made no words mark, or made another")
	}
	b := &liveBlocks{}
	changeBlock(t, r, true, liveblock.KindExec, "git  push")
	r.pollLiveBlocks(context.Background(), b)
	if b.last == nil || b.last.V != liveblock.VersionWords {
		t.Fatalf("overlay read %+v: want the version %d file read", b.last, liveblock.VersionWords)
	}
	s := b.Load()
	if !s.HasWords() || s.HasExec() {
		t.Fatalf("Set: HasWords %v HasExec %v", s.HasWords(), s.HasExec())
	}
	if e, ok := s.WordOn("exec:git push"); !ok || e.Value != "git push" {
		t.Fatalf("WordOn = %+v, %v", e, ok)
	}
	if _, ok := s.MatchExec([]string{"git", "git push"}, liveblock.FileID{}, false, nil); ok {
		t.Fatal("a command block refused an exec as a program")
	}
	changeBlock(t, r, false, liveblock.KindExec, "git push")
	r.pollLiveBlocks(context.Background(), b)
	if b.Load().HasWords() {
		t.Fatal("the Set still holds the command after its removal")
	}
	lines := blockGapLines(t, r)
	if len(lines) != 2 || lines[0].Why != record.GapLiveBlockAdded || lines[1].Why != record.GapLiveBlockRemoved {
		t.Fatalf("lines %+v: want an add and a remove", lines)
	}
	for _, l := range lines {
		c := l.LiveBlock
		if c.Kind != "exec" || c.Value != "git push" || c.Rule != "live.block[exec:git push]" || c.Serial == 0 {
			t.Errorf("line %+v", c)
		}
	}
}
