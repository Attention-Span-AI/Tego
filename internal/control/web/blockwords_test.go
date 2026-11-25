// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/url"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/liveblock"
)

// TestBlockNowTakesACommandsWords (ADR 0171): Block now with an exec value that has words places a block on that command
// on a run whose launcher made the words mark, says it as it says a program, and is refused in the launcher's words
// (nothing written, never the whole program's block) on a run without it; Remove takes it away by another spelling.
func TestBlockNowTakesACommandsWords(t *testing.T) {
	s, c, dir := liveFenceServer(t)
	post1 := func(path, value string) string {
		return follow(t, s, c, post(s, "/runs/"+adjRun+"/"+path, url.Values{"csrf": {s.csrf}, "kind": {"exec"}, "value": {value}}, own, "", c))
	}
	b := post1("block", "git push")
	mustContain(t, "a run with no words mark", b, "Not done:", "does not say it reads a block on a command")
	if ch := overlayChanges(t, dir); len(ch) != 0 {
		t.Fatalf("an overlay change was written for a run that reads no commands: %+v", ch)
	}
	if err := liveblock.MarkWords(dir); err != nil {
		t.Fatal(err)
	}
	b = post1("block", "git  push")
	mustContain(t, "a run with the mark", b, "Blocked git push on run", "It is refused from the next try on.")
	o, err := liveblock.Read(dir, adjRun)
	if err != nil || o.V != liveblock.VersionWords || len(o.Blocks) != 1 || o.Blocks[0].Value != "git push" || !o.Blocks[0].IsWords() {
		t.Fatalf("overlay %+v, %v: want one command block at version %d", o, err, liveblock.VersionWords)
	}
	if b := post1("block", "git push"); !strings.Contains(b, "was already blocked") {
		t.Errorf("a second block: %s", b)
	}
	if b := post1("block", "git push && ls"); !strings.Contains(b, "Not done:") {
		t.Errorf("a value that is no command: %s", b)
	}
	b = post1("unblock", "git   push")
	mustContain(t, "remove", b, "Removed the block on git push")
	if o, err := liveblock.Read(dir, adjRun); err != nil || len(o.Blocks) != 0 {
		t.Fatalf("overlay after remove %+v, %v", o, err)
	}
}
