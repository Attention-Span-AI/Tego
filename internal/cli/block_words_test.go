// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestBlockCommandWords (ADR 0171): `tego block <run> exec "git push"` places a block on a command's words on a run
// whose launcher made the words mark, and refuses a run without it in words ([launcher-too-old], nothing written), never
// placing the whole program's block instead; --list shows it, another spelling of the command removes it, and the line a
// script reads first keeps its form.
func TestBlockCommandWords(t *testing.T) {
	dir, id, _ := liveRun(t)
	code, out, errs := run(t, "block", id, "exec", "git push")
	if code != identity.ExitFinding || out != "" || !strings.Contains(errs, "[launcher-too-old]") ||
		!strings.Contains(errs, "does not say it reads a block on a command's words") || !strings.Contains(errs, id) {
		t.Fatalf("a run with no words mark: exit %d stdout %q stderr %q, want 1 and [launcher-too-old]", code, out, errs)
	}
	if _, err := os.Lstat(filepath.Join(dir, liveblock.FileName)); !os.IsNotExist(err) {
		t.Fatalf("an overlay was written for a run that reads no commands (the whole-program block, or a version 6 file): %v", err)
	}
	if err := liveblock.MarkWords(dir); err != nil {
		t.Fatal(err)
	}
	code, out, errs = run(t, "block", id, "exec", " git   push ")
	if code != identity.ExitOK || errs != "" || !strings.HasPrefix(out, id+": blocked live.block[exec:git push]\n") ||
		!strings.Contains(out, "matched as an exec.deny entry of that text would be") || !strings.Contains(out, "best effort") {
		t.Fatalf("block: exit %d stdout %q stderr %q", code, out, errs)
	}
	o, err := liveblock.Read(dir, id)
	if err != nil || o.V != liveblock.VersionWords || len(o.Blocks) != 1 || o.Blocks[0].Value != "git push" || !o.Blocks[0].IsWords() {
		t.Fatalf("overlay %+v, %v: want one command block at version %d", o, err, liveblock.VersionWords)
	}
	if code, out, _ := run(t, "block", id, "exec", "git push"); code != identity.ExitOK || !strings.Contains(out, "already blocked") {
		t.Errorf("a second block: exit %d stdout %q", code, out)
	}
	// The program itself is another block: the command's words are no program.
	if code, _, _ := run(t, "block", id, "exec", "git"); code != identity.ExitOK {
		t.Fatalf("block git: exit %d", code)
	}
	if code, out, errs := run(t, "block", "--list", id); code != identity.ExitOK || errs != "" || !strings.Contains(out, "exec  git push") ||
		!strings.Contains(out, "2 live block(s)") {
		t.Errorf("list: exit %d stdout %q stderr %q", code, out, errs)
	}
	for _, bad := range []string{"/usr/bin/git push", "git push && ls", "git commit -m 'x"} {
		code, out, errs := run(t, "block", id, "exec", bad)
		if bad == "/usr/bin/git push" { // an absolute value with a space is a program path, as it always was
			if code != identity.ExitOK {
				t.Errorf("%q: exit %d stdout %q stderr %q, want a program block", bad, code, out, errs)
			}
			continue
		}
		if code != identity.ExitUsage || out != "" || errs == "" {
			t.Errorf("%q: exit %d stdout %q stderr %q, want a usage error", bad, code, out, errs)
		}
	}
	if code, out, _ := run(t, "unblock", id, "exec", "git  push"); code != identity.ExitOK || !strings.Contains(out, "block removed live.block[exec:git push]") {
		t.Errorf("unblock by another spelling: exit %d stdout %q", code, out)
	}
	o, err = liveblock.Read(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range o.Blocks {
		if e.IsWords() {
			t.Errorf("the command block is still held: %+v", e)
		}
	}
}
