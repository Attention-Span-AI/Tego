// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestLiftNoteIsSignedAndShown: tego lift --note signs the note inside the lift's MAC, shows it before it asks and after
// the launcher's line answers, and writes it only to a run whose launcher made the mark that it reads one.
func TestLiftNoteIsSignedAndShown(t *testing.T) {
	noTerminal(t, false, "")
	dir, id := adjustableRun(t)
	if err := liveblock.MarkNote(dir); err != nil {
		t.Fatal(err)
	}
	const note = "ticket 4411: nightly export <b>&amp;</b>"
	liftWait = 3 * time.Second
	go func() {
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if o, err := liveblock.Read(dir, id); err == nil && o.Serial > 0 {
				appendFenceLineNote(t, dir, id, 2, record.GapLiveRuleLifted, record.LiveOpLift, "read", "/srv/billing", o.Serial, "", note)
				return
			}
		}
	}()
	code, out, errs := run(t, "lift", id, "read", "/srv/billing", "--note", "  "+note+"  ", "--yes")
	if code != identity.ExitOK || strings.Count(out, "Note for the record: "+note+"\n") != 1 || !strings.Contains(out, id+": lifted live.fence[read:/srv/billing]") ||
		!strings.Contains(out, "\nNote: "+note+"\n") {
		t.Fatalf("lift --note: exit %d stdout %q stderr %q", code, out, errs)
	}
	o := mustRead(t, dir, id)
	c := o.Changes[len(o.Changes)-1]
	key, err := liveblock.ReadKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Note != note || !liveblock.LiftMACOK(key, id, c) {
		t.Fatalf("overlay change %+v: want the trimmed note, MAC'ed with it", c)
	}
	c.Note = "ticket 9999"
	if liveblock.LiftMACOK(key, id, c) {
		t.Fatal("a changed note still checks")
	}
}

// TestLiftNoteRefusals: a note is refused in words, and nothing is asked, when it is not printable text or too long
// (usage, exit 2), and when the run's launcher does not say it reads one (exit 1, [launcher-too-old]); a lift with no
// note is not refused for the missing mark, and the missing mark never makes the lift go on without the note.
func TestLiftNoteRefusals(t *testing.T) {
	noTerminal(t, false, "")
	dir, id := adjustableRun(t)
	overlay := filepath.Join(dir, liveblock.FileName)
	for name, note := range map[string]string{"a line break": "one\ntwo", "an escape byte": "\x1b[2J", "an override": "a\u202eb",
		"too long": strings.Repeat("n", liveblock.MaxNote+1), "a tab": "a\tb"} {
		code, out, errs := run(t, "lift", id, "read", "/srv/billing", "--note", note, "--yes")
		if code != identity.ExitUsage || out != "" || !strings.Contains(errs, "--note") || !strings.Contains(errs, "[usage]") {
			t.Errorf("%s: exit %d stdout %q stderr %q", name, code, out, errs)
		}
	}
	code, out, errs := run(t, "lift", id, "read", "/srv/billing", "--note", "ticket 4411", "--yes")
	if code != identity.ExitFinding || !strings.Contains(errs, "[launcher-too-old]") || !strings.Contains(errs, id) ||
		!strings.Contains(errs, "without a note") || strings.Contains(out, "asked") {
		t.Errorf("no mark: exit %d stdout %q stderr %q", code, out, errs)
	}
	if _, err := os.Stat(overlay); !os.IsNotExist(err) {
		t.Errorf("an overlay was written for a refused note: %v", err)
	}
	if code, out, errs := run(t, "lift", id, "read", "/srv/billing", "--yes"); code != identity.ExitOK || !strings.Contains(out, "lift asked") || strings.Contains(out, "Note") {
		t.Errorf("a lift with no note on an unmarked run: exit %d stdout %q stderr %q", code, out, errs)
	}
	if c := mustRead(t, dir, id).Changes; len(c) != 1 || c[0].Note != "" {
		t.Errorf("changes %+v: want the one lift, with no note", c)
	}
}

// TestLiftNoteOnTheLaunchersLine: the note shown after the answer is the launcher's line's, bounded and escaped as the
// dashboard's fence row shows it (record.LiveNoteShown); a line that lost the note is said, and the lift still stands.
func TestLiftNoteOnTheLaunchersLine(t *testing.T) {
	noTerminal(t, false, "")
	dir, id := adjustableRun(t)
	if err := liveblock.MarkNote(dir); err != nil {
		t.Fatal(err)
	}
	liftWait = 3 * time.Second
	answer := func(note string) {
		go func() {
			for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				if o, err := liveblock.Read(dir, id); err == nil && o.Serial > 0 {
					appendFenceLineNote(t, dir, id, int(o.Serial)+1, record.GapLiveRuleLifted, record.LiveOpLift, "read", "/srv/billing", o.Serial, "", note)
					return
				}
			}
		}()
	}
	// A tampered line (a writer other than Tego): the escape byte is written escaped, not as a byte.
	hostile := "ok\x1b[2J\u202eevil"
	answer(hostile)
	code, out, errs := run(t, "lift", id, "read", "/srv/billing", "--note", "ticket 4411", "--yes")
	want := record.LiveNoteShown(hostile)
	if code != identity.ExitOK || !strings.Contains(out, "\nNote: "+want+"\n") || strings.ContainsAny(out, "\x1b\u202e") || !strings.Contains(errs, "does not carry the note") {
		t.Fatalf("a hostile note on the line: exit %d stdout %q stderr %q", code, out, errs)
	}
}
