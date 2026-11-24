// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// liftReadNote is liftRead with a note, signed inside the MAC.
func liftReadNote(t *testing.T, r *runner, key []byte, by, note string, at, until time.Time) {
	t.Helper()
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, err := o.LiftNote(liveblock.KindRead, fenceRead, by, note, at, until, key)
		return err
	})
}

// TestFenceLiftNoteIsOnItsLine: a lift's note is written on the live-rule-lifted line, and only there; the line is a
// line of record revision 41 (spec/record/v1/fixtures/live/valid/live-rule-lifted-note.json is its twin). A lift with no note writes the line it always did, with no note key. A lift of the entry
// again with another note writes another line though nothing it allows changes, so no note is dropped; the same note
// again writes none. A note edited in the file after the lift was signed is a refused lift (mac), and no note is written.
func TestFenceLiftNoteIsOnItsLine(t *testing.T) {
	r := fenceRunner(t)
	ctx := context.Background()
	b, err := r.startLiveBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f := b.fence.(*liveFence)
	at := time.Now().UTC().Round(time.Millisecond)
	liftReadNote(t, r, f.key, "uid:1000 pid:7 cli", "ticket 4411: nightly export", at, time.Time{})
	r.pollLiveBlocks(ctx, b)
	liftReadNote(t, r, f.key, "uid:1000 pid:7 cli", "ticket 4411: nightly export", at.Add(time.Second), time.Time{}) // same again
	r.pollLiveBlocks(ctx, b)
	liftReadNote(t, r, f.key, "uid:1000 pid:8 dashboard", "moved to ticket 4500", at.Add(2*time.Second), time.Time{})
	r.pollLiveBlocks(ctx, b)
	// A note changed in the file after the signature: refused, and its text is nowhere on a line.
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		c, err := o.LiftNote(liveblock.KindNet, fenceNet, "uid:1 pid:2 cli", "signed words", at.Add(3*time.Second), time.Time{}, f.key)
		o.Changes[len(o.Changes)-1].Note = "forged words"
		_ = c
		return err
	})
	r.pollLiveBlocks(ctx, b)
	lines := liveLines(t, r)
	if len(lines) != 3 {
		t.Fatalf("lines %+v, want two live-rule-lifted and one live-lift-refused", lines)
	}
	if lines[0].Why != record.GapLiveRuleLifted || lines[0].LiveBlock.Note != "ticket 4411: nightly export" {
		t.Fatalf("first line %+v", lines[0].LiveBlock)
	}
	if lines[1].Why != record.GapLiveRuleLifted || lines[1].LiveBlock.Note != "moved to ticket 4500" || lines[1].LiveBlock.Serial != 3 {
		t.Fatalf("second line %+v: the same note again writes none, another note writes one", lines[1].LiveBlock)
	}
	if lines[2].Why != record.GapLiveLiftRefused || lines[2].LiveBlock.Refused != record.LiveRefusedMAC || lines[2].LiveBlock.Note != "" {
		t.Fatalf("forged note: %+v", lines[2])
	}
}

// TestFenceLiftNoteLinesGolden: a lift with no note writes the line the base build wrote, byte for byte, and one with a
// note adds only the note key (testdata/livefence_lift_lines_golden.jsonl).
func TestFenceLiftNoteLinesGolden(t *testing.T) {
	r := fenceRunner(t)
	ctx := context.Background()
	b, err := r.startLiveBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f := b.fence.(*liveFence)
	at := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	liftRead(t, r, f.key, "uid:1000 pid:7 cli", at, time.Time{})
	r.pollLiveBlocks(ctx, b)
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, err := o.LiftNote(liveblock.KindNet, fenceNet, "uid:1000 pid:8 dashboard", "ticket 4411", at.Add(time.Second), time.Time{}, f.key)
		return err
	})
	r.pollLiveBlocks(ctx, b)
	got := gapPayloads(t, r)
	if bytes.Count(got, []byte(`"note"`)) != 1 {
		t.Fatalf("lines\n%s\nwant the note key on exactly the second", got)
	}
	golden := filepath.Join("testdata", "livefence_lift_lines_golden.jsonl")
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
		t.Fatalf("lift lines\n%s\nwant\n%s", got, want)
	}
}

// TestLauncherMarksNoteReader: the launcher's mark that it reads a lift's note is made with the poll, as the other marks
// are, and not before.
func TestLauncherMarksNoteReader(t *testing.T) {
	r := pauseRunner(t)
	if liveblock.TakesNote(r.dir) {
		t.Fatal("the run directory has the note mark before its launcher made it")
	}
	r.markNoteReader()
	if !liveblock.TakesNote(r.dir) {
		t.Fatal("the launcher made no note mark")
	}
}

// TestNoteRuleIsOneInBothCopies: pkg/spec/record's reader and internal/liveblock's writer, which cannot import each
// other, say yes and no to the same texts.
func TestNoteRuleIsOneInBothCopies(t *testing.T) {
	texts := []string{"", "a", strings.Repeat("a", record.MaxLiveNote), strings.Repeat("a", record.MaxLiveNote+1),
		strings.Repeat("\u00e9", 100), strings.Repeat("\u00e9", 101), "a\nb", "a\tb", "a\rb", "a\x00b", "a\x1bb", "\x7f", "a\u0085b",
		"a\xffb", "a\u00a0b", "a b", " ", "a\u200bb", "a\u202eb", "a\u2028b", "a\u2029b", "a\ufeffb", "\U000e0041", "\u65e5\u672c", "\U0001f600",
		"a\u0301", "\ue000", "\ufffd"}
	if record.MaxLiveNote != liveblock.MaxNote {
		t.Fatalf("the bounds differ: record %d, liveblock %d", record.MaxLiveNote, liveblock.MaxNote)
	}
	for _, s := range texts {
		rec, wr := record.ValidLiveNote(s) == nil, liveblock.ValidNote(s) == nil
		if rec != wr {
			t.Errorf("%q: record says %t, liveblock says %t", s, rec, wr)
		}
	}
}
