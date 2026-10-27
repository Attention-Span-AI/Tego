// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// generateLiveControl writes spec/record/v1/fixtures/live-control.jsonl through the real Writer: a run at
// record_minor 24 (MinorLiveControl) under record: full whose contract reads and writes its project. A person blocks
// the reads of .env live from the dashboard (a gap live-block-added line of kind read) and the next read of it is
// refused under live.block[read:/home/u/proj/.env] with its refused mirror; a write block of src/ added from the CLI
// refuses the next write open there, while a read of a file in src/ is still allowed under the contract's own entry.
// Then the person pauses the run from the dashboard and resumes it (run-paused, run-resumed), and a pause from the CLI
// the launcher could not apply (pause-failed: the run kept running) is followed by its resume (run-resumed: the run
// was not frozen). Its run_start carries launcher_uid, fs_reads and reads_notified, as every run_start at
// MinorRunIdentity, MinorHeldReads and MinorReasonReads or later does.
func generateLiveControl(t *testing.T, dir string, anchor ChainAnchor) {
	t.Helper()
	clk := newStepClock(fixedStart, 952_345_000_000, time.Millisecond)
	w, err := Open(dir, testRef, WithClock(clk), WithAnchor(anchor))
	if err != nil {
		t.Fatal(err)
	}
	w.pid, w.tid = 48211, 48211
	f := &fixtureRun{t: t, w: w, clk: clk, step: 1}
	start := startPayload()
	start.Command = []string{"codex", "--no-daemon"}
	start.RecordMinor = record.MinorLiveControl
	launcher := uint32(1000)
	start.LauncherUID = &launcher
	start.FSReads = &record.FSReads{Reads: record.FSReadsDirect, Why: record.FSReadsWhyNoneNested}
	start.ReadsNotified = &record.ReadsNotified{Notified: true, Why: record.ReadsNotifiedWhyFull}
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	at := func(serial uint64) time.Time {
		return fixedStart.Add(2*time.Second + time.Duration(serial)*time.Second).UTC()
	}
	gap := func(why string, p record.GapPayload) {
		p.What, p.Why = record.GapEnforce, why
		f.emit(time.Millisecond, f.plain(record.KindGap, record.SourceSupervisor, 48211, 48211, p))
	}
	block := func(kind, value, by string, serial uint64) {
		gap(record.GapLiveBlockAdded, record.GapPayload{LiveBlock: &record.LiveBlockChange{Op: record.LiveOpAdd, Kind: kind,
			Value: value, Rule: record.LiveRule(kind, value), By: by, Serial: serial, At: at(serial)}})
	}
	control := func(why, op, by string, serial uint64) {
		gap(why, record.GapPayload{LiveControl: &record.LiveControlChange{Op: op, By: by, Serial: serial, At: at(serial)}})
	}
	refuse := func(rule string, reason record.Reason, p record.FSPayload) {
		f.emit(time.Millisecond, f.action(record.KindFS, record.SourceSeccomp, fxTID, rule, record.VerdictRefused, reason,
			record.Unattributed(), p))
		m := f.plain(record.KindRefused, record.SourceSeccomp, fxPID, fxTID, record.RefusedPayload{Op: p.Op, Target: p.Path,
			Reason: reason, Rule: rule})
		m.Rule, m.Reason = rule, reason
		f.emit(0, m)
	}
	dashboard, cli := "uid:1000 pid:51234 dashboard", "uid:1000 pid:51302 cli"
	const env, src = "/home/u/proj/.env", "/home/u/proj/src/"
	block(record.LiveKindRead, env, dashboard, 1)
	refuse(record.LiveRule(record.LiveKindRead, env), record.ReasonReadDenied, record.FSPayload{Op: record.FSOpen, Path: env,
		Flags: 0x80000})
	block(record.LiveKindWrite, src, cli, 2)
	refuse(record.LiveRule(record.LiveKindWrite, src), record.ReasonWriteOutsideContract, record.FSPayload{Op: record.FSOpen,
		Path: src + "main.py", Flags: 0x241})
	f.emit(time.Millisecond, f.action(record.KindFS, record.SourceSeccomp, fxTID, "fs.read[./]", record.VerdictAllow, "",
		record.Unattributed(), record.FSPayload{Op: record.FSOpen, Path: src + "main.py", Flags: 0x80000}))
	control(record.GapRunPaused, record.LiveOpPause, dashboard, 3)
	control(record.GapRunResumed, record.LiveOpResume, dashboard, 4)
	control(record.GapPauseFailed, record.LiveOpPause, cli, 5)
	control(record.GapRunResumed, record.LiveOpResume, cli, 6)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit, ExitCode: 0,
		Supervisor: record.Supervisor{Notifications: 3}}); err != nil {
		t.Fatal(err)
	}
}

// TestLiveControlFixtureFrozen regenerates live-control.jsonl and compares it byte for byte with the committed file;
// -update rewrites it, as TestFixturesFrozen does for the others. The Writer encodes every line at the run's revision
// (MarshalLineAt), so the fixture also shows the live changes' lines pass ValidateAt at 24.
func TestLiveControlFixtureFrozen(t *testing.T) {
	root := t.TempDir()
	generateLiveControl(t, filepath.Join(root, testRef.ID), &memAnchor{})
	got := readFile(t, filepath.Join(root, testRef.ID, EventsFile))
	path := filepath.Join(fixturesDir, "live-control.jsonl")
	if *updateFixtures {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("live-control.jsonl: %v (run with -update to generate)", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("live-control.jsonl differs from the generator output; run go test ./internal/ledger -run TestLiveControlFixtureFrozen -update")
	}
}

// TestWriterKeepsALongLiveBlockLine: a block whose value is near liveblock's 4096-byte bound makes a live_block past
// BlobThreshold, which the R10 stage moves to live_block_blob; the line is still written, as before revision 24's
// checks, rather than refused for a live_block it no longer holds.
func TestWriterKeepsALongLiveBlockLine(t *testing.T) {
	dir := filepath.Join(t.TempDir(), testRef.ID)
	w, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	start := startPayload()
	start.RecordMinor = record.MinorLiveControl
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	value := "/home/u/" + strings.Repeat("d/", 2040)
	for _, p := range []record.GapPayload{
		{What: record.GapEnforce, Why: record.GapLiveBlockAdded, LiveBlock: &record.LiveBlockChange{Op: record.LiveOpAdd,
			Kind: record.LiveKindWrite, Value: value, Rule: record.LiveRule(record.LiveKindWrite, value), By: "uid:1000 pid:2 cli",
			Serial: 1, At: fixedStart.UTC()}},
		{What: record.GapEnforce, Why: record.GapRunPaused, LiveControl: &record.LiveControlChange{Op: record.LiveOpPause,
			By: "uid:1000 pid:2 " + strings.Repeat("x", BlobThreshold), Serial: 2, At: fixedStart.UTC()}},
	} {
		ev := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor}
		if err := ev.SetPayload(p); err != nil {
			t.Fatal(err)
		}
		if err := w.SplitBlobsStage(w.Append)(ev); err != nil {
			t.Fatalf("%s: %v", p.Why, err)
		}
		if !bytes.Contains(ev.Payload, []byte(`_blob"`)) {
			t.Fatalf("%s: the payload was not split: %.200s", p.Why, ev.Payload)
		}
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
}

// TestWriterRefusesLiveControlBelowItsRevision: a ledger at MinorReasonReads (23) cannot hold a pause line or a read
// block, so a launcher of this build that stamped an older revision would lose the line rather than write one an
// older reader misreads; the run's record goes on.
func TestWriterRefusesLiveControlBelowItsRevision(t *testing.T) {
	dir := filepath.Join(t.TempDir(), testRef.ID)
	w, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	start := startPayload()
	start.RecordMinor = record.MinorReasonReads
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	at := fixedStart.UTC()
	for _, p := range []record.GapPayload{
		{What: record.GapEnforce, Why: record.GapRunPaused, LiveControl: &record.LiveControlChange{Op: record.LiveOpPause,
			By: "uid:1000 pid:2 cli", Serial: 1, At: at}},
		{What: record.GapEnforce, Why: record.GapLiveBlockAdded, LiveBlock: &record.LiveBlockChange{Op: record.LiveOpAdd,
			Kind: record.LiveKindRead, Value: "/x", Rule: record.LiveRule(record.LiveKindRead, "/x"), By: "uid:1000 pid:2 cli",
			Serial: 1, At: at}},
	} {
		ev := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor}
		if err := ev.SetPayload(p); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(ev); record.FieldCode(err) != "below-minor" {
			t.Errorf("%s at 23: Append = %v, want [below-minor]", p.Why, err)
		}
	}
	ev := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor}
	if err := ev.SetPayload(record.GapPayload{What: record.GapEnforce, Why: record.GapLiveBlockUnreadable}); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(ev); err != nil {
		t.Fatalf("a gap line after the refused ones: %v", err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
}
