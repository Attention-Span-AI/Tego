// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/reason"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// refusedLines is the run's refused lines in dir, in ledger order.
func refusedLines(t *testing.T, dir string) []*record.Event {
	t.Helper()
	var out []*record.Event
	for _, e := range readAll(t, dir) {
		if e.Kind == record.KindRefused {
			out = append(out, e)
		}
	}
	return out
}

// checkRecentIsTheLedgers: the file's recent list is the ledger's newest refused lines, oldest first, each with
// that line's seq, ts, pid and payload, and its count is the ledger's.
func checkRecentIsTheLedgers(t *testing.T, f *reason.File, lines []*record.Event) {
	t.Helper()
	if f.Refusals != uint64(len(lines)) {
		t.Fatalf("refusals %d, the ledger has %d refused lines", f.Refusals, len(lines))
	}
	tail := lines[len(lines)-len(f.Recent):]
	for i, e := range f.Recent {
		var p record.RefusedPayload
		if err := tail[i].DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if e.Seq != tail[i].Seq || !e.TS.Equal(tail[i].TS) || e.PID != tail[i].PID || e.Target != p.Target ||
			e.Op != p.Op || e.Reason != tail[i].Reason || e.Rule != tail[i].Rule {
			t.Fatalf("recent[%d] = %+v, the ledger's line %d is %+v %+v", i, e, tail[i].Seq, tail[i], p)
		}
	}
}

// TestReasonFileListsTheNewest32: 100 refusals inside one coalescing window leave a file whose recent list is the
// newest 32 refused lines and whose count is 100, so a reader with no cursor learns that 68 are not listed.
func TestReasonFileListsTheNewest32(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 0)
	for i := range 100 {
		if err := w.Append(refusedEvent(fmt.Sprintf("/t/%d", i))); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(gapEvent("between")); err != nil { // refused lines are not consecutive seqs
			t.Fatal(err)
		}
	}
	f, _ := waitReason(t, dir, func(f *reason.File) bool { return f.Refusals == 100 })
	if len(f.Recent) != reason.RingSize {
		t.Fatalf("%d recent, want %d", len(f.Recent), reason.RingSize)
	}
	if got, notListed := f.Since(0); len(got) != 32 || notListed != 68 {
		t.Errorf("Since(0) = %d entries, %d not listed; want 32, 68", len(got), notListed)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	checkRecentIsTheLedgers(t, f, refusedLines(t, dir))
}

// TestReasonFileOrderUnderConcurrentAppends: refusals appended from several goroutines while a reader polls both
// copies. Every read is a whole v1 file; its seq and count never go back from one read to the next (a newer
// refusal is never followed by an older one); and the last file is the ledger's newest 32 refused lines.
func TestReasonFileOrderUnderConcurrentAppends(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 0)
	mirror := t.TempDir()
	if err := w.MirrorLastRefusal(mirror); err != nil {
		t.Fatal(err)
	}
	const goroutines, each = 4, 400
	done := make(chan struct{})
	var readers sync.WaitGroup
	for _, d := range []string{dir, mirror} {
		readers.Go(func() {
			var seq, count uint64
			for reads := 0; ; reads++ {
				select {
				case <-done:
					t.Logf("%s: %d reads", filepath.Base(d), reads)
					return
				default:
				}
				b, err := os.ReadFile(filepath.Join(d, LastRefusalFile))
				if os.IsNotExist(err) {
					continue
				}
				f, err := reason.Decode(bytes.NewReader(b))
				if err != nil {
					t.Errorf("a read of %s: %v: %s", d, err, b)
					return
				}
				if f.Seq < seq || f.Refusals < count || (f.Seq == seq && f.Refusals != count) {
					t.Errorf("%s went from seq %d (%d refusals) to seq %d (%d refusals)", d, seq, count, f.Seq, f.Refusals)
					return
				}
				seq, count = f.Seq, f.Refusals
			}
		})
	}
	var appenders sync.WaitGroup
	for g := range goroutines {
		appenders.Go(func() {
			for i := range each {
				e := refusedEvent(fmt.Sprintf("/g%d/%d", g, i))
				if i%3 == 0 {
					e = gapEvent("between")
				}
				if err := w.Append(e); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	appenders.Wait()
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	close(done)
	readers.Wait()
	b, err := os.ReadFile(filepath.Join(dir, LastRefusalFile))
	if err != nil {
		t.Fatal(err)
	}
	f, err := reason.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	checkRecentIsTheLedgers(t, f, refusedLines(t, dir))
	if m, _ := os.ReadFile(filepath.Join(mirror, LastRefusalFile)); !bytes.Equal(m, b) {
		t.Errorf("the mirror's last file differs from the run directory's")
	}
}

// TestAppendDoesNoReasonFileIO: post() fills the ring under the refusal lock and touches no file, so Append goes
// on while a write of last-refusal.json holds the file lock (a slow disk, a stalled mirror).
func TestAppendDoesNoReasonFileIO(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 0)
	w.refusal.fileMu.Lock() // as a scheduled write would, for as long as it likes
	appended := make(chan error, 1)
	go func() {
		for i := range 100 {
			if err := w.Append(refusedEvent(fmt.Sprintf("/t/%d", i))); err != nil {
				appended <- err
				return
			}
		}
		appended <- nil
	}()
	select {
	case err := <-appended:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		w.refusal.fileMu.Unlock()
		t.Fatal("Append waited for the reason file's lock")
	}
	if _, err := os.Stat(filepath.Join(dir, LastRefusalFile)); !os.IsNotExist(err) {
		t.Errorf("last-refusal.json written while its lock was held: %v", err)
	}
	w.refusal.fileMu.Unlock()
	f, _ := waitReason(t, dir, func(f *reason.File) bool { return f.Refusals == 100 })
	if f.Target != "/t/99" {
		t.Errorf("target %s, want /t/99", f.Target)
	}
	_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
}

// TestReasonFileBoundsAnAgentsLongTarget: a target is a string the agent chose, up to the ledger's line bound. The
// file stays within reason.MaxFileBytes with the target cut and its length said, the ledger line keeps it whole,
// and the ring keeps no more than a cut copy of it.
func TestReasonFileBoundsAnAgentsLongTarget(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 0)
	long := "/t/" + strings.Repeat("\x01", 256<<10)
	for range 3 {
		if err := w.Append(refusedEvent(long)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Append(refusedEvent("/t/short")); err != nil {
		t.Fatal(err)
	}
	w.refusal.mu.Lock()
	waiting := 0
	for i, s := range w.refusal.ring {
		if cap(s.payload) > maxSlotPayload {
			t.Errorf("ring slot %d holds %d bytes", i, cap(s.payload))
		}
		waiting += len(s.long)
	}
	if waiting != w.refusal.waiting || waiting > maxWaitingBytes {
		t.Errorf("the ring holds %d bytes of long payloads, counted %d, bound %d", waiting, w.refusal.waiting, maxWaitingBytes)
	}
	w.refusal.mu.Unlock()
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, LastRefusalFile))
	if err != nil {
		t.Fatal(err)
	}
	f, err := reason.Decode(bytes.NewReader(b))
	if err != nil || len(b) > reason.MaxFileBytes {
		t.Fatalf("%d bytes: %v", len(b), err)
	}
	if len(f.Recent) == 0 || f.Target != "/t/short" || f.Refusals != 4 {
		t.Fatalf("%d recent, target %q, %d refusals", len(f.Recent), f.Target, f.Refusals)
	}
	for _, e := range f.Recent[:len(f.Recent)-1] {
		if len(e.Target) > reason.MaxFieldBytes || !strings.HasSuffix(e.Target, fmt.Sprintf("…(%d bytes)", len(long))) {
			t.Errorf("a long target in the file: %d bytes, ending %q", len(e.Target), e.Target[max(0, len(e.Target)-20):])
		}
	}
	var p record.RefusedPayload
	if err := refusedLines(t, dir)[0].DecodePayload(&p); err != nil || p.Target != long {
		t.Errorf("the ledger line's target is not whole (%d bytes, %v)", len(p.Target), err)
	}
}

// holdFlush makes post() schedule no write: the test writes the file itself, or Close does.
func holdFlush(w *Writer) {
	w.refusal.mu.Lock()
	w.refusal.armed = true
	w.refusal.mu.Unlock()
}

// TestPostNeverDecodesOnAppendsPath: a target is a string the agent chose, and a path within PATH_MAX made of control
// bytes is a 24 KiB payload (each byte escaped as six). post() copies a payload into the ring and never decodes it:
// decoding that payload cost more than the whole Append had (2026-10-24). In the steady state a refusal
// that fits a slot allocates nothing, and a longer one only its copy.
func TestPostNeverDecodesOnAppendsPath(t *testing.T) {
	w, _, _ := openTestWriter(t)
	startRun(t, w, 0)
	holdFlush(w)
	pathMax := refusedEvent("/t/" + strings.Repeat("\x01", 4093))
	long := refusedEvent("/t/" + strings.Repeat("\x01", 64<<10))
	for range reason.RingSize { // every slot has its buffer
		w.refusal.post(w, pathMax)
	}
	if n := testing.AllocsPerRun(100, func() { w.refusal.post(w, pathMax) }); n != 0 {
		t.Errorf("post of a %d-byte payload: %.0f allocations, want 0", len(pathMax.Payload), n)
	}
	if n := testing.AllocsPerRun(100, func() { w.refusal.post(w, long) }); n > 1 {
		t.Errorf("post of a %d-byte payload: %.0f allocations, want at most its copy", len(long.Payload), n)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
}

// TestEachRefusalIsDecodedOnce: a write decodes the refusals no write has decoded yet and keeps their fields, cut, so
// the next write decodes only what is new, and a long payload is let go once decoded.
func TestEachRefusalIsDecodedOnce(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 0)
	holdFlush(w)
	for i := range reason.RingSize {
		if err := w.Append(refusedEvent(fmt.Sprintf("/t/%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Append(refusedEvent("/t/" + strings.Repeat("a", 64<<10))); err != nil {
		t.Fatal(err)
	}
	w.flushRefusal(false)
	if w.refusal.decoded != reason.RingSize || w.refusal.waiting != 0 {
		t.Fatalf("first write: %d decoded, %d bytes waiting; want %d, 0", w.refusal.decoded, w.refusal.waiting, reason.RingSize)
	}
	holdFlush(w)
	if err := w.Append(refusedEvent("/t/new")); err != nil {
		t.Fatal(err)
	}
	w.flushRefusal(false)
	if w.refusal.decoded != reason.RingSize+1 {
		t.Errorf("second write: %d decoded in all, want %d", w.refusal.decoded, reason.RingSize+1)
	}
	f, _ := waitReason(t, dir, func(f *reason.File) bool { return f.Refusals == reason.RingSize+2 })
	if f.Target != "/t/new" || len(f.Recent) != reason.RingSize || !strings.HasSuffix(f.Recent[30].Target, "bytes)") {
		t.Errorf("target %q, %d recent, recent[30] ends %q", f.Target, len(f.Recent), f.Recent[30].Target[max(0, len(f.Recent[30].Target)-20):])
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
}

// TestAWriteDecodesOnlyTheRefusalsTheFileCanList: a write decodes the ring newest first and stops once those it
// decoded take more than the file even at their smallest (reason.MinEntryBytes), since Encode lists none older. A
// flood of PATH_MAX targets made of control bytes (24 KiB each in the file) costs a few decodes a write, not 32,
// and the file is the bytes Encode makes of the whole ring.
func TestAWriteDecodesOnlyTheRefusalsTheFileCanList(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 0)
	holdFlush(w)
	for i := range reason.RingSize {
		if err := w.Append(refusedEvent(fmt.Sprintf("/t/%02d", i) + strings.Repeat("\x01", 4090))); err != nil {
			t.Fatal(err)
		}
	}
	w.flushRefusal(false)
	if w.refusal.decoded >= reason.RingSize/4 {
		t.Errorf("a write decoded %d of %d refusals", w.refusal.decoded, reason.RingSize)
	}
	got, err := os.ReadFile(filepath.Join(dir, LastRefusalFile))
	if err != nil {
		t.Fatal(err)
	}
	var all []reason.Refusal
	for _, e := range refusedLines(t, dir) {
		var p record.RefusedPayload
		if err := e.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		p.Reason, p.Rule = e.Reason, e.Rule
		all = append(all, reason.Refusal{Seq: e.Seq, TS: e.TS, PID: e.PID, Payload: p})
	}
	want, err := reason.Encode(testRef.ID, reason.RingSize, all)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the file differs from Encode of the whole ring:\n got %d bytes\nwant %d bytes", len(got), len(want))
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
}

// TestReasonFileStaysContiguousWhenLongRefusalsOutrunItsWrites: payloads too long for a ring slot wait whole for the
// write that cuts them, within 2 MiB in all. When refusals the agent made long come faster than the file is written,
// the oldest refusals leave the ring rather than the ring growing or post() decoding: recent stays contiguous and
// its last entry the latest, and the count stays exact, so the reader is told how many are not listed.
func TestReasonFileStaysContiguousWhenLongRefusalsOutrunItsWrites(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 0)
	holdFlush(w)
	// A 720 KiB payload: three are past 2 MiB. Printable, so that the file's 64 KiB bound keeps every cut entry.
	long := "/t/" + strings.Repeat("a", 720<<10)
	for range 3 {
		if err := w.Append(refusedEvent(long)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Append(refusedEvent("/t/short")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, LastRefusalFile))
	if err != nil {
		t.Fatal(err)
	}
	f, err := reason.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	lines := refusedLines(t, dir)
	if f.Refusals != 4 || f.Target != "/t/short" || f.Seq != lines[3].Seq {
		t.Fatalf("refusals %d, target %q, seq %d; want 4, /t/short, %d", f.Refusals, f.Target, f.Seq, lines[3].Seq)
	}
	if len(f.Recent) != 3 {
		t.Fatalf("%d recent, want the newest 3: the oldest long refusal leaves the ring", len(f.Recent))
	}
	for i, e := range f.Recent {
		if e.Seq != lines[1+i].Seq {
			t.Errorf("recent[%d] is seq %d, want %d", i, e.Seq, lines[1+i].Seq)
		}
	}
	if got, notListed := f.Since(0); len(got) != 3 || notListed != 1 {
		t.Errorf("Since(0) = %d entries, %d not listed; want 3, 1", len(got), notListed)
	}
}

// TestAResumedWriterCountsTheRefusalsTheLedgerHolds: refusals is the refused lines the run's ledger has written, not
// those of the Writer that wrote last. A Writer that resumes a run after a crash counts the refused lines already in
// events.jsonl, so the count still only grows and a reader whose cursor is the count it read before the crash learns
// of the next refusal (2026-10-24: the count restarted at 0, and Since hid it).
func TestAResumedWriterCountsTheRefusalsTheLedgerHolds(t *testing.T) {
	w, dir, anchor := openTestWriter(t)
	startRun(t, w, 0)
	for i := range 3 {
		if err := w.Append(refusedEvent(fmt.Sprintf("/t/%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := waitReason(t, dir, func(f *reason.File) bool { return f.Refusals == 3 })
	// The process dies: no Close, so no run_end and no final write; its descriptors go with it.
	w.flushRefusal(true)
	_ = w.events.Close()
	_ = w.lock.Close()

	w2, err := Open(dir, testRef, WithAnchor(anchor))
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if err := w2.Append(refusedEvent("/t/after")); err != nil {
		t.Fatal(err)
	}
	if err := w2.Close(record.RunEndPayload{Reason: record.RunEndStopped}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, LastRefusalFile))
	if err != nil {
		t.Fatal(err)
	}
	f, err := reason.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	lines := refusedLines(t, dir)
	if f.Refusals != uint64(len(lines)) || f.Seq != lines[len(lines)-1].Seq || f.Target != "/t/after" {
		t.Fatalf("refusals %d, seq %d, target %q; the ledger has %d refused lines, the last seq %d",
			f.Refusals, f.Seq, f.Target, len(lines), lines[len(lines)-1].Seq)
	}
	got, notListed := f.Since(before.Refusals)
	if len(got) != 1 || got[0].Target != "/t/after" || notListed != 0 {
		t.Errorf("Since(%d) = %+v, %d not listed; want the one refusal after the resume", before.Refusals, got, notListed)
	}
}

// TestAbandonWritesThePendingRefusalAndNothingAfter: Abandon, like Close, writes the latest refusal before it returns,
// into both copies, even inside the coalescing window, and no write scheduled before it runs after it.
func TestAbandonWritesThePendingRefusalAndNothingAfter(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 0)
	mirror := t.TempDir()
	if err := w.MirrorLastRefusal(mirror); err != nil {
		t.Fatal(err)
	}
	w.refusal.mu.Lock()
	w.refusal.last = time.Now() // as if a write had just run: the next one waits for the window to end
	w.refusal.mu.Unlock()
	for _, target := range []string{"/t/first", "/t/latest"} {
		if err := w.Append(refusedEvent(target)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, LastRefusalFile))
	if err != nil {
		t.Fatalf("Abandon left no last-refusal.json: %v", err)
	}
	f, err := reason.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	lines := refusedLines(t, dir)
	if f.Refusals != 2 || f.Target != "/t/latest" || f.Seq != lines[1].Seq || len(f.Recent) != 2 {
		t.Fatalf("refusals %d, target %q, seq %d, %d recent; want 2, /t/latest, %d, 2", f.Refusals, f.Target, f.Seq,
			len(f.Recent), lines[1].Seq)
	}
	if m, err := os.ReadFile(filepath.Join(mirror, LastRefusalFile)); err != nil || !bytes.Equal(m, b) {
		t.Errorf("the mirror does not hold the same bytes: %v", err)
	}
	time.Sleep(3 * refusalWindow) // the write scheduled at the first refusal is due
	w.refusal.fileMu.Lock()
	writes := w.refusal.writes
	w.refusal.fileMu.Unlock()
	if after, _ := os.ReadFile(filepath.Join(dir, LastRefusalFile)); writes != 1 || !bytes.Equal(after, b) {
		t.Errorf("%d writes; the file changed after Abandon: %v", writes, !bytes.Equal(after, b))
	}
}

// TestAReasonFileCutStatesTheFieldsRealLength: a cut field says how long the field was (ADR 0061 (6)), and so does
// the sentence that quotes it. The writer keeps each refusal's fields cut to reason.MaxFieldBytes once it decoded
// them, and a second cut (the single refusal's tight form, the sentence's MaxShownBytes) stated the length of that
// cut copy, 4096 bytes, not the field's (2026-10-24). The file is the bytes Encode makes of the uncut
// refusal.
func TestAReasonFileCutStatesTheFieldsRealLength(t *testing.T) {
	huge := "/t/" + strings.Repeat("\x01", 100000) // 100003 bytes, each escaped as six in JSON
	long := "/t/" + strings.Repeat("a", 100000)
	for _, tc := range []struct {
		name string
		p    record.RefusedPayload
	}{
		{"tight", record.RefusedPayload{Op: "exec", Target: huge, CommandRule: huge + "r", CommandMatch: huge + "m"}},
		{"cut", record.RefusedPayload{Op: "open", Target: long}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, dir, _ := openTestWriter(t)
			startRun(t, w, 0)
			e := &record.Event{Kind: record.KindRefused, Source: record.SourceLandlock, PID: 5, TID: 5,
				Reason: record.ReasonReadDenied, Rule: "fs.deny_read[~/.ssh]"}
			if err := e.SetPayload(tc.p); err != nil {
				t.Fatal(err)
			}
			if err := w.Append(e); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(dir, LastRefusalFile))
			if err != nil {
				t.Fatal(err)
			}
			f, err := reason.Decode(bytes.NewReader(got))
			if err != nil {
				t.Fatal(err)
			}
			end := func(s string) string { return s[max(0, len(s)-24):] }
			if n := fmt.Sprintf("%d bytes)", len(tc.p.Target)); !strings.HasSuffix(f.Target, "("+n) ||
				!strings.Contains(f.Text, " ("+n+":") {
				t.Errorf("target ends %q, text %q: want both to say %s", end(f.Target), f.Text, n)
			}
			if tc.p.CommandMatch != "" {
				if n := fmt.Sprintf("(%d bytes)", len(tc.p.CommandMatch)); !strings.HasSuffix(f.CommandMatch, n) ||
					!strings.HasSuffix(f.Recent[0].CommandMatch, n) {
					t.Errorf("command_match ends %q, recent's %q: want %s", end(f.CommandMatch), end(f.Recent[0].CommandMatch), n)
				}
			}
			l := refusedLines(t, dir)[0]
			p := tc.p
			p.Reason, p.Rule = l.Reason, l.Rule
			want, err := reason.Encode(testRef.ID, 1, []reason.Refusal{{Seq: l.Seq, TS: l.TS, PID: l.PID, Payload: p}})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("the file (%d bytes) differs from Encode of the uncut refusal (%d bytes)", len(got), len(want))
			}
		})
	}
}

// TestTheHooksCopyIsWrittenBeforeTheRunDirectorysCopy: the mirror (the copy a harness's hook reads through
// TEGO_REASON) is written first, under its own lock, so a refusal reaches it while a write of the run directory's
// copy, which no process of the run reads, is still held up (a rename on a slow disk). Both copies were written under
// one lock, the run directory's first, so a slow write there could hold the mirror back. On CI a refused line's
// mirror entry was still missing 71 ms after the line, and the hook told the refusal one request late (2026-11-11);
// what held it back there was not measured: a slow rename under that lock and the timer's delay both fit, and only
// the first is removed here. Here the run directory's lock is held, as a slow rename would hold it, across three
// refusals a window apart; the mirror must list each, and the run directory's copy must catch up, never older than
// the one before it, once the lock is free.
func TestTheHooksCopyIsWrittenBeforeTheRunDirectorysCopy(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	t.Cleanup(func() { _ = w.Abandon() }) // after a failure, so the temporary directory can go; after Close, a no-op
	startRun(t, w, 0)
	mirror := t.TempDir()
	if err := w.MirrorLastRefusal(mirror); err != nil {
		t.Fatal(err)
	}
	w.refusal.fileMu.Lock() // as a write of the run directory's copy would, on a slow disk
	held := true
	release := func() {
		if held {
			held = false
			w.refusal.fileMu.Unlock()
		}
	}
	defer release()
	for i := range 3 {
		if err := w.Append(refusedEvent(fmt.Sprintf("/t/%d", i))); err != nil {
			t.Fatal(err)
		}
		var f *reason.File
		for deadline := time.Now().Add(5 * time.Second); f == nil || f.Refusals != uint64(i+1); time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				release()
				t.Fatalf("refusal %d: the mirror waited for the run directory's copy (it lists %v)", i+1, f)
			}
			if b, err := os.ReadFile(filepath.Join(mirror, LastRefusalFile)); err == nil {
				f, _ = reason.Decode(bytes.NewReader(b))
			}
		}
		if f.Target != fmt.Sprintf("/t/%d", i) {
			t.Fatalf("refusal %d: the mirror's latest is %s", i+1, f.Target)
		}
		if _, err := os.Stat(filepath.Join(dir, LastRefusalFile)); !os.IsNotExist(err) {
			t.Fatalf("the run directory's copy was written while its lock was held: %v", err)
		}
	}
	release()
	got, b := waitReason(t, dir, func(f *reason.File) bool { return f.Refusals == 3 })
	if got.Target != "/t/2" {
		t.Errorf("the run directory's copy ends at %s, want /t/2", got.Target)
	}
	if m, _ := os.ReadFile(filepath.Join(mirror, LastRefusalFile)); !bytes.Equal(m, b) {
		t.Errorf("the run directory's copy differs from the mirror once both are written")
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
}

// TestTheHooksCopyListsOnlyLinesTheLedgerHolds: a reader of the mirror never learns of a refusal the record does not
// hold. A refused line is written to events.jsonl before the ring takes it (post runs after the write), and the
// mirror is written from the ring, so every seq the mirror names, at any moment, is a line already in events.jsonl.
// That is why the mirror is written first and the run directory's copy second: a crash between the two leaves the
// mirror a write ahead of the run directory's copy, which no process of the run reads, and neither ahead of the
// ledger. Four writers append refused lines while a reader checks each mirror it reads against events.jsonl.
func TestTheHooksCopyListsOnlyLinesTheLedgerHolds(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 0)
	mirror := t.TempDir()
	if err := w.MirrorLastRefusal(mirror); err != nil {
		t.Fatal(err)
	}
	ledgerSeqs := func() map[uint64]bool {
		b, err := os.ReadFile(filepath.Join(dir, EventsFile))
		if err != nil {
			t.Error(err)
			return nil
		}
		out := map[uint64]bool{}
		lines := bytes.Split(b, []byte("\n"))
		for _, l := range lines[:len(lines)-1] { // the last piece may be a line still being written
			var e struct {
				Seq  uint64 `json:"seq"`
				Kind string `json:"kind"`
			}
			if err := json.Unmarshal(l, &e); err != nil {
				t.Errorf("events.jsonl: %v: %s", err, l)
				return nil
			}
			if e.Kind == string(record.KindRefused) {
				out[e.Seq] = true
			}
		}
		return out
	}
	stop := make(chan struct{})
	var readers sync.WaitGroup
	reads := 0
	readers.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			b, err := os.ReadFile(filepath.Join(mirror, LastRefusalFile))
			if err != nil {
				time.Sleep(100 * time.Microsecond)
				continue
			}
			f, err := reason.Decode(bytes.NewReader(b))
			if err != nil {
				t.Errorf("the mirror is not one whole file: %v", err)
				return
			}
			have := ledgerSeqs() // read after the mirror: a line the mirror names was written before it
			for _, r := range f.Recent {
				if !have[r.Seq] {
					t.Errorf("the mirror names seq %d, which events.jsonl does not hold", r.Seq)
					return
				}
			}
			reads++
		}
	})
	var writers sync.WaitGroup
	for g := range 4 {
		writers.Go(func() {
			for i := range 100 {
				if err := w.Append(refusedEvent(fmt.Sprintf("/t/%d.%d", g, i))); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	writers.Wait()
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	close(stop)
	readers.Wait()
	if reads == 0 {
		t.Error("the reader never read the mirror")
	}
	f, _ := waitReason(t, mirror, func(f *reason.File) bool { return f.Refusals == 400 })
	if b, _ := os.ReadFile(filepath.Join(dir, LastRefusalFile)); f == nil || !bytes.Equal(b, mustRead(t, filepath.Join(mirror, LastRefusalFile))) {
		t.Errorf("after Close the two copies differ")
	}
}

// mustRead is the file at path.
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
