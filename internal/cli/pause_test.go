// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestPauseResumeLifecycle: against a run a stand-in launcher holds (it applies nothing), pause writes the overlay's
// pause by the cli and says it is not confirmed yet, a second pause is "already paused", resume undoes it, and a
// second resume says it was not paused.
func TestPauseResumeLifecycle(t *testing.T) {
	old := pauseConfirmWait
	pauseConfirmWait = 100 * time.Millisecond
	t.Cleanup(func() { pauseConfirmWait = old })
	dir, id, _ := liveRun(t)
	if err := liveblock.MarkControl(dir); err != nil { // as a launcher that reads a pause marks its run
		t.Fatal(err)
	}

	code, out, errs := run(t, "pause", id)
	if code != identity.ExitOK || !strings.Contains(out, id+": pause asked; the run's launcher has not confirmed it yet") {
		t.Fatalf("pause: exit %d stdout %q stderr %q", code, out, errs)
	}
	o, err := liveblock.Read(dir, id)
	if err != nil || !o.Paused || len(o.Changes) != 1 || o.Changes[0].Op != liveblock.OpPause || !strings.HasSuffix(o.Changes[0].By, " cli") {
		t.Fatalf("overlay %+v, %v: want one pause by the cli", o, err)
	}
	if code, out, _ := run(t, "pause", id); code != identity.ExitOK || out != id+": already paused\n" {
		t.Errorf("a second pause: exit %d stdout %q", code, out)
	}
	if code, out, _ := run(t, "resume", id); code != identity.ExitOK || !strings.Contains(out, "resume asked") {
		t.Errorf("resume: exit %d stdout %q", code, out)
	}
	if code, out, _ := run(t, "resume", id); code != identity.ExitOK || out != id+": was not paused\n" {
		t.Errorf("a second resume: exit %d stdout %q", code, out)
	}
	if o, _ := liveblock.Read(dir, id); o == nil || o.Paused || o.Serial != 2 {
		t.Fatalf("overlay after resume %+v", o)
	}
}

// controlLine is the last gap line in dir's ledger that records a pause or a resume of serial or later: its why and
// seq. It reads the whole ledger; awaitControl reads only what was appended.
func controlLine(dir string, serial uint64) (string, uint64) {
	sc := controlScan{path: filepath.Join(dir, ledger.EventsFile), serial: serial}
	return sc.next()
}

// TestPauseRefusals: no run id is a usage error, a caller inside a run is refused before anything is read, and a run
// that has ended is refused.
func TestPauseRefusals(t *testing.T) {
	if code, _, _ := run(t, "pause"); code != identity.ExitUsage {
		t.Errorf("pause with no run: exit %d, want %d", code, identity.ExitUsage)
	}
	dir, id, _ := liveRun(t)
	old := selfInRun
	selfInRun = func() (bool, error) { return true, nil }
	code, _, errs := run(t, "resume", id)
	selfInRun = old
	if code != identity.ExitFinding || !strings.Contains(errs, "a governed agent cannot change its own governance") {
		t.Fatalf("resume inside a run: exit %d stderr %q", code, errs)
	}
	if _, err := liveblock.Read(dir, id); err == nil {
		t.Fatal("a refused resume wrote the overlay")
	}

	// A run whose launcher did not mark that it reads a pause (an older Tego's) is refused both, and nothing is
	// written.
	odir, oid, _ := liveRun(t)
	for _, name := range []string{"pause", "resume"} {
		code, _, errs := run(t, name, oid)
		if code != identity.ExitFinding || !strings.Contains(errs, "cannot be paused: an older Tego started it") ||
			!strings.Contains(errs, "no-pause") {
			t.Fatalf("%s of an older launcher's run: exit %d stderr %q", name, code, errs)
		}
	}
	if _, err := liveblock.Read(odir, oid); err == nil {
		t.Fatal("a pause refused for an older launcher wrote the overlay")
	}

	_, ended := controlLedger(t, nil)
	if code, _, errs := run(t, "pause", ended); code != identity.ExitFinding || !strings.Contains(errs, "is not running") {
		t.Fatalf("pause of an ended run: exit %d stderr %q", code, errs)
	}
}

// controlLedger writes a closed run whose ledger holds the given gap lines after run_start.
func controlLedger(t *testing.T, gaps []record.GapPayload) (dir, id string) {
	t.Helper()
	root := gcRoot(t)
	var host [32]byte
	rid, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id = string(rid)
	dir = filepath.Join(root, id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "tester"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"true"}, Cwd: "/", Tier: "landlock", RecordMinor: record.Minor}); err != nil {
		t.Fatal(err)
	}
	for _, g := range gaps {
		ev := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor}
		if err := ev.SetPayload(g); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(record.RunEndPayload{Reason: "exit"}); err != nil {
		t.Fatal(err)
	}
	return dir, id
}

// TestControlLine: the launcher's last line for the asked serial or a later one is the answer, an earlier serial's is
// not, and a retry that worked after a failure reads as the success.
func TestControlLine(t *testing.T) {
	at := time.Date(2026, 10, 27, 12, 3, 0, 0, time.UTC)
	lc := func(op string, serial uint64) *record.LiveControlChange {
		return &record.LiveControlChange{Op: op, By: "uid:1000 pid:9 cli", Serial: serial, At: at}
	}
	dir, _ := controlLedger(t, []record.GapPayload{
		{What: record.GapEnforce, Why: record.GapRunPaused, LiveControl: lc("pause", 1)},
		{What: record.GapEnforce, Why: record.GapRunResumed, LiveControl: lc("resume", 2)},
		{What: record.GapEnforce, Why: record.GapPauseFailed, LiveControl: lc("pause", 3)},
		{What: record.GapEnforce, Why: record.GapRunPaused, LiveControl: lc("pause", 3)},
	})
	for _, tc := range []struct {
		serial uint64
		why    string
		seq    uint64
	}{{1, record.GapRunPaused, 4}, {2, record.GapRunPaused, 4}, {3, record.GapRunPaused, 4}, {4, "", 0}} {
		why, seq := controlLine(dir, tc.serial)
		if why != tc.why || seq != tc.seq {
			t.Errorf("controlLine(%d) = %q #%d, want %q #%d", tc.serial, why, seq, tc.why, tc.seq)
		}
	}
}

// TestControlScanReadsOnlyAppended: awaitControl's scan starts at the ledger's size before the change, so an older
// line for the same serial is not taken for the answer; each call reads only what was appended, and a line still
// being written is read once it is complete.
func TestControlScanReadsOnlyAppended(t *testing.T) {
	at := time.Date(2026, 10, 27, 12, 3, 0, 0, time.UTC)
	dir, _ := controlLedger(t, []record.GapPayload{{What: record.GapEnforce, Why: record.GapPauseFailed,
		LiveControl: &record.LiveControlChange{Op: "pause", By: "uid:1000 pid:9 cli", Serial: 1, At: at}}})
	path := filepath.Join(dir, ledger.EventsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var control []byte
	for l := range bytes.Lines(data) {
		if bytes.Contains(l, []byte(`"live_control"`)) {
			control = bytes.Replace(l, []byte(record.GapPauseFailed), []byte(record.GapRunPaused), 1)
		}
	}
	if control == nil {
		t.Fatal("no control line in the ledger")
	}
	sc := controlScan{path: path, off: int64(len(data)), serial: 1}
	if why, _ := sc.next(); why != "" {
		t.Fatalf("a line before the start was read: %q", why)
	}
	appendBytes := func(b []byte) {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		if _, err := f.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	half := len(control) / 2
	appendBytes(control[:half])
	if why, _ := sc.next(); why != "" || sc.off != int64(len(data)) {
		t.Fatalf("a torn line was read: %q, off %d", why, sc.off)
	}
	appendBytes(control[half:])
	if why, _ := sc.next(); why != record.GapRunPaused || sc.off != int64(len(data)+len(control)) {
		t.Fatalf("the appended line: %q, off %d (want %d)", why, sc.off, len(data)+len(control))
	}
	// Started mid-file, at the byte after the control line's start, the scan skips that partial line.
	sc = controlScan{path: path, off: int64(len(data)) + 1, serial: 1}
	if why, _ := sc.next(); why != "" {
		t.Fatalf("a scan from inside a line took it: %q", why)
	}
}
