// SPDX-License-Identifier: Apache-2.0

package status

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// nopAnchor keeps the tests out of the host-wide chain.log.
type nopAnchor struct{}

func (nopAnchor) Append(string, string) error       { return nil }
func (nopAnchor) Head(string) (string, bool, error) { return "", false, nil }

// fixedClock stamps every event with the same wall time, so idle is exactly what a test asks for.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }
func (c fixedClock) Mono() uint64   { return uint64(c.t.UnixNano()) }

var base = time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC)

// write builds a run directory whose events are stamped at base, and returns its path. fn appends
// whatever the case needs; the writer is left open when keepOpen, which is what "the lock is held"
// means for a reader.
func write(t *testing.T, keepOpen bool, fn func(w *ledger.Writer), end *record.RunEndPayload) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "r-00000000-000000000000a-aaaaaa")
	w, err := ledger.Open(dir, record.RunRef{ID: filepath.Base(dir), Agent: "tester"},
		ledger.WithAnchor(nopAnchor{}), ledger.WithClock(fixedClock{base}))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if fn != nil {
		fn(w)
	}
	if end != nil {
		if err := w.Close(*end); err != nil {
			t.Fatalf("close: %v", err)
		}
		return dir
	}
	if !keepOpen {
		// Release the lock without writing run_end, the way a killed launcher does.
		if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
			t.Fatalf("close: %v", err)
		}
		truncateLastLine(t, filepath.Join(dir, ledger.EventsFile))
		return dir
	}
	t.Cleanup(func() { _ = w.Close(record.RunEndPayload{Reason: record.RunEndExit}) })
	return dir
}

// truncateLastLine drops a ledger's last line.
func truncateLastLine(t *testing.T, path string) {
	t.Helper()
	b := readFile(t, path)
	for i := len(b) - 2; i >= 0; i-- {
		if b[i] == '\n' {
			writeFile(t, path, b[:i+1])
			return
		}
	}
	writeFile(t, path, nil)
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := osReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return b
}

func writeFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := osWriteFile(p, b); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

// runStart appends a run_start with the given stall_after ("" for none).
func runStart(stall string) func(*ledger.Writer) {
	return func(w *ledger.Writer) {
		p := record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "landlock"}
		if stall != "" {
			p.Limits = &record.Limits{StallAfter: stall}
		}
		if err := w.WriteRunStart(p); err != nil {
			panic(err)
		}
	}
}

// appendEvent adds one event of the given kind with an optional payload.
func appendEvent(w *ledger.Writer, kind record.Kind, payload any) {
	e := &record.Event{Kind: kind, Source: record.SourceSupervisor, PID: 1, TID: 1}
	if payload != nil {
		if err := e.SetPayload(payload); err != nil {
			panic(err)
		}
	}
	if err := w.Append(e); err != nil {
		panic(err)
	}
}

func derive(t *testing.T, dir string, held bool, now time.Time, stall time.Duration) *Snapshot {
	t.Helper()
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer r.Close()
	s, err := Derive(r, held, now, stall)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	return s
}

// TestDeriveStates is limits-check-doctor-cli.md R7 to R11 as a table; its "lost" case is R8 (no lock, run_start
// but no run_end reads Lost, not Done).
func TestDeriveStates(t *testing.T) {
	tests := []struct {
		name  string
		build func(t *testing.T) (dir string, held bool)
		now   time.Time
		stall time.Duration
		want  State
	}{
		{"done", func(t *testing.T) (string, bool) {
			return write(t, false, runStart(""), &record.RunEndPayload{Reason: record.RunEndExit, ExitCode: 0}), false
		}, base, time.Hour, Done},
		{"lost", func(t *testing.T) (string, bool) {
			return write(t, false, runStart(""), nil), false
		}, base, time.Hour, Lost},
		{"a live run with no run_end is running", func(t *testing.T) (string, bool) {
			return write(t, true, runStart(""), nil), true
		}, base, time.Hour, Running},
		{"stalled", func(t *testing.T) (string, bool) {
			return write(t, true, runStart(""), nil), true
		}, base.Add(2 * time.Hour), time.Hour, Stalled},
		{"waiting model", func(t *testing.T) (string, bool) {
			return write(t, true, func(w *ledger.Writer) {
				runStart("")(w)
				appendEvent(w, record.KindSSLRequest, record.SSLRequestPayload{Host: "api", Method: "POST"})
			}, nil), true
		}, base, time.Hour, WaitingModel},
		{"a response clears waiting model", func(t *testing.T) (string, bool) {
			return write(t, true, func(w *ledger.Writer) {
				runStart("")(w)
				appendEvent(w, record.KindSSLRequest, record.SSLRequestPayload{Host: "api"})
				appendEvent(w, record.KindSSLResponse, record.SSLResponsePayload{Status: 200, ParserVersion: "1"})
			}, nil), true
		}, base, time.Hour, Running},
		{"waiting tool", func(t *testing.T) (string, bool) {
			return write(t, true, func(w *ledger.Writer) {
				runStart("")(w)
				appendEvent(w, record.KindSSLRequest, record.SSLRequestPayload{Host: "api"})
				appendEvent(w, record.KindSSLResponse, record.SSLResponsePayload{Status: 200, ParserVersion: "1"})
				appendEvent(w, record.KindDecision, record.DecisionPayload{Step: 1, Tool: "bash", ToolUseID: "t1"})
			}, nil), true
		}, base, time.Hour, WaitingTool},
		{"a new request supersedes waiting tool", func(t *testing.T) (string, bool) {
			return write(t, true, func(w *ledger.Writer) {
				runStart("")(w)
				appendEvent(w, record.KindDecision, record.DecisionPayload{Step: 1, Tool: "bash", ToolUseID: "t1"})
				appendEvent(w, record.KindSSLRequest, record.SSLRequestPayload{Host: "api"})
			}, nil), true
		}, base, time.Hour, WaitingModel},
		{"stall wins over waiting model", func(t *testing.T) (string, bool) {
			return write(t, true, func(w *ledger.Writer) {
				runStart("")(w)
				appendEvent(w, record.KindSSLRequest, record.SSLRequestPayload{Host: "api"})
			}, nil), true
		}, base.Add(time.Hour), time.Minute, Stalled},
		{"an empty locked ledger is running", func(t *testing.T) (string, bool) {
			return write(t, true, nil, nil), true
		}, base, time.Hour, Running},
		{"an empty unlocked ledger never started", func(t *testing.T) (string, bool) {
			return write(t, false, nil, nil), false
		}, base, time.Hour, NeverStarted},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, held := tc.build(t)
			got := derive(t, dir, held, tc.now, tc.stall)
			if got.St != tc.want {
				t.Fatalf("state %q, want %q (idle %s, events %d)", got.St, tc.want, got.Idle, got.Events)
			}
		})
	}
}

func TestDeriveReportsTheExitOfADoneRun(t *testing.T) {
	dir := write(t, false, runStart(""), &record.RunEndPayload{Reason: record.RunEndStopped, ExitCode: 143})
	s := derive(t, dir, false, base, time.Hour)
	if s.St != Done || s.ExitReason != record.RunEndStopped || s.ExitCode != 143 {
		t.Fatalf("snapshot %+v", s)
	}
	if s.Agent != "tester" || s.Run == "" {
		t.Fatalf("the snapshot must name the run and its agent: %+v", s)
	}
}

func TestDeriveStallAfterSource(t *testing.T) {
	// The run's own compiled stall_after comes from run_start.limits, else the machine default.
	dir := write(t, true, runStart("90s"), nil)
	s := derive(t, dir, true, base, 0)
	if s.StallAfter != 90*time.Second || s.StallAfterSource != SourceRunStart {
		t.Fatalf("stall %s from %q, want 90s from run_start", s.StallAfter, s.StallAfterSource)
	}
	if s2 := derive(t, write(t, true, runStart(""), nil), true, base, 0); s2.StallAfter != DefaultStallAfter ||
		s2.StallAfterSource != SourceMachine {
		t.Fatalf("stall %s from %q, want the machine default", s2.StallAfter, s2.StallAfterSource)
	}
	// A run whose own ceiling has passed is stalled without the caller naming one.
	s3 := derive(t, write(t, true, runStart("1s"), nil), true, base.Add(time.Minute), 0)
	if s3.St != Stalled {
		t.Fatalf("state %q, want stalled", s3.St)
	}
}

func TestDeriveStepAndCounts(t *testing.T) {
	dir := write(t, true, func(w *ledger.Writer) {
		runStart("")(w)
		e := &record.Event{Kind: record.KindFS, Source: record.SourceSeccomp, PID: 2, TID: 2,
			Rule: "fs.write[./out]", Verdict: record.VerdictAllow, Authority: record.AuthorityRule,
			Attr: &record.Attribution{Step: 3, Confidence: record.ConfidenceLikely, Method: record.MethodTime}}
		if err := e.SetPayload(record.FSPayload{Op: record.FSOpen, Path: "/work/out/a"}); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}, nil)
	s := derive(t, dir, true, base, time.Hour)
	if s.Step != 3 {
		t.Fatalf("step %d, want 3", s.Step)
	}
	if s.Events != 2 {
		t.Fatalf("events %d, want 2", s.Events)
	}
	if s.LastEvent == nil || s.LastEvent.Kind != record.KindFS {
		t.Fatalf("last event %+v", s.LastEvent)
	}
	if s.SinceMonoNS == 0 || s.Since.IsZero() {
		t.Fatal("a snapshot exposes both the wall and the monotonic reading (§6 case 7)")
	}
}

func TestDeriveTwoRunEndLinesUseTheFirst(t *testing.T) {
	// §6 case 5: a second run_end is an anomaly, never a crash and never a changed answer.
	dir := write(t, false, runStart(""), &record.RunEndPayload{Reason: record.RunEndExit, ExitCode: 3})
	path := filepath.Join(dir, ledger.EventsFile)
	b := readFile(t, path)
	lines := splitLines(b)
	writeFile(t, path, append(b, lines[len(lines)-1]...))
	s := derive(t, dir, false, base, time.Hour)
	if s.St != Done || s.ExitCode != 3 {
		t.Fatalf("snapshot %+v", s)
	}
	// And it is reported, not resolved silently: the CLI warns [ledger-anomaly] and --json names it.
	if s.ExtraRunEnds != 1 || len(s.Anomalies()) != 1 || !strings.Contains(s.Anomalies()[0], "run_end") {
		t.Errorf("ExtraRunEnds %d, Anomalies %q; want one naming run_end", s.ExtraRunEnds, s.Anomalies())
	}
	healthy := derive(t, write(t, false, runStart(""), &record.RunEndPayload{Reason: record.RunEndExit}), false, base, time.Hour)
	if healthy.ExtraRunEnds != 0 || healthy.Anomalies() != nil {
		t.Errorf("a healthy ledger reports %q", healthy.Anomalies())
	}
}

func TestLockHeld(t *testing.T) {
	dir := write(t, true, runStart(""), nil)
	held, err := LockHeld(dir)
	if err != nil || !held {
		t.Fatalf("held=%v err=%v, want held", held, err)
	}
	empty := t.TempDir()
	held, err = LockHeld(empty)
	if err != nil || held {
		t.Fatalf("a directory with no lock file reads as free: held=%v err=%v", held, err)
	}
}

func TestDeriveAll(t *testing.T) {
	root := t.TempDir()
	mkRun(t, root, "r-00000000-000000000000a-aaaaaa", true)
	mkRun(t, root, "r-00000000-000000000000b-bbbbbb", false)
	if err := osMkdir(filepath.Join(root, "not-a-run")); err != nil {
		t.Fatal(err)
	}
	snaps, err := DeriveAll(t.Context(), root, base)
	if err != nil {
		t.Fatalf("DeriveAll: %v", err)
	}
	if len(snaps) != 2 {
		t.Fatalf("got %d snapshots, want 2", len(snaps))
	}
	if snaps[0].Run >= snaps[1].Run {
		t.Fatalf("runs must be sorted oldest first: %s then %s", snaps[0].Run, snaps[1].Run)
	}
	if snaps[0].St != Done || snaps[1].St != Lost {
		t.Fatalf("states %q %q", snaps[0].St, snaps[1].St)
	}
}

func TestDeriveAllMissingRoot(t *testing.T) {
	snaps, err := DeriveAll(t.Context(), filepath.Join(t.TempDir(), "never"), base)
	if err != nil || snaps != nil {
		t.Fatalf("snaps %v err %v, want nothing", snaps, err)
	}
}

// mkRun writes one finished or lost run into root.
func mkRun(t *testing.T, root, id string, ended bool) {
	t.Helper()
	dir := filepath.Join(root, id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "tester"},
		ledger.WithAnchor(nopAnchor{}), ledger.WithClock(fixedClock{base}))
	if err != nil {
		t.Fatal(err)
	}
	runStart("")(w)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	if !ended {
		truncateLastLine(t, filepath.Join(dir, ledger.EventsFile))
	}
}

// TestLockHeldRefusesAFIFO: a FIFO planted as a run's lock hung `tego status` in the open; it is refused
// at once now, like a link.
func TestLockHeldRefusesAFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, ledger.LockFile), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := LockHeld(dir); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO lock was read as a lock")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("LockHeld blocked on a FIFO")
	}
}

// TestDeriveObservesItsContext: a cancelled context ends the read of a ledger (R29).
func TestDeriveObservesItsContext(t *testing.T) {
	root := t.TempDir()
	mkRun(t, root, "r-00000000-000000000000a-aaaaaa", true)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := DeriveAll(ctx, root, base); !errors.Is(err, context.Canceled) {
		t.Fatalf("DeriveAll err %v, want context.Canceled", err)
	}
}
