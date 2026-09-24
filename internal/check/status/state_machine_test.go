// SPDX-License-Identifier: Apache-2.0

package status

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestDeriveStateMachinePrecedence pins boundaries of the R7-R12 state machine that
// TestDeriveStates (status_test.go) does not already exercise: R7's dependence on the caller's own
// lock probe rather than run_end alone (E4), R9's precedence over R11 (not just R10, which
// "stall wins over waiting model" already covers) and over R10 when both are simultaneously true,
// and the inclusive ">=" at R9's own boundary (docs/p0/limits-check-doctor-cli.md §5, §8 I3).
func TestDeriveStateMachinePrecedence(t *testing.T) {
	tests := []struct {
		name  string
		build func(t *testing.T) (dir string, held bool)
		now   time.Time
		stall time.Duration
		want  State
	}{
		{
			// R7 fires only on "!lockHeld AND run_end present" — never on run_end alone. A launcher
			// whose cgroup teardown is slow can flush run_end before releasing its flock (§6 E4); as
			// long as the caller's own probe still reports the lock held, this must read running, not
			// done, so nothing ever reports a run finished while its process is still alive.
			name: "run_end on disk with the lock still held reads running, not done",
			build: func(t *testing.T) (string, bool) {
				dir := write(t, false, runStart(""), &record.RunEndPayload{Reason: record.RunEndExit, ExitCode: 0})
				return dir, true // override: the caller's probe still says held, despite run_end on disk
			},
			now: base, stall: time.Hour, want: Running,
		},
		{
			// R9 is checked before R11 exactly as it is before R10 ("stall wins over waiting model"
			// in status_test.go already pins that half). A run whose last decision asked for a tool
			// and then went idle past stall_after must read stalled, not stuck showing "waiting tool"
			// forever — the tool never came back either, and R9 is what notices.
			name: "stall wins over waiting tool",
			build: func(t *testing.T) (string, bool) {
				dir := write(t, true, func(w *ledger.Writer) {
					runStart("")(w)
					appendEvent(w, record.KindDecision, record.DecisionPayload{Step: 1, Tool: "bash", ToolUseID: "t1"})
				}, nil)
				return dir, true
			},
			now: base.Add(2 * time.Hour), stall: time.Hour, want: Stalled,
		},
		{
			// R10 is checked before R11. An SSLRequest that never got its response leaves
			// openRequest set; a decision naming a tool logged afterward (without an intervening
			// response) sets toolPending too, so both R10's and R11's conditions hold at once. The
			// state machine's declared order (R10 before R11) must decide it, not source order in the
			// switch happening to agree by accident.
			name: "an open model request wins over a pending tool when both hold",
			build: func(t *testing.T) (string, bool) {
				dir := write(t, true, func(w *ledger.Writer) {
					runStart("")(w)
					appendEvent(w, record.KindSSLRequest, record.SSLRequestPayload{Host: "api", Method: "POST"})
					appendEvent(w, record.KindDecision, record.DecisionPayload{Step: 1, Tool: "bash", ToolUseID: "t1"})
				}, nil)
				return dir, true
			},
			now: base, stall: time.Hour, want: WaitingModel,
		},
		{
			// R9 reads "idle >= stall_after" (§5): the boundary itself is stalled, not one poll later.
			name: "idle exactly equal to stall_after is already stalled",
			build: func(t *testing.T) (string, bool) {
				return write(t, true, runStart(""), nil), true
			},
			now: base.Add(time.Hour), stall: time.Hour, want: Stalled,
		},
		{
			// The other side of the same boundary: one nanosecond under stall_after must not trip R9.
			name: "idle one nanosecond under stall_after is still running",
			build: func(t *testing.T) (string, bool) {
				return write(t, true, runStart(""), nil), true
			},
			now: base.Add(time.Hour - time.Nanosecond), stall: time.Hour, want: Running,
		},
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

// TestDeriveTornMiddleLineIsFatal covers status.Derive's own error contract (§4 "Functions and
// contracts": "a torn middle line is fatal", §6 E3 vs. case 2, §7's failure-modes row). Only an
// *unterminated* final line is the live-writer race that case 2 tolerates; a terminated line earlier
// in the file that fails to decode is real corruption, and Derive must report it as an error rather
// than silently skip it and hand back a Snapshot for whatever it did manage to read — "status returns
// an error, never guesses a state".
func TestDeriveTornMiddleLineIsFatal(t *testing.T) {
	dir := write(t, false, runStart(""), &record.RunEndPayload{Reason: record.RunEndExit, ExitCode: 0})
	path := filepath.Join(dir, ledger.EventsFile)
	lines := splitLines(readFile(t, path))
	if len(lines) != 2 {
		t.Fatalf("fixture has %d lines, want 2 (run_start, run_end)", len(lines))
	}
	// Splice a terminated, undecodable line between run_start and run_end: not the torn tail (it has
	// its own "\n" and something valid follows it), so it must not be forgiven the way case 2 is.
	var corrupt []byte
	corrupt = append(corrupt, lines[0]...)
	corrupt = append(corrupt, []byte("not a record line\n")...)
	corrupt = append(corrupt, lines[1]...)
	writeFile(t, path, corrupt)

	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer func() { _ = r.Close() }()
	s, err := Derive(r, false, base, time.Hour)
	if err == nil {
		t.Fatalf("Derive returned state %q over a corrupt ledger instead of an error", s.St)
	}
	if !errors.Is(err, ledger.ErrCorruptLedger) {
		t.Errorf("error %v does not wrap ledger.ErrCorruptLedger", err)
	}
}

// TestDeriveEmptyLockedLedgerGraceWindow is §6 E1's locked half: a run with nothing flushed yet (not
// even run_start) has no event for Since to read, so the grace window runs from the ledger file's own
// mtime instead (status.go's os.Stat fallback), still on the wall clock since there is no MonoNS
// reading to compare against. Pin both sides of that window so a run that genuinely sat idle since
// creation is not stuck reading "running" forever for lack of a single event to time out from.
func TestDeriveEmptyLockedLedgerGraceWindow(t *testing.T) {
	dir := write(t, true, nil, nil)
	path := filepath.Join(dir, ledger.EventsFile)
	if err := os.Chtimes(path, base, base); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	if s := derive(t, dir, true, base, time.Hour); s.St != Running {
		t.Fatalf("state %q right after creation, want %q", s.St, Running)
	}
	s := derive(t, dir, true, base.Add(2*time.Hour), time.Hour)
	if s.St != Stalled {
		t.Fatalf("state %q once stall_after has elapsed since the file's own mtime, want %q", s.St, Stalled)
	}
	if s.IdleClock != ClockWall {
		t.Errorf("idle clock %q, want %q: there is no event to read a monotonic reading from", s.IdleClock, ClockWall)
	}
}
