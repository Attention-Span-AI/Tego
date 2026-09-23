// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestStatusExitCode pins R25's status half of the exit-code contract: a finished run reads clean
// (exit 0) and a run whose launcher died without writing run_end is a finding (exit 1) —
// statusExit's translation of status.Snapshot.St, which nothing in this package exercised end to
// end through Main before this (main_test.go only ever fed status a malformed run id). endedRun
// and lostRun are gc_test.go's fixtures for exactly these two ledger shapes.
// (limits-check-doctor-cli.md R25.)
func TestStatusExitCode(t *testing.T) {
	tests := []struct {
		name      string
		build     func(t *testing.T, root string, at time.Time) string
		wantCode  int
		wantState string
	}{
		{"a finished run is clean", endedRun, identity.ExitOK, "done"},
		{"a run with no run_end and no lock is a finding", lostRun, identity.ExitFinding, "lost"},
		// A launcher that unwound before run_start (Abandon) leaves an empty ledger and a free lock. The sweep treats it as
		// empty, yet status said lost and exited 1.
		{"a run abandoned before run_start never started", abandonedRun, identity.ExitOK, "never started"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := gcRoot(t)
			id := tc.build(t, root, time.Now())
			code, out, errs := run(t, "status", id)
			if code != tc.wantCode {
				t.Fatalf("exit %d, want %d (stdout %q stderr %q)", code, tc.wantCode, out, errs)
			}
			if !strings.Contains(out, tc.wantState) {
				t.Errorf("table lacks state %q:\n%s", tc.wantState, out)
			}
		})
	}
}

// abandonedRun is a run whose launcher unwound before run_start: Open, then Abandon, which writes nothing.
func abandonedRun(t *testing.T, root string, at time.Time) string {
	t.Helper()
	var host [32]byte
	id, err := identity.NewRunID(host, at, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w, err := ledger.Open(filepath.Join(root, string(id)), record.RunRef{ID: string(id), Agent: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}
	return string(id)
}

// TestStatusTableColumns pins R31's default rendering: one aligned table over the Snapshot's
// fields in declaration order (RUN, AGENT, STATE, IDLE, STEP, EVENTS, EXIT), with the run_end
// reason and code rendered together as "<reason> (<code>)", followed by the run's gap line (R34),
// which says "none" out loud for a run that recorded no gap.
func TestStatusTableColumns(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	code, out, errs := run(t, "status", id)
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 6 {
		t.Fatalf("want a header, one row, the gap line, the capability line, the resources line and the ledger line, "+
			"got %d lines:\n%s", len(lines), out)
	}
	// The ledger line: the size of events.jsonl, and no record.max_run_bytes in the fixture's run_start.
	if !strings.HasPrefix(lines[5], "ledger: ") || !strings.HasSuffix(lines[5], " B, no ceiling") {
		t.Errorf("ledger line %q", lines[5])
	}
	if lines[2] != "gaps: none" {
		t.Errorf("gap line %q, want %q", lines[2], "gaps: none")
	}
	// The fixture's run_start predates the capability line (R-cap), which says so rather than
	// reading as a run that could do nothing.
	if lines[3] != "capabilities: not recorded" {
		t.Errorf("capability line %q, want %q", lines[3], "capabilities: not recorded")
	}
	// Its run_end carries no resources object either (R-res): every peak is unknown, never 0.
	if want := "resources: memory peak unknown, pids peak unknown, cpu unknown (user unknown, system unknown), " +
		"cpu throttled unknown, memory events unknown"; lines[4] != want {
		t.Errorf("resources line %q, want %q", lines[4], want)
	}
	header := lines[0]
	prev := -1
	for _, col := range []string{"RUN", "AGENT", "STATE", "IDLE", "STEP", "EVENTS", "EXIT"} {
		i := strings.Index(header, col)
		if i < 0 {
			t.Fatalf("header %q lacks column %q", header, col)
		}
		if i <= prev {
			t.Fatalf("header %q has %q out of R31's declaration order", header, col)
		}
		prev = i
	}
	if !strings.Contains(lines[1], id) || !strings.Contains(lines[1], "done") || !strings.Contains(lines[1], "exit (0)") {
		t.Errorf("row %q lacks the run id, state or exit reason/code", lines[1])
	}
}

// TestStatusJSONSingleRunIsOneObject pins the other half of R31: --json on one named run prints
// that run's own object directly, never wrapped in the {"runs":[...]} shape --all uses — a caller
// piping `tego status <run> --json | jq .state` must not have to branch on how many runs matched.
func TestStatusJSONSingleRunIsOneObject(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	code, out, errs := run(t, "status", id, "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if n := strings.Count(strings.TrimRight(out, "\n"), "\n"); n != 0 {
		t.Fatalf("--json wrote %d extra lines, want one object on one line:\n%s", n, out)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("--json is not one JSON object: %v (%q)", err, out)
	}
	if _, wrapped := got["runs"]; wrapped {
		t.Errorf("a single named run must not be wrapped in {\"runs\":[...]}: %s", out)
	}
	if got["run"] != id {
		t.Errorf("run = %v, want %q: %s", got["run"], id, out)
	}
	if got["state"] != "done" {
		t.Errorf("state = %v, want \"done\": %s", got["state"], out)
	}
}

// TestStatusJSONAllIsAList covers the --all shape (R31): still exactly one JSON object per
// invocation, this time the {"runs":[...]} list, holding every run under the ledger root.
func TestStatusJSONAllIsAList(t *testing.T) {
	root := gcRoot(t)
	first := endedRun(t, root, time.Now().Add(-time.Hour))
	second := endedRun(t, root, time.Now())
	code, out, errs := run(t, "status", "--all", "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if n := strings.Count(strings.TrimRight(out, "\n"), "\n"); n != 0 {
		t.Fatalf("--json wrote %d extra lines, want one object on one line:\n%s", n, out)
	}
	var got statusListJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("--json is not one JSON object: %v (%q)", err, out)
	}
	if len(got.Runs) != 2 {
		t.Fatalf("runs %d, want 2: %s", len(got.Runs), out)
	}
	seen := map[string]bool{}
	for _, r := range got.Runs {
		seen[r.Run] = true
	}
	if !seen[first] || !seen[second] {
		t.Errorf("runs %v missing one of %q, %q", got.Runs, first, second)
	}
}

// TestStatusNoRuns covers the empty-ledger-root case: a machine that has never run anything is
// not a finding, and `tego status --all` says so in one line instead of printing an empty table.
func TestStatusNoRuns(t *testing.T) {
	root := gcRoot(t)
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "status", "--all")
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "no runs") {
		t.Errorf("stdout %q", out)
	}
}

// TestStatusJSONIsAlwaysJSON: `status --json` with no runs printed the table's "no runs", which no JSON reader
// parses, and exit_code was dropped for an agent that exited 0.
func TestStatusJSONIsAlwaysJSON(t *testing.T) {
	root := gcRoot(t)
	for _, args := range [][]string{{"status", "--json"}, {"status", "--json", "--all"}} {
		code, out, errs := run(t, args...)
		if code != identity.ExitOK {
			t.Fatalf("%v: exit %d: %s", args, code, errs)
		}
		var got statusListJSON
		if err := json.Unmarshal([]byte(out), &got); err != nil || got.Runs == nil || len(got.Runs) != 0 {
			t.Errorf("%v with no runs: %q is not {\"runs\":[]} (%v)", args, out, err)
		}
	}
	ended := endedRun(t, root, time.Now())
	code, out, errs := run(t, "status", ended, "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(out, `"exit_reason":"exit","exit_code":0`) {
		t.Errorf("an agent that exited 0 has no exit_code 0:\n%s", out)
	}
	lost := lostRun(t, root, time.Now())
	_, out, _ = run(t, "status", lost, "--json")
	if strings.Contains(out, `"exit_code"`) {
		t.Errorf("a run with no run_end has an exit_code:\n%s", out)
	}
}

// TestSweptRunClaimsNothingMissing: the sweep ends a lost run, so it is no longer status.Lost, and its record may stop
// short all the same: the launcher that held its lines died. Status keeps saying so, and so does the receipt, where the
// sweep used to swap "may stop short" for "no action known to be missing".
func TestSweptRunClaimsNothingMissing(t *testing.T) {
	root := gcRoot(t)
	id := lostRun(t, root, time.Now().Add(-time.Hour))
	if code, _, stderr := run(t, "gc"); code != 0 {
		t.Fatalf("gc exit %d: %s", code, stderr)
	}
	_, out, _ := run(t, "status", id)
	if strings.Contains(out, "no action known to be missing") {
		t.Errorf("a swept run claims nothing is missing:\n%s", out)
	}
	if !strings.Contains(out, "\nin words: 1 gap in the record (counts are a minimum)\n") {
		t.Errorf("a swept run does not say its counts are a minimum:\n%s", out)
	}
	_, out, stderr := run(t, "receipt", id, "--json")
	if !strings.Contains(out, `"record"`) || !strings.Contains(out, "tego knows it missed some actions") {
		t.Errorf("a swept run's receipt has no record gap:\n%s\n%s", out, stderr)
	}
}

// TestStatusLostRunClaimsNothingMissing: a lost run's launcher died with no run_end, so its record may stop short of
// what it did: status says so where it would say "no action known to be missing", as the receipt calls the same run
// incomplete. A finished run with the same gap keeps the plain sentence.
func TestStatusLostRunClaimsNothingMissing(t *testing.T) {
	root := gcRoot(t)
	const cut = "the record has no end, so it may stop short of what the run did"
	paused := liveChangesRun(t, root, false)
	dropLastLine(t, filepath.Join(root, paused, ledger.EventsFile))
	bare := lostRun(t, root, time.Now())
	for _, c := range []struct{ id, want string }{
		{paused, cut + "; a live block was added; the run was paused; the run was resumed"},
		{bare, cut},
	} {
		_, out, _ := run(t, "status", c.id)
		if !strings.Contains(out, "\nin words: "+c.want+"\n") {
			t.Errorf("status of a lost run:\n%s\nwant in words: %s", out, c.want)
		}
		if strings.Contains(out, "no action known to be missing") {
			t.Errorf("a lost run claims nothing is missing:\n%s", out)
		}
		_, out, _ = run(t, "status", c.id, "--json")
		if !strings.Contains(out, `"gap_words":"`+c.want+`"`) {
			t.Errorf("status --json of a lost run: %s", out)
		}
	}
}

// TestStatusUnknownRunIsUsage covers the run-not-found branch (R25: a usage error, distinct from
// the malformed-id branch main_test.go already pins) — a validly-shaped run id that names no
// directory under the ledger root is the caller's mistake, not tego's own error.
func TestStatusUnknownRunIsUsage(t *testing.T) {
	gcRoot(t)
	code, _, errs := run(t, "status", "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
	if code != identity.ExitUsage {
		t.Fatalf("exit %d, want %d (stderr %q)", code, identity.ExitUsage, errs)
	}
	if !strings.Contains(errs, "no such run") {
		t.Errorf("stderr %q", errs)
	}
}

// corruptRun builds a finished run and then tears a line in the middle of its ledger, which is §6
// case 3: never produced by a healthy writer, fatal to every view, and reported distinctly from the
// torn *last* line of case 2. It is the uid-independent way to make one run unreadable.
func corruptRun(t *testing.T, root string, at time.Time) string {
	t.Helper()
	id := endedRun(t, root, at)
	path := filepath.Join(root, id, ledger.EventsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("fixture run has %d lines, need a middle one to tear", len(lines))
	}
	torn := append([]string{lines[0], "{not a record"}, lines[1:]...)
	if err := os.WriteFile(path, []byte(strings.Join(torn, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestCorruptLedgerIsLedgerCorrupt: §7 documents a torn middle line as [ledger-corrupt], and every command that reads
// a run reported it as [io], a disk error.
func TestCorruptLedgerIsLedgerCorrupt(t *testing.T) {
	root := gcRoot(t)
	bad := corruptRun(t, root, time.Now())
	for _, args := range [][]string{{"events", bad}, {"events", bad, "--last"}, {"drift", bad}, {"measure", bad}, {"status", bad}, {"status", "--all"}} {
		code, _, errs := run(t, args...)
		if code != identity.ExitError || !strings.Contains(errs, "[ledger-corrupt]") || strings.Contains(errs, "[io]") {
			t.Errorf("%v: exit %d, stderr %q; want 125 [ledger-corrupt]", args, code, errs)
		}
	}
}

// TestStatusReportsRunsItCouldNotRead pins E26 against the fail-open this command used to have: the
// per-run errors DeriveAll collects were dropped into tego.log, so a ledger root whose every run was
// unreadable printed "no runs" on stdout and exited 0 — the same answer a machine that has never run
// anything gives. An unreadable run is reported as itself (§7: a ledger check/* could not read).
// (limits-check-doctor-cli.md E8: one run's error never aborts the listing, and is not swallowed either.)
func TestStatusReportsRunsItCouldNotRead(t *testing.T) {
	root := gcRoot(t)
	bad := corruptRun(t, root, time.Now())

	code, out, errs := run(t, "status", "--all")
	if code != identity.ExitError {
		t.Fatalf("exit %d, want %d (stdout %q stderr %q)", code, identity.ExitError, out, errs)
	}
	if strings.Contains(out, "no runs") {
		t.Errorf("an unreadable run was reported as an empty ledger root: %q", out)
	}
	if !strings.Contains(errs, bad) {
		t.Errorf("stderr %q does not name the run it could not read (%s)", errs, bad)
	}
}

// TestStatusAllStillListsTheRunsItCouldRead is §6 case 8's other half: one corrupt run never hides
// the rest. The readable run is in the table, the corrupt one is on stderr, and the exit code says
// the table is incomplete rather than claiming a clean or a complete finding.
func TestStatusAllStillListsTheRunsItCouldRead(t *testing.T) {
	root := gcRoot(t)
	good := endedRun(t, root, time.Now().Add(-time.Hour))
	bad := corruptRun(t, root, time.Now())

	code, out, errs := run(t, "status", "--all")
	if code != identity.ExitError {
		t.Fatalf("exit %d, want %d (stdout %q stderr %q)", code, identity.ExitError, out, errs)
	}
	if !strings.Contains(out, good) {
		t.Errorf("the readable run is missing from the table:\n%s", out)
	}
	if !strings.Contains(errs, bad) {
		t.Errorf("stderr %q does not name the unreadable run (%s)", errs, bad)
	}
}

// TestStatusEACCESIsNotAnEmptyReport is E26 in the shape an operator meets it: runs recorded under
// sudo leave root-owned 0700 directories in a user-owned ledger root, and reading them as the user
// fails with EACCES. That must read as "permission denied", never as "no runs".
// (limits-check-doctor-cli.md E26.)
func TestStatusEACCESIsNotAnEmptyReport(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory; EACCES cannot be provoked")
	}
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	dir := filepath.Join(root, id)
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	code, out, errs := run(t, "status", "--all")
	if code != identity.ExitError {
		t.Fatalf("exit %d, want %d (stdout %q stderr %q)", code, identity.ExitError, out, errs)
	}
	if strings.Contains(out, "no runs") {
		t.Errorf("an unreadable run was reported as an empty ledger root: %q", out)
	}
	if !strings.Contains(errs, "permission denied") {
		t.Errorf("stderr %q does not report the permission failure", errs)
	}
}

// TestStatusBareReadsOnlyTheNewestRun pins the cost of the default invocation: it prints one row, so
// it reads one run. The older run here is unreadable, which a full DeriveAll pass would report (and
// would have to, per E26) — bare `tego status` never opens it, so the newest run's row is clean.
func TestStatusBareReadsOnlyTheNewestRun(t *testing.T) {
	root := gcRoot(t)
	old := corruptRun(t, root, time.Now().Add(-time.Hour))
	newest := endedRun(t, root, time.Now())

	code, out, errs := run(t, "status")
	if code != identity.ExitOK {
		t.Fatalf("exit %d, want %d (stdout %q stderr %q)", code, identity.ExitOK, out, errs)
	}
	if !strings.Contains(out, newest) {
		t.Errorf("the newest run is missing from the row:\n%s", out)
	}
	if strings.Contains(out, old) || strings.Contains(errs, old) {
		t.Errorf("an older run was read for a one-row report (stdout %q stderr %q)", out, errs)
	}
}

// bornRun is a run directory at the moment ledger.Open has made it and taken its lock but has not
// yet created events.jsonl. A reader can land in that window (it is the newest run, which is exactly
// the one bare `tego status` reads), and a launcher that died inside it leaves one behind for good.
func bornRun(t *testing.T, root string, at time.Time) string {
	t.Helper()
	var host [32]byte
	id, err := identity.NewRunID(host, at, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, string(id))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ledger.LockFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return string(id)
}

// TestStatusSkipsARunThatHasRecordedNothing separates "I could not read this run" from "this run has
// recorded nothing yet". Only the first makes a report incomplete, so a run directory younger than
// its own ledger — or left behind by a launcher that died in that window — must not turn every
// `tego status` on the machine into an error.
func TestStatusSkipsARunThatHasRecordedNothing(t *testing.T) {
	root := gcRoot(t)
	done := endedRun(t, root, time.Now().Add(-time.Hour))
	bornRun(t, root, time.Now())

	t.Run("bare status steps to the newest run it can report", func(t *testing.T) {
		code, out, errs := run(t, "status")
		if code != identity.ExitOK {
			t.Fatalf("exit %d, want %d (stdout %q stderr %q)", code, identity.ExitOK, out, errs)
		}
		if !strings.Contains(out, done) {
			t.Errorf("no row for the run that did record something:\n%s", out)
		}
		if errs != "" {
			t.Errorf("stderr %q: a run that recorded nothing is not a fault", errs)
		}
	})
	t.Run("--all reports it without failing", func(t *testing.T) {
		code, out, errs := run(t, "status", "--all")
		if code != identity.ExitOK {
			t.Fatalf("exit %d, want %d (stdout %q stderr %q)", code, identity.ExitOK, out, errs)
		}
		if !strings.Contains(out, done) {
			t.Errorf("no row for the run that did record something:\n%s", out)
		}
		if errs != "" {
			t.Errorf("stderr %q: a run that recorded nothing is not a fault", errs)
		}
	})
}

// TestStatusBareDoesNotHideAnUnreadableNewestRun is E26 on the default invocation: when the run it
// would report cannot be read, the answer is that failure. Answering about the run before it would
// present an older run as the current one — the mistake the operator cannot see.
func TestStatusBareDoesNotHideAnUnreadableNewestRun(t *testing.T) {
	root := gcRoot(t)
	older := endedRun(t, root, time.Now().Add(-time.Hour))
	newest := corruptRun(t, root, time.Now())

	code, out, errs := run(t, "status")
	if code != identity.ExitError {
		t.Fatalf("exit %d, want %d (stdout %q stderr %q)", code, identity.ExitError, out, errs)
	}
	if strings.Contains(out, older) {
		t.Errorf("an older run was presented instead of the unreadable newest one:\n%s", out)
	}
	if !strings.Contains(errs, newest) {
		t.Errorf("stderr %q does not name the run it could not read (%s)", errs, newest)
	}
}

// TestStatusAllGapLines pins R34 for the listing: `status --all` prints `gaps <run>: <line>` for each run
// that recorded a gap and nothing for a run that recorded none, under the table.
// TestStatusAllGapLines is limits-check-doctor-cli.md R34's `status --all` half: a gappy run prints its own gap line and a quiet one prints none.
func TestStatusAllGapLines(t *testing.T) {
	root := gcRoot(t)
	quiet := endedRun(t, root, time.Now().Add(-time.Hour))
	var host [32]byte
	id, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gappy := string(id)
	w, err := ledger.Open(filepath.Join(root, gappy), record.RunRef{ID: gappy, Agent: "tester"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{
		Command: []string{"true"}, Cwd: "/", Tier: "landlock", TegoVersion: "test", Kernel: "test",
		ContractHash: strings.Repeat("a", 64), LauncherPID: 1, LauncherStartNS: 1,
	}); err != nil {
		t.Fatal(err)
	}
	for _, g := range []record.GapPayload{{What: "capture", Why: "no-openssl", Binary: "/usr/bin/gh"}, {What: "record", Why: "channel-full", Count: 3}} {
		e := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor, PID: 1, TID: 1}
		if err := e.SetPayload(g); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}

	code, out, errs := run(t, "status", "--all")
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	want := "gaps " + gappy + ": capture/no-openssl x1 (in /usr/bin/gh); record/channel-full x1 (3 events lost)"
	if !strings.Contains(out, want+"\n") {
		t.Errorf("the listing lacks %q:\n%s", want, out)
	}
	if strings.Contains(out, "gaps "+quiet) || strings.Contains(out, "gaps: ") {
		t.Errorf("a run with no gap got a gap line, or the listing printed the single-run form:\n%s", out)
	}
}

// TestStatusAllObservesItsContext: --all reads every retained ledger, so a cancelled context must end
// the read (R29), not be looked at once before it starts.
func TestStatusAllObservesItsContext(t *testing.T) {
	root := gcRoot(t)
	endedRun(t, root, time.Now().Add(-time.Hour))
	endedRun(t, root, time.Now().Add(-2*time.Hour))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, all := range []bool{true, false} {
		if _, _, err := collectStatus(ctx, root, "", all, time.Now()); !errors.Is(err, context.Canceled) {
			t.Errorf("all=%v: err %v, want context.Canceled", all, err)
		}
	}
}

// TestStatusNamedRunWithoutLedgerIsNeverStarted: `status <id>` on a run directory with no events.jsonl is
// §6 case 8's never-started run (exit 0), as it is under --all, not a raw open error at 125.
func TestStatusNamedRunWithoutLedgerIsNeverStarted(t *testing.T) {
	root := gcRoot(t)
	id := bornRun(t, root, time.Now())
	code, out, errs := run(t, "status", id)
	if code != identity.ExitOK {
		t.Fatalf("exit %d, want %d (stdout %q stderr %q)", code, identity.ExitOK, out, errs)
	}
	if !strings.Contains(out, "never started") {
		t.Errorf("stdout %q does not say never started", out)
	}
}
