// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// fixtureRun writes the frozen v1 fixture ledger into a temp run directory and returns its path.
func fixtureRun(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "spec", "record", "v1", "fixtures", "run-fixture.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestEventsRendersAFixtureRun(t *testing.T) {
	dir := fixtureRun(t)
	code, out, errs := run(t, "events", dir)
	if code != identity.ExitOK {
		t.Fatalf("exit %d (stderr %q)", code, errs)
	}
	if !strings.HasPrefix(out, "SEQ") {
		t.Errorf("no table header: %q", firstLine(out))
	}
	if !strings.Contains(out, "run_start") || !strings.Contains(out, "run_end") {
		t.Error("the table is missing the run's first or last event")
	}
}

// TestEventsJSONIsTheStoredBytes is limits-check-doctor-cli.md I8 and R31: events --json prints the stored line, never a re-serialization.
func TestEventsJSONIsTheStoredBytes(t *testing.T) {
	dir := fixtureRun(t)
	code, out, errs := run(t, "events", dir, "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d (stderr %q)", code, errs)
	}
	src, err := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimRight(string(src), "\n") != strings.TrimRight(out, "\n") {
		t.Error("--json is not byte-identical to the stored ledger")
	}
}

// TestEventsFilterThatMatchesNothingIsNotAFinding replaces TestEventsFilterThatMatchesNothingIsAFinding,
// which asserted identity.ExitFinding for these same invocations. R29 gives events exit 0 alone and
// RUN-IDENTITY.md's exit-1 set names only drift/status/doctor/compile: an empty result is a true
// answer about the run, not a finding about its conformance. The second case is the one that bit —
// a CI gate collecting refusals with `set -e` failed on every run that refused nothing.
func TestEventsFilterThatMatchesNothingIsNotAFinding(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())

	tests := []struct {
		name string
		dir  string
		args []string
	}{
		{"a kind the run never recorded", fixtureRun(t), []string{"--kind", "ask"}},
		{"--last on a run that went right", filepath.Join(root, id), []string{"--last"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errs := run(t, append([]string{"events", tc.dir}, tc.args...)...)
			if code != identity.ExitOK {
				t.Fatalf("exit %d, want %d (stderr %q)", code, identity.ExitOK, errs)
			}
			if !strings.Contains(errs, "no events matched") {
				t.Errorf("stderr %q does not say the filter matched nothing", errs)
			}
		})
	}
}

// TestEventsLastShowsWhatWentWrong pins the flag's own promise — "only the last refusal, gap or
// limit". It was implemented as a kind filter with no ordering, so the fixture's four failure-kind
// events (a refusal, two gaps and the limit that ended the run) all printed, oldest first, and the
// answer the flag names was the last row of a scroll. §3 and spec/reason/REASON-CHANNEL.md §2 both
// say one.
func TestEventsLastShowsWhatWentWrong(t *testing.T) {
	dir := fixtureRun(t)
	code, out, errs := run(t, "events", dir, "--last")
	if code != identity.ExitOK {
		t.Fatalf("exit %d (stderr %q)", code, errs)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("--last printed %d lines, want a header and one row:\n%s", len(lines), out)
	}
	// seq 96 is the fixture's newest failure-kind event: the limit that stopped the run.
	if !strings.HasPrefix(lines[1], "96 ") || !strings.Contains(lines[1], "limit") {
		t.Errorf("--last row %q is not the run's last failure event", lines[1])
	}
}

// TestEventsLastNarrowsAnExplicitKind is the other half of --last: it is an ordering, so with a
// --kind of its own it answers "the last of those". Appending its three kinds made it widen the
// query instead — `--last --kind fs` used to print every fs event plus every refusal, gap and limit.
func TestEventsLastNarrowsAnExplicitKind(t *testing.T) {
	dir := fixtureRun(t)
	code, out, errs := run(t, "events", dir, "--last", "--kind", "fs")
	if code != identity.ExitOK {
		t.Fatalf("exit %d (stderr %q)", code, errs)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("--last --kind fs printed %d lines, want a header and one row:\n%s", len(lines), out)
	}
	// seq 95 is the fixture's newest fs event; 96 (limit) and 29 (refused) are not fs events.
	if !strings.HasPrefix(lines[1], "95 ") || !strings.Contains(lines[1], "fs") {
		t.Errorf("row %q is not the run's last fs event", lines[1])
	}
}

// TestEventsLastJSONIsTheStoredLine holds I8 across the narrowing: --last still prints the ledger's
// own bytes, the ones the chain hashed, never a rendering of last-refusal.json or a re-encode.
func TestEventsLastJSONIsTheStoredLine(t *testing.T) {
	dir := fixtureRun(t)
	code, out, errs := run(t, "events", dir, "--last", "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d (stderr %q)", code, errs)
	}
	src, err := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	want := ""
	for _, line := range strings.Split(strings.TrimRight(string(src), "\n"), "\n") {
		if strings.Contains(line, `"kind":"limit"`) {
			want = line
		}
	}
	if want == "" {
		t.Fatal("the fixture has no limit event to be the last one")
	}
	if strings.TrimRight(out, "\n") != want {
		t.Errorf("--last --json printed\n%s\nwant the stored line\n%s", out, want)
	}
}

func TestEventsLimitStopsEarly(t *testing.T) {
	dir := fixtureRun(t)
	code, out, _ := run(t, "events", dir, "--json", "--limit", "2")
	if code != identity.ExitOK {
		t.Fatalf("exit %d", code)
	}
	if got := len(strings.Split(strings.TrimRight(out, "\n"), "\n")); got != 2 {
		t.Errorf("%d lines, want 2", got)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// TestEventsLastVerdictRefusedFindsTheRefusal: a refused line carries no verdict field (the schema forbids
// one), so --verdict tested nothing on it and `--last --verdict refused` was always empty.
func TestEventsLastVerdictRefusedFindsTheRefusal(t *testing.T) {
	dir := fixtureRun(t)
	code, out, errs := run(t, "events", dir, "--last", "--verdict", "refused")
	if code != identity.ExitOK {
		t.Fatalf("exit %d (stderr %q)", code, errs)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[1], "29 ") {
		t.Errorf("want the run's refusal, seq 29:\n%s", out)
	}
}
