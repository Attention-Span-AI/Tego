// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/drift"
	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The one-line verdict is how a person learns why a run ended without reading an exit code: every reason
// that is not a plain exit must say something, and the reasons other messages already covered must not
// say it twice.
func TestWriteRunSummaryByReason(t *testing.T) {
	cases := []struct {
		reason string
		want   string // "" means silent
	}{
		{record.RunEndExit, ""},
		{"", ""},
		{record.RunEndExecFailed, ""},
		{record.RunEndOOM, "out of memory"},
		{record.RunEndPids, "process limit"},
		{record.RunEndStopped, "run stopped"},
		{record.RunEndLimit, "a limit was reached"},
		{record.RunEndSignal, "signalled"},
		{record.RunEndError, "run ended: error"},
		{"something-new", "run ended: something-new"},
	}
	for _, c := range cases {
		var b bytes.Buffer
		writeRunSummary(&b, tegoruntime.Result{RunID: "r-1", Reason: c.reason})
		out := b.String()
		if c.want == "" {
			if out != "" {
				t.Errorf("reason %q printed %q, want nothing", c.reason, out)
			}
			continue
		}
		if !strings.Contains(out, c.want) || !strings.Contains(out, "r-1") || strings.Count(out, "\n") != 1 {
			t.Errorf("reason %q printed %q, want one line naming %q and the run", c.reason, out, c.want)
		}
	}
}

func TestDriftErrorExitCodes(t *testing.T) {
	var b bytes.Buffer
	if got := driftError(&b, fmt.Errorf("agent a and b: %w", drift.ErrMixedAgent)); got != identity.ExitUsage {
		t.Errorf("mixed agents exit %d, want the usage code %d", got, identity.ExitUsage)
	}
	if !strings.Contains(b.String(), "refusing to aggregate") {
		t.Errorf("message = %q", b.String())
	}
	b.Reset()
	if got := driftError(&b, fmt.Errorf("read: %w", ledger.ErrCorruptLedger)); got != identity.ExitError {
		t.Errorf("corrupt ledger exit %d, want %d", got, identity.ExitError)
	}
	if !strings.Contains(b.String(), codeUnverified) {
		t.Errorf("a corrupt ledger must carry its own code, got %q", b.String())
	}
	b.Reset()
	if got := driftError(&b, errors.New("disk on fire")); got != identity.ExitError || !strings.Contains(b.String(), codeIO) {
		t.Errorf("other failure: exit %d, %q", got, b.String())
	}
}

func TestFirstDiagnosticPrefersTheFirstError(t *testing.T) {
	ds := []agent.Diagnostic{
		{Severity: agent.SeverityWarning, Code: "W1", Message: "just a warning"},
		{Severity: agent.SeverityError, Code: "E1", Message: "first error"},
		{Severity: agent.SeverityError, Code: "E2", Message: "second error"},
	}
	if msg, code := firstDiagnostic(ds, errors.New("fallback")); msg != "first error" || code != "E1" {
		t.Errorf("got %q %q", msg, code)
	}
	if msg, code := firstDiagnostic(ds[:1], errors.New("fallback")); msg != "fallback" || code != agent.CodeSchema {
		t.Errorf("only warnings: got %q %q, want the error's own text under the schema code", msg, code)
	}
}

func TestNoRunRecordAndSkippedRunKeepTheirCause(t *testing.T) {
	n := noRunRecord{dir: "/x/r-1", err: os.ErrNotExist}
	if !errors.Is(n, os.ErrNotExist) || !strings.Contains(n.Error(), "/x/r-1") {
		t.Errorf("noRunRecord: %v", n)
	}
	s := skippedRun{run: "r-2", err: ledger.ErrCorruptLedger}
	if !errors.Is(s, ledger.ErrCorruptLedger) || !strings.HasPrefix(s.Error(), "r-2: ") {
		t.Errorf("skippedRun: %v", s)
	}
}

func TestFlagTakesValue(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	fs.String("tier", "", "")
	fs.Bool("json", false, "")
	cases := []struct {
		name     string
		consumed []string
		i        int
		want     bool
	}{
		{"first argument", []string{"--"}, 0, false},
		{"after a value flag", []string{"--tier", "--"}, 1, true},
		{"single dash spelling", []string{"-tier", "--"}, 1, true},
		{"after a bool flag", []string{"--json", "--"}, 1, false},
		{"after an assigned flag", []string{"--tier=x", "--"}, 1, false},
		{"after an unknown flag", []string{"--nope", "--"}, 1, false},
		{"after a plain word", []string{"word", "--"}, 1, false},
		{"after a bare dash", []string{"-", "--"}, 1, false},
	}
	for _, c := range cases {
		if got := flagTakesValue(fs, c.consumed, c.i); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestResolvedNoteAndDurationText(t *testing.T) {
	if got := resolvedNote(agent.ResolvedPaths{}); got != "" {
		t.Errorf("nothing resolved elsewhere: %q", got)
	}
	got := resolvedNote(agent.ResolvedPaths{Path: "/a", Dest: "/b", Script: "/c"})
	for _, want := range []string{"path resolved to /a", "dest resolved to /b", "script resolved to /c"} {
		if !strings.Contains(got, want) {
			t.Errorf("note %q lacks %q", got, want)
		}
	}
	if durationText(0) != "0s" {
		t.Error("a zero duration budget is a real budget and must render as one")
	}
	if durationText(90*time.Minute) != "1h30m0s" {
		t.Errorf("got %q", durationText(90*time.Minute))
	}
}

func TestRunIDsNewestFirst(t *testing.T) {
	root := t.TempDir()
	// Two hosts: the time component orders them, never the host prefix.
	ids := []string{"r-aaaaaaaa-000000000000a-aaaaaa", "r-00000000-000000000000c-cccccc", "r-ffffffff-000000000000b-bbbbbb"}
	for _, id := range ids {
		if !ledger.IsRunID(id) {
			t.Fatalf("test id %q is not shaped like a run id", id)
		}
		if err := os.Mkdir(filepath.Join(root, id), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	os.Mkdir(filepath.Join(root, "not-a-run"), 0o700)
	os.WriteFile(filepath.Join(root, "r-00000000-000000000000d-dddddd"), nil, 0o600) // a file, not a run directory
	got, err := runIDsNewestFirst(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{ids[1], ids[2], ids[0]}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
	if got, err := runIDsNewestFirst(filepath.Join(root, "absent")); err != nil || got != nil {
		t.Errorf("an absent root is a machine that never ran anything: %v, %v", got, err)
	}
	f := filepath.Join(root, "afile")
	os.WriteFile(f, nil, 0o600)
	if _, err := runIDsNewestFirst(f); err == nil {
		t.Error("a root that is not a directory is an error")
	}
}
