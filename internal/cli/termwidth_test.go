// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// atWidth makes tego's output a terminal width columns wide for the test.
func atWidth(t *testing.T, width int) {
	t.Helper()
	was := terminalWidthOf
	terminalWidthOf = func(io.Writer) int { return width }
	t.Cleanup(func() { terminalWidthOf = was })
}

// tooWide lists the lines of s wider than width that hold more than one word after their indentation: a line that is
// one unbreakable word (a path) may be wider.
func tooWide(s string, width int) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if utf8.RuneCountInString(l) > width && len(strings.Fields(l)) > 1 {
			out = append(out, l)
		}
	}
	return out
}

// TestWrapLines: a long line is broken at words, at a clause where it can be, indented under its own indentation; every
// word survives in order, and a line that fits or a word that does not is left alone.
func TestWrapLines(t *testing.T) {
	for _, c := range []struct {
		name, in string
		width    int
		want     string
	}{
		{"fits", "  a short line", 80, "  a short line"},
		{"at a clause", "tego run: r-1 ended (exited with code 0) · tier landlock · refused 3 (not in contract 3) · asked 0 · chain verified",
			60, "tego run: r-1 ended (exited with code 0) · tier landlock\n  · refused 3 (not in contract 3) · asked 0 · chain verified"},
		{"at a word, under its indent", "  Not known: this run did not record every read, so a sensitive file may have been read.", 50,
			"  Not known: this run did not record every read,\n    so a sensitive file may have been read."},
		{"a path stays whole", "  Wrote /very/long/" + strings.Repeat("deep/", 12) + "file.txt now", 40,
			"  Wrote\n    /very/long/" + strings.Repeat("deep/", 12) + "file.txt\n    now"},
		{"line breaks kept", "a\n\nb", 10, "a\n\nb"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := wrapLines(c.in, c.width); got != c.want {
				t.Errorf("wrapLines(%q, %d)\n got %q\nwant %q", c.in, c.width, got, c.want)
			}
		})
	}
}

// TestReceiptTextFitsTheTerminal: at a terminal 80 and 60 columns wide, `tego receipt` breaks its long sentences (the
// text receipt had lines up to 141 columns), loses no word and no line, and to anything that is not a terminal prints
// the bytes it always did.
func TestReceiptTextFitsTheTerminal(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "spec", "record", "v1", "fixtures", "*.jsonl"))
	if err != nil || len(files) < 5 {
		t.Fatalf("fixtures: %d, %v", len(files), err)
	}
	sawLong := false
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), data, 0o600); err != nil {
			t.Fatal(err)
		}
		code, plain, _ := run(t, "receipt", dir)
		if code != identity.ExitOK {
			continue // a fixture that is not a whole run says so on stderr; the others are the receipts
		}
		for _, width := range []int{80, 60} {
			t.Run(fmt.Sprintf("%s at %d", filepath.Base(f), width), func(t *testing.T) {
				atWidth(t, width)
				code, out, errs := run(t, "receipt", dir)
				if code != identity.ExitOK {
					t.Fatalf("exit %d: %s", code, errs)
				}
				if long := tooWide(out, width); len(long) > 0 {
					t.Errorf("%d lines wider than %d columns, first: %q", len(long), width, long[0])
				}
				if strings.Join(strings.Fields(out), " ") != strings.Join(strings.Fields(plain), " ") {
					t.Errorf("the wrapped receipt lost or changed words:\n%s", out)
				}
			})
		}
		if len(tooWide(plain, 60)) > 0 {
			sawLong = true // a pipe still gets the long line as it was
		}
	}
	if !sawLong {
		t.Error("no fixture has a receipt line wider than 60 columns: the test shows nothing")
	}
}

// TestEndSummaryFitsTheTerminal: tego run's summary at a terminal 80 and 60 columns wide breaks at its clauses, keeps its
// first line's start ("tego run: <run> ended", which a script reads the run id from) and every word, and its hint stays
// its last line.
func TestEndSummaryFitsTheTerminal(t *testing.T) {
	for _, width := range []int{80, 60} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			root, _ := summaryHarness(t)
			atWidth(t, width)
			var stderr bytes.Buffer
			var id string
			startRun = func(_ context.Context, _ *agent.RuleTable, _ []string, d tegoruntime.Deps) (tegoruntime.Result, error) {
				id = summaryLedger(t, root, d.AnchorPath)
				return tegoruntime.Result{RunID: id, Reason: record.RunEndExit}, nil
			}
			argv := []string{"tego", "run", filepath.Join("testdata", "minimal.yaml"), "--offline", "--", "true"}
			if code := mainWith(t.Context(), argv, io.Discard, &stderr, []Command{cmdRun()}); code != identity.ExitOK {
				t.Fatalf("exit %d:\n%s", code, stderr.String())
			}
			out := stderr.String()
			at := strings.Index(out, "tego run: "+id+" ended")
			if at < 0 {
				t.Fatalf("the summary no longer starts as scripts read it:\n%s", out)
			}
			summary := out[at:]
			if long := tooWide(summary, width); len(long) > 0 {
				t.Errorf("%d summary lines wider than %d columns, first: %q\n%s", len(long), width, long[0], summary)
			}
			for _, want := range []string{"tier landlock", "refused 2 (", "asked 1 (0 approved, 1 denied)", "wrote 1 file", "chain verified"} {
				if !strings.Contains(strings.Join(strings.Fields(summary), " "), want) {
					t.Errorf("the summary lost %q:\n%s", want, summary)
				}
			}
		})
	}
}
