// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// spliceVersionLineAt1 rewrites the run's ledger (run_start, run_end) as run_start, a line of record version v
// (the raw JSON token), run_end, with the chain whole: the spliced line's id is the digest of its bytes and
// run_end is re-sealed after it.
func spliceVersionLineAt1(t *testing.T, root, id, v string) {
	t.Helper()
	path := filepath.Join(root, id, ledger.EventsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("fixture has %d lines, want run_start and run_end", len(lines))
	}
	start, err := record.Decode(lines[0])
	if err != nil {
		t.Fatal(err)
	}
	l := fmt.Sprintf(`{"v":%s,"seq":1,"id":"%s","prev":"%s","run":"%s","kind":"hologram"}`, v, record.ZeroID, start.ID, id)
	sum := sha256.Sum256([]byte(l))
	newer := strings.Replace(l, record.ZeroID, hex.EncodeToString(sum[:]), 1)
	end, err := record.Decode(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	end.Seq, end.Prev = 2, hex.EncodeToString(sum[:])
	endLine, err := end.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	out := string(lines[0]) + "\n" + newer + "\n" + strings.TrimSuffix(string(endLine), "\n") + "\n"
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestViewsSkipANewerRecordVersionWithOneWarning pins limits-check-doctor-cli.md §6 case 20 end to end: events
// (table and --json), status, drift and measure read past a line of a newer record version, each with one
// warning naming the count, and exit as they would without it.
func TestViewsSkipANewerRecordVersionWithOneWarning(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	spliceVersionLineAt1(t, root, id, "2")
	for _, args := range [][]string{
		{"events", id}, {"events", id, "--json"}, {"status", id}, {"drift", id}, {"measure", id}, {"learn", id},
		{"events", id, "--follow"}, {"events", id, "--follow", "--json"},
	} {
		t.Run(strings.Join(append([]string{args[0]}, args[2:]...), " "), func(t *testing.T) {
			code, out, errs := run(t, args...)
			if code == identity.ExitError || code == identity.ExitUsage {
				t.Fatalf("exit %d, want the view's ordinary answer (stdout %q stderr %q)", code, out, errs)
			}
			if slices.Contains(args, "--follow") && code != identity.ExitOK {
				t.Fatalf("--follow over an ended run: exit %d, want 0 (stderr %q)", code, errs)
			}
			if n := strings.Count(errs, "skipped 1 line(s) of a record version newer than 1"); n != 1 {
				t.Fatalf("stderr holds %d skip warnings, want exactly one:\n%s", n, errs)
			}
			if strings.Contains(out, "hologram") {
				t.Fatalf("the newer line reached the output:\n%s", out)
			}
			if args[len(args)-1] == "--json" && strings.Count(out, "\n") != 2 {
				t.Fatalf("events --json wrote %d lines, want the two v1 lines:\n%s", strings.Count(out, "\n"), out)
			}
		})
	}
}

// TestViewsRefuseAVersionZeroLine: v 0 is not a newer version, so the views still report the ledger corrupt.
func TestViewsRefuseAVersionZeroLine(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	spliceVersionLineAt1(t, root, id, "0")
	code, _, errs := run(t, "events", id)
	if code != identity.ExitError || !strings.Contains(errs, "corrupt") {
		t.Fatalf("events over a v0 line: exit %d stderr %q, want 125 and a corrupt-ledger message", code, errs)
	}
}
