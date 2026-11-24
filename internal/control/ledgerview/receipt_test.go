// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/measure"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestReceiptAgreesWithDashboardAndMeasure is the receipt's cross-view agreement: on every
// record v1 fixture, the receipt's refusals total equals the dashboard's run refusal count (the Refused figure on
// the run page and the runs table) and `tego measure`'s refused column, and the receipt's tokens equal measure's.
// A fixture where they part is a demo where the Receipt tab and the header next to it show different numbers.
func TestReceiptAgreesWithDashboardAndMeasure(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "*.jsonl"))
	if err != nil || len(files) < 5 {
		t.Fatalf("fixtures: %d, %v", len(files), err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var first struct {
				Run string `json:"run"`
			}
			if err := json.Unmarshal(data[:bytes.IndexByte(data, '\n')], &first); err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			dir := filepath.Join(root, first.Run)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), data, 0o600); err != nil {
				t.Fatal(err)
			}
			run, err := LoadRun(root, first.Run)
			if err != nil {
				t.Fatal(err)
			}
			rc, err := LoadReceipt(t.Context(), root, first.Run)
			if err != nil {
				t.Fatal(err)
			}
			r, err := ledger.OpenReader(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			r.SkipNewerVersions()
			m, err := measure.ComputeAt(t.Context(), r, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			if rc.Refusals.Total != run.Refusals || rc.Refusals.Total != m.Refused {
				t.Errorf("refusals: receipt %d, dashboard %d, measure %d", rc.Refusals.Total, run.Refusals, m.Refused)
			}
			// The Refusals tab lists as many refusals as the count beside it (folded rows carry their Count).
			listed := 0
			for _, row := range RunRefusals(run) {
				listed += max(row.Count, 1)
			}
			if listed != run.Refusals {
				t.Errorf("the Refusals tab lists %d refusals, its count says %d", listed, run.Refusals)
			}
			tk := rc.Tokens
			if tk.In != m.TokensIn || tk.Out != m.TokensOut || tk.CacheRead != m.CacheRead || tk.CacheWrite != m.CacheWrite ||
				tk.Metered != m.Responses || tk.Unpriced != m.Unpriced {
				t.Errorf("tokens: receipt %+v, measure in %d out %d cache %d/%d responses %d unpriced %d", tk,
					m.TokensIn, m.TokensOut, m.CacheRead, m.CacheWrite, m.Responses, m.Unpriced)
			}
		})
	}
}

func TestReceiptSensitiveContextHasItsOwnCacheKey(t *testing.T) {
	root := t.TempDir()
	const run = "r-aaaaaaaa-0000000000092-rcsens"
	t0 := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	writeRun(t, root, run,
		line(run, "demo", 0, t0, "run_start", `"tier":"landlock","command":["sh"],"cwd":"/p"`),
		line(run, "demo", 1, t0.Add(time.Second), "fs", `"rule":"unmatched","verdict":"allow","op":"open","flags":0,"path":"/p/workpapers/plan.data"`),
		line(run, "demo", 2, t0.Add(2*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	plain, err := LoadReceipt(t.Context(), root, run)
	if err != nil {
		t.Fatal(err)
	}
	with, err := LoadReceiptWithSensitive(t.Context(), root, run, Sensitive{Entries: []string{"./workpapers/"}, Cwd: "/p"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadReceiptWithSensitive(t.Context(), root, run, Sensitive{Entries: []string{"./workpapers/"}, Cwd: "/p"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := LoadReceiptWithSensitive(t.Context(), root, run, Sensitive{Entries: []string{"./workpapers/"}, Cwd: "/elsewhere"})
	if err != nil {
		t.Fatal(err)
	}
	different, err := LoadReceiptWithSensitive(t.Context(), root, run, Sensitive{Entries: []string{"./other/"}, Cwd: "/p"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plain.SensitiveReads) != 0 || len(other.SensitiveReads) != 0 || len(different.SensitiveReads) != 0 || len(with.SensitiveReads) != 1 || with != again || with == plain {
		t.Fatalf("plain=%+v with=%+v other=%+v cached=%v", plain.SensitiveReads, with.SensitiveReads, other.SensitiveReads, with == again)
	}
}

// Supervisor-held opens can carry syscall_ret without errno (held_open.go).
func TestFailedOpenReturnIsNotASensitiveRead(t *testing.T) {
	e := record.Event{Kind: record.KindFS, Verdict: record.VerdictAllow, Payload: json.RawMessage(`{"op":"open","path":"/p/workpapers/plan.data","syscall_ret":-13}`)}
	ev := fromRecord(&e)
	if !ev.readNothing {
		t.Fatal("negative kernel return treated as a read")
	}
	r := &Run{Events: []Event{ev}, Cwd: "/p"}
	sig := Signal(r, Sensitive{Entries: []string{"./workpapers/"}, Cwd: "/p"})
	if len(sig.Secrets) != 1 || sig.Secrets[0].Unread != 1 {
		t.Fatalf("failed-open signal %+v", sig.Secrets)
	}
}
