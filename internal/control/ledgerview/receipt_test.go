// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/measure"
	"github.com/attention-span-ai/tego/internal/ledger"
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
