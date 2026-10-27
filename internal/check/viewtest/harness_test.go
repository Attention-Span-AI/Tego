// SPDX-License-Identifier: Apache-2.0

package viewtest

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/drift"
	"github.com/attention-span-ai/tego/internal/check/events"
	"github.com/attention-span-ai/tego/internal/check/learn"
	"github.com/attention-span-ai/tego/internal/check/measure"
	"github.com/attention-span-ai/tego/internal/check/status"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestViewsReadHarnessFixture: every view reads spec/record/v1/fixtures/harness.jsonl, a run at record_minor 14 with
// run_start.harness (agent-contract.md R27, ADR 0062). The hook-state write its fs.harness-state grant allowed is a
// runtime grant, never an undeclared entry to drift and learn; the refused write to the settings file is a refusal.
func TestViewsReadHarnessFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "harness.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), runID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := status.Derive(reader(t, dir), true, time.Now(), 0); err != nil {
		t.Fatalf("status: %v", err)
	}
	m, err := measure.ComputeAt(t.Context(), reader(t, dir), nil, 1<<62)
	if err != nil || m.Refused != 1 {
		t.Fatalf("measure: refused %d, %v", m.Refused, err)
	}
	rep, err := drift.ComputeCtx(t.Context(), reader(t, dir), &agent.RuleTable{})
	if err != nil {
		t.Fatalf("drift: %v", err)
	}
	for _, s := range rep.Sections() {
		for _, c := range s.Counts {
			if strings.HasPrefix(c.Rule, "fs.harness-state[") && !agent.IsRuntimeRule(c.Rule) {
				t.Errorf("drift counts the hook-state grant %s as a contract rule", c.Rule)
			}
		}
	}
	_ = gapsLine(rep)
	l := learn.New(learn.Options{})
	for e, err := range reader(t, dir).Iter() {
		if err == nil {
			err = l.Add(e)
		}
		if err != nil {
			t.Fatalf("learn: %v", err)
		}
	}
	p, err := l.Proposal()
	if err != nil {
		t.Fatalf("learn: %v", err)
	}
	if c := p.Contract(); strings.Contains(c, "/hook-state") || !strings.Contains(c, "1 file actions in the hook-state directory the run grants its harness") ||
		strings.Contains(c, "CODEX_HOME") {
		t.Errorf("learn does not count the hook-state write as the harness's runtime grant:\n%s", c)
	}
	var b bytes.Buffer
	if _, err := eventsJSON(t, &b, dir, events.Filter{}); err != nil || !strings.Contains(b.String(), `"harness":{"name":"claude-code","provisioned":true`) {
		t.Fatalf("events --json: %v\n%s", err, b.String())
	}
	b.Reset()
	if _, err := eventsTable(t, &b, dir, events.Filter{}); err != nil || !strings.Contains(b.String(), "fs.harness-state[") {
		t.Fatalf("events table: %v\n%s", err, b.String())
	}
}
