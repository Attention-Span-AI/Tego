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

// TestViewsReadHarnessHookFixture: every view reads spec/record/v1/fixtures/harness-hook.jsonl, a run at record_minor
// 17 whose launcher granted its harness hook's exact argv (ADR 0064). The hook's exec, allowed under
// exec.harness-hook[<tego>], is a runtime grant: drift never counts it as a contract entry, and learn proposes no
// exec entry for the tego binary (one would admit every argv of it) and counts it in its own note; the other argv of
// the binary, refused under the same rule, is a refusal.
func TestViewsReadHarnessHookFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "harness-hook.jsonl"))
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
	var hookRefused int
	for _, s := range rep.Sections() {
		for _, c := range s.Counts {
			if strings.Contains(c.Rule, "/usr/local/bin/tego") && !agent.IsRuntimeRule(c.Rule) {
				t.Errorf("drift counts the hook grant as a contract rule: %s", c.Rule)
			}
			if c.Rule == "exec."+agent.HarnessHookGrant+"[/usr/local/bin/tego]" {
				hookRefused += c.Refused
			}
		}
	}
	// The fixture's refused `tego run` is an action the contract does not describe: the run drifts (R25's exit 1),
	// as the same refusal under unmatched did before the grant existed.
	if hookRefused != 1 || !rep.Drifted() {
		t.Errorf("drift: %d refusals under the hook grant's rule, drifted %t; want 1 and true", hookRefused, rep.Drifted())
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
	if c := p.Contract(); strings.Contains(c, "/usr/local/bin/tego") || !strings.Contains(c, "1 execs of the harness hook the run grants itself (exec.harness-hook)") {
		t.Errorf("learn does not count the hook's exec as the run's own grant:\n%s", c)
	}
	var b bytes.Buffer
	if _, err := eventsJSON(t, &b, dir, events.Filter{}); err != nil || !strings.Contains(b.String(), `"hook":{"argv":["/usr/local/bin/tego","hook","claude-code"`) {
		t.Fatalf("events --json: %v\n%s", err, b.String())
	}
	b.Reset()
	if _, err := eventsTable(t, &b, dir, events.Filter{}); err != nil || !strings.Contains(b.String(), "exec.harness-hook[") {
		t.Fatalf("events table: %v\n%s", err, b.String())
	}
}
