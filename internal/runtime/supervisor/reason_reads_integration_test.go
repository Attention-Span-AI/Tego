// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// reasonReadsRun is a modeBenchHeld target opening <dir>/f n times read-only under the filter's every-open arm, served
// by a loop at tier landlock under record: summary whose table has reason reads (ADR 0077), with a deny_read over f
// when denied.
func reasonReadsRun(t *testing.T, n int, denied bool) *harness {
	t.Helper()
	as, _ := heldAgent(t)
	h := startHarnessWith(t, harnessOpts{as: as, loops: n, mode: modeBenchHeld, filterGate: "r",
		prepare: func(dir string) { _ = os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644) },
		rules: func(rt *agent.RuleTable, dir string) {
			rt.Tier = backend.TierLandlock
			rt.Record = agent.RecordSummary
			rt.ReasonReads = agent.ReasonReadsOn
			if denied {
				f := filepath.Join(dir, "f")
				rt.FS = append(rt.FS, agent.FSRule{Path: f, Resolved: f, Kind: agent.FSDenyRead})
			}
			if !rt.ReasonReadsNotified() {
				t.Fatalf("the table has no reason reads: %s", rt.ReadsNotifiedWhy(rt.Tier))
			}
		}})
	h.stop(t)
	return h
}

// fsLines is the harness's fs lines.
func fsLines(t *testing.T, h *harness) []*record.Event {
	t.Helper()
	var out []*record.Event
	for _, ev := range h.sink.all() {
		if ev.Kind == record.KindFS {
			out = append(out, ev)
		}
	}
	return out
}

// TestReasonReadsAllowedReadsWriteNoLine: under record: summary a run with reason reads is told of every read open, and
// 1000 allowed reads write no line: each is answered CONTINUE as the filter would have let it pass (quietRead).
func TestReasonReadsAllowedReadsWriteNoLine(t *testing.T) {
	h := reasonReadsRun(t, 1000, false)
	if n := h.loop.metrics.notifications.Load(); n < 1000 {
		t.Fatalf("%d notifications for 1000 read opens: the every-open arm notified none", n)
	}
	if lines := fsLines(t, h); len(lines) != 0 {
		t.Fatalf("%d fs lines for 1000 allowed reads under summary, want none; first %+v", len(lines), lines[0])
	}
}

// TestReasonReadsRefusedReadIsOneLine: a read open under a deny_read the Landlock ruleset enforces is continued (the
// kernel's Landlock refuses it; this harness installs no ruleset, so here it opens) and its line is the one refused
// read-denied line under the entry, mechanism landlock, written under record: summary.
func TestReasonReadsRefusedReadIsOneLine(t *testing.T) {
	h := reasonReadsRun(t, 1, true)
	lines := fsLines(t, h)
	if len(lines) != 1 {
		t.Fatalf("%d fs lines for one refused read, want one: %+v", len(lines), lines)
	}
	ev := lines[0]
	var p record.FSPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	want := "fs.deny_read[" + filepath.Join(h.dir, "f") + "]"
	if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonReadDenied || ev.Rule != want ||
		p.Mechanism != record.MechanismLandlock || p.Op != record.FSOpen || ev.Source != record.SourceSeccomp {
		t.Fatalf("line %s %s %s, mechanism %q, op %s, source %s; want refused read-denied %s, mechanism landlock",
			ev.Verdict, ev.Reason, ev.Rule, p.Mechanism, p.Op, ev.Source, want)
	}
}
