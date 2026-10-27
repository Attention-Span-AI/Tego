// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// reasonContract is a contract pinned to tier landlock whose command is python (harness auto resolves generic), with
// extra top-level keys appended.
func reasonContract(extra string) string {
	return "version: 0\nname: reason\ncommand: [python]\ntier: landlock\nfs:\n  write: [\"out/\"]\n  deny_read: [\"secrets/\"]\n" + extra
}

// TestReasonReadsWhenAndWhy holds ADR 0077's rule (agent-contract.md R29): reason.reads: auto is the measured default,
// off; on notifies every read open at tier landlock where nothing else does (held, an ask_read entry, a read gate,
// record: full), whatever the harness, never at a root tier, whose kernel record carries the refusal, nor in a run
// that enforces nothing.
func TestReasonReadsWhenAndWhy(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name, extra string
		tier        backend.Tier
		on          bool
		why         string
		mode        ReasonReadsMode
	}{
		{"auto, the measured default", "", backend.TierLandlock, false, record.ReadsNotifiedWhyReasonOff, ReasonReadsAuto},
		{"off", "reason:\n  reads: off\n", backend.TierLandlock, false, record.ReadsNotifiedWhyReasonOff, ReasonReadsOff},
		{"on", "reason:\n  reads: on\n", backend.TierLandlock, true, record.ReadsNotifiedWhyReason, ReasonReadsOn},
		{"on, harness none", "harness: none\nreason:\n  reads: on\n", backend.TierLandlock, true, record.ReadsNotifiedWhyReason, ReasonReadsOn},
		{"on, record full", "record: full\nreason:\n  reads: on\n", backend.TierLandlock, false, record.ReadsNotifiedWhyFull, ReasonReadsOn},
		{"on, a root tier", "reason:\n  reads: on\n", backend.TierCgroup, false, record.ReadsNotifiedWhyKernel, ReasonReadsOn},
		{"on, observe", "reason:\n  reads: on\n", backend.TierObserve, false, record.ReadsNotifiedWhyRecordsOnly, ReasonReadsOn},
		{"on, held reads", "fs:\n  reads: held\n", backend.TierLandlock, false, record.ReadsNotifiedWhyHeld, ReasonReadsOn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := reasonContract(tc.extra)
			if strings.HasPrefix(tc.extra, "fs:") {
				src = "version: 0\nname: reason\ncommand: [python]\ntier: landlock\nfs:\n  write: [\"out/\"]\n  deny_read: [\"secrets/\"]\n  reads: held\nreason:\n  reads: on\n"
			}
			rt, _ := f.compile(f.load(src))
			if rt.ReasonReads != tc.mode {
				t.Errorf("ReasonReads = %q, want %q", rt.ReasonReads, tc.mode)
			}
			if got := rt.ReasonReadsAt(tc.tier); got != tc.on {
				t.Errorf("ReasonReadsAt(%s) = %v, want %v", tc.tier, got, tc.on)
			}
			if got := rt.ReadsNotifiedWhy(tc.tier); got != tc.why {
				t.Errorf("ReadsNotifiedWhy(%s) = %q, want %q", tc.tier, got, tc.why)
			}
			// NotifiesReads (the filter's every-open arm at tier landlock) says yes for reason reads too, and never
			// HoldsFSNotifications: a decision plane keeps deciding a root tier's opens in the kernel (ADR 0077).
			if tc.tier == backend.TierLandlock && tc.on && !rt.NotifiesReads() {
				t.Error("NotifiesReads() = false for a table with reason reads")
			}
			if tc.on && rt.HoldsFSNotifications() {
				t.Error("HoldsFSNotifications() = true: reason reads must never hold fs notifications")
			}
		})
	}
}

// TestReasonReadsPrint holds compile's print of reason.reads: a table that records a refused read says so with its cost,
// and one that does not says why and how to turn it on.
func TestReasonReadsPrint(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct{ extra, want string }{
		{"reason:\n  reads: on\n", "reason    reads recorded at tier landlock"},
		{"reason:\n  reads: off\n", "reason    reason-reads-off (reason.reads: off)"},
		{"", "reason    reason-reads-off (reason.reads: auto)"},
	} {
		rt, _ := f.compile(f.load(reasonContract(tc.extra)))
		var b bytes.Buffer
		if err := PrintRuleTable(&b, rt); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(b.String(), tc.want) {
			t.Errorf("%q: compile print has no %q:\n%s", tc.extra, tc.want, b.String())
		}
		if !strings.Contains(b.String(), ReasonReadCost) || !strings.Contains(b.String(), ReasonReadWorkload) {
			t.Errorf("%q: the line states no measured cost", tc.extra)
		}
		if strings.Contains(tc.want, "off") && !strings.Contains(b.String(), "reason.reads: on records it") {
			t.Errorf("%q: the off line names no opt-in reason.reads: on", tc.extra)
		}
	}
}

// TestStallWarningUnderOffFollowsReasonReads: with reason.reads: on at tier landlock every read open is a notification
// the supervisor answers, which is the run's activity under record: off, so the landlock stall-reads-unseen warning
// goes; the default (auto, off) keeps it, and an --observe run's filter notifies no read for the reason channel, so it
// keeps its own.
func TestStallWarningUnderOffFollowsReasonReads(t *testing.T) {
	const base = "version: 0\nname: stallreads\ncommand: [\"/bin/sh\"]\ntier: landlock\nrecord: off\nlimits: {stall_after: 2s}\n"
	for _, tc := range []struct {
		name, extra string
		opts        []CompileOption
		at          []backend.Tier
	}{
		{"reason reads on", "reason:\n  reads: on\n", nil, nil},
		{"the default", "", nil, []backend.Tier{backend.TierLandlock}},
		{"--observe", "reason:\n  reads: on\n", []CompileOption{WithObserve()}, []backend.Tier{backend.TierObserve}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			_, ds := f.compile(f.load(base+tc.extra), tc.opts...)
			for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierObserve} {
				got := len(stallWarnings(ForTier(ds, tier))) > 0
				if want := slices.Contains(tc.at, tier); got != want {
					t.Errorf("at %s: warned %v, want %v:\n%s", tier, got, want, render(ds))
				}
			}
		})
	}
}

// TestReasonReadsSchema refuses a reason.reads value outside auto, on and off.
func TestReasonReadsSchema(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(f.project, "agent.yaml")
	f.file(path, reasonContract("reason:\n  reads: maybe\n"), 0o644)
	_, ds, err := Load(path, f.profiles())
	if err == nil || !hasCode(ds, CodeSchema) {
		t.Fatalf("reason.reads: maybe loaded without a schema error: %v %v", err, ds)
	}
}
