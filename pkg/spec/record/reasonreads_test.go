// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"testing"
)

// ADR 0077: run_start's reads_notified came at 23, on every run, and a read Landlock refused is a line with
// mechanism landlock.
func TestRecordMinorCoversReasonReads(t *testing.T) {
	if MinorReasonReads != 23 || Minor < MinorReasonReads || MinorReasonReads <= MinorLedgerCap {
		t.Fatalf("Minor %d, MinorReasonReads %d: reads_notified is 23, after the ledger cap at 22", Minor, MinorReasonReads)
	}
	b, err := json.Marshal(ReadsNotified{Notified: true, Why: ReadsNotifiedWhyReason})
	if err != nil || string(b) != `{"notified":true,"why":"reason"}` {
		t.Fatalf("reads_notified = %s (%v)", b, err)
	}
	if b, _ := json.Marshal(ReadsNotified{Why: ReadsNotifiedWhyReasonOff}); string(b) != `{"notified":false,"why":"reason-off"}` {
		t.Fatalf("an unnotified run's reads_notified = %s", b)
	}
}

// TestReasonReadsFixture: reason-reads.jsonl is a run at record_minor 23 under record: summary whose reads were
// notified for the reason channel (ADR 0077), read through Decode and Validate alone: run_start says notified, why
// reason; the refused read is one fs line from seccomp, read-denied under fs.deny_read[~/.ssh], mechanism landlock,
// and its refused mirror names the mechanism too; no allowed read has a line.
func TestReasonReadsFixture(t *testing.T) {
	events := readFixture(t, "reason-reads.jsonl")
	var p RunStartPayload
	if len(events) < 2 || events[0].Kind != KindRunStart || events[0].DecodePayload(&p) != nil {
		t.Fatalf("no run_start: %+v", events)
	}
	if p.RecordMinor != MinorReasonReads || p.ReadsNotified == nil || !p.ReadsNotified.Notified || p.ReadsNotified.Why != ReadsNotifiedWhyReason {
		t.Fatalf("record_minor %d, reads_notified %+v", p.RecordMinor, p.ReadsNotified)
	}
	var fsLines, mirrors int
	for _, e := range events[1:] {
		switch e.Kind {
		case KindFS:
			var fs FSPayload
			if e.DecodePayload(&fs) != nil || e.Verdict != VerdictRefused || e.Reason != ReasonReadDenied ||
				e.Rule != "fs.deny_read[~/.ssh]" || fs.Mechanism != MechanismLandlock || e.Source != SourceSeccomp {
				t.Errorf("fs line %d: %s %s %s mechanism %q from %s", e.Seq, e.Verdict, e.Reason, e.Rule, fs.Mechanism, e.Source)
			}
			fsLines++
		case KindRefused:
			var r RefusedPayload
			if e.DecodePayload(&r) != nil || r.Mechanism != MechanismLandlock || e.Reason != ReasonReadDenied {
				t.Errorf("refused line %d: mechanism %q reason %s", e.Seq, r.Mechanism, e.Reason)
			}
			mirrors++
		}
	}
	if fsLines != 1 || mirrors != 1 {
		t.Fatalf("%d fs lines and %d refused lines, want one each", fsLines, mirrors)
	}
}
