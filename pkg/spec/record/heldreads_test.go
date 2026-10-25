// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"testing"
)

// ADR 0069 D4: run_start's fs_reads came at 18 (after host_sockets at 16 and the run identity at 17), on every run, so a
// reader of a ledger at 18 or later knows whether its reads were held.
func TestRecordMinorCoversHeldReads(t *testing.T) {
	if MinorHeldReads != 18 || Minor < MinorHeldReads || MinorHeldReads <= MinorProfiles {
		t.Fatalf("Minor %d, MinorHeldReads %d: fs_reads is 18, after profiles at 15", Minor, MinorHeldReads)
	}
	b, err := json.Marshal(FSReads{Reads: FSReadsHeld, Why: "nested", Nested: []string{"fs.deny_read[/p/.env]"}})
	if err != nil || string(b) != `{"reads":"held","why":"nested","nested":["fs.deny_read[/p/.env]"]}` {
		t.Fatalf("fs_reads = %s (%v)", b, err)
	}
	if b, _ := json.Marshal(FSReads{Reads: FSReadsDirect, Why: "none-nested"}); string(b) != `{"reads":"direct","why":"none-nested"}` {
		t.Fatalf("a direct run's fs_reads = %s", b)
	}
}

// TestHeldReadsFixture: held-reads.jsonl is a run at record_minor 18 whose reads were held (ADR 0069), read through
// Decode and Validate alone: run_start says held, why nested, and names the nested entry; each refusal is one fs line,
// read-denied by a deny_read rule from the supervisor's notifications (source seccomp), the nested .env by its entry
// and the .env.local made during the run by the built-in name rule; no allowed read has a line.
func TestHeldReadsFixture(t *testing.T) {
	events := readFixture(t, "held-reads.jsonl")
	var p RunStartPayload
	if len(events) < 2 || events[0].Kind != KindRunStart || events[0].DecodePayload(&p) != nil {
		t.Fatalf("no run_start: %+v", events)
	}
	if p.RecordMinor != MinorHeldReads || p.FSReads == nil || p.FSReads.Reads != FSReadsHeld || p.FSReads.Why != FSReadsWhyNested ||
		len(p.FSReads.Nested) != 1 || !p.Capabilities["fs.deny_read.nested"] || p.Capabilities["fs.deny_read.moved"] {
		t.Fatalf("record_minor %d, fs_reads %+v, capabilities %v", p.RecordMinor, p.FSReads, p.Capabilities)
	}
	var refused []string
	for _, e := range events[1:] {
		var fs FSPayload
		if e.Kind != KindFS || e.DecodePayload(&fs) != nil {
			continue
		}
		if e.Verdict != VerdictRefused || e.Reason != ReasonReadDenied || e.Source != SourceSeccomp || e.Authority != AuthorityRule {
			t.Errorf("fs line %d: %s %s from %s by %s, want a read-denied refusal from seccomp", e.Seq, e.Verdict, e.Reason, e.Source, e.Authority)
		}
		refused = append(refused, e.Rule+" "+fs.Path)
	}
	want := []string{p.FSReads.Nested[0] + " /srv/proj/out/.env", "fs.deny_read[/srv/proj/**/.env.*] /srv/proj/out/.env.local"}
	if len(refused) != len(want) || refused[0] != want[0] || refused[1] != want[1] {
		t.Fatalf("refused fs lines %q, want %q", refused, want)
	}
	if last := events[len(events)-1]; last.Kind != KindRunEnd {
		t.Fatalf("the fixture ends with %s, want run_end", last.Kind)
	}
}
