// SPDX-License-Identifier: Apache-2.0

package record

import (
	"bufio"
	"os"
	"path/filepath"
	"testing"
)

const fixturesDir = "../../../spec/record/v1/fixtures"

// readFixture decodes and verifies a fixture ledger through the pure codec: every line decodes, validates and
// links to the previous one.
func readFixture(t *testing.T, name string) []*Event {
	t.Helper()
	f, err := os.Open(filepath.Join(fixturesDir, name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var chain Chain
	var events []*Event
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		e, err := chain.Add(sc.Bytes())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := e.Validate(); err != nil {
			t.Fatalf("%s line %d: %v", name, e.Seq, err)
		}
		events = append(events, e)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}

// TestRunFixture: the frozen 20-step run validates through Decode and the chain
// verifier and has the shape every view is built against.
func TestRunFixture(t *testing.T) {
	events := readFixture(t, "run-fixture.jsonl")
	kinds := map[Kind]int{}
	steps := map[int]bool{}
	for i, e := range events {
		kinds[e.Kind]++
		if e.Kind.IsAction() {
			if e.Attr == nil || !e.Attr.Valid() {
				t.Errorf("line %d: action without attribution", i)
			}
			if e.Attr.Method == MethodTime {
				steps[e.Attr.Step] = true
			}
			if e.Attr.Confidence == ConfidenceExact || e.Attr.Method == MethodToolID || e.Attr.Method == MethodTID {
				t.Errorf("line %d: P1 attribution in a P0 fixture (R8)", i)
			}
		} else if e.Attr != nil {
			t.Errorf("line %d: %s carries attribution", i, e.Kind)
		}
		if e.Run != events[0].Run || e.Agent != "retriever" {
			t.Errorf("line %d: run/agent drift", i)
		}
		if i > 0 && e.MonoNS <= events[i-1].MonoNS {
			t.Errorf("line %d: mono_ns not increasing", i)
		}
	}
	want := map[Kind]int{KindRunStart: 1, KindRunEnd: 1, KindSSLRequest: 20, KindSSLResponse: 20, KindDecision: 20,
		KindRefused: 1, KindLimit: 1, KindGap: 2}
	for k, n := range want {
		if kinds[k] != n {
			t.Errorf("%s: %d lines, want %d", k, kinds[k], n)
		}
	}
	for _, k := range []Kind{KindExec, KindFS, KindNet, KindMCP} {
		if kinds[k] == 0 {
			t.Errorf("no %s event", k)
		}
	}
	for _, k := range []Kind{KindAsk, KindAnswer, KindBoundary} {
		if kinds[k] != 0 {
			t.Errorf("%s is not a P0 kind", k)
		}
	}
	if len(steps) != 20 {
		t.Errorf("actions attributed to %d steps, want 20", len(steps))
	}
	first, last := events[0], events[len(events)-1]
	var start RunStartPayload
	if first.Kind != KindRunStart || first.DecodePayload(&start) != nil || start.Limits == nil || start.Limits.Tokens == nil || *start.Limits.Tokens != 60000 {
		t.Fatalf("run_start: %+v", start)
	}
	var end RunEndPayload
	if last.Kind != KindRunEnd || last.DecodePayload(&end) != nil || end.Reason != RunEndLimit || last.Reason != "limit" {
		t.Fatalf("run_end: %+v", end)
	}
	var lim LimitPayload
	if e := events[len(events)-2]; e.Kind != KindLimit || e.DecodePayload(&lim) != nil || lim.Which != LimitTokens ||
		lim.Value <= lim.Ceiling || e.Reason != ReasonLimitTokens {
		t.Fatalf("limit before run_end: %+v %+v", e, lim)
	}
	for _, e := range events {
		if e.Kind == KindRefused {
			var r RefusedPayload
			if e.DecodePayload(&r) != nil || r.Reason != ReasonReadDenied || r.Rule != e.Rule || e.Reason != r.Reason {
				t.Fatalf("refused: %+v", r)
			}
		}
	}
}

// TestHostSocketsFixture is ADR 0070's golden run (record minor 16): with no net: section a host daemon's socket and
// an abstract name the run does not hold are refused host-sockets, each with its refused line, the Docker daemon's
// line naming what it gives, while the run's own socket and an IP destination are allowed.
func TestHostSocketsFixture(t *testing.T) {
	events := readFixture(t, "host-sockets.jsonl")
	var start RunStartPayload
	if events[0].Kind != KindRunStart || events[0].DecodePayload(&start) != nil || start.HostSockets {
		t.Fatalf("first line %+v: want a run_start without the host_sockets opt-out", events[0])
	}
	refused, what := 0, ""
	for _, e := range events {
		var n NetPayload
		if e.Kind != KindNet || e.DecodePayload(&n) != nil {
			continue
		}
		switch {
		case e.Rule == "host-sockets":
			if e.Verdict != VerdictRefused || n.Proto != "unix" || e.Reason != ReasonNetNotAllowed {
				t.Errorf("host-sockets line %+v %+v: want a unix refusal, net-not-allowed", e, n)
			}
			refused++
			what += n.What
		case e.Verdict != VerdictAllow:
			t.Errorf("line %+v %+v: want the run's own socket and the IP destination allowed", e, n)
		}
	}
	if refused != 2 || what != "the Docker daemon, root-equivalent" {
		t.Errorf("%d host-sockets refusals naming %q, want two and the Docker daemon's", refused, what)
	}
}

// TestUserDenyWriteFixture is ADR 0071's golden run (record minor 19): run_start's best_effort lists fs.deny_write, a
// write in the contract's fs.deny_write entry is refused under fs.deny_write[<entry as declared>] with its refused line,
// and a write in the subtree a nested write entry reopens is allowed under that entry.
func TestUserDenyWriteFixture(t *testing.T) {
	events := readFixture(t, "user-deny-write.jsonl")
	var start RunStartPayload
	if events[0].Kind != KindRunStart || events[0].DecodePayload(&start) != nil || start.RecordMinor != MinorUserDenyWrite ||
		len(start.BestEffort) != 1 || start.BestEffort[0] != "fs.deny_write" {
		t.Fatalf("first line %+v: want a run_start at minor %d listing fs.deny_write", events[0], MinorUserDenyWrite)
	}
	const rule = "fs.deny_write[./deploy/]"
	refused, refusedLine, allowed := 0, 0, 0
	for _, e := range events {
		switch {
		case e.Kind == KindFS && e.Rule == rule:
			if e.Verdict != VerdictRefused || e.Reason != ReasonWriteOutsideContract {
				t.Errorf("%+v: want refused write-outside-contract", e)
			}
			refused++
		case e.Kind == KindRefused:
			var p RefusedPayload
			if e.DecodePayload(&p) != nil || p.Rule != rule {
				t.Errorf("refused line %+v: want rule %s", e, rule)
			}
			refusedLine++
		case e.Kind == KindFS:
			if e.Verdict != VerdictAllow || e.Rule != "fs.write[./deploy/tmp/]" {
				t.Errorf("%+v: want the reopened subtree's write allowed under its write entry", e)
			}
			allowed++
		}
	}
	if refused != 1 || refusedLine != 1 || allowed != 1 {
		t.Errorf("%d refused fs lines, %d refused lines, %d allowed: want one each", refused, refusedLine, allowed)
	}
}

// TestKindsFixture covers every v1 kind, the three P1/P2 kinds included, so a reader of any phase has a golden
// line per kind.
func TestKindsFixture(t *testing.T) {
	events := readFixture(t, "kinds.jsonl")
	seen := map[Kind]bool{}
	for _, e := range events {
		seen[e.Kind] = true
	}
	for _, k := range Kinds {
		if !seen[k] {
			t.Errorf("no %s line in kinds.jsonl", k)
		}
	}
	if len(events) != len(Kinds) {
		t.Errorf("%d lines, want one per kind (%d)", len(events), len(Kinds))
	}
}

// TestProfilesFixture: profiles.jsonl is a run at record_minor 15 whose run_start lists the profiles its contract
// merged (ADR 0066 D6), in merge order, each with its source and a sha256, read through Decode and Validate alone.
func TestProfilesFixture(t *testing.T) {
	events := readFixture(t, "profiles.jsonl")
	var p RunStartPayload
	if len(events) < 2 || events[0].Kind != KindRunStart || events[0].DecodePayload(&p) != nil {
		t.Fatalf("no run_start: %+v", events)
	}
	if p.RecordMinor != MinorProfiles || len(p.Profiles) != 3 {
		t.Fatalf("record_minor %d, profiles %+v", p.RecordMinor, p.Profiles)
	}
	for i, want := range []ProfileRef{{Name: "tego/python", Source: ProfileSourceBuiltin}, {Name: "base", Source: ProfileSourceDir}, {Name: "team", Source: ProfileSourceDir}} {
		got := p.Profiles[i]
		if got.Name != want.Name || got.Source != want.Source || len(got.SHA256) != 64 {
			t.Errorf("profiles[%d] = %+v, want %s from %s with a sha256", i, got, want.Name, want.Source)
		}
	}
	if last := events[len(events)-1]; last.Kind != KindRunEnd {
		t.Fatalf("the fixture ends with %s, want run_end", last.Kind)
	}
}
