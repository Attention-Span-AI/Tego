// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

var liveDir = filepath.Join(fixturesDir, "live")

// TestRecordMinorCoversLiveControl: the live controls are revision 24, the next free one after reads_notified's 23
// (TestRecordMinorsAreContiguous), and this build writes it. A pause line names live_control and no live_block; a live
// block line names live_block and no live_control.
func TestRecordMinorCoversLiveControl(t *testing.T) {
	if MinorLiveControl != 24 || MinorReasonReads != 23 || Minor < MinorLiveControl {
		t.Fatalf("Minor %d, MinorLiveControl %d: the live controls are 24, after reads_notified at 23", Minor, MinorLiveControl)
	}
	at := time.Date(2026, 10, 27, 12, 3, 0, 0, time.UTC)
	b, err := json.Marshal(GapPayload{What: GapEnforce, Why: GapRunPaused, LiveControl: &LiveControlChange{Op: LiveOpPause,
		By: "uid:1000 pid:2 dashboard", Serial: 3, At: at}})
	if err != nil || string(b) != `{"what":"enforce","why":"run-paused","live_control":{"op":"pause","by":"uid:1000 pid:2 dashboard","serial":3,"at":"2026-10-27T12:03:00Z"}}` {
		t.Fatalf("a pause line = %s (%v)", b, err)
	}
	b, err = json.Marshal(GapPayload{What: GapEnforce, Why: GapLiveBlockAdded, LiveBlock: &LiveBlockChange{Op: LiveOpAdd,
		Kind: LiveKindWrite, Value: "/p/src/", Rule: LiveRule(LiveKindWrite, "/p/src/"), By: "uid:1 pid:2 cli", Serial: 1, At: at}})
	if err != nil || !strings.Contains(string(b), `"live_block":{"op":"add","kind":"write","value":"/p/src/","rule":"live.block[write:/p/src/]",`) ||
		strings.Contains(string(b), "live_control") {
		t.Fatalf("a write block's line = %s (%v)", b, err)
	}
	if !slices.Equal(LiveBlockKinds, []string{"exec", "net", "path", "read", "write"}) {
		t.Fatalf("LiveBlockKinds = %q", LiveBlockKinds)
	}
	LiveBlockKinds[0] = "mutated"
	defer func() { LiveBlockKinds[0] = LiveKindExec }()
	e := liveGap(t, GapPayload{What: GapEnforce, Why: GapLiveBlockAdded, LiveBlock: &LiveBlockChange{Op: LiveOpAdd,
		Kind: LiveKindExec, Value: "curl", Rule: "live.block[exec:curl]", Serial: 1}})
	if err := e.ValidateAt(MinorLiveBlock); err != nil {
		t.Fatalf("editing LiveBlockKinds changed validation: %v", err)
	}
}

// liveGap is a valid gap envelope around p.
func liveGap(t *testing.T, p GapPayload) *Event {
	t.Helper()
	e := &Event{V: Version, Kind: KindGap, Source: SourceSupervisor, Run: "r-00000000-000000000000a-aaaaaa", Agent: "retriever",
		TS: time.Date(2026, 10, 27, 12, 3, 1, 0, time.UTC)}
	if err := e.SetPayload(p); err != nil {
		t.Fatal(err)
	}
	return e
}

// liveDoc is one document of spec/record/v1/fixtures/live: mvpDoc's form, with the rule of a refused line.
type liveDoc struct {
	Kind    Kind            `json:"kind"`
	Minor   int             `json:"minor"`
	Rule    string          `json:"rule"`
	Payload json.RawMessage `json:"payload"`
}

// liveEvent builds the line a fixtures/live document describes: a valid envelope of its kind around its payload.
func liveEvent(t *testing.T, path string) (*Event, int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d liveDoc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("%s: %v", filepath.Base(path), err)
	}
	e := &Event{V: Version, Kind: d.Kind, Source: SourceSupervisor, Run: "r-00000000-000000000000a-aaaaaa", Agent: "retriever",
		TS: time.Date(2026, 10, 27, 12, 3, 1, 0, time.UTC), Payload: d.Payload}
	if d.Kind == KindRefused {
		var p struct {
			Reason Reason `json:"reason"`
		}
		_ = json.Unmarshal(d.Payload, &p)
		e.Rule, e.Reason = d.Rule, p.Reason
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("%s: the envelope the harness built is not valid: %v", filepath.Base(path), err)
	}
	return e, d.Minor
}

// TestLiveFieldFixtures: every valid document of fixtures/live passes Event.ValidateAt at its ledger's revision and
// encodes through MarshalLineAt; every invalid one is refused by both with the code its file name starts with, and
// below-minor, field-case, live-block and live-control each have one. Validate alone, which knows no revision, passes
// every one of them: these rules are ValidateAt's.
func TestLiveFieldFixtures(t *testing.T) {
	valid, _ := filepath.Glob(filepath.Join(liveDir, "valid", "*.json"))
	invalid, _ := filepath.Glob(filepath.Join(liveDir, "invalid", "*.json"))
	if len(valid) < 8 || len(invalid) < 20 {
		t.Fatalf("%d valid and %d invalid fixtures; want at least 8 and 20", len(valid), len(invalid))
	}
	for _, f := range valid {
		e, minor := liveEvent(t, f)
		if err := e.ValidateAt(minor); err != nil {
			t.Errorf("%s: refused: %v", filepath.Base(f), err)
		}
		if _, err := e.MarshalLineAt(minor); err != nil {
			t.Errorf("%s: MarshalLineAt refused: %v", filepath.Base(f), err)
		}
	}
	seen := map[string]bool{}
	for _, f := range invalid {
		code, _, _ := strings.Cut(filepath.Base(f), ".")
		if !slices.Contains(FieldCodes, code) {
			t.Errorf("%s: %q is no code of this package", filepath.Base(f), code)
		}
		seen[code] = true
		e, minor := liveEvent(t, f)
		err := e.ValidateAt(minor)
		if got := FieldCode(err); got != code {
			t.Errorf("%s: %v [%s], want [%s]", filepath.Base(f), err, got, code)
		}
		t.Logf("%s: %v", filepath.Base(f), err)
		if err != nil && !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("%s: %v is not ErrInvalidEvent", filepath.Base(f), err)
		}
		if _, err := e.MarshalLineAt(minor); FieldCode(err) != code {
			t.Errorf("%s: MarshalLineAt = %v, want [%s]", filepath.Base(f), err, code)
		}
	}
	for _, c := range []string{"below-minor", "field-case", "live-block", "live-control"} {
		if !seen[c] {
			t.Errorf("no invalid fixture of fixtures/live shows [%s]", c)
		}
	}
}

// TestLiveChangesAtEachRevision: each pause why, live_control and read or write kind passes at 24 and later and is
// refused [below-minor] at 23; the kinds of revision 21 pass at every revision (no check holds them to 21); a gap with neither field and another why passes
// at every revision, as before 24.
func TestLiveChangesAtEachRevision(t *testing.T) {
	at := time.Date(2026, 10, 27, 12, 3, 0, 0, time.UTC)
	ctl := func(why, op string) GapPayload {
		return GapPayload{What: GapEnforce, Why: why, LiveControl: &LiveControlChange{Op: op, By: "uid:1 pid:2 cli", Serial: 1, At: at}}
	}
	blk := func(kind, value string) GapPayload {
		return GapPayload{What: GapEnforce, Why: GapLiveBlockAdded, LiveBlock: &LiveBlockChange{Op: LiveOpAdd, Kind: kind,
			Value: value, Rule: LiveRule(kind, value), By: "uid:1 pid:2 dashboard", Serial: 1, At: at}}
	}
	cases := []struct {
		name string
		p    GapPayload
		from int
	}{
		{"run-paused", ctl(GapRunPaused, LiveOpPause), MinorLiveControl},
		{"run-resumed", ctl(GapRunResumed, LiveOpResume), MinorLiveControl},
		{"pause-failed", ctl(GapPauseFailed, LiveOpPause), MinorLiveControl},
		{"resume-failed", ctl(GapResumeFailed, LiveOpResume), MinorLiveControl},
		{"read", blk(LiveKindRead, "/p/.env"), MinorLiveControl},
		{"write", blk(LiveKindWrite, "/p/src/"), MinorLiveControl},
		{"exec", blk(LiveKindExec, "curl"), 0},
		{"net", blk(LiveKindNet, "example.com:443"), 0},
		{"path", blk(LiveKindPath, "/p/.env"), 0},
		{"unreadable", GapPayload{What: GapEnforce, Why: GapLiveBlockUnreadable}, 0},
		{"record gap", GapPayload{What: GapRecord, Why: "dropped", Count: 12}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := liveGap(t, tc.p)
			for _, m := range []int{0, MinorLiveBlock - 1, MinorLiveBlock, MinorReasonReads, MinorLiveControl, MinorLiveControl + 1, MinorShares} {
				err := e.ValidateAt(m)
				switch {
				case m >= tc.from && err != nil:
					t.Errorf("at %d: %v", m, err)
				case m < tc.from && FieldCode(err) != "below-minor":
					t.Errorf("at %d: %v, want [below-minor]", m, err)
				}
			}
			if err := e.Validate(); err != nil {
				t.Errorf("Validate: %v", err)
			}
		})
	}
	for _, rule := range []string{"live.block[read:/p/.env]", "live.block[write:/p/src/]"} {
		e := &Event{V: Version, Kind: KindRefused, Source: SourceSeccomp, Run: "r-00000000-000000000000a-aaaaaa",
			Agent: "retriever", TS: at, Rule: rule, Reason: ReasonReadDenied}
		if err := e.ValidateAt(MinorLiveControl); err != nil {
			t.Errorf("%s at 24: %v", rule, err)
		}
		if err := e.ValidateAt(MinorReasonReads); FieldCode(err) != "below-minor" {
			t.Errorf("%s at 23: %v, want [below-minor]", rule, err)
		}
	}
	// Revision 21's kinds are not held to 21: the check adds no rule below 24's.
	e := &Event{V: Version, Kind: KindRefused, Source: SourceSeccomp, Run: "r-00000000-000000000000a-aaaaaa",
		Agent: "retriever", TS: at, Rule: "live.block[exec:ls]", Reason: ReasonExecNotAllowed}
	if err := e.ValidateAt(0); err != nil {
		t.Errorf("live.block[exec:ls] at 0: %v", err)
	}
}

// TestLiveBlockFixtureValidatesAt: every line of live-block.jsonl, the revision-21 run, passes ValidateAt at 21, so
// the live block lines this build's launcher has written since revision 21 stay valid under the checks 24 added.
func TestLiveBlockFixtureValidatesAt(t *testing.T) {
	for i, e := range readFixture(t, "live-block.jsonl") {
		if err := e.ValidateAt(MinorLiveBlock); err != nil {
			t.Errorf("line %d: %v", i, err)
		}
	}
}

// TestLiveControlFixture reads spec/record/v1/fixtures/live-control.jsonl through Decode, Validate and Chain, and
// every line through ValidateAt at its revision: a run at record_minor 24 in which a person blocked the reads of .env
// and the writes under src/ live, each refused under its live.block[read:...] or live.block[write:...] rule while a
// read in src/ stayed allowed; then paused and resumed the run, and a pause the launcher could not apply was followed
// by its resume.
func TestLiveControlFixture(t *testing.T) {
	events := readFixture(t, "live-control.jsonl")
	var start RunStartPayload
	if len(events) != 13 || events[0].Kind != KindRunStart || events[0].DecodePayload(&start) != nil ||
		start.RecordMinor != MinorLiveControl {
		t.Fatalf("live-control.jsonl: %d events, record_minor %d", len(events), start.RecordMinor)
	}
	for i, e := range events {
		if err := e.ValidateAt(MinorLiveControl); err != nil {
			t.Errorf("line %d: %v", i, err)
		}
	}
	gap := func(i int, why string) GapPayload {
		t.Helper()
		var p GapPayload
		if events[i].Kind != KindGap || events[i].DecodePayload(&p) != nil || p.What != GapEnforce || p.Why != why {
			t.Fatalf("line %d is %+v, want gap enforce %s", i, events[i], why)
		}
		return p
	}
	if c := gap(1, GapLiveBlockAdded).LiveBlock; c == nil || c.Kind != LiveKindRead || c.Rule != "live.block[read:/home/u/proj/.env]" ||
		c.Serial != 1 || !strings.HasSuffix(c.By, " dashboard") {
		t.Fatalf("the read block's line names %+v", c)
	}
	if e := events[2]; e.Kind != KindFS || e.Verdict != VerdictRefused || e.Rule != "live.block[read:/home/u/proj/.env]" ||
		e.Reason != ReasonReadDenied {
		t.Fatalf("the blocked read is %+v", e)
	}
	if e := events[3]; e.Kind != KindRefused || e.Rule != "live.block[read:/home/u/proj/.env]" {
		t.Fatalf("the blocked read's mirror is %+v", e)
	}
	if c := gap(4, GapLiveBlockAdded).LiveBlock; c == nil || c.Kind != LiveKindWrite || c.Value != "/home/u/proj/src/" || c.Serial != 2 {
		t.Fatalf("the write block's line names %+v", c)
	}
	if e := events[5]; e.Kind != KindFS || e.Verdict != VerdictRefused || e.Rule != "live.block[write:/home/u/proj/src/]" {
		t.Fatalf("the blocked write is %+v", e)
	}
	if e := events[7]; e.Kind != KindFS || e.Verdict != VerdictAllow || e.Rule != "fs.read[./]" {
		t.Fatalf("the read under the write block is %+v", e)
	}
	for i, want := range map[int]struct {
		why, op string
		serial  uint64
	}{8: {GapRunPaused, LiveOpPause, 3}, 9: {GapRunResumed, LiveOpResume, 4}, 10: {GapPauseFailed, LiveOpPause, 5},
		11: {GapRunResumed, LiveOpResume, 6}} {
		p := gap(i, want.why)
		if c := p.LiveControl; c == nil || c.Op != want.op || c.Serial != want.serial || c.By == "" || c.At.IsZero() || p.LiveBlock != nil {
			t.Errorf("line %d (%s) names %+v", i, want.why, p)
		}
	}
	if events[12].Kind != KindRunEnd {
		t.Fatalf("the last line is %s", events[12].Kind)
	}
	// Read as a ledger of revision 23, the pause lines and the new kinds are refused by name.
	for _, i := range []int{1, 2, 3, 4, 5, 6, 8, 9, 10, 11} {
		if got := FieldCode(events[i].ValidateAt(MinorReasonReads)); got != "below-minor" {
			t.Errorf("line %d read at 23: [%s], want [below-minor]", i, got)
		}
	}
}

// TestReadmeNamesTheLiveControlMinor: the record README documents revision 24's whys, field, kinds, rules and fixtures.
func TestReadmeNamesTheLiveControlMinor(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := "At `record_minor` " + strconv.Itoa(MinorLiveControl) + " ("
	i := strings.Index(string(b), want)
	if i < 0 {
		t.Fatalf("spec/record/v1/README.md has no %q", want)
	}
	text := string(b[i:min(len(b), i+4800)])
	for _, s := range []string{"`" + GapRunPaused + "`", "`" + GapRunResumed + "`", "`" + GapPauseFailed + "`",
		"`" + GapResumeFailed + "`", "`live_control`", "`{op, by, serial, at}`", "`" + LiveOpPause + "`", "`" + LiveOpResume + "`",
		"`" + LiveKindRead + "`", "`" + LiveKindWrite + "`", "`live.block[read:", "`live.block[write:", "`below-minor`",
		"`live-block`", "`live-control`", "fixtures/live-control.jsonl", "fixtures/live"} {
		if !strings.Contains(text, s) {
			t.Errorf("README's record_minor %d entry does not name %s", MinorLiveControl, s)
		}
	}
}
