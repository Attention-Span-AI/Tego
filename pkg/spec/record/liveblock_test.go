// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestRecordMinorCoversLiveBlocks: live blocks are revision 21, the next free one after the harness hook's 20
// (TestRecordMinorsAreContiguous), and this build writes it.
func TestRecordMinorCoversLiveBlocks(t *testing.T) {
	if MinorLiveBlock != MinorHarnessHook+1 || Minor < MinorLiveBlock {
		t.Fatalf("Minor %d, MinorLiveBlock %d: live blocks are 21, after the harness hook at 20", Minor, MinorLiveBlock)
	}
	b, err := json.Marshal(GapPayload{What: GapEnforce, Why: GapLiveBlockAdded, LiveBlock: &LiveBlockChange{Op: "add",
		Kind: "exec", Value: "curl", Rule: "live.block[exec:curl]", By: "uid:1 pid:2 cli", Serial: 1}})
	if err != nil || !strings.Contains(string(b), `"live_block":{"op":"add","kind":"exec","value":"curl","rule":"live.block[exec:curl]","by":"uid:1 pid:2 cli","serial":1,`) {
		t.Fatalf("a live-block gap = %s (%v)", b, err)
	}
	b, err = json.Marshal(GapPayload{What: GapRecord, Why: "x"})
	if err != nil || strings.Contains(string(b), "live_block") {
		t.Fatalf("a gap of another why carries live_block: %s (%v)", b, err)
	}
}

// TestLiveBlockFixture reads spec/record/v1/fixtures/live-block.jsonl through Decode, Validate and Chain alone: a run
// at record_minor 21 in which a person blocked a program and a destination live, each refused under its
// live.block[...] rule with the reason its kind has, then removed both, after which the contract's own entries
// allowed them; and one overlay the launcher could not read.
func TestLiveBlockFixture(t *testing.T) {
	events := readFixture(t, "live-block.jsonl")
	var start RunStartPayload
	if len(events) != 13 || events[0].Kind != KindRunStart || events[0].DecodePayload(&start) != nil || start.RecordMinor != MinorLiveBlock {
		t.Fatalf("live-block.jsonl: %d events, record_minor %d", len(events), start.RecordMinor)
	}
	gap := func(i int, why string) *LiveBlockChange {
		t.Helper()
		var p GapPayload
		if events[i].Kind != KindGap || events[i].DecodePayload(&p) != nil || p.What != GapEnforce || p.Why != why {
			t.Fatalf("line %d is %+v, want gap enforce %s", i, events[i], why)
		}
		return p.LiveBlock
	}
	if c := gap(1, GapLiveBlockAdded); c == nil || c.Op != "add" || c.Rule != "live.block[exec:curl]" || c.Serial != 1 || !strings.HasSuffix(c.By, " dashboard") {
		t.Fatalf("the exec block's line names %+v", c)
	}
	if e := events[2]; e.Kind != KindExec || e.Verdict != VerdictRefused || e.Rule != "live.block[exec:curl]" || e.Reason != ReasonExecNotAllowed {
		t.Fatalf("the blocked exec is %+v", e)
	}
	if e := events[3]; e.Kind != KindRefused || e.Rule != "live.block[exec:curl]" {
		t.Fatalf("the blocked exec's mirror is %+v", e)
	}
	if c := gap(4, GapLiveBlockAdded); c == nil || c.Kind != "net" || c.Value != "example.com:443" || c.Serial != 2 {
		t.Fatalf("the net block's line names %+v", c)
	}
	if e := events[5]; e.Kind != KindNet || e.Verdict != VerdictRefused || e.Rule != "live.block[net:example.com:443]" || e.Reason != ReasonNetNotAllowed {
		t.Fatalf("the blocked connect is %+v", e)
	}
	for i, serial := range map[int]uint64{7: 3, 8: 4} {
		if c := gap(i, GapLiveBlockRemoved); c == nil || c.Op != "remove" || c.Serial != serial {
			t.Fatalf("line %d's removal names %+v", i, c)
		}
	}
	if e := events[9]; e.Kind != KindExec || e.Verdict != VerdictAllow || e.Rule != "exec[/usr/bin/curl]" {
		t.Fatalf("the exec after the removal is %+v", e)
	}
	if e := events[10]; e.Kind != KindNet || e.Verdict != VerdictAllow || e.Rule != "net[example.com:443]" {
		t.Fatalf("the connect after the removal is %+v", e)
	}
	if c := gap(11, GapLiveBlockUnreadable); c != nil {
		t.Fatalf("an unreadable overlay's line names a block: %+v", c)
	}
}

// TestReadmeNamesTheLiveBlockMinor: the record README documents revision 21's rule, gap whys and live_block fields.
func TestReadmeNamesTheLiveBlockMinor(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := "At `record_minor` " + strconv.Itoa(MinorLiveBlock) + " ("
	i := strings.Index(string(b), want)
	if i < 0 {
		t.Fatalf("spec/record/v1/README.md has no %q", want)
	}
	text := string(b[i:min(len(b), i+3200)])
	for _, s := range []string{"`live.block[<kind>:<value>]`", "`" + GapLiveBlockAdded + "`", "`" + GapLiveBlockRemoved + "`",
		"why=" + GapLiveBlockUnreadable + "`", "why=" + GapLiveBlockLost + "`", "`live_block`", "`{op, kind, value, rule, by, serial, at}`",
		"fixtures/live-block.jsonl"} {
		if !strings.Contains(text, s) {
			t.Errorf("README's record_minor %d entry does not name %s", MinorLiveBlock, s)
		}
	}
}
