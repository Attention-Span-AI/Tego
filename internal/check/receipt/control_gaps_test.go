// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // a machine with no zone database still has America/New_York

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// pausedAndBlockedRun is an enforced run with a refusal, two pause and resume cycles and one live block: a person's
// own actions, written as gap what=enforce lines, none of which lost an action (PW-2).
func pausedAndBlockedRun(extra ...line) []line {
	ctl := func(at time.Duration, why string) line {
		return line{kind: record.KindGap, at: at, payload: record.GapPayload{What: record.GapEnforce, Why: why}}
	}
	lines := []line{
		start("off", true),
		{kind: record.KindNet, at: time.Second, verdict: record.VerdictRefused, rule: "unmatched", reason: record.ReasonNetNotAllowed,
			payload: record.NetPayload{Proto: "tcp", Dst: "127.0.0.1:9722"}},
		{kind: record.KindFS, at: 2 * time.Second, verdict: record.VerdictAllow, rule: "w",
			payload: record.FSPayload{Op: record.FSOpen, Path: "/p/out.txt", Flags: 0o1101}},
		ctl(3*time.Second, record.GapRunPaused), ctl(4*time.Second, record.GapRunResumed),
		ctl(5*time.Second, record.GapRunPaused), ctl(6*time.Second, record.GapRunResumed),
		ctl(7*time.Second, record.GapLiveBlockAdded),
	}
	lines = append(lines, extra...)
	return append(lines, end(10*time.Second, 0))
}

func coverageFields(rc *Receipt) map[string]string {
	m := map[string]string{}
	for _, g := range rc.Coverage.Gaps {
		m[g.Field] = g.Why
	}
	return m
}

func TestControlGapsAreNoLostActions(t *testing.T) {
	rc := compute(t, pausedAndBlockedRun(), Options{})
	f := coverageFields(rc)
	if _, ok := f["record"]; ok {
		t.Errorf("pause, resume and a live block count as lost actions: %+v", rc.Coverage)
	}
	if rc.Refusals.Total != 1 {
		t.Errorf("refusals = %d, want 1", rc.Refusals.Total)
	}
	// Capture off leaves tokens unrecorded and the stall partial; those notes are the only gaps.
	if len(f) != 2 || f["tokens"] == "" || f["stall"] == "" {
		t.Errorf("coverage = %+v", rc.Coverage)
	}

	// With tokens recorded (capture on, no model call) and no other gap, the receipt is complete.
	lines := pausedAndBlockedRun()
	lines[0] = start("forwarder", true)
	if rc = compute(t, lines, Options{}); !rc.Coverage.Complete {
		t.Errorf("a paused and blocked run is not complete: %+v", rc.Coverage)
	}
}

// TestEveryLiveChangeIsNoLostAction: the receipt and tego status read a gap one way (gaps.Classify), so an MCP tool's
// or a model route's live change is a person's act here too, not "tego knows it missed some actions".
func TestEveryLiveChangeIsNoLostAction(t *testing.T) {
	for _, why := range []string{record.GapMCPToolChanged, record.GapModelRouteChanged, record.GapLiveRuleLifted} {
		g := record.GapPayload{What: record.GapEnforce, Why: why}
		rc := compute(t, pausedAndBlockedRun(line{kind: record.KindGap, at: 8 * time.Second, payload: g}), Options{})
		if got, ok := coverageFields(rc)["record"]; ok {
			t.Errorf("%s reads as a lost action: %q", why, got)
		}
	}
}

func TestLostActionsStillCount(t *testing.T) {
	cases := []struct {
		name string
		gap  record.GapPayload
	}{
		{"channel full", record.GapPayload{What: record.GapRecord, Why: "channel-full"}},
		{"live block lost", record.GapPayload{What: record.GapEnforce, Why: record.GapLiveBlockLost}},
		{"live block unreadable", record.GapPayload{What: record.GapEnforce, Why: record.GapLiveBlockUnreadable}},
		{"unknown", record.GapPayload{What: "plane", Why: "plane-down"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rc := compute(t, pausedAndBlockedRun(line{kind: record.KindGap, at: 8 * time.Second, payload: c.gap}), Options{})
			if got := coverageFields(rc)["record"]; !strings.HasPrefix(got, "1 gap line: tego knows it missed some actions") {
				t.Errorf("record = %q, coverage %+v", got, rc.Coverage)
			}
		})
	}
	// A gap line whose payload does not decode counts, the conservative reading.
	rc := compute(t, pausedAndBlockedRun(line{kind: record.KindGap, at: 8 * time.Second, payload: map[string]any{"what": 7}}), Options{})
	if !strings.HasPrefix(coverageFields(rc)["record"], "1 gap line") {
		t.Errorf("an undecodable gap is not counted: %+v", rc.Coverage)
	}
}

func TestPriceGapIsACostNote(t *testing.T) {
	// A model response that carried no token counts: a model call with no cost the receipt could compute.
	call := line{kind: record.KindSSLResponse, at: 8 * time.Second, payload: map[string]any{"request_seq": 1, "status": 200,
		"parser_version": "1", "model": "m", "latency_ms": 1}}
	for _, why := range []string{gapNoPriceTable, gapPriceVersion} {
		gap := line{kind: record.KindGap, at: 8 * time.Second, payload: record.GapPayload{What: record.GapRecord, Why: why}}
		lines := pausedAndBlockedRun(gap, call)
		lines[0] = start("forwarder", true)
		f := coverageFields(compute(t, lines, Options{}))
		if _, ok := f["record"]; ok || f["tokens.est_cost_usd"] != "no price table: the cost is not estimated" {
			t.Errorf("%s: coverage = %v", why, f)
		}
		// With prices of its own the receipt prices what it can, so the run's missing table is no cost note.
		if f = coverageFields(compute(t, lines, Options{Prices: flatPrices{}})); f["tokens.est_cost_usd"] != "" || f["record"] != "" {
			t.Errorf("%s with prices: coverage = %v", why, f)
		}
		// No model call, or capture off: nothing to price, so no cost note, and no lost action either.
		lines = pausedAndBlockedRun(gap)
		lines[0] = start("forwarder", true)
		if f = coverageFields(compute(t, lines, Options{})); len(f) != 0 {
			t.Errorf("%s without a model call: coverage = %v", why, f)
		}
		if f = coverageFields(compute(t, pausedAndBlockedRun(gap), Options{})); f["tokens.est_cost_usd"] != "" || f["record"] != "" {
			t.Errorf("%s with capture off: coverage = %v", why, f)
		}
	}
	// An unpriced model's gap is neither a lost action nor a second cost note.
	lines := pausedAndBlockedRun(line{kind: record.KindGap, at: 8 * time.Second,
		payload: record.GapPayload{What: record.GapRecord, Why: gapUnpricedModel}})
	lines[0] = start("forwarder", true)
	if f := coverageFields(compute(t, lines, Options{Prices: flatPrices{}})); len(f) != 0 {
		t.Errorf("unpriced-model: coverage = %v", f)
	}
}

func TestCaptureGapMakesTokensAFloor(t *testing.T) {
	gap := line{kind: record.KindGap, at: 8 * time.Second, payload: record.GapPayload{What: record.GapCapture, Why: "no-openssl", Binary: "/usr/bin/gh"}}
	lines := pausedAndBlockedRun(gap)
	lines[0] = start("forwarder", true)
	f := coverageFields(compute(t, lines, Options{}))
	if _, ok := f["record"]; ok || f["tokens.capture"] != "1 capture gap line: model traffic tego could not read, so the token counts are a floor" {
		t.Errorf("coverage = %v", f)
	}
	// Tokens not recorded: the tokens note already says so, and no capture note repeats it.
	f = coverageFields(compute(t, pausedAndBlockedRun(gap), Options{}))
	if _, ok := f["tokens.capture"]; ok || f["tokens"] == "" {
		t.Errorf("capture off: coverage = %v", f)
	}
}

// TestTextNamesTheZoneOfTheTimesItLists: a zone's name belongs to an instant, so a receipt read after a daylight-saving
// change said EST over the EDT times of a run from before it, and one that crossed the change had one word for two
// offsets. The dates are fixed, so one of the two cases fails on any day the heading reads the clock.
func TestTextNamesTheZoneOfTheTimesItLists(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	saved := receiptClock
	t.Cleanup(func() { receiptClock = saved })
	receiptClock = func() *time.Location { return ny }
	text := func(stamps ...time.Time) string {
		t.Helper()
		rc := &Receipt{V: Version, Run: "r-x", Ended: true}
		rc.Refusals.Total = len(stamps)
		for _, ts := range stamps {
			rc.Refusals.List = append(rc.Refusals.List, Refusal{TS: ts, Op: "connect", Target: "127.0.0.1:9722", Rule: "unmatched", Reason: "net-not-allowed"})
			rc.Asks.List = append(rc.Asks.List, Ask{TS: ts, Op: "read", Target: "/p/token", Answer: "approved"})
		}
		rc.Asks.Asked, rc.Asks.Approved = len(stamps), len(stamps)
		var b bytes.Buffer
		if err := rc.Text(&b); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	for _, tc := range []struct {
		at   time.Time
		zone string
	}{{time.Date(2026, 7, 1, 16, 0, 0, 0, time.UTC), "EDT"}, {time.Date(2026, 1, 15, 17, 0, 0, 0, time.UTC), "EST"}} {
		out := text(tc.at)
		for _, want := range []string{"\nRefused actions (times in " + tc.zone + ")\n", "\nTimes it asked you (times in " + tc.zone + ")\n", "    12:00:00  connect"} {
			if !strings.Contains(out, want) {
				t.Errorf("a run at %s lacks %q:\n%s", tc.at, want, out)
			}
		}
	}
	// 01:59:59 EDT, then 01:00:01 EST two seconds later.
	out := text(time.Date(2026, 11, 1, 5, 59, 59, 0, time.UTC), time.Date(2026, 11, 1, 6, 0, 1, 0, time.UTC))
	for _, want := range []string{"\nRefused actions (times in EDT)\n", "    01:59:59  connect", "    01:00:01 EST  connect", "    01:00:01 EST  read"} {
		if !strings.Contains(out, want) {
			t.Errorf("a run across the change lacks %q:\n%s", want, out)
		}
	}
}

func TestTextPrintsTimesInTheReadersZone(t *testing.T) {
	saved := receiptClock
	t.Cleanup(func() { receiptClock = saved })
	edt := time.FixedZone("EDT", -4*3600)
	receiptClock = func() *time.Location { return edt }

	at := time.Date(2026, 10, 27, 13, 49, 3, 0, time.UTC)
	rc := &Receipt{V: Version, Run: "r-x", Ended: true}
	rc.Refusals.Total = 1
	rc.Refusals.ByRule = []RuleCount{{Rule: "unmatched", Reason: "net-not-allowed", Count: 1}}
	rc.Refusals.List = []Refusal{{TS: at, Op: "connect", Target: "127.0.0.1:9722", Rule: "unmatched", Reason: "net-not-allowed"}}
	rc.Asks.Asked, rc.Asks.Approved = 1, 1
	rc.Asks.List = []Ask{{TS: at, Op: "read", Target: "/p/token", Answer: "approved"}}
	var b bytes.Buffer
	if err := rc.Text(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"\nRefused actions (times in EDT)\n", "\nTimes it asked you (times in EDT)\n",
		"    09:49:03  connect 127.0.0.1:9722", "    09:49:03  read /p/token"} {
		if !strings.Contains(out, want) {
			t.Errorf("text lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "13:49:03") {
		t.Errorf("text prints UTC:\n%s", out)
	}
	// The JSON keeps the ledger's UTC.
	b.Reset()
	if err := rc.JSON(&b); err != nil || !strings.Contains(b.String(), "2026-10-27T13:49:03Z") {
		t.Errorf("json: %v\n%s", err, b.String())
	}
}
