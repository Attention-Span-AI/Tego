// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func oversizeLine(at time.Duration, why, server string, size, limit int64) line {
	return line{kind: record.KindGap, at: at, payload: record.GapPayload{What: record.GapRecord, Why: why,
		Binary: record.OversizeNote(server, size, limit)}}
}

// TestDroppedMCPMessagesShowInTheReceipt (GAPS C201, C202): a message the MCP relay dropped for its size is a gap line, and
// the receipt says so with the server, the size and the limit, in its coverage. No action went unrecorded, so the
// counts are no floor.
func TestDroppedMCPMessagesShowInTheReceipt(t *testing.T) {
	lines := pausedAndBlockedRun(
		oversizeLine(8*time.Second, record.GapMCPResponseOversize, "files", 9_000_000, 8_388_608),
		oversizeLine(9*time.Second, record.GapMCPStreamOversize, "web", 12_000_000, 8_388_608),
		// the counted line a run writes for the messages past its lines
		line{kind: record.KindGap, at: 9 * time.Second, payload: record.GapPayload{What: record.GapRecord,
			Why: record.GapMCPStreamOversize, Count: 3}})
	lines[0] = start("forwarder", true)
	rc := compute(t, lines, Options{})
	if rc.Coverage.Complete {
		t.Fatalf("a run that dropped messages is complete: %+v", rc.Coverage)
	}
	var got string
	for _, g := range rc.Coverage.Gaps {
		switch g.Field {
		case "record.mcp":
			if g.Code != CodeMessagesDropped {
				t.Errorf("code %q", g.Code)
			}
			got = g.Why
		case "record":
			t.Errorf("a dropped message reads as a missed action: %+v", g)
		}
	}
	for _, want := range []string{"5 MCP messages", "12000000 bytes", `"web"`, "8388608 bytes", "no action went unrecorded"} {
		if !strings.Contains(got, want) {
			t.Errorf("coverage %q lacks %q", got, want)
		}
	}
	var out bytes.Buffer
	if err := rc.Text(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "record.mcp (partial): 5 MCP messages") {
		t.Errorf("the text receipt does not say it:\n%s", out.String())
	}
}

// TestDatagramSendsAreCountedApartFromConnects (GAPS C172): a UDP connect sends nothing and a datagram does, and the
// receipt tells them apart: connection_tries still counts every attempt, datagram_sends says how many of them sent, and
// each place says how many of its attempts were sends. A ledger from before the op counts a send as a connect.
func TestDatagramSendsAreCountedApartFromConnects(t *testing.T) {
	net := func(at time.Duration, op, dst string) line {
		return line{kind: record.KindNet, at: at, verdict: record.VerdictAllow, rule: "net.allow[udp://203.0.113.9:53]",
			payload: record.NetPayload{Op: op, Proto: "udp", Dst: dst}}
	}
	rc := compute(t, []line{
		start("off", true),
		net(time.Second, "", "203.0.113.9:53"), // a connect
		net(2*time.Second, record.NetOpSend, "203.0.113.9:53"),
		net(3*time.Second, record.NetOpSend, "203.0.113.9:53"),
		net(4*time.Second, record.NetOpSend, "203.0.113.7:9999"), // a place only ever sent to
		end(5*time.Second, 0),
	}, Options{})
	if rc.ConnectionTries != 4 || rc.DatagramSends != 3 {
		t.Fatalf("tries %d sends %d, want 4 and 3", rc.ConnectionTries, rc.DatagramSends)
	}
	sends := map[string]int{}
	for _, c := range rc.Connections {
		sends[c.Destination] = c.Sends
		if c.Destination == "203.0.113.9:53" && c.Count != 3 {
			t.Errorf("%+v: count %d, want connects and sends together", c, c.Count)
		}
	}
	if sends["203.0.113.9:53"] != 2 || sends["203.0.113.7:9999"] != 1 {
		t.Fatalf("sends by place %v", sends)
	}
	if got, want := rc.ConnectionSummary(), "4 connections to 2 places (3 sent a UDP datagram, 1 only connected)."; got != want {
		t.Errorf("summary %q, want %q", got, want)
	}
	// Before the op: the same attempts, no way to tell, no claim.
	old := compute(t, []line{start("off", true), net(time.Second, "", "203.0.113.9:53"), net(2*time.Second, "", "203.0.113.9:53"), end(3*time.Second, 0)}, Options{})
	if old.ConnectionTries != 2 || old.DatagramSends != 0 || strings.Contains(old.ConnectionSummary(), "datagram") {
		t.Errorf("a ledger without the op: %+v / %q", old.ConnectionTries, old.ConnectionSummary())
	}
}
