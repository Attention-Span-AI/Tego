// SPDX-License-Identifier: Apache-2.0

package mirror

import (
	"fmt"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// refusedConnect is a connect of process pid refused under unmatched, net-not-allowed, captured at mono.
func refusedConnect(pid int, mono uint64) *record.Event {
	return &record.Event{Kind: record.KindNet, PID: pid, TID: pid, MonoNS: mono, Rule: "unmatched",
		Verdict: record.VerdictRefused, Reason: record.ReasonNetNotAllowed}
}

// refusedLine is a refused line with process pid's envelope at mono, under unmatched, net-not-allowed: the mirror of
// refusedConnect(pid, mono), or a refusal of its own.
func refusedLine(pid int, mono uint64) *record.Event {
	return &record.Event{Kind: record.KindRefused, PID: pid, TID: pid, MonoNS: mono, Rule: "unmatched",
		Reason: record.ReasonNetNotAllowed}
}

// write is an allowed write of process pid at mono.
func write(pid int, mono uint64) *record.Event {
	return &record.Event{Kind: record.KindFS, PID: pid, TID: pid, MonoNS: mono, Rule: "fs.write[./out]",
		Verdict: record.VerdictAllow}
}

// TestPairs: each refused line pairs with the refused action whose envelope (pid and monotonic clock), rule and reason
// it copies among the 4 lines before it, each action with one mirror at most, the nearest first; failing that, with
// the line just before it when that is such an action in all but the envelope. want is the seqs of the lines that
// mirror an action.
func TestPairs(t *testing.T) {
	allowed := refusedConnect(7, 200)
	allowed.Verdict, allowed.Reason = record.VerdictAllow, ""
	otherRule := refusedLine(7, 200)
	otherRule.Rule = "fs.deny_read[~/.ssh]"
	otherReason := refusedLine(7, 200)
	otherReason.Reason = record.ReasonAskDenied
	cases := []struct {
		name  string
		lines []*record.Event
		want  []uint64
	}{
		{"a mirror right after its action", []*record.Event{refusedConnect(7, 200), refusedLine(7, 200)}, []uint64{1}},
		{"a line another writer slipped in",
			[]*record.Event{refusedConnect(7, 200), write(9, 210), refusedLine(7, 200)}, []uint64{2}},
		{"three lines slipped in", []*record.Event{refusedConnect(7, 200), write(9, 210), write(9, 220), write(9, 230),
			refusedLine(7, 200)}, []uint64{4}},
		{"its action beyond the window", []*record.Event{refusedConnect(7, 200), write(9, 210), write(9, 220),
			write(9, 230), write(9, 240), refusedLine(7, 200)}, nil},
		// Two refusals written before either mirror: each mirror takes the action whose envelope it copies, not the
		// line just before it, so the second mirror still finds its own action.
		{"two refusals before either mirror", []*record.Event{refusedConnect(7, 200), refusedConnect(8, 210),
			refusedLine(7, 200), refusedLine(8, 210)}, []uint64{2, 3}},
		{"their mirrors the other way round", []*record.Event{refusedConnect(7, 200), refusedConnect(8, 210),
			refusedLine(8, 210), refusedLine(7, 200)}, []uint64{2, 3}},
		// An action whose envelope matches is taken before the line just before it: the first refused line takes the
		// action at seq 0, so the second, with the same envelope, finds none left and is a refusal of its own.
		{"the envelope before adjacency", []*record.Event{refusedConnect(7, 200), refusedConnect(8, 210),
			refusedLine(7, 200), refusedLine(7, 200)}, []uint64{2}},
		// A mirror whose writer stamped a clock of its own, or none: the line just before it is its action.
		{"another clock: the line just before", []*record.Event{refusedConnect(7, 200), refusedLine(7, 201)}, []uint64{1}},
		{"another clock and a line between",
			[]*record.Event{refusedConnect(7, 200), write(9, 210), refusedLine(7, 201)}, nil},
		{"no clock: the line just before", []*record.Event{refusedConnect(7, 0), refusedLine(7, 0)}, []uint64{1}},
		{"no clock and a line between", []*record.Event{refusedConnect(7, 0), write(9, 210), refusedLine(7, 0)}, nil},
		{"another process", []*record.Event{refusedConnect(7, 200), write(9, 210), refusedLine(8, 200)}, nil},
		// An action has one mirror: a second refused line copying its envelope is a refusal of its own.
		{"one mirror per action", []*record.Event{refusedConnect(7, 200), refusedLine(7, 200), refusedLine(7, 200)},
			[]uint64{1}},
		{"under another rule", []*record.Event{refusedConnect(7, 200), otherRule}, nil},
		{"for another reason", []*record.Event{refusedConnect(7, 200), otherReason}, nil},
		{"after an allowed action", []*record.Event{allowed, refusedLine(7, 200)}, nil},
		{"after a refused line", []*record.Event{refusedLine(7, 200), refusedLine(7, 200)}, nil},
		{"a refused line on its own", []*record.Event{write(9, 210), refusedLine(7, 200)}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var p Pairs
			var got []uint64
			for i, l := range tc.lines {
				e := *l
				e.Seq = uint64(i)
				if p.Take(&e) {
					got = append(got, e.Seq)
				}
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("mirrors at %v, want %v", got, tc.want)
			}
		})
	}
}
