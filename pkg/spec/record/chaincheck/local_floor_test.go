// SPDX-License-Identifier: Apache-2.0

package chaincheck_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
	"github.com/attention-span-ai/tego/pkg/spec/record/chaincheck"
)

// floorRun lines a run of a run_start (with or without the root-only floor) and one answer, chained, with
// the answer's payload as given; ValidateAt alone accepts every line, only the run's floor can tell them apart.
func floorRun(t *testing.T, floor bool, answer string) [][]byte {
	t.Helper()
	start := `{"record_minor":37,"tier":"landlock"`
	if floor {
		start += `,"local_approval_authority":{"mode":"owner_only","sha256":"` + strings.Repeat("ab", 32) + `","agent_uid":1001}`
	}
	var lines [][]byte
	prev := ""
	for i, c := range []struct {
		kind    record.Kind
		payload string
	}{{record.KindRunStart, start + `}`}, {record.KindAnswer, answer}} {
		e := &record.Event{V: record.Version, Seq: uint64(i), Prev: prev, TS: time.Unix(10+int64(i), 0).UTC(), MonoNS: uint64(1 + i), Run: "r-00000000-000000000000a-aaaaaa", Agent: "test",
			Kind: c.kind, Source: record.SourceSupervisor, Payload: json.RawMessage(c.payload)}
		line, err := e.MarshalLineAt(37)
		if err != nil {
			t.Fatal(err)
		}
		prev = e.ID
		lines = append(lines, line)
	}
	return lines
}

const (
	rootAnswer  = `{"ask_id":"q-local","approved":true,"by":"uid:0 pid:42","actor":{"uid":0,"pid":42,"start_boot_ns":10,"user_namespace":4026531837,"source":"kernel-local-uid","role":"owner"}}`
	causeAnswer = `{"ask_id":"q-local","approved":false,"by":"timeout","answer_reason":"ask-timeout","system_cause":"timeout"}`
	plainAnswer = `{"ask_id":"q-local","approved":true,"by":"uid:1000"}`
	plainDenied = `{"ask_id":"q-local","approved":false,"by":"uid:1000","answer_reason":"ask-denied"}`
)

// An answer is held to its run's floor: an actor or system cause only in a run whose run_start carries the floor,
// and every answer of such a run carries one.
func TestLineCheckHoldsAnswersToTheRunsFloor(t *testing.T) {
	for _, c := range []struct {
		name   string
		floor  bool
		answer string
		ok     bool
	}{
		{"root answer under the floor", true, rootAnswer, true},
		{"system cause under the floor", true, causeAnswer, true},
		{"unattributed answer under the floor", true, plainAnswer, false},
		{"unattributed denial under the floor", true, plainDenied, false},
		{"root answer in a run without the floor", false, rootAnswer, false},
		{"system cause in a run without the floor", false, causeAnswer, false},
		{"plain answer in a run without the floor", false, plainAnswer, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			lc := chaincheck.LineCheck{Validate: true}
			var err error
			for _, line := range floorRun(t, c.floor, c.answer) {
				if _, _, err = lc.Add(line); err != nil {
					break
				}
			}
			if (err == nil) != c.ok {
				t.Fatalf("verify: %v, want ok=%v", err, c.ok)
			}
		})
	}
}
