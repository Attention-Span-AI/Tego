// SPDX-License-Identifier: Apache-2.0

package reason

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// FuzzDecode: Decode never panics, refuses anything past MaxFileBytes, and what it accepts holds its invariants,
// so Since and Render over it cannot index out of range or pass their bounds.
func FuzzDecode(f *testing.F) {
	good, err := Encode(testRun, 100, refusals(32))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte(`{"op":"open","target":"/x","reason":"read-denied","rule":"r"}`))
	f.Add([]byte(`{"v":1,"seq":1,"refusals":1,"recent":[{"seq":1}]}`))
	f.Add([]byte(`{"v":1,"seq":1,"refusals":18446744073709551615,"recent":[{"seq":1}]}`))
	f.Add(bytes.Repeat([]byte(" "), MaxFileBytes+1))
	f.Fuzz(func(t *testing.T, b []byte) {
		file, err := Decode(bytes.NewReader(b))
		if len(b) > MaxFileBytes {
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("%d bytes decoded: %v", len(b), err)
			}
			return
		}
		if err != nil {
			return
		}
		if len(file.Recent) == 0 || len(file.Recent) > RingSize || uint64(len(file.Recent)) > file.Refusals {
			t.Fatalf("accepted %d recent of %d refusals", len(file.Recent), file.Refusals)
		}
		for _, seen := range []uint64{0, 1, file.Refusals / 2, file.Refusals - 1, file.Refusals, file.Refusals + 1} {
			es, nl := file.Since(seen)
			if seen < file.Refusals && uint64(len(es))+nl != file.Refusals-seen {
				t.Fatalf("Since(%d) = %d + %d, want %d", seen, len(es), nl, file.Refusals-seen)
			}
			if out := Render(es, nl); len(out) > MaxRenderBytes {
				t.Fatalf("Render: %d bytes", len(out))
			}
		}
	})
}

// FuzzEncodeFits: whatever strings a refusal holds, Encode's file is at most MaxFileBytes and Decode accepts it.
func FuzzEncodeFits(f *testing.F) {
	f.Add("open", "/home/u/.ssh/id", "fs.deny_read[~/.ssh]", "", 1, 3)
	f.Add("connect", strings.Repeat("\x01", 70000), strings.Repeat("<", 5000), "curl", 32, 4000)
	f.Fuzz(func(t *testing.T, op, target, rule, match string, n, grow int) {
		n = 1 + abs(n)%RingSize
		rs := refusals(n)
		for i := range rs {
			rs[i].Payload = record.RefusedPayload{Op: op, Target: target + strings.Repeat("x", abs(grow)%20000),
				Reason: record.ReasonReadDenied, Rule: rule, CommandMatch: match}
		}
		b, err := Encode(testRun, uint64(n)+7, rs)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > MaxFileBytes {
			t.Fatalf("%d bytes", len(b))
		}
		if _, err := Decode(bytes.NewReader(b)); err != nil {
			t.Fatalf("Decode of Encode's file: %v", err)
		}
		// A writer holds refusals cut (Refusal.Cut); its file is the one Encode makes of them uncut.
		cut := make([]Refusal, len(rs))
		for i := range rs {
			cut[i] = rs[i].Cut()
		}
		if c, err := Encode(testRun, uint64(n)+7, cut); err != nil || !bytes.Equal(c, b) {
			t.Fatalf("Encode of the cut refusals (%d bytes, %v) is not Encode of the refusals (%d bytes)", len(c), err, len(b))
		}
		// MinEntryBytes never says more than an entry takes, so a writer that stops decoding on it lists the same.
		for i, e := range build(testRun, uint64(n)+7, rs, MaxFieldBytes).Recent {
			eb, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			if m := MinEntryBytes(rs[i].Payload); m > len(eb) {
				t.Fatalf("MinEntryBytes %d, the entry takes %d", m, len(eb))
			}
		}
	})
}

func abs(n int) int {
	if n < 0 {
		return -(n + 1)
	}
	return n
}
