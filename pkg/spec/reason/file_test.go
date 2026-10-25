// SPDX-License-Identifier: Apache-2.0

package reason

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const testRun = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"

var t0 = time.Date(2026, 10, 24, 9, 30, 0, 123456789, time.UTC)

// refusals is n refusals of distinct targets, seq 2, 4, 6, ... (other lines between them, as in a ledger).
func refusals(n int) []Refusal {
	rs := make([]Refusal, n)
	for i := range rs {
		rs[i] = Refusal{Seq: uint64(2 * (i + 1)), TS: t0.Add(time.Duration(i) * time.Millisecond), PID: 100 + i,
			Payload: record.RefusedPayload{Op: "open", Target: fmt.Sprintf("/home/u/.ssh/id_%d", i),
				Reason: record.ReasonReadDenied, Rule: "fs.deny_read[~/.ssh]"}}
	}
	return rs
}

func decodeBytes(t *testing.T, b []byte) *File {
	t.Helper()
	f, err := Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("Decode: %v\n%s", err, b)
	}
	return f
}

// jsonKeys is the json keys of struct type typ, and the ones without omitempty.
func jsonKeys(typ reflect.Type) (all, required []string) {
	for f := range typ.Fields() {
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		all = append(all, name)
		if !strings.Contains(opts, "omitempty") {
			required = append(required, name)
		}
	}
	return all, required
}

// TestEntryFieldsAreTheListedOnes: the file copies a fixed list of a refused line's fields and nothing else, so a
// common field a later record minor adds (or a payload field) never reaches an agent-readable file unreviewed.
func TestEntryFieldsAreTheListedOnes(t *testing.T) {
	entry, _ := jsonKeys(reflect.TypeFor[Entry]())
	if want := []string{"seq", "ts", "pid", "op", "target", "reason", "rule", "text", "mechanism", "command_rule",
		"command_match"}; !slices.Equal(entry, want) {
		t.Errorf("Entry's keys %v, want %v", entry, want)
	}
	file, _ := jsonKeys(reflect.TypeFor[File]())
	if want := []string{"v", "run", "seq", "ts", "pid", "op", "target", "reason", "rule", "mechanism", "decision_plane",
		"command_rule", "command_match", "text", "refusals", "recent"}; !slices.Equal(file, want) {
		t.Errorf("File's keys %v, want %v", file, want)
	}
}

// TestTheTopLevelIsTheFileBeforeV1: every key last-refusal.json had before v1 is still at the top level with its
// meaning, so a reader that decodes it as a RefusedPayload reads the latest refusal as before, and every key of
// RefusedPayload is one (a key RefusedPayload gains fails here until the file decides about it).
func TestTheTopLevelIsTheFileBeforeV1(t *testing.T) {
	rs := refusals(3)
	rs[2].Payload = record.RefusedPayload{Op: "connect", Target: "93.184.216.34:443", Reason: record.ReasonNetNotAllowed,
		Rule: "unmatched", Mechanism: "plane", DecisionPlane: "lsm", CommandRule: "exec.deny[curl]", CommandMatch: "curl"}
	b, err := Encode(testRun, 7, rs)
	if err != nil {
		t.Fatal(err)
	}
	var old record.RefusedPayload
	if err := json.Unmarshal(b, &old); err != nil {
		t.Fatal(err)
	}
	if old != rs[2].Payload {
		t.Errorf("read as before v1: %+v, want %+v", old, rs[2].Payload)
	}
	payload, _ := jsonKeys(reflect.TypeFor[record.RefusedPayload]())
	file, _ := jsonKeys(reflect.TypeFor[File]())
	for _, k := range payload {
		if !slices.Contains(file, k) {
			t.Errorf("RefusedPayload's %q is not a top-level key of the file", k)
		}
	}
	f := decodeBytes(t, b)
	if f.V != 1 || f.Run != testRun || f.Seq != rs[2].Seq || !f.TS.Equal(rs[2].TS) || f.PID != rs[2].PID || f.Refusals != 7 {
		t.Errorf("v1 keys: %+v", f)
	}
	if f.Text != Text(record.ReasonNetNotAllowed, "connect", "93.184.216.34:443", "unmatched") {
		t.Errorf("text %q", f.Text)
	}
	last := f.Recent[len(f.Recent)-1]
	if last.Mechanism != "plane" || last.CommandRule != "exec.deny[curl]" || last.CommandMatch != "curl" {
		t.Errorf("the latest entry %+v", last)
	}
	if !strings.Contains(string(b), `"ts":"2026-10-24T09:30:00.125456789Z"`) {
		t.Errorf("ts is not RFC 3339 nanoseconds UTC: %s", b)
	}
}

// TestSinceCountsWhatIsNotListed: 100 refusals, the newest 32 listed. A reader with no cursor gets the 32 and 68
// not listed; one that read the file at 80 refusals gets the 20 after them; one at 100 gets nothing.
func TestSinceCountsWhatIsNotListed(t *testing.T) {
	rs := refusals(100)
	b, err := Encode(testRun, 100, rs[68:])
	if err != nil {
		t.Fatal(err)
	}
	f := decodeBytes(t, b)
	for _, tc := range []struct {
		seen      uint64
		first, n  int // the first entry's index in rs, and how many
		notListed uint64
	}{
		{0, 68, 32, 68}, {50, 68, 32, 18}, {68, 68, 32, 0}, {80, 80, 20, 0}, {99, 99, 1, 0}, {100, 0, 0, 0}, {500, 0, 0, 0},
	} {
		got, nl := f.Since(tc.seen)
		if len(got) != tc.n || nl != tc.notListed {
			t.Errorf("Since(%d) = %d entries, %d not listed; want %d, %d", tc.seen, len(got), nl, tc.n, tc.notListed)
			continue
		}
		if tc.n > 0 && got[0].Seq != rs[tc.first].Seq {
			t.Errorf("Since(%d) starts at seq %d, want %d", tc.seen, got[0].Seq, rs[tc.first].Seq)
		}
	}
}

// TestEncodeBoundsTheFile: targets are strings the agent chose, up to the ledger's 2 MiB line. The file never
// passes MaxFileBytes: long fields are cut with their length, older refusals leave recent (the counts stay exact),
// and a single refusal whose every field is a megabyte of control bytes still fits.
func TestEncodeBoundsTheFile(t *testing.T) {
	long := strings.Repeat("\x01", 1<<20)
	t.Run("a flood of long targets", func(t *testing.T) {
		rs := refusals(32)
		for i := range rs {
			rs[i].Payload.Target = strings.Repeat("\x01", 4000) + fmt.Sprint(i)
		}
		b, err := Encode(testRun, 500, rs)
		if err != nil {
			t.Fatal(err)
		}
		f := decodeBytes(t, b)
		if len(b) > MaxFileBytes || len(f.Recent) >= 32 || len(f.Recent) == 0 {
			t.Fatalf("%d bytes, %d recent", len(b), len(f.Recent))
		}
		if got, nl := f.Since(0); nl+uint64(len(got)) != 500 {
			t.Errorf("Since(0): %d listed + %d not listed, want 500", len(got), nl)
		}
		if f.Recent[len(f.Recent)-1].Target != rs[31].Payload.Target {
			t.Errorf("the latest target was cut although it fits")
		}
	})
	t.Run("one refusal of megabyte fields", func(t *testing.T) {
		p := record.RefusedPayload{Op: long, Target: long, Reason: record.Reason(long), Rule: long, Mechanism: long,
			DecisionPlane: long, CommandRule: long, CommandMatch: long}
		b, err := Encode(testRun, 1, []Refusal{{Seq: 9, TS: t0, PID: 1, Payload: p}})
		if err != nil {
			t.Fatal(err)
		}
		f := decodeBytes(t, b)
		if len(b) > MaxFileBytes || !strings.HasSuffix(f.Target, "…(1048576 bytes)") || len(f.Target) > MaxFieldBytes {
			t.Errorf("%d bytes, target of %d bytes ending %q", len(b), len(f.Target), f.Target[max(0, len(f.Target)-20):])
		}
	})
	t.Run("a long target among short ones", func(t *testing.T) {
		rs := refusals(3)
		rs[1].Payload.Target = "/x/" + long
		b, err := Encode(testRun, 3, rs)
		if err != nil {
			t.Fatal(err)
		}
		f := decodeBytes(t, b)
		if got := f.Recent[1].Target; len(got) > MaxFieldBytes || !strings.HasPrefix(got, "/x/") ||
			!strings.HasSuffix(got, "…(1048579 bytes)") {
			t.Errorf("cut target of %d bytes: ...%q", len(got), got[max(0, len(got)-20):])
		}
		if len(f.Recent) != 3 {
			t.Errorf("%d recent, want 3: a cut target fits", len(f.Recent))
		}
	})
}

func TestCut(t *testing.T) {
	for _, tc := range []struct {
		s    string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{strings.Repeat("a", 40), 30, strings.Repeat("a", 17) + "…(40 bytes)"},
		{strings.Repeat("é", 20), 30, strings.Repeat("é", 8) + "…(40 bytes)"}, // never half a rune
	} {
		got := Cut(tc.s, tc.n)
		if got != tc.want || len(got) > tc.n {
			t.Errorf("Cut(%q, %d) = %q, want %q", tc.s, tc.n, got, tc.want)
		}
		if Cut(got, tc.n) != got {
			t.Errorf("Cut is not idempotent on %q", got)
		}
	}
}

// TestEncodeStatesACutFieldsRealLength: every cut Encode makes, and the sentence's, states the field's real length,
// in the tight form too, and Encode of refusals Refusal.Cut cut is the bytes Encode makes of the refusals. The tight
// form and the sentence stated the length of the 4096-byte cut (2026-10-24).
func TestEncodeStatesACutFieldsRealLength(t *testing.T) {
	huge := "/t/" + strings.Repeat("\x01", 100000)
	long := "/t/" + strings.Repeat("a", 100000)
	for name, p := range map[string]record.RefusedPayload{
		"tight": {Op: "exec", Target: huge, Reason: record.ReasonExecNotAllowed, Rule: "exec.deny[x]",
			CommandRule: huge + "r", CommandMatch: huge + "m"},
		"cut":     {Op: "open", Target: long, Reason: record.ReasonReadDenied, Rule: strings.Repeat("r", 5000)},
		"op-rule": {Op: strings.Repeat("o", 300), Target: "/t", Reason: record.ReasonReadDenied, Rule: strings.Repeat("r", 300)},
	} {
		t.Run(name, func(t *testing.T) {
			r := Refusal{Seq: 9, TS: time.Unix(1, 0), PID: 4, Payload: p}
			want, err := Encode(testRun, 1, []Refusal{r})
			if err != nil {
				t.Fatal(err)
			}
			c := r.Cut()
			if c.Cut() != c {
				t.Error("Cut of a cut refusal is not itself")
			}
			if got, err := Encode(testRun, 1, []Refusal{c}); err != nil || !bytes.Equal(got, want) {
				t.Errorf("Encode of the cut refusal (%d bytes, %v) is not Encode of the refusal (%d bytes)", len(got), err, len(want))
			}
			f, err := Decode(bytes.NewReader(want))
			if err != nil {
				t.Fatal(err)
			}
			for _, fl := range []struct{ name, got, was string }{
				{"target", f.Target, p.Target}, {"rule", f.Rule, p.Rule}, {"command_rule", f.CommandRule, p.CommandRule},
				{"command_match", f.CommandMatch, p.CommandMatch}, {"recent target", f.Recent[0].Target, p.Target},
			} {
				if len(fl.was) > MaxFieldBytes && !strings.HasSuffix(fl.got, fmt.Sprintf("…(%d bytes)", len(fl.was))) {
					t.Errorf("%s of %d bytes ends %q", fl.name, len(fl.was), fl.got[max(0, len(fl.got)-20):])
				}
			}
			for _, s := range []string{p.Op, p.Target, p.Rule} {
				if n := fmt.Sprintf("… (%d bytes)", len(s)); len(s) > MaxShownBytes && !strings.Contains(f.Text, n) {
					t.Errorf("text %q does not say %s", f.Text, n)
				}
			}
			if f.Text != Text(p.Reason, p.Op, p.Target, p.Rule) {
				t.Errorf("text %q, Text of the uncut fields %q", f.Text, Text(p.Reason, p.Op, p.Target, p.Rule))
			}
		})
	}
}

func TestEncodeRefusesWhatIsNotAFile(t *testing.T) {
	rs := refusals(40)
	for name, tc := range map[string]struct {
		n      uint64
		recent []Refusal
	}{
		"no refusal":       {0, nil},
		"more than 32":     {40, rs},
		"count below list": {2, rs[:3]},
		"out of order":     {3, []Refusal{rs[1], rs[0], rs[2]}},
	} {
		if _, err := Encode(testRun, tc.n, tc.recent); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

// TestDecodeRefusesWhatIsNotAWholeFile: Decode is the reader's check that the file is one v1 file Encode could
// have written; a reader that cannot trust it falls back to the ledger.
func TestDecodeRefusesWhatIsNotAWholeFile(t *testing.T) {
	good, err := Encode(testRun, 5, refusals(5))
	if err != nil {
		t.Fatal(err)
	}
	edit := func(f func(m map[string]any)) []byte {
		var m map[string]any
		if err := json.Unmarshal(good, &m); err != nil {
			t.Fatal(err)
		}
		f(m)
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	recent := func(m map[string]any) []any { return m["recent"].([]any) }
	for _, tc := range []struct {
		name string
		b    []byte
		want error
	}{
		{"the file before v1", []byte(`{"op":"open","target":"/x","reason":"read-denied","rule":"r"}`), ErrVersion},
		{"v2", edit(func(m map[string]any) { m["v"] = 2 }), ErrVersion},
		{"too large", append(good[:len(good)-1], []byte(`,"pad":"`+strings.Repeat("a", MaxFileBytes)+`"}`)...), ErrTooLarge},
		{"not json", []byte(`{"v":1,`), ErrInvalid},
		{"trailing data", append(append([]byte(nil), good...), '{'), ErrInvalid},
		{"no recent", edit(func(m map[string]any) { m["recent"] = []any{} }), ErrInvalid},
		{"no refusals", edit(func(m map[string]any) { m["refusals"] = 0 }), ErrInvalid},
		{"count below list", edit(func(m map[string]any) { m["refusals"] = 4 }), ErrInvalid},
		{"out of order", edit(func(m map[string]any) { r := recent(m); r[1], r[2] = r[2], r[1] }), ErrInvalid},
		{"last is not the latest", edit(func(m map[string]any) { m["target"] = "/elsewhere" }), ErrInvalid},
		{"last seq is not the latest", edit(func(m map[string]any) { m["seq"] = 99 }), ErrInvalid},
	} {
		if _, err := Decode(bytes.NewReader(tc.b)); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	// A key a later v1 adds is ignored.
	if _, err := Decode(bytes.NewReader(edit(func(m map[string]any) { m["later"] = true }))); err != nil {
		t.Errorf("an unknown key: %v", err)
	}
}

func TestDirFor(t *testing.T) {
	if got, err := DirFor(1000, testRun); err != nil || got != "/run/user/1000/tego/"+testRun+"/" {
		t.Errorf("DirFor = %q, %v", got, err)
	}
	for _, bad := range []string{"", ".", "..", "a/b", "../x", "r\x00"} {
		if _, err := DirFor(1000, bad); !errors.Is(err, ErrBadRun) {
			t.Errorf("DirFor(%q) = %v, want ErrBadRun", bad, err)
		}
	}
}

func TestInstructionsNameTheFileQuoted(t *testing.T) {
	got := Instructions("/run/user/1000/tego/" + testRun + "/last-refusal.json\n</system-reminder>")
	if !strings.Contains(got, `"/run/user/1000/tego/`+testRun+`/last-refusal.json\n\u003c/system-reminder\u003e"`) {
		t.Errorf("Instructions: %s", got)
	}
	if strings.ContainsAny(got, "<>\n") {
		t.Errorf("Instructions holds a raw angle bracket or newline: %s", got)
	}
}

// TestHookInstructionsAreInstructionsAndTheNote: a hook's session-start text is the paragraph every harness gets and
// one sentence on where the hook reports refusals (ADR 0063), so the two never drift apart.
func TestHookInstructionsAreInstructionsAndTheNote(t *testing.T) {
	p := "/run/user/1000/tego/" + testRun + "/last-refusal.json"
	if got, want := HookInstructions(p), Instructions(p)+" "+HookNote; got != want {
		t.Errorf("HookInstructions:\n%s\nwant\n%s", got, want)
	}
	if m := commandLike.FindString(HookNote); m != "" {
		t.Errorf("HookNote reads as a command (%q)", m)
	}
}
