// SPDX-License-Identifier: Apache-2.0

package record

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// This file pins the R/E/I numbers of docs/p0/record-ledger.md §2.1 that a careful reading of line_test.go,
// payload_test.go and fixture_test.go found genuinely unpinned. Everything else in that section's R1-R8,
// I3/I4/I9/I10 is already exercised (canonical order, id computation and tamper detection, payload splicing,
// unknown-field tolerance, the version gate's existence, attribution presence, the hash chain, the closed
// sets) by the existing tests; duplicating those here would not catch anything a break of the same code
// wouldn't already be caught by.

// TestMarshalLineNeverOmitsAlwaysPresentZeroFields pins E20 ("cgroup id is 0 or absent. Recorded as 0;
// downstream treats it as unknown, never a valid zero id") and, by the same R1 contract, the same guarantee
// for pid/tid/mono_ns: none of R1's always-present fields carry `omitempty`, unlike rule/verdict/authority/
// reason/attribution. The existing TestMarshalLineOmitsZeroOptionalFields only ever exercises non-zero
// pid/tid/cgroup, so a regression that accidentally dropped one of them at zero (the exact shape of the bug
// this test is written against) would pass every test in line_test.go undetected.
func TestMarshalLineNeverOmitsAlwaysPresentZeroFields(t *testing.T) {
	e := base(KindGap, `{"why":"x"}`)
	e.PID, e.TID, e.Cgroup, e.MonoNS = 0, 0, 0, 0
	line := mustLine(t, e)
	for _, want := range []string{`"pid":0`, `"tid":0`, `"cgroup":0`, `"mono_ns":0`} {
		if !bytes.Contains(line, []byte(want)) {
			t.Errorf("zero-value always-present field dropped: want %s in %s", want, line)
		}
	}
}

// TestMarshalLineIDDependsOnSeq pins E4 ("Two events identical down to the nanosecond. Still get distinct
// ids -- seq differs and is hashed"). Two events built identically except for Seq, sharing the same (bogus
// but shape-valid) Prev so chain linkage can't be the thing that makes the ids differ, must still hash to
// different ids: seq itself has to be part of what MarshalLine feeds sha256. A 3-event TestChain already
// exists, but there prev necessarily differs alongside seq, so it never isolates seq's own contribution to
// the digest the way this test does.
func TestMarshalLineIDDependsOnSeq(t *testing.T) {
	mk := func(seq uint64) *Event {
		e := action(KindFS, `{"op":"open","path":"/x"}`)
		e.Seq = seq
		e.Prev = strings.Repeat("a", IDLen) // same prev on both; only seq differs
		return e
	}
	e1, e2 := mk(5), mk(6)
	l1, l2 := mustLine(t, e1), mustLine(t, e2)
	if e1.ID == e2.ID {
		t.Fatalf("events differing only in seq (5 vs 6) got the same id %s", e1.ID)
	}
	if bytes.Equal(l1, l2) {
		t.Fatalf("lines differing only in seq must not be byte-identical")
	}
}

// TestDecodeVersionGateCheckedBeforeOtherFields pins R5's ordering clause: "v is checked first; anything but
// 1 returns ErrUnsupportedVersion before any other field is read." Every existing TestDecodeErrors case has
// exactly one thing wrong with the line, so none of them can tell an implementation that checks the version
// first from one that happens to reach the same verdict after parsing other fields too. This line has two
// independent problems (v=2 and a non-numeric pid); only ErrUnsupportedVersion is a pass, because that's the
// one the gate must report before pid is ever looked at.
func TestDecodeVersionGateCheckedBeforeOtherFields(t *testing.T) {
	good := string(mustLine(t, base(KindGap, `{"why":"x"}`)))
	bad := strings.Replace(good, `{"v":1,`, `{"v":2,`, 1)
	bad = strings.Replace(bad, `"pid":4242`, `"pid":"bad"`, 1)
	if bad == good {
		t.Fatal("test setup: replacements did not apply")
	}
	if _, err := Decode([]byte(bad)); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("err = %v, want ErrUnsupportedVersion (the version gate must run before pid is parsed)", err)
	}
}

// TestDecodeResortsNonCanonicalPayloadKeys pins I9's parenthetical: decoding reproduces every field "except
// Payload, which returns spliced-and-resorted, not necessarily byte-identical for non-canonical input key
// order -- expected, tested explicitly." MarshalLine can never itself produce an out-of-order payload (it
// always sorts on the way out), so every other round-trip test in this package only ever feeds Decode bytes
// that were already canonical. This test hand-splices a payload key ahead of one that sorts earlier than it,
// the shape a foreign writer or hand-built fixture could produce, and checks Decode hands back the resorted
// object rather than echoing the wire's literal order.
func TestDecodeResortsNonCanonicalPayloadKeys(t *testing.T) {
	orig := mustLine(t, base(KindGap, `{"why":"x"}`))
	raw := bytes.Replace(orig, []byte(`"why":"x"}`), []byte(`"zeta":2,"why":"x"}`), 1)
	if bytes.Equal(raw, orig) {
		t.Fatal("test setup: splice did not apply")
	}
	got, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if want := `{"why":"x","zeta":2}`; string(got.Payload) != want {
		t.Fatalf("Payload = %s, want resorted %s (wire order was zeta, why)", got.Payload, want)
	}
}

// TestAttributionByKindAndP0Writers pins record-ledger.md R8. Attr is populated for exactly the four action
// kinds (exec, fs, net, mcp) and refused on every other kind. A P0 writer's constructors give only
// {unattributed,none} or {likely,time,Step:N}; the P1 forms (exact, tool_id, tid) are never produced by them,
// though Decode accepts a line that carries one.
func TestAttributionByKindAndP0Writers(t *testing.T) {
	for _, k := range Kinds {
		e := perKind(t)[k]
		if e == nil {
			continue
		}
		if want := k.IsAction(); (e.Attr != nil) != want {
			t.Errorf("%s: Attr present = %v, want %v", k, e.Attr != nil, want)
		}
		if k.IsAction() {
			e.Attr = nil
		} else {
			e.Attr = Unattributed()
		}
		if err := e.Validate(); err == nil {
			t.Errorf("%s: Validate accepted the wrong attribution presence", k)
		}
	}
	if u := Unattributed(); u.Confidence != "unattributed" || u.Method != "none" || u.Thread != "" || u.Step != 0 {
		t.Errorf("Unattributed() = %+v, want {unattributed,none}", u)
	}
	if a := AttributedByTime("t1", 3); a.Confidence != "likely" || a.Method != "time" || a.Step != 3 {
		t.Errorf("AttributedByTime() = %+v, want {likely,time,Step:3}", a)
	}
	for _, p1 := range []*Attribution{
		{Thread: "t1", Step: 1, Confidence: "exact", Method: "tool_id"},
		{Thread: "t1", Step: 1, Confidence: "exact", Method: "tid"},
	} {
		e := action(KindFS, `{"op":"open","path":"/x"}`)
		e.Attr = p1
		line, err := e.MarshalLine()
		if err != nil {
			t.Fatalf("MarshalLine %+v: %v", p1, err)
		}
		got, err := Decode(line)
		if err != nil {
			t.Fatalf("Decode refused a P1 attribution %+v: %v", p1, err)
		}
		if got.Attr == nil || got.Attr.Method != p1.Method || got.Attr.Confidence != "exact" {
			t.Errorf("Decode lost the attribution: %+v", got.Attr)
		}
	}
}
