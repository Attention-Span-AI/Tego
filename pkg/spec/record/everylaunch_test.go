// SPDX-License-Identifier: Apache-2.0

package record

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestEveryLaunchIsASupersetOfRevisions39And40 (ADR 0157): revision 41 allows everything 39 and 40 allow, with the same
// rules. A baseline block is required at 39 itself and carried at 41 when the run had one; applied_limits is allowed at 40
// and at 41; neither is allowed below its revision.
func TestEveryLaunchIsASupersetOfRevisions39And40(t *testing.T) {
	if MinorEveryLaunch != MinorAppliedLimits+1 || Minor != MinorEveryLaunch || !SupportsMinor(MinorEveryLaunch) || SupportsMinor(MinorEveryLaunch+1) {
		t.Fatalf("MinorEveryLaunch %d, Minor %d: 41 follows 40 and is the one this build writes", MinorEveryLaunch, Minor)
	}
	e, p := baselineStartFixture(t)

	// A baseline run at 41: the block and its hashes validate and are read as recorded.
	at41 := p
	at41.RecordMinor = MinorEveryLaunch
	if err := at41.ValidateBaseline(); err != nil {
		t.Fatalf("a baseline run at 41: %v", err)
	}
	if !at41.BaselineRecorded() {
		t.Fatal("a baseline run at 41 is not BaselineRecorded")
	}
	// The block is still checked at 41: a hash that does not reproduce is refused there as at 39.
	bad := at41
	bad.EffectiveHash = strings.Repeat("0", 64)
	if err := bad.ValidateBaseline(); err == nil {
		t.Fatal("a baseline run at 41 with a wrong effective hash was accepted")
	}
	// A run at 41 with no baseline (the run had none) is valid and not BaselineRecorded; at 39 the block is required.
	none := RunStartPayload{RecordMinor: MinorEveryLaunch, Tier: "landlock"}
	if err := none.ValidateBaseline(); err != nil || none.BaselineRecorded() {
		t.Fatalf("a run at 41 with no baseline: %v, recorded %t", err, none.BaselineRecorded())
	}
	at39 := none
	at39.RecordMinor = MinorBaseline
	if err := at39.ValidateBaseline(); err == nil {
		t.Fatal("a run at 39 with no baseline block was accepted")
	}
	// A baseline at 41 is read through the raw gate too (the whole line, not a typed copy).
	if err := e.ValidateAt(MinorBaseline); err != nil {
		t.Fatal(err)
	}

	// applied_limits is allowed at 40 and 41, refused below.
	lim := &AppliedLimits{PidsMax: intp(64)}
	for minor, code := range map[int]string{MinorLearn: "below-minor", MinorAppliedLimits: "", MinorEveryLaunch: ""} {
		q := RunStartPayload{RecordMinor: minor, AppliedLimits: lim}
		if got := FieldCode(q.ValidateFields()); got != code {
			t.Errorf("applied_limits at %d: [%s], want [%s]", minor, got, code)
		}
	}
	// At 39 itself the block is required, so the comparison is made on the fixture, which holds one.
	q39 := p
	q39.AppliedLimits = lim
	if got := FieldCode(q39.ValidateFields()); got != "below-minor" {
		t.Errorf("applied_limits at 39: [%s], want [below-minor]", got)
	}
	// An adoption that wrote limits and had a baseline carries both at 41.
	both := at41
	both.AppliedLimits = lim
	if err := both.ValidateFields(); err != nil {
		t.Fatalf("baseline and applied_limits at 41: %v", err)
	}
}

// TestRunStartHome (ADR 0157): run_start.home is allowed from 41, refused below it [below-minor], and must be a clean
// absolute printable path no longer than MaxRunHome [run-home].
func TestRunStartHome(t *testing.T) {
	for _, c := range []struct {
		name  string
		minor int
		home  string
		code  string
	}{
		{"absolute at 41", MinorEveryLaunch, "/home/ada", ""},
		{"root's home", MinorEveryLaunch, "/root", ""},
		{"at 40", MinorAppliedLimits, "/home/ada", "below-minor"},
		{"at 31", MinorLearn, "/home/ada", "below-minor"},
		{"relative", MinorEveryLaunch, "home/ada", "run-home"},
		{"trailing slash", MinorEveryLaunch, "/home/ada/", "run-home"},
		{"dot dot", MinorEveryLaunch, "/home/../root", "run-home"},
		{"double slash", MinorEveryLaunch, "/home//ada", "run-home"},
		{"newline", MinorEveryLaunch, "/home/a\nb", "run-home"},
		{"not utf-8", MinorEveryLaunch, "/home/\xff", "run-home"},
		{"too long", MinorEveryLaunch, "/" + strings.Repeat("a", MaxRunHome), "run-home"},
		{"at the bound", MinorEveryLaunch, "/" + strings.Repeat("a", MaxRunHome-1), ""},
	} {
		p := RunStartPayload{RecordMinor: c.minor, Tier: "landlock", Home: c.home}
		if got := FieldCode(p.ValidateFields()); got != c.code {
			t.Errorf("%s: [%s], want [%s]", c.name, got, c.code)
		}
		if c.name == "not utf-8" {
			continue // JSON marshalling repairs the bytes, so no line carries them
		}
		if got := FieldCode(liveModesEvent(t, KindRunStart, "", p).ValidateAt(c.minor)); got != c.code {
			t.Errorf("%s through ValidateAt: [%s], want [%s]", c.name, got, c.code)
		}
	}
}

// TestLiveBlockAddrs (ADR 0157): a net block by name put in force (live-block-added, live-rule-restored) may name the
// addresses it was enforced on from revision 41, refused below it [below-minor]; the list is sorted, canonical, unmapped,
// bounded by MaxLiveBlockAddrs, with addrs_more only on a full list, and stands on no other line [live-block].
func TestLiveBlockAddrs(t *testing.T) {
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	add := func(addrs ...string) GapPayload {
		return GapPayload{What: GapEnforce, Why: GapLiveBlockAdded, LiveBlock: &LiveBlockChange{Op: "add", Kind: "net",
			Value: "example.com:443", Rule: LiveRule("net", "example.com:443"), By: "uid:1 pid:2 cli", Serial: 1, At: at, Addrs: addrs}}
	}
	restore := func(addrs ...string) GapPayload {
		return GapPayload{What: GapEnforce, Why: GapLiveRuleRestored, LiveBlock: &LiveBlockChange{Op: "restore", Kind: "net",
			Value: "api.example.com:443", Rule: LiveFenceRule("net", "api.example.com:443"), By: "uid:1 pid:2 cli", Serial: 2, At: at, Addrs: addrs}}
	}
	more := func(p GapPayload, n int) GapPayload { p.LiveBlock.AddrsMore = n; return p }
	full := func() []string {
		var out []string
		for i := range MaxLiveBlockAddrs {
			out = append(out, fmt.Sprintf("10.0.0.%d", i+1))
		}
		return out
	}
	// "10.0.0.2" sorts before "10.0.0.10" as an address, not as text.
	ordered := []string{"10.0.0.2", "10.0.0.10", "93.184.216.34", "2606:2800:21f:cb07:6820:80da:af6b:8b2c", "fe80::1%2", "fe80::1%3"}
	good := []struct {
		name string
		p    GapPayload
	}{
		{"a name block's addresses", add(ordered...)},
		{"one address", add("93.184.216.34")},
		{"a restored fence entry's", restore("93.184.216.34", "fe80::1%2")},
		{"a full list and a count of more", more(add(full()...), 5)},
		{"no addresses: the lookup answered none", add()},
	}
	for _, c := range good {
		e := liveModesEvent(t, KindGap, "", c.p)
		if err := e.ValidateAt(MinorEveryLaunch); err != nil {
			t.Errorf("%s at 41: %v", c.name, err)
		}
		withAddrs := len(c.p.LiveBlock.Addrs) > 0
		if got := FieldCode(e.ValidateAt(MinorAppliedLimits)); (got == "below-minor") != withAddrs {
			t.Errorf("%s at 40: [%s], want [below-minor] exactly when addresses are named (%t)", c.name, got, withAddrs)
		}
	}
	// The sort is by address, so a list in text order is refused where it is not in address order.
	if err := liveModesEvent(t, KindGap, "", add("10.0.0.10", "10.0.0.2")).ValidateAt(MinorEveryLaunch); FieldCode(err) != "live-block" {
		t.Errorf("text order: %v, want [live-block]", err)
	}
	remove := add("93.184.216.34")
	remove.Why, remove.LiveBlock.Op = GapLiveBlockRemoved, "remove"
	execBlock := GapPayload{What: GapEnforce, Why: GapLiveBlockAdded, LiveBlock: &LiveBlockChange{Op: "add", Kind: "exec", Value: "/bin/ls",
		Rule: LiveRule("exec", "/bin/ls"), By: "uid:1 pid:2 cli", Serial: 1, At: at, Addrs: []string{"93.184.216.34"}}}
	over := add(append(full(), "10.0.1.1")...)
	for _, c := range []struct {
		name string
		p    GapPayload
	}{
		{"not sorted", add("93.184.216.34", "10.0.0.2")},
		{"a repeat", add("10.0.0.2", "10.0.0.2")},
		{"not an address", add("example.com")},
		{"not canonical", add("010.0.0.2")},
		{"a mapped address", add("::ffff:10.0.0.2")},
		{"upper case hex", add("2606:2800:21F::1")},
		{"past the cap", over},
		{"more on a list that is not full", more(add("10.0.0.2"), 1)},
		{"a negative count", more(add(full()...), -1)},
		{"a count with no list", more(add(), 3)},
		{"on a removal", remove},
		{"on an exec block", execBlock},
	} {
		if err := liveModesEvent(t, KindGap, "", c.p).ValidateAt(MinorEveryLaunch); FieldCode(err) != "live-block" {
			t.Errorf("%s: %v, want [live-block]", c.name, err)
		}
	}
}
