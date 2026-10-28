// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// liveModesEvent is a line of kind k with payload p, in the envelope the live fixtures use.
func liveModesEvent(t *testing.T, k Kind, rule string, p any) *Event {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	e := &Event{V: Version, Kind: k, Source: SourceSupervisor, Run: "r-00000000-000000000000a-aaaaaa", Agent: "retriever",
		TS: time.Date(2026, 10, 27, 12, 3, 1, 0, time.UTC), Payload: b}
	if k == KindRefused {
		e.Rule, e.Reason = rule, ReasonReadDenied
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("the envelope is not valid: %v", err)
	}
	return e
}

// TestLiveModesValidation holds revision 26's fields, ops and whys (ADR 0125): each is refused at 25 [below-minor]
// and, well formed, accepted at 26; each malformed form is refused at 26 by its code.
func TestLiveModesValidation(t *testing.T) {
	if MinorLiveModes != MinorCredentialsAndMCPTools+1 || Minor < MinorLiveModes {
		t.Fatalf("Minor %d, MinorLiveModes %d: the live modes are 26, after the credentials and MCP tools at 25", Minor, MinorLiveModes)
	}
	until := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	at := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	block := func(op, kind, value string) *LiveBlockChange {
		return &LiveBlockChange{Op: op, Kind: kind, Value: value, Rule: LiveRule(kind, value), By: "uid:1 pid:2 cli", Serial: 4, At: at}
	}
	fence := func(op, kind, value string) *LiveBlockChange {
		c := block(op, kind, value)
		c.Rule = LiveFenceRule(kind, value)
		return c
	}
	with := func(c *LiveBlockChange, f func(*LiveBlockChange)) *LiveBlockChange { f(c); return c }
	// liftReq is a lift recorded under the request's rule, live.lift[...]: one that names no fence entry.
	liftReq := func(kind, value string) *LiveBlockChange {
		c := block("lift", kind, value)
		c.Rule = LiveLiftRule(kind, value)
		return c
	}
	refusedAs := func(why string) func(*LiveBlockChange) { return func(c *LiveBlockChange) { c.Refused = why } }
	gap := func(why string, c *LiveBlockChange) GapPayload {
		return GapPayload{What: GapEnforce, Why: why, LiveBlock: c}
	}
	fenceDoc := &LiveFence{SHA256: strings.Repeat("0a", 32), Entries: []LiveFenceEntry{
		{Kind: "read", Value: "/srv/exports", Source: LiveFenceSourceNew, Rule: LiveFenceRule("read", "/srv/exports")},
		{Kind: "exec", Value: "/usr/bin/psql", Source: LiveFenceSourceDeny, Rule: LiveFenceRule("exec", "/usr/bin/psql")}}}
	setUntil := func(c *LiveBlockChange) { c.Until = until }
	good := []struct {
		name string
		kind Kind
		rule string
		p    any
	}{
		{"add with until", KindGap, "", gap(GapLiveBlockAdded, with(block("add", "exec", "/bin/ls"), setUntil))},
		{"remove with until", KindGap, "", gap(GapLiveBlockRemoved, with(block("remove", "net", "example.com"), setUntil))},
		{"block expired", KindGap, "", gap(GapLiveBlockExpired, with(block("expire", "path", "/srv/x"), setUntil))},
		{"unblock expired", KindGap, "", gap(GapLiveUnblockExpired, with(block("expire", "write", "/srv/x"), setUntil))},
		{"rule lifted", KindGap, "", gap(GapLiveRuleLifted, fence("lift", "read", "/srv/exports"))},
		{"rule restored", KindGap, "", gap(GapLiveRuleRestored, fence("restore", "net", "api.stripe.com:443"))},
		{"lift expired", KindGap, "", gap(GapLiveLiftExpired, with(fence("expire", "exec", "/usr/bin/psql"), setUntil))},
		{"lift refused locked", KindGap, "", gap(GapLiveLiftRefused, with(liftReq("read", "/etc"), refusedAs(LiveRefusedLocked)))},
		{"lift refused outside the fence", KindGap, "", gap(GapLiveLiftRefused, with(liftReq("read", "/etc"), refusedAs(LiveRefusedOutsideFence)))},
		{"lift refused mac, a fence entry", KindGap, "", gap(GapLiveLiftRefused, with(fence("lift", "read", "/etc"), refusedAs(LiveRefusedMAC)))},
		{"lift refused mac, no fence entry", KindGap, "", gap(GapLiveLiftRefused, with(liftReq("read", "/etc"), refusedAs(LiveRefusedMAC)))},
		{"lift refused until", KindGap, "", gap(GapLiveLiftRefused, with(fence("lift", "read", "/etc"), func(c *LiveBlockChange) { c.Refused, c.Until = LiveRefusedUntil, until }))},
		// A launcher built before the lift rule wrote every refused lift under live.fence[...] at 26, and a later one
		// writes live.lift[...]
		// where the lift names no fence entry: each build's line is valid to the other's reader.
		{"lift refused outside the fence, an older launcher's line", KindGap, "", gap(GapLiveLiftRefused, with(fence("lift", "read", "/etc"), refusedAs(LiveRefusedOutsideFence)))},
		{"lift refused locked, an older launcher's line", KindGap, "", gap(GapLiveLiftRefused, with(fence("lift", "read", "/etc"), refusedAs(LiveRefusedLocked)))},
		{"lift refused until, under the request's rule", KindGap, "", gap(GapLiveLiftRefused, with(liftReq("read", "/etc"), func(c *LiveBlockChange) { c.Refused, c.Until = LiveRefusedUntil, until }))},
		{"fence rule", KindRefused, "live.fence[read:/srv/exports]", map[string]string{"op": "open", "target": "/srv/exports/a",
			"reason": "read-denied", "rule": "live.fence[read:/srv/exports]"}},
	}
	for _, c := range good {
		e := liveModesEvent(t, c.kind, c.rule, c.p)
		if err := e.ValidateAt(MinorLiveModes); err != nil {
			t.Errorf("%s at 26: %v", c.name, err)
		}
		if err := e.ValidateAt(MinorLiveModes - 1); FieldCode(err) != "below-minor" {
			t.Errorf("%s at 25: %v, want [below-minor]", c.name, err)
		}
	}
	bad := []struct {
		name, code string
		p          GapPayload
	}{
		{"expire without until", "live-block", gap(GapLiveBlockExpired, block("expire", "exec", "/bin/ls"))},
		{"lift-expired without until", "live-block", gap(GapLiveLiftExpired, fence("expire", "exec", "/bin/ls"))},
		{"refused on a lifted line", "live-block", gap(GapLiveRuleLifted, with(fence("lift", "read", "/x"), func(c *LiveBlockChange) { c.Refused = "mac" }))},
		{"refused missing", "live-block", gap(GapLiveLiftRefused, fence("lift", "read", "/x"))},
		{"refused unknown", "live-block", gap(GapLiveLiftRefused, with(fence("lift", "read", "/x"), func(c *LiveBlockChange) { c.Refused = "busy" }))},
		{"lift under a block rule", "live-block", gap(GapLiveRuleLifted, block("lift", "read", "/x"))},
		{"expiry under a fence rule", "live-block", gap(GapLiveBlockExpired, with(fence("expire", "exec", "/x"), setUntil))},
		{"fence kind path", "live-block", gap(GapLiveRuleRestored, fence("restore", "path", "/x"))},
		{"op add on lifted", "live-block", gap(GapLiveRuleLifted, fence("add", "read", "/x"))},
		{"no live_block", "live-block", gap(GapLiveUnblockExpired, nil)},
		// A refused lift is under live.fence[...] or live.lift[...] of its own kind and value, nothing else.
		{"refused lift under a block rule", "live-block", gap(GapLiveLiftRefused, with(block("lift", "read", "/x"), refusedAs(LiveRefusedOutsideFence)))},
		{"refused lift under another value's rule", "live-block", gap(GapLiveLiftRefused, with(liftReq("read", "/x"), func(c *LiveBlockChange) {
			c.Refused, c.Rule = LiveRefusedLocked, LiveLiftRule("read", "/y")
		}))},
		{"lift rule on a lifted line", "live-block", gap(GapLiveRuleLifted, liftReq("read", "/x"))},
	}
	for _, c := range bad {
		if err := liveModesEvent(t, KindGap, "", c.p).ValidateAt(MinorLiveModes); FieldCode(err) != c.code {
			t.Errorf("%s: %v, want [%s]", c.name, err, c.code)
		}
	}
	// run_start: live_mode and live_fence.
	starts := []struct {
		name, code string
		minor      int
		mode       string
		fence      *LiveFence
	}{
		{"adjustable", "", 26, LiveModeAdjustable, fenceDoc},
		{"locked writes neither", "", 26, "", nil},
		{"adjustable at 25", "below-minor", 25, LiveModeAdjustable, fenceDoc},
		{"mode locked", "live-mode", 26, "locked", fenceDoc},
		{"mode without fence", "live-mode", 26, LiveModeAdjustable, nil},
		{"fence without mode", "live-mode", 26, "", fenceDoc},
		{"bad digest", "live-fence", 26, LiveModeAdjustable, &LiveFence{SHA256: "x", Entries: []LiveFenceEntry{}}},
		{"nil entries", "live-fence", 26, LiveModeAdjustable, &LiveFence{SHA256: strings.Repeat("0a", 32)}},
		{"65 entries", "live-fence", 26, LiveModeAdjustable, func() *LiveFence {
			f := &LiveFence{SHA256: strings.Repeat("0a", 32)}
			for i := range MaxLiveFence + 1 {
				v := "/srv/" + strconv.Itoa(i)
				f.Entries = append(f.Entries, LiveFenceEntry{Kind: "read", Value: v, Source: "new", Rule: LiveFenceRule("read", v)})
			}
			return f
		}()},
		{"twice", "live-fence", 26, LiveModeAdjustable, &LiveFence{SHA256: strings.Repeat("0a", 32),
			Entries: []LiveFenceEntry{fenceDoc.Entries[0], fenceDoc.Entries[0]}}},
		{"value too long", "live-fence", 26, LiveModeAdjustable, func() *LiveFence {
			v := "/srv/" + strings.Repeat("a", MaxLiveFenceValue)
			return &LiveFence{SHA256: strings.Repeat("0a", 32),
				Entries: []LiveFenceEntry{{Kind: "read", Value: v, Source: "new", Rule: LiveFenceRule("read", v)}}}
		}()},
		{"value at the bound", "", 26, LiveModeAdjustable, func() *LiveFence {
			v := "/srv/" + strings.Repeat("a", MaxLiveFenceValue-5)
			return &LiveFence{SHA256: strings.Repeat("0a", 32),
				Entries: []LiveFenceEntry{{Kind: "read", Value: v, Source: "new", Rule: LiveFenceRule("read", v)}}}
		}()},
		{"bad source", "live-fence", 26, LiveModeAdjustable, &LiveFence{SHA256: strings.Repeat("0a", 32),
			Entries: []LiveFenceEntry{{Kind: "net", Value: "a.b", Source: "maybe", Rule: LiveFenceRule("net", "a.b")}}}},
	}
	for _, c := range starts {
		p := RunStartPayload{RecordMinor: c.minor, Tier: "cgroup", LiveMode: c.mode, LiveFence: c.fence}
		err := p.ValidateFields()
		if FieldCode(err) != c.code || (c.code == "") != (err == nil) {
			t.Errorf("%s: ValidateFields = %v, want [%s]", c.name, err, c.code)
		}
		if err := liveModesEvent(t, KindRunStart, "", p).ValidateAt(c.minor); FieldCode(err) != c.code {
			t.Errorf("%s: ValidateAt = %v, want [%s]", c.name, err, c.code)
		}
	}
	// A Locked run's lines do not change: a plain add at 26 carries no until and no refused.
	b, err := json.Marshal(gap(GapLiveBlockAdded, block("add", "exec", "/bin/ls")))
	if err != nil || strings.Contains(string(b), "until") || strings.Contains(string(b), "refused") {
		t.Fatalf("a plain add encodes as %s (%v)", b, err)
	}
	if !IsMVPField(KindRunStart, "live_fence") || !IsMVPField(KindRunStart, "live_mode") {
		t.Fatal("live_mode and live_fence could be moved to a blob, out of ValidateAt's reach")
	}
}

// TestReadmeNamesTheLiveModesMinor: the record README documents revision 26's fields and whys.
func TestReadmeNamesTheLiveModesMinor(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := "At `record_minor` " + strconv.Itoa(MinorLiveModes) + " ("
	i := strings.Index(string(b), want)
	if i < 0 {
		t.Fatalf("spec/record/v1/README.md has no %q", want)
	}
	text := string(b[i:min(len(b), i+4000)])
	for _, s := range []string{"`live.fence[<kind>:<value>]`", "`" + GapLiveBlockExpired + "`", "`" + GapLiveUnblockExpired + "`",
		"`" + GapLiveRuleLifted + "`", "`" + GapLiveRuleRestored + "`", "`" + GapLiveLiftExpired + "`", "`" + GapLiveLiftRefused + "`",
		"`live_mode`", "`live_fence`", "`until`", "`refused`"} {
		if !strings.Contains(text, s) {
			t.Errorf("README's record_minor %d entry does not name %s", MinorLiveModes, s)
		}
	}
}
