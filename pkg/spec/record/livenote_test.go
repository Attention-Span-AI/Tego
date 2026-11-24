// SPDX-License-Identifier: Apache-2.0

package record

import (
	"strings"
	"testing"
	"time"
)

// TestLiveBlockNote (ADR 0125, amended 2026-11-23): live_block.note stands only on a live-rule-lifted line, from revision
// 41, as at most MaxLiveNote bytes of printable text; it is refused below 41 [below-minor], and anything else wrong with
// it [live-block].
func TestLiveBlockNote(t *testing.T) {
	at := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	lifted := func(note string) GapPayload {
		return GapPayload{What: GapEnforce, Why: GapLiveRuleLifted, LiveBlock: &LiveBlockChange{Op: "lift", Kind: "read",
			Value: "/srv/x", Rule: LiveFenceRule("read", "/srv/x"), By: "uid:1 pid:2 cli", Serial: 3, At: at, Note: note}}
	}
	other := func(why, op, note string) GapPayload {
		p := lifted(note)
		p.Why, p.LiveBlock.Op = why, op
		if why == GapLiveLiftRefused {
			p.LiveBlock.Refused = LiveRefusedMAC
		}
		if why == GapLiveLiftExpired {
			p.LiveBlock.Until = at
		}
		return p
	}
	block := GapPayload{What: GapEnforce, Why: GapLiveBlockAdded, LiveBlock: &LiveBlockChange{Op: "add", Kind: "net",
		Value: "example.com:443", Rule: LiveRule("net", "example.com:443"), By: "uid:1 pid:2 cli", Serial: 1, At: at, Note: "x"}}
	good := []struct{ name, note string }{
		{"a short note", "ticket 4411: the nightly export needs this"},
		{"a note of exactly the bound", strings.Repeat("a", MaxLiveNote)},
		{"non-ASCII letters", "d\u00e9ploiement urgent, \u65e5\u672c\u8a9e"},
		{"none", ""},
	}
	for _, c := range good {
		e := liveModesEvent(t, KindGap, "", lifted(c.note))
		if err := e.ValidateAt(MinorEveryLaunch); err != nil {
			t.Errorf("%s at 41: %v", c.name, err)
		}
		if got := FieldCode(e.ValidateAt(MinorAppliedLimits)); (got == "below-minor") != (c.note != "") {
			t.Errorf("%s at 40: [%s], want [below-minor] exactly when a note is there", c.name, got)
		}
	}
	bad := []struct {
		name string
		p    GapPayload
	}{
		{"one byte past the bound", lifted(strings.Repeat("a", MaxLiveNote+1))},
		{"a newline", lifted("one\ntwo")},
		{"a tab", lifted("a\tb")},
		{"an escape byte", lifted("\x1b[2Jclear")},
		{"a NUL", lifted("a\x00b")},
		{"a bidirectional override", lifted("ok \u202eevil")},
		{"a zero-width space", lifted("a\u200bb")},
		{"a line separator", lifted("a\u2028b")},
		{"on a refused lift", other(GapLiveLiftRefused, "lift", "x")},
		{"on an expired lift", other(GapLiveLiftExpired, "expire", "x")},
		{"on a restore", other(GapLiveRuleRestored, "restore", "x")},
		{"on a live block", block},
	}
	for _, c := range bad {
		e := liveModesEvent(t, KindGap, "", c.p)
		if got := FieldCode(e.ValidateAt(MinorEveryLaunch)); got != "live-block" {
			t.Errorf("%s: [%s], want [live-block]", c.name, got)
		}
	}
}

// TestValidLiveNote: the bound is in bytes, not characters.
func TestValidLiveNote(t *testing.T) {
	if err := ValidLiveNote(strings.Repeat("\u00e9", MaxLiveNote/2)); err != nil {
		t.Errorf("%d bytes of two-byte letters: %v", MaxLiveNote, err)
	}
	if err := ValidLiveNote(strings.Repeat("\u00e9", MaxLiveNote/2+1)); err == nil {
		t.Errorf("%d bytes accepted", MaxLiveNote+2)
	}
	if err := ValidLiveNote("a\xffb"); err == nil {
		t.Error("invalid UTF-8 accepted")
	}
}
