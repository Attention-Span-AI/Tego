// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestLogsTargetGroupLinksTheTargetQuery: a By target group opens the lines of its own name (target:<name>), not a
// text search that finds only the lines spelled as the group is, and a query on a program or a target does not list
// the rule changes of other things beside its lines.
func TestLogsTargetGroupLinksTheTargetQuery(t *testing.T) {
	s := newServer(t, noiseRoot(t, "r-aaaaaaaa-0000000000035-tgtgrp"))
	c := login(t, s)
	b := get(t, s, c, "/logs?group=target")
	want := `href="/logs?where=target%3A%2Fw%2Fproj%2Fmain.go"`
	if !strings.Contains(b, want) {
		t.Errorf("the group of /w/proj/main.go does not open target:/w/proj/main.go (want %s):\n%s", want, b)
	}
	if strings.Contains(b, "q=%2Fw%2Fproj%2Fmain.go") {
		t.Error("a target group still opens a text search")
	}
	page := get(t, s, c, "/logs?where="+url.QueryEscape("target:/w/proj/main.go"))
	if n := matchedOn(t, page); n != 1 {
		t.Errorf("target:/w/proj/main.go lists %d lines, want 1", n)
	}
}

// TestRuleChangesFollowProgramAndTargetTerms: prog: and target: narrow lines, so the rule changes (which have neither)
// are not listed beside them.
func TestRuleChangesFollowProgramAndTargetTerms(t *testing.T) {
	for _, q := range []string{"prog:curl", "-prog:curl", "target:/w/a", "-target:/w/a"} {
		lq := readLogsQuery(url.Values{"where": {q}}, time.Now())
		if lq.err != nil {
			t.Fatalf("%s: %v", q, lq.err)
		}
		if contextOnly(lq.f) {
			t.Errorf("%s narrows by more than run, agent and time, and still lists rule changes", q)
		}
	}
	if lq := readLogsQuery(url.Values{"where": {"agent:codex"}}, time.Now()); !contextOnly(lq.f) {
		t.Error("an agent term alone no longer lists rule changes")
	}
}
