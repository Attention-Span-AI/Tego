// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAnEntryTextedUnmatchedNeverJoinsTheUnmatchedBucket is limits-check-doctor-cli.md E12. A rule is named
// after its section and the author's text (fs.write[unmatched]), and only the sentinel is the bare word, so an
// author who writes `unmatched` as a path gets its own declared bucket beside the unmatched one, and each
// counts its own events, rather than the two merging into one that hides an undeclared action.
func TestAnEntryTextedUnmatchedNeverJoinsTheUnmatchedBucket(t *testing.T) {
	rt := &agent.RuleTable{FS: []agent.FSRule{
		{Path: "/proj/unmatched", Kind: agent.FSWrite, Raw: "unmatched", Access: agent.AccessWriteSet},
	}}
	var b strings.Builder
	b.WriteString(fsLine(1, "fs.write[unmatched]", string(record.VerdictAllow), "/proj/unmatched/x"))
	b.WriteString(fsLine(2, UnmatchedRule, string(record.VerdictRefused), "/etc/shadow"))
	rep, err := Compute(readerOver(t, []byte(b.String())), rt)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	declared, ok := find(rep.FS, "fs.write[unmatched]")
	if !ok || !declared.Declared || declared.Allow != 1 || declared.Refused != 0 {
		t.Errorf("the author's entry = %+v (found %v), want a declared bucket with its one allow", declared, ok)
	}
	sentinel, ok := find(rep.FS, UnmatchedRule)
	if !ok || sentinel.Declared || sentinel.Refused != 1 || sentinel.Allow != 0 {
		t.Errorf("the sentinel bucket = %+v (found %v), want an undeclared bucket with its one refusal", sentinel, ok)
	}
	if len(rep.FS) != 2 {
		t.Errorf("%d fs buckets, want 2: %+v", len(rep.FS), rep.FS)
	}
	if !rep.Drifted() {
		t.Error("the refused action outside the contract must still drift")
	}
}
