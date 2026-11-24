// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/pkg/spec/agentdiff"
)

func TestCompiledDirectionOfUnorderedFamiliesIsMixed(t *testing.T) {
	rows := []agentdiff.Result{{Family: "filesystem", Direction: agentdiff.Narrowed}, {Family: "listeners", Direction: agentdiff.CannotClassify}}
	if d, why := compiledDirection(rows); d != rule.Mixed || !strings.Contains(why, "listeners changed and cannot be ordered") {
		t.Fatalf("%s: %s", d, why)
	}
	if d := sentenceDirection(rows, "fs.write"); d != rule.Mixed {
		t.Fatalf("a sentence is never narrowing beside a family that cannot be ordered: %s", d)
	}
	if d := sentenceDirection(rows[:1], "fs.write"); d != rule.Narrows {
		t.Fatalf("the filesystem sentence takes the filesystem's rows: %s", d)
	}
	if d := sentenceDirection(rows, "not.a.list"); d != rule.Mixed {
		t.Fatalf("an unknown list is never narrowing: %s", d)
	}
}
