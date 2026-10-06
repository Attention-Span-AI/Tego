// SPDX-License-Identifier: Apache-2.0

package events

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestSummaryNamesTheCommandRule: an exec line a command rule decided shows the entry, its list, an ambiguous match
// and the interpretation that read it (ADR 0048 (8)); an exec no command rule decided reads as before.
func TestSummaryNamesTheCommandRule(t *testing.T) {
	for payload, want := range map[string]string{
		`{"path":"/usr/bin/git","argv":["git","psuh"],"command_rule":"git push","command_list":"deny","command_match":"ambiguous","command_via":"name"}`:              "git psuh command=deny:git push (ambiguous)",
		`{"path":"/usr/lib/git-core/git-push","argv":["git-push"],"command_rule":"git push","command_list":"deny","command_match":"definite","command_via":"dashed"}`: "git-push command=deny:git push via=dashed",
		`{"path":"/usr/bin/ls","argv":["ls","-l"]}`: "ls -l",
	} {
		e := &record.Event{Kind: record.KindExec, Payload: []byte(payload)}
		if got := Summary(e); got != want {
			t.Errorf("Summary = %q, want %q", got, want)
		}
	}
}
