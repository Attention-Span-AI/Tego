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

func TestExecSummaryNamesFilelessAndDropped(t *testing.T) {
	for _, tc := range []struct{ payload, want string }{
		{`{"path":"/memfd:x","fileless":true}`, "/memfd:x [fileless: executable in memory]"},
		{`{"path":"/p/tool","dropped":true}`, "/p/tool [dropped: file written by the agent]"},
		{`{"path":"/bin/ls","fileless":false,"dropped":false}`, "/bin/ls"},
	} {
		if got := Summary(&record.Event{Kind: record.KindExec, Payload: []byte(tc.payload)}); got != tc.want {
			t.Errorf("%s: %q", tc.payload, got)
		}
	}
}
