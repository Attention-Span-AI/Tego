// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// stallOnAPTY runs a shell that reads its terminal line by line under stall_after: 14s, with the person
// (typeEvery > 0) typing a line at that interval for typeFor and then Ctrl-D, or no one typing. The kernel stamps
// the terminal's read time once per 8-second window, so the stall_after is above twice that.
func stallOnAPTY(t *testing.T, typeEvery, typeFor time.Duration) Result {
	t.Helper()
	c := contractFor("ttyinput", []string{"/bin/sh"}, []string{"/bin/sh"})
	c = strings.Replace(c, "  pids: 128", "  pids: 128\n  stall_after: 14s", 1)
	f := newFixture(t, c)
	p := openPTY(t)
	deps := f.deps(t, nil)
	deps.Stdio = Stdio{In: p.slave, Out: p.slave, Err: p.slave}
	if typeEvery > 0 {
		go func() {
			for end := time.Now().Add(typeFor); time.Now().Before(end); time.Sleep(typeEvery) {
				_, _ = p.master.WriteString("a key\n")
			}
			_, _ = p.master.Write([]byte{4}) // Ctrl-D at the start of a line: end of input
		}()
	}
	res, err := Run(context.Background(), f.rt, []string{"/bin/sh", "-c", "while read line; do :; done"}, deps)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

// G7: a person typing at the agent's terminal is activity, so a run whose agent writes nothing and records
// nothing is not ended by stall_after while the person types.
func TestIntegrationTypingKeepsAnInteractiveRunFromStalling(t *testing.T) {
	t.Parallel()
	res := stallOnAPTY(t, 2*time.Second, 36*time.Second) // well past stall_after
	if res.Reason != record.RunEndExit || res.ExitCode != 0 {
		t.Fatalf("a run typed into for 36 s under stall_after 14s ended %s exit %d, want its own exit 0", res.Reason, res.ExitCode)
	}
}

// With no one typing the same run is ended as stalled, so the activity above is the typing and nothing else.
func TestIntegrationNoInputStillStalls(t *testing.T) {
	t.Parallel()
	res := stallOnAPTY(t, 0, 0)
	if res.Reason != record.RunEndLimit {
		t.Fatalf("a run nobody types into ended %s, want limit (stall_after)", res.Reason)
	}
}
