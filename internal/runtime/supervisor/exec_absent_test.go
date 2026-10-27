// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestUnrestrictedExecBeneathAnAbsentRowIsRefused: with exec
// unrestricted, a binary made during the run beneath an absent built-in row's ungranted name (~/.codex, missing at
// compile) has no EXECUTE or READ_FILE in the Landlock ruleset, so the kernel refuses its exec; the loop's verdict says
// so, read_denied, by the row, where it said allow, unmatched. A binary elsewhere still runs.
func TestUnrestrictedExecBeneathAnAbsentRowIsRefused(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	row := filepath.Join(home, ".codex", "auth.json")
	tool, free := filepath.Join(home, ".codex", "bin", "tool"), filepath.Join(home, "bin", "tool")
	for _, p := range []string{tool, free} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	c := compile(&Policy{Rules: &agent.RuleTable{
		Tier: backend.TierLandlock, Contract: &agent.Contract{}, Record: agent.RecordSummary,
		AbsentDenyRead: []agent.AbsentRow{{Path: row, Resolved: row, At: filepath.Join(home, ".codex")}},
	}})
	image := func(p string) execImage {
		t.Helper()
		fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd) //nolint:errcheck // a test descriptor
		img, err := describeImage(fd)
		if err != nil {
			t.Fatal(err)
		}
		return img
	}
	if d := c.decideExec(tool, tool, image(tool), nil, ruleUnmatched); d.verdict != record.VerdictRefused ||
		d.reason != record.ReasonReadDenied || d.rule != "fs.deny_read["+row+"]" {
		t.Errorf("exec %s = %s %s %s, want refused read_denied by the row", tool, d.verdict, d.reason, d.rule)
	}
	if d := c.decideExec(free, free, image(free), nil, ruleUnmatched); d.verdict != record.VerdictAllow {
		t.Errorf("exec %s = %s %s, want allow", free, d.verdict, d.rule)
	}
}
