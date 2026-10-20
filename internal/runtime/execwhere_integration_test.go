// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationAnExecThroughADescriptorIsJudgedWhereItsImageLies on a real kernel,
// for the deny_read refusal beside codex-home-exec: under no exec: section (deny nothing) and a deny_read tier 1
// enforces, the agent opens a binary under the deny_read O_PATH, makes its directory unsearchable and runs it through
// /proc/self/fd/<n> (opathExecHelper). Landlock refuses the exec open, EACCES, as the image lies under the deny_read.
// The supervisor could not walk the kernel's spelling of the image back to it, and judged on /proc/<pid>/fd/<n> it
// recorded the exec allow unmatched while the kernel refused it. It is now judged where the kernel spells the image,
// and the line says refused under the deny_read, which is what the run met.
func TestIntegrationAnExecThroughADescriptorIsJudgedWhereItsImageLies(t *testing.T) {
	secret := t.TempDir()
	sub := filepath.Join(secret, "sub")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	bin, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(sub, "tool")
	if err := os.WriteFile(tool, bin, 0o755); err != nil {
		t.Fatal(err)
	}
	agentReaches(t, tool)
	agentOwns(t, secret, sub, tool)
	f := newFixture(t, `version: 0
name: iexecwhere
command: ["/bin/true"]
tier: landlock
fs:
  write: ["./out/"]
  deny_read: ["`+secret+`/"]
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 128
`)
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })
	res, err := Run(context.Background(), f.rt, []string{os.Args[0], opathExecArg, tool, sub}, f.deps(t, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 126 {
		t.Fatalf("exit %d, want 126: the exec of the image under the deny_read is refused EACCES (9 is a helper failure, 0 an image that ran)", res.ExitCode)
	}
	var lines []string
	found := false
	for _, e := range runDirs(t, f.root) {
		for _, ev := range events(t, e) {
			if ev.Kind != record.KindExec {
				continue
			}
			var p record.ExecPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(p.Path, "/fd/") {
				continue
			}
			lines = append(lines, string(ev.Verdict)+" "+ev.Rule+" "+string(ev.Reason)+" "+p.Path)
			found = found || ev.Verdict == record.VerdictRefused && ev.Reason == record.ReasonReadDenied && strings.HasPrefix(ev.Rule, "fs.deny_read[")
		}
	}
	if !found {
		t.Errorf("descriptor exec lines %q, want one refused read-denied under the deny_read: the kernel refused it", lines)
	}
}
