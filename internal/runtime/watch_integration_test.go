// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationAWatchOfADenyReadTargetIsRefused is GAPS A10's watch at tier landlock on the real kernel, through the
// compiled contract, Prepare's filter and the ledger: the agent's inotify watch of a deny_read directory the ruleset
// enforces is refused EACCES, and so is a dnotify watch (fcntl F_NOTIFY) of a descriptor of it, opened to list on the
// READ_DIR the ruleset leaves it, and a fanotify mark of it where the kernel offers unprivileged fanotify, while a
// watch of its write directory is made (watchHelper's exit 0). Each refusal is a refused line in events.jsonl, op the
// syscall, target the directory, reason read-denied, rule the entry (supervisor R36, enforce-landlock R11e). Before,
// no watch call was notified and no hook of the tier saw one: the watch was made, and reported which of the target's
// files were opened and changed (watchHelper exits watchExitTargetWatched, and with the inotify and fanotify arms
// alone, watchExitDnotifyWatched).
func TestIntegrationAWatchOfADenyReadTargetIsRefused(t *testing.T) {
	secret := t.TempDir()
	if err := os.WriteFile(filepath.Join(secret, "token"), []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	agentReaches(t, secret)
	agentOwns(t, secret)
	f := newFixture(t, `version: 0
name: iwatch
command: ["/bin/true"]
tier: landlock
fs:
  write: ["./out/"]
  deny_read: ["`+secret+`/"]
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 64
record: summary
`)
	res, err := Run(context.Background(), f.rt, []string{os.Args[0], watchArg, secret, f.out}, f.deps(t, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("agent exit %d, want 0: 3 is an inotify watch of the deny_read target that was made, 4 one refused "+
			"with another errno, 5 the write directory's watch refused, 6 or 7 the same as 3 or 4 for the fanotify mark, 8 "+
			"or 10 for the dnotify watch, 11 the target not opened to list, 12 the write directory's dnotify watch "+
			"refused, 9 a helper failure", res.ExitCode)
	}
	rule := ""
	for _, r := range f.rt.FS {
		if r.Kind == agent.FSDenyRead && filepath.Clean(r.Path) == secret {
			rule = r.RuleName() // the entry as declared: fs.deny_read[<secret>/]
		}
	}
	if rule == "" {
		t.Fatalf("the compiled table has no deny_read entry at %s", secret)
	}
	// The dnotify watch is named by its descriptor's own file: the target where its walk lands.
	landed, err := filepath.EvalSymlinks(secret)
	if err != nil {
		t.Fatal(err)
	}
	var ops []string
	for _, dir := range runDirs(t, f.root) {
		for _, ev := range events(t, dir) {
			if ev.Kind != record.KindRefused {
				continue
			}
			var p record.RefusedPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if p.Op != "inotify_add_watch" && p.Op != "fanotify_mark" && p.Op != "fcntl" {
				continue
			}
			named := p.Target == secret || p.Op == "fcntl" && p.Target == landed
			if !named || ev.Rule != rule || ev.Reason != record.ReasonReadDenied {
				t.Errorf("refused %s %q rule=%s reason=%s, want target %q under %s, read-denied", p.Op, p.Target, ev.Rule,
					ev.Reason, secret, rule)
			}
			ops = append(ops, p.Op)
		}
	}
	if len(ops) < 2 || ops[0] != "inotify_add_watch" || ops[1] != "fcntl" {
		t.Errorf("refused watch lines %q, want the inotify watch's first, then the dnotify watch's (and the fanotify "+
			"mark's, where the kernel offers one)", ops)
	}
}
