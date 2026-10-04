// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// multicallContract lists two hard links of one binary by name in exec.allow, as a contract naming two uutils
// commands (/usr/bin/ls and /usr/bin/cat resolve to two links of one inode on Ubuntu 25.10) or two busybox applets
// does.
const multicallContract = `version: 0
name: plane-multicall
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
exec:
  allow: ["python3", "./mc/one", "./mc/two"]
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
record: full
`

// multicallAgent runs each link and reports "RESULT <name> <outcome>".
const multicallAgent = `import subprocess

def attempt(name, path):
    try:
        r = subprocess.run([path])
        print("RESULT", name, "ok" if r.returncode == 0 else "exit=%d" % r.returncode, flush=True)
    except OSError as e:
        print("RESULT", name, "refused errno=%d" % e.errno, flush=True)

attempt("one", "./mc/one")
attempt("two", "./mc/two")
attempt("three", "./mc/three")
attempt("one-elsewhere", "./other/one")
`

// TestPlaneRunMulticallLinks is enforce-plane §6 E15 (ADR 0025's 2026-09-30 note) in a real run: a multi-call binary
// (one inode, hard-linked under several names, as uutils and busybox install) whose two link names exec.allow lists
// runs under both, while a third link name in the same directory and a link under a listed name in another
// directory are refused; the ledger names each link exec'd, each allowed one under its own entry. It runs in every
// plane mode this machine passes at tier cgroup, and at tier bpflsm where the LSM mode passes. Before the note the
// run failed Prepare: the fill keyed one exec row per inode and refused the second entry.
func TestPlaneRunMulticallLinks(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	type cell struct{ mode, tier string }
	var cells []cell
	for _, m := range modes {
		cells = append(cells, cell{m, "cgroup"})
		if m == "lsm" {
			cells = append(cells, cell{m, "bpflsm"})
		}
	}
	for _, c := range cells {
		t.Run(c.tier+"@"+c.mode, func(t *testing.T) { multicallRunCell(t, bin, uid, gid, c.mode, c.tier) })
	}
}

func multicallRunCell(t *testing.T, bin string, uid, gid int, mode, tier string) {
	tool, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Skipf("the multi-call binary is a copy of /bin/true: %v", err)
	}
	p := newPlaneProject(t, uid, gid,
		map[string]string{"agent.py": multicallAgent, "agent.yaml": multicallContract, "mc/one": string(tool)},
		[]string{"out", "other"},
		map[string]string{"mc/two": "mc/one", "mc/three": "mc/one", "other/one": "mc/one"})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var out bytes.Buffer
	cmd := p.runAt(ctx, bin, tier, "agent.yaml", mode, &out)
	runErr := cmd.Run()
	t.Logf("tego run --tier %s (%s): %v\n%s", tier, mode, runErr, out.String())
	if runErr != nil {
		t.Fatalf("the run did not complete: %v", runErr)
	}
	res := agentResults(t, out.String())
	for name, want := range map[string]string{"one": "ok", "two": "ok", "three": "refused", "one-elsewhere": "refused"} {
		if !strings.HasPrefix(res[name], want) {
			t.Errorf("%s: %q, want %s", name, res[name], want)
		}
	}
	events := runEvents(t, p.ledger)
	if start := findEvent(events, func(e map[string]any) bool { return e["kind"] == "run_start" }); start == nil || start["tier"] != tier {
		t.Errorf("run_start %v, want tier %s", start, tier)
	}
	execLines := func(suffix string) []map[string]any {
		var lines []map[string]any
		for _, e := range events {
			if e["kind"] == "exec" && strings.HasSuffix(fmt.Sprint(e["path"]), suffix) {
				lines = append(lines, e)
			}
		}
		return lines
	}
	for _, c := range []struct{ suffix, verdict, rule string }{
		{"/mc/one", "allow", "exec[./mc/one]"},
		{"/mc/two", "allow", "exec[./mc/two]"},
		{"/mc/three", "refused", ""},
		{"/other/one", "refused", ""},
	} {
		lines := execLines(c.suffix)
		if len(lines) != 1 || lines[0]["verdict"] != c.verdict || (c.rule != "" && lines[0]["rule"] != c.rule) {
			t.Errorf("exec lines for %s: %v, want one %s line (rule %q)", c.suffix, lines, c.verdict, c.rule)
		}
	}
	if t.Failed() {
		t.Log(ledgerDump(p.ledger))
	}
}
