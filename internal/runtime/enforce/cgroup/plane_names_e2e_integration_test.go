// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ADR 0043's name entries in a real `tego run` (NAME-BPF's governed-run cell): a tego built with the objects and
// the test hooks runs a contract whose built-in .env list becomes name entries over the project; the backend fills the slot's name map, config row and scope rows, and the kernel decides. The
// agent works in work/, a write entry beneath the contract's directory (the built-in's scope): a write entry that
// held the contract file would be a contradiction compile refuses.

const namesPlaneContract = `version: 0
name: plane-name-entries
command: ["python3", "./agent.py", "OUTSIDE"]
fs:
  write: ["./out/", "./work/", "OUTSIDE/"]
exec:
  allow: [python3]
net:
  allow: []
env:
  pass: ["PATH", "HOME", "PYTHONDONTWRITEBYTECODE"]
record: full
`

// namesPlaneAgent waits for the test to create work/later/.env.local from outside the run, then tries each action in
// work/ and reports it as "RESULT <name> <outcome>".
const namesPlaneAgent = `import os, sys, time

def result(name, outcome):
    print("RESULT", name, outcome, flush=True)

def attempt(name, fn):
    try:
        fn()
        result(name, "ok")
    except OSError as e:
        result(name, "refused errno=%d" % e.errno)

def read(p):
    with open(p) as f:
        f.read()

def write(p):
    with open(p, "w") as f:
        f.write("x")

outside = sys.argv[1]
write("out/ready")
while not os.path.exists("out/go"):
    time.sleep(0.02)
attempt("read-created-later", lambda: read("work/later/.env.local"))
attempt("read-plain", lambda: read("work/plain.txt"))
attempt("create", lambda: write("work/new/.env"))
attempt("rename-into", lambda: os.rename("work/a.txt", "work/.env.moved"))
attempt("link-into", lambda: os.link("work/b.txt", "work/.env.link"))
attempt("move-out", lambda: os.rename("work/sub", outside + "/sub"))
attempt("move-within", lambda: os.rename("work/sub2", "work/sub3"))
`

// TestPlaneNameEntriesRunEndToEnd is NAME-BPF's governed-run cell, at tier bpflsm (lsm mode) and at tier cgroup in each
// plane mode this kernel passes: a .env.local a process outside the run writes after the run started is unreadable
// to the agent, which also cannot create a .env, rename or link a file onto a covered name, or move a directory out
// of the project (D5), while a plain read and a move within the project go ahead; the read and the move each have one
// ledger line, from the plane, named by the built-in entry's label (ADR 0043 D8), and no file the refusals named
// exists. On the fanotify fallback the listener refuses the read (EPERM, one listener line) and its supervisor the
// creation, the renames, the link and the move out (R10's EACCES, supervisor R15f), the move with one line of its own.
func TestPlaneNameEntriesRunEndToEnd(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	for _, mode := range modes {
		tiers := []string{"cgroup"}
		if mode == "lsm" {
			tiers = append(tiers, "bpflsm")
		}
		for _, tier := range tiers {
			t.Run(tier+"@"+mode, func(t *testing.T) { namesPlaneRunCell(t, bin, uid, gid, mode, tier) })
		}
	}
	t.Run("cgroup@fanotify", func(t *testing.T) { namesPlaneRunCell(t, bin, uid, gid, "fanotify", "cgroup") })
}

func namesPlaneRunCell(t *testing.T, bin string, uid, gid int, mode, tier string) {
	t.Helper()
	outside, err := os.MkdirTemp("", "tego-plane-names-outside-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(outside) })
	if err := os.Chown(outside, uid, gid); err != nil {
		t.Fatal(err)
	}
	contract := strings.ReplaceAll(namesPlaneContract, "OUTSIDE", outside)
	p := newPlaneProject(t, uid, gid, map[string]string{
		"agent.py": namesPlaneAgent, "agent.yaml": contract, "work/a.txt": "a\n", "work/b.txt": "b\n",
		"work/plain.txt": "p\n", "work/sub/f": "f\n", "work/sub2/f": "f\n",
	}, []string{"out", "work/later", "work/new"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var out lockedBuffer
	cmd := p.runAt(ctx, bin, tier, "agent.yaml", mode, &out)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = os.WriteFile(filepath.Join(p.project, "out/go"), nil, 0o644)
			cancel()
			_ = cmd.Wait()
		}
	}()
	// The agent is ready, or the run ended or stalled first: then its own output says why.
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(filepath.Join(p.project, "out/ready")); err == nil {
			break
		}
		if !processLive(cmd.Process.Pid) || time.Now().After(deadline) {
			time.Sleep(200 * time.Millisecond)
			t.Fatalf("tego run --tier %s (%s) ended or stalled before its agent was ready:\n%s", tier, mode, out.String())
		}
	}
	// A tool of the user's, outside the run, writes a .env.local after compile and after the run started.
	later := filepath.Join(p.project, "work", "later", ".env.local")
	if err := os.WriteFile(later, []byte("SECRET=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A process outside the run reads it while the run's plane or marks are live.
	if _, err := os.ReadFile(later); err != nil {
		t.Errorf("a host process cannot read %s during the run: %v", later, err)
	}
	if err := os.WriteFile(filepath.Join(p.project, "out/go"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	waited = true
	if err != nil {
		t.Fatalf("tego run --tier %s (%s): %v\n%s", tier, mode, err, out.String())
	}
	res := agentResults(t, out.String())
	want := map[string]string{
		"read-created-later": "refused errno=13", "read-plain": "ok", "create": "refused errno=13",
		"rename-into": "refused errno=13", "link-into": "refused errno=13", "move-out": "refused errno=13",
		"move-within": "ok",
	}
	fallback := mode == "fanotify"
	if fallback {
		want["read-created-later"] = "refused errno=1" // the listener's FAN_DENY reaches the opener as EPERM (E2)
	}
	for name, w := range want {
		if res[name] != w {
			t.Errorf("%s: the agent saw %q, want %q", name, res[name], w)
		}
	}
	for _, gone := range []string{"work/new/.env", "work/.env.moved", "work/.env.link"} {
		if _, err := os.Lstat(filepath.Join(p.project, gone)); err == nil {
			t.Errorf("a refused action left %s", gone)
		}
	}
	if _, err := os.Stat(filepath.Join(p.project, "work", "sub", "f")); err != nil {
		t.Errorf("the refused move took work/sub out of the project: %v", err)
	}
	// ADR 0043 C9: the run records fs.deny_read.created_later where its plane's name check decides, and not on the
	// fallback, whose listener and supervisor refuse best effort; the row is in every ledger at MinorHeldReads or later
	// (ADR 0069 appended it, and the name entries' rule form is the held reads' own).
	for _, e := range runEvents(t, p.ledger) {
		if e["kind"] != "run_start" {
			continue
		}
		caps, _ := e["capabilities"].(map[string]any)
		if got, ok := caps["fs.deny_read.created_later"].(bool); !ok || got == fallback {
			t.Errorf("run_start capabilities fs.deny_read.created_later = %v (present %v), want %v", got, ok, !fallback)
		}
		if minor, _ := e["record_minor"].(float64); int(minor) < record.MinorHeldReads {
			t.Errorf("run_start record_minor = %v, want %d or later", e["record_minor"], record.MinorHeldReads)
		}
	}
	if fallback {
		var reads, moves []map[string]any
		for _, e := range runEvents(t, p.ledger) {
			if e["kind"] != "fs" || e["verdict"] != "refused" {
				continue
			}
			switch e["path"] {
			case later:
				reads = append(reads, e)
			case filepath.Join(p.project, "work", "sub"):
				moves = append(moves, e)
			}
		}
		rule := ""
		if len(reads) == 1 {
			rule, _ = reads[0]["rule"].(string)
		}
		if len(reads) != 1 || reads[0]["reason"] != "read-denied" || reads[0]["mechanism"] != nil ||
			!strings.HasPrefix(rule, "fs.deny_read[") || !strings.HasSuffix(rule, "/**/.env.*]") {
			t.Errorf("the created-later read on the fallback has lines %v, want one listener line, read-denied, "+
				"named fs.deny_read[<scope>/**/.env.*]", reads)
		}
		// The move out is the supervisor's refusal (R15f, D5), one line of its own, named by the .env entry.
		moveRule := ""
		if len(moves) == 1 {
			moveRule, _ = moves[0]["rule"].(string)
		}
		if len(moves) != 1 || moves[0]["reason"] != "rename-outside-contract" || moves[0]["mechanism"] == "plane" ||
			!strings.HasPrefix(moveRule, "fs.deny_read[") || !strings.HasSuffix(moveRule, "/**/.env]") {
			t.Errorf("the move out on the fallback has lines %v, want one supervisor line, rename-outside-contract, "+
				"named fs.deny_read[<scope>/**/.env]", moves)
		}
		if t.Failed() {
			t.Logf("tego run --tier %s (%s):\n%s", tier, mode, out.String())
			t.Log(ledgerDump(p.ledger))
		}
		return
	}
	events := runEvents(t, p.ledger)
	var reads, moves []map[string]any
	for _, e := range events {
		if e["kind"] != "fs" || e["verdict"] != "refused" {
			continue
		}
		path, _ := e["path"].(string)
		switch {
		case path == later:
			reads = append(reads, e)
		case path == filepath.Join(p.project, "work", "sub"):
			moves = append(moves, e)
		}
	}
	label := func(e map[string]any, form string) bool {
		rule, _ := e["rule"].(string)
		return strings.HasPrefix(rule, "fs.deny_read[") && strings.HasSuffix(rule, "/**/"+form+"]")
	}
	if len(reads) != 1 || reads[0]["reason"] != "read-denied" || reads[0]["mechanism"] != "plane" ||
		reads[0]["decision_plane"] != mode || !label(reads[0], ".env.*") {
		t.Errorf("the created-later read has lines %v, want one plane line, read-denied, named fs.deny_read[<scope>/**/.env.*]", reads)
	}
	if len(moves) != 1 || moves[0]["reason"] != "rename-outside-contract" || moves[0]["plane_reason"] != "refer" ||
		moves[0]["mechanism"] != "plane" || !label(moves[0], ".env") {
		t.Errorf("the move out has lines %v, want one plane line, rename-outside-contract (refer), named fs.deny_read[<scope>/**/.env]", moves)
	}
	if t.Failed() {
		t.Logf("tego run --tier %s (%s):\n%s", tier, mode, out.String())
		t.Log(ledgerDump(p.ledger))
	}
}
