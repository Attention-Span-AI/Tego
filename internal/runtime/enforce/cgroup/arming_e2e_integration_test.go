// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// armingContract makes ./out/ writable and denies reads of ./out/tools/, which holds a hard link to the tego
// binary that runs it: before ADR 0021 tier 2 refused this run at Prepare (ErrStageDenied), since the stage exemption
// would have hidden every read of tego from the permission group. The deny is nested in a write entry so that Landlock
// leaves it to the group or the plane, and R10 refuses a write entry at or over the file tego runs from, so the file
// is reached by a second name there. exec.allow names python3 alone, so an exec of tego by the run would be refused,
// the stage's first, whichever name it went by.
const armingContract = `version: 0
name: t2-arming
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
  deny_read: ["./out/tools/"]
exec:
  allow: ["python3"]
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
record: full
`

// armingAgent reads the tego binary it runs under, by the name the contract denies.
const armingAgent = `import os
try:
    with open("out/tools/tego", "rb") as f:
        f.read(4)
    print("RESULT read-tego allowed", flush=True)
except OSError as e:
    print("RESULT read-tego refused errno=%d" % e.errno, flush=True)
`

// TestTier2ArmsAfterTheStageExec is ADR 0021 (2) and (4) against the kernel, as an operator runs it: `sudo tego
// run --tier cgroup` with the tego binary under a deny_read entry and outside exec.allow. The tier arms (the
// run-set row and the fanotify marks) after the child stage's execve of that binary and before the ack, so:
//
//   - the stage's exec is never decided: the run starts, where a decided exec of an unnamed binary is refused at
//     clone3 (exit 125);
//   - the stage's exec is never recorded: no exec line names /proc/self/exe or the tego binary, and the first
//     one the run records is the agent's own exec of python3 (at tier 2 the supervisor writes every exec line,
//     ADR 0016 step 3, and the stage exec'd before its filter existed);
//   - a deny_read over tego is decided like any other file: the agent's read of it is refused, by the group with
//     EPERM and a source=fanotify line naming the entry where the run decides through fanotify, by the decision
//     plane with EACCES and a source=kernel read-denied line naming it where doctor selected a plane mode
//     (TIER3-PLAN T6; the plane's rows exist before the run-set row that arms them, as the marks did); either line
//     names the file by the denied link the agent opened, not by the name tego runs from.
//
// It runs as root with SUDO_UID set. It needs the objects in the tego it builds, not in this test binary, so
// both of the package's root builds run it (test/vm/root-must-pass.txt).
func TestTier2ArmsAfterTheStageExec(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("tier 2 needs root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
	}
	uid, gid, ok := sudoIDs()
	if !ok {
		t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("the agent is a python3 script: %v", err)
	}
	base, err := os.MkdirTemp("", "tego-t2-arm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o711); err != nil {
		t.Fatal(err)
	}
	built := buildTaggedTego(t, base)
	requireTier(t, built, "cgroup")

	project := filepath.Join(base, "project")
	tools := filepath.Join(project, "out", "tools")
	if err := os.MkdirAll(tools, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "agent.py"), []byte(armingAgent), 0o644); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(project, "agent.yaml")
	if err := os.WriteFile(contract, []byte(armingContract), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := filepath.Walk(project, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	}); err != nil {
		t.Fatal(err)
	}
	// The binary that runs, root's, with a second name in the denied directory: after the walk above, which would
	// hand it to the agent's user. The agent opens that name, so its refusal names denied, not bin: an open's line
	// names the path the open resolved (trace_proc's bpf_d_path of the file's f_path, or the fanotify event
	// descriptor's /proc/self/fd link), and two hard links are two dentries.
	bin := built
	denied := filepath.Join(tools, "tego")
	if err := os.Link(bin, denied); err != nil {
		t.Fatal(err)
	}
	ledgerRoot := filepath.Join(base, "ledger")
	if err := os.Mkdir(ledgerRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	_, resolverSetting, _ := machineResolver(t)
	cfg := filepath.Join(base, "config.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\nresolver: %s\n", ledgerRoot,
		resolverSetting)), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "run", "--tier", "cgroup", contract, "--", python, "./agent.py")
	cmd.Dir = project
	cmd.Env = testutil.TegoEnv(t, base, "TEGO_CONFIG="+cfg, "GOTRACEBACK=all")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.Cancel = func() error {
		t.Logf("`tego run` still running after the bound; its processes:\n%s", stalledRun())
		return cmd.Process.Signal(syscall.SIGABRT)
	}
	cmd.WaitDelay = 15 * time.Second
	runErr := cmd.Run()
	t.Logf("tego run: %v\nstdout:\n%s\nstderr:\n%s", runErr, stdout.String(), stderr.String())
	if runErr != nil {
		t.Fatalf("`tego run --tier cgroup` from a binary denied by deny_read and outside exec.allow did not run to "+
			"completion: %v (the stage's exec was decided, or Prepare refused the binary)", runErr)
	}
	plane := planeSelected(t, bin, "")
	wantRead, wantSource := "refused errno=1", "fanotify"
	if plane != PlaneFanotify {
		wantRead, wantSource = "refused errno=13", "kernel"
	}
	if got := agentResults(t, stdout.String())["read-tego"]; got != wantRead {
		t.Errorf("the agent's read of the tego binary under deny_read, deciding through %s: %q, want %q", plane, got, wantRead)
	}

	events := runEvents(t, ledgerRoot)
	var execs []string
	for _, e := range events {
		if e["kind"] == "exec" {
			execs = append(execs, fmt.Sprint(e["path"]))
		}
	}
	if len(execs) == 0 {
		t.Fatal("no exec line: nothing recorded the agent's first exec")
	}
	for _, p := range execs {
		if p == "/proc/self/exe" || p == bin || strings.HasSuffix(p, "/tego") {
			t.Errorf("an exec line names the child stage's exec of tego (%s): the run was armed "+
				"before the stage exec'd; execs %v", p, execs)
		}
	}
	if execs[0] != python {
		for _, e := range events {
			if e["kind"] == "exec" || e["kind"] == "gap" {
				t.Logf("arming outcome diagnostic: %v", e)
			}
		}
		t.Errorf("the run's first recorded exec is %s, want the agent's own %s; execs %v", execs[0], python, execs)
	}
	if findEvent(events, func(e map[string]any) bool {
		return e["kind"] == "fs" && e["source"] == wantSource && e["verdict"] == "refused" &&
			e["reason"] == "read-denied" && e["rule"] == "fs.deny_read[./out/tools/]" && e["path"] == denied
	}) == nil {
		t.Errorf("no source=%s read-denied refusal naming fs.deny_read[./out/tools/] for %s, the name the agent read",
			wantSource, denied)
		for _, e := range events {
			if e["kind"] == "fs" && e["verdict"] == "refused" {
				t.Logf("refused fs line the run did record: %v", e)
			}
		}
	}
	end := findEvent(events, func(e map[string]any) bool { return e["kind"] == "run_end" })
	if end == nil || end["reason"] != "exit" {
		t.Errorf("run_end %v, want reason exit", end)
	}
}
