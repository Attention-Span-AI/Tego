// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// cancelledAgent says it is running, then waits far longer than the test lets its run live.
const cancelledAgent = `import time
print("READY", flush=True)
time.sleep(120)
`

const cancelledContract = `version: 0
name: t2-cancelled
command: ["python3", "./agent.py"]
exec:
  allow: ["python3"]
env:
  pass: ["PATH", "HOME"]
`

// lockedBuffer is a strings.Builder a test can read while a command writes to it.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.WriteString(string(p))
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestACancelledTestRunLeavesNoRowOfItsBuild: a `tego run` a test stops at its bound (tegoRunCommand) is
// stopped as an operator stops one, and tears its run down: once it has returned, the build's run set holds no
// row of a live cgroup. Before, the bound SIGKILLed the launcher alone; its agent lived on in the run's scope,
// whose row kept the build pinned, and TestSecondLauncherAdoptsTheBuildsPinnedObjects, later in the same binary,
// found the build still there after its last launcher left.
func TestACancelledTestRunLeavesNoRowOfItsBuild(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("tier 2 needs root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
	}
	uid, gid, ok := sudoIDs()
	if !ok {
		t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
	}
	if _, err := bpfHash(); err != nil {
		t.Skipf("untagged: this test binary carries no BPF objects; the run belongs to the tegobpf suite: %v", err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("the agent is a python3 script: %v", err)
	}
	base, err := os.MkdirTemp("", "tego-t2-cancel-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o711); err != nil {
		t.Fatal(err)
	}
	bin := buildTaggedTego(t, base)
	requireTier(t, bin, "cgroup")
	if liveRunRows(t) {
		t.Fatal("the build's run set holds a live cgroup's row before this test's run started")
	}
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"agent.py": cancelledAgent, "agent.yaml": cancelledContract} {
		if err := os.WriteFile(filepath.Join(project, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Lchown(filepath.Join(project, name), uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Lchown(project, uid, gid); err != nil {
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := tegoRunCommand(ctx, bin, "run", "--tier", "cgroup", filepath.Join(project, "agent.yaml"), "--", python,
		"./agent.py")
	cmd.Dir = project
	cmd.Env = testutil.TegoEnv(t, base, "TEGO_CONFIG="+cfg)
	var stdout, stderr lockedBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.After(2 * time.Minute)
	for !strings.Contains(stdout.String(), "READY") {
		select {
		case err := <-done:
			t.Fatalf("the run ended before its agent started: %v\n%s", err, stderr.String())
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("the agent did not start in 2 minutes\n%s", stderr.String())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !liveRunRows(t) {
		t.Fatal("the running run has no live row in its build's run set: this test would prove nothing")
	}
	cancel() // the test's bound, reached
	select {
	case err := <-done:
		t.Logf("tego run, stopped at the bound: %v", err)
	case <-time.After(3 * time.Minute):
		t.Fatal("tego run did not return 3 minutes after its bound")
	}
	if liveRunRows(t) {
		t.Fatalf("a run stopped at the test's bound left its row in the build's run set, and with it the build "+
			"pinned for every later test\n%s", stderr.String())
	}
}
