// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The limits of a boundary adoption on the real kernel, as root (ADR 0055, the 2026-11-11 limits amendment): a machine
// config's limits.pids and limits.cpu ceilings are written into the adoption's cgroup before the move, so the adopted
// agent's forks past pids.max fail with EAGAIN and cpu.max throttles it, as cpu.stat counts; a tree with more tasks
// than the pids ceiling is refused before anything moves. A host whose cgroup root does not enable cpu (a stock
// AlmaLinux 9.8: systemd enables cpu at the root only once a unit asks for it) refuses the cpu ceiling's adoption,
// naming the setup, and nothing moves: that is the test's check on such a host, where it used to skip.

// adoptLimitsScript is the stand-in agent: commands from the fifo $AGENT_CMDS, each acknowledged in $AGENT_ACKS.
// "forks" runs $AGENT_FORKS (python3), which forks sleeping children until a fork fails and writes "<children> <errno
// name>" to $AGENT_OUT; "burn" spins one CPU for two seconds; "spawn" starts five sleeping children.
const adoptLimitsScript = `#!/bin/sh
exec 3<>"$AGENT_CMDS"
while IFS= read -r line <&3; do
	case "$line" in
	forks) python3 "$AGENT_FORKS" >"$AGENT_OUT" 2>&1 ;;
	burn) python3 -c 'import time
t = time.time()
while time.time() - t < 2: pass' ;;
	spawn) for i in 1 2 3 4 5; do sleep 600 & done ;;
	esac
	echo "$line $?" >>"$AGENT_ACKS"
done
`

// adoptForksPy forks until the kernel refuses, then ends its children.
const adoptForksPy = `import errno, os, time
kids, err = [], "none"
for _ in range(64):
    try:
        pid = os.fork()
    except OSError as e:
        err = errno.errorcode.get(e.errno, str(e.errno))
        break
    if pid == 0:
        time.sleep(30)
        os._exit(0)
    kids.append(pid)
print(len(kids), err)
for k in kids:
    os.kill(k, 9)
    os.waitpid(k, 0)
`

// adoptLimitsEnv is an adoptEnv whose machine config sets limits ceilings, with a boundary contract an adoption can
// hold, and its agent's workspace (where it writes), as uid 65534.
func adoptLimitsEnv(t *testing.T, ceilings string) (e *adoptEnv, contract, ws string) {
	t.Helper()
	e = newAdoptEnv(t)
	// The agent's sleeping children are in the terminal's cgroup; the test ends them all (cgroup.kill, 5.14+).
	t.Cleanup(func() { _ = os.WriteFile(filepath.Join(e.term, "cgroup.kill"), []byte("1"), 0) })
	if err := os.WriteFile(e.config, []byte("version: 0\nledger_root: "+e.ledger+"\nlimits:\n"+ceilings), 0o600); err != nil {
		t.Fatal(err)
	}
	ws = filepath.Join(e.dir, "ws")
	if err := os.Mkdir(ws, 0o777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(ws, 0o777)
	e.acks = filepath.Join(ws, "acks")
	forks := filepath.Join(e.dir, "forks.py")
	if err := os.WriteFile(forks, []byte(adoptForksPy), 0o644); err != nil {
		t.Fatal(err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("needs python3")
	}
	if real, err := filepath.EvalSymlinks(python); err == nil {
		python = real
	}
	contractDir := filepath.Join(filepath.Dir(e.dir), "contract")
	if err := os.Mkdir(contractDir, 0o755); err != nil {
		t.Fatal(err)
	}
	contract = filepath.Join(contractDir, "boundary.yaml")
	y := fmt.Sprintf("version: 0\nname: boundary\ncommand: [\"/bin/sh\"]\nrecord: summary\nfs:\n  write: [%q, \"/dev/null\"]\n"+
		"exec:\n  allow: [\"/bin/sh\", \"/usr/bin/sleep\", %q]\n", ws, python)
	if err := os.WriteFile(contract, []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(e.cmds, 0o666)
	e.startAgentAs(65534, adoptLimitsScript, "AGENT_FORKS="+forks, "AGENT_OUT="+filepath.Join(ws, "out"))
	return e, contract, ws
}

// adoptBoundaryOrSkip adopts e's agent under contract, skipping when no plane mode decides tier cgroup on this boot
// (no boundary holds then). A ceiling's controller the cgroup root does not enable is the caller's to check first
// (cgroupRootEnables): a refusal for it here fails the test.
func adoptBoundaryOrSkip(t *testing.T, e *adoptEnv, contract string) (*adopter, string) {
	t.Helper()
	a, run, ok := e.tryAdopt("--uid", "65534", "--boundary", contract)
	if ok {
		return a, run
	}
	switch text := a.text(); {
	case strings.Contains(text, "no decision plane decides") && os.Getenv("TEGO_TEST_PLANE_PREEMPT") != "waive":
		t.Skipf("no plane mode decides tier cgroup on this boot: %s", text)
	default:
		t.Fatalf("tego adopt --boundary ended before it recorded: %s", text)
	}
	return nil, ""
}

// TestIntegrationAdoptAppliesPidsAndCPUCeilings: on a machine whose config sets limits.pids 6 and limits.cpu 0.1, a
// boundary adoption (refused until 2026-11-11) goes on; its scope holds pids.max 6 and cpu.max 10000 100000 when it
// records; the adopted agent's forks fail with EAGAIN once its cgroup holds 6 tasks (the agent's shell and python
// count 2 of them); a busy loop is throttled (cpu.stat nr_throttled grows); and the release moves it back, its cgroup
// gone.
//
// Where the cgroup root does not enable cpu, the adoption is refused instead: exit 125 [adopt-refused], naming
// limits.cpu and the setup that gives the root cpu, with the agent where it was and no adoption scope left.
func TestIntegrationAdoptAppliesPidsAndCPUCeilings(t *testing.T) {
	e, contract, ws := adoptLimitsEnv(t, "  pids: 6\n  cpu: 0.1\n")
	if !cgroupRootEnables(t, "cpu") {
		adoptRefusesCPUCeiling(t, e, contract)
		return
	}
	a, run := adoptBoundaryOrSkip(t, e, contract)
	if !strings.Contains(a.text(), "limits: cpu 0.1, pids 6, written to its cgroup before the move") {
		t.Errorf("the notice does not say the limits: %s", a.text())
	}
	scope := e.scopeOf(run)
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(scope, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return strings.TrimSpace(string(b))
	}
	if got := read("pids.max"); got != "6" {
		t.Errorf("pids.max = %q, want 6", got)
	}
	if got := read("cpu.max"); got != "10000 100000" {
		t.Errorf("cpu.max = %q, want 10000 100000", got)
	}
	if s := e.send("forks"); s != 0 {
		t.Fatalf("the fork test exited %d", s)
	}
	out, _ := os.ReadFile(filepath.Join(ws, "out"))
	f := strings.Fields(string(out))
	if len(f) != 2 || f[1] != "EAGAIN" {
		t.Fatalf("the fork test said %q, want a count and EAGAIN", out)
	}
	if n, _ := strconv.Atoi(f[0]); n != 4 {
		t.Errorf("%d forks succeeded under pids.max 6 beside the agent's shell and python, want 4", n)
	}
	throttled := func() uint64 {
		for _, l := range strings.Split(read("cpu.stat"), "\n") {
			if v, ok := strings.CutPrefix(l, "nr_throttled "); ok {
				n, _ := strconv.ParseUint(v, 10, 64)
				return n
			}
		}
		t.Fatalf("cpu.stat has no nr_throttled: %s", read("cpu.stat"))
		return 0
	}
	before := throttled()
	if s := e.send("burn"); s != 0 {
		t.Fatalf("the busy loop exited %d", s)
	}
	if after := throttled(); after <= before {
		t.Errorf("cpu.stat nr_throttled went from %d to %d over a two-second busy loop under cpu.max 0.1", before, after)
	}
	_ = a.cmd.Process.Signal(syscall.SIGTERM)
	if code := a.wait(t); code != 0 {
		t.Fatalf("exit %d: %s", code, a.text())
	}
	if got := cgroupOfPID(e.agentPID); got != e.termRel {
		t.Errorf("the released agent is in %s, not %s", got, e.termRel)
	}
	if s := e.scopeOf(run); s != "" {
		t.Errorf("the scope %s is left after the release", s)
	}
	end := lastRunEnd(t, e.lines(run))
	if end.Resources == nil || end.Resources.CPUNrThrottled == nil || *end.Resources.CPUNrThrottled == 0 {
		t.Errorf("run_end.resources does not count the throttling: %+v", end.Resources)
	}
	if end.Reason != record.RunEndStopped {
		t.Errorf("run_end reason %s, want stopped", end.Reason)
	}
}

// cgroupRootEnables reports whether the cgroup2 root's subtree_control enables controller c.
func cgroupRootEnables(t *testing.T, c string) bool {
	t.Helper()
	b, err := os.ReadFile("/sys/fs/cgroup/cgroup.subtree_control")
	if err != nil {
		t.Fatal(err)
	}
	return slices.Contains(strings.Fields(string(b)), c)
}

// adoptRefusesCPUCeiling is TestIntegrationAdoptAppliesPidsAndCPUCeilings on a cgroup root without cpu (AlmaLinux 9.8 as
// it boots): limits.cpu cannot be applied there, so the adoption is refused before the agent moves, and says how to give
// the root cpu.
func adoptRefusesCPUCeiling(t *testing.T, e *adoptEnv, contract string) {
	t.Helper()
	scopes := func() int { m, _ := filepath.Glob("/sys/fs/cgroup/tego.slice/*/adopt-*.scope"); return len(m) }
	before := scopes()
	out, err := e.tegoCmd("adopt", "--pid", strconv.Itoa(e.agentPID), "--uid", "65534", "--boundary", contract).CombinedOutput()
	if strings.Contains(string(out), "no decision plane decides") && os.Getenv("TEGO_TEST_PLANE_PREEMPT") != "waive" {
		t.Skipf("no plane mode decides tier cgroup on this boot: %s", out)
	}
	for _, want := range []string{
		`controller "cpu" is not delegated, so limits.cpu cannot be applied and the run is refused`,
		`fix: add "+cpu" to cgroup.subtree_control of /sys/fs/cgroup`,
		"[adopt-refused]",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("the refusal does not say %q", want)
		}
	}
	if code := exitCode(err); code != 125 || t.Failed() {
		t.Fatalf("adopting under limits.cpu on a cgroup root without cpu: exit %d, want 125 and the refusal: %s", code, out)
	}
	if got := cgroupOfPID(e.agentPID); got != e.termRel {
		t.Errorf("the refused adoption moved the agent: it is in %s, not %s", got, e.termRel)
	}
	if after := scopes(); after != before {
		t.Errorf("a refused adoption left a scope: %d adoption scopes, %d before", after, before)
	}
}

// TestIntegrationAdoptRefusesATreeOverItsPidsCeiling: an agent whose tree holds more tasks than limits.pids (its shell
// and five sleeping children under pids 4) is refused, exit 125 [adopt-refused], with the count and the ceiling;
// nothing moved and no scope is left.
func TestIntegrationAdoptRefusesATreeOverItsPidsCeiling(t *testing.T) {
	e, contract, _ := adoptLimitsEnv(t, "  pids: 4\n")
	if s := e.send("spawn"); s != 0 {
		t.Fatalf("spawn exited %d", s)
	}
	time.Sleep(200 * time.Millisecond)
	scopes := func() int { m, _ := filepath.Glob("/sys/fs/cgroup/tego.slice/*/adopt-*.scope"); return len(m) }
	before := scopes()
	out, err := e.tegoCmd("adopt", "--pid", strconv.Itoa(e.agentPID), "--uid", "65534", "--boundary", contract).CombinedOutput()
	if strings.Contains(string(out), "no decision plane decides") && os.Getenv("TEGO_TEST_PLANE_PREEMPT") != "waive" {
		t.Skipf("no plane mode decides tier cgroup on this boot: %s", out)
	}
	if code := exitCode(err); code != 125 || !strings.Contains(string(out), "holds 6 tasks") ||
		!strings.Contains(string(out), "pids ceiling 4") || !strings.Contains(string(out), "raise limits.pids to 7 or more") ||
		!strings.Contains(string(out), "[adopt-refused]") {
		t.Fatalf("adopting a tree of 6 tasks under pids 4: exit %d (want 125, refused with the count): %s", code, out)
	}
	if got := cgroupOfPID(e.agentPID); got != e.termRel {
		t.Errorf("the refused adoption moved the agent: it is in %s", got)
	}
	if after := scopes(); after != before {
		t.Errorf("a refused adoption left a scope: %d adoption scopes, %d before", after, before)
	}
}
