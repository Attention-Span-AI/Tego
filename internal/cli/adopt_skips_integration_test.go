// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// adoptSkipStormScript is a busy agent of eight parallel readers of $AGENT_FILE, until $AGENT_STOP exists: every read
// is an open the plane's file_open program decides. It starts them only when the test writes a line to the FIFO
// $AGENT_GO, after the adoption is recorded: the adoption's own start-up probe asks the plane a known answer, and
// under the waiver a probe that meets a skipped hook rejects the mode, so readers already running could make the
// adoption refuse to start (seen once in six runs on Fedora 7.2.9; ADR 0148, review of 2026-11-13).
const adoptSkipStormScript = `#!/bin/sh
read -r _ <"$AGENT_GO"
for i in 1 2 3 4 5 6 7 8; do
	( while [ ! -e "$AGENT_STOP" ]; do read -r _ <"$AGENT_FILE"; done ) &
done
wait
`

// adoptSkipHostStorm is a process no run governs that opens a file in a loop, so that the shared file_open program
// meets enough concurrent openers to be skipped where kernel code is preempted.
const adoptSkipHostStorm = `import os, sys
p = sys.argv[1]
while True:
    os.close(os.open(p, os.O_RDONLY))
`

// adoptSkipHostSpawner is a process no run governs that runs /usr/bin/true in a loop: ADR 0024 (16)'s measured load
// put eight such spawners beside eight openers, whose wakeups give the scheduler a task to preempt the openers for.
const adoptSkipHostSpawner = `while :; do /usr/bin/true; done`

// fmodRetSkips sums the skip counters of the fmod_ret plane programs every build has attached under the pin root, read
// from outside the run as the cgroup package's skipsnap does, so a missing line can be told from a missing skip.
func fmodRetSkips(t *testing.T) uint64 {
	t.Helper()
	dirs, _ := filepath.Glob("/sys/fs/bpf/tego/*-fmod_ret/links/*")
	var sum uint64
	for _, path := range dirs {
		l, err := link.LoadPinnedLink(path, nil)
		if err != nil {
			continue
		}
		if info, err := l.Info(); err == nil {
			if p, err := ebpf.NewProgramFromID(info.Program); err == nil {
				if st, err := p.Stats(); err == nil {
					sum += st.RecursionMisses
				}
				_ = p.Close()
			}
		}
		_ = l.Close()
	}
	return sum
}

// adoptSkipProofRows are the rows (TEGO_VM_ROW) whose kernels preempt kernel code, where this test must make a skip.
var adoptSkipProofRows = []string{"fedora-7.0", "fedora-7.2"}

// TestIntegrationAdoptSkipIsRecordedAtOnce is ADR 0148 decision 7 on the real kernel: an adoption whose deciding
// programs the kernel skips is not ended (ending it would release the agent) and does not wait for its end to say so.
// The plane runs in fmod_ret mode, whose hooks a kernel that preempts kernel code can skip (the test build's waiver
// admits the mode there, for this test's tego commands only), and a busy agent beside eight readers no run governs
// makes the file_open hook meet enough concurrent openers. While the adopter still runs and the agent is still in the
// adoption's cgroup, the ledger must carry gap what=enforce why=bpf-decision-skip/shared-build with decision_plane
// fmod_ret and `tego status` must say the rules may not have held; the poll keeps counting, so a later line follows;
// the release then ends the adoption as it always does, with the agent running where it came from.
//
// The agent runs as uid 65534, adopted with --uid, as the boundary test's is: a boundary adoption makes the agent
// owner's ~/.tego for its deny of that owner's records (ADR 0055 Decision 5), so a root agent's adoption would make
// root's real one, which the suite's guard refuses. On skipAdoptProofRows nothing here skips: an adoption that fails,
// a mode that is not fmod_ret or a missing python3 is a failure there.
func TestIntegrationAdoptSkipIsRecordedAtOnce(t *testing.T) {
	proofRow := slices.Contains(adoptSkipProofRows, os.Getenv("TEGO_VM_ROW"))
	e := newAdoptEnv(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		if proofRow {
			t.Fatalf("the host's readers are a python3 script, and this proof row has none: %v", err)
		}
		t.Skipf("the host's readers are a python3 script: %v", err)
	}
	ws := filepath.Join(e.dir, "ws")
	if err := os.Mkdir(ws, 0o777); err != nil {
		t.Fatal(err)
	}
	contractDir := filepath.Join(filepath.Dir(e.dir), "contract")
	if err := os.Mkdir(contractDir, 0o755); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(contractDir, "boundary.yaml")
	y := fmt.Sprintf("version: 0\nname: skips\ncommand: [\"/bin/sh\"]\nrecord: summary\nfs:\n  write: [%q, \"/dev/null\"]\n"+
		"exec:\n  allow: [\"/bin/sh\", \"/usr/bin/sh\", \"/usr/bin/bash\"]\n", ws)
	if err := os.WriteFile(contract, []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(e.file, 0o644)
	stop := filepath.Join(e.dir, "stop")
	// The agent's readers wait for a line on this FIFO. The test holds it open for reading and writing, so neither
	// the agent's open nor the write below can block, and the line is still there if the agent opens late.
	goPath := filepath.Join(e.dir, "go")
	if err := syscall.Mkfifo(goPath, 0o666); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(goPath, 0o666)
	goFIFO, err := os.OpenFile(goPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = goFIFO.Close() })
	released := false
	releaseReaders := func() {
		if !released {
			released = true
			_, _ = goFIFO.WriteString("go\n")
		}
	}
	e.startAgentAs(65534, adoptSkipStormScript, "AGENT_STOP="+stop, "AGENT_GO="+goPath)
	// A test that ends before the release still lets the agent run on to its stop file.
	t.Cleanup(func() { _ = os.WriteFile(stop, nil, 0o644); releaseReaders() })
	// The waiver reaches this test's tego commands only (tegoCmd copies it from this process's environment), and the
	// test build's TEGO_TEST_PLANE pins fmod_ret mode (bpf.plane is honoured from /etc/tego/config.yaml only).
	t.Setenv("TEGO_TEST_PLANE_PREEMPT", "waive")
	e.tegoEnv = append(e.tegoEnv, "TEGO_TEST_PLANE=fmod_ret")
	a, run, ok := e.tryAdopt("--uid", "65534", "--boundary", contract)
	if !ok {
		if proofRow {
			t.Fatalf("tego adopt --boundary ended before it recorded on %s: %s", os.Getenv("TEGO_VM_ROW"), a.text())
		}
		t.Skipf("no fmod_ret plane decides an adopted boundary on this boot: %s", a.text())
	}
	if !strings.Contains(a.text(), "held by the decision plane") {
		t.Fatalf("a boundary adoption without the plane: %s", a.text())
	}
	start, _ := runStartOf(t, e.lines(run))
	t.Logf("adopted as %s, decision plane %q: %s", run, start.DecisionPlane, a.text())
	if start.DecisionPlane != "fmod_ret" {
		t.Fatalf("the adoption's plane is %q, not fmod_ret (TEGO_TEST_PLANE pins it, the waiver admits it): %s",
			start.DecisionPlane, a.text())
	}
	skips0 := fmodRetSkips(t)
	// The adoption is recorded and its plane is the pinned one: now the agent's readers may start.
	releaseReaders()
	var readers []*exec.Cmd
	stopReaders := func() {
		for _, c := range readers {
			_ = c.Process.Kill()
			_ = c.Wait()
		}
		readers = nil
	}
	t.Cleanup(stopReaders)
	for range 8 {
		c := exec.Command(python, "-c", adoptSkipHostStorm, e.file)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		readers = append(readers, c)
	}
	for range 8 {
		c := exec.Command("/bin/sh", "-c", adoptSkipHostSpawner)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		readers = append(readers, c)
	}
	decidingLines := func() (n int, total int, planes []string) {
		for _, ev := range e.lines(run) {
			var g record.GapPayload
			if ev.Kind == record.KindGap && ev.DecodePayload(&g) == nil && g.Why == record.GapDecidingSkip {
				n++
				total += g.Count
				planes = append(planes, g.DecisionPlane)
			}
		}
		return n, total, planes
	}
	// The first line, while the adoption lives.
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if n, _, _ := decidingLines(); n > 0 {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	n1, total1, planes := decidingLines()
	if n1 == 0 {
		t.Logf("the fmod_ret programs' counters gained %d skips meanwhile", fmodRetSkips(t)-skips0)
		stopReaders()
		if proofRow {
			t.Fatalf("no deciding skip in 90 s of a busy adopted agent and eight readers on %s, whose kernel preempts "+
				"kernel code", os.Getenv("TEGO_VM_ROW"))
		}
		t.Skip("no fmod_ret program was skipped here: this kernel did not preempt a task inside one")
	}
	select {
	case err := <-a.done:
		t.Fatalf("the adoption ended at its first skip (%v): %s", err, a.text())
	default:
	}
	scope := e.scopeOf(run)
	if scope == "" || !strings.HasSuffix(scope, cgroupOfPID(e.agentPID)) {
		t.Fatalf("the agent is no longer governed after the skip: in %q, scope %q", cgroupOfPID(e.agentPID), scope)
	}
	if slices.ContainsFunc(planes, func(p string) bool { return p != "fmod_ret" }) {
		t.Errorf("deciding lines name planes %v, want fmod_ret", planes)
	}
	status, _ := e.tegoCmd("status", run).CombinedOutput()
	if !strings.Contains(string(status), "the rules may not have held") {
		t.Errorf("tego status of the live adoption does not say the rules may not have held:\n%s", status)
	}
	// The poll goes on: allow the reporting interval plus the guest's scheduling and observation delay. The
	// deterministic runtime clock tests enforce the rate bound; this guest proof establishes continued reporting.
	waitAdoptSkipNextReport(func() int { n, _, _ := decidingLines(); return n }, n1, time.Now, time.Sleep)
	n2, total2, _ := decidingLines()
	stopReaders() // the agent itself runs on through its release
	t.Logf("first line after the adoption recorded: %d line(s), %d skips; later: %d lines, %d skips; adopter: %s",
		n1, total1, n2, total2, a.text())
	if n2 <= n1 {
		t.Errorf("no later line in %v of continued skips: the poll stopped after the first", adoptSkipNextReportBudget)
	}
	_ = a.cmd.Process.Signal(syscall.SIGTERM)
	if code := a.wait(t); code != 0 {
		t.Fatalf("tego adopt exit %d: %s", code, a.text())
	}
	if end := lastRunEnd(t, e.lines(run)); end.Reason == record.RunEndError {
		t.Errorf("run_end %+v: a skip ended the adoption with an error", end)
	}
	if n3, total3, _ := decidingLines(); n3 < n2 || total3 < total2 {
		t.Errorf("the end lost lines: %d lines and %d skips, %d and %d before", n3, total3, n2, total2)
	}
	if syscall.Kill(e.agentPID, 0) != nil || cgroupOfPID(e.agentPID) == "" || cgroupOfPID(e.agentPID) != e.termRel {
		t.Errorf("the released agent is not running where it came from: in %q, want %q", cgroupOfPID(e.agentPID), e.termRel)
	}
	if err := os.WriteFile(stop, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

// The product reports at most once a minute. A real guest needs a separate allowance for the next product poll,
// ledger write and the test's observation, especially when the host is busy.
const (
	adoptSkipReportInterval   = time.Minute
	adoptSkipSchedulingBudget = 30 * time.Second
	adoptSkipNextReportBudget = adoptSkipReportInterval + adoptSkipSchedulingBudget
)

func waitAdoptSkipNextReport(lines func() int, previous int, now func() time.Time, pause func(time.Duration)) bool {
	deadline := now().Add(adoptSkipNextReportBudget)
	for now().Before(deadline) {
		if lines() > previous {
			return true
		}
		pause(250 * time.Millisecond)
	}
	return lines() > previous
}
