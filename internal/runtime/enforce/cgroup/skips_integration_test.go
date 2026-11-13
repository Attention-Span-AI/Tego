// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
)

// The agents of TestSkippedDecidingProgramEndsTheRun. Each writes out/ready once it runs, which is after the runtime
// read its skip counters' base (the agent is released only then), and stops at out/stop or its own timeout. Outside
// snapshots are diagnostics: an agent can end before the final snapshot, so only the run's record proves a skip in
// the product's reading window.

// skipBindAgent binds the contract's one abstract listener name over and over on CPU 0 until out/stop or %d seconds,
// closing each socket: every bind ends in sys_exit_bind, whose program (tego_bind_result, the listener cleanup) the run
// relies on.
const skipBindAgent = `import os, socket, time
try:
    os.sched_setaffinity(0, {0})
except OSError:
    pass
open("out/ready", "w").close()
end = time.time() + %d
n = 0
while time.time() < end and not os.path.exists("out/stop"):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.bind("\0%s")
    except OSError:
        pass
    s.close()
    n += 1
print("RESULT binds", n, flush=True)
`

// skipSleepAgent does nothing the run's programs decide: it waits for out/stop or %d seconds.
const skipSleepAgent = `import os, time
open("out/ready", "w").close()
end = time.time() + %d
while time.time() < end and not os.path.exists("out/stop"):
    time.sleep(0.05)
print("RESULT slept", flush=True)
`

// skipHostBinder is the ungoverned case's binder, a process in no run: it binds its own abstract name on CPU 0 and
// sleeps 200 microseconds between binds, so it wakes onto the CPU as often as the agent's binds, which wait on the
// supervisor, do; a binder that never slept was skipped nowhere in 22,467 updates (2026-11-11), since a CPU-bound pair
// switches only at the scheduler's own ticks.
const skipHostBinder = `import os, socket, time
os.sched_setaffinity(0, {0})
while True:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.bind("\0%s")
    except OSError:
        pass
    s.close()
    time.sleep(0.0002)
`

// skipAgentSeconds bounds an agent's own loop; skipForceWindow bounds how long a forced case tries to make a skip.
const (
	skipAgentSeconds = 90
	skipForceWindow  = 40 * time.Second
)

// skipProofRows are the kernel rows (TEGO_VM_ROW) on which the forced cases must force a skip: their kernels preempt
// kernel code (lazy), so a skip that cannot be forced there is a broken proof, not a kernel that does not allow one.
// fedora-7.2 is not one: its kernel also preempts kernel code, but from 7.2 a syscall tracepoint program runs under
// its own per-CPU guard, not the machine-wide one startBPFActiveHammer holds, so this hammer cannot make it skip
// there (ADR 0148, review of 2026-11-13). The forced cases still run on that row and skip when nothing was forced.
var skipProofRows = []string{"fedora-7.0"}

// startBPFActiveHammer updates a per-CPU array map from a thread pinned to CPU 0 until stop closes, and returns the
// count of updates. bpf(2)'s map update holds the CPU's bpf_prog_active with only migration off
// (bpf_disable_instrumentation; kernel/bpf/syscall.c), so where the kernel preempts kernel code, a preemption inside it
// leaves the counter held while the agent runs on CPU 0, and every syscall tracepoint program the agent's syscalls
// reach there is skipped and counted (trace_call_bpf). The value is 4 KiB per CPU, so most of the thread's time is
// inside that window. This is the only way the test forces a skip: no Tego program is changed, slowed or replaced.
func startBPFActiveHammer(t *testing.T, stop <-chan struct{}) *atomic.Uint64 {
	t.Helper()
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 4096, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Uint64
	done := make(chan struct{})
	t.Cleanup(func() { <-done; _ = m.Close() })
	go func() {
		defer close(done)
		runtime.LockOSThread() // never unlocked: the pinned thread ends with the goroutine
		var set unix.CPUSet
		set.Set(0)
		if err := unix.SchedSetaffinity(0, &set); err != nil {
			t.Errorf("pin the hammer to CPU 0: %v", err)
			return
		}
		vals := make([][4096]byte, ncpu)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := m.Update(uint32(0), vals, ebpf.UpdateAny); err != nil {
				t.Errorf("hammer update: %v", err)
				return
			}
			n.Add(1)
		}
	}()
	return &n
}

// watchedSkips sums, between two snapshots (skipSnapshot), the counters of the programs an unpinned lsm-mode run with
// listener policy relies on: the plane's lsm links but its exec pin check, cgroup_mkdir and the listener cleanup.
func watchedSkips(hash string, before, after map[string]uint64) (sum uint64, moved []string) {
	tracked := []string{ebpfbindings.ProgCgroupMkdir, ebpfbindings.ProgBindResult, ebpfbindings.ProgListenResult,
		ebpfbindings.ProgURingBindResult, ebpfbindings.ProgURingListenResult}
	plane := planeDirName(hash, ebpfbindings.PlaneLSM) + "/"
	for key, n := range after {
		dir, name := filepath.Split(key)
		watched := dir == plane && name != ebpfbindings.PlaneExecPinProgram(ebpfbindings.PlaneLSM) ||
			dir == hash+"/" && slices.Contains(tracked, name)
		if !watched || n <= before[key] {
			continue
		}
		sum += n - before[key]
		moved = append(moved, fmt.Sprintf("%s +%d", key, n-before[key]))
	}
	return sum, moved
}

// TestSkippedDecidingProgramEndsTheRun is ADR 0148's proof on a kernel that preempts kernel code, with the product
// build and the plane in lsm mode (no test waiver): a run with listener policy relies on tego_bind_result, a syscall
// tracepoint program the kernel can skip there, and the kernel is made to skip it by startBPFActiveHammer beside the
// agent on CPU 0, only once the agent says it runs and only until the test's last snapshot. The run's own record
// decides: a run whose record says a deciding program was skipped must have ended with reason error and kernel skips in
// its detail, its record must carry gap what=enforce why=bpf-decision-skip/shared-build with a count and the plane's
// mode, and its receipt must not call its coverage complete (code rules-uncertain); a run whose record says none must
// have ended by exit, as before. Outside counter movements are diagnostic only: the snapshots cannot establish
// whether a skip preceded the product's final reading. Each forced proof requires a deciding skip in the run's record.
//
// The control is the run with no hammer. The forced case's skip must be forced: where it is not, the case skips,
// except on skipProofRows, where it fails. The ungoverned case is the design's stated cost (ADR 0148 decision 6): the
// run's agent only sleeps, while a process no run governs binds beside the hammer on CPU 0; the skipped executions are
// that process's, the counter cannot say so, and the run that relies on the program is ended all the same.
func TestSkippedDecidingProgramEndsTheRun(t *testing.T) {
	// The proof boot: a proof row booted with bpf among its LSMs, where every escape below is a failure.
	lsms, _ := os.ReadFile("/sys/kernel/security/lsm")
	proofBoot := slices.Contains(skipProofRows, os.Getenv("TEGO_VM_ROW")) &&
		slices.Contains(strings.Split(strings.TrimSpace(string(lsms)), ","), "bpf")
	if proofBoot {
		failSkippedDecidingProof(t)
	}
	bin, uid, gid, modes := planePreconditions(t)
	if !slices.Contains(modes, "lsm") {
		if proofBoot {
			t.Fatalf("the plane's lsm mode is not selected on %s with bpf an active LSM (modes %v)", os.Getenv("TEGO_VM_ROW"), modes)
		}
		t.Skipf("the plane's lsm mode is not selected here (modes %v): this proof is of the product's mode", modes)
	}
	hash, err := bpfHash()
	if err != nil {
		t.Fatal(err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		if proofBoot {
			t.Fatalf("the agent is a python3 script, and this proof boot has none: %v", err)
		}
		t.Skipf("the agent is a python3 script: %v", err)
	}
	for _, c := range []struct {
		name               string
		forced, ungoverned bool
	}{{name: "control"}, {name: "forced", forced: true}, {name: "ungoverned", forced: true, ungoverned: true}} {
		t.Run(c.name, func(t *testing.T) {
			name := fmt.Sprintf("tego-skip-%d-%d", os.Getpid(), time.Now().UnixNano())
			agent := fmt.Sprintf(skipBindAgent, skipAgentSeconds, name)
			if c.ungoverned {
				agent = fmt.Sprintf(skipSleepAgent, skipAgentSeconds)
			}
			contract := fmt.Sprintf(`version: 0
name: skip-forced
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
exec:
  allow: ["python3"]
net:
  allow: []
  listen: ["unix:@%s"]
env:
  pass: ["PATH", "HOME"]
record: off
`, name)
			p := newPlaneProject(t, uid, gid, map[string]string{"agent.py": agent, "agent.yaml": contract}, []string{"out"}, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
			defer cancel()
			var out bytes.Buffer
			cmd := p.runAt(ctx, bin, "cgroup", "agent.yaml", "lsm", &out)
			started := time.Now()
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			waitFile(t, filepath.Join(p.project, "out", "ready"), 2*time.Minute, cmd, &out)
			before := skipSnapshot(t)
			stop := make(chan struct{})
			stopHammer := sync.OnceFunc(func() { close(stop) })
			// Stop before cleanup joins the hammer even when a later prerequisite calls Fatal.
			defer stopHammer()
			var updates *atomic.Uint64
			var binder *exec.Cmd
			if c.forced {
				updates = startBPFActiveHammer(t, stop)
				if c.ungoverned {
					// The binder: this test's own child, in no run, binding another abstract name on CPU 0.
					binder = exec.Command(python, "-c", fmt.Sprintf(skipHostBinder, name+"-host"))
					if err := binder.Start(); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = binder.Process.Kill(); _ = binder.Wait() })
				}
			}
			// The window: the control's is a few seconds of the agent's binds; a forced case's lasts until the run ends or
			// a watched skip has been seen and the poll has had time to answer it, within skipForceWindow.
			window := 3 * time.Second
			if c.forced {
				window = skipForceWindow
			}
			var runErr error
			ended := false
			deadline := time.Now().Add(window)
			for time.Now().Before(deadline) && !ended {
				select {
				case runErr = <-done:
					ended = true
				case <-time.After(250 * time.Millisecond):
					if c.forced {
						if n, _ := watchedSkips(hash, before, skipSnapshot(t)); n > 0 && time.Until(deadline) > 2*time.Second {
							deadline = time.Now().Add(2 * time.Second)
						}
					}
				}
			}
			if binder != nil {
				_ = binder.Process.Kill()
			}
			stopHammer()
			// Even a pending cmd.Wait result cannot prove that the run's final reading has not happened. Shared
			// counters may move after that reading, so this snapshot is diagnostic, never a lower bound on its record.
			after := skipSnapshot(t)
			if err := os.WriteFile(filepath.Join(p.project, "out", "stop"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			if !ended {
				runErr = <-done
			}
			took := time.Since(started)
			logSkipDelta(t, "skip-forced", before, after)
			sum, moved := watchedSkips(hash, before, after)
			events := runEvents(t, p.ledger)
			end := findEvent(events, func(e map[string]any) bool { return e["kind"] == "run_end" })
			var gaps []map[string]any
			for _, e := range events {
				if e["kind"] == "gap" && strings.HasPrefix(fmt.Sprint(e["why"]), "bpf-") && e["what"] == "enforce" {
					gaps = append(gaps, e)
				}
			}
			var decided float64
			for _, g := range gaps {
				if g["why"] == "bpf-decision-skip/shared-build" {
					cnt, _ := g["count"].(float64)
					decided += cnt
					if cnt < 1 || g["decision_plane"] != "lsm" {
						t.Errorf("the deciding skip line: %v, want a count and decision_plane lsm", g)
					}
				}
			}
			hammered := uint64(0)
			if updates != nil {
				hammered = updates.Load()
			}
			t.Logf("run took %v; watched skips in the test's window %d %v; %d hammer updates; run_end %v; enforce skip "+
				"gaps %v; run err %v", took.Round(time.Millisecond), sum, moved, hammered, end, gaps, runErr)
			if c.forced {
				requireDecidingSkipProof(t, proofBoot, decided, sum, hammered)
			}
			if decided == 0 {
				// No skip in the run's window: the run says what it said before.
				if runErr != nil || end == nil || end["reason"] != "exit" || len(gaps) != 0 {
					t.Fatalf("a run with no skip: err %v, run_end %v, gaps %v\n%s", runErr, end, gaps, out.String())
				}
				return
			}
			// A watched program was skipped while the run lived: it must not look like a run in which every rule held.
			if runErr == nil {
				t.Errorf("tego run exited 0 after the kernel skipped a program the run relies on\n%s", out.String())
			}
			if end == nil || end["reason"] != "error" || !strings.Contains(fmt.Sprint(end["detail"]), "kernel skips") {
				t.Errorf("run_end %v, want reason error with the kernel skips detail", end)
			}
			rc := receiptJSON(t, bin, p)
			var rulesUncertain bool
			for _, g := range rc.Coverage.Gaps {
				rulesUncertain = rulesUncertain || g.Field == "refusals" && g.Code == "rules-uncertain"
			}
			if rc.Coverage.Complete || !rulesUncertain {
				t.Errorf("the receipt's coverage %+v, want incomplete with refusals rules-uncertain", rc.Coverage)
			}
		})
	}
}

// receiptCoverage is the part of `tego receipt --json` this file reads.
type receiptCoverage struct {
	Coverage struct {
		Complete bool `json:"complete"`
		Gaps     []struct {
			Field, Code, Why string
		} `json:"gaps"`
	} `json:"coverage"`
}

// receiptJSON runs `tego receipt --json` on the project's one run, with the project's own config, anchor and log.
func receiptJSON(t *testing.T, bin string, p *planeProject) receiptCoverage {
	t.Helper()
	runs, err := filepath.Glob(filepath.Join(p.ledger, "*", "events.jsonl"))
	if err != nil || len(runs) != 1 {
		t.Fatalf("runs under %s: %v %v", p.ledger, runs, err)
	}
	cmd := exec.Command(bin, "receipt", "--json", filepath.Dir(runs[0]))
	cmd.Env = append(os.Environ(), "TEGO_CONFIG="+p.cfg, "TEGO_TEST_CHAIN_ANCHOR="+filepath.Join(p.base, "chain.log"),
		"TEGO_TEST_OWN_LOG_HOME="+filepath.Join(p.base, "home"))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("tego receipt: %v\n%s", err, stderr.String())
	}
	var rc receiptCoverage
	if err := json.Unmarshal(stdout.Bytes(), &rc); err != nil {
		t.Fatalf("receipt JSON: %v\n%s", err, stdout.String())
	}
	return rc
}

// decidingProofTest is the part of testing.T needed to keep required guest proofs from passing through a helper's
// skip, and to distinguish a forced skip in the run's record from an unrelated shared counter movement.
type decidingProofTest interface {
	Helper()
	Cleanup(func())
	Skipped() bool
	Fatalf(string, ...any)
	Skipf(string, ...any)
}

// failSkippedDecidingProof also catches skips buried in prerequisites such as the binary build and tier probe.
func failSkippedDecidingProof(t decidingProofTest) {
	t.Helper()
	t.Cleanup(func() {
		if t.Skipped() {
			t.Fatalf("the required deciding-skip proof skipped a prerequisite on this proof boot")
		}
	})
}

func requireDecidingSkipProof(t decidingProofTest, proofBoot bool, decided float64, outside, hammered uint64) {
	t.Helper()
	if decided > 0 {
		return
	}
	if proofBoot {
		t.Fatalf("no deciding skip was recorded during the run after %d hammer updates on this proof boot "+
			"(%d skips in outside snapshots, whose window may extend past the run's final reading)", hammered, outside)
		return
	}
	t.Skipf("no deciding skip was recorded during the run after %d hammer updates "+
		"(%d skips in outside snapshots): no skip was proven in the run's reading window", hammered, outside)
}
