// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/pin"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// ADR 0022's kill tests through the real binary (plan C5): `tego run` as root from the tagged binary, with bpf.linger
// set by TEGO_TEST_LINGER (internal/cli/machine_testhook.go) as /etc/tego/config.yaml would set it, and the reaper
// held by TEGO_TEST_REAP_HOLD (reap_e2e_integration_test.go). Each test runs in every cell the machine offers
// (killCells): tier cgroup with each decision-plane mode pinned by TEGO_TEST_PLANE, and tier bpflsm. Every run of
// the package's binary is of one build, so each cell first ends the timers earlier ones left for it, which sleep to a
// linger of their own.

// killCell is one way a kill test runs the build: the tier its runs ask for and the environment that pins its plane.
type killCell struct {
	name, tier string
	env        []string
}

// killCells are the cells this machine runs: tier cgroup in each plane mode it passes (lsm, fmod_ret), or with the
// fanotify listener where it passes none, and tier bpflsm where doctor offers it. A cell the machine lacks is logged.
func killCells(t *testing.T, e reapEnv) []killCell {
	t.Helper()
	var cells []killCell
	for _, m := range planeModesHere(t, e.bin) {
		cells = append(cells, killCell{name: "cgroup-" + m, tier: "cgroup", env: []string{"TEGO_TEST_PLANE=" + m}})
	}
	if len(cells) == 0 {
		cells = append(cells, killCell{name: "cgroup-" + PlaneFanotify, tier: "cgroup",
			env: []string{"TEGO_TEST_PLANE=" + PlaneFanotify}})
	}
	switch offered, out, err := testutil.DoctorOffers(isolatedTego(t, e.bin, "doctor", "--require", "bpflsm")); {
	case err != nil:
		t.Fatalf("tego doctor --require bpflsm gave no answer about this machine: %v\n%s", err, out)
	case offered:
		cells = append(cells, killCell{name: "bpflsm", tier: "bpflsm"})
	default:
		t.Log("this machine offers no tier bpflsm: its kill-test cell is not run here")
	}
	return cells
}

// inCells runs body once per cell of killCells, each in a subtest with a fresh project, ledger and config.
func inCells(t *testing.T, body func(t *testing.T, e reapEnv)) {
	t.Helper()
	e := newReapEnv(t)
	for _, c := range killCells(t, e) {
		t.Run(c.name, func(t *testing.T) {
			ce := e
			ce.tier, ce.env = c.tier, c.env
			body(t, ce.fresh(t))
		})
	}
}

// TestIntegrationLingerZeroKillRemovesTheBuild is step 1 test 1: at bpf.linger 0 the only launcher is SIGKILLed,
// and once its reaper is let go the build is gone, its pin directory and its plane directories with it; no link the
// kernel still has attaches a program of the build, and no timer runs for it (linger 0 starts none).
func TestIntegrationLingerZeroKillRemovesTheBuild(t *testing.T) {
	inCells(t, lingerZeroKill)
}

func lingerZeroKill(t *testing.T, e reapEnv) {
	r := e.startOrphanable(t, "TEGO_TEST_LINGER=0s")
	endTimers(t, r.hash)
	progs := buildPrograms(t, r.hash)
	if len(progs) == 0 {
		t.Fatalf("the build %s pins no program", r.hash)
	}
	r.kill(t)
	r.assertKept(t, "launcher dead, reaper held")
	released := time.Now()
	if err := os.WriteFile(r.hold, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// At linger 0 the reaper removes the build itself before it exits (ReapBuild): the removal takes the kernel's
	// teardown, which 6.1 and 5.14 do synchronously in the unpinning process, waited for up to teardownWait.
	r.waitPurged(t, 10*time.Second+teardownWait)
	waitBuildGone(t, r.hash, 30*time.Second)
	waitNoLinkOf(t, progs, 30*time.Second)
	t.Logf("released the reaper: the build and every link of its %d programs gone after %v", len(progs),
		time.Since(released).Round(time.Millisecond))
	if pids := timers(r.hash); len(pids) > 0 {
		t.Errorf("timers %v run for the build at bpf.linger 0", pids)
	}
}

// TestIntegrationABuildOutlivesItsLastLauncherWhileAKilledOnesRunLives is step 2, at bpf.linger 0 and 2 s: launcher A
// is SIGKILLed with its reaper held, launcher B of the same build runs and exits, and the build stays (its pins, its
// plane directories, A's run links), since A's run is alive and in its run set (ADR 0022 (1)); once A's reaper is let
// go and has purged A's run, the build goes: at once at linger 0, by the reaper; at 2 s by the timer the reaper
// starts, within the linger and the timer's second of slack, plus the removal's own time.
func TestIntegrationABuildOutlivesItsLastLauncherWhileAKilledOnesRunLives(t *testing.T) {
	inCells(t, outlivesItsLastLauncher)
}

func outlivesItsLastLauncher(t *testing.T, cell reapEnv) {
	for _, linger := range []time.Duration{0, 2 * time.Second} {
		t.Run("linger="+linger.String(), func(t *testing.T) {
			env := "TEGO_TEST_LINGER=" + linger.String()
			e := cell.fresh(t)
			a := e.startOrphanable(t, env)
			endTimers(t, a.hash)
			a.kill(t)
			// B records in a ledger root of its own: `run` first ends the orphans its own ledger root holds (R20's
			// SweepLive), A's among them, which would leave no run of A's to keep the build.
			b := e
			b.ledger, b.cfg = filepath.Join(e.base, "ledger-b"), filepath.Join(e.base, "config-b.yaml")
			if err := os.Mkdir(b.ledger, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(b.cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\n", b.ledger)), 0o644); err != nil {
				t.Fatal(err)
			}
			if out, err := b.runQuick(t, env); err != nil {
				t.Fatalf("launcher B: %v\n%s", err, out)
			}
			time.Sleep(linger + 1500*time.Millisecond) // past B's linger by more than the lock mtime's second
			a.assertKept(t, "B exited, A's reaper held")
			if _, err := os.Stat(filepath.Join(DefaultBPFFS, pinRoot, a.hash, pinProgs)); err != nil {
				t.Fatalf("the build went under A's live run: %v", err)
			}
			released := time.Now()
			if err := os.WriteFile(a.hold, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			a.waitPurged(t, 10*time.Second+teardownWait) // at linger 0 the reaper removes the build before it exits
			purged := time.Since(released)
			// The timer sleeps to the lock's mtime, which the reaper stamps, plus the linger and a second; the
			// removal then takes the kernel's teardown, waited for up to teardownWait (on 6.1 7 to 10.5 s for the
			// whole build, 2026-10-20).
			waitBuildGone(t, a.hash, linger+time.Second+teardownWait+10*time.Second)
			gone := time.Since(released)
			t.Logf("released A's reaper: A purged after %v, the build gone after %v", purged.Round(time.Millisecond),
				gone.Round(time.Millisecond))
			if linger > 0 && gone < linger {
				t.Errorf("the build went %v after A's reaper was let go, inside its linger of %v", gone, linger)
			}
		})
	}
}

// TestIntegrationAKilledTimerLeavesTheBuildUntilStop is step 3 through the real binary: a run at bpf.linger 5 s exits,
// its launcher, the last out, starts the build's timer in tego's helper cgroup, and every timer of the build is
// SIGKILLed; past the linger the build stays (no other run, stop or gc acts for it), and a root `tego stop` of the
// finished run starts its timer again, which removes it.
func TestIntegrationAKilledTimerLeavesTheBuildUntilStop(t *testing.T) {
	inCells(t, killedTimerLeavesTheBuild)
}

func killedTimerLeavesTheBuild(t *testing.T, e reapEnv) {
	const linger = 5 * time.Second
	env := "TEGO_TEST_LINGER=" + linger.String()
	if out, err := e.runQuick(t, env); err != nil {
		t.Fatalf("tego run: %v\n%s", err, out)
	}
	dirs, _ := filepath.Glob(filepath.Join(e.ledger, "r-*"))
	if len(dirs) != 1 {
		t.Fatalf("run directories %v, want the one run's", dirs)
	}
	id := filepath.Base(dirs[0])
	hash, _ := reapRunStart(t, dirs[0])["bpf_hash"].(string)
	if hash == "" {
		t.Fatalf("run_start of %s names no build", id)
	}
	// The run's own timer, or an earlier test's that held the timer lock, on which the run's exited.
	pids := timers(hash)
	if len(pids) == 0 {
		t.Fatal("no timer runs for the build after its last run")
	}
	for _, pid := range pids {
		cg, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
		if !strings.Contains(string(cg), "/tego.slice/helpers.scope") {
			t.Errorf("the timer %d runs in %q, want tego.slice/helpers.scope", pid, strings.TrimSpace(string(cg)))
		}
	}
	endTimers(t, hash)
	time.Sleep(linger + 3*time.Second)
	if _, err := os.Stat(filepath.Join(DefaultBPFFS, pinRoot, hash, pinProgs)); err != nil {
		t.Fatalf("the build went with its timer killed and no run, stop or gc after it: %v", err)
	}
	stop := exec.Command(e.bin, "stop", id)
	stop.Env = append(testutil.TegoEnv(t, e.base, "TEGO_CONFIG="+e.cfg, env), e.env...)
	out, err := stop.CombinedOutput()
	stopped := time.Now()
	if err != nil || !strings.Contains(string(out), id+": not running") {
		t.Fatalf("tego stop: %v\n%s", err, out)
	}
	waitBuildGone(t, hash, time.Second+teardownWait+10*time.Second)
	t.Logf("the timer tego stop started removed the build %v after stop returned", time.Since(stopped).Round(time.Millisecond))
}

// runQuick runs reapAgent's quick form to its end at e.tier with e.env, as a second launcher of the build.
func (e reapEnv) runQuick(t *testing.T, extraEnv ...string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command(e.bin, "run", "--tier", e.tier, filepath.Join(e.project, "agent.yaml"), "--",
		e.python, "./agent.py", "quick")
	cmd.Dir = e.project
	cmd.Env = append(append(testutil.TegoEnv(t, e.base, "TEGO_CONFIG="+e.cfg), e.env...), extraEnv...)
	cmd.WaitDelay = 5 * time.Second
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return out.Bytes(), err
	case <-time.After(launchWait):
		_ = cmd.Process.Kill()
		<-done
		return out.Bytes(), fmt.Errorf("the run did not end within %v", launchWait)
	}
}

// timers are the pids of the processes whose argv is `<exe> __bpf-linger <hash> ...`.
func timers(hash string) []int {
	var out []int
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			continue
		}
		argv := strings.Split(string(b), "\x00")
		if len(argv) > 2 && argv[1] == LingerCommand && argv[2] == hash {
			out = append(out, pid)
		}
	}
	return out
}

// endTimers SIGKILLs the timers of build hash that earlier tests left, while the caller's launcher holds the build,
// and waits for them to go: each sleeps to its own linger and holds the timer lock, on which a timer of this test's
// linger would exit.
func endTimers(t *testing.T, hash string) {
	t.Helper()
	pids := timers(hash)
	for _, pid := range pids {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	for deadline := time.Now().Add(10 * time.Second); len(timers(hash)) > 0; {
		if time.Now().After(deadline) {
			t.Fatalf("the earlier timers %v of the build did not end", timers(hash))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(pids) > 0 {
		t.Logf("ended the earlier tests' timers %v of the build", pids)
	}
}

// buildRoots are build hash's pin directory and its plane directories.
func buildRoots(hash string) []string {
	base := filepath.Join(DefaultBPFFS, pinRoot)
	roots := []string{filepath.Join(base, hash)}
	for _, m := range planeModes {
		roots = append(roots, filepath.Join(base, planeDirName(hash, m)))
	}
	return roots
}

// buildPrograms are the ids of the programs pinned under build hash and its plane directories, and of the programs
// their pinned links attach.
func buildPrograms(t *testing.T, hash string) map[ebpf.ProgramID]bool {
	t.Helper()
	ids := map[ebpf.ProgramID]bool{}
	for _, root := range buildRoots(hash) {
		err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
			if errors.Is(err, fs.ErrNotExist) && path == root {
				return fs.SkipDir
			}
			if err != nil || e.IsDir() {
				return err
			}
			obj, err := pin.Load(path, nil)
			if err != nil {
				return err
			}
			defer func() { _ = obj.Close() }()
			switch o := obj.(type) {
			case *ebpf.Program:
				info, err := o.Info()
				if err != nil {
					return err
				}
				if id, ok := info.ID(); ok {
					ids[id] = true
				}
			case link.Link:
				info, err := o.Info()
				if err != nil {
					return err
				}
				ids[info.Program] = true
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	return ids
}

// waitBuildGone waits for build hash's pin directory and its plane directories to be gone.
func waitBuildGone(t *testing.T, hash string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		var left []string
		for _, root := range buildRoots(hash) {
			if _, err := os.Stat(root); err == nil {
				left = append(left, root)
			}
		}
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after %v the build is still pinned at %v (timers %v)", within, left, timers(hash))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitNoLinkOf waits until no link the kernel holds attaches one of progs.
func waitNoLinkOf(t *testing.T, progs map[ebpf.ProgramID]bool, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		var left []string
		it := new(link.Iterator)
		for it.Next() {
			if info, err := it.Link.Info(); err == nil && progs[info.Program] {
				left = append(left, fmt.Sprintf("link %d (type %d) of program %d", info.ID, info.Type, info.Program))
			}
		}
		if err := it.Err(); err != nil {
			t.Fatalf("iterate the kernel's links: %v", err)
		}
		it.Close()
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after %v these links still attach the build's programs: %v", within, left)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
