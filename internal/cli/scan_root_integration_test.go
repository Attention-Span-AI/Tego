// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli

import (
	"bufio"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestScanAdvancedDropEveryThread checks the actual irreversible scan drop in a
// child. Locked threads survive the transition, and the drop is held at each
// point between its all-thread changes until the kernel has cloned at least one
// new thread there (scanThreadWaves.duringDrop). The parent reads every task's
// kernel credential state.
func TestScanAdvancedDropEveryThread(t *testing.T) {
	if os.Getenv("TEGO_SCAN_DROP_HELPER") == "1" {
		scanDropGuestHelper(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root in a guest")
	}
	if scanTestBinaryHasCgo() {
		// With cgo the runtime cannot change every thread's credentials: syscall.Setgroups answers EOPNOTSUPP at the first
		// step, and the drop then (rightly) fails closed. The shipped binary is built CGO_ENABLED=0, so this test must be.
		t.Fatal("this test binary was built with cgo, which cannot drop every thread's credentials (EOPNOTSUPP); build it as the product is: CGO_ENABLED=0 go test -c -tags integration,tegotesthooks ./internal/cli")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestScanAdvancedDropEveryThread$", "-test.v")
	cmd.Env = append(os.Environ(), "TEGO_SCAN_DROP_HELPER=1", "GOMAXPROCS=2")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 0, Gid: 0, Groups: []uint32{0, 27, 54321}}}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan string, 1)
	newDuring, newSteps := 0, 0
	readDone := make(chan struct{})
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); <-readDone })
	go func() {
		defer close(readDone)
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			if strings.HasPrefix(s.Text(), "SCAN-DROP-READY ") {
				ready <- s.Text()
				return
			}
			t.Log(s.Text())
		}
		ready <- ""
	}()
	select {
	case line := <-ready:
		if line == "" {
			t.Fatal("child ended before credentials could be read; see its preceding output")
		}
		t.Log(line)
		for _, field := range strings.Fields(line) {
			if count, ok := strings.CutPrefix(field, "created-during="); ok {
				newDuring, err = strconv.Atoi(count)
				if err != nil {
					t.Fatal(err)
				}
			}
			if count, ok := strings.CutPrefix(field, "steps-with-new-threads="); ok {
				newSteps, err = strconv.Atoi(count)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	case <-time.After(20 * time.Second):
		t.Fatal("credential transition did not finish in 20 seconds")
	}
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) < 48 {
		t.Fatalf("only %d threads, want retained and newly created threads", len(tasks))
	}
	for _, task := range tasks {
		path := filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "task", task.Name(), "status")
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		fields := map[string][]string{}
		for _, line := range strings.Split(string(b), "\n") {
			key, value, ok := strings.Cut(line, ":")
			if ok {
				fields[key] = strings.Fields(value)
			}
		}
		for _, key := range []string{"Uid", "Gid"} {
			if strings.Join(fields[key], ",") != "54320,54320,54320,54320" {
				t.Errorf("tid %s %s=%v", task.Name(), key, fields[key])
			}
		}
		if len(fields["Groups"]) != 0 {
			t.Errorf("tid %s Groups=%v", task.Name(), fields["Groups"])
		}
		for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
			if strings.Join(fields[key], "") != "0000000000000000" {
				t.Errorf("tid %s %s=%v", task.Name(), key, fields[key])
			}
		}
		if strings.Join(fields["NoNewPrivs"], "") != "1" {
			t.Errorf("tid %s NoNewPrivs=%v", task.Name(), fields["NoNewPrivs"])
		}
		t.Logf("tid=%s Uid=%v Gid=%v Groups=%v CapEff=%v NoNewPrivs=%v", task.Name(), fields["Uid"], fields["Gid"], fields["Groups"], fields["CapEff"], fields["NoNewPrivs"])
	}
	if newDuring < 4 || newSteps != 4 {
		t.Errorf("new kernel threads during the credential transition: %d at %d points, want at least one at each of 4", newDuring, newSteps)
	}
	if t.Failed() {
		return
	}
	t.Logf("SCAN-DROP-EVERY-THREAD PASS threads=%d", len(tasks))
}

func scanDropGuestHelper(t *testing.T) {
	groups, err := syscall.Getgroups()
	if err != nil || len(groups) < 2 {
		t.Fatalf("real supplementary groups missing: %v %v", groups, err)
	}
	w := newScanThreadWaves(t)
	w.die = func(args ...any) {
		fmt.Fprintln(os.Stderr, args...)
		os.Exit(1)
	}
	w.spawn(24)
	before := mustScanTaskIDs(t)
	initialTIDs := slices.Sorted(maps.Keys(before))
	runtime.LockOSThread()
	waves := w.duringDrop(func() error { return dropScanPrivileges(54320, 54320) })
	during, steps := 0, []string{}
	for _, wave := range waves {
		during += len(wave.newTIDs)
		steps = append(steps, fmt.Sprintf("%s:%v", wave.step, wave.newTIDs))
	}
	w.spawn(8)
	after := mustScanTaskIDs(t)
	if len(after) < len(before)+24 {
		t.Fatalf("new threads absent: before=%d after=%d", len(before), len(after))
	}
	fmt.Printf("SCAN-DROP-READY before=%d after=%d created-during=%d steps-with-new-threads=%d supplementary-before=%v initial-tids=%v new-tids-by-step=%v\n", len(before), len(after), during, len(waves), groups, initialTIDs, steps)
	for {
		time.Sleep(time.Hour)
	}
}

// scanTestBinaryHasCgo reports whether this test binary was built with cgo, from the build settings the toolchain records.
func scanTestBinaryHasCgo() bool {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, s := range info.Settings {
		if s.Key == "CGO_ENABLED" {
			return s.Value == "1"
		}
	}
	return false
}

// scanThreadWaves makes kernel threads on demand: each goroutine it starts locks itself to its thread and blocks
// forever, so that thread never runs anything else and the next goroutine needs another one.
type scanThreadWaves struct {
	t       *testing.T
	created chan int
	// die ends the test on a failed drop. The helper child makes it exit at once: by then it may have dropped its
	// credentials, and the test binary's guard, run by what is left of that process, cannot read the real ~/.tego
	// of the accounts it watches and reports them removed, hiding the failure's own message.
	die func(args ...any)
}

// scanDropWave is what one point of the drop saw: the kernel threads created while the drop was held there, each
// listed in /proc/self/task at that point and absent from it when the point was reached.
type scanDropWave struct {
	step    string
	newTIDs []int
}

func newScanThreadWaves(t *testing.T) *scanThreadWaves {
	return &scanThreadWaves{t: t, created: make(chan int), die: t.Fatal}
}

// spawn starts n locked goroutines and returns their thread ids once every one is running on its thread.
func (w *scanThreadWaves) spawn(n int) []int {
	for range n {
		go func() {
			runtime.LockOSThread()
			w.created <- syscall.Gettid()
			select {}
		}()
	}
	tids := make([]int, 0, n)
	for range n {
		tids = append(tids, <-w.created)
	}
	return tids
}

// duringDrop runs drop with the drop held at each point between its all-thread changes (scanDropStepHook). At each
// point it lists the process's threads, starts 16 locked goroutines and then more, one at a time, until one runs
// on a thread that was not listed, which the kernel therefore cloned while the drop was held. That ends: every
// locked goroutine keeps its thread, so after as many goroutines as there were listed threads the next one cannot
// find a free one. Only then is the drop released. No sleep and no retry decides the schedule:
// a correct drop meets threads created in every gap, and a drop that misses one leaves it with the old credentials,
// which the parent reads from the kernel.
func (w *scanThreadWaves) duringDrop(drop func() error) []scanDropWave {
	reached := make(chan string)
	release := make(chan struct{})
	scanDropStepHook = func(step string) {
		reached <- step
		<-release
	}
	defer func() { scanDropStepHook = nil }()
	var waves []scanDropWave
	var waveErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		for step := range reached {
			if waveErr == nil {
				var wave scanDropWave
				wave, waveErr = w.wave(step)
				waves = append(waves, wave)
			}
			release <- struct{}{}
		}
	}()
	err := drop()
	close(reached)
	<-done
	if err != nil {
		w.die(fmt.Sprintf("the drop failed after %d of its points: %v", len(waves), err))
	}
	if waveErr != nil {
		w.die(waveErr)
	}
	if want := []string{"groups", "gid", "uid", "no-new-privs"}; len(waves) != len(want) {
		w.die(fmt.Sprintf("drop held at %d points, want %v", len(waves), want))
	}
	return waves
}

func (w *scanThreadWaves) wave(step string) (scanDropWave, error) {
	listed, err := scanTaskIDs()
	if err != nil {
		return scanDropWave{}, err
	}
	tids := w.spawn(16)
	for !slices.ContainsFunc(tids, func(tid int) bool { return !listed[tid] }) {
		if len(tids) > len(listed) {
			return scanDropWave{}, fmt.Errorf("at %s: %d locked goroutines found %d listed threads without a new one", step, len(tids), len(listed))
		}
		tids = append(tids, w.spawn(1)...)
	}
	now, err := scanTaskIDs()
	if err != nil {
		return scanDropWave{}, err
	}
	wave := scanDropWave{step: step}
	for _, tid := range tids {
		if listed[tid] {
			continue
		}
		if !now[tid] {
			return scanDropWave{}, fmt.Errorf("at %s: thread %d is not in /proc/self/task", step, tid)
		}
		wave.newTIDs = append(wave.newTIDs, tid)
	}
	slices.Sort(wave.newTIDs)
	return wave, nil
}

// scanTaskIDs is the kernel's list of this process's threads. The waves read it off the test's goroutine, so it
// returns its error rather than failing the test there.
func scanTaskIDs() (map[int]bool, error) {
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return nil, err
	}
	ids := make(map[int]bool, len(tasks))
	for _, task := range tasks {
		tid, err := strconv.Atoi(task.Name())
		if err != nil {
			return nil, err
		}
		ids[tid] = true
	}
	return ids, nil
}

func mustScanTaskIDs(t *testing.T) map[int]bool {
	ids, err := scanTaskIDs()
	if err != nil {
		t.Fatal(err)
	}
	return ids
}
