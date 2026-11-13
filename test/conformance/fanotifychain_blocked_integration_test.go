// SPDX-License-Identifier: Apache-2.0

//go:build integration

package conformance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const blockedOpenChild = "TEGO_CONFORMANCE_BLOCKED_OPEN"

// testFanotifyProbeBlockedOpenCancellation exercises the probe's actual responder and worker owner with an
// unanswered kernel permission event. The responder is held before answerUntil, not replaced: after cancellation
// it must close the real group without writing a decision. No BPF program is needed to exercise that lifetime.
func testFanotifyProbeBlockedOpenCancellation(t *testing.T) {
	if path := os.Getenv(blockedOpenChild); path != "" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if ready := os.Getenv(blockedOpenChild + "_READY"); ready != "" {
			if err := os.WriteFile(ready, []byte(strconv.Itoa(unix.Gettid())), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("independent open: %v", err)
		}
		if err := unix.Close(fd); err != nil {
			t.Fatal(err)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("pending permission proof requires root")
	}
	path := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(path, []byte("scratch probe, never protected content"), 0o600); err != nil {
		t.Fatal(err)
	}
	row := os.Getenv("TEGO_VM_ROW")
	if row == "" {
		row = "host"
	}
	t.Run(row, func(t *testing.T) {
		for _, order := range []string{"pending", "before_start", "twice", "killed_pending"} {
			t.Run(order, func(t *testing.T) {
				// Warm runtime poll/exec machinery before comparing resource counts. A worker pins its syscall
				// to a thread and returns that thread to the runtime when it finishes, as the real probe does.
				goroutines := runtime.NumGoroutine()
				for i := 0; i < 10; i++ {
					blockedOpenIteration(t, path, order, i == 0)
				}
				blockedOpenEventually(t, "warmup goroutines joined", func() bool {
					return runtime.NumGoroutine() == goroutines
				})
				before := blockedOpenResources(t)
				t.Logf("resource baseline=%+v", before)
				start := time.Now()
				for i := 0; i < 200; i++ {
					blockedOpenIteration(t, path, order, false)
					blockedOpenEventually(t, fmt.Sprintf("resources after iteration %d (baseline=%+v)", i+1, before), func() bool {
						after := blockedOpenResources(t)
						// The runtime can grow its reusable OS-thread pool when a locked worker blocks.
						// Each iteration checks that worker's join and thread directly; total threads are
						// diagnostic, rather than an unrelated scheduler-capacity ceiling.
						return after.fds == before.fds && after.goroutines == before.goroutines
					})
				}
				t.Logf("200/200 in %s; resources before=%+v after=%+v; decisions written=0", time.Since(start), before, blockedOpenResources(t))
			})
		}
	})
}

type blockedOpenCounts struct{ fds, threads, goroutines int }

func blockedOpenResources(t *testing.T) blockedOpenCounts {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	threads, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	return blockedOpenCounts{len(fds), len(threads), runtime.NumGoroutine()}
}

func blockedOpenEventually(t *testing.T, what string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not complete within 3s; resources=%+v", what, blockedOpenResources(t))
		}
		time.Sleep(time.Millisecond)
	}
}

func blockedOpenReceive[T any](t *testing.T, what string, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatalf("%s did not complete within 3s", what)
		var zero T
		return zero
	}
}

func blockedOpenCommand(ctx context.Context, path, ready string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFanotifyProbeCancellationClosesGroup$/^pending_permission$", "-test.count=1", "-test.timeout=10s")
	cmd.Env = append(os.Environ(), blockedOpenChild+"="+path, blockedOpenChild+"_READY="+ready)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = time.Second
	return cmd
}

func blockedOpenIteration(t *testing.T, path, order string, report bool) {
	var lastWait string
	defer func() {
		if t.Failed() && lastWait != "" {
			t.Log(lastWait)
		}
	}()
	t.Helper()
	group, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_CLOEXEC)
	if err != nil {
		t.Fatalf("fanotify group: %v", err)
	}
	var once sync.Once
	closed := make(chan error, 1)
	closeGroup := func() { once.Do(func() { closed <- unix.Close(group) }) }
	defer closeGroup() // Emergency cleanup also releases the syscall when an assertion fails.
	if err := unix.FanotifyMark(group, unix.FAN_MARK_ADD, unix.FAN_OPEN_PERM, unix.AT_FDCWD, path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if order == "before_start" {
		cancel()
	}
	responderStart, workerCleanup := make(chan struct{}), make(chan struct{})
	var startOnce, cleanupOnce sync.Once
	startResponder := func() { startOnce.Do(func() { close(responderStart) }) }
	releaseWorker := func() { cleanupOnce.Do(func() { close(workerCleanup) }) }
	defer startResponder()
	defer releaseWorker()
	answered := make(chan error, 1)
	go func() {
		<-responderStart
		answered <- answerUntil(group, ctx.Done(), closeGroup)
	}()
	started, returned := make(chan int, 1), make(chan error, 1)
	cleaning, finished, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var child *exec.Cmd
	childCtx, stopChild := context.WithCancel(context.Background())
	defer stopChild()
	if order == "killed_pending" {
		ready := path + ".ready"
		defer func() { _ = os.Remove(ready) }()
		child = blockedOpenCommand(childCtx, path, ready)
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		blockedOpenEventually(t, "child thread announcement", func() bool {
			b, err := os.ReadFile(ready)
			if err != nil {
				return false
			}
			tid, err := strconv.Atoi(string(b))
			if err != nil {
				return false
			}
			started <- tid
			return true
		})
	}
	go func() {
		inChain, err := waitFanotifyChainProbe(ctx, func(ctx context.Context) (bool, error) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			defer close(finished)
			var openErr error
			if ctx.Err() != nil {
				started <- unix.Gettid()
				openErr = ctx.Err()
			} else if child != nil {
				openErr = child.Wait()
			} else {
				started <- unix.Gettid()
				fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
				openErr = err
				if err == nil {
					openErr = unix.Close(fd)
				}
			}
			returned <- openErr
			responderErr := <-answered
			closeGroup()
			close(cleaning)
			<-workerCleanup
			return false, responderErr
		})
		if inChain {
			err = errors.New("cancelled probe returned a measured chain result")
		}
		done <- err
	}()
	tid := blockedOpenReceive(t, "opener start", started)
	if order != "before_start" {
		// Nothing reads or writes this group until cancellation. Readiness proves an event is queued;
		// the specific task's sleep in fanotify_get_response proves Open really awaits its permission.
		blockedOpenEventually(t, "pending kernel permission open", func() bool {
			pfd := []unix.PollFd{{Fd: int32(group), Events: unix.POLLIN}}
			n, err := unix.Poll(pfd, 0)
			if err != nil && !errors.Is(err, unix.EINTR) {
				t.Fatal(err)
			}
			stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", tid))
			if err != nil {
				return false
			}
			wchan, err := os.ReadFile(fmt.Sprintf("/proc/%d/wchan", tid))
			fields := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+1:]))
			state := ""
			if len(fields) > 0 {
				state = fields[0]
			}
			lastWait = fmt.Sprintf("tid=%d poll=%d revents=%#x state=%s wchan=%q err=%v", tid, n, pfd[0].Revents, state, wchan, err)
			return n == 1 && pfd[0].Revents&unix.POLLIN != 0 && len(fields) > 0 && (fields[0] == "S" || fields[0] == "D") && err == nil && strings.Contains(string(wchan), "fanotify")
		})
		if report {
			t.Log(lastWait)
		}
		select {
		case err := <-returned:
			t.Fatalf("opener returned before cancellation, with no decision written: %v", err)
		default:
		}
	}
	if child != nil {
		if err := child.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		// Killing the task must be sufficient even while the group still holds its event unanswered.
		openErr := blockedOpenReceive(t, "killed pending opener", returned)
		var exitErr *exec.ExitError
		if !errors.As(openErr, &exitErr) || exitErr.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
			t.Fatalf("killed pending opener: %v, want SIGKILL", openErr)
		}
	}
	start := time.Now()
	cancel()
	if order == "twice" {
		cancel()
	}
	startResponder()
	if child == nil {
		openErr := blockedOpenReceive(t, "cancelled opener", returned)
		if order == "before_start" {
			if !errors.Is(openErr, context.Canceled) {
				t.Fatalf("pre-cancelled worker: %v", openErr)
			}
		} else if openErr != nil {
			t.Fatalf("group closure's open: %v, want success (the kernel releases unanswered permission events)", openErr)
		}
	}
	blockedOpenReceive(t, "responder joined by worker", cleaning)
	if err := blockedOpenReceive(t, "group closure", closed); err != nil {
		t.Fatalf("close group: %v", err)
	}
	if _, err := unix.FcntlInt(uintptr(group), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("group descriptor remains open: %v", err)
	}
	select {
	case err := <-done:
		t.Fatalf("probe returned before joining worker cleanup: %v", err)
	case <-time.After(time.Millisecond):
	}
	releaseWorker()
	if err := blockedOpenReceive(t, "probe worker join", done); !errors.Is(err, context.Canceled) {
		t.Fatalf("probe result: %v, want context.Canceled", err)
	}
	select {
	case <-finished:
	default:
		t.Fatal("probe returned with its worker still running")
	}
	if report {
		t.Logf("cancel and join: %s; probe result=context.Canceled; group fd=%d closed", time.Since(start), group)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("cancel and join took %s, bound 3s", elapsed)
	}
	if child != nil {
		blockedOpenEventually(t, "killed opener thread exit", func() bool {
			_, err := os.Stat(fmt.Sprintf("/proc/%d", tid))
			return errors.Is(err, os.ErrNotExist)
		})
	} else {
		// UnlockOSThread returns the completed worker's thread to Go's pool. It need not exit, but it
		// must no longer wait for fanotify. The joined worker and unchanged goroutine count also rule
		// out retaining it in a live, locked goroutine that is merely sleeping elsewhere.
		wchan, err := os.ReadFile(fmt.Sprintf("/proc/self/task/%d/wchan", tid))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("completed opener thread %d: %v", tid, err)
		}
		if strings.Contains(string(wchan), "fanotify") {
			t.Fatalf("joined opener thread %d remains in fanotify: %q", tid, wchan)
		}
	}
	// Closing a permission group fails open. This is safe here because only our disposable probe is marked,
	// the owner returns context.Canceled, and no cancelled measurement can become an enforcement decision.
	secondCtx, stopSecond := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopSecond()
	if out, err := blockedOpenCommand(secondCtx, path, "").CombinedOutput(); err != nil {
		t.Fatalf("second process opening the same file after cancellation: %v (%s), context=%v", err, out, secondCtx.Err())
	}
}
