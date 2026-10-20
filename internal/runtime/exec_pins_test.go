// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/execpin"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
)

type fakePinHandle struct {
	on    bool
	err   error
	swept bool
}

func (h *fakePinHandle) ExecPins() (execpin.Key, bool) { return execpin.Key{7}, h.on }

func (h *fakePinHandle) PinExec(uint32, uint64, []byte) (uint32, error) { return 3, h.err }

func (h *fakePinHandle) SweepExecPins(func(uint32, uint64) bool) error { h.swept = true; return nil }

// TestExecPinnerOnlyForAPinnedHandle (ADR 0048 (3) P2): the supervisor gets a pinner and the run's key only from a
// handle whose slot is pinned, and the tier's full map reads as the supervisor's ErrExecPinsFull, which makes it sweep.
func TestExecPinnerOnlyForAPinnedHandle(t *testing.T) {
	if p, _ := execPinner(struct{}{}); p != nil {
		t.Fatal("a handle that cannot pin gave a pinner")
	}
	if p, _ := execPinner(&fakePinHandle{}); p != nil {
		t.Fatal("an unpinned handle gave a pinner")
	}
	h := &fakePinHandle{on: true}
	p, key := execPinner(h)
	if p == nil || key != (execpin.Key{7}) {
		t.Fatalf("a pinned handle: %v %v", p, key)
	}
	if seq, err := p.Pin(1, 2, nil); seq != 3 || err != nil {
		t.Fatalf("Pin = %d, %v", seq, err)
	}
	h.err = errors.Join(cgroup.ErrPinsFull, errors.New("E2BIG"))
	if _, err := p.Pin(1, 2, nil); !errors.Is(err, supervisor.ErrExecPinsFull) {
		t.Fatalf("a full map: %v", err)
	}
	h.err = errors.New("other")
	if _, err := p.Pin(1, 2, nil); err == nil || errors.Is(err, supervisor.ErrExecPinsFull) {
		t.Fatalf("another error: %v", err)
	}
	if err := p.Sweep(func(uint32, uint64) bool { return true }); err != nil || !h.swept {
		t.Fatal("Sweep did not reach the handle")
	}
}

// TestKillPinnedExecKillsTheSampledProcess (ADR 0048 (3), R6d): the backstop for a kill the plane could not send
// SIGKILLs, through its pidfd, the process the kill sample named, and refuses a pid whose start time says it is
// another process (a pid reused since the sample), leaving that process running.
func TestKillPinnedExecKillsTheSampledProcess(t *testing.T) {
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	fs := proc.New()
	st, err := fs.Stat(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	kill := killPinnedExec(fs)
	if err := kill(child.Process.Pid, st.StartBootNS()+uint64(time.Second)); err == nil {
		t.Fatal("the backstop signalled a pid whose start time is another process's")
	}
	if err := child.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("the refused kill reached the process: %v", err)
	}
	if err := kill(child.Process.Pid, st.StartBootNS()); err != nil {
		t.Fatalf("kill the sampled process: %v", err)
	}
	err = child.Wait()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("wait: %v, want the process killed", err)
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("the process ended %v, want SIGKILL", ee)
	}
}
