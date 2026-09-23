// SPDX-License-Identifier: Apache-2.0

//go:build integration

package launch

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
)

// listenerHandle is fakeHandle with the loop a tier-2 handle owns (api.Listener): what makes Start hold
// the launcher's job control (E40).
type listenerHandle struct{ fakeHandle }

func (listenerHandle) RunListener(context.Context) error { return nil }

// The job-control helpers run before TestMain: TEGO_LAUNCH_HELPER=jobcontrol starts an agent under a
// listener handle, =jobcontrol-plain under one without, and each prints the agent's pid and sleeps. The child
// stage's environment is empty, so the stage never takes this branch.
func init() {
	switch os.Getenv("TEGO_LAUNCH_HELPER") {
	case "jobcontrol":
		os.Exit(jobControlHelper(listenerHandle{fakeHandle{ruleset: -1}}))
	case "jobcontrol-plain":
		os.Exit(jobControlHelper(fakeHandle{ruleset: -1}))
	}
}

func jobControlHelper(h api.Handle) int {
	ctx := context.Background()
	child, err := (&Launcher{}).Start(ctx, ChildSpec{Command: []string{"/bin/sleep", "60"}, Dir: "/", Handle: h}, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	// The listener stays open until the helper process exits.
	if _, err := child.WaitNotifyFD(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := child.Ack(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(child.PID)
	time.Sleep(time.Hour) // the test kills the process group
	return 0
}

// procState is field 3 of /proc/<pid>/stat: R, S, T (stopped) ...
func procState(t *testing.T, pid int) byte {
	t.Helper()
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 || i+2 >= len(b) {
		t.Fatalf("unparsable stat %q", b)
	}
	return b[i+2]
}

// ignores reports whether /proc/<pid>/status's SigIgn mask has sig.
func ignores(t *testing.T, pid int, sig syscall.Signal) bool {
	t.Helper()
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "SigIgn:"); ok {
			mask, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			if err != nil {
				t.Fatal(err)
			}
			return mask&(1<<(uint(sig)-1)) != 0
		}
	}
	t.Fatal("no SigIgn line")
	return false
}

// TestJobControlStopsTheAgentNotATier2Launcher is E40: a terminal's SIGTSTP (Ctrl-Z) reaches the whole
// foreground process group. A launcher whose handle owns a listener the host waits on (tier 2's fanotify
// group) must keep running, or every open and exec on its marked mounts waits until it is continued; the
// agent, in the same group, must still stop. So the launcher ignores the job-control stops, and the child
// stage sets them back to the default before it execs the agent, since an ignored disposition would
// otherwise reach the agent. A launcher without a listener (tier 1) is left as it was: it stops with its
// agent, which is what lets the shell's job control take the terminal back and `fg` the run.
//
// Also pins runtime-launch.md R9a: a tier-2 launcher ignores the job-control stops and the agent still stops (root/kernel; unverified where not run as root).
func TestJobControlStopsTheAgentNotATier2Launcher(t *testing.T) {
	for _, tc := range []struct {
		name          string
		mode          string
		launcherStops bool
	}{
		{"a launcher holding a listener", "jobcontrol", false},
		{"a launcher without one", "jobcontrol-plain", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			helper := exec.Command(os.Args[0])
			helper.Env = append(os.Environ(), "TEGO_LAUNCH_HELPER="+tc.mode)
			helper.Stderr = os.Stderr
			helper.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // its own group, as a shell's job
			out, err := helper.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := helper.Start(); err != nil {
				t.Fatal(err)
			}
			pgid := helper.Process.Pid
			t.Cleanup(func() {
				_ = unix.Kill(-pgid, syscall.SIGKILL)
				_ = helper.Wait()
			})
			line, err := bufio.NewReader(out).ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			agent, err := strconv.Atoi(strings.TrimSpace(line))
			if err != nil {
				t.Fatal(err)
			}
			waitComm(t, agent, "sleep")
			for _, sig := range []syscall.Signal{syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU} {
				if got := ignores(t, pgid, sig); got == tc.launcherStops {
					t.Errorf("launcher ignores %s = %v, want %v", unix.SignalName(sig), got, !tc.launcherStops)
				}
				if ignores(t, agent, sig) {
					t.Errorf("the agent ignores %s: the child stage must reset it before exec", unix.SignalName(sig))
				}
			}

			if err := unix.Kill(-pgid, syscall.SIGTSTP); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for procState(t, agent) != 'T' {
				if time.Now().After(deadline) {
					t.Fatalf("the agent did not stop on SIGTSTP (state %c)", procState(t, agent))
				}
				time.Sleep(5 * time.Millisecond)
			}
			// The signal reached the whole group at once. A launcher that stops is waited for, up to the same
			// bound as the agent. One that must not stop is given 200 ms to stop wrongly and then checked:
			// that sleep proves an absence, which no condition can signal, and is the only one left here.
			if tc.launcherStops {
				deadline = time.Now().Add(5 * time.Second)
				for procState(t, pgid) != 'T' && time.Now().Before(deadline) {
					time.Sleep(5 * time.Millisecond)
				}
			} else {
				time.Sleep(200 * time.Millisecond)
			}
			if stopped := procState(t, pgid) == 'T'; stopped != tc.launcherStops {
				t.Errorf("launcher stopped = %v, want %v", stopped, tc.launcherStops)
			}
			_ = unix.Kill(-pgid, syscall.SIGCONT)
		})
	}
}
