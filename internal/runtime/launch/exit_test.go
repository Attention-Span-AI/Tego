// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func exited(code int) syscall.WaitStatus { return syscall.WaitStatus(code << 8) }
func killed(sig syscall.Signal) syscall.WaitStatus {
	return syscall.WaitStatus(sig)
}

// Also pins runtime-launch.md I9: one terminal reason per wait result.
func TestEnded(t *testing.T) {
	tests := []struct {
		name   string
		r      WaitResult
		o      Outcome
		reason identity.EndReason
		code   int
	}{
		{"exit 0", WaitResult{Status: exited(0)}, Outcome{}, identity.ReasonExit, 0},
		{"exit 3", WaitResult{Status: exited(3)}, Outcome{}, identity.ReasonExit, 3},
		{"died by SIGSEGV, no launcher signal", WaitResult{Status: killed(syscall.SIGSEGV)}, Outcome{}, identity.ReasonExit, 139},
		{"exec not found", WaitResult{Status: exited(127), ExecErr: syscall.ENOENT}, Outcome{}, identity.ReasonExecFailed, 127},
		{"exec denied", WaitResult{Status: exited(126), ExecErr: syscall.EACCES}, Outcome{}, identity.ReasonExecFailed, 126},
		{"exec ENOEXEC", WaitResult{Status: exited(126), ExecErr: syscall.ENOEXEC}, Outcome{}, identity.ReasonExecFailed, 126},
		{"SIGTERM forwarded, agent exited by it", WaitResult{Status: killed(syscall.SIGTERM)}, Outcome{Signal: syscall.SIGTERM}, identity.ReasonSignal, 143},
		{"SIGINT, agent exited 0 in time", WaitResult{Status: exited(0)}, Outcome{Signal: syscall.SIGINT}, identity.ReasonSignal, 0},
		{"SIGTERM escalated to cgroup.kill", WaitResult{Status: killed(syscall.SIGKILL)}, Outcome{Signal: syscall.SIGTERM, Escalated: true}, identity.ReasonSignal, 137},
		{"tego stop in time", WaitResult{Status: killed(syscall.SIGTERM)}, Outcome{Signal: syscall.SIGTERM, Stopped: true}, identity.ReasonStopped, 143},
		{"tego stop escalated", WaitResult{Status: killed(syscall.SIGKILL)}, Outcome{Signal: syscall.SIGTERM, Stopped: true, Escalated: true}, identity.ReasonStopped, 137},
		{"exec failure wins over signal", WaitResult{Status: exited(127), ExecErr: syscall.ENOENT}, Outcome{Signal: syscall.SIGTERM}, identity.ReasonExecFailed, 127},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reason, code := Ended(tc.r, tc.o)
			if reason != tc.reason || code != tc.code {
				t.Fatalf("Ended = %s/%d, want %s/%d", reason, code, tc.reason, tc.code)
			}
		})
	}
}
