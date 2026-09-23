// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"syscall"
	"testing"
)

// exited builds a wait status for a normal exit with code n.
func exited(n int) syscall.WaitStatus { return syscall.WaitStatus(n << 8) }

// killed builds a wait status for death by signal.
func killed(sig syscall.Signal) syscall.WaitStatus { return syscall.WaitStatus(sig) }

// T-exit-1/2/3: the exit-code table (R10–R13, I7).
// identity-config.md R10, R11, R12, R13 (the table), I7 (no code in 200-254 from these reasons), E23 (a status neither exited nor signaled).
func TestExitCode(t *testing.T) {
	cases := []struct {
		name      string
		reason    EndReason
		ws        syscall.WaitStatus
		escalated bool
		xf        ExecFailure
		want      int
	}{
		{"exit 0", ReasonExit, exited(0), false, ExecFailureNone, 0},
		{"exit 3 passthrough", ReasonExit, exited(3), false, ExecFailureNone, 3},
		{"exit 255 passthrough", ReasonExit, exited(255), false, ExecFailureNone, 255},
		{"exit by SIGSEGV -> 139", ReasonExit, killed(syscall.SIGSEGV), false, ExecFailureNone, 139},
		{"signal reason follows ws exit", ReasonSignal, exited(2), false, ExecFailureNone, 2},
		{"signal reason follows ws signal", ReasonSignal, killed(syscall.SIGTERM), false, ExecFailureNone, 143},
		{"signal escalated still follows ws", ReasonSignal, killed(syscall.SIGKILL), true, ExecFailureNone, 137},
		{"limit ignores ws", ReasonLimit, killed(syscall.SIGKILL), false, ExecFailureNone, 124},
		{"limit ignores exit", ReasonLimit, exited(0), false, ExecFailureNone, 124},
		{"stopped", ReasonStopped, killed(syscall.SIGTERM), false, ExecFailureNone, 143},
		{"stopped escalated", ReasonStopped, killed(syscall.SIGKILL), true, ExecFailureNone, 137},
		{"oom", ReasonOOM, killed(syscall.SIGKILL), false, ExecFailureNone, 137},
		{"pids", ReasonPids, 0, false, ExecFailureNone, 137},
		{"exec denied", ReasonExecFailed, 0, false, ExecFailureDenied, 126},
		{"exec not found", ReasonExecFailed, 0, false, ExecFailureNotFound, 127},
		{"exec failed unspecified", ReasonExecFailed, 0, false, ExecFailureNone, 126},
		{"xf ignored for other reasons", ReasonExit, exited(0), false, ExecFailureNotFound, 0},
		{"orphaned", ReasonOrphaned, 0, false, ExecFailureNone, 125},
		{"error", ReasonError, 0, false, ExecFailureNone, 125},
		{"unknown reason", EndReason("weird"), exited(0), false, ExecFailureNone, 125},
		{"E23 neither exited nor signaled", ReasonExit, syscall.WaitStatus(0x7f), false, ExecFailureNone, 125},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExitCode(tc.reason, tc.ws, tc.escalated, tc.xf)
			if got != tc.want {
				t.Errorf("ExitCode = %d, want %d", got, tc.want)
			}
			if tc.reason != ReasonExit && tc.reason != ReasonSignal && got >= 200 && got <= 254 {
				t.Errorf("I7: tego's own code %d in the systemd band", got)
			}
		})
	}
}

func TestSignalTables(t *testing.T) {
	cases := []struct {
		sig        syscall.Signal
		tty, notty bool
		grace      bool
	}{
		{syscall.SIGTERM, true, true, true},
		{syscall.SIGHUP, true, true, true},
		{syscall.SIGUSR1, true, true, false},
		{syscall.SIGUSR2, true, true, false},
		{syscall.SIGINT, false, true, true},
		{syscall.SIGQUIT, false, true, false},
		{syscall.SIGTSTP, false, false, false},
		{syscall.SIGWINCH, false, false, false},
		{syscall.SIGKILL, false, false, false},
	}
	for _, tc := range cases {
		if got := Forwardable(tc.sig, true); got != tc.tty {
			t.Errorf("Forwardable(%v, tty) = %v, want %v", tc.sig, got, tc.tty)
		}
		if got := Forwardable(tc.sig, false); got != tc.notty {
			t.Errorf("Forwardable(%v, no tty) = %v, want %v", tc.sig, got, tc.notty)
		}
		if got := StartsStopGrace(tc.sig); got != tc.grace {
			t.Errorf("StartsStopGrace(%v) = %v, want %v", tc.sig, got, tc.grace)
		}
	}
	list := ForwardAlways()
	list[0] = syscall.SIGKILL
	if ForwardAlways()[0] == syscall.SIGKILL {
		t.Error("ForwardAlways returned shared state")
	}
	if SignalExitCode(syscall.SIGTERM) != ExitStoppedTerm || SignalExitCode(syscall.SIGKILL) != ExitStoppedKill {
		t.Error("SignalExitCode inconsistent with the stop codes")
	}
}

// TestExitCodesLeaveTheLSBBand asserts agent-contract.md E36: the R10 contradiction and the machine-config
// code are exit 125 (no 210, no 213), and the one code left in the 200-254 band is doctor --require's 211.
func TestExitCodesLeaveTheLSBBand(t *testing.T) {
	if ExitConfig != ExitLauncher || ExitLauncher != 125 {
		t.Errorf("ExitConfig=%d ExitLauncher=%d, want both 125 (config-untrusted folded into 125)", ExitConfig, ExitLauncher)
	}
	if ExitRequire != 211 {
		t.Errorf("ExitRequire=%d, want 211", ExitRequire)
	}
	for name, code := range map[string]int{"ExitOK": ExitOK, "ExitLimit": ExitLimit, "ExitLauncher": ExitLauncher,
		"ExitNoExec": ExitNoExec, "ExitNotFound": ExitNotFound, "ExitStoppedKill": ExitStoppedKill,
		"ExitStoppedTerm": ExitStoppedTerm, "ExitConfig": ExitConfig, "ExitError": ExitError} {
		if code >= 200 && code <= 254 {
			t.Errorf("%s=%d is in the LSB band 200-254; only ExitRequire (211) may be", name, code)
		}
	}
	if CodeContradiction != "contradiction" {
		t.Errorf("CodeContradiction=%q, want the R10 diagnostic code", CodeContradiction)
	}
}
