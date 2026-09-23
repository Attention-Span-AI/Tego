// SPDX-License-Identifier: Apache-2.0

package identity

import "syscall"

// Exit codes of tego run (spec/identity/RUN-IDENTITY.md). The agent's own code passes through;
// the codes below are Tego's, following the convention of docker run, GNU timeout and the shell.
// The LSB/systemd band 200–254 is never used by tego run (I7).
const (
	// ExitOK is success.
	ExitOK = 0
	// ExitLimit is a run ended by a limit (tokens, cost, wall, stall, repeats).
	ExitLimit = 124
	// ExitLauncher is a failure before exec: invalid contract, tier or capture unavailable, untrusted
	// machine config, cgroup, ledger or program-load error; one sentence on stderr with the code.
	ExitLauncher = 125
	// ExitNoExec is a command found but not executable (EACCES, ENOEXEC, or exec not granted).
	ExitNoExec = 126
	// ExitNotFound is a command that was not found.
	ExitNotFound = 127
	// ExitStoppedKill is 128+SIGKILL: cgroup.kill at stop_grace, or a memory or pids cap.
	ExitStoppedKill = 137
	// ExitStoppedTerm is 128+SIGTERM: tego stop or a forwarded SIGTERM ended the run in time.
	ExitStoppedTerm = 143
	// ExitConfig is the exit code for an untrusted or invalid machine config. It equals ExitLauncher:
	// the normative resolution of 2026-09-22 folded the former 213 into 125 [config-untrusted].
	ExitConfig = ExitLauncher
)

// Exit codes of the other subcommands.
const (
	// ExitFinding is a finding: drift found, status stalled or lost, doctor finds no tier this machine can run, compile error.
	ExitFinding = 1
	// ExitUsage is a usage error.
	ExitUsage = 2
	// ExitError is Tego's own error in any subcommand.
	ExitError = 125
	// ExitRequire is doctor --require's code when the machine is below the required tier; never tego run's.
	ExitRequire = 211
)

// Diagnostic codes used in the bracketed suffix of exit-125 messages.
const (
	// CodeConfigUntrusted is a machine config layer that failed the trust check or did not parse.
	CodeConfigUntrusted = "config-untrusted"
	// CodeTierUnavailable is a pinned or auto-selected tier the machine cannot provide.
	CodeTierUnavailable = "tier-unavailable"
	// CodeCaptureUnavailable is a run with a tokens, cost_usd or repeats budget whose capture mechanism could
	// not start, refused rather than run unmetered.
	CodeCaptureUnavailable = "capture-unavailable"
	// CodeBudgetUnmetered is a run with a tokens, cost_usd or repeats budget its contract declares and nothing to
	// count it with (no capture runs for it, or no price table that prices a model for cost_usd), refused rather
	// than run with a limit that never trips; compile reports the same contracts under this code.
	CodeBudgetUnmetered = "budget-unmetered"
	// CodeContradiction is a contract whose write entries cover the run directory or the contract file.
	CodeContradiction = "contradiction"
	// CodePrivilegedPathUnsupported is a launcher that gained privilege without being root of the initial user
	// namespace: a file-capability or setuid copy, or a privileged inherited capability set. Every subcommand but
	// version refuses it the same way, exit 125 (ADR 0042 (3)(a)).
	CodePrivilegedPathUnsupported = "privileged-path-unsupported"
)

// signalBase is added to a signal number to synthesise the shell's exit code for signal death.
const signalBase = 128

// EndReason mirrors record's run_end.reason verbatim (I9).
type EndReason string

// The closed set of run end reasons.
const (
	ReasonExit       EndReason = "exit"
	ReasonSignal     EndReason = "signal"
	ReasonLimit      EndReason = "limit"
	ReasonStopped    EndReason = "stopped"
	ReasonOOM        EndReason = "oom"
	ReasonPids       EndReason = "pids"
	ReasonExecFailed EndReason = "exec-failed"
	ReasonOrphaned   EndReason = "orphaned"
	ReasonError      EndReason = "error"
)

// ExecFailure disambiguates ReasonExecFailed.
type ExecFailure int

// ExecFailure values.
const (
	// ExecFailureNone is "not an exec failure"; with ReasonExecFailed it maps to ExitNoExec.
	ExecFailureNone ExecFailure = iota
	// ExecFailureDenied is EACCES/ENOEXEC or an exec the tier did not grant (126).
	ExecFailureDenied
	// ExecFailureNotFound is ENOENT on the command (127).
	ExecFailureNotFound
)

// ExitCode turns "why the run ended" into the exit status of tego run.
//
// Pre: ws comes from a real wait on the agent's main process for ReasonExit and ReasonSignal
// (the caller checks Exited()/Signaled() first, E23), and is the zero value for reasons that never
// wait one. Post: total; an unrecognised reason yields ExitLauncher.
//
// Exit and signal both follow ws — Exited() → ExitStatus(), Signaled() → 128+signal; the
// forwarded signal never becomes a formula. R11: limit → 124 regardless of ws. R12: stopped → 143,
// or 137 when escalated; oom and pids → 137. R13: exec-failed → 126 (denied) or 127 (not found).
func ExitCode(reason EndReason, ws syscall.WaitStatus, escalated bool, xf ExecFailure) int {
	switch reason {
	case ReasonExit, ReasonSignal:
		return waitStatusCode(ws) // R10
	case ReasonLimit:
		return ExitLimit // R11
	case ReasonStopped: // R12
		if escalated {
			return ExitStoppedKill
		}
		return ExitStoppedTerm
	case ReasonOOM, ReasonPids:
		return ExitStoppedKill // R12
	case ReasonExecFailed: // R13
		if xf == ExecFailureNotFound {
			return ExitNotFound
		}
		return ExitNoExec
	case ReasonOrphaned, ReasonError:
		return ExitLauncher
	}
	return ExitLauncher
}

// waitStatusCode maps a wait status to the shell convention; a status that neither exited nor
// was signaled (E23, a caller contract violation) yields ExitLauncher.
func waitStatusCode(ws syscall.WaitStatus) int {
	switch {
	case ws.Exited():
		return ws.ExitStatus()
	case ws.Signaled():
		return signalBase + int(ws.Signal())
	}
	return ExitLauncher
}

// SignalExitCode is the exit code the shell convention assigns to death by sig (128+n).
func SignalExitCode(sig syscall.Signal) int { return signalBase + int(sig) }

// ForwardAlways lists the signals tego run forwards to the agent unconditionally.
func ForwardAlways() []syscall.Signal {
	return []syscall.Signal{syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2}
}

// ForwardWhenNotTTY lists the signals forwarded only when stdin is not a terminal (a terminal
// delivers them to the shared process group itself).
func ForwardWhenNotTTY() []syscall.Signal {
	return []syscall.Signal{syscall.SIGINT, syscall.SIGQUIT}
}

// StopGraceTriggers lists the signals that start the stop_grace countdown.
func StopGraceTriggers() []syscall.Signal {
	return []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP}
}

// Forwardable reports whether sig is forwarded by rule when stdin is (not) a terminal. It says
// which signals are forwardable; whether to forward a specific delivery is the launcher's decision.
func Forwardable(sig syscall.Signal, stdinIsTTY bool) bool {
	if containsSignal(ForwardAlways(), sig) {
		return true
	}
	return !stdinIsTTY && containsSignal(ForwardWhenNotTTY(), sig)
}

// StartsStopGrace reports whether sig starts the stop_grace countdown.
func StartsStopGrace(sig syscall.Signal) bool { return containsSignal(StopGraceTriggers(), sig) }

func containsSignal(list []syscall.Signal, sig syscall.Signal) bool {
	for _, s := range list {
		if s == sig {
			return true
		}
	}
	return false
}
