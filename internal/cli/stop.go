// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/check/status"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runlock"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// stopPoll is how often stop re-probes the run's lock while waiting for the launcher to finish.
const stopPoll = 100 * time.Millisecond

func init() { register(cmdStop) }

// cmdStop is `tego stop <run> [--grace <d>]` (R29): it drops the stop marker so the launcher ends
// the run with reason=stopped rather than reason=signal, sends SIGTERM through a pidfd it has
// verified against the lock file (R22), and escalates to cgroup.kill if the run is still alive when
// the grace expires. --grace is written into the marker, so it is the launcher's own stop_grace for
// this stop — longer or shorter than the machine's — and not only how long this command waits
// before its backstop kill; without it the machine's stop_grace applies to both. Exit 0 whatever the
// run does, including "not running" (§6 case 11); 2 for a --grace that is not a positive duration.
//
// `tego stop --agent <name>` stops every live run whose agent is name, the contract's `name:`, which stays
// the same across the runs a restarting unit starts while the run id changes with each: it prints one line per run
// as a stop by id does, or "<name>: no live run", and exits 0 either way; 2 for a name that is not an agent id.
func cmdStop() Command {
	var graceText, agentName string
	return Command{
		Name:    "stop",
		Summary: "stop a running run",
		Usage:   "<run> | --agent <name> [--grace <d>]",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&graceText, "grace", "", "how long to wait before cgroup.kill, e.g. 30s or 1d "+
				"(default: the machine's stop_grace)")
			fs.StringVar(&agentName, "agent", "", "stop every live run of this agent (the contract's name:) instead of one run")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			byAgent := agentName != ""
			if byAgent && fs.NArg() != 0 || !byAgent && fs.NArg() != 1 {
				message(stderr, "", 0, 0, "tego stop: exactly one run id, or --agent <name> alone", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			// The machine config's grammar, as gc's --keep (explicitDuration): "1d" is a grace like any
			// other (R29).
			grace, given, err := explicitDuration(fs, "grace", graceText)
			if err != nil {
				message(stderr, "", 0, 0, "tego stop: --grace: "+err.Error()+"; it must be a positive duration", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			if given && grace <= 0 {
				// A zero or negative grace written into the marker would read as no request at all,
				// so the run would get the machine's stop_grace while this command waited for none.
				message(stderr, "", 0, 0, "tego stop: --grace must be a positive duration; "+
					"omit it for the machine's stop_grace", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			if byAgent {
				return runStopAgent(ctx, agentName, grace, stdout, stderr)
			}
			return runStop(ctx, fs.Arg(0), grace, stdout, stderr)
		},
	}
}

// runStopAgent is `tego stop --agent <name>`: every run the ledger root's live index lists whose agent is name is
// stopped as `tego stop <run>` would stop it, one after the other; the first stop that fails ends the command with
// its exit code. A listed run that has already ended prints "not running", as a stop by id does.
func runStopAgent(ctx context.Context, name string, requested time.Duration, stdout, stderr io.Writer) int {
	if _, err := identity.ParseAgentID(name); err != nil {
		message(stderr, "", 0, 0, fmt.Sprintf("tego stop: --agent %q: %v", name, err), codeUsage)
		return identity.ExitUsage
	}
	m, cds, err := loadMachine(config.TrustWarn)
	writeConfigDiagnostics(stderr, cds)
	if err != nil {
		message(stderr, "", 0, 0, "tego stop: machine config: "+err.Error(), identity.CodeConfigUntrusted)
		return identity.ExitError
	}
	root, err := ledgerRootOf(m)
	if err != nil {
		message(stderr, "", 0, 0, "tego stop: "+err.Error(), codeIO)
		return identity.ExitError
	}
	ids, err := ledger.LiveEntries(root)
	if err != nil {
		message(stderr, "", 0, 0, "tego stop: "+err.Error(), codeIO)
		return identity.ExitError
	}
	found := 0
	for _, id := range ids {
		agentID, err := runAgent(filepath.Join(root, id))
		if err != nil || string(agentID) != name {
			continue // a run with no agent line yet, or another agent's
		}
		found++
		if code := runStop(ctx, id, requested, stdout, stderr); code != identity.ExitOK {
			return code
		}
	}
	if found == 0 {
		fmt.Fprintf(stdout, "%s: no live run\n", name)
	}
	return identity.ExitOK
}

// runStop is the in-process body of stop. requested is --grace, 0 when it was not given.
func runStop(ctx context.Context, runID string, requested time.Duration, stdout, stderr io.Writer) (code int) {
	m, cds, err := loadMachine(config.TrustWarn)
	writeConfigDiagnostics(stderr, cds)
	if err != nil {
		message(stderr, "", 0, 0, "tego stop: machine config: "+err.Error(), identity.CodeConfigUntrusted)
		return identity.ExitError
	}
	// Once the run is stopped or not running, a root stop starts the timer of every tier-2 build whose timer died
	// (ADR 0022 (4), (8)): such a build stays attached host-wide until a reaper, stop or gc acts for it, and stop
	// re-arms rather than sweeps, so its own latency stays an exec, not a removal's 1.7 to 3.7 s of ftrace locks,
	// and the timer applies the lingering cap. Best effort: a failure is reported and stop's exit is unchanged. A
	// stop the caller interrupted does not wait for it.
	defer func() {
		if code != identity.ExitOK || ctx.Err() != nil || !stopPrivileged() {
			return
		}
		if err := stopRearmBuilds(m); err != nil {
			message(stderr, "", 0, 0, "tego stop: builds: "+err.Error(), codeIO)
		}
	}()
	root, err := ledgerRootOf(m)
	if err != nil {
		message(stderr, "", 0, 0, "tego stop: "+err.Error(), codeIO)
		return identity.ExitError
	}
	if !ledger.IsRunID(runID) {
		message(stderr, "", 0, 0, fmt.Sprintf("tego stop: %q %v", runID, errBadRunID), codeUsage)
		return identity.ExitUsage // R25: usage error
	}
	dir := filepath.Join(root, runID)
	if _, err := os.Stat(dir); err != nil {
		// Only a directory that is not there is the caller's typo (R25). A run the caller cannot stat
		// may still be running, so it is reported as the errno, 125 [io], never as "no such run" (E26).
		if errors.Is(err, fs.ErrNotExist) {
			message(stderr, "", 0, 0, fmt.Sprintf("tego stop: %s: %v under %s; %s", runID, errRunNotFound, root, listRunsHint), codeUsage)
			return identity.ExitUsage
		}
		message(stderr, "", 0, 0, "tego stop: "+err.Error(), readCode(err))
		return identity.ExitError
	}
	// An adoption (ADR 0055) is released, never stopped: its lock is its adopter's, which can be a
	// guard holding other adoptions that a SIGTERM would end too, and its agent is the operator's own process, which
	// no stop kills (--grace has nothing to bound). Its record is root's, so a stop by another user goes on below
	// and is refused by the adopter's own permissions.
	if stopAdopted(runID) {
		return releaseAdoption(ctx, "tego stop", runID, stdout, stderr)
	}
	// The standing orphan pass, not a fallback for this run — it runs before the lock probe so
	// a launcher that died is ended here rather than reported as "still running". Like run's, it
	// sweeps the runs the live index names (sweepLive), not every run under the root.
	if res, err := sweepLive(ctx, root, sweepOptions(m)...); err != nil {
		logOwn("stop: sweep: " + err.Error())
	} else {
		for _, e := range res.Errs {
			logOwn("stop: sweep: " + e.Error())
		}
	}
	held, info, err := runlock.ProbeLock(dir)
	if err != nil {
		message(stderr, "", 0, 0, "tego stop: "+err.Error(), codeIO)
		return identity.ExitError
	}
	if !held {
		// Case 11: the launcher is already gone. No signal is sent and nothing else is touched.
		fmt.Fprintf(stdout, "%s: not running\n", runID)
		return identity.ExitOK
	}
	if info.PID <= 0 {
		// Held, but the holder has not written its pid/start line yet (ledger.Open flocks before
		// writeLockInfo runs). Signalling pid 0 would fail EINVAL, so wait for the line or the lock.
		held, info, err = awaitLockInfo(ctx, dir)
		if err != nil && ctx.Err() != nil {
			// Cancelled while the run was still starting: not an I/O failure (R29).
			message(stderr, "", 0, 0, "tego stop: interrupted", codeIO)
			return identity.ExitError
		}
		if err != nil {
			message(stderr, "", 0, 0, "tego stop: "+err.Error(), codeIO)
			return identity.ExitError
		}
		if !held {
			fmt.Fprintf(stdout, "%s: not running\n", runID)
			return identity.ExitOK
		}
		if info.PID <= 0 {
			message(stderr, "", 0, 0, "tego stop: the run's lock is held but names no launcher process", codeIO)
			return identity.ExitError
		}
	}
	machine := m.StopGrace.Value
	if machine <= 0 {
		machine = config.DefaultStopGrace // what the launcher falls back to for the same missing value
	}
	grace := requested
	if grace <= 0 {
		grace = machine
	}
	return stopRun(ctx, dir, runID, info, requested, grace, machine, stdout, stderr)
}

// stopAdopted reports whether run is an adoption this process can release: root of the initial user namespace and
// an adoption record for it. A variable so a test can stand an adoption up without root.
var stopAdopted = func(run string) bool {
	return adoptPrivileged() && tegoruntime.AdoptionRecorded(adoptStateDir, run)
}

// stopPrivileged reports whether stop may start build timers: root of the initial user namespace, as for gc's bpf
// sweep (ADR 0042 (5)(d)); a variable so a test can take the root path.
var stopPrivileged = config.InitNSRoot

// stopRearmBuilds is a root stop's pass over the tier-2 builds (cgroup.RearmTimers): this tego, as LingerCommand,
// for each build no launcher holds whose timer is not running. A variable so a test sees when it runs.
var stopRearmBuilds = func(m *config.Machine) error {
	_, err := cgroupenforce.RearmTimers(cgroupenforce.SweepOptions{Linger: m.BPF.Linger.Value}, "/proc/self/exe")
	return err
}

// signalTarget delivers the stop signal; a variable so a test can make the launcher vanish between the
// verified pidfd and the delivery.
var signalTarget = func(t *runlock.StopTarget, sig syscall.Signal) error { return t.Signal(sig) }

// lockInfoWait bounds how long stop waits for a holder that has taken the lock but not yet written who it is.
var lockInfoWait = 2 * time.Second

// awaitLockInfo re-probes a held lock whose info line is still empty, until the line appears, the lock
// frees, or lockInfoWait passes.
func awaitLockInfo(ctx context.Context, dir string) (bool, runlock.LockInfo, error) {
	deadline := time.Now().Add(lockInfoWait)
	for {
		held, info, err := runlock.ProbeLock(dir)
		if err != nil || !held || info.PID > 0 || time.Now().After(deadline) {
			return held, info, err
		}
		select {
		case <-ctx.Done():
			return held, info, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// postKillWait bounds how long stop waits for the lock to free after its backstop cgroup.kill.
var postKillWait = 5 * time.Second

// stopRun performs the stop itself: marker, SIGTERM through the verified pidfd, wait, escalate.
// requested is what the marker asks the launcher for (0: its own stop_grace); grace is how long this
// command waits before its own backstop; machine is the machine's stop_grace, the launcher's timer when
// a marker names no grace.
func stopRun(ctx context.Context, dir, runID string, info runlock.LockInfo,
	requested, grace, machine time.Duration, stdout, stderr io.Writer) int {
	// The launcher is verified first: a marker placed for a stop that then fails (not the lock holder, an
	// I/O error) would stay in a live run and turn its next Ctrl-C into reason=stopped (R22).
	target, err := runlock.OpenStopTargetFor(dir, info)
	if err != nil {
		if errors.Is(err, runlock.ErrStale) {
			// The pid was reused since the lock file was written: the launcher is gone and
			// signalling that pid would hit an unrelated process (R22, case 15).
			fmt.Fprintf(stdout, "%s: not running\n", runID)
			return identity.ExitOK
		}
		message(stderr, "", 0, 0, "tego stop: "+err.Error(), codeIO)
		return identity.ExitError
	}
	defer func() { _ = target.Close() }()
	// A marker that already exists keeps the grace the first stop asked for: the launcher reads it
	// when the first SIGTERM arrives, and arms its timer once. This stop's own backstop honours it
	// too, or a plain `stop` after `stop --grace 1h` would write cgroup.kill itself once the machine's
	// stop_grace was up, cutting short the grace the launcher is still keeping; and a `stop --grace 1s`
	// after a plain `stop` would cut short the machine's stop_grace the first stop left in force.
	err = tegoruntime.RequestStopGraceThen(ctx, dir, requested, func(existing bool) error {
		if existing {
			grace = backstopAfter(dir, grace, machine)
		}
		// The complete marker must precede SIGTERM. Publication and delivery share
		// the marker lock, so another successful stop cannot use a marker that a
		// failed publisher is about to roll back. ESRCH retains the ended-run path.
		err := signalTarget(target, syscall.SIGTERM)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	})
	if err != nil {
		message(stderr, "", 0, 0, "tego stop: "+err.Error(), codeIO)
		return identity.ExitError
	}
	if waitForEnd(ctx, dir, grace) {
		fmt.Fprintf(stdout, "%s: stopped\n", runID)
		return identity.ExitOK
	}
	if ctx.Err() != nil {
		// A signal to this command (R29: it cancels the context) gives up the wait; it does not end the
		// grace. Writing cgroup.kill here killed the run at once, however long a grace it had been given;
		// the launcher's own stop_grace timer, armed by the SIGTERM above, still ends it.
		fmt.Fprintf(stdout, "%s: stop requested; stopped waiting (the launcher's stop_grace still applies)\n", runID)
		return identity.ExitOK
	}
	// The launcher's own stop_grace timer should have written cgroup.kill by now (R9); this is the
	// backstop for a launcher that is itself wedged, and one extra write to cgroup.kill is harmless.
	escalateRun(dir, runID, stderr)
	// cgroup.kill is one asynchronous write, so the wait after it is short, not a second full grace.
	after := min(grace, postKillWait)
	if waitForEnd(ctx, dir, after) {
		fmt.Fprintf(stdout, "%s: stopped\n", runID)
	} else {
		fmt.Fprintf(stdout, "%s: still running after %s (and %s after cgroup.kill)\n", runID, grace, after)
	}
	return identity.ExitOK
}

// backstopAfter is how long a stop that found an earlier stop's marker waits before its own
// cgroup.kill: its own grace, or the grace that marker asked the launcher for when that is longer
// (limits-check-doctor-cli.md R29, runtime-launch.md R9). A marker that names no grace — a plain first
// `stop` — left the launcher on machine, its stop_grace (StopRequestGrace's 0 is the launcher's "use
// stop_grace" too), so that is the first stop's grace. The launcher's timer runs from the first stop's
// SIGTERM, so waiting that long from this later one never ends the run before the launcher would have;
// a shorter own grace is the only one that could.
func backstopAfter(dir string, own, machine time.Duration) time.Duration {
	first := tegoruntime.StopRequestGrace(dir)
	if first <= 0 {
		first = machine
	}
	if first > own {
		return first
	}
	return own
}

// escalateRun is the backstop kill; a variable so the tests can see when it would have been written
// without a cgroup to write it to.
var escalateRun = escalate

// waitForEnd polls the run's lock until it is free or d elapses. The lock, not a pid and not a
// state file, is what "still running" means (invariant 1). A probe that fails says nothing either
// way, so it is logged and the poll continues: reporting "stopped" on an unreadable lock would be a
// guess, and escalating on one would kill a run this command cannot even see.
func waitForEnd(ctx context.Context, dir string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		held, err := status.LockHeld(dir)
		switch {
		case err != nil:
			logOwn("stop: probe lock: " + err.Error())
		case !held:
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(stopPoll):
		}
	}
}

// escalate writes cgroup.kill for the run, which SIGKILLs its whole subtree (R9's escalate). The
// write is one syscall with no wait of its own: delivery is asynchronous and the caller confirms it
// by watching the run's lock (R10).
//
// The scope is found as a sweep finds an orphan's (tegoruntime.RunScope): under every root it can be
// under, and only the one whose cgroup id run_start recorded. The path was built under the stopper's
// own cgroup root with no id check, so a user stopping a root launcher's run killed nothing, and a scope
// of the same name made since would have been killed in its place (R29).
func escalate(dir, runID string, stderr io.Writer) {
	agentID, err := runAgent(dir)
	if err != nil {
		message(stderr, "", 0, 0, "tego stop: "+err.Error(), codeIO)
		return
	}
	uid, _ := config.InvokingUID()
	mgr, err := stopCgroups(uid)
	if err != nil {
		message(stderr, "", 0, 0, "tego stop: "+err.Error(), codeIO)
		return
	}
	var marks []tegoruntime.SweepOption
	if stopRootMarks != "" {
		marks = append(marks, tegoruntime.WithSweepRootMarks(stopRootMarks))
	}
	c, ok, err := tegoruntime.RunScope(mgr, filepath.Dir(dir), runID, string(agentID), marks...)
	switch {
	case err != nil:
		message(stderr, "", 0, 0, "tego stop: "+err.Error(), codeIO)
		return
	case !ok:
		logOwn("stop: escalate: no scope of run " + runID + " is left to kill")
		return
	}
	if err := mgr.Kill(c); err != nil {
		logOwn("stop: escalate: " + err.Error())
	}
}

// stopCgroups is the cgroup manager of the stop's backstop kill; a variable so a test can root it in a
// temporary tree.
var stopCgroups = func(uid int) (cgroup.Manager, error) { return cgroup.Detect(uid) }

// stopRootMarks is the directory of root launch records the backstop kill consults; "" is the host's
// (/run/tego/launched). A variable so a root test can stand a run up as a root launcher leaves it without
// writing into the real /run/tego; nothing in a product build sets it.
var stopRootMarks string

// runAgent reads the agent id from a run's own ledger, so stop needs no second source of truth for
// the cgroup path.
func runAgent(dir string) (identity.AgentID, error) {
	r, err := ledger.OpenReader(dir)
	if err != nil {
		return "", fmt.Errorf("open run: %w", err)
	}
	defer func() { _ = r.Close() }()
	for e, err := range r.Iter() {
		if err != nil {
			return "", fmt.Errorf("read run: %w", err)
		}
		if e.Agent != "" {
			return identity.ParseAgentID(e.Agent)
		}
	}
	return "", fmt.Errorf("run has no agent id yet")
}
