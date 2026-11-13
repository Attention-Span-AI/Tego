// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/attention-span-ai/tego/internal/check/status"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/runlock"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// pauseFact is a live run's pause as tego status shows it, read from what the dashboard reads: the launcher's
// last pause line in the ledger (internal/control/ledgerview LiveFacts.Paused) and the request its overlay holds
// (internal/control/runact PauseRequest).
type pauseFact struct {
	// Paused is the launcher's last pause line: run-paused, or resume-failed (still frozen), with no run-resumed
	// after it. A pause the launcher has not confirmed is not Paused.
	Paused bool
	// Pending is "pause" or "resume" while the overlay asks one with a serial above the last line's, which the
	// launcher answers within about half a second; "" otherwise.
	Pending string
	// LauncherGone is a run whose launcher is gone (runlock.LauncherGone: its lock is free, or the process its lock
	// line names has exited or is another process) with no run_end, and whose last recorded pause line held it paused
	// (ADR 0124, second amendment of 2026-11-11). That is the last state recorded, not proof the run stayed frozen: a
	// stop thaws without a line, and lines queued when the launcher died are lost. Scope says what its scope shows now.
	// Tego never thaws it; tego stop ends what is left of it and closes its record.
	LauncherGone bool
	Scope        scopeFact
	// LauncherUnknown is why a held lock's launcher could not be confirmed alive or gone (runlock.LauncherCheck's
	// cause): such a run reads as its derived state with "(launcher unknown)", and a line under the table says which
	// check failed and what to do. "" when the launcher was judged.
	LauncherUnknown string
}

// scopeFact is what a run's own scope says now (cgroup.events): Known says it could be read (a scope that is no
// longer there is known and empty), Populated that a process is in it, Frozen that the freezer holds every one.
type scopeFact struct{ Known, Populated, Frozen bool }

// now is the fact in words for tego status and tego stop.
func (f scopeFact) now() string {
	switch {
	case !f.Known:
		return "whether its processes are still frozen could not be read from its scope"
	case !f.Populated:
		return "no process is left in its scope"
	case f.Frozen:
		return "its processes are frozen (its scope's cgroup.events says frozen 1)"
	}
	return "its processes are NOT frozen: they run with no launcher deciding or recording what they do (a stop's thaw before the launcher died, or a write to the scope's cgroup.freeze, does that)"
}

// json is the fact for --json's scope_now: frozen, running, empty or unknown.
func (f scopeFact) json() string {
	switch {
	case !f.Known:
		return "unknown"
	case !f.Populated:
		return "empty"
	case f.Frozen:
		return "frozen"
	}
	return "running"
}

// readScope reads run's scope as the stop's backstop finds it (tegoruntime.RunScope: by the cgroup id run_start
// recorded, and a root-launched run's only on root's record). A variable so a test can stand in for the freezer.
var readScope = func(dir, run string) scopeFact {
	agentID, err := runAgent(dir)
	if err != nil {
		return scopeFact{}
	}
	uid, _ := config.InvokingUID()
	mgr, err := stopCgroups(uid)
	if err != nil {
		return scopeFact{}
	}
	var marks []tegoruntime.SweepOption
	if stopRootMarks != "" {
		marks = append(marks, tegoruntime.WithSweepRootMarks(stopRootMarks))
	}
	c, ok, err := tegoruntime.RunScope(mgr, filepath.Dir(dir), run, string(agentID), marks...)
	if err != nil {
		return scopeFact{}
	}
	if !ok {
		return scopeFact{Known: true}
	}
	populated, err := cgroup.Populated(c)
	if err != nil {
		return scopeFact{}
	}
	if !populated {
		return scopeFact{Known: true}
	}
	frozen, err := cgroup.Frozen(c)
	if err != nil {
		return scopeFact{}
	}
	return scopeFact{Known: true, Populated: true, Frozen: frozen}
}

// state is the STATE column for a run in st: "paused" for one held frozen, "pausing" or "resuming" while the
// launcher has yet to answer a request, the derived state otherwise. A paused run records nothing, so its derived
// state turns stalled once stall_after has passed; it still reads paused, which is why it is idle.
func (p pauseFact) state(st status.State) string {
	if p.LauncherGone {
		if p.Scope.Populated && p.Scope.Frozen {
			return stateLostFrozen
		}
		return string(status.Lost)
	}
	if !live(st) {
		return string(st)
	}
	if p.LauncherUnknown != "" {
		return p.liveState(st) + " (launcher unknown)"
	}
	return p.liveState(st)
}

// liveState is state for a run whose launcher holds it.
func (p pauseFact) liveState(st status.State) string {
	switch {
	case p.Pending == pendPause:
		return "pausing"
	case p.Pending == pendResume:
		return "resuming"
	case p.Paused:
		return "paused"
	}
	return string(st)
}

// The words of pauseFact.Pending.
const (
	pendPause  = "pause"
	pendResume = "resume"
)

// stateLostFrozen is the STATE of a lost run whose last recorded state was paused and whose scope is frozen now.
const stateLostFrozen = "lost, frozen"

// live reports whether st is a state of a run its launcher still holds.
func live(st status.State) bool {
	return st != status.Done && st != status.Lost && st != status.NeverStarted
}

// runPauses is the pause of each snapshot with no run_end that is live or lost, by run id; a run it cannot read the
// pause of, or that never was paused, is left out (not paused). A paused run whose launcher is gone is LauncherGone:
// a lost one (nobody holds its lock), or a live-looking one whose lock is held by a process that is not its launcher
// (runlock.LauncherGone, which proves the launcher by its pid and start time). It reads the ledger of live and lost
// runs only.
func runPauses(root string, snaps []*status.Snapshot) map[string]pauseFact {
	out := map[string]pauseFact{}
	for _, s := range snaps {
		lost := s.St == status.Lost
		if s.Ended || !lost && (!s.LockHeld || !live(s.St)) {
			continue
		}
		dir := filepath.Join(root, s.Run)
		p := readPause(dir, s.Run)
		var cause error
		launcher := runlock.Gone
		if !lost {
			launcher, cause, _ = runlock.LauncherCheck(dir)
		}
		if launcher == runlock.Unknown && cause != nil {
			p.LauncherUnknown = cause.Error()
		}
		if p.Paused {
			p.LauncherGone = launcher == runlock.Gone
		}
		if lost && !p.LauncherGone {
			continue // a lost run that was not paused reads lost, as before
		}
		if p.LauncherGone {
			p.Pending = "" // no launcher answers a request any more
			p.Scope = readScope(dir, s.Run)
		}
		if p != (pauseFact{}) {
			out[s.Run] = p
		}
	}
	return out
}

// launcherGone is runlock.LauncherGone, false when the lock cannot be read: such a run stays as its state reads.
func launcherGone(dir string) bool {
	gone, err := runlock.LauncherGone(dir)
	return err == nil && gone
}

// writeLauncherUnknown says, under the table, which runs' launchers could not be judged and what to do.
func writeLauncherUnknown(w io.Writer, snaps []*status.Snapshot, pauses map[string]pauseFact) error {
	for _, s := range snaps {
		if why := pauses[s.Run].LauncherUnknown; why != "" {
			if _, err := fmt.Fprintf(w, "launcher unknown %s: its lock is held, but the launcher the lock line names could not be "+
				"confirmed (%s). To fix: %s.\n", record.Printable(s.Run), record.Printable(why), runlock.UnknownRecovery); err != nil {
				return err
			}
		}
	}
	return nil
}

// readPause is run's pause from its directory: the last pause line in the ledger and the overlay's last pause or
// resume request.
func readPause(dir, run string) pauseFact {
	why, confirmed := lastPauseLine(filepath.Join(dir, ledger.EventsFile))
	p := pauseFact{Paused: why == record.GapRunPaused || why == record.GapResumeFailed}
	o, err := liveblock.Read(dir, run)
	if err != nil {
		return p // no overlay (never paused or blocked), or one that cannot be read: the ledger's word stands
	}
	var asked uint64
	for _, c := range o.Changes {
		if c.Control() {
			asked = c.Serial
		}
	}
	if asked > confirmed && o.Paused != p.Paused {
		p.Pending = map[bool]string{true: pendPause, false: pendResume}[o.Paused]
	}
	return p
}

// lastPauseLine is the why and overlay serial of the last gap line in the ledger at path that records a pause or a
// resume (record.GapPayload.LiveControl, what=enforce); "" and 0 when there is none or the file cannot be read.
func lastPauseLine(path string) (why string, serial uint64) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0
	}
	defer func() { _ = f.Close() }() // read-only
	rd := bufio.NewReaderSize(f, 64<<10)
	for {
		line, err := rd.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// A line longer than the buffer: a blob-split field keeps live_control lines short, so it is not one.
			if _, err := skipLine(rd); err != nil {
				return why, serial
			}
			continue
		}
		if err != nil {
			return why, serial // no complete line left: one still being written is not read
		}
		if !bytes.Contains(line, []byte(`"live_control"`)) {
			continue
		}
		e, err := record.Decode(bytes.TrimSuffix(line, []byte("\n")))
		if err != nil || e.Kind != record.KindGap {
			continue
		}
		var p record.GapPayload
		if e.DecodePayload(&p) != nil || p.What != record.GapEnforce || p.LiveControl == nil {
			continue
		}
		switch p.Why {
		case record.GapRunPaused, record.GapRunResumed, record.GapPauseFailed, record.GapResumeFailed:
			why, serial = p.Why, p.LiveControl.Serial
		}
	}
}

// writeLostPaused says, under the table, what is known of a lost run whose last recorded state was paused: that
// state, as recorded, what its scope shows now, and the one command that ends it. One line per such run.
func writeLostPaused(w io.Writer, snaps []*status.Snapshot, pauses map[string]pauseFact) error {
	for _, s := range snaps {
		p := pauses[s.Run]
		if !p.LauncherGone {
			continue
		}
		run := record.Printable(s.Run)
		if _, err := fmt.Fprintf(w, "lost %s: its launcher died, and the last state it recorded was paused, with no resume "+
			"after it. Now %s. Tego never thaws a run with no launcher; tego stop %s ends what is left and closes the record "+
			"(run_end orphaned).\n", run, p.Scope.now(), run); err != nil {
			return err
		}
	}
	return nil
}

// lostWhilePaused reports whether run under root is lost with its last recorded state paused: it has no run_end, its
// last pause line holds it paused, and its launcher is gone (runlock.LauncherGone). A read that fails is no: the run
// then reads as its lock says.
func lostWhilePaused(ctx context.Context, root, run string) bool {
	dir := filepath.Join(root, run)
	if !launcherGone(dir) {
		return false
	}
	st, err := ledger.NewRunRepository(root).State(ctx, run)
	if err != nil || st == ledger.StateEnded || st == ledger.StateEmpty {
		return false
	}
	return readPause(dir, run).Paused
}
