// SPDX-License-Identifier: Apache-2.0

package web

import (
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/runact"
)

// The run page's Pause and Resume (record.MinorLiveControl). The button posts to /runs/<id>/pause or /resume, which
// asks the run's launcher through the run's overlay (runact.Pause): the dashboard freezes nothing itself. The
// launcher freezes or thaws the run's cgroup within about half a second and writes a gap line, which moves the read
// model's revision, so the page's live update (static/live.js over /events) re-renders the run's head with the
// confirmed state: the "Paused by you at 12:03" line and the Resume button come from that line, never from the
// request alone (ledgerview.LiveFacts.Paused).

func init() {
	funcs["paused"] = runPaused
	funcs["lostPaused"] = lostPaused
	funcs["unknownRecovery"] = unknownRecovery
	funcs["pausedBy"] = pausedBy
}

// pauseRun is the runact call the handler makes; tests replace it to see what reaches the overlay.
var pauseRun = runact.Pause

// launcherUnknown is runact.LauncherUnknown, which the run page asks of a running run; tests stand in for it.
var launcherUnknown = runact.LauncherUnknown

// unknownRecovery is what to do about a launcher that could not be judged, for the run page's words.
func unknownRecovery() string { return runact.UnknownRecovery }

// runPaused reports whether r is running and its launcher has recorded it paused: the Paused pill a Runs or Overview
// row shows in place of Running. An ended run is never paused, and neither is anything that is not a run (the state
// template is handed a *ledgerview.Run everywhere today; any other value reads as not paused rather than failing).
func runPaused(v any) bool {
	r, ok := v.(*ledgerview.Run)
	return ok && r != nil && r.State() == "running" && ledgerview.LiveFactsOf(r).Paused
}

// lostPaused reports whether r is lost (no run_end, its launcher gone) and its launcher's last recorded pause line held
// it paused. That is the last state recorded, not proof it stayed frozen; Tego never thaws it, and tego stop ends it
// (ADR 0124, second amendment of 2026-11-11).
func lostPaused(v any) bool {
	r, ok := v.(*ledgerview.Run)
	return ok && r != nil && r.State() == "lost" && ledgerview.LiveFactsOf(r).Paused
}

// pausedBy says who asked for a pause, from a change's by ("uid:<uid> pid:<pid> <via>"): "you, from the dashboard"
// when the uid is the dashboard's own, "you, from a terminal" for tego pause, "user 1001 …" for another uid.
func pausedBy(by string) string {
	f := strings.Fields(by)
	who, via := "someone", ""
	if len(f) > 0 {
		if uid, ok := strings.CutPrefix(f[0], "uid:"); ok {
			who = "user " + uid
			if uid == strconv.Itoa(os.Getuid()) {
				who = "you"
			}
		}
	}
	if len(f) > 2 {
		switch f[len(f)-1] {
		case "dashboard":
			via = ", from the dashboard"
		case "cli":
			via = ", from a terminal"
		}
	}
	return who + via
}

// pauseAsk is the pause or resume a run's overlay asks that its launcher has not answered with a line yet: Waiting
// is true from the request until the launcher's line for it, Paused what is asked and At when. Takes is whether the
// run's launcher reads a pause at all (runact.PauseAsk.Takes): the page offers Pause, and shows a pause's state, only
// then.
type pauseAsk struct {
	Takes   bool
	Waiting bool
	Paused  bool
	At      time.Time
}

// pauseAskOf compares the overlay's request with the launcher's last line: a request newer than that line's serial
// that asks the other state is waiting.
func pauseAskOf(a runact.PauseAsk, f ledgerview.LiveFacts) pauseAsk {
	return pauseAsk{Takes: a.Takes, Waiting: a.Serial > f.PauseSerial && a.Paused != f.Paused, Paused: a.Paused, At: a.At}
}

// pause is POST /runs/<run>/pause and /runs/<run>/resume: runact.Pause. It returns to the page the form was on (the
// run's page when it names none) with what was asked; the page then shows the launcher's confirmation as it lands.
func (s *Server) pause(w http.ResponseWriter, r *http.Request, run string, on bool) {
	back := backTo(r, runPage(run))
	name := shortRun(run)
	rr, lerr := ledgerview.LoadRun(s.cfg.Ledger, run)
	if lerr == nil && rr.Agent != "" {
		name = rr.Agent + " (" + shortRun(run) + ")"
	}
	// A request that waits for a person holds a thread the freezer cannot enter, so a pause asked now could not take:
	// the page offers no Pause then, and a stale form is refused with the same words.
	if on && lerr == nil && len(rr.Pending) > 0 && rr.State() == "running" {
		s.redirectBack(w, r, back, flash{Text: "Not done: " + name + " waits on a request. Answer it first; then Pause freezes it."})
		return
	}
	p, err := pauseRun(r.Context(), s.cfg.Ledger, run, on)
	if err != nil {
		var why string
		switch {
		case errors.Is(err, runact.ErrBadRun):
			why = "there is no such run in this ledger."
		case errors.Is(err, runact.ErrPauseNotRunning):
			why = "the run is not running, so there is nothing to pause or resume."
		case errors.Is(err, runact.ErrPauseUnsupported):
			why = "this run cannot be paused: an older Tego started it, it was adopted, or it has no cgroup of its own. Stop run ends it."
		case errors.Is(err, runact.ErrGoverned):
			why = "a governed agent cannot change its own governance."
		default:
			why = "the run could not be " + map[bool]string{true: "paused", false: "resumed"}[on] + ": " + plainErr(err) + "."
		}
		s.redirectBack(w, r, back, flash{Text: "Not done: " + why})
		return
	}
	f := flash{OK: true}
	switch p.Word {
	case runact.WordPaused:
		f.Text = "Pause asked of " + name + ". It says Paused here once the run confirms it, usually within a second."
	case runact.WordAlreadyPaused:
		f.Text = capFirst(name) + " was already paused."
	case runact.WordResumed:
		f.Text = "Resume asked of " + name + ". The run confirms it here, usually within a second."
	default:
		f.Text = capFirst(name) + " was not paused."
	}
	s.redirectBack(w, r, back, f)
}
