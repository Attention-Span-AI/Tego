// SPDX-License-Identifier: Apache-2.0

package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Lift, grant and restore of an Adjustable run's fence entries, and the time limit of every live change (ADR 0125).
// GET /runs/<run>/lift?kind=&value=&for=&until=&tz= is the preview: what the run will be able to do, for how long, in
// whose hands the enforcement is, and a confirm form bound to that one change by the rule service's acknowledgement
// (LiveAck: the run, the entry, the absolute limit, the permanent flag and the overlay's serial). POST
// /runs/<run>/lift checks the checkbox and the acknowledgement against the overlay as it is now and asks runact.Lift;
// POST /runs/<run>/restore asks runact.Restore, which narrows and needs no acknowledgement. Both POSTs pass the same
// session, CSRF, Host and governed-peer checks as every change (server.go), and runact refuses a lift from inside a
// run again (SelfGoverned). The page decides nothing: the run's launcher checks the lift's MAC and writes the line
// of what took effect, which the Rules page's fence panel folds (ledgerview.FenceRows).

// LiveAckService is what the lift preview and its confirm ask of the rule service (internal/control/rules ack.go).
type LiveAckService interface {
	LiveAck(run, kind, value string, until time.Time, permanent bool, serial uint64) string
	LiveAckOK(got, run, kind, value string, until time.Time, permanent bool, serial uint64) bool
}

// The writers the forms call; tests may replace them.
var (
	liftRun    = runact.Lift
	restoreRun = runact.Restore
	blockRun   = runact.BlockUntil
	// liveNow is the clock a limit is made and checked on: runact checks it against the real clock, whatever clock
	// the pages read (Config.Now).
	liveNow = time.Now
)

// The values of a time limit's select (the "for" field, templates/rules-parts.tmpl forselect) besides forSpans'. Block
// now picks forRun; the lift forms pick "1h", since a lift loosens.
const (
	forRun   = "run"
	forUntil = "until"
	forPerm  = "perm"
	// forTyped is "for…": a duration the person types in the span field, in --for's syntax (45m, 72h, 3d, 1d12h,
	// 7w), read by the parser --for uses (liveblock.ParseDuration).
	forTyped = "for"
)

// spanForms are the typed durations a "for…" error suggests, as --for's help names them.
const spanForms = "type a duration such as 45m, 4m, 72h, 3d, 1d12h or 7w"

// forSpans are the fixed durations a time limit's select offers. untilOf adds one to the clock read when the request
// that names it arrives, to the nanosecond: a Block now click, or the Lift… or Grant… click that makes the preview,
// whose confirm then carries that end. The short ones (2 to 30 minutes) are what until… cannot say exactly, since it
// takes a whole minute: "until 20:33" picked at 20:31:51 lasts 69 s.
var forSpans = map[string]time.Duration{"2m": 2 * time.Minute, "4m": 4 * time.Minute, "15m": 15 * time.Minute,
	"30m": 30 * time.Minute, "1h": time.Hour, "1d": 24 * time.Hour, "3d": 72 * time.Hour, "1w": 7 * 24 * time.Hour}

// errNoUntil is a time limit chosen as "until…" with no date and time; errNoSpan one chosen as "for…" with no
// duration.
var (
	errNoUntil = errors.New("pick the date and time it ends")
	errNoSpan  = errors.New(spanForms)
)

// untilOf is the absolute end a form's time limit names, made at now: zero for the rest of the run (an empty choice
// too, as an older form posts none); perm for "permanently", which is no end here and a change of the rules file
// after. until is a datetime-local value, read in the zone tz names (minutes west of UTC, as a browser's
// getTimezoneOffset says) or else the dashboard's; span is the typed duration of "for…". A limit is held to
// liveblock.CheckUntil's bounds.
func untilOf(choice, until, span, tz string, now time.Time) (end time.Time, perm bool, err error) {
	switch choice {
	case "", forRun:
		return time.Time{}, false, nil
	case forPerm:
		return time.Time{}, true, nil
	case forTyped:
		span = strings.TrimSpace(span)
		if span == "" {
			return time.Time{}, false, errNoSpan
		}
		d, err := liveblock.ParseDuration(span)
		if err != nil {
			return time.Time{}, false, fmt.Errorf("for %q: %v; %s", span, err, spanForms) // the CLI's --for error, in the form's words
		}
		end = now.Add(d)
	case forUntil:
		until = strings.TrimSpace(until)
		if until == "" {
			return time.Time{}, false, errNoUntil
		}
		loc := time.Local
		if m, err := strconv.Atoi(tz); err == nil && m >= -16*60 && m <= 16*60 {
			loc = time.FixedZone("", -m*60)
		}
		for _, layout := range []string{"2006-01-02T15:04", "2006-01-02T15:04:05"} {
			if end, err = time.ParseInLocation(layout, until, loc); err == nil {
				break
			}
		}
		if err != nil {
			return time.Time{}, false, fmt.Errorf("%q is not a date and time", until)
		}
	default:
		d, ok := forSpans[choice]
		if !ok {
			return time.Time{}, false, fmt.Errorf("%q is not a time limit", choice)
		}
		end = now.Add(d)
	}
	end = end.UTC()
	if err := liveblock.CheckUntil(now, end); err != nil {
		return time.Time{}, false, errors.New("a time limit ends 1 minute to 400 days from now")
	}
	return end, false, nil
}

// whenWords says a limit's end as the pages do: "until Fri 31 Oct 17:00 (in 3 days)", or "for the rest of this run".
func whenWords(until, now time.Time) string {
	if until.IsZero() {
		return "for the rest of this run"
	}
	return "until " + until.Local().Format("Mon 2 Jan 15:04") + " (" + inWords(until.Sub(now)) + ")"
}

// inWords is a span ahead in rounded words: "in 45 minutes", "in 5 hours", "in 3 days", "in 7 weeks".
func inWords(d time.Duration) string {
	n := func(v float64, one, many string) string {
		i := int(v + 0.5)
		if i <= 1 {
			return "in 1 " + one
		}
		return "in " + strconv.Itoa(i) + " " + many
	}
	switch {
	case d < 0:
		return "already passed"
	case d < 90*time.Minute:
		return n(d.Minutes(), "minute", "minutes")
	case d < 23*time.Hour+30*time.Minute:
		return n(d.Hours(), "hour", "hours")
	case d < 14*24*time.Hour:
		return n(d.Hours()/24, "day", "days")
	}
	return n(d.Hours()/24/7, "week", "weeks")
}

// chipUntil is a lifted row's or a timed block's end, short: "Fri 17:00", with the date when it is not this week.
func chipUntil(until, now time.Time) string {
	l := until.Local()
	if until.Sub(now) < 6*24*time.Hour {
		return l.Format("Mon 15:04")
	}
	return l.Format("Mon 2 Jan 15:04")
}

func init() {
	funcs["blockChip"] = blockChipOf
	funcs["activeBlocks"] = activeBlocks
}

// activeBlocks is how many of blocks refuse at now: neither past their limit nor unblocked for a while.
func activeBlocks(blocks []liveblock.Entry, now time.Time) int {
	n := 0
	for _, b := range blocks {
		if t := blockTimeOf(b, now); !t.Ended && !t.Dormant {
			n++
		}
	}
	return n
}

// blockTime is how a live block's time limit stands at now, as the pages say it (ADR 0125 decision 4). liveblock.Read
// keeps an ended block in the file for a day (endedKeep), and a block unblocked for a while stays listed with From
// set (RemoveUntil); livestatus knows neither, so a page that showed only its state would call both in force.
type blockTime struct {
	// Ended: its limit has passed by the page's clock, so it refuses nothing (the launcher judges on its own clocks
	// and writes live-block-expired within a poll). Dormant: it is unblocked until From and refuses again then.
	Ended, Dormant bool
	// Ends is the row's words: "until Fri 17:00", "ended at Tue 13:51", "unblocked until Fri 17:00, then refused
	// again"; "" for a block in force with no limit.
	Ends string
	// Why replaces the chip's plain line when the limit changes what it says; "" keeps it.
	Why string
}

// Timed: the block has a limit or an unblock with one, so "they end with the run" no longer says all.
func (t blockTime) Timed() bool { return t.Ends != "" }

// blockTimeOf is block b's time limit at now.
func blockTimeOf(b liveblock.Entry, now time.Time) blockTime {
	switch {
	case !b.Until.IsZero() && !now.Before(b.Until):
		return blockTime{Ended: true, Ends: "ended at " + chipUntil(b.Until, now),
			Why: "Its time limit has passed: it refuses nothing now."}
	case !b.From.IsZero() && now.Before(b.From):
		t := blockTime{Dormant: true, Ends: "unblocked until " + chipUntil(b.From, now) + ", then refused again",
			Why: "Unblocked for now: it refuses nothing until " + chipUntil(b.From, now) + "."}
		if !b.Until.IsZero() {
			t.Ends += " until " + chipUntil(b.Until, now)
		}
		return t
	case !b.Until.IsZero():
		return blockTime{Ends: "until " + chipUntil(b.Until, now)}
	}
	return blockTime{}
}

// blockChip is the run page's chip of block b: liveChipOf's, with its time limit judged at now. An ended block's
// chip says so and offers no Remove; an unblocked one says until when; a timed one in force says when it ends
// instead of "until the run ends".
type blockChip struct {
	liveChip
	blockTime
}

// blockChipOf is block b's chip on the run v describes, at now.
func blockChipOf(b liveblock.Entry, v liveView, now time.Time) blockChip {
	c := blockChip{liveChip: liveChipOf(b, v), blockTime: blockTimeOf(b, now)}
	if c.State == ledgerview.LiveEnded || c.State == ledgerview.LiveRecordedOnly {
		return c // the run has ended, or refuses nothing anyway: the limit changes nothing it says
	}
	switch {
	case c.Ended:
		// The chip says when it ended; the row's words beside it would say it again ("ended at Tue 20:02" and
		// "Ended at Tue 20:02"), so they drop it.
		c.Label, c.Class, c.Note = "Ended at "+chipUntil(b.Until, now), "b-done", c.Why
		c.Ends = ""
	case c.Dormant:
		c.Label, c.Class, c.Note = "Unblocked until "+chipUntil(b.From, now), "b-waiting", c.Why
	case c.Ends != "" && c.State == ledgerview.LiveInForce:
		c.Note = "Refused from the next try " + c.Ends + "."
	}
	return c
}

// liftWhat is what a fence entry lets run do, as a verb phrase: "read ~/x", "connect to host:port", "run /path". A
// read's folder is written as Logs writes it (runPath): under the run's home as ~/…, under its working directory as
// ./…, so the fence row and the lift preview say ~/datasets where Logs does, never /home/<you>/…/with/home/datasets. A
// nil run (it could not be read) falls back to the dashboard user's home.
func liftWhat(kind, value string, run *ledgerview.Run) string {
	switch kind {
	case string(liveblock.KindRead):
		return "read " + runPath(value, run)
	case string(liveblock.KindNet):
		return "connect to " + value
	}
	return "run " + value
}

// fenceRowView is one row of the Rules page's fence panel.
type fenceRowView struct {
	ledgerview.FenceRow
	// What is the entry as a sentence ("Read ~/x"); Chip and ChipClass its state chip; Verb "Lift" (one of the
	// contract's refusals) or "Grant" (new access), and Done its past tense ("Lifted", "Granted") for the chip and the
	// "· lifted by" aside.
	What, Chip, ChipClass, Verb, Done string
}

// fenceView is the Rules page's fence panel of an Adjustable run.
type fenceView struct {
	Rows []fenceRowView
	// Running: the run runs, so its rows offer Lift, Grant and Restore.
	Running bool
}

// fenceViewOf is run's fence panel as of now.
func fenceViewOf(run *ledgerview.Run, now time.Time) *fenceView {
	v := &fenceView{Running: run.State() == "running"}
	for _, r := range ledgerview.FenceRows(run, now) {
		row := fenceRowView{FenceRow: r, What: capFirst(liftWhat(r.Kind, r.Value, run)), Verb: "Lift", Done: "Lifted"}
		if r.Source == record.LiveFenceSourceNew {
			// New access is granted, not lifted: the row's chip and aside say what its Grant… button did.
			row.Verb, row.Done = "Grant", "Granted"
		}
		switch {
		case r.State != ledgerview.FenceLifted:
			row.Chip, row.ChipClass = "Blocked", "b-refused"
		case r.Until.IsZero():
			row.Chip, row.ChipClass = row.Done+" for this run", "b-asked"
		default:
			row.Chip, row.ChipClass = row.Done+" until "+chipUntil(r.Until, now), "b-asked"
		}
		v.Rows = append(v.Rows, row)
	}
	return v
}

// liftData is the lift preview's data.
type liftData struct {
	Run *ledgerview.Run
	// Kind and Value are the fence entry's (Value normalized); What its verb phrase; Grant: it is new access.
	Kind, Value, What string
	Grant, Exec       bool
	// When says the limit; Until is its absolute UTC instant ("" for none), Permanent the person's choice to keep it.
	When, Until string
	Permanent   bool
	// Serial is the overlay's serial the acknowledgement binds; Ack the acknowledgement.
	Serial uint64
	Ack    string
	// Err says why no lift can be confirmed here; the page then shows no confirm form.
	Err string
	// CLI is the terminal twin; Back the Rules page's fence panel.
	CLI, Back string
}

// fenceBack is the Rules page's fence panel of run.
func fenceBack(run string) string { return "/rules?run=" + url.QueryEscape(run) + "#live-fence" }

// liftPreview serves GET /runs/<run>/lift: the preview, which changes nothing.
func (s *Server) liftPreview(w http.ResponseWriter, r *http.Request, id string) {
	run, err := ledgerview.LoadRun(s.cfg.Ledger, id)
	if err != nil {
		s.fail(w, http.StatusNotFound, "No such run", "No run "+id+" is in this ledger root.")
		return
	}
	snap, ok := s.load(w)
	if !ok {
		return
	}
	q := r.URL.Query()
	d := liftData{Run: run, Back: fenceBack(id)}
	d.Kind, d.Value, d.Err = s.fenceEntryOf(run, q.Get("kind"), q.Get("value"))
	d.What, d.Exec = liftWhat(d.Kind, d.Value, run), d.Kind == string(liveblock.KindExec)
	if e, ok := ledgerview.LiveFactsOf(run).InFence(d.Kind, d.Value); ok {
		d.Grant = e.Source == record.LiveFenceSourceNew
	}
	now := liveNow()
	until, perm, err := untilOf(q.Get("for"), q.Get("until"), q.Get("span"), q.Get("tz"), now)
	if err != nil && d.Err == "" {
		d.Err = "The time limit is not one: " + err.Error() + "."
	}
	d.When, d.Permanent = whenWords(until, now), perm
	if !until.IsZero() {
		d.Until = until.Format(time.RFC3339Nano)
	}
	svc, _ := s.cfg.Rules.(LiveAckService)
	if svc == nil && d.Err == "" {
		d.Err = "Lifting is off here · use tego lift"
	}
	if d.Err == "" {
		lb, err := runact.Live(s.cfg.Ledger, id)
		if err != nil {
			d.Err = "The run's live rules could not be read: " + rulesview.LiveErrWords(err) + "."
		} else {
			d.Serial = lb.Serial
			d.Ack = svc.LiveAck(id, d.Kind, d.Value, until, perm, d.Serial)
		}
	}
	verb := "lift"
	if d.Grant {
		verb = "grant"
	}
	// The terminal twin only for a change the page could confirm: a kind or value that did not parse came from the
	// link, and a crafted link must not hand the person a command to paste.
	if d.Err == "" {
		var limit string
		switch {
		case q.Get("for") == forUntil && !until.IsZero():
			limit = " --until " + shellWord(until.Local().Format("2006-01-02 15:04"))
		case forSpans[q.Get("for")] > 0:
			limit = " --for " + q.Get("for")
		case q.Get("for") == forTyped && !until.IsZero():
			limit = " --for " + shellWord(strings.TrimSpace(q.Get("span")))
		}
		d.CLI = "tego " + verb + " " + id + " " + changeWords(d.Kind, d.Value, limit)
	}
	title := "Lift"
	if d.Grant {
		title = "Grant"
	}
	s.render(w, http.StatusOK, "livefence", s.chromeOf(snap, title+" · "+shortRun(id), "rules"), d)
}

// fenceEntryOf is kind and value parsed and normalized as a live block's, and why no lift of them can be asked of run
// now ("" when one can): the run is not running, is Locked, or its fence does not list the entry.
func (s *Server) fenceEntryOf(run *ledgerview.Run, kind, value string) (k, v, why string) {
	pk, err := liveblock.ParseKind(kind)
	if err != nil {
		return kind, value, "That is not a fence entry: " + plainErr(err) + "."
	}
	v, err = liveblock.Normalize(pk, value)
	if err != nil {
		return string(pk), value, "That is not a fence entry: " + plainErr(err) + "."
	}
	k = string(pk)
	f := ledgerview.LiveFactsOf(run)
	switch {
	case !f.Adjustable:
		return k, v, "Locked run · loosening applies from the next run"
	case run.State() != "running":
		return k, v, "This run is not running, so there is nothing to lift."
	}
	if _, ok := f.InFence(k, v); !ok {
		return k, v, capFirst(liftWhat(k, v, run)) + " is outside this run's fence, so it applies from the next run."
	}
	return k, v, ""
}

// liftMu makes a lift's acknowledgement check and its write one step against this dashboard's other lifts and
// restores: a second confirm of the same preview (a double click, a second tab) then reads the serial the first one
// moved and is refused, and a restore made here cannot slip between a lift's check and its write. A change made
// elsewhere (tego restore in a terminal) in that window still can; closing it needs runact.Lift to check the serial
// inside the overlay's own lock.
var liftMu sync.Mutex

// liftPost serves POST /runs/<run>/lift: the confirm.
func (s *Server) liftPost(w http.ResponseWriter, r *http.Request, id string) {
	liftMu.Lock()
	defer liftMu.Unlock()
	f := r.PostForm
	back := fenceBack(id)
	notDone := func(why string) { s.redirectBack(w, r, back, flash{Text: "Not done: " + why}) }
	if f.Get("understand") != "yes" {
		notDone("tick “I understand this run gets this access now” to confirm it.")
		return
	}
	k, err := liveblock.ParseKind(f.Get("kind"))
	if err != nil {
		notDone(plainErr(err) + ".")
		return
	}
	v, err := liveblock.Normalize(k, f.Get("value"))
	if err != nil {
		notDone(plainErr(err) + ".")
		return
	}
	var until time.Time
	if u := f.Get("until"); u != "" {
		if until, err = time.Parse(time.RFC3339Nano, u); err != nil {
			notDone("the time limit is not one. Preview again.")
			return
		}
	}
	perm := f.Get("permanent") == "1"
	svc, _ := s.cfg.Rules.(LiveAckService)
	if svc == nil {
		notDone("this dashboard was started without its rule service, so it cannot confirm a lift. Use tego lift in a terminal.")
		return
	}
	lb, err := runact.Live(s.cfg.Ledger, id)
	if err != nil {
		notDone(liftErr(err))
		return
	}
	if !svc.LiveAckOK(f.Get("ack"), id, string(k), v, until, perm, lb.Serial) {
		notDone("this run's live rules changed since the preview. Preview again.")
		return
	}
	now := liveNow()
	if !until.IsZero() && liveblock.CheckUntil(now, until) != nil {
		notDone("the time limit has passed or is out of bounds (it ends 1 minute to 400 days from now). Preview again.")
		return
	}
	l, err := liftRun(r.Context(), s.cfg.Ledger, id, string(k), v, until, "dashboard")
	if err != nil {
		notDone(liftErr(err))
		return
	}
	rr, rerr := ledgerview.LoadRun(s.cfg.Ledger, id)
	if rerr != nil {
		rr = nil // the line names the folder from the dashboard user's home (liftWhat)
	}
	what := liftWhat(string(k), v, rr)
	if perm {
		if rr != nil {
			if ref := rules.Ref(rr.Contract); ref != "" {
				done := "Lifted"
				if e, ok := ledgerview.LiveFactsOf(rr).InFence(string(k), v); ok && e.Source == record.LiveFenceSourceNew {
					done = "Granted" // new access, as the fence row's chip says
				}
				s.redirectBack(w, r, "/rules/change?c="+url.QueryEscape(ref), flash{OK: true, Text: done + " now. To keep it from the next run, " +
					"move this entry from live.fence into the rules below and save (its own preview and confirm)."})
				return
			}
		}
	}
	text := "Asked: " + what + " " + whenWords(l.Until, now) + " on run " + shortRun(id) +
		". Tego's live layer allows it within a second; the Rules page shows it once the launcher has recorded it."
	if perm {
		text += " This run names no rules file, so there is no file to keep it in."
	}
	s.redirectBack(w, r, back, flash{OK: true, Text: text})
}

// restorePost serves POST /runs/<run>/restore: the fence entry is refused again. It narrows, so it needs no
// acknowledgement.
func (s *Server) restorePost(w http.ResponseWriter, r *http.Request, id string) {
	liftMu.Lock()
	defer liftMu.Unlock()
	f := r.PostForm
	back := backTo(r, fenceBack(id))
	_, err := restoreRun(r.Context(), s.cfg.Ledger, id, f.Get("kind"), f.Get("value"), "dashboard")
	if err != nil {
		s.redirectBack(w, r, back, flash{Text: "Not done: " + liftErr(err)})
		return
	}
	rr, rerr := ledgerview.LoadRun(s.cfg.Ledger, id)
	if rerr != nil {
		rr = nil // the line names the folder from the dashboard user's home (liftWhat)
	}
	what := liftWhat(f.Get("kind"), f.Get("value"), rr)
	if k, err := liveblock.ParseKind(f.Get("kind")); err == nil {
		if v, err := liveblock.Normalize(k, f.Get("value")); err == nil {
			what = liftWhat(string(k), v, rr)
		}
	}
	s.redirectBack(w, r, back, flash{OK: true, Text: "Restored: " + what + " is refused again on run " + shortRun(id) + "."})
}

// liftErr is why a lift or a restore was not asked, in plain words.
func liftErr(err error) string {
	switch {
	case errors.Is(err, runact.ErrBadRun):
		return "there is no such run in this ledger."
	case errors.Is(err, runact.ErrGoverned):
		return "this request came from inside a run, and an agent can never loosen its own rules."
	case errors.Is(err, runact.ErrNotRunning):
		return "the run is not running, so its fence no longer applies."
	case errors.Is(err, runact.ErrLocked):
		return "this run is Locked: loosening applies from its next run."
	case errors.Is(err, runact.ErrOutsideFence):
		return "that entry is outside this run's fence, so it applies from the next run."
	case errors.Is(err, runact.ErrNoKey):
		return "this run's live key cannot be read, so no lift can be asked (a run started by an older tego has none)."
	case errors.Is(err, liveblock.ErrInvalid):
		return plainErr(err) + "."
	}
	return "the change could not be asked: " + plainErr(err) + "."
}
