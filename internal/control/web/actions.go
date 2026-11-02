// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/askclient"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
)

// answerTimeout bounds one answer's exchange with the run's broker (askproto.Timeout bounds each packet).
const answerTimeout = 10 * time.Second

// routePost routes the state-changing requests, which postAllowed has passed. An answer, a stop and a block answer
// 303 back to the page the form was on, with one line saying what was done (flash.go).
func (s *Server) routePost(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == "/approvals/answer":
		s.answer(w, r)
	case p == "/rule":
		s.ruleGonePost(w, r)
	case p == "/rules/change":
		s.rulesChangePost(w, r)
	case p == "/rules/revert":
		s.rulesRevert(w, r)
	case p == "/rules/new":
		s.rulesNewPost(w, r)
	case p == "/severity/add", p == "/severity/remove":
		s.severityPost(w, r, strings.TrimPrefix(p, "/severity/"))
	case strings.HasPrefix(p, "/runs/") && strings.Contains(p, "/lines/"):
		s.eventDetail(w, r)
	case strings.HasPrefix(p, "/runs/") && strings.HasSuffix(p, "/stop"):
		s.stop(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/runs/"), "/stop"))
	case strings.HasPrefix(p, "/runs/") && strings.HasSuffix(p, "/block"):
		s.block(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/runs/"), "/block"), true)
	case strings.HasPrefix(p, "/runs/") && strings.HasSuffix(p, "/unblock"):
		s.block(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/runs/"), "/unblock"), false)
	case strings.HasPrefix(p, "/runs/") && strings.HasSuffix(p, "/lift"):
		s.liftPost(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/runs/"), "/lift"))
	case strings.HasPrefix(p, "/runs/") && strings.HasSuffix(p, "/restore"):
		s.restorePost(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/runs/"), "/restore"))
	case strings.HasPrefix(p, "/runs/") && strings.HasSuffix(p, "/pause"):
		s.pause(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/runs/"), "/pause"), true)
	case strings.HasPrefix(p, "/runs/") && strings.HasSuffix(p, "/resume"):
		s.pause(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/runs/"), "/resume"), false)
	default:
		if !s.layerPost(w, r) {
			s.fail(w, http.StatusNotFound, "Not found", "Nothing at this address takes a form.")
		}
	}
}

// The broker calls the answer form makes; tests replace them to see what reaches the broker.
var (
	answerAsk    = runact.Answer
	alternateAsk = runact.Alternate
)

// runPage is a run's page, where its actions return when the form named no page.
func runPage(run string) string { return "/runs/" + url.PathEscape(run) }

// askOf is the ask askID of run as its page shows it, and the run; the zero Ask when the run or the ask is not found
// (the answer still goes to the broker, which knows best).
func (s *Server) askOf(run, askID string) (ledgerview.Ask, *ledgerview.Run) {
	rr, err := ledgerview.LoadRun(s.cfg.Ledger, run)
	if err != nil {
		return ledgerview.Ask{}, nil
	}
	for _, a := range rr.Pending {
		if a.AskID == askID {
			return a, rr
		}
	}
	return ledgerview.Ask{}, rr
}

// runPath shortens p as the ask card shows it: under the run's working directory as ./… (./confidential/plan.md),
// under the run's home as ~/… (a demo's with/home reads ~/.config/telemetry/token), else against the dashboard user's
// home.
func runPath(p string, rr *ledgerview.Run) string {
	if rr == nil {
		return tilde(p)
	}
	return runPathIn(p, ledgerview.RunHome(rr), rr.Cwd)
}

// noticeMax is about the most characters of a target the line after an answer names: with Make it permanent after it,
// five lines of a toast at 1440 px.
const noticeMax = 120

// noticeTarget is p as the line after an answer names it (the toast, or the flash line without JavaScript): runPath's
// form, each of a held mutation's two names ("a → b") in it, and past noticeMax characters cut in the middle as the ask
// card cuts a long target, a path's file name kept whole when it is short enough. A 4 KB path an agent made up
// otherwise made a toast taller than the window, its × off the top (QA BR-3); the card and the line page keep the
// target whole.
func noticeTarget(p string, rr *ledgerview.Run) string {
	s := runPath(p, rr)
	if a, b, two := strings.Cut(p, " → "); two {
		s = runPath(a, rr) + " → " + runPath(b, rr)
	}
	if utf8.RuneCountInString(s) <= noticeMax {
		return s
	}
	if strings.HasPrefix(p, "/") && !strings.Contains(p, " ") {
		if i := strings.LastIndexByte(strings.TrimSuffix(s, "/"), '/'); i >= 0 {
			if base := s[i+1:]; utf8.RuneCountInString(base) <= noticeMax/2 {
				return cutMiddle(s[:i+1], noticeMax-utf8.RuneCountInString(base)) + base
			}
		}
	}
	return cutMiddle(s, noticeMax)
}

// runPathIn is runPath with the run's home and working directory given.
func runPathIn(p, home, cwd string) string {
	if dir, base := splitPathIn(p, home, cwd, len(p)); dir+base != p {
		return dir + base
	}
	return tilde(p)
}

// answer is POST /approvals/answer (run, ask, decision=approve|deny|alternate, always=yes, file): `tego approve|deny
// <run> <ask_id> [--always]` and `tego alternate <run> <ask_id> --file <path> [--always]`. It returns to the page
// the form was on (Approvals when it names none) with the answer in a line: "Denied: read of ~/.config/x/token".
func (s *Server) answer(w http.ResponseWriter, r *http.Request) {
	run, id, verb := r.PostForm.Get("run"), r.PostForm.Get("ask"), r.PostForm.Get("decision")
	always, file := r.PostForm.Get("always") == "yes", r.PostForm.Get("file")
	back := backTo(r, "/approvals")
	if verb != "approve" && verb != "deny" && verb != "alternate" {
		s.redirectBack(w, r, back, flash{Text: "Not done: the answer is Allow once, Deny or a stand-in file."})
		return
	}
	ask, rr := s.askOf(run, id)
	what := "the request"
	if ask.AskID != "" {
		what = askNoun(ask.Op, ask.Rule, ask.Hold)
		if ask.Target != "" {
			what += " " + noticeTarget(ask.Target, rr)
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), answerTimeout)
	defer cancel()
	var a runact.Answered
	var err error
	if verb == "alternate" {
		a, err = alternateAsk(ctx, s.cfg.Ledger, run, id, file, always)
	} else {
		a, err = answerAsk(ctx, s.cfg.Ledger, run, id, verb == "approve", always)
	}
	if err != nil {
		s.redirectBack(w, r, back, flash{Text: "Not done: " + answerErr(err)})
		return
	}
	f := flash{OK: true}
	d := a.Decision
	switch {
	case verb == "alternate":
		f.Text = "Gave " + cutMiddle(tilde(file), noticeMax) + " instead, for the " + what
	case verb == "approve" && !d.Approved:
		// The broker's own words say why (the hold timed out first, the run ended): the operation was refused.
		f.OK, f.Text = false, "Not allowed: "+strings.TrimPrefix(a.Word, "not approved: ")
	case verb == "approve" && d.Always:
		f.Text = "Allowed for the rest of this run: " + what
	case verb == "approve":
		f.Text = "Allowed once: " + what
	case d.Always:
		f.Text = "Denied for the rest of this run: " + what
	default:
		f.Text = "Denied: " + what
	}
	if always && !d.Always && verb != "alternate" && f.OK {
		f.Text += " (this once only: the answer could not be kept for the rest of the run)"
	}
	// A denial can become a rule of the contract, so the next run is refused without asking: the link names the ask's
	// line, and its page sends it on to the refusal the ask decided (which may be written a moment after the answer),
	// with Never allow picked on its Act panel. A run with no contract file (tego watch) has nothing to change, and a
	// dashboard without the rule service's Act half (Config.Rules) changes none: its line page says policy editing is off.
	if _, act := s.cfg.Rules.(ActService); act && f.OK && verb == "deny" && rr != nil && rr.Contract != "" {
		if seq := askLine(rr, ask, id); seq > 0 {
			f.Link, f.LinkText = "/runs/"+url.PathEscape(run)+"/lines/"+strconv.FormatUint(seq, 10)+"?decided=1#act", "Make it permanent: Never allow"
		}
	}
	s.redirectBack(w, r, back, f)
}

// askLine is the seq of the ask line of request id: the waiting ask's own, else (no longer waiting by the time the
// run was read) the run's last ask line with that id; 0 when the run holds none.
func askLine(rr *ledgerview.Run, ask ledgerview.Ask, id string) uint64 {
	if ask.Seq > 0 {
		return ask.Seq
	}
	evs := rr.AllEvents()
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Kind == "ask" && evs[i].AskID == id {
			return evs[i].Seq
		}
	}
	return 0
}

// answerErr is why an answer was not given, in plain words, without the package names the errors carry.
func answerErr(err error) string {
	switch {
	case errors.Is(err, runact.ErrBadRun):
		return "there is no such run in this ledger."
	case errors.Is(err, runact.ErrBadAsk):
		return "that is not a request id. The request is still waiting."
	case errors.Is(err, runact.ErrBadAlternate), errors.Is(err, askproto.ErrBadAlternate):
		return "the stand-in file must be an absolute path to a readable file. The request is still waiting: name another file, or allow or deny it."
	case errors.Is(err, askproto.ErrNoAlternate):
		return "only a held file open takes a stand-in file. The request is still waiting: allow or deny it."
	case errors.Is(err, askproto.ErrNotRememberable), errors.Is(err, askproto.ErrStandingFull):
		return "this answer cannot be kept for the rest of the run. The request is still waiting: answer it once."
	case errors.Is(err, askproto.ErrStandingBusy):
		return "another answer for the same request is being recorded. The request is still waiting: look again in a moment, or answer it once."
	case errors.Is(err, askproto.ErrNotPending):
		return "this request is no longer waiting: it was answered, timed out, or its run ended."
	case errors.Is(err, askclient.ErrNoBroker), errors.Is(err, os.ErrNotExist):
		return "the run is not running, so nothing holds this request any more."
	case errors.Is(err, askproto.ErrProtocol):
		return "the run's broker did not understand the answer. The request is still waiting."
	}
	return plainErr(err) + "."
}

// plainErr is err's text without the "package: " prefixes Go errors collect, first letter as written.
func plainErr(err error) string {
	msg := err.Error()
	for {
		head, rest, ok := strings.Cut(msg, ": ")
		if !ok || strings.ContainsAny(head, " \"'") || head != strings.ToLower(head) {
			return msg
		}
		msg = rest
	}
}

// stopData is the Stop confirm page: the run, and whether a stop was already asked of it.
type stopData struct {
	Run      *ledgerview.Run
	Stopping bool
}

// stopConfirm is GET /runs/<run>/stop: the confirm step, which changes nothing.
func (s *Server) stopConfirm(w http.ResponseWriter, _ *http.Request, id string) {
	run, err := ledgerview.LoadRun(s.cfg.Ledger, id)
	if err != nil {
		s.fail(w, http.StatusNotFound, "No such run", "No run "+id+" is in this ledger root.")
		return
	}
	snap, ok := s.load(w)
	if !ok {
		return
	}
	title := "Stop " + run.Agent
	if run.Agent == "" {
		title = "Stop " + shortRun(id)
	}
	s.render(w, http.StatusOK, "stop", s.chromeOf(snap, title, "runs"), stopData{run, run.Live && runact.Stopping(s.cfg.Ledger, id)})
}

// stop is POST /runs/<run>/stop with confirm=yes: `tego stop <run>`. It waits StopWait at most, then returns to the
// run's page: "Stopped" when the run ended, "Stopping" when it is still ending (the page says Stopping until its
// run_end).
func (s *Server) stop(w http.ResponseWriter, r *http.Request, run string) {
	if r.PostForm.Get("confirm") != "yes" {
		s.stopConfirm(w, r, run)
		return
	}
	name := shortRun(run)
	if rr, err := ledgerview.LoadRun(s.cfg.Ledger, run); err == nil && rr.Agent != "" {
		name = rr.Agent + " (" + shortRun(run) + ")"
	}
	st, err := runact.Stop(r.Context(), s.cfg.Ledger, run, s.cfg.StopWait)
	f := flash{OK: true}
	switch {
	case errors.Is(err, runact.ErrBadRun):
		f = flash{Text: "Not done: there is no such run in this ledger."}
	case err != nil:
		f = flash{Text: "Not done: the run could not be stopped: " + plainErr(err) + "."}
	case st.Word == "not running":
		f.Text = name + " was not running, so there was nothing to stop."
	case st.Ended:
		f.Text = "Stopped " + name + "."
	default:
		// The launcher sends SIGTERM, then SIGKILL after the stop grace (stop_grace, 10 s by default): an agent that
		// ignores SIGTERM or waits on an ask takes the whole grace.
		f.Text = "Stopping " + name + ": the agent and everything it started end within the stop grace (10 s by default)."
	}
	s.redirectBack(w, r, runPage(run), f)
}

// block is POST /runs/<run>/block and /runs/<run>/unblock (kind=exec|net|path, value): a live block added to or
// removed from the running run (runact.Block). The run's launcher puts it in force within about a second and writes
// a gap live-block-added or live-block-removed line. It returns to the page the form was on (the run's page when
// it names none) with what was done: "Blocked ls on run r-…bzf".
//
// The form's time limit (for, until, span, tz: untilOf, ADR 0125 decision 4) makes it runact.BlockUntil's: a block that ends
// by itself, or an unblock after which the block refuses again. "permanently" places the block with no end and goes on
// to Change rules for the run's rules file, where the matching refusal is its own change (preview, confirm, journal).
func (s *Server) block(w http.ResponseWriter, r *http.Request, run string, add bool) {
	kind, value := r.PostForm.Get("kind"), r.PostForm.Get("value")
	back := backTo(r, runPage(run))
	now := liveNow()
	until, perm, err := untilOf(r.PostForm.Get("for"), r.PostForm.Get("until"), r.PostForm.Get("span"), r.PostForm.Get("tz"), now)
	if err != nil {
		s.redirectBack(w, r, back, flash{Text: "Not done: the time limit is not one: " + err.Error() + "."})
		return
	}
	b, err := blockRun(r.Context(), s.cfg.Ledger, run, kind, value, add, until, "dashboard")
	if err != nil {
		var why string
		switch {
		case errors.Is(err, runact.ErrBadRun):
			why = "there is no such run in this ledger."
		case errors.Is(err, runact.ErrNotRunning):
			why = "the run is not running, so no block can be put in force."
		case errors.Is(err, runact.ErrNoTimeLimits):
			why = "this run was started by an older tego that has no time limits: block it with no end, or restart the run."
		case errors.Is(err, liveblock.ErrInvalid):
			why = plainErr(err) + "."
		default:
			why = "the block could not be changed: " + plainErr(err) + "."
		}
		s.redirectBack(w, r, back, flash{Text: "Not done: " + why})
		return
	}
	what := blockWhat(kind, value)
	if v := strings.TrimPrefix(strings.TrimSuffix(b.Rule, "]"), "live.block["); v != b.Rule {
		if k, val, ok := strings.Cut(v, ":"); ok {
			what = blockWhat(k, val)
		}
	}
	on := " on run " + shortRun(run)
	f := flash{OK: true}
	switch b.Word {
	case "blocked":
		// What the block does to this run (internal/check/livestatus): a watched run records it and refuses nothing,
		// and a path block on a run whose reads are not seen refuses changes only.
		switch {
		case b.Observe:
			f.Text = "Marked " + what + on + ": recorded, not enforced, since this run is only watched."
		case strings.HasPrefix(b.Rule, "live.block[path:") && !b.ReadsSeen:
			f.Text = "Blocked " + what + on + ". Changes are refused from the next try on; this run's reads are not seen, so reading it still works."
		default:
			f.Text = "Blocked " + what + on + ". It is refused from the next try on."
		}
	case "already blocked":
		f.Text = capFirst(what) + " was already blocked" + on + "."
	case "block removed":
		f.Text = "Removed the block on " + what + on + ". The contract decides again."
	default:
		f.Text = capFirst(what) + " was not blocked" + on + "."
	}
	switch {
	case b.Until.IsZero() || b.Word == "was not blocked":
	case add:
		f.Text += " It lasts " + whenWords(b.Until, now) + "."
	default:
		f.Text += " The block refuses again at " + b.Until.Local().Format("Mon 2 Jan 15:04") + " (" + inWords(b.Until.Sub(now)) + ")."
	}
	f.Text += realFlash(b)
	if perm && add && (b.Word == "blocked" || b.Word == "already blocked") {
		if rr, err := ledgerview.LoadRun(s.cfg.Ledger, run); err == nil {
			if ref := contractRef(rr.Contract); ref != "" {
				text := "Blocked now · to keep it next run, add the block below and save"
				if b.Observe { // a watched run records a mark and refuses nothing
					text = "Marked now (watched run, recorded only) · to block it next run, add the block below and save"
				}
				s.redirectBack(w, r, "/rules/change?c="+url.QueryEscape(ref), flash{OK: true, Text: text})
				return
			}
		}
		f.Text += " This run names no rules file, so there is no file to keep it in."
	}
	s.redirectBack(w, r, back, f)
}

// realFlash says what a path, read or write block does about the path its value leads to through a link
// (runact.Blocked): refuses it too, does not (a run an older tego started), or cannot tell (the walk ran out of time).
// The path is the agent's to shape (it planted the links), so it is written with its invisible characters shown.
func realFlash(b runact.Blocked) string {
	switch {
	case b.Real != "":
		return " It leads to " + visibleText(tilde(b.Real)) + " through a link; the block refuses both."
	case b.Uncovered != "":
		return " It leads to " + visibleText(tilde(b.Uncovered)) + " through a link, which this run's older tego does not follow: block that path too."
	case b.RealUnknown:
		return " Whether it leads elsewhere through a link could not be worked out in time; it is refused as written."
	}
	return ""
}

// blockWhat names what a live block of kind on value refuses: "ls", "connections to 127.0.0.1:8080", "the path /x".
func blockWhat(kind, value string) string {
	switch kind {
	case "net":
		return "connections to " + value
	case "path":
		return "the path " + tilde(value)
	}
	return value
}

// capFirst is s with its first letter upper case.
func capFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// shellWord is s as one word of a POSIX shell line: unchanged when it holds only characters a shell leaves alone,
// otherwise in single quotes, so a terminal twin a page shows can be pasted as it stands.
func shellWord(s string) string {
	s = strings.TrimSpace(s)
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-:@,+=") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
