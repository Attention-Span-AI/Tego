// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/liveblock"
)

// The event details page (/runs/<run>/lines/<seq>): one ledger line in plain words, the exact line as written, the
// lines around it, the same file, program or destination across every run, and an "Act on this" panel that turns
// the line into a rule of the run's contract at the scope picked (a file or any folder above it up to the run's
// working directory or home; a program or its command; a destination or its whole host). The panel leads with the
// one action that fits (on a line an ask entry decided, "Never allow" at that entry's folder),
// folds the ones that do not under "Why not the others", previews the change as sentences with its direction, and
// writes it on Confirm (POST, the same checks as every form, the preview's base hash carried back) through
// Config.Rules, as `tego rule` does. A narrowing offers "Also apply now" on each live run of the contract; after the
// write the panel shows what changed and an Undo. A live run also gets Block now at the picked scope, which posts to
// the run's existing live-block form. The page reads no contract and writes no file itself.

// ActService is the rule service's details-page half (rules.Service.ActOn and Revert); a Config.Rules without it
// serves the page without the panel.
type ActService interface {
	ActOn(ctx context.Context, r rules.ActReq) (*rules.ActPlan, error)
	Revert(ctx context.Context, r rules.RevertReq) (*rules.Reverted, error)
}

// contextLines is how many lines before and after the line the page lists.
const contextLines = 5

// eventPage is parsed apart from pageNames so the page is one new file; it shares the layout and the funcs.
var eventPage = sync.OnceValues(func() (*template.Template, error) {
	t, err := template.New("layout.tmpl").Funcs(funcs).Funcs(template.FuncMap{"scopeKey": scopeKey, "scopeVal": scopeVal, "baseName": path.Base, "ctxRow": ctxRowOf}).
		Funcs(factsFuncs).
		ParseFS(assets, "templates/layout.tmpl", "templates/rulelink.tmpl", "templates/event.tmpl", "templates/evfacts.tmpl")
	if err != nil {
		return nil, err
	}
	return t, escapeRegions("event", t)
})

// eventData is the details page's data.
type eventData struct {
	Run *ledgerview.Run
	Ev  ledgerview.Event
	// F is the facts column (eventfacts.go): the line explained, its process chain, decision, question and chain.
	F *factsView
	// FullCommand is the whole command an exec line or run_start moved to a blob (a row keeps 8 KiB of it), ""
	// when the line has none or the blob fails its checks.
	FullCommand string
	// CLI is the terminal twin that prints this line byte for byte: seq is gapless from 0, so line seq N is line N+1.
	CLI   string
	Label string
	Into  string // how far into the run the line came
	// AgentText is set for a line whose target the agent chose (a path, a program, a destination).
	AgentText bool
	Before    []ledgerview.Event
	After     []ledgerview.Event
	// Prev and Next are the lines just before and after, nil at either end.
	Prev, Next *ledgerview.Event
	Similar    ledgerview.Similar
	CSRF       string
	// Act is the panel's model; ActErr says why it is not shown.
	Act    *actView
	ActErr string
	// NoAct hides the panel: a line nobody can make a rule from (noActKinds).
	NoAct bool
	// Guard is the rule that already refuses the line, in words, on a refusal by a deny_read entry or the built-in
	// secret list: the panel leads with it and folds the options that widen under "Change this rule" (UX-F10).
	Guard string
	// Head is the headline's sentence with its object ("The agent tried to read" ~/.config/telemetry/token), nil when
	// the panel's plan names no action and the page says "Line #N: <kind>" instead.
	Head *headView
}

// headView is the line page's headline: Lead the words, Target what they act on (masked, the run's home as ~/, cut
// near maxHeadTarget characters) and Title the whole masked value.
type headView struct {
	Lead, Target, Title string
}

// ctxRow is one row of "Around it" in the words Logs uses (r9 QG-9): an ask row reads "Asked to read <file>" under an
// Asked chip, an answer row "Denied by somebody after 77 ms: <file>" under the answer's own chip, never "Recorded"
// and never the answer line's raw target ("q-… by uid:1000 pid:…, not approved").
type ctxRow struct {
	Class, Icon, Word string
	Op, Text, Title   string
}

// ctxRowOf is e as an "Around it" row: the operation and target as shownOp and shown say them, masked, and for an ask
// or answer line (which has no verdict of its own) a chip that says what the line is; every other line keeps the chip
// the template hands in (verdictClass, verdictIcon, verdictWord, as on every row of the dashboard).
func ctxRowOf(e ledgerview.Event, class, icon, word string) ctxRow {
	r := ctxRow{Op: shownOp(e), Title: shown(e), Class: class, Icon: icon, Word: word}
	r.Text = cutMiddle(r.Title, 90)
	switch {
	case e.Kind == "ask" && e.Verdict == "":
		r.Class, r.Icon, r.Word = "asked", "i-hand", "Asked"
	case e.Kind == "answer" && e.Verdict == "":
		var p rowPayload
		ok := json.Unmarshal([]byte(e.Raw), &p) == nil
		if ok {
			// What was answered, never the line's own summary ("q-… by uid:1000 pid:…, not approved").
			r.Title = mask(p.Target)
			r.Text = cutMiddle(r.Title, 90)
		}
		switch {
		case !ok || p.Approved == nil:
			r.Class, r.Icon, r.Word = "neutral", "i-hand", "Answered"
		case *p.Approved:
			r.Class, r.Icon, r.Word = "allowed", "i-check", "Allowed"
		default:
			r.Class, r.Icon, r.Word = "refused", "i-ban", "Denied"
		}
	}
	return r
}

// answerChip is the verdict chip of a Logs row for an answer line, which has no verdict of its own: Denied, Allowed or
// Answered as "Around it" says it (ctxRowOf), never the grey "Recorded" of a line with no decision; the zero ctxRow
// for every other line.
func answerChip(e ledgerview.Event) ctxRow {
	if e.Kind != "answer" || e.Verdict != "" {
		return ctxRow{}
	}
	return ctxRowOf(e, "", "", "")
}

// maxHeadTarget is about how many characters of its object the headline shows; the title keeps the rest.
const maxHeadTarget = 80

// headOf is the headline of a line the plan p names an action for: the verb as the panel's plan reads it, and its
// object, a file path with the run's home shortened as Highlights shortens it, a destination as host:port, or a
// program's name. Nil when p names no action (the page then says "Line #N: <kind>").
func headOf(p *rules.ActPlan, home string) *headView {
	if p == nil || p.Kind == "" {
		return nil
	}
	h := &headView{Lead: "The agent "}
	switch {
	case p.Refused:
		h.Lead += "tried to " + p.Verb
	case p.Kind == "read":
		h.Lead += "read"
	case p.Kind == "write":
		h.Lead += "wrote to"
	case p.Kind == "exec":
		h.Lead += "ran"
	default:
		h.Lead += "connected to"
	}
	switch p.Kind {
	case "exec":
		prog := p.Program
		if prog == "" {
			prog = p.What
		}
		h.Title = mask(prog)
		h.Target = cutMiddle(path.Base(h.Title), maxHeadTarget)
	case "net":
		h.Title = mask(p.Dest)
		if h.Title == "" {
			h.Title = mask(p.What)
		}
		h.Target = cutMiddle(h.Title, maxHeadTarget)
	default:
		h.Title = mask(p.What)
		dir, base := splitPath(h.Title, home, maxHeadTarget*3/4)
		h.Target = cutMiddle(dir+base, maxHeadTarget)
	}
	if h.Target == "" || h.Target == "." {
		h.Target, h.Title = "", ""
	}
	return h
}

// actView is the "Act on this" panel: the scopes to pick from, the actions at the picked scope, the picked change.
type actView struct {
	Plan   *rules.ActPlan
	Scopes []scopeView
	Scope  rules.Scope
	// Never is set when an ask entry decided the line: Block is "Never allow" (the ask entry turned into a refusal at
	// its own folder), and the page opens on that folder.
	Never bool
	// Lead is the action the panel leads with: the picked one, else the first possible narrowing at the scope.
	Lead string
	// Wider is how many of Scopes are folded under step 1's "…/" chip (the folders far above the picked one), and
	// WiderOpen whether the fold opens on the picked scope.
	Wider     int
	WiderOpen bool
	// Actions are the possible actions at the picked scope, Lead first; Others the impossible ones with why, folded
	// under "Why not the others" (F12). Their Effect and Why name paths short, with the full words in their titles.
	Actions, Others []choiceView
	// Effect, Summary and Sentences are the picked change's, paths short; EffectTitle is Effect in full.
	Effect, Summary, EffectTitle string
	Sentences                    []sayView
	// PickErr is the plan's PickErr in short paths, for the preview's banner ("./vault/", as the rest of the
	// panel names it, not the absolute path).
	PickErr string
	// Now is "Also apply now", one checkbox per live run of the contract.
	Now []nowView
	// Live are what a Saved change's "Also apply now" did, each with its state on its run now (settleLive).
	Live []liveOut
	// Observe is a watched line's run (tego watch): Block now there marks, recorded only, and refuses nothing.
	Observe bool
	// CLI is the picked change's `tego rule` twin.
	CLI string
	// LiveKind and LiveValue are the Block now form's kind and value at the picked scope (F19), "" when the run is
	// not live, the line names nothing to block, or the picked change offers "Also apply now" on this run instead.
	LiveKind, LiveValue string
	// LiveShown is LiveValue in short paths, for the button (its title keeps the full value).
	LiveShown string
	// LiveNote says what Block now names when it is wider than the picked scope (a command: a live block names the
	// whole program).
	LiveNote string
	// Held is the live block of this run that already covers the line (heldLive), shown in place of Block now: after
	// an Undo that kept its live block, the panel says the block is still there instead of offering it again.
	Held *heldView
}

// heldView is a live block of the line's run that covers the line, with its state on the run now.
type heldView struct {
	// Block is the overlay key ("read:/p/vault"), Shown it in short paths.
	Block, Shown string
	// State is livestatus's word; Since the line that confirmed it in force, 0 when none has.
	State string
	Since uint64
}

// Liftable is the Saved change's live blocks an Undo may lift with it: each placed on a run that has
// not ended. The Undo form offers one box for them; the rule service lifts only those still in force then (lift.go).
func (v *actView) Liftable() []liveOut {
	var out []liveOut
	for _, o := range v.Live {
		if o.OK && o.State != ledgerview.LiveEnded {
			out = append(out, o)
		}
	}
	return out
}

// liveOut is one "Also apply now" outcome on the Saved panel, with what the block does to its run now
// (internal/check/livestatus over that run's record, as ledgerview.LiveFacts hands it): the launcher's confirming gap
// line arrives about half a second after the write, and the panel is the r-act live region, so the line moves from
// "Putting it in force…" to "Live now…, in force since line #N" over the page's live updates, with no reload.
type liveOut struct {
	rules.LiveResult
	This bool // the run of the line
	// Shown is Block in short paths, for the line (Block keeps the full value the overlay is keyed by).
	Shown string
	// State is livestatus's word ("" before settleLive); Before and After frame the run's name in the line ("Live now
	// on " this run ", in force since line #412"); Title is livestatus's sentence.
	State, Before, After, Title string
}

// Chip is the badge class the outcome's state wears on the Saved panel: in force (or partly, refusing changes) is the
// green of the Narrows chip beside it, so "Live now on this run" reads as done at a glance; "" for the states said as a
// plain line (being put in force, recorded only, ended).
func (o liveOut) Chip() string {
	if o.State == ledgerview.LiveInForce || o.State == ledgerview.LivePartial {
		return "b-narrows"
	}
	return ""
}

// Rest is the line after the chip: "in force since line #412", without the comma or colon that joins it to the run's
// name when the outcome is said as one line.
func (o liveOut) Rest() string { return strings.TrimLeft(o.After, ",: ") }

// nowView is one live run's "Also apply now" checkbox: the live blocks it places, or why none can be.
type nowView struct {
	Run  string
	This bool // the run of the line
	// Observe is a watched run: the block would be recorded on each matching line, not enforced.
	Observe bool
	Blocks  []string
	// Shown is Blocks in short paths, for the row; Title is them in full.
	Shown, Title string
	OK           bool
	Why          string
	// FenceLift is a widening inside the running Adjustable run's fence (rules.NowOption.FenceLift): no block is
	// placed, and the row links to the run's fence on the Rules page, where a lift gives it now.
	FenceLift bool
}

// scopeView is one scope chip: its words and whether it is the picked one.
type scopeView struct {
	Scope rules.Scope
	Text  string
	Mono  bool
	Title string
	// Says is what the picked chip names, in short paths (the title keeps the full one).
	Says    string
	Current bool
	// URL is the chip's link: the same line at this scope, on the picked action's step 3 when one is picked.
	URL string
	// Wider is a folder folded under step 1's "…/" chip.
	Wider bool
}

// sayView is one sentence of a change, its paths short as the panel writes them, with each side in full for its title
// ("" when the short words are the full ones).
type sayView struct {
	rules.Sentence
	BeforeTitle, AfterTitle string
}

// choiceView is one action at the picked scope, its Effect and Why in short paths, EffectTitle and WhyTitle in full.
type choiceView struct {
	rules.Choice
	EffectTitle, WhyTitle string
}

// lineCLI is the command that prints line seq of run exactly as written: `tego events --json` prints the stored lines
// byte for byte, one per line, and seq counts lines from 0, so line seq is line seq+1 of that output.
func lineCLI(run string, seq uint64) string {
	return "tego events " + run + " --json | sed -n '" + strconv.FormatUint(seq+1, 10) + "p'"
}

// lineRoute splits "/runs/<run>/lines/<seq>" into its run and seq.
func lineRoute(p string) (run string, seq uint64, ok bool) {
	rest, found := strings.CutPrefix(p, "/runs/")
	if !found {
		return "", 0, false
	}
	run, n, found := strings.Cut(rest, "/lines/")
	if !found || strings.Contains(n, "/") {
		return "", 0, false
	}
	seq, err := strconv.ParseUint(n, 10, 64)
	return run, seq, err == nil && run != ""
}

// scopeOf reads a scope from a query or form: level=<n>, cmd=1, host=1; given says the query named one, so the page
// does not move it to the deciding ask entry's folder.
func scopeOf(q url.Values) (sc rules.Scope, given bool) {
	sc = rules.Scope{Command: q.Get("cmd") == "1", Host: q.Get("host") == "1"}
	if n, err := strconv.Atoi(q.Get("level")); err == nil && n > 0 && n < 64 {
		sc.Level = n
	}
	return sc, q.Has("level") || q.Has("cmd") || q.Has("host")
}

// scopeKey and scopeVal are a scope's query parameter ("level" 2, "cmd" 1, "host" 1, and "level" 0 for the event's
// own target, so picking the file stays picked on a line that opens on its ask entry's folder). The template writes
// them as {{scopeKey .}}={{scopeVal .}}: one "key=value" string would have its "=" query-escaped in an href
// ("level%3d2"), and the chip it links would open on no scope at all.
func scopeKey(sc rules.Scope) string {
	switch {
	case sc.Command:
		return "cmd"
	case sc.Host:
		return "host"
	}
	return "level"
}

func scopeVal(sc rules.Scope) string {
	if sc.Command || sc.Host {
		return "1"
	}
	return strconv.Itoa(sc.Level)
}

// eventDetail serves GET (the details, the options, a preview, and a saved change's panel) and POST (the write, or an
// Undo) of /runs/<run>/lines/<seq>.
func (s *Server) eventDetail(w http.ResponseWriter, r *http.Request) {
	run, seq, ok := lineRoute(r.URL.Path)
	if !ok {
		s.fail(w, http.StatusNotFound, "No such line", "The address names no run line.")
		return
	}
	post := r.Method == http.MethodPost
	// postAllowed has checked the Origin or Referer, the form and the CSRF token; a rule write also wants the Origin
	// itself, as the Rule page does.
	if post && !s.sameOrigin(r) {
		s.fail(w, http.StatusForbidden, "Refused", "This form did not come from this dashboard's own page "+
			"(Origin check). Open the line again and confirm from there.")
		return
	}
	rr, err := ledgerview.LoadRun(s.cfg.Ledger, run)
	if errors.Is(err, os.ErrNotExist) {
		s.fail(w, http.StatusNotFound, "No such run", "No run "+run+" is in this ledger root.")
		return
	}
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "The run could not be read", err.Error())
		return
	}
	before, at, after, ok := ledgerview.Context(rr, seq, contextLines)
	if !ok {
		s.fail(w, http.StatusNotFound, "No such line", "Run "+run+" has no line #"+strconv.FormatUint(seq, 10)+".")
		return
	}
	if post {
		s.eventPost(w, r, rr, at)
		return
	}
	q := r.URL.Query()
	if q.Has("blob") {
		s.serveBlob(w, rr, at.Seq, q.Get("blob"))
		return
	}
	if q.Get("decided") == "1" && at.Kind == "ask" {
		// The Deny answer's "Make it permanent" link names the ask; the rule is made from the line that ask decided.
		if d := decidedBy(rr, &at); d != nil {
			http.Redirect(w, r, "/runs/"+url.PathEscape(run)+"/lines/"+strconv.FormatUint(d.Seq, 10)+"?a=block#act-check", http.StatusSeeOther)
			return
		}
	}
	snap, ok := s.load(w)
	if !ok {
		return
	}
	d := eventData{Run: rr, Ev: at, Before: before, After: after, CSRF: s.csrf}
	if len(before) > 0 {
		d.Prev = &before[len(before)-1]
	}
	if len(after) > 0 {
		d.Next = &after[0]
	}
	d.F = s.buildFacts(r.Context(), rr, &at)
	d.FullCommand, _ = ledgerview.BlobCommand(s.cfg.Ledger, run, at.Raw)
	d.CLI = lineCLI(run, seq)
	d.Label = ruleLabel(at, rulesview.RunLists(s.cfg.Ledger, run))
	if l, ok := blockLabels(rr)[at.Rule]; ok {
		d.Label = l
	}
	if v, ok := strings.CutPrefix(at.Rule, "exec.deny["); ok && d.Label == at.Rule {
		d.Label = "Denied command: " + strings.TrimSuffix(v, "]")
	}
	// The Rule row shows this label when the rule is not found (a profile rule, a gone rules file); it folds the run's
	// home and working directory as the row's other texts do (runText), not the owner's ~/…/with/home path.
	d.Label = runText(d.Label, ledgerview.RunHome(rr), rr.Cwd)
	switch at.Kind {
	case "fs", "exec", "net", "refused", "ask", "mcp":
		d.AgentText = true
	}
	if !rr.Start.IsZero() && !at.TS.Before(rr.Start) {
		d.Into = human(at.TS.Sub(rr.Start).Truncate(time.Millisecond))
	}
	d.Similar = ledgerview.FindSimilar(snap, &at)
	if at.Refused() && strings.HasPrefix(at.Rule, "fs.deny_read[") {
		d.Guard = d.Label
		if d.F.RuleFound && d.F.Rule.Sentence != "" {
			d.Guard = d.F.Rule.Sentence
		}
	}
	if as, isAct := s.cfg.Rules.(ActService); noActKinds[at.Kind] {
		d.NoAct = true
	} else if !isAct {
		d.ActErr = "Policy editing is off in this dashboard"
	} else {
		s.act(r.Context(), as, &d, q)
		if w := actErrWords(d.ActErr); w != d.ActErr {
			d.ActErr = "No rule can be made from this line: " + w + "."
		}
		if d.Act != nil && d.Act.Plan.Err != "" {
			d.Act.Plan.Err = actErrWords(d.Act.Plan.Err)
		}
	}
	if at.Kind == "ask" && q.Get("decided") == "1" && d.ActErr == "" && (d.Act == nil || d.Act.Plan.Err != "") {
		d.ActErr = "Not in the record yet · look again in a moment"
		d.Act = nil
	}
	if at.Kind == "ask" && d.Act != nil && d.Act.Plan.Err != "" {
		// A question is not an action: the rule is made from the line its answer let through or refused.
		d.Act, d.ActErr = nil, askActWords(d.F)
	}
	if d.Act != nil {
		home := ledgerview.RunHome(rr)
		if home == "" {
			home = d.Act.Plan.Home
		}
		d.Head = headOf(d.Act.Plan, home)
	}
	c := s.chromeOf(snap, "Line #"+strconv.FormatUint(seq, 10)+" · "+shortRun(run), "runs")
	c.Host, c.Ledger, c.CSRF, c.Preview = s.host, s.cfg.Ledger, s.csrf, s.cfg.Preview
	if fw, ok := w.(*flashWriter); ok {
		c.Flash = fw.flash
	}
	t, err := eventPage()
	if err != nil {
		http.Error(w, "tego-control serve: template event: "+err.Error(), http.StatusInternalServerError)
		return
	}
	renderPage(w, http.StatusOK, t, "event", page{chrome: c, Data: d})
}

// act fills the panel: a change saved here (?saved=<id>, the Saved panel with its Undo), else the options at the
// scope (the deciding ask entry's folder when the query names none) and, with an action, its preview.
func (s *Server) act(ctx context.Context, as ActService, d *eventData, q url.Values) {
	if v, ok := s.kept(q.Get("saved")).(savedAct); ok && v.run == d.Run.ID && v.seq == d.Ev.Seq {
		d.Act = actModel(v.plan, v.plan.Scope, d.Run, &d.Ev)
		s.settleLive(d.Act, d.Run)
		return
	}
	action := q.Get("a")
	if action != "block" && action != "ask" && action != "allow" {
		action = ""
	}
	sc, given := scopeOf(q)
	req := rules.ActReq{Run: d.Run.ID, Seq: d.Ev.Seq, Action: action, Scope: sc, Hint: lineHint(s.cfg.Ledger, d.Run.ID, d.Ev.Seq)}
	if !given {
		// Where the page opens: on a line an ask entry decided, that entry's folder, where Block moves the entry.
		p, err := as.ActOn(ctx, rules.ActReq{Run: req.Run, Seq: req.Seq, Hint: req.Hint})
		if err != nil {
			d.ActErr = err.Error()
			return
		}
		if p.EntryScope != nil {
			req.Scope = *p.EntryScope
		}
		if action == "" {
			d.Act = actModel(p, req.Scope, d.Run, &d.Ev)
			s.settleLive(d.Act, d.Run)
			return
		}
	}
	p, err := as.ActOn(ctx, req)
	if err != nil {
		d.ActErr = err.Error()
		return
	}
	d.Act = actModel(p, req.Scope, d.Run, &d.Ev)
	s.settleLive(d.Act, d.Run)
}

// settleLive says what each "Also apply now" outcome does to its run now, and whether the line's run is only
// watched: from each run's own record (ledgerview.LiveFacts: run_start's tier and reads, run_end, the launcher's
// confirming gap lines) and the overlay serial the placement returned. A placement whose serial is not known (0) is
// looked up in the run's overlay; one found nowhere is said as waiting, never as in force.
func (s *Server) settleLive(v *actView, rr *ledgerview.Run) {
	if v == nil {
		return
	}
	v.Observe = ledgerview.LiveFactsOf(rr).Observe
	s.heldLive(v, rr)
	for i := range v.Live {
		o := &v.Live[i]
		if !o.OK {
			continue
		}
		f := ledgerview.LiveFactsOf(rr)
		if !o.This {
			other, err := ledgerview.LoadRun(s.cfg.Ledger, o.Run)
			if err != nil {
				o.State, o.Before, o.After = ledgerview.LiveWaiting, "Placed on ", "; its state cannot be read now"
				continue
			}
			f = ledgerview.LiveFactsOf(other)
		}
		serial := o.Serial
		var e liveblock.Entry // the block as the overlay holds it now, with its time limit
		if lb, err := runact.Live(s.cfg.Ledger, o.Run); err == nil {
			if serial == 0 {
				serial = lb.Serials[o.Block]
			}
			e, _ = lb.Entry(o.Block)
		}
		if serial == 0 {
			serial = f.Confirmed + 1 // not in the overlay: never claimed in force
		}
		kind, _, _ := strings.Cut(o.Block, ":")
		o.State, o.Before, o.After, o.Title = liveOutWords(f.StatusAt(kind, serial, s.cfg.Now(), e.From, e.Until))
	}
}

// heldLive finds the live block of the line's run that already covers the line: a path, read or write block
// on the file or a folder above it (a read is not covered by a write block, nor a write by a read block), a block of
// the program by path or name, or of the destination or its host. When one is there, the panel shows it with its state
// and a link to remove it on the run page, in place of a Block now that would only place it again. A Saved panel
// already says what its own "Also apply now" placed, and a run that is not live has no blocks in force.
func (s *Server) heldLive(v *actView, rr *ledgerview.Run) {
	p := v.Plan
	if v.LiveKind == "" || p.Saved || !rr.Live {
		return
	}
	lb, err := runact.Live(s.cfg.Ledger, rr.ID)
	if err != nil || len(lb.Blocks) == 0 {
		return
	}
	covers := func(kind, value string) bool {
		switch p.Kind {
		case "read", "write":
			if kind != "path" && kind != p.Kind {
				return false
			}
			dir := strings.TrimSuffix(value, "/")
			return dir != "" && (p.What == dir || strings.HasPrefix(p.What, dir+"/"))
		case "exec":
			return kind == "exec" && (value == p.Program || value == path.Base(p.Program))
		case "net":
			return kind == "net" && (value == p.Dest || p.Host != "" && value == p.Host)
		}
		return false
	}
	now := s.cfg.Now()
	for _, b := range lb.Blocks {
		// A block past its time limit, or unblocked for a while, refuses nothing now (ADR 0125 decision 4): Block now
		// stays offered.
		if t := blockTimeOf(b, now); !covers(string(b.Kind), b.Value) || t.Ended || t.Dormant {
			continue
		}
		key := b.Key()
		st := ledgerview.LiveFactsOf(rr).StatusAt(string(b.Kind), lb.Serials[key], s.cfg.Now(), b.From, b.Until)
		switch st.State {
		case ledgerview.LiveEnded:
			return
		case ledgerview.LiveDormant, ledgerview.LiveExpired:
			continue // refuses nothing now by its time limit: the line is not held by it
		}
		sh := actShortener(p, rr)
		v.Held = &heldView{Block: key, Shown: sh.brief(b.Value), State: st.State, Since: st.Since}
		v.LiveKind, v.LiveValue, v.LiveShown, v.LiveNote = "", "", "", ""
		return
	}
}

// liveOutWords is an outcome's line around its run's name, by its state now.
func liveOutWords(st ledgerview.LiveStatus) (state, before, after, title string) {
	since := ""
	if st.Since > 0 {
		since = ", in force since line #" + strconv.FormatUint(st.Since, 10)
	}
	switch st.State {
	case ledgerview.LiveInForce:
		return st.State, "Live now on ", since, st.Sentence
	case ledgerview.LivePartial:
		return st.State, "Live now on ", since + ": changes are refused; this run's reads are not seen", st.Sentence
	case ledgerview.LiveWaiting:
		return st.State, "Putting it in force on ", "…", st.Sentence
	case ledgerview.LiveRecordedOnly:
		return st.State, "Recorded only on ", " (watched run): matching actions are recorded, not stopped", st.Sentence
	case ledgerview.LiveDormant:
		return st.State, "Unblocked for a while on ", ": it refuses nothing until its time limit ends", st.Sentence
	case ledgerview.LiveExpired:
		return st.State, "Ended by its time limit on ", ": it no longer refuses anything", st.Sentence
	}
	return st.State, "Ended with ", ": it no longer refuses anything", st.Sentence
}

// savedAct is a change the panel saved, kept for its Saved panel (Server.keep): the line it was made from and the
// service's plan of the write.
type savedAct struct {
	run  string
	seq  uint64
	plan *rules.ActPlan
}

// eventPost is the panel's POST: with undo=<journal id> an Undo of a change saved here, otherwise the write of the
// picked change on the base its preview showed (a=, the scope, base=, now=…, ack=<the preview's Ack> when ticked). It answers as every action
// does (flash.go): a 303 with one line, to the line's page with the Saved panel (?saved=<id>) after a write, back to
// the preview when nothing was written, and to the line's options after an Undo; or that line as JSON for live.js,
// which shows the same address in place, so the panel turns into Saved, Live now and Undo without a page load.
func (s *Server) eventPost(w http.ResponseWriter, r *http.Request, rr *ledgerview.Run, at ledgerview.Event) {
	page := "/runs/" + url.PathEscape(rr.ID) + "/lines/" + strconv.FormatUint(at.Seq, 10)
	as, ok := s.cfg.Rules.(ActService)
	if !ok {
		s.redirectBack(w, r, page+"#act", flash{Text: "Not done · policy editing is off in this dashboard"})
		return
	}
	f := r.PostForm
	if f.Get("undo") != "" {
		fl := undo(r.Context(), as, f)
		if fl.OK {
			fl.Here = page + "#act"
		}
		s.redirectBack(w, r, page+"#act", fl)
		return
	}
	action := f.Get("a")
	if action != "block" && action != "ask" && action != "allow" {
		s.redirectBack(w, r, page+"#act", flash{Text: "Not done · pick a change, then confirm"})
		return
	}
	sc, _ := scopeOf(f)
	// A write that saved nothing returns to the preview at its "Not saved: ..." line (#flash, the in-flow banner at
	// the top of the main column), not at the panel: without JavaScript #act and #act-check both scroll that line out
	// of view, so the person would not see why nothing was saved (TestNeverAllowInChrome measures it).
	// On a wide screen the sticky panel still shows the preview beside it. live.js posts inline and shows the same
	// line as a toast, so it never follows this address.
	preview := page + "?a=" + action + "&" + scopeKey(sc) + "=" + scopeVal(sc) + "#flash"
	p, err := as.ActOn(r.Context(), rules.ActReq{Run: rr.ID, Seq: at.Seq, Action: action, Scope: sc, Write: true,
		Base: f.Get("base"), AlsoNow: f["now"], Ack: f.Get("ack"), Hint: lineHint(s.cfg.Ledger, rr.ID, at.Seq)}) // a Write re-reads the line itself (ActReq.Hint)
	switch {
	case err != nil:
		s.redirectBack(w, r, page+"#act", flash{Text: "Not saved: " + plainErr(err) + "."})
	case p.Err != "":
		s.redirectBack(w, r, page+"#act", flash{Text: "Not saved: no rule can be made from this line: " + actErrWords(p.Err) + "."})
	case !p.Saved:
		s.redirectBack(w, r, preview, flash{Text: notSavedLine(p)})
	default:
		dest := page + "?saved=" + s.keep(savedAct{run: rr.ID, seq: at.Seq, plan: p}) + "#act"
		s.redirectBack(w, r, dest, flash{OK: true, Text: savedLine(p, rr.ID, actShortener(p, rr)), Here: dest})
	}
}

// savedLine is a change the panel saved, in one line: what the next run of the contract gets, and where "Also apply
// now" placed it. It never says "Live now" or "putting it in force": the launcher confirms a block about half a second
// after the write, the notice outlives that moment, and the Saved panel below says when it has (settleLive); a watched
// run only records it.
func savedLine(p *rules.ActPlan, run string, sh shortener) string {
	var after []string
	for _, sn := range p.Sentences {
		after = append(after, sh.brief(sn.After))
	}
	what := strings.Join(after, "; ")
	if what == "" {
		what = "it will " + sh.brief(p.Effect)
	}
	line := "Saved: " + what + ", from the next run of " + path.Base(p.Contract) + "."
	var here, other int
	watched := false
	for _, l := range p.Live {
		switch {
		case l.OK && l.Run == run:
			here++
			watched = l.Observe
		case l.OK:
			other++
		}
	}
	switch {
	case here > 0 && watched && other == 0:
		line += " Recorded only on this run, which is only watched."
	// No future claim: the notice stays on screen after the panel turns to Live now, so it points at the
	// panel, which follows each block's state over the page's live updates.
	case here > 0 && other > 0:
		line += " Its state on this run and on " + plural4(other, "other run", "other runs") + " is shown in the panel."
	case here > 0:
		line += " Its state on this run is shown in the panel."
	case other > 0:
		line += " Its state on " + plural4(other, "running run", "running runs") + " is shown in the panel."
	}
	return line
}

// notSavedLine is why a confirm wrote nothing, in one line; the page it returns to shows the change again on the
// file as it is now.
func notSavedLine(p *rules.ActPlan) string {
	switch {
	case p.Nothing:
		return "Nothing to save: " + p.PickErr
	case p.Stale:
		return "Not saved · the policy changed since you looked · check again and confirm"
	case p.AckMismatch:
		return "Not saved · the preview changed · tick the box and confirm again"
	case p.NeedsAck:
		return "Not saved · tick \"Next run may do more\" to confirm"
	}
	return "Not saved: " + p.PickErr
}

// undo is the Undo form of a saved change (undo=<journal id>, base=<the text it wrote>, ack=<its UndoAck> when ticked): the
// service's Revert, which refuses when the contract holds other text since. Undoing a narrowing widens, so the form
// says what comes back on its button and in a required checkbox; without the tick nothing is undone. It returns the
// line the page shows.
func undo(ctx context.Context, as ActService, q url.Values) flash {
	rv, err := as.Revert(ctx, rules.RevertReq{ID: q.Get("undo"), Base: q.Get("base"), Ack: q.Get("ack"), Lift: q.Get("lift") != ""})
	switch {
	case rv != nil:
		f := flash{OK: true, Text: undoneLine(rv)}
		if err != nil { // written, not journaled (rulefile.ErrJournal): the old text is back; the line says the journal missed it
			f.Text += " " + capFirst(plainErr(err)) + "."
		}
		return f
	case errors.Is(err, rules.ErrStale):
		return flash{Text: "Not undone · the policy changed since · edit it on the Policy page"}
	case errors.Is(err, rules.ErrAckMismatch):
		return flash{Text: "Not undone · this Undo is out of date · use History under Edit policy"}
	case errors.Is(err, rules.ErrNeedsAck):
		return flash{Text: "Not undone · tick \"Next run may do more\" to confirm"}
	}
	return flash{Text: "Nothing was undone: " + plainErr(err) + "."}
}

// undoneLine is an Undo done, in one line: what it undid, and where the undone text is kept.
func undoneLine(rv *rules.Reverted) string {
	line := "Undone: from its next run, " + path.Base(rv.Contract) + " has the rules it had before that change."
	if rv.Bak != "" {
		line += " The undone text is kept as " + path.Base(rv.Bak) + "."
	}
	if w := undoLiveLine(rv); w != "" {
		line += " " + w
	}
	return line
}

// decidedBy is the line the ask line a decided: a refusal after it that an ask ended in (a person said no, no answer
// came in time) under the same ask rule, or nil while none is in the run's ledger. The one that names the ask's own
// target wins; failing that, the first whose target is not another ask's of the run, so with two asks pending under
// one entry the link from one never opens the other's refusal. A target spelled differently on the two lines (a
// connection's "host (dst)") falls back to that first one.
func decidedBy(rr *ledgerview.Run, a *ledgerview.Event) *ledgerview.Event {
	want := a.AskTarget()
	evs := rr.AllEvents() // a run the cache evicted reads its lines again
	others := map[string]bool{}
	for i := range evs {
		if o := &evs[i]; o.Kind == "ask" && o.AskID != a.AskID && o.AskTarget() != "" && o.AskTarget() != want {
			others[o.AskTarget()] = true
		}
	}
	var first *ledgerview.Event
	for i := range evs {
		e := &evs[i]
		if e.Seq <= a.Seq || !e.Refused() || !strings.HasPrefix(e.Reason, "ask-") || a.Rule != "" && e.Rule != a.Rule {
			continue
		}
		if want != "" && e.Target == want {
			return e
		}
		if first == nil && !others[e.Target] {
			first = e
		}
	}
	return first
}

// actModel builds the panel from the service's plan: the scope chips of the line's kind, the actions at the picked
// scope, the preview in short paths, "Also apply now", the CLI twin and, for a live run, the Block now form.
func actModel(p *rules.ActPlan, sc rules.Scope, rr *ledgerview.Run, e *ledgerview.Event) *actView {
	v := &actView{Plan: p, Scope: sc, Never: p.EntryScope != nil}
	sh := actShortener(p, rr)
	switch p.Kind {
	case "read", "write":
		if sc.Level >= len(p.Levels) {
			v.Scope = rules.Scope{}
		}
		// The breadcrumb reads from the widest folder down to the file. The run's home is "~/" and its working
		// directory "./", the words the rest of the panel uses for them.
		for i := len(p.Levels) - 1; i >= 0; i-- {
			text := path.Base(p.Levels[i])
			switch {
			case i > 0 && p.Levels[i] == sh.home:
				text = "~"
			case i > 0 && p.Levels[i] == sh.cwd:
				text = "."
			}
			if i > 0 {
				text += "/"
			}
			title := "This file: " + p.Levels[i]
			if i > 0 {
				title = "Every file under " + p.Levels[i] + "/"
			}
			if p.EntryScope != nil && p.EntryScope.Level == i {
				title += " (the folder that asked)"
			}
			v.Scopes = append(v.Scopes, scopeView{Scope: rules.Scope{Level: i}, Text: text, Mono: true, Title: title})
		}
	case "exec":
		v.Scopes = append(v.Scopes, scopeView{Scope: rules.Scope{}, Text: "This program: " + path.Base(p.Program), Title: p.Program})
		if p.Command != "" {
			v.Scopes = append(v.Scopes, scopeView{Scope: rules.Scope{Command: true}, Text: "This command: " + p.Command,
				Title: "Only " + p.Command + ", however its options are spelled"})
		}
	case "net":
		v.Scopes = append(v.Scopes, scopeView{Scope: rules.Scope{}, Text: "This destination: " + p.Dest})
		if p.Host != "" {
			v.Scopes = append(v.Scopes, scopeView{Scope: rules.Scope{Host: true}, Text: "The whole host: " + p.Host,
				Title: "Every port of " + p.Host})
		}
	}
	if v.Scope.Command && p.Command == "" || v.Scope.Host && p.Host == "" {
		v.Scope = rules.Scope{}
	}
	line := "/runs/" + url.PathEscape(rr.ID) + "/lines/" + strconv.FormatUint(e.Seq, 10) + "?"
	for i := range v.Scopes {
		sv := &v.Scopes[i]
		sv.Current = sv.Scope == v.Scope
		sv.Says = sv.Text
		if sv.Title != "" {
			sv.Says = sh.brief(sv.Title)
		}
		sv.URL = line + scopeKey(sv.Scope) + "=" + scopeVal(sv.Scope) + "#act"
		if p.Action != "" {
			sv.URL = line + scopeKey(sv.Scope) + "=" + scopeVal(sv.Scope) + "&a=" + p.Action + "#act-check"
		}
	}
	v.foldWider(p)
	v.Lead = p.Action
	for _, c := range p.Choices {
		if c.Scope != v.Scope {
			continue
		}
		cv := choiceView{Choice: c, EffectTitle: sh.title(c.Effect), WhyTitle: sh.title(c.Why)}
		cv.Effect, cv.Why = sh.brief(c.Effect), sh.brief(c.Why)
		if !c.OK {
			v.Others = append(v.Others, cv)
			continue
		}
		if v.Lead == "" && c.Direction == "narrows" {
			v.Lead = c.Action
		}
		v.Actions = append(v.Actions, cv)
	}
	// The lead first; the rest keep the service's order (block, ask, allow).
	slices.SortStableFunc(v.Actions, func(a, b choiceView) int {
		switch {
		case a.Action == v.Lead && b.Action != v.Lead:
			return -1
		case b.Action == v.Lead && a.Action != v.Lead:
			return 1
		}
		return 0
	})
	v.Effect, v.Summary, v.PickErr = sh.brief(p.Effect), sh.brief(p.Summary), sh.brief(p.PickErr)
	v.EffectTitle = sh.title(p.Effect)
	for _, s := range p.Sentences {
		v.Sentences = append(v.Sentences, sayView{Sentence: rules.Sentence{Before: sh.brief(s.Before), After: sh.brief(s.After), Direction: s.Direction},
			BeforeTitle: sh.title(s.Before), AfterTitle: sh.title(s.After)})
	}
	offered := false
	for _, o := range p.Now {
		i := slices.IndexFunc(v.Now, func(n nowView) bool { return n.Run == o.Run })
		if i < 0 {
			v.Now = append(v.Now, nowView{Run: o.Run, This: o.Run == rr.ID})
			i = len(v.Now) - 1
		}
		n := &v.Now[i]
		n.Observe = n.Observe || o.Observe
		if o.OK {
			n.OK = true
			n.Blocks = append(n.Blocks, o.Block)
			n.Title = strings.Join(n.Blocks, ", ")
			n.Shown = sh.brief(n.Title)
			offered = offered || o.Run == rr.ID
		} else if n.Why == "" {
			n.Why, n.FenceLift = sh.brief(o.Why), o.FenceLift
		}
	}
	// A live run's own checkbox first, then the others newest first, as the service lists them.
	slices.SortStableFunc(v.Now, func(a, b nowView) int {
		switch {
		case a.This && !b.This:
			return -1
		case b.This && !a.This:
			return 1
		}
		return 0
	})
	for _, l := range p.Live {
		l.Err = sh.brief(l.Err)
		v.Live = append(v.Live, liveOut{LiveResult: l, This: l.Run == rr.ID, Shown: sh.brief(l.Block)})
	}
	if p.Action != "" {
		v.CLI = "tego rule " + rr.ID + " " + strconv.FormatUint(e.Seq, 10) + " --" + p.Action
		switch {
		case v.Scope.Command:
			v.CLI += " --command"
		case v.Scope.Host:
			v.CLI += " --host"
		case v.Scope.Level == 1:
			v.CLI += " --folder"
		case v.Scope.Level > 1:
			v.CLI += " --level " + strconv.Itoa(v.Scope.Level)
		}
	}
	if rr.Live && !(offered && !p.Saved) {
		switch p.Kind {
		case "exec":
			v.LiveKind, v.LiveValue = "exec", p.Program
			if v.Scope.Command {
				v.LiveNote = "A live block names a whole program, so this blocks every " + path.Base(p.Program) + " command, not only " + p.Command + "."
			}
		case "net":
			v.LiveKind, v.LiveValue = "net", p.Dest
			if v.Scope.Host && p.Host != "" {
				v.LiveValue = p.Host // a host without a port: every port (liveblock)
			}
		case "read", "write":
			v.LiveKind, v.LiveValue = "path", p.What
			if v.Scope.Level > 0 && v.Scope.Level < len(p.Levels) {
				v.LiveValue = p.Levels[v.Scope.Level]
			}
		}
		v.LiveShown = sh.brief(v.LiveValue)
		// Saved with "Also apply now" having placed this block on this run (or, for a program, the block of its name,
		// which refuses it under any path: liveblock): Block now would only say it again.
		same := []string{v.LiveKind + ":" + v.LiveValue}
		switch v.LiveKind {
		case "exec":
			same = append(same, "exec:"+path.Base(v.LiveValue))
		case "path":
			// A read or write block "Also apply now" placed on the same path: the narrowing is already live there.
			same = append(same, "read:"+v.LiveValue, "write:"+v.LiveValue)
		}
		for _, l := range p.Live {
			if p.Saved && l.OK && l.Run == rr.ID && slices.Contains(same, l.Block) {
				v.LiveKind, v.LiveValue, v.LiveShown, v.LiveNote = "", "", "", ""
				break
			}
		}
	}
	return v
}

// shortener writes absolute paths under the run's working directory as ./… and under the home as ~/…, so the
// panel's options and sentences read in the words the contract uses instead of repeating /home/… (F12). The full
// text stays in the line's own facts and the diff.
type shortener struct{ cwd, home string }

// actShortener is the Act panel's shortener: "~/" is the run's own home (ledgerview.RunHome), as the line page's
// headline, Highlights and Logs write it, so the panel says ~/.config/telemetry/ where the headline does instead of
// the same folder from the dashboard user's home; one "~" on the page, never two. Plan.Home (the user's) is the
// fallback for a run whose home cannot be told. Display only: the contract's text, the diff and the CLI keep full
// paths, and brief's words carry them in their titles.
func actShortener(p *rules.ActPlan, rr *ledgerview.Run) shortener {
	sh := shortener{cwd: p.Cwd, home: p.Home}
	if h := ledgerview.RunHome(rr); h != "" {
		sh.home = h
	}
	return sh
}

// brief is text, with each absolute path still longer than maxBrief characters (one outside the working directory
// and the home) cut in its folder's middle, as the path shortener cuts a cell: "/home/…/stage/with/x.yaml". The
// panel puts the full words in the title (title).
func (sh shortener) brief(s string) string {
	s = sh.text(s)
	var b strings.Builder
	for {
		i := pathStart(s)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		j := i + strings.IndexAny(s[i:]+" ", " \t\n,;()]") // a rule key's path ends at its "]"
		b.WriteString(s[:i])
		p := s[i:j]
		if len(p) > maxBrief {
			slash := strings.HasSuffix(p, "/")
			dir, base := path.Split(strings.TrimSuffix(p, "/"))
			p = elideDir(dir, maxBrief-len(base)) + base
			if slash {
				p += "/"
			}
		}
		b.WriteString(p)
		s = s[j:]
	}
}

// title is s in full for a title attribute when brief shortens it, "" when the short words are the full ones.
func (sh shortener) title(s string) string {
	if sh.brief(s) == s {
		return ""
	}
	return s
}

// pathPieces is s for the "pwp" template with a line break allowed only between the folders of a long path (a word
// of more than softAt characters with a "/" in it), each hyphenated folder name kept whole: the Act card wraps
// "~/.cache/tego-workdir/…" at a "/", never inside a name ("con fig/", "tego- workdir/"). Prose, and a path short
// enough to move to the next line whole, are left as they are.
func pathPieces(s string) []piece {
	var out []piece
	plain := func(t string) {
		if n := len(out); n > 0 && !out[n-1].Br && !out[n-1].Keep && !strings.HasSuffix(out[n-1].Text, "/") {
			out[n-1].Text += t
			return
		}
		out = append(out, piece{Text: t})
	}
	for _, w := range strings.SplitAfter(s, " ") {
		word := strings.TrimSuffix(w, " ")
		if len(word) <= softAt || !strings.Contains(word, "/") {
			plain(w)
			continue
		}
		segs := strings.SplitAfter(word, "/")
		for i, seg := range segs {
			if seg == "" {
				continue
			}
			if i == len(segs)-1 || (i == len(segs)-2 && segs[len(segs)-1] == "") {
				seg += w[len(word):] // the space after the word stays with its last folder
			}
			out = append(out, piece{Text: seg, Br: i > 0, Keep: strings.Contains(seg, "-") && len(seg) <= keepMax})
		}
	}
	return out
}

// softAt is the longest path pathPieces leaves whole.
const softAt = 24

// maxBrief is about how many characters of an absolute path brief keeps: the Act card's width at 1440 px.
const maxBrief = 48

// pathStart is the index of the first absolute path in s (a "/" at the start, or after a space, "(", "[" or ":"
// as in read:/p), -1 for none.
func pathStart(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] != '/' || i+1 >= len(s) || s[i+1] == ' ' {
			continue
		}
		if i == 0 || strings.IndexByte(" ([:", s[i-1]) >= 0 {
			return i
		}
	}
	return -1
}

// foldWider folds step 1's breadcrumb: the folders more than two above the picked one (or the folder that asked)
// go behind one "…/" chip when that hides two or more, so the row reads ~/ .config/ telemetry/ token instead of a
// chip for every folder from /home down. A picked folded folder opens the fold.
func (v *actView) foldWider(p *rules.ActPlan) {
	if p.Kind != "read" && p.Kind != "write" {
		return
	}
	keep := v.Scope.Level
	if p.EntryScope != nil {
		keep = max(keep, p.EntryScope.Level)
	}
	keep += 2
	if len(p.Levels)-1-keep < 2 {
		return
	}
	for i := range v.Scopes {
		sv := &v.Scopes[i]
		if sv.Scope.Level > keep {
			sv.Wider = true
			v.Wider++
			v.WiderOpen = v.WiderOpen || sv.Current
		}
	}
}

func (sh shortener) text(s string) string {
	roots := []struct{ dir, as string }{{sh.cwd, "."}, {sh.home, "~"}}
	if len(sh.home) > len(sh.cwd) {
		roots[0], roots[1] = roots[1], roots[0] // the longer, inner one first
	}
	for _, r := range roots {
		if r.dir == "" || r.dir == "/" {
			continue
		}
		s = strings.ReplaceAll(s, r.dir+"/", r.as+"/")
	}
	return s
}
