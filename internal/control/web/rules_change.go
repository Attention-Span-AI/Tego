// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/liveblock"
)

// The Change rules pages, every one served through the rule service (Config.Rules,
// internal/control/rules), which holds every guard; this file makes no decision of its own:
//
//   - GET /rules/change?c=<ref>: one panel per list a change may touch, with Add (a hint per kind) and Remove on every
//     entry the file spells (Never allow too on an ask entry), each a small GET form to the preview; the history of
//     the file's changes with Undo; and "Advanced: edit YAML", a free edit of the whole text.
//   - GET /rules/change/preview?c&base&op&key&v: the change in sentences, Narrows or Widens, "Applies from the next
//     run", "Also apply now" per running run, the YAML diff and the terminal twin. It writes nothing.
//   - POST /rules/change (csrf, c, base, op, key, v, now…, ack; or mode=raw with text, step=check|save and ack): the
//     write, answered as every action is (flash.go): 303 to the Saved page with one line, or that line as JSON for
//     live.js, which opens the Saved page with it in a toast. A refusal goes back to the form with the line saying
//     why. A free edit's Check answers its page (the text it checked is too long for an address, and checking
//     changes nothing).
//   - GET /rules/change/saved?c&id: the Saved page of a change written or undone (sentences, diff, live outcomes, the
//     .bak, Undo), from what the write kept (Server.keep), for keptTTL; then Change rules itself.
//   - POST /rules/revert (csrf, c, id, base, ack): Undo from the journal, answered as a write is.
//
// The ack of a write that is not a narrowing is the Ack of the preview it confirms (rules ack.go), which the
// checkbox posts as its value: the service writes nothing when it is not that change's.
//
// A browser names a contract by its opaque ref only (rules.ContractRef.Ref); a path in a request names nothing. The
// pages work without JavaScript. Their live regions (the lists and history of Change rules, the whole Saved page)
// update in place with the layout's; the YAML editor sits outside them, so a live update never touches its text.

// changeBuilt says whether the Change rules form exists: the Rules page's Change rules button links to it.
const changeBuilt = true

// ChangeService is the rule service as the Change rules pages ask it (internal/control/rules.Service).
type ChangeService interface {
	Contracts() ([]rules.ContractRef, error)
	Current(ref string) (*rules.Current, error)
	PlanChange(ctx context.Context, req rules.ChangeReq) (*rules.ChangePlan, error)
	ApplyChange(ctx context.Context, req rules.ChangeReq) (*rules.Applied, error)
	PlanRaw(ctx context.Context, req rules.RawReq) (*rules.ChangePlan, error)
	ApplyRaw(ctx context.Context, req rules.RawReq) (*rules.Applied, error)
	History(ref string) ([]rules.HistoryEntry, error)
	Revert(ctx context.Context, req rules.RevertReq) (*rules.Reverted, error)
}

// maxRawForm bounds the body of POST /rules/change: a free edit carries a whole contract (agent.MaxContractSize, 1
// MiB), which form encoding can triple.
const maxRawForm = 3<<20 + maxForm

// widens is the direction word of a widening (rules.ChangePlan.Direction): undoing anything else asks for the
// acknowledgement, since undoing a narrowing widens and a mixed change or a free edit cannot be classified.
const widens = "widens"

// maxHistory is how many journal entries a page lists.
const maxHistory = 20

// groupMeta is one list a change may touch, as the form shows it: the panel's title, a sentence under it, and the
// hint and example of its Add input.
type groupMeta struct {
	Key, Title, Lede, Hint, Example, Icon string
	// Ask marks an ask list: its entries also offer Never allow (an edit with op never).
	Ask bool
}

// changeGroups is every list rules.EditKeys names, in the Rules page's order (read, change, ask, never, programs,
// network). TestChangeGroupsCoverEditKeys holds it to rules.EditKeys.
var changeGroups = []groupMeta{
	{Key: "fs.write", Title: "Can change", Lede: "files and folders it may write", Icon: "i-scroll-text",
		Hint: "File, or folder ending in / · ./out/, ~/notes/ or absolute", Example: "./out/"},
	{Key: "fs.ask", Title: "Asks you before it changes", Lede: "a write here waits for your answer", Icon: "i-hand", Ask: true,
		Hint: "File or folder ending in /, inside what it may change", Example: "./held/"},
	{Key: "fs.ask_read", Title: "Asks you before it reads", Lede: "a read here waits for your answer", Icon: "i-hand", Ask: true,
		Hint: "File or folder ending in /", Example: "~/.config/telemetry/"},
	{Key: "fs.deny_read", Title: "Can never read", Lede: "on top of the built-in secret list", Icon: "i-ban",
		Hint: "A file or a folder ending in /: ./secrets/, ~/.aws/.", Example: "./secrets/"},
	{Key: "fs.deny_write", Title: "Can never change", Lede: "even inside what it may change", Icon: "i-ban",
		Hint: "File or folder ending in /, inside what it may change", Example: "./.git/"},
	{Key: "exec.allow", Title: "Programs it may run", Lede: "every other program is refused", Icon: "i-terminal",
		Hint: "git, /usr/bin/git, or git status", Example: "git"},
	{Key: "net.allow", Title: "Can connect to", Lede: "every other destination is refused", Icon: "i-activity",
		Hint: "host:port, such as api.github.com:443.", Example: "api.github.com:443"},
	{Key: "net.ask", Title: "Asks you before it connects to", Lede: "a connection here waits for your answer", Icon: "i-hand", Ask: true,
		Hint: "host:port, such as pypi.org:443.", Example: "pypi.org:443"},
}

// changeGroup is one panel of the form: its list's entries.
type changeGroup struct {
	groupMeta
	Entries []string
	// Absent says the file has no such list.
	Absent bool
}

// histView is the history list and what its Undo forms carry.
type histView struct {
	CSRF, Ref, Base string
	Rows            []historyRow
}

// historyRow is one journal entry as a page lists it, with its Undo when the contract still holds its text.
type historyRow struct {
	rules.HistoryEntry
	// CanUndo: the entry stands and the contract holds its text; UndoAck: undoing it is not a narrowing, so the form
	// asks for the acknowledgement.
	CanUndo, UndoAck bool
	// Lift is the live blocks the entry placed that its Undo can lift with it (undolive.go), with CanUndo.
	Lift []liftOut
}

// rawView is the advanced editor's state.
type rawView struct {
	// Open shows the editor open (it was asked for, or a form of it was posted).
	Open bool
	Text string
	// Plan is the Check's result; Diags are its compile diagnostics, Lines the text around the lines they name.
	Plan  *rules.ChangePlan
	Diags []diagLine
	Lines []numLine
	// Err is why the editor's form was refused (stale, unacknowledged, not compiling, env values).
	Err string
	// Now is the checked text's "Also apply now": its narrowing list changes that map to a live block on a running
	// run, and every other change with why it waits for the next run.
	Now []nowRun
}

// diagLine is one line of a compile diagnostic and the contract line it names (0: none).
type diagLine struct {
	Line int
	Text string
}

// numLine is one line of the edited text with its number; Bad marks a line a diagnostic names, Gap a skipped stretch.
type numLine struct {
	N        int
	Text     string
	Bad, Gap bool
}

// changeData is the Change rules page's data.
type changeData struct {
	Contracts []rules.ContractRef
	// C is the contract shown; nil on the chooser.
	C *rules.ContractRef
	// NotWritable says why the dashboard may not change it.
	NotWritable string
	Groups      []changeGroup
	ListsErr    string
	Hist        histView
	HistoryErr  string
	// CanRaw: the advanced editor is offered; RawWhy says why not otherwise. Text is the contract's text for it, with
	// every env.set value as rulesview.Hidden when EnvHidden (the service puts them back on save).
	CanRaw    bool
	RawWhy    string
	Text      string
	EnvHidden bool
	Raw       *rawView
	// Hint is the terminal twin: compile the file.
	Hint string
}

// nowRun is one running run "Also apply now" can reach, with the live blocks the change maps to on it.
type nowRun struct {
	Run    string
	OK     bool
	Blocks []nowBlock
	// Observe is a watched run: what it gets now is recorded, not enforced.
	Observe bool
}

// nowBlock is one "Also apply now" option with its live block in words (liveWords), the raw key kept for a title.
type nowBlock struct {
	rules.NowOption
	Words string
}

// nowRuns groups a plan's "Also apply now" options by run, in the service's order (the "nowrows" template).
func nowRuns(opts []rules.NowOption) []nowRun {
	var out []nowRun
	home := homeDir()
	for _, o := range opts {
		i := slices.IndexFunc(out, func(n nowRun) bool { return n.Run == o.Run })
		if i < 0 {
			out = append(out, nowRun{Run: o.Run})
			i = len(out) - 1
		}
		out[i].Blocks = append(out[i].Blocks, nowBlock{NowOption: o, Words: liveWords(o.Block, shortener{cwd: o.Cwd, home: home})})
		out[i].OK = out[i].OK || o.OK
		out[i].Observe = out[i].Observe || o.Observe
	}
	return out
}

// previewData is the preview's data, and the confirm's again when the service refused it.
type previewData struct {
	P    *rules.ChangePlan
	Edit rules.Edit
	Now  []nowRun
	// After is the change's After sentences, which the widening box and its checkbox name.
	After string
	// NowOn names the running runs whose "Also apply now" box is offered ("r-…qfjbjv", or "2 running runs"), for the
	// sentence that says when the change holds; "" when none is. NowRecorded: every one of them is only watched.
	NowOn       string
	NowRecorded bool
	// CLINote says the edit by hand; CLI are the commands that check it and apply it now.
	CLINote string
	CLI     []string
}

// savedData is the Saved page: a change written or undone, and Undo of it.
type savedData struct {
	Ref, Contract, Agent string
	Applied              *rules.Applied
	Reverted             *rules.Reverted
	// Base is the text's sha256 now, which Undo carries; UndoID the journal entry it undoes ("" offers none).
	Base, UndoID string
	UndoAck      bool
	// UndoAckValue is the acknowledgement Undo's checkbox posts (rules.HistoryEntry.Ack of UndoID).
	UndoAckValue string
	// UndoWords is what the next run can do again once the change is undone.
	UndoWords string
	// UndoLift is the live blocks the change placed that Undo can lift with it (undolive.go); UndoLive, on an undo
	// written, what became of the blocks the undone change had placed (undoLiveLine).
	UndoLift []liftOut
	UndoLive string
	Hist     histView
	CLI      []string
	// Warn is what went wrong after a write (the journal line, the live blocks).
	Warn string

	// Headline, Live and Next are a written change's state on its running runs now, worked out on every render
	// (settleSaved), so the page's live region turns "Putting it in force" into "Live now" with no reload.
	Headline string
	Live     []savedOut
	Next     []savedNext
}

// savedOut is one "Also apply now" outcome on the Saved page with its state on its run now: Chip and Class are the
// state's badge, Before and After frame the run's name in the line, Words the block in words.
type savedOut struct {
	rules.LiveResult
	State, Chip, Class, Before, After, Title, Words string
}

// savedNext is one list change that waits for the next run on a running run: no live block applies it, or Also apply
// now was not ticked for that run.
type savedNext struct {
	Run, Change, Why string
	// FenceLift is a widening inside the running Adjustable run's fence (rules.NowOption.FenceLift): the row links to
	// the run's fence on the Rules page, where a lift gives it now.
	FenceLift bool
}

// changeService is the rule service as ChangeService, or the page that says the dashboard has none.
func (s *Server) changeService(w http.ResponseWriter) (ChangeService, bool) {
	svc, ok := s.cfg.Rules.(ChangeService)
	if !ok {
		s.fail(w, http.StatusNotFound, "Edit policy", "Policy editing is off here · start it with tego-control serve, or use tego rule <run> <line>")
	}
	return svc, ok
}

// changeChrome is the chrome of every Change rules page: the Rules tab. The pages are live like every other; a live
// update never reloads them and leaves a form someone is filling in as it is (static/live.js).
func (s *Server) changeChrome(w http.ResponseWriter, title string) (chrome, bool) {
	snap, ok := s.load(w)
	if !ok {
		return chrome{}, false
	}
	return s.chromeOf(snap, title, "rules"), true
}

// serviceFail answers an error of the rule service that no page can recover from.
func (s *Server) serviceFail(w http.ResponseWriter, heading string, err error) {
	switch {
	case errors.Is(err, rules.ErrNoContract):
		s.fail(w, http.StatusNotFound, "No such policy file", "No run used that policy file · pick one on the Policy page")
	case errors.Is(err, rules.ErrNotWritable):
		s.fail(w, http.StatusForbidden, heading, err.Error())
	default:
		s.fail(w, http.StatusInternalServerError, heading, err.Error())
	}
}

// rulesChange serves GET /rules/change and /rules/change/preview.
func (s *Server) rulesChange(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.changeService(w)
	if !ok {
		return
	}
	switch r.URL.Path {
	case "/rules/change/preview":
		s.rulesPreview(w, r, svc)
		return
	case "/rules/change/saved":
		s.rulesSaved(w, r, svc)
		return
	}
	s.changePage(w, r, svc, r.URL.Query().Get("c"))
}

// changePage is Change rules for the contract ref, or the chooser when ref is "".
func (s *Server) changePage(w http.ResponseWriter, r *http.Request, svc ChangeService, ref string) {
	refs, err := svc.Contracts()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "Change rules", "The runs of this ledger could not be read: "+err.Error())
		return
	}
	if isLegacyRef(ref) { // an old link's ref (legacyRef): the same file, named by the service's ref from here on
		for _, c := range refs {
			if legacyRef(c.Path) == ref {
				http.Redirect(w, r, "/rules/change?c="+url.QueryEscape(c.Ref), http.StatusSeeOther)
				return
			}
		}
	}
	d := changeData{Contracts: refs}
	if ref != "" {
		i := slices.IndexFunc(refs, func(c rules.ContractRef) bool { return c.Ref == ref })
		if i < 0 {
			s.serviceFail(w, "Change rules", rules.ErrNoContract)
			return
		}
		d.C = &refs[i]
		if !s.fillChange(w, svc, &d) {
			return
		}
		if r.URL.Query().Get("raw") == "1" && d.CanRaw {
			d.Raw = &rawView{Open: true, Text: d.Text}
		}
	}
	title := "Change rules"
	if d.C != nil {
		title += " · " + d.C.Agent
	}
	c, ok := s.changeChrome(w, title)
	if ok {
		s.render(w, http.StatusOK, "rules-change", c, d)
	}
}

// fillChange reads d.C's text, lists and history into d; false when it has answered.
func (s *Server) fillChange(w http.ResponseWriter, svc ChangeService, d *changeData) bool {
	d.Hint = "tego compile " + shellWord(d.C.Path)
	if !d.C.Writable {
		d.NotWritable = d.C.Why
		return true
	}
	cur, err := svc.Current(d.C.Ref)
	switch {
	case errors.Is(err, rules.ErrNotWritable):
		d.NotWritable = err.Error()
		return true
	case err != nil:
		s.serviceFail(w, "Change rules", err)
		return false
	}
	d.C.Base, d.ListsErr = cur.Base, cur.ListsErr
	for _, g := range changeGroups {
		es, has := cur.Lists[g.Key]
		d.Groups = append(d.Groups, changeGroup{groupMeta: g, Entries: es, Absent: !has})
	}
	d.CanRaw, d.EnvHidden = cur.Editor != nil, cur.Editor != nil && cur.EnvSet
	if d.CanRaw {
		d.Text = string(cur.Editor)
	} else {
		d.RawWhy = cur.EditorWhy + ": " + d.Hint
	}
	d.Hist = histView{CSRF: s.csrf, Ref: d.C.Ref, Base: cur.Base}
	d.Hist.Rows, d.HistoryErr = historyOf(svc, d.C.Ref, cur.Base)
	return true
}

// historyOf is the newest journal entries of the contract ref, with Undo on the one the text at base holds.
func historyOf(svc ChangeService, ref, base string) ([]historyRow, string) {
	hs, err := svc.History(ref)
	if err != nil {
		return nil, "The change record could not be read: " + err.Error()
	}
	out := make([]historyRow, 0, min(len(hs), maxHistory))
	for i, h := range hs {
		if i == maxHistory {
			break
		}
		row := historyRow{HistoryEntry: h, UndoAck: h.Direction != widens}
		row.CanUndo = h.Current && h.UndoneBy == "" && base != ""
		if row.CanUndo && row.UndoAck {
			row.Lift = liftOuts(h.Lift)
		}
		out = append(out, row)
	}
	return out, ""
}

// editOf is the one edit a preview or confirm names (op, key, v), or why it names none.
func editOf(v url.Values) (rules.Edit, string) {
	e := rules.Edit{Op: v.Get("op"), Key: v.Get("key"), Entry: v.Get("v")}
	if e.Op == "add" {
		e.Entry = strings.TrimSpace(e.Entry)
	}
	switch {
	case e.Op != "add" && e.Op != "remove" && e.Op != "never":
		return e, "Add, remove, or turn an ask into Never allow"
	case !slices.Contains(rules.EditKeys(), e.Key):
		return e, "Change one of the lists on Edit policy"
	case e.Entry == "":
		return e, "Type the entry to add: " + hintOf(e.Key)
	case len(e.Entry) > rules.MaxEntry:
		return e, fmt.Sprintf("An entry is at most %d bytes.", rules.MaxEntry)
	}
	return e, ""
}

// hintOf is the Add hint of the list key.
func hintOf(key string) string {
	for _, g := range changeGroups {
		if g.Key == key {
			return g.Hint
		}
	}
	return ""
}

// rulesPreview serves GET /rules/change/preview: the change planned, nothing written.
func (s *Server) rulesPreview(w http.ResponseWriter, r *http.Request, svc ChangeService) {
	q := r.URL.Query()
	e, why := editOf(q)
	if why != "" {
		s.fail(w, http.StatusBadRequest, "Not a change", why)
		return
	}
	req := rules.ChangeReq{Ref: q.Get("c"), Base: q.Get("base"), Edits: []rules.Edit{e}}
	p, err := svc.PlanChange(r.Context(), req)
	if err != nil {
		s.serviceFail(w, "Check the change", err)
		return
	}
	s.renderPreview(w, http.StatusOK, previewOf(p, e))
}

// previewOf is the preview's data for the plan p of the edit e.
func previewOf(p *rules.ChangePlan, e rules.Edit) previewData {
	d := previewData{P: p, Edit: e}
	var after []string
	for _, sn := range p.Sentences {
		after = append(after, sn.After)
	}
	d.After = strings.Join(after, "; ")
	d.Now = nowRuns(p.Now)
	var on []string
	d.NowRecorded = true
	for _, n := range d.Now {
		if n.OK {
			on = append(on, n.Run)
			d.NowRecorded = d.NowRecorded && n.Observe
		}
	}
	switch len(on) {
	case 0:
		d.NowRecorded = false
	case 1:
		d.NowOn = shortRun(on[0])
	default:
		d.NowOn = plural4(len(on), "running run", "running runs")
	}
	d.CLINote, d.CLI = changeCLI(p.Contract, e, p.Now)
	return d
}

// changeCLI is the terminal twin of the edit e of the contract at path: the edit by hand in words, then the compile
// that checks it and `tego block` for each live block "Also apply now" offers.
func changeCLI(path string, e rules.Edit, now []rules.NowOption) (string, []string) {
	var what string
	switch e.Op {
	case "add":
		what = "add " + strconv.Quote(e.Entry) + " to " + e.Key
	case "remove":
		what = "remove " + strconv.Quote(e.Entry) + " from " + e.Key
	default:
		what = "remove " + strconv.Quote(e.Entry) + " from " + e.Key + " (and refuse it instead)"
	}
	out := []string{"tego compile " + shellWord(path)}
	for _, o := range now {
		if o.OK {
			out = append(out, "tego block "+o.Run+" "+changeWords(o.Kind, o.Value, ""))
		}
	}
	return "By hand: in " + path + ", " + what + ", then check it", out
}

func (s *Server) renderPreview(w http.ResponseWriter, status int, d previewData) {
	c, ok := s.changeChrome(w, "Check the change · "+d.P.Agent)
	if ok {
		s.render(w, status, "rules-preview", c, d)
	}
}

// refusal is the status and sentence of a confirm the service refused that the page can say and show again.
func refusal(err error) (int, string, bool) {
	switch {
	case errors.Is(err, rules.ErrStale):
		return http.StatusConflict, "Not saved · the policy changed since you looked · check again and save", true
	case errors.Is(err, rules.ErrAckMismatch):
		return http.StatusBadRequest, "Not saved · the preview changed · tick the box and save", true
	case errors.Is(err, rules.ErrNeedsAck):
		return http.StatusBadRequest, "Not saved · tick \"Next run may do more\" and save", true
	case errors.Is(err, rules.ErrRefused):
		return http.StatusUnprocessableEntity, "Nothing was written: " + strings.TrimPrefix(err.Error(), rules.ErrRefused.Error()+": "), true
	}
	return 0, "", false
}

// rulesChangePost serves POST /rules/change, which postAllowed has passed: a structured change, or with mode=raw a
// free edit's Check or Save.
func (s *Server) rulesChangePost(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.changeService(w)
	if !ok {
		return
	}
	f := r.PostForm
	if f.Get("do") == "applynow" {
		s.applyNowPost(w, r) // the Rules page's Apply now (rules_pending.go)
		return
	}
	if f.Get("mode") == "raw" {
		s.rawPost(w, r, svc)
		return
	}
	e, why := editOf(f)
	if why != "" {
		s.fail(w, http.StatusBadRequest, "Not a change", why)
		return
	}
	req := rules.ChangeReq{Ref: f.Get("c"), Base: f.Get("base"), Edits: []rules.Edit{e}, AlsoNow: f["now"], Ack: f.Get("ack")}
	a, err := svc.ApplyChange(r.Context(), req)
	if err != nil {
		_, text, again := refusal(err)
		if !again {
			s.serviceFail(w, "Change rules", err)
			return
		}
		// Back to the preview, which plans the edit again on the file as it is now. The address carries no base: the
		// preview reads the file's own (ChangePlan.Base), so its form carries the base and the ack of that new plan and
		// the next Save can land. With the refused, stale base the preview would plan on the file now but say so in a
		// second banner, and every later Save from a page still holding the old base was refused again.
		q := url.Values{"c": {req.Ref}, "op": {e.Op}, "key": {e.Key}, "v": {e.Entry}}
		if errors.Is(err, rules.ErrStale) {
			text = staleText(r.Context(), svc, req, e, text)
		}
		s.redirectBack(w, r, "/rules/change/preview?"+q.Encode(), flash{Text: text})
		return
	}
	d := savedData{Ref: a.Plan.Ref, Contract: a.Plan.Contract, Agent: a.Plan.Agent, Applied: a, UndoID: a.ID, Warn: a.Warn,
		CLI: []string{"tego compile " + shellWord(a.Plan.Contract)}}
	d.UndoAck, d.UndoWords = a.Plan.Direction != widens, beforeWords(a.Plan.Sentences)
	s.savedAnswer(w, r, d, appliedLine(a))
}

// staleText is what a Save refused as stale says: text, or, when the edit cannot be made again because the file as it
// is now already has it, that nothing more was needed, so the person does not save it again. That is the second POST
// of a double click (the first one wrote it from the same base) or the same edit made by hand: the edit planned on
// the file now has nothing to do, or cannot be made and the change the file holds now (the journal's newest, which
// stands) made it. Only the words differ: nothing is written either way.
func staleText(ctx context.Context, svc ChangeService, req rules.ChangeReq, e rules.Edit, text string) string {
	const already = "Already in the policy · nothing written"
	p, err := svc.PlanChange(ctx, rules.ChangeReq{Ref: req.Ref, Edits: req.Edits})
	switch {
	case err != nil || p.Err == "":
		return text // the edit can be made on the file now: the preview shows it again
	case p.Nothing:
		return already
	}
	hs, err := svc.History(req.Ref)
	if err != nil || len(hs) == 0 || !hs[0].Current {
		return text
	}
	want := e.Key + " -= " + e.Entry // a removal, and the ask a Never allow takes away
	if e.Op == "add" {
		want = e.Key + " += " + e.Entry
	}
	if slices.Contains(strings.Split(hs[0].Summary, "; "), want) {
		return already
	}
	return text
}

// appliedLine is a change written, in one line: what the next run gets, and where "Also apply now" put it in force.
func appliedLine(a *rules.Applied) string {
	var after []string
	for _, sn := range a.Plan.Sentences {
		after = append(after, sn.After)
	}
	line := "Saved: " + strings.Join(after, "; ")
	if a.Plan.Raw || len(after) == 0 {
		line = "Saved: the free edit of " + filepath.Base(a.Plan.Contract)
	}
	line += ", from the next run."
	n := 0
	for _, l := range a.Live {
		if l.OK {
			n++
		}
	}
	if n > 0 {
		line += " Putting it in force now on " + plural4(n, "running run", "running runs") + "."
	}
	return line
}

// savedAnswer answers a change written or undone: its Saved page is kept (Server.keep) and the answer goes there,
// with line said once (flash.go).
func (s *Server) savedAnswer(w http.ResponseWriter, r *http.Request, d savedData, line string) {
	dest := "/rules/change/saved?" + url.Values{"c": {d.Ref}, "id": {s.keep(d)}}.Encode()
	f := flash{OK: true, Text: line, Go: dest}
	if d.Warn != "" {
		f.Text += " Written, but: " + d.Warn
	}
	s.redirectBack(w, r, dest, f)
}

// rulesSaved serves GET /rules/change/saved?c&id: the Saved page the write or the Undo kept, with the history and the
// Undo read again; once it is no longer kept, Change rules for c.
func (s *Server) rulesSaved(w http.ResponseWriter, r *http.Request, svc ChangeService) {
	q := r.URL.Query()
	d, ok := s.kept(q.Get("id")).(savedData)
	if !ok || d.Ref != q.Get("c") {
		s.changePage(w, r, svc, q.Get("c"))
		return
	}
	s.renderSaved(w, svc, d)
}

// beforeWords is what the next run could do before a change, as the Undo box says it gets back.
func beforeWords(ss []rules.Sentence) string {
	var b []string
	for _, sn := range ss {
		if sn.Before != "" {
			b = append(b, sn.Before)
		}
	}
	return strings.Join(b, "; ")
}

// renderSaved fills in the text's base for Undo and the history, and renders the Saved page.
func (s *Server) renderSaved(w http.ResponseWriter, svc ChangeService, d savedData) {
	if cur, err := svc.Current(d.Ref); err == nil {
		d.Base = cur.Base
		d.Hist = histView{CSRF: s.csrf, Ref: d.Ref, Base: cur.Base}
		d.Hist.Rows, _ = historyOf(svc, d.Ref, cur.Base)
		// The page is kept and shown again (its live region, a reload): its Undo stays while the entry can be undone.
		if i := slices.IndexFunc(d.Hist.Rows, func(h historyRow) bool { return h.ID == d.UndoID }); i < 0 || !d.Hist.Rows[i].CanUndo {
			d.UndoID = ""
		} else {
			d.UndoAckValue, d.UndoLift = d.Hist.Rows[i].Ack, d.Hist.Rows[i].Lift
		}
	} else {
		d.UndoID = "" // the text cannot be read now, so no Undo can carry its base
	}
	s.settleSaved(&d)
	title := "Saved"
	if d.Reverted != nil {
		title = "Undone"
	}
	c, ok := s.changeChrome(w, title+" · "+d.Agent)
	if ok {
		s.render(w, http.StatusOK, "rules-saved", c, d)
	}
}

// settleSaved works out a written change's Headline, Live and Next from what its "Also apply now" placed and each
// run's own record now, as the line page's Saved panel does (event.go settleLive: ledgerview.LiveFacts over the run's
// lines, the overlay serial the placement returned or the run's overlay holds). A placement whose serial is not known
// and is not in the overlay is said as waiting, never as in force.
func (s *Server) settleSaved(d *savedData) {
	d.Headline, d.Live, d.Next = "", nil, nil
	if d.Applied == nil {
		return
	}
	home, cwd := homeDir(), map[string]string{}
	for _, o := range d.Applied.Plan.Now {
		if cwd[o.Run] == "" {
			cwd[o.Run] = o.Cwd
		}
	}
	placedOn := map[string]bool{}
	for _, l := range d.Applied.Live {
		if l.Lift {
			continue
		}
		placedOn[l.Run] = true
		o := savedOut{LiveResult: l, Words: liveWords(l.Block, shortener{cwd: cwd[l.Run], home: home})}
		if l.OK {
			s.settleOut(&o)
		}
		d.Live = append(d.Live, o)
	}
	for _, o := range d.Applied.Plan.Now {
		n := savedNext{Run: o.Run, Change: o.Change, Why: o.Why, FenceLift: o.FenceLift}
		switch {
		case o.OK && placedOn[o.Run]:
			continue // its outcome is in Live
		case o.OK:
			n.Why = "Also apply now was not ticked for this run"
		}
		if n.Change == "" {
			n.Change = o.Block
		}
		if !slices.Contains(d.Next, n) {
			d.Next = append(d.Next, n)
		}
	}
	d.Headline = savedHeadline(d.Live)
}

// settleOut sets the state of the placed outcome o on its run now.
func (s *Server) settleOut(o *savedOut) {
	rr, err := ledgerview.LoadRun(s.cfg.Ledger, o.Run)
	if err != nil {
		o.State, o.Chip, o.Class, o.Before, o.After = ledgerview.LiveWaiting, "Placed", "b-waiting", "on run ", ": its state cannot be read now"
		return
	}
	f := ledgerview.LiveFactsOf(rr)
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
	st := f.StatusAt(kind, serial, s.cfg.Now(), e.From, e.Until)
	o.State, o.Title = st.State, st.Sentence
	since := ""
	if st.Since > 0 {
		since = " since line #" + strconv.FormatUint(st.Since, 10)
	}
	switch st.State {
	case ledgerview.LiveInForce:
		o.Chip, o.Class, o.Before, o.After = "Live now", "b-active", "on run ", since
	case ledgerview.LivePartial:
		o.Chip, o.Class, o.Before, o.After = "Live now", "b-active", "on run ", since+": changes are refused; this run's reads are not seen"
	case ledgerview.LiveWaiting:
		o.Chip, o.Class, o.Before, o.After = "Putting it in force", "b-waiting", "on run ", "…"
	case ledgerview.LiveRecordedOnly:
		o.Chip, o.Class, o.Before, o.After = "Recorded only", "b-observed", "on watched run ", ": matching actions are recorded, not stopped"
	case ledgerview.LiveDormant:
		o.Chip, o.Class, o.Before, o.After = "Unblocked for a while", "b-neutral", "on run ", ": it refuses nothing until "+limitAt(e.From)
	case ledgerview.LiveExpired:
		o.Chip, o.Class, o.Before, o.After = "Ended by its time limit", "b-done", "on run ", ": it no longer refuses anything"
	default:
		o.Chip, o.Class, o.Before, o.After = "Ended", "b-neutral", "run ", " has ended: it no longer refuses anything"
	}
}

// savedHeadline is the Saved page's heading for the outcomes: live now on the runs once every placed block is in
// force there, putting it in force while one waits, and from the next run only when nothing was applied now or what
// was is no longer live (a watched run, a run that ended).
func savedHeadline(outs []savedOut) string {
	var runs []string
	live, waiting := true, false
	for _, o := range outs {
		if !o.OK {
			continue
		}
		if !slices.Contains(runs, o.Run) {
			runs = append(runs, o.Run)
		}
		switch o.State {
		case ledgerview.LiveInForce, ledgerview.LivePartial:
		case ledgerview.LiveWaiting:
			live, waiting = false, true
		default:
			live = false
		}
	}
	on := ""
	if len(runs) == 1 {
		on = shortRun(runs[0])
	} else {
		on = plural4(len(runs), "running run", "running runs")
	}
	switch {
	case len(runs) == 0:
	case live:
		return "Saved · live now on " + on + " and from the next run"
	case waiting:
		return "Saved · from the next run; putting it in force on " + on + " now"
	}
	return "Saved · applies from the next run"
}

// rulesRevert serves POST /rules/revert, which postAllowed has passed: Undo of a journal entry.
func (s *Server) rulesRevert(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.changeService(w)
	if !ok {
		return
	}
	f := r.PostForm
	req := rules.RevertReq{ID: f.Get("id"), Base: f.Get("base"), Ack: f.Get("ack"), Lift: f.Get("lift") != ""}
	rv, err := svc.Revert(r.Context(), req)
	if rv == nil && err != nil {
		_, text, again := refusal(err)
		if !again {
			s.serviceFail(w, "Undo a rule change", err)
			return
		}
		switch {
		case errors.Is(err, rules.ErrNeedsAck):
			text = "Not undone · tick \"Next run may do more\" and undo"
		case errors.Is(err, rules.ErrStale):
			// The page it goes back to is read again: its history offers Undo only on a change the file still holds.
			text = "Not undone · the policy changed since · History reloaded"
		}
		back := "/rules/change"
		// The way back names the contract only when the posted c is the one whose journal holds the entry: c is the
		// form's word, which the service does not check against the entry.
		if ref := f.Get("c"); ref != "" {
			if hs, herr := svc.History(ref); herr == nil && slices.ContainsFunc(hs, func(h rules.HistoryEntry) bool { return h.ID == req.ID }) {
				back += "?c=" + url.QueryEscape(ref)
			}
		}
		s.redirectBack(w, r, backTo(r, back), flash{Text: strings.Replace(text, "Nothing was written", "Not undone", 1)})
		return
	}
	d := savedData{Ref: rv.Ref, Contract: rv.Contract, Reverted: rv, UndoID: rv.ID, UndoAck: rv.Direction != widens, UndoLive: undoLiveLine(rv)}
	if err != nil { // written, not journaled (rulefile.ErrJournal)
		d.Warn = err.Error()
	}
	if cs, cerr := svc.Contracts(); cerr == nil {
		if i := slices.IndexFunc(cs, func(c rules.ContractRef) bool { return c.Ref == rv.Ref }); i >= 0 {
			d.Agent = cs[i].Agent
		}
	}
	d.CLI = []string{"tego compile " + shellWord(rv.Contract)}
	line := "Undone: from its next run, " + filepath.Base(rv.Contract) + " has the rules it had before that change."
	if d.UndoLive != "" {
		line += " " + d.UndoLive
	}
	s.savedAnswer(w, r, d, line)
}

// rawPost serves POST /rules/change with mode=raw: step=check compiles the posted text in the contract's run context and
// shows its diff or its diagnostics and, when it compiles, the acknowledgement box bound to that text (its Ack);
// step=save writes it under every guard, confirmed like a widening with that Ack (ack): a text changed after its
// check writes nothing and is checked again.
func (s *Server) rawPost(w http.ResponseWriter, r *http.Request, svc ChangeService) {
	f := r.PostForm
	ref, base := f.Get("c"), f.Get("base")
	// A textarea submits its lines ending in CR LF (HTML's form encoding); a contract's lines end in LF.
	text := strings.ReplaceAll(f.Get("text"), "\r\n", "\n")
	refs, err := svc.Contracts()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "Change rules", err.Error())
		return
	}
	i := slices.IndexFunc(refs, func(c rules.ContractRef) bool { return c.Ref == ref })
	if i < 0 {
		s.serviceFail(w, "Change rules", rules.ErrNoContract)
		return
	}
	d := changeData{Contracts: refs, C: &refs[i]}
	if !s.fillChange(w, svc, &d) {
		return
	}
	if d.NotWritable != "" || !d.CanRaw {
		why := d.NotWritable
		if why == "" {
			why = d.RawWhy
		}
		s.fail(w, http.StatusForbidden, "Edit YAML", why)
		return
	}
	d.Raw = &rawView{Open: true, Text: text}
	status := http.StatusOK
	req := rules.RawReq{Ref: ref, Base: base, Text: []byte(text), Ack: f.Get("ack"), AlsoNow: f["now"]}
	switch {
	case f.Get("step") == "save":
		a, err := svc.ApplyRaw(r.Context(), req)
		if err == nil {
			sd := savedData{Ref: a.Plan.Ref, Contract: a.Plan.Contract, Agent: a.Plan.Agent, Applied: a, UndoID: a.ID, Warn: a.Warn,
				UndoAck: true, CLI: []string{"tego compile " + shellWord(a.Plan.Contract)}}
			s.savedAnswer(w, r, sd, appliedLine(a))
			return
		}
		var again bool
		if status, d.Raw.Err, again = refusal(err); !again {
			s.serviceFail(w, "Edit YAML", err)
			return
		}
		if errors.Is(err, rules.ErrNeedsAck) {
			d.Raw.Err = "Not saved · check the text, tick to confirm, then save"
			if errors.Is(err, rules.ErrAckMismatch) {
				d.Raw.Err = "Not saved · the text changed · check it again and save"
			}
		}
		if r.Header.Get(inlineHeader) != "" {
			// live.js posted the Save: the editor keeps its text, and the toast says why nothing was written (a
			// plain form gets the editor again with the check below).
			s.redirectBack(w, r, "", flash{Text: d.Raw.Err})
			return
		}
		fallthrough
	default:
		p, err := svc.PlanRaw(r.Context(), req)
		if err != nil {
			s.serviceFail(w, "Edit YAML", err)
			return
		}
		d.Raw.Plan = p
		if p.Err == "" {
			d.Raw.Now = nowRuns(p.Now)
		}
		if p.EnvRefused {
			status = http.StatusUnprocessableEntity
		}
		if p.Err != "" {
			d.Raw.Diags = diagsOf(p.Err, p.Contract)
			d.Raw.Lines = numbered(text, d.Raw.Diags)
		}
	}
	c, ok := s.changeChrome(w, "Edit YAML · "+d.C.Agent)
	if ok {
		s.render(w, status, "rules-change", c, d)
	}
}

// diagPos finds the line a compile diagnostic names: "<file>:12:3: ", "<file>:12: " or YAML's "line 12".
var diagPos = regexp.MustCompile(`:(\d+)(?::\d+)?: |\bline (\d+)\b`)

// diagsOf splits a plan's compile error into its lines, each with the contract line it names. A position in the
// contract's own file is preferred to one in a profile it extends.
func diagsOf(msg, contract string) []diagLine {
	var out []diagLine
	for _, l := range strings.Split(msg, "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		d := diagLine{Text: strings.TrimRight(l, " ")}
		probe := l
		if contract != "" && strings.Contains(l, contract+":") {
			probe = l[strings.Index(l, contract+":")+len(contract):]
		} else if strings.Contains(l, ".yaml:") && !strings.Contains(l, "line ") {
			probe = "" // another file's position (a profile): no line of this text
		}
		if m := diagPos.FindStringSubmatch(probe); m != nil {
			n := m[1]
			if n == "" {
				n = m[2]
			}
			d.Line, _ = strconv.Atoi(n)
		}
		out = append(out, d)
	}
	return out
}

// numbered is the text's lines around those the diagnostics name (two either side), with their numbers; nil when no
// diagnostic names a line.
func numbered(text string, ds []diagLine) []numLine {
	bad := map[int]bool{}
	for _, d := range ds {
		if d.Line > 0 {
			bad[d.Line] = true
		}
	}
	if len(bad) == 0 {
		return nil
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	var out []numLine
	last := 0
	for i, l := range lines {
		n := i + 1
		near := false
		for b := range bad {
			near = near || (n >= b-2 && n <= b+2)
		}
		if !near {
			continue
		}
		if last != 0 && n > last+1 {
			out = append(out, numLine{Gap: true})
		}
		out = append(out, numLine{N: n, Text: l, Bad: bad[n]})
		last = n
	}
	return out
}
