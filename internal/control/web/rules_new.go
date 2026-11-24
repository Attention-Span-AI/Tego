// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// "Set up a new agent" (GET and POST /rules/new): a form for a project folder, an agent
// name, the presets, and optional folders it may write, hosts it may reach and its command, or a finished run to start
// from. A read-only GET preview shows the contract's rules in sentences, what compile says and the YAML;
// Create (a POST through postAllowed) writes <dir>/agent.yaml through the rule service, never over a file, and is
// answered as every action is (flash.go): 303 to the page of the agent set up (?created=<id>, what the write kept,
// Server.keep) with one line, or that line as JSON for live.js, which shows that address in place (the whole page is
// its live region); a refusal goes back to the preview with the line saying why. The created page shows the line
// that starts the agent. From a run, the draft is saved by default as the user registry's entry <name> through
// registry.Save, the writer tego rules learn --save writes through, so tego run <name> and the tego-agent@<name> unit find
// it; "The project folder" writes agent.yaml as before. "Show refused reads (slower)" adds reason: {reads: on}: from a
// run it is on by default, as --save's default is, and takes learn's own rendering. From presets the switch starts
// off; selecting ci supplies its own default. Turning the switch on adds a block through setup.Options.Reads. The run page's
// Tighten tab links here with the run named, which previews at once. The page makes no decision of its own: every check and the write are the service's, which runs path-dependent work in its bounded own-image helper as the user who started the dashboard.

// SetupService is what "Set up a new agent" asks of the rule service (internal/control/rules new.go).
type SetupService interface {
	PlanNew(ctx context.Context, req rules.NewReq) (*rules.NewPlan, error)
	CreateNew(ctx context.Context, req rules.NewReq, base string) (*rules.Created, error)
	DescribeNew(ctx context.Context, ref string) (*rules.NewPlan, error)
	Contracts() ([]rules.ContractRef, error)
}

// maxFromRuns bounds the "Start from a run" list.
const maxFromRuns = 30

// newData is the page's data.
type newData struct {
	Draft string

	View      string
	Editor    string
	Fields    []builderField
	Errors    []builderError
	YAML      []builderLine
	Decisions []rules.Decision

	// Form is what was typed, echoed into the inputs; Writes and Hosts as typed, one item per comma or line.
	Form   rules.NewReq
	Writes string
	Hosts  string
	// Pass and AskRead are the "Variables it needs" and "Ask before reading" fields, as typed.
	Pass, AskRead string
	Mode          string // presets | run
	// To is where a draft from a run is saved: "registry" (the user registry's entry, for tego run <name>, as tego rules learn
	// --save saves it; the default) or "project" (agent.yaml in the project folder). Reads is the "Show refused reads
	// (slower)" switch: from a run on by default, as tego rules learn --save records them unless --reads off; from presets
	// off by default; an explicitly selected ci preset supplies its own read default.
	To    string
	Reads bool
	// ReadsCost is what recording refused reads costs, as compile and tego rules learn --save state it.
	ReadsCost string
	Presets   []presetOpt
	Runs      []fromRunOpt
	// Plan is the preview, nil before the first one; Text its YAML with env.set values hidden.
	Plan   *rules.NewPlan
	Groups []newGroup
	Text   string
	// Start is the line that starts the agent once it is written.
	Start string
	// Err is why Create refused.
	Err string
	// Created is the write done.
	Created *rules.Created
	// Ref is the new contract's ref on the Rules page.
	Ref string
	// Off says the dashboard was started without the rule service.
	Off bool
	// LiveMode is the mode picked ("locked" or "adjustable", ADR 0125); FenceRead, FenceNet and FenceExec the fence's
	// textareas as typed, one entry per line or comma.
	LiveMode                       string
	FenceRead, FenceNet, FenceExec string
}

// liveForm reads the form's live mode and fence into d (rules.NewReq's LiveMode and fence): Locked unless Adjustable
// is picked, and no fence under Locked, so a Locked draft is the contract it always was.
func liveForm(d *newData, v url.Values) {
	d.LiveMode = rules.NewLiveLocked
	if v.Get("live") == rules.NewLiveAdjustable {
		d.LiveMode = rules.NewLiveAdjustable
	}
	d.FenceRead, d.FenceNet, d.FenceExec = v.Get("fence_read"), v.Get("fence_net"), v.Get("fence_exec")
	d.Form.LiveMode = d.LiveMode
	if d.LiveMode == rules.NewLiveAdjustable {
		d.Form.FenceRead, d.Form.FenceNet, d.Form.FenceExec = splitList(d.FenceRead), splitList(d.FenceNet), splitList(d.FenceExec)
	}
}

// fromRunOpt is one finished run "Start from a run" offers.
type fromRunOpt struct {
	ID, Agent string
	Start     time.Time
}

// presetOpt is one preset checkbox. Also is what the previewed command's agent was given past the label's promise.
type presetOpt struct {
	Name, Promise, Also string
	On                  bool
}

// rulesNew serves GET /rules/new: the form and, once a folder is typed, its preview.
func (s *Server) rulesNew(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	snap, err := ledgerview.Load(s.cfg.Ledger)
	if err != nil {
		snap = &ledgerview.Snapshot{ReadError: err.Error()}
	}
	if d, ok := s.kept(q.Get("created")).(newData); ok {
		s.renderNew(w, snap, http.StatusOK, d)
		return
	}
	d := s.newForm(r, snap, q.Get("dir"), q.Get("name"), q["preset"], q.Get("writes"), q.Get("hosts"), q.Get("cmd"), q.Get("from"), q.Get("mode"))
	liveForm(&d, q)
	// A run named in the address (the run page's "Make a contract from this run") is previewed at once: the folder is
	// that run's own.
	if d.Off || (q.Get("dir") == "" && q.Get("preview") == "" && (d.Mode != "run" || d.Form.FromRun == "")) {
		s.renderNew(w, snap, http.StatusOK, d)
		return
	}
	p, err := s.cfg.Setup.PlanNew(r.Context(), d.Form)
	if err != nil {
		d.Err = err.Error()
	}
	s.fillPlan(&d, p)
	s.renderNew(w, snap, http.StatusOK, d)
}

// rulesNewPost serves POST /rules/new after the shared write guards: prepare and preview, or Create.
func (s *Server) rulesNewPost(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	if f.Get("guide") == "review" {
		r = r.Clone(r.Context())
		q := r.URL.Query()
		q.Set("guide", "review")
		q.Set("preview", "1")
		r.URL.RawQuery = q.Encode()
		w = s.tourRequest(w, r)
	}
	if s.cfg.Setup != nil && f.Get("builder") == "1" && f.Get("step") != "save" {
		snap, _ := ledgerview.Load(s.cfg.Ledger)
		d := s.newForm(r, snap, f.Get("dir"), f.Get("name"), f["preset"], f.Get("writes"), f.Get("hosts"), f.Get("cmd"), f.Get("from"), f.Get("mode"))
		liveForm(&d, f)
		p, err := s.cfg.Setup.PlanNew(r.Context(), d.Form)
		if err != nil {
			d.Err = err.Error()
		}
		s.fillPlan(&d, p)
		s.renderNew(w, snap, http.StatusOK, d)
		return
	}
	// The preview the form came from, to go back to when nothing is written: the same fields as a GET.
	back := url.Values{"preview": {"1"}}
	for _, k := range []string{"mode", "dir", "name", "writes", "hosts", "pass", "askread", "cmd", "from", "to", "reads", "live", "fence_read", "fence_net", "fence_exec"} {
		if v := f.Get(k); v != "" {
			back.Set(k, v)
		}
	}
	back["preset"] = f["preset"]
	if f.Get("guide") == "review" {
		back.Set("guide", "review")
	}
	if s.cfg.Setup == nil {
		s.redirectBack(w, r, "/rules/new", flash{Text: "Not created · contract editing is off here · use tego rules create --preset"})
		return
	}
	snap, _ := ledgerview.Load(s.cfg.Ledger) // as in rulesNew
	d := s.newForm(r, snap, f.Get("dir"), f.Get("name"), f["preset"], f.Get("writes"), f.Get("hosts"), f.Get("cmd"), f.Get("from"), f.Get("mode"))
	liveForm(&d, f)
	c, err := s.cfg.Setup.CreateNew(r.Context(), d.Form, f.Get("base"))
	if c == nil && s.checkUnavailable(w, err) {
		return
	}
	if errors.Is(err, rules.ErrReviewGone) {
		d.Err = err.Error()
		text := rulesview.RedactEnvText(string(d.Form.Text))
		s.fillPlan(&d, &rules.NewPlan{Text: []byte(text), Source: []byte(text), Draft: d.Form.Draft})
		s.renderNew(w, snap, http.StatusConflict, d)
		return
	}
	if c == nil {
		if f.Get("builder") == "1" {
			// A refused Save preserves input but offers no newly built proposal.
			text := rulesview.RedactEnvText(string(d.Form.Text))
			s.fillPlan(&d, &rules.NewPlan{Text: []byte(text), Source: []byte(text), Draft: d.Form.Draft})
			d.Err = "Not saved: " + plainErr(err)
			status := http.StatusUnprocessableEntity
			if errors.Is(err, rules.ErrStale) {
				status = http.StatusConflict
			}
			s.renderNew(w, snap, status, d)
			return
		}
		// The registry's button says Save, and the service's sentence says why and what to do: once, after one lead.
		lead, verb, why := "Not created: ", "create", err.Error()
		if d.Form.Registry && d.Form.FromRun != "" {
			lead, verb, why = "Not saved: ", "save", plainErr(err)
		}
		if errors.Is(err, rules.ErrStale) {
			why = "the reviewed destination or inherited rules changed. Review the contract again, then " + verb + " again."
		}
		s.redirectBack(w, r, "/rules/new?"+back.Encode(), flash{Text: lead + why})
		return
	}
	// This server knows the registry changed; do not retain the pre-save guide facts.
	s.guide.mu.Lock()
	s.guide.last = nil
	s.guide.mu.Unlock()
	d.Created, d.Ref = c, c.Ref
	d.Start = cmdText(startLine(c.Dir))
	line := "Set up " + c.Name + ": contract written. Start it with the command below."
	if c.Registry {
		d.Start = cmdText(runLine(c.Dir, c.Name))
		line = "Saved " + c.Name + ". Start it with the command below."
	}
	if err != nil { // written, not journaled (rulefile.ErrJournal)
		d.Err = err.Error()
		line += " (" + d.Err + ")"
	}
	dest := "/rules/new?created=" + s.keep(d)
	if f.Get("guide") == "review" {
		dest += "&guide=review"
	}
	s.redirectBack(w, r, dest, flash{OK: true, Text: line, Here: dest})
}

// newForm reads the form's fields into newData, with the preset and run choices.
func (s *Server) newForm(r *http.Request, snap *ledgerview.Snapshot, dir, name string, presets []string, writes, hosts, cmd, from, mode string) newData {
	d := newData{View: builderView(r), Fields: builderFields, Writes: writes, Hosts: hosts, Mode: mode, Off: s.cfg.Setup == nil, ReadsCost: agent.ReasonReadCost + ", " + agent.ReasonReadWorkload}
	if d.Mode != "run" && d.Mode != "blank" {
		d.Mode = "presets"
	}
	d.Pass, d.AskRead = r.FormValue("pass"), r.FormValue("askread")
	d.Form = rules.NewReq{PreviewOnly: r.Method != http.MethodPost && s.governed(r) != nil, PrepareDirectories: r.Method == http.MethodPost, Draft: r.FormValue("draft"), Session: s.session, Dir: dir, Name: name, Writes: splitList(writes), Hosts: splitList(hosts), Command: cmd,
		Pass: splitList(d.Pass), AskRead: splitList(d.AskRead)}
	if d.Mode == "run" {
		d.Form.FromRun = strings.TrimSpace(from)
	} else {
		d.Form.Presets = presets
	}
	fresh := dir == "" && len(presets) == 0 && r.URL.Query().Get("preview") == "" && r.Method != http.MethodPost
	for _, p := range rules.Presets() {
		on := slices.Contains(presets, p.Name) || fresh && (p.Name == "no-secrets" || p.Name == "no-prod")
		d.Presets = append(d.Presets, presetOpt{Name: p.Name, Promise: p.Promise, On: on})
	}
	if snap != nil {
		for _, rr := range snap.Runs {
			if rr.Live || rr.State() == "unknown" || len(d.Runs) >= maxFromRuns {
				continue
			}
			d.Runs = append(d.Runs, fromRunOpt{ID: rr.ID, Agent: rr.Agent, Start: rr.Start})
			if rr.ID == d.Form.FromRun && strings.TrimSpace(dir) == "" {
				d.Form.Dir = rr.Cwd // a run's proposal is written for the folder it ran in
			}
		}
	}
	if d.Mode == "run" {
		// A fresh form (no preview yet, not a Create) saves to the user registry and records refused reads, as tego
		// learn --save does; a form sent back says what was picked, and an unticked box sends nothing.
		fresh := r.URL.Query().Get("preview") == "" && r.Method != http.MethodPost
		d.To = r.FormValue("to")
		if d.To != "registry" && d.To != "project" {
			d.To = "project"
			if fresh {
				d.To = "registry"
			}
		}
		d.Reads = r.FormValue("reads") == "on" || fresh
		d.Form.Registry = d.To == "registry"
	} else {
		// The switch starts off; an explicitly selected ci preset supplies its own read default.
		d.Reads = r.FormValue("reads") == "on"
	}
	if d.Mode != "run" {
		d.To = r.FormValue("to")
		if d.To == "" && s.cfg.Machine != nil && s.cfg.Machine.Registry.Value != "" {
			d.To = "registry"
		}
		d.Form.Registry = d.To == "registry"
	}
	d.Form.Reads = d.Reads
	d.Form.Blank = d.Mode == "blank"
	if r.Method == http.MethodPost && r.FormValue("builder") == "1" && r.FormValue("step") != "source" {
		d.Form.Text = []byte(strings.ReplaceAll(r.FormValue("text"), "\r\n", "\n"))
		d.Form.Drop = r.PostForm["drop"]
		for k, v := range r.PostForm {
			if strings.HasPrefix(k, "choice-") && len(v) > 0 && v[0] == "drop" {
				d.Form.Drop = append(d.Form.Drop, strings.TrimPrefix(k, "choice-"))
			}
		}
		d.Form.NameHosts = map[string]string{}
		for k, v := range r.PostForm {
			if strings.HasPrefix(k, "host-") && len(v) > 0 {
				d.Form.NameHosts[strings.TrimPrefix(k, "host-")] = v[0]
			}
		}
		d.Form.Switches = r.FormValue("current-view") == "simple"
		d.Form.Wall = r.FormValue("wall")
		if r.FormValue("limit-wall") == "on" && d.Form.Wall == "" {
			d.Form.Wall = "2h"
		}
		d.Form.RemoveWall = r.FormValue("wall-choice") == "1" && r.FormValue("limit-wall") != "on" && d.Form.Wall == ""
		d.Form.WantAsk = r.FormValue("ask-connections") == "on"
		d.Form.DropAsk = r.FormValue("ask-choice") == "1" && !d.Form.WantAsk
		if d.Form.WantAsk {
			d.Form.AskHosts = splitList(r.FormValue("ask-hosts"))
		}
	}
	if d.Form.FromRun != "" {
		// A contract made from a run that leaked never allows where its secrets went (QA PW-1). Preview and Create
		// both come through here, so the draft, and the base hash Create checks, agree.
		d.Form.Withhold = s.fromRunLeak(snap, d.Form.FromRun)
	}
	return d
}

// fromRunLeak is leakDests of run id: from the snapshot, or read on its own as the run page reads it when the
// snapshot does not hold it (an older run, or a ledger the snapshot could not read).
func (s *Server) fromRunLeak(snap *ledgerview.Snapshot, id string) []string {
	var all []*ledgerview.Run
	var run *ledgerview.Run
	if snap != nil {
		all, run = snap.Runs, snap.Find(id)
	}
	if run == nil {
		run, _ = ledgerview.LoadRun(s.cfg.Ledger, id) // it checks the id; a run that cannot be read has no proposal either
	}
	return s.leakDests(all, run)
}

// fillPlan puts the preview into d.
func (s *Server) fillPlan(d *newData, p *rules.NewPlan) {
	if p == nil {
		return
	}
	if len(p.Text) == 0 && len(d.Form.Text) > 0 {
		// A busy or cancelled preflight has no compiled projection. Preserve the
		// submitted editor and authenticated draft handle while refusing Save.
		text := rulesview.RedactEnvText(string(d.Form.Text))
		p.Text, p.Source = []byte(text), []byte(text)
		p.Draft, p.OK = d.Form.Draft, false
	}
	d.Plan, d.Groups = p, newGroups(p.Groups)
	d.Draft = p.Draft
	d.Decisions = p.Decisions
	d.Reads = p.Reads
	d.Form.Wall = p.Wall
	d.Form.AskHosts = p.AskHosts
	d.Editor = rulesview.RedactEnvText(string(p.Source))
	if d.View == "full" {
		d.Editor = rulesview.RedactEnvText(string(p.Text))
	}
	d.Errors = newBuilderErrors(p, d.View, d.Mode)
	d.YAML = builderLines(rulesview.RedactEnvText(string(p.Text)), rulesview.RedactEnvText(string(p.Source)), p.Decisions)
	for i := range d.Presets {
		d.Presets[i].Also = strings.Join(p.Grants[d.Presets[i].Name], ", ")
	}
	if len(p.Text) > 0 {
		d.Text = rulesview.RedactEnvText(string(p.Text))
	}
	if p.Dir != "" {
		d.Start = startLine(p.Dir)
		if p.Registry && p.Name != "" {
			d.Start = runLine(p.Dir, p.Name)
		}
	}
	if p.Name != "" && strings.TrimSpace(d.Form.Name) == "" {
		d.Form.Name = p.Name
	}
}

// startLine is the terminal line that starts the agent under its new contract. It names no command: the contract
// holds the one the form was given (a line with shell syntax as sh -c), and `tego run … -- <cmd>` would both replace
// it and hand the typed text to the person's own shell, where `a && b` runs b outside tego.
func startLine(dir string) string {
	return "cd " + shellWord(dir) + " && tego run " + rules.NewFile
}

// runLine is the terminal line that starts the agent saved as the user registry's entry name: tego run <name>, typed in
// the folder it runs in, as tego rules learn --save's next: line says it.
func runLine(dir, name string) string {
	return "cd " + shellWord(dir) + " && tego run " + name
}

// splitList is a comma- or line-separated field as items, each trimmed, blanks dropped.
func splitList(s string) []string {
	var out []string
	for _, item := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func (s *Server) renderNew(w http.ResponseWriter, snap *ledgerview.Snapshot, status int, d newData) {
	if d.View == "" {
		d.View = "simple"
	}
	rememberBuilderView(w, d.View)
	var c chrome
	if snap == nil {
		c = s.chromeFromLedger("New contract", "rules")
	} else {
		c = s.chromeOf(snap, "New contract", "rules")
	}
	c.PhoneName = "Contracts" // the compact header names the section, as the contract builder pages always have
	if d.Created != nil {
		c.Title = "Agent set up · " + d.Created.Name
	}
	s.render(w, status, "rules-new", c, d)
}

// notRunData is the Rules page's view of a contract set up here that no run ran yet.
type notRunData struct {
	Plan   *rules.NewPlan
	Groups []newGroup
	Text   string
	Start  string
}

// catalogueContracts keeps every guarded-read refusal for the Rules chooser,
// including files that already ran and entries created before their first run.
func (s *Server) catalogueContracts(ctx context.Context) []contractOpt {
	var svc interface {
		Contracts() ([]rules.ContractRef, error)
	}
	if s.cfg.Setup != nil {
		svc = s.cfg.Setup
	} else if changes, ok := s.cfg.Rules.(ChangeService); ok {
		svc = changes
	}
	if svc == nil {
		return nil
	}
	if local, ok := svc.(*rules.Service); ok {
		svc = local.ForRequest(ctx)
	}
	cs, err := svc.Contracts()
	if err != nil {
		return nil
	}
	var out []contractOpt
	for _, c := range cs {
		why := c.Why
		if !c.Writable && why == "" {
			why = "this contract cannot be changed here"
		}
		out = append(out, contractOpt{Ref: c.Ref, Path: c.Path, Aliases: c.Aliases, Agent: c.Agent, Runs: c.Runs, Live: len(c.Live), Why: why})
	}
	return out
}

// notRun is the view of the not-run contract ref, nil when the service has none such.
func (s *Server) notRun(r *http.Request, ref string) (*notRunData, error) {
	if s.cfg.Setup == nil || len(ref) != 16 {
		return nil, nil
	}
	p, err := s.cfg.Setup.DescribeNew(r.Context(), ref)
	if err != nil {
		return nil, err
	}
	return &notRunData{Plan: p, Groups: newGroups(p.Groups), Text: rulesview.RedactEnvText(string(p.Text)), Start: startLine(p.Dir)}, nil
}

// maxGroupRows is how many rules a group of a draft lists before the rest fold under "and N more": a preset's
// allow-list of variables is two dozen names, which would push the network and the Create button off the screen.
const maxGroupRows = 8

// newGroup is one group of a draft's rules: the first maxGroupRows, and the rest folded.
type newGroup struct {
	ruleGroup
	More []ruleRow
}

// newGroups is a plan's groups as the page shows them, each with its icon.
func newGroups(gs []rules.NewGroup) []newGroup {
	out := make([]newGroup, 0, len(gs))
	for _, g := range gs {
		ng := newGroup{ruleGroup: ruleGroup{ID: g.ID, Title: g.Title, Lede: g.Lede, Default: g.Default, Icon: groupIcon(g.ID)}}
		for i, r := range g.Rules {
			row := ruleRow{Sentence: r.Sentence, Effect: r.Effect, Note: r.Note}
			if i < maxGroupRows {
				ng.Rows = append(ng.Rows, row)
			} else {
				ng.More = append(ng.More, row)
			}
		}
		out = append(out, ng)
	}
	return out
}
