// SPDX-License-Identifier: Apache-2.0

package web

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/liveblock"
)

// The Rules page (GET /rules[?run=<id>|?c=<ref>]): one run's Rules in force (rulesview.InForce), one table per group
// in plain sentences, with each rule's hits in that run linking to Logs, the run's live blocks with Remove, a banner
// when its rules file changed for the next run, and the raw contract and compile table behind a toggle. The chooser
// picks a rules file a run of this ledger recorded (by an opaque ref, never a path) and one of its runs. The page
// reads; Remove posts to /runs/<run>/unblock, and Change rules opens /rules/change (rules_change.go).

// maxChooserRuns bounds the run chooser's list of one rules file's runs.
const maxChooserRuns = 40

// contractRef is the opaque ref of a rules file a run recorded: the hex sha256 of its cleaned absolute path. The
// browser names a contract by it and never by a path, so a request cannot smuggle a path in .
func contractRef(path string) string {
	if path == "" || !filepath.IsAbs(path) {
		return ""
	}
	sum := sha256.Sum256([]byte(filepath.Clean(path)))
	return hex.EncodeToString(sum[:])
}

// contractOpt is one rules file in the chooser.
type contractOpt struct {
	Ref, Path, Agent string
	Runs, Live       int
}

// runOpt is one run of the chosen rules file in the chooser.
type runOpt struct {
	ID    string
	Start time.Time
	State string
}

// ruleRow is one rule as the page shows it.
type ruleRow struct {
	Sentence, Target string
	// Effect is inforce's effect word: allow, ask, deny, limit or note.
	Effect string
	// Enforced is how it is enforced; State is inforce's claim word (enforced, best_effort, not_enforced, none).
	Enforced, State string
	// Source is the short place ("agent.yaml:12", "run copy line 9", "built in"); SourceTitle the full one.
	Source, SourceTitle string
	Hits                int
	// HitsURL is the Logs search for the rule's ledger key in this run, "" when no ledger line names the rule.
	HitsURL string
	// Kind and Value are a live block's, for Remove.
	Kind, Value string
	// ByOS: the kernel enforces it in full, the usual case, so its Enforced by cell stays empty and the exceptions
	// stand out (the rule's ByKernel, which inforce sets).
	ByOS bool
	// Devices are the terminal device rules folded under this one row (rulesview.FoldDevices), each kept whole for
	// the expander; Hits is then their sum. Nil for a rule shown alone.
	Devices []ruleRow
	// Ends says when a timed live block ends ("until Fri 17:00", "ended at Tue 13:51", ADR 0125); "" for every
	// other row. Ended: its limit has passed, so it refuses nothing and offers no Remove.
	Ends  string
	Ended bool
}

// ruleGroup is one table of the page.
type ruleGroup struct {
	ID, Title, Lede, Default, Icon string
	// Open: the default leaves the agent wide open (the group's Open, which inforce sets); Narrow is the change that
	// narrows it, "" when the page cannot offer one.
	Open   bool
	Narrow string
	// DefaultHits is how many lines of the run the default decided (the group's DefaultHits); DefaultURL is the Logs
	// search for them, "" when there are none.
	DefaultHits int
	DefaultURL  string
	Rows        []ruleRow
	// Calm is a live group none of whose blocks refuses anything now (marks on a watched run, blocks still waiting):
	// its panel drops the red edge, which says a refusal.
	Calm bool
}

// rulesData is the Rules page's data.
type rulesData struct {
	Contracts []contractOpt
	Ref       string
	// CanChange is changeBuilt: the Change rules button links to the form, or is disabled with a hint.
	CanChange bool
	Runs      []runOpt
	// Run is the run shown; nil on an empty ledger.
	Run *ledgerview.Run
	V   *rulesview.InForceView
	// Agent is the name the page says, Tier the tier in words, Source the rules file shortened.
	Agent, Tier, Source string
	Running, Watch      bool
	Groups              []ruleGroup
	Live                *ruleGroup
	// Text and Table are the run's copy and compile table with env.set values hidden; Hint the terminal twin.
	Text, Table, Hint string
	// CopyNote says why positions are the run copy's lines, "" when they are the rules file's.
	CopyNote string
	Pending  *pendingView
	// CanSetUp: "Set up a new agent" (rules_new.go) is served. NotRun is the chosen contract when it was set up here
	// and no run ran it yet.
	CanSetUp bool
	NotRun   *notRunData
	// Mode is the run's live mode (ADR 0125): "adjustable" when its run_start says so, else "locked". Fence is an
	// Adjustable run's fence panel, nil on a Locked run. Now is the page's clock, which the limits are said against.
	Mode  string
	Fence *fenceView
	Now   time.Time
}

// pendingView is the amber banner's content: what changed in the rules file after the run started. On a running run
// it is the "Changed since this run started" panel (rules_pending.go): each change says what it is on the run now,
// and the line to start the next run with these rules.
type pendingView struct {
	Changes []pendingChange
	Edited  time.Time
	// Unchecked: the file could not be compared with what the run ran.
	Unchecked bool
	// Differs: the file loads to other rules than the run ran and nothing dates a change (rulesview.Pending.Differs),
	// so the banner has no change and no time to show, only that the file differs.
	Differs bool
	// Live: each change has its state on the running run (fillPendingLive). Restart is the terminal line that starts
	// the next run of the rules file with the command this run was started with ("" when the run names none).
	Live    bool
	Restart string
}

// pendingChange is one journaled change of the rules file that stands (rulesview.Pending: a revert's Summary says what
// it undid).
type pendingChange struct {
	At        time.Time
	Summary   string
	Sentences []string
	Via       string
	// ID is the change's journal id; Now its state on the running run (fillPendingLive), nil on an ended run.
	ID  string
	Now *pendingLive
}

// rules serves GET /rules.
func (s *Server) rules(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	q := r.URL.Query()
	d := rulesData{CanChange: changeBuilt, CanSetUp: s.cfg.Setup != nil}
	for _, c := range rulesview.ContractsFromRuns(snap) {
		d.Contracts = append(d.Contracts, contractOpt{Ref: contractRef(c.Path), Path: c.Path, Agent: c.Agent, Runs: c.Runs, Live: c.Live})
	}
	d.Contracts = append(d.Contracts, s.notRunContracts()...)
	var run *ledgerview.Run
	if want := q.Get("run"); want != "" {
		run = findRun(snap, want)
		if run == nil {
			if rr, err := ledgerview.LoadRun(s.cfg.Ledger, want); err == nil && rr.ID == want {
				run = rr
			}
		}
		if run == nil {
			s.fail(w, http.StatusNotFound, "No such run", "This ledger holds no run "+want+". Pick one on the Rules page or on Runs.")
			return
		}
	}
	if ref := q.Get("c"); ref != "" {
		var found *contractOpt
		for i := range d.Contracts {
			if d.Contracts[i].Ref == ref {
				found = &d.Contracts[i]
			}
		}
		if found == nil {
			s.fail(w, http.StatusNotFound, "No such policy file", "No run used that policy file · pick one on the Policy page")
			return
		}
		if found.Runs == 0 { // set up here, not run yet: its rules as written and the line that starts it
			if d.NotRun = s.notRun(r, ref); d.NotRun != nil {
				d.Ref, d.Agent = ref, found.Agent
				c := s.chromeOf(snap, "Policy · "+found.Agent, "rules")
				s.render(w, http.StatusOK, "rules", c, d)
				return
			}
		}
		// The run chosen belongs to another rules file when the person changed the contract and kept the run: the
		// contract wins, and its newest run is shown.
		if run == nil || contractRef(run.Contract) != ref {
			run = nil
			for _, rr := range snap.Runs {
				if contractRef(rr.Contract) == ref {
					run = rr
					break
				}
			}
		}
	}
	if run == nil && len(snap.Runs) > 0 {
		run = snap.Runs[0]
	}
	c := s.chromeOf(snap, "Rules", "rules")
	if run == nil {
		s.render(w, http.StatusOK, "rules", c, d)
		return
	}
	d.Run, d.Ref = run, contractRef(run.Contract)
	for _, rr := range snap.Runs {
		if contractRef(rr.Contract) == d.Ref && (d.Ref != "" || rr.ID == run.ID) && len(d.Runs) < maxChooserRuns {
			d.Runs = append(d.Runs, runOpt{ID: rr.ID, Start: rr.Start, State: rr.State()})
		}
	}
	if len(d.Runs) == 0 { // a run loaded from disk beyond the snapshot
		d.Runs = []runOpt{{ID: run.ID, Start: run.Start, State: run.State()}}
	}
	d.Running = run.State() == "running"
	d.V = rulesview.InForce(r.Context(), s.cfg.Ledger, run.ID, rulesview.Options{Machine: s.cfg.Machine, Anchor: s.cfg.Anchor, Profiles: s.cfg.Profiles, Run: run})
	s.fillRules(&d)
	s.fillPendingLive(r.Context(), &d)
	s.fillLiveMode(&d)
	if d.Agent != "" {
		c.Title = "Policy · " + d.Agent
	}
	s.render(w, http.StatusOK, "rules", c, d)
}

// fillLiveMode sets the page's mode and, on an Adjustable run, its fence panel (ADR 0125), and the end of each timed
// live block in the live group.
func (s *Server) fillLiveMode(d *rulesData) {
	d.Now, d.Mode = s.cfg.Now(), "locked"
	if ledgerview.LiveFactsOf(d.Run).Adjustable {
		d.Mode, d.Fence = "adjustable", fenceViewOf(d.Run, d.Now)
	}
	if d.Live == nil {
		return
	}
	lb, err := runact.Live(s.cfg.Ledger, d.Run.ID)
	if err != nil {
		return // the live group says the blocks could not be read (rulesview's LiveErr)
	}
	blocks := make(map[string]liveblock.Entry, len(lb.Blocks))
	for _, b := range lb.Blocks {
		blocks[b.Key()] = b
	}
	timed := false
	for i := range d.Live.Rows {
		row := &d.Live.Rows[i]
		b, ok := blocks[liveblock.Key(liveblock.Kind(row.Kind), row.Value)]
		if !ok {
			continue
		}
		t := blockTimeOf(b, d.Now)
		row.Ends, row.Ended = t.Ends, t.Ended
		timed = timed || t.Timed()
		// livestatus says "In force since line #N" for any block the launcher confirmed; past its limit, or
		// unblocked for a while, the block refuses nothing, and the row must not say it does.
		if t.Ended || t.Dormant {
			row.Enforced, row.State = t.Why, "none"
		}
	}
	if timed {
		d.Live.Lede = strings.Replace(d.Live.Lede, "They end with the run.", "Each ends with the run or at its time limit.", 1)
		d.Live.Default = strings.Replace(d.Live.Default, "ends with the run", "ends with the run or at its time limit", 1)
	}
}

// findRun is the snapshot's run id, nil when it holds none.
func findRun(snap *ledgerview.Snapshot, id string) *ledgerview.Run {
	for _, r := range snap.Runs {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// fillRules turns d.V into the page's groups, banner and details.
func (s *Server) fillRules(d *rulesData) {
	v, run := d.V, d.Run
	d.Agent = v.View.Agent
	if d.Agent == "" {
		d.Agent = run.Agent
	}
	tier := v.View.Tier
	if tier == "" {
		tier = run.Tier
	}
	d.Tier, d.Watch = tierPhrase(tier), tier == "observe"
	file := v.Source
	if file == "" {
		file = v.CopyPath
	}
	d.Source = tailCut(file, 60)
	if v.Positions == rulesview.PositionsCopy && v.Source != "" {
		d.CopyNote = "Line numbers are the run's own copy of its rules: " + v.PositionsWhy + "."
	}
	logs := func(key string) string {
		if key == "" {
			return ""
		}
		return logsURL(run.ID, key)
	}
	for _, g := range v.View.Groups {
		rg := ruleGroup{ID: g.ID, Title: g.Title, Lede: g.Lede, Default: g.Default, Icon: groupIcon(g.ID)}
		if rg.Open = g.Open; rg.Open {
			rg.Narrow = narrowLink(g.ID, d.Ref, d.CanChange)
		}
		if g.DefaultHits > 0 && g.DefaultKind != "" {
			rg.DefaultHits, rg.DefaultURL = g.DefaultHits, logsURL(run.ID, "rule:unmatched kind:"+g.DefaultKind)
		}
		toRow := func(rl rulesview.Rule) ruleRow {
			row := ruleRow{Sentence: rl.Sentence, Target: rl.Target, Effect: string(rl.Effect), Enforced: rl.EnforcedText,
				State: string(rl.State), Hits: rl.Hits, HitsURL: logs(rl.RuleKey)}
			if g.ID != "live" && rl.ByKernel {
				row.ByOS = true
			}
			row.Source, row.SourceTitle = sourceWords(rl.Source.File, rl.Source.Line, rl.Source.Origin, v)
			if g.ID == "live" {
				row.Kind, row.Value, _ = strings.Cut(rl.Entry, ":")
			}
			return row
		}
		rules := []rulesview.Fold{}
		if g.ID == "live" {
			for _, rl := range g.Rules {
				rules = append(rules, rulesview.Fold{Rule: rl})
			}
		} else {
			rules = rulesview.FoldDevices(g.Rules)
		}
		for _, f := range rules {
			row := toRow(f.Rule)
			if len(f.Devices) > 0 {
				row = foldRow(f.Devices, toRow)
			}
			rg.Rows = append(rg.Rows, row)
		}
		if g.ID == "live" {
			if len(rg.Rows) > 0 {
				rg.Calm = true
				for _, row := range rg.Rows {
					if row.State == "best_effort" { // inforce gives a live block a claim only while it refuses
						rg.Calm = false
					}
				}
				d.Live = &rg
			}
			continue
		}
		if len(rg.Rows) == 0 && rg.Default == "" {
			continue
		}
		d.Groups = append(d.Groups, rg)
	}
	d.Text, d.Table = v.Contract.Shown()
	if v.Source != "" {
		d.Hint = "tego compile " + shellWord(v.Source)
		if cwd := v.Contract.Cwd; cwd != "" {
			d.Hint = "cd " + shellWord(cwd) + " && " + d.Hint
		}
	}
	if p := v.Pending; p != nil {
		pv := &pendingView{Edited: p.Edited, Unchecked: p.Unchecked, Differs: p.Differs}
		for _, e := range p.Changes {
			pv.Changes = append(pv.Changes, pendingChange{At: e.At, Summary: e.Summary, Sentences: e.Sentences, Via: e.Via, ID: e.ID})
		}
		d.Pending = pv
	}
}

// foldRow is the one row the terminal device rules fold into: "Can change terminal devices (4)", its effect and
// enforcement those of the rules (all one effect; ByOS only when every one is), its hits their sum, its source the
// one line they share or "several lines", and each rule kept as it was for the expander.
func foldRow(devs []rulesview.Rule, toRow func(rulesview.Rule) ruleRow) ruleRow {
	row := ruleRow{Effect: string(devs[0].Effect), ByOS: true}
	for i, rl := range devs {
		r := toRow(rl)
		row.Devices = append(row.Devices, r)
		row.Hits += r.Hits
		row.ByOS = row.ByOS && r.ByOS
		if i == 0 {
			row.Enforced, row.State, row.Source, row.SourceTitle = r.Enforced, r.State, r.Source, r.SourceTitle
		} else if r.Source != row.Source {
			row.Source, row.SourceTitle = "several lines", "see each device"
		}
		if r.Enforced != row.Enforced {
			row.Enforced = "varies: see each device"
		}
	}
	verb := "Can change"
	switch row.Effect { // inforce's effect words
	case "deny":
		verb = "Can never change"
	case "ask":
		verb = "Asks before it changes"
	}
	row.Sentence = fmt.Sprintf("%s terminal devices (%d)", verb, len(devs))
	return row
}

// narrowLink is the Change rules form's section that narrows an open default of group id, "" when the form cannot
// be offered (not built, or no rules file to change); the environment, which the form's lists do not hold, opens
// the YAML editor.
func narrowLink(id, ref string, canChange bool) string {
	if !canChange || ref == "" {
		return ""
	}
	base := "/rules/change?c=" + ref
	switch id {
	case "network":
		return base + "#rc-net.allow"
	case "programs":
		return base + "#rc-exec.allow"
	}
	return base + "#yaml"
}

// sourceWords is where a rule came from, short (for the cell) and full (for its title): the rules file's name and
// line, a profile's, the run copy's line, or the origin word of a rule written in no file.
func sourceWords(file string, line int, origin string, v *rulesview.InForceView) (short, full string) {
	at := func(f string) string {
		if line > 0 {
			return fmt.Sprintf("%s:%d", f, line)
		}
		return f
	}
	switch {
	case file != "" && file == v.CopyPath:
		if line > 0 {
			return fmt.Sprintf("run copy line %d", line), at(file)
		}
		return "run copy", file
	case origin == "profile" && file != "":
		return "profile " + at(filepath.Base(file)), at(file)
	case file != "":
		return at(filepath.Base(file)), at(file)
	case strings.HasPrefix(origin, "live block by "):
		// liveblock records the writer as "uid:1000 pid:42 dashboard": the last word says from where.
		by := strings.TrimPrefix(origin, "live block by ")
		if words := strings.Fields(by); len(words) > 0 {
			return "live, from the " + words[len(words)-1], origin
		}
	}
	return origin, origin
}

// groupIcon is the sprite icon of a group's heading.
func groupIcon(id string) string {
	switch id {
	case "read":
		return "i-eye"
	case "change":
		return "i-scroll-text"
	case "ask":
		return "i-hand"
	case "never-read", "never-change", "live":
		return "i-ban"
	case "programs":
		return "i-terminal"
	case "network":
		return "i-activity"
	case "env":
		return "i-key-round"
	case "limits":
		return "i-square"
	}
	return "i-shield"
}

// tierPhrase is a run's tier in the page's words.
func tierPhrase(t string) string {
	switch t {
	case "landlock":
		return "Basic (Landlock)"
	case "cgroup":
		return "Strong (cgroup BPF)"
	case "bpflsm":
		return "Strongest (BPF LSM)"
	case "observe":
		return "Watched only"
	case "":
		return "Unknown protection"
	}
	return t
}
