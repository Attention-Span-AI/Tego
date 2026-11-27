// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/contractsrc"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/pathcheck"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// The Rules page (GET /rules[?run=<id>|?c=<ref>]): one run's Rules in force (rulesview.InForce), one table per group
// in plain sentences, with each rule's hits in that run linking to Logs, the run's live blocks with Remove (an ended
// run's, which refuse nothing, under a collapsed row), a banner when its rules file changed for the next run, and the
// raw contract and compile table behind a toggle. The chooser picks a rules file a run of this ledger recorded (by an
// opaque ref, never a path) and one of its runs. The page reads; Remove posts to /runs/<run>/unblock, and Change rules
// opens /rules/change (rules_change.go).
//
// The ref is the rule service's (rules.Ref, rules.ContractRef.Ref), worked out here from the path a run recorded, so
// the page needs no service to name a file and Change rules is linked to with no hop. The runs and the run shown come
// from the read model's snapshot (ledgerview.Load); a run past it is read on its own (ledgerview.LoadRun).

// maxChooserRuns bounds the run chooser's list of one rules file's runs; the run shown is listed too when it is older.
const maxChooserRuns = 40

// legacyRef is the ref the Rules page named a rules file by before it named it by the rule service's: the hex sha256
// of the recorded path, cleaned, 64 digits. Only an old link carries one now (a bookmark, a page still open from
// before); /rules and /rules/change send it on to the file's ref.
func legacyRef(path string) string {
	if path == "" || !filepath.IsAbs(path) {
		return ""
	}
	sum := sha256.Sum256([]byte(filepath.Clean(path)))
	return hex.EncodeToString(sum[:])
}

// isLegacyRef says ref has legacyRef's shape: no ref of the rule service's (16 hex digits) has it.
func isLegacyRef(ref string) bool {
	return len(ref) == sha256.Size*2 && strings.Trim(ref, "0123456789abcdef") == ""
}

// refMemo is rules.Ref of each recorded path, worked out once a request: the page asks it of every run of the
// snapshot, and it resolves the path's folder.
type refMemo map[string]string

func (m refMemo) of(path string) string {
	path = filepath.Clean(path)
	ref, ok := m[path]
	if !ok {
		ref = rules.RefLexical(path)
		m[path] = ref
	}
	return ref
}

// contractOpt is one rules file in the chooser; Gone marks one no longer at its path (rulesview.ContractRun).
type contractOpt struct {
	Ref, Path, Agent string
	// Aliases are the other spellings of the file the runs (and the rule service) recorded; the file is listed once,
	// and the page says the others reach it.
	Aliases    []string
	Runs, Live int
	Gone       bool
	Why        string
	Last       time.Time
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
	Summary          string
	Key, URL         string
	// Note is said beside the rule: a draft from a run's note on an address entry (rules.AddressNote).
	Note string
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
	// ByOS is the rule's ByKernel claim from inforce. The page still prints the exact enforcement text.
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
	General       *contractsrc.General
	BaselineState string
	Query, State  string
	FilterPage    bool
	List          bool
	Selected      *ruleRow
	Contracts     []contractOpt
	Ref           string
	// CanChange is changeBuilt: the Change rules button links to the form, or is disabled with a hint.
	CanChange bool
	Runs      []runOpt
	// RunPage says which page of the rules file's runs Runs is, and whether older or newer ones exist (chooserRuns).
	RunPage chooserPage
	// Run is the run shown; nil on an empty ledger.
	Run *ledgerview.Run
	V   *rulesview.InForceView
	// Agent is the name the page says, Tier the tier in words, Source the rules file shortened.
	Agent, Tier, Source string
	CannotChange        string
	// SelectionErr keeps the catalogue visible when a requested alias cannot be checked.
	SelectionErr   string
	Running, Watch bool
	Groups         []ruleGroup
	Live           *ruleGroup
	// EndedLive is an ended run's live blocks, each said by what it did while the run ran (rulesview's EndedLive:
	// blocked, marked on a watched run, or never put in force), listed under a collapsed row below the note that counts
	// them; they refuse nothing now, so no live table holds them and none offers Remove.
	EndedLive []ruleRow
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
	// Compare is what the file says now against what this run ran, family by family, for a file edited outside Tego or
	// one that differs with nothing to date it (fillSourceCompare); nil when it was not asked for.
	Compare *rules.SourceComparison
}

// SourceCompareService is the rule service's comparison of a run's rules with its file as it is now
// (rules.Service.CompareSource); a Config.Rules without it shows the banner without the comparison.
type SourceCompareService interface {
	CompareSource(ctx context.Context, run string) rules.SourceComparison
}

// fillSourceCompare adds the comparison to a pending banner that names an edit outside Tego, or says the file differs
// with nothing to date it: both say only that the file changed, and the comparison says what the next run does
// differently and which way it moves.
func (s *Server) fillSourceCompare(ctx context.Context, d *rulesData) {
	p := d.Pending
	if p == nil || d.Run == nil || (p.Edited.IsZero() && !p.Differs) {
		return
	}
	if cs, ok := s.cfg.Rules.(SourceCompareService); ok {
		if c := cs.CompareSource(ctx, d.Run.ID); !c.NoCompiler {
			p.Compare = &c
		}
	}
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
	ctx, cancel := pathcheck.Bound(r.Context())
	defer cancel()
	r = r.WithContext(ctx)
	q := r.URL.Query()
	d := rulesData{CanChange: changeBuilt, CanSetUp: s.cfg.Setup != nil}
	if q.Get("run") == "" && q.Get("c") == "" {
		uid, _ := config.InvokingUID()
		general := s.readGeneral(r.Context(), s.cfg.Machine, uid)
		d.General = &general
		d.BaselineState = s.baselineNotice()
		if d.BaselineState == "" {
			d.BaselineState = "No machine baseline entries are configured in this snapshot."
		}
	}
	refs := refMemo{}
	// list is the landing page: every contract that ran, not one contract's rules.
	list := q.Get("c") == "" && q.Get("run") == ""
	// Obtain the selected run before location or catalogue reads can consume the request
	// budget on a source location. The source view retains a recorded-text fallback.
	var run *ledgerview.Run
	if want := q.Get("run"); want != "" {
		run = snap.Find(want)
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
	selected := run
	if ref := q.Get("c"); ref != "" {
		if selected == nil || rules.RefLexical(selected.Contract) != ref {
			selected = nil
			for _, rr := range snap.Runs {
				if rules.RefLexical(rr.Contract) == ref {
					selected = rr
					break
				}
			}
		}
	} else if !list && selected == nil && len(snap.Runs) > 0 {
		selected = snap.Runs[0]
	}
	if selected != nil {
		d.V = rulesview.InForce(r.Context(), s.cfg.Ledger, selected.ID, rulesview.Options{Machine: s.cfg.Machine, Anchor: s.cfg.Anchor, Profiles: s.cfg.Profiles, Run: selected})
	}
	ran := rulesview.ContractsFromRunsContext(r.Context(), snap)
	for _, entry := range ran {
		resolved := entry.Resolved
		if resolved == "" {
			resolved = entry.Path
		}
		refs[entry.Path] = rules.RefLexical(resolved)
	}
	if old := q.Get("c"); isLegacyRef(old) {
		for _, c := range ran {
			if legacyRef(c.Path) == old {
				q.Set("c", refs.of(c.Path))
				http.Redirect(w, r, "/rules?"+q.Encode(), http.StatusSeeOther)
				return
			}
		}
	}
	d.Contracts = s.chooserContracts(ran, refs, r.Context())
	if list {
		d.List, d.Now = true, s.cfg.Now()
		d.Query, d.State, d.FilterPage = strings.TrimSpace(q.Get("q")), q.Get("state"), q.Get("filters") == "1"
		if d.Query != "" || d.State != "" {
			filtered := make([]contractOpt, 0, len(d.Contracts))
			for _, c := range d.Contracts {
				match := d.State == "" || d.State == "running" && c.Live > 0 || d.State == "gone" && c.Gone || d.State == "not-run" && c.Runs == 0
				if match && strings.Contains(strings.ToLower(c.Agent+" "+c.Path), strings.ToLower(d.Query)) {
					filtered = append(filtered, c)
				}
			}
			d.Contracts = filtered
		}
		s.render(w, http.StatusOK, "rules", s.chromeOf(snap, "Rules files", "rules"), d)
		return
	}
	if ref := q.Get("c"); ref != "" {
		var found *contractOpt
		for i := range d.Contracts {
			if d.Contracts[i].Ref == ref {
				found = &d.Contracts[i]
			}
		}
		if found == nil {
			if (len(ref) == 16 && strings.Trim(ref, "0123456789abcdef") == "") || isLegacyRef(ref) {
				for _, entry := range d.Contracts {
					if pathcheck.UnansweredText(entry.Why) {
						d.SelectionErr = "The requested contract cannot be identified: " + entry.Why
						break
					}
				}
			}
			if d.SelectionErr != "" {
				d.CanChange = false
				s.render(w, http.StatusOK, "rules", s.chromeOf(snap, "Rules files", "rules"), d)
				return
			}
			s.fail(w, http.StatusNotFound, "No such contract file", "No run used that contract file · pick one on the Rules files page")
			return
		}
		if found.Runs == 0 { // set up here, not run yet: its rules as written and the line that starts it
			d.Ref, d.Agent = ref, found.Agent
			var err error
			if found.Why != "" {
				d.SelectionErr = found.Why
			} else {
				d.NotRun, err = s.notRun(r, ref)
				if err != nil {
					d.SelectionErr = err.Error()
				}
			}
			if d.SelectionErr != "" {
				d.CanChange = false
				s.render(w, http.StatusOK, "rules", s.chromeOf(snap, "Rules files", "rules"), d)
				return
			}
			if d.NotRun != nil {
				d.Ref, d.Agent = ref, found.Agent
				c := s.chromeOf(snap, "Contract · "+found.Agent, "rules")
				s.render(w, http.StatusOK, "rules", c, d)
				return
			}
		}
		// The run chosen belongs to another rules file when the person changed the contract and kept the run: the
		// contract wins, and its newest run is shown.
		if run == nil || refs.of(run.Contract) != ref {
			run = nil
			for _, rr := range snap.Runs {
				if refs.of(rr.Contract) == ref {
					run = rr
					break
				}
			}
		}
	}
	if run == nil && len(snap.Runs) > 0 {
		run = snap.Runs[0]
	}
	c := s.chromeOf(snap, "Rules files", "rules")
	if run == nil {
		s.render(w, http.StatusOK, "rules", c, d)
		return
	}
	d.Run, d.Ref = run, refs.of(run.Contract)
	page, _ := strconv.Atoi(q.Get("rp"))
	pg := chooserRuns(snap, run, d.Ref, refs, page)
	if d.Ref != "" {
		if pg.Older {
			pg.OlderURL = "/rules?c=" + d.Ref + "&rp=" + strconv.Itoa(pg.Page+1)
		}
		if pg.Newer {
			pg.NewerURL = "/rules?c=" + d.Ref
			if pg.Page > 1 {
				pg.NewerURL += "&rp=" + strconv.Itoa(pg.Page-1)
			}
		}
	}
	d.Runs, d.RunPage = pg.Runs, pg
	for _, entry := range d.Contracts {
		if entry.Ref == d.Ref && entry.Why != "" {
			d.CanChange = false
			d.CannotChange = entry.Why
		}
	}
	d.Running = run.State() == "running"
	if d.V == nil || d.V.Run != run.ID {
		d.V = rulesview.InForce(r.Context(), s.cfg.Ledger, run.ID, rulesview.Options{Machine: s.cfg.Machine, Anchor: s.cfg.Anchor, Profiles: s.cfg.Profiles, Run: run})
	}
	why := d.V.SourceUnavailable
	if pathcheck.UnansweredText(d.V.Err) {
		why = d.V.Err
	}
	if why != "" {
		d.CanChange = false
		d.CannotChange = joinRefusal(d.CannotChange, why)
		for i := range d.Contracts {
			if d.Contracts[i].Ref == d.Ref {
				d.Contracts[i].Why = joinRefusal(d.Contracts[i].Why, why)
			}
		}
	}
	s.fillRules(&d)
	if note := rulesview.LaunchNoteOf(snap, d.Ref, refs.of, run); note != "" {
		d.V.View.Notes = append(d.V.View.Notes, note)
	}
	s.fillPendingLive(r.Context(), &d)
	s.fillSourceCompare(r.Context(), &d)
	s.fillLiveMode(&d)
	if key := q.Get("rule"); key != "" {
		if d.Live != nil {
			for _, row := range d.Live.Rows {
				if row.Key == key {
					r := row
					d.Selected = &r
				}
			}
		}
		for _, g := range d.Groups {
			for _, row := range g.Rows {
				if row.Key == key {
					r := row
					d.Selected = &r
				}
				for _, device := range row.Devices {
					if device.Key == key {
						r := device
						d.Selected = &r
					}
				}
			}
		}
		if d.Selected == nil {
			s.fail(w, http.StatusNotFound, "No such rule", "This run has no rule with that key. Open its contract to choose a rule.")
			return
		}
	}
	if d.Agent != "" {
		c.Title = "Contract · " + d.Agent
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
	facts := ledgerview.LiveFactsOf(d.Run)
	for i := range d.Live.Rows {
		row := &d.Live.Rows[i]
		b, ok := blocks[liveblock.Key(liveblock.Kind(row.Kind), row.Value)]
		if !ok {
			continue
		}
		t := blockTimeOf(b, d.Now, facts)
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

// chooserContracts is the chooser's rules files: those the runs named (ran, the newest run's file first), one per ref,
// so a file two runs recorded through two spellings of its folder (one through a link) is one entry, under its newest
// run's spelling, counting the runs of both, and gone when nothing is at that spelling now (both reach one file when
// they share a ref); then those the rule service set up here that no run ran yet.
func (s *Server) chooserContracts(ran []rulesview.ContractRun, refs refMemo, ctx context.Context) []contractOpt {
	var out []contractOpt
	at := map[string]int{}
	for _, c := range ran {
		ref := refs.of(c.Path)
		if i, ok := at[ref]; ok {
			out[i].Aliases = addAlias(out[i].Aliases, out[i].Path, c.Path)
			out[i].Runs += c.Runs
			out[i].Live += c.Live
			out[i].Why = joinRefusal(out[i].Why, c.Why)
			if c.NewestStart.After(out[i].Last) {
				out[i].Last = c.NewestStart
			}
			continue
		}
		at[ref] = len(out)
		out = append(out, contractOpt{Ref: ref, Path: c.Path, Agent: c.Agent, Runs: c.Runs, Live: c.Live, Gone: c.Gone, Why: c.Why, Last: c.NewestStart})
	}
	for _, c := range s.catalogueContracts(ctx) {
		if i, ok := at[c.Ref]; ok {
			// Location metadata can answer while a guarded source read fails.
			// Keep the catalogue's refusal for contracts that already ran too.
			out[i].Why = joinRefusal(out[i].Why, c.Why)
			out[i].Aliases = addAlias(out[i].Aliases, out[i].Path, c.Path)
			for _, a := range c.Aliases {
				out[i].Aliases = addAlias(out[i].Aliases, out[i].Path, a)
			}
		} else if c.Runs == 0 {
			out = append(out, c)
		}
	}
	return out
}

// addAlias adds spelling to aliases unless it is the file's own path shown or already there: one file reached under two
// spellings is listed once, and the second says so.
func addAlias(aliases []string, path, spelling string) []string {
	if spelling == "" || spelling == path || slices.Contains(aliases, spelling) {
		return aliases
	}
	return append(aliases, spelling)
}

func joinRefusal(previous, current string) string {
	if previous == "" {
		return current
	}
	if current == "" || current == previous {
		return previous
	}
	return previous + "; " + current
}

// chooserPage is the chooser's run list as one page of a rules file's runs, newest first.
type chooserPage struct {
	Runs []runOpt
	// Page is the page shown (0 is the newest runs); Older and Newer say another page exists on that side.
	Page         int
	Older, Newer bool
	// OlderURL and NewerURL are the Rules page of the neighbouring page of runs, "" when there is none.
	OlderURL, NewerURL string
}

// chooserRuns is the chooser's run list: page (0-based) of maxChooserRuns runs of the rules file ref, newest first, and
// the run shown when it is not among them (an older run reached by ?run=, or one read from disk past the snapshot) in
// its place by start, so the list never names another run than the one the page shows. A run that named no rules file
// is listed alone. Older and Newer say there are runs past either end of the page, which the page links to: no run is
// reachable only by typing its id.
func chooserRuns(snap *ledgerview.Snapshot, run *ledgerview.Run, ref string, refs refMemo, page int) chooserPage {
	page = max(page, 0)
	first, last := page*maxChooserRuns, (page+1)*maxChooserRuns
	var out []runOpt
	seen := 0
	pg := chooserPage{Page: page, Newer: page > 0}
	for _, rr := range snap.Runs { // newest start first
		if refs.of(rr.Contract) != ref || ref == "" && rr.ID != run.ID {
			continue
		}
		if seen >= last {
			pg.Older = true // one run past the page is enough to say there are more
			break
		}
		if seen >= first {
			out = append(out, runOpt{ID: rr.ID, Start: rr.Start, State: rr.State()})
		}
		seen++
	}
	if slices.ContainsFunc(out, func(o runOpt) bool { return o.ID == run.ID }) {
		pg.Runs = out
		return pg
	}
	i := len(out)
	for i > 0 && out[i-1].Start.Before(run.Start) {
		i--
	}
	pg.Runs = slices.Insert(out, i, runOpt{ID: run.ID, Start: run.Start, State: run.State()})
	return pg
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
	d.Source = file
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
			key := rl.RuleKey
			if key == "" {
				key = rl.Key + "[" + rl.Entry + "]"
			}
			row := ruleRow{Key: key, URL: "/rules?run=" + run.ID + "&rule=" + url.QueryEscape(key), Sentence: rl.Sentence, Target: rl.Target, Effect: string(rl.Effect), Enforced: rl.EnforcedText,
				State: string(rl.State), Hits: rl.Hits, HitsURL: logs(rl.RuleKey)}
			if rl.Invocation != "" {
				// Its hits are the lines that name this entry, a part of its program's lines, which Logs cannot
				// filter by (no command_rule key): a link on the program's rule would list more lines than the count.
				row.HitsURL = ""
			}
			if rl.Key == "record" {
				row.Sentence = strings.ReplaceAll(row.Sentence, "a record that cannot be changed unnoticed", "a saved record")
			}
			if g.ID != "live" && rl.ByKernel {
				row.ByOS = true
			}
			row.Summary = row.Sentence
			if len(row.Target) > 40 {
				noun := "this location"
				if strings.HasPrefix(row.Key, "net") {
					noun = "this host"
				}
				row.Summary = strings.ReplaceAll(row.Sentence, row.Target, noun)
			}
			row.Source, row.SourceTitle = sourceWords(rl.Source.File, rl.Source.Line, rl.Source.Origin, v)
			if g.ID == "live" {
				row.Kind, row.Value, _ = strings.Cut(rl.Entry, ":")
			}
			return row
		}
		folds := []rulesview.Fold{}
		if g.ID == "live" {
			for _, rl := range g.Rules {
				folds = append(folds, rulesview.Fold{Rule: rl})
			}
		} else {
			folds = rulesview.FoldDevices(g.Rules)
		}
		for _, f := range folds {
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
	for _, rl := range v.EndedLive {
		row := ruleRow{Sentence: rl.Sentence, Hits: rl.Hits, HitsURL: logs(rl.RuleKey)}
		row.Summary = row.Sentence
		if row.Target != "" {
			row.Summary = strings.ReplaceAll(row.Sentence, row.Target, "this location")
		}
		row.Source, row.SourceTitle = sourceWords(rl.Source.File, rl.Source.Line, rl.Source.Origin, v)
		d.EndedLive = append(d.EndedLive, row)
	}
	d.Text, d.Table = v.Contract.Shown()
	if v.Source != "" {
		d.Hint = "tego rules check " + shellWord(v.Source)
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
	row.Key = "terminal-devices:" + row.Effect
	baseURL, _, _ := strings.Cut(row.Devices[0].URL, "&rule=")
	row.URL = baseURL + "&rule=" + url.QueryEscape(row.Key)
	row.Sentence = fmt.Sprintf("%s terminal devices (%d)", verb, len(devs))
	row.Summary = row.Sentence
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
		return "Plus (cgroup BPF)"
	case "bpflsm":
		return "Max (BPF LSM)"
	case "observe":
		return "Watched only"
	case "":
		return "Unknown protection"
	}
	return t
}
