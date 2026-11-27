// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/guide"
)

// tourStops teach the six stages without changing the six machine facts that
// setup prints. Install remains in the evidence disclosure. Watch and Recorded
// deliberately share the same verified, ended-record fact.
var tourStops = []struct{ key, label, fact string }{
	{"check", "Check", guide.StepCheck}, {"pick", "Pick", guide.StepFind},
	{"watch", "Watch", guide.StepRecord}, {"recorded", "Recorded", guide.StepRecord},
	{"review", "Review", guide.StepContract}, {"enforce", "Enforce", guide.StepEnforce},
}

func tourKey(key string) bool {
	for _, st := range tourStops {
		if st.key == key {
			return true
		}
	}
	return false
}

func tourFact(g *setupGuide, id string) guide.StepWords {
	for _, st := range g.Words.Steps {
		if st.ID == id {
			return st
		}
	}
	return guide.StepWords{ID: id, State: guide.NotKnown, Fact: guide.NotKnownFact}
}

func tourCurrent(g *setupGuide) string {
	for _, stop := range tourStops {
		state := tourFact(g, stop.fact).State
		if state != guide.Done && state != guide.Skipped {
			return stop.key
		}
	}
	return "enforce"
}

// tourPath is the existing product page for the teaching stage. Review uses the
// receipt until the sentence editor lands; its action opens today's real builder.
func tourPath(g *setupGuide, key string) (string, string) {
	run := tourFact(g, guide.StepRecord).Run
	switch key {
	case "check":
		return "/machine", "This machine"
	case "pick":
		return "/agents", "Agents"
	case "recorded", "review":
		if run != "" {
			return runPage(run) + "/receipt", "Run receipt"
		}
	case "watch":
		if run != "" {
			return runPage(run), "Run"
		}
	case "enforce":
		if id := tourFact(g, guide.StepEnforce).Run; id != "" {
			return runPage(id) + "/receipt", "Run receipt"
		}
		return "/rules", "Rules files"
	}
	return "/runs", "Runs"
}

func tourURL(g *setupGuide, key string) string {
	path, _ := tourPath(g, key)
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + "guide=" + key
}

func (s *Server) guideEntry(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	g := s.setupGuide(r.Context(), snap)
	if g == nil {
		s.fail(w, http.StatusServiceUnavailable, "Guide unavailable", "The dashboard has no setup inputs. Run tego setup in your terminal, then reopen the dashboard.")
		return
	}
	key := r.URL.Query().Get("step")
	if key == "" {
		key = tourCurrent(g)
	}
	if !tourKey(key) {
		s.fail(w, http.StatusBadRequest, "Unknown guide step", "Open Guide to return to the current step.")
		return
	}
	http.Redirect(w, r, tourURL(g, key), http.StatusSeeOther)
}

// tourWriter carries context to render without changing the real pages' data or
// handlers. render unwraps it before the normal full/region response selection.
type tourWriter struct {
	http.ResponseWriter
	frame *tourFrame
	offer bool
}

func guideHidden(r *http.Request) bool {
	c, err := r.Cookie("tego-guide")
	return err == nil && c.Value == "hidden"
}

func (s *Server) tourRequest(w http.ResponseWriter, r *http.Request) http.ResponseWriter {
	key := r.URL.Query().Get("guide")
	if !tourKey(key) {
		if r.URL.Path == "/" && s.cfg.Guide != nil && !guideHidden(r) {
			return &tourWriter{ResponseWriter: w, offer: true}
		}
		return w
	}
	snap, err := ledgerview.Load(s.cfg.Ledger)
	if err != nil {
		return w
	}
	g := s.setupGuide(r.Context(), snap)
	if g == nil {
		return w
	}
	f := s.makeTour(r, g, key)
	f.Pending = len(snap.Pending())
	if f.Pending > 0 {
		f.Title = "A request needs you"
		f.Instruction = "Answer the waiting request in Approvals, then return here to continue this step."
		f.Action, f.Href = "Open Approvals", "/approvals"
		f.Command, f.Form, f.Move = "", "", ""
	}
	return &tourWriter{ResponseWriter: w, frame: f}
}

func (s *Server) makeTour(r *http.Request, g *setupGuide, key string) *tourFrame {
	f := &tourFrame{Words: g.Words, Next: g.Next, CanCopy: g.CanCopy, Step: key, Action: "Reload stored check", Href: "/guide?step=" + key}
	path, label := tourPath(g, key)
	f.Leave, f.Page = path, label
	q := r.URL.Query()
	q.Del("guide")
	f.Leave = r.URL.Path
	if len(q) > 0 {
		f.Leave += "?" + q.Encode()
	}
	for i, st := range tourStops {
		fact := tourFact(g, st.fact)
		fact.N = i + 1
		f.Steps = append(f.Steps, tourStop{StepWords: fact, Key: st.key, Label: st.label})
		if key == st.key {
			f.N, f.State, f.Fact = i+1, fact.State, fact.Fact
		}
	}
	// CanCopy carries the trusted helper's Next.Built result. A stored fix can contain arbitrary
	// printable text and must never be promoted to a runnable command.
	command := func() {
		if g.CanCopy {
			if g.Next.Placeholder {
				f.Form = g.Next.Command
			} else {
				f.Command = g.Next.Command
			}
		}
	}
	switch key {
	case "check":
		f.Title = "Can Tego run here?"
		f.Instruction = "Run tego setup in a terminal on this machine, then reload its stored check here."
		if f.State == guide.Done {
			f.Action, f.Href = "Pick your agent", "/guide?step=pick"
		} else {
			command()
			// Automatic scope entry can make recording the next step even while
			// the stored check says this shell is outside the user manager.
			if g.Next.Rule == guide.RuleRecordTodo {
				f.Instruction = "In a terminal on this machine, " + strings.TrimRight(g.Next.Text, ":.") + ". Then reload its stored check here."
			}
			if g.Next.Rule == guide.RuleCheckOutside || g.Next.Rule == guide.RuleCheckBlocked || g.Next.Rule == guide.RuleCheckNoManager || g.Next.Rule == guide.RuleCheckNoManagerName {
				f.Instruction = "In a terminal on this machine, " + strings.TrimRight(g.Next.Text, ":.") + ". Then run tego setup and reload its stored check here."
				if g.Next.Rule == guide.RuleCheckOutside {
					f.Instruction = "In a terminal on this machine, " + strings.TrimRight(g.Next.Text, ":.") + ". Then reload its stored check here."
				}
			}
		}
	case "pick":
		f.Title = "Pick your agent"
		f.Instruction = "Choose your usual command in its folder; Pick completes when its first run is recorded, without refusing anything."
		if g.Next.Rule == guide.RuleRecordTodo {
			command()
		}
		f.Action, f.Href = "Watch one run", "/guide?step=watch"
		if f.State != guide.Done && tourFact(g, guide.StepContract).State == guide.Done {
			f.Instruction = "Use a saved contract for the first run; Pick completes when that run is recorded."
			f.Action, f.Href = "Start its first run", "/guide?step=enforce"
		}
	case "watch":
		f.Title = "Let it do a normal job"
		f.Instruction = "Run the command in your terminal, then stop it when the job ends so you can review its record."
		if g.Next.Rule == guide.RuleRecordTodo {
			command()
		}
		f.Waiting = f.State == guide.Waiting || f.State == guide.Todo
		f.Action = "Check for the run"
		if f.State == guide.Blocked || f.State == guide.NotKnown {
			f.Title = "The recording needs checking"
			f.Instruction = "Open All steps to see what could not be checked, then inspect the run’s record."
			f.Action, f.Href = "Inspect the record", f.Leave
			if tourFact(g, guide.StepRecord).Run == "" {
				f.Action = "Open Runs"
			}
			if g.Next.Step == guide.StepRecord {
				command()
			}
		}
		if f.State == guide.Skipped {
			f.Instruction = "A saved contract lets you skip recording. Start the agent under its rules."
			f.Action, f.Href = "Enforce its rules", "/guide?step=enforce"
		}
		if f.State == guide.Done {
			f.Move = "/guide?step=recorded"
			f.Action, f.Href = "See what was recorded", f.Move
		}
	case "recorded":
		f.Title = "What did it record?"
		f.Instruction = "Read what this run recorded and what it could not see, then review the rules you want."
		f.Action, f.Href = "Review its rules", "/guide?step=review"
	case "review":
		f.Title = "Review what it needs"
		f.Instruction = "Open What the run recorded, then choose its rules; use Create contract to make a contract."
		f.Action = "Create contract"
		f.Href = "/rules/new?mode=run&guide=review"
		if run := tourFact(g, guide.StepRecord).Run; run != "" {
			f.Href += "&from=" + url.QueryEscape(run)
		}
		if f.State == guide.Done {
			f.Instruction = "The contract is saved and compiles. Choose Enforce its rules to start a run under it."
			f.Action, f.Href = "Enforce its rules", "/guide?step=enforce"
		} else if g.Next.Step == guide.StepContract {
			command()
			switch g.Next.Rule {
			case guide.RuleContractBlocked:
				f.Instruction = "Fix the existing contract using the terminal compile result, or choose Create contract to make another."
			case guide.RuleRecordDone:
				f.Instruction = "Review What the run recorded. Create contract and the terminal learn command each make a contract from this run."
			}
		}
	case "enforce":
		f.Title = "Run it with its rules"
		f.Action = "Check for the run"
		f.Instruction = "Start one run under its contract in your terminal, then check its record and each refusal."
		f.Waiting = f.State == guide.Waiting || f.State == guide.Todo
		if g.Next.Step == guide.StepEnforce || g.Done {
			command()
		}
		if f.State == guide.Done {
			f.Title = "Its record checks out"
			f.Instruction = "Review the recorded refusals below, then open the full run to see its actions and limits."
			f.Action, f.Href = "Open the verified run", f.Leave
		}
	}
	if key == "enforce" && (f.State == guide.Blocked || f.State == guide.NotKnown) {
		f.Title = "Its record needs checking"
		f.Instruction = "Check where this run’s record breaks before using its results; next, inspect the recorded lines."
		f.Action, f.Href = "Check the record", f.Leave
	}
	if (key == "recorded" || key == "review") && (tourFact(g, guide.StepRecord).State == guide.Todo || tourFact(g, guide.StepRecord).State == guide.Waiting) {
		f.Title = "Record a run first"
		f.Instruction = "Start the command from its folder, then return after the run ends to review what it did."
		f.Command, f.Form = "", ""
		f.Action, f.Href = "Watch one run", "/guide?step=watch"
	}
	if key == "enforce" && f.State == guide.Todo && tourFact(g, guide.StepContract).State != guide.Done {
		f.Title = "Save its contract first"
		f.Instruction = "Review the recorded actions and save a contract, then return here to enforce its rules."
		f.Command, f.Form = "", ""
		f.Waiting = false
		f.Action, f.Href = "Review its rules", "/guide?step=review"
	}
	// A prior step still needing a check wins over commands that cannot run here.
	if g.Next.Step == guide.StepCheck && key != "check" {
		f.Command, f.Form, f.Move = "", "", ""
		f.Waiting = false
		f.Action, f.Href = "Check this machine first", "/guide?step=check"
		if key == "review" {
			f.Instruction = "Check this machine first, then return to review its rules."
		}
	}
	if key == "recorded" || key == "review" || key == "enforce" {
		id := tourFact(g, guide.StepRecord).Run
		if key == "enforce" {
			id = tourFact(g, guide.StepEnforce).Run
		}
		if id != "" {
			sensitive := ledgerview.Sensitive{}
			if run, err := ledgerview.LoadRun(s.cfg.Ledger, id); err == nil && run != nil {
				sensitive = s.sensitiveOf(rulesview.RunLists(s.cfg.Ledger, id), run)
			}
			f.Receipt = loadReceipt(r.Context(), s.cfg.Ledger, id, sensitive, s.receiptPricing())
			if rc := f.Receipt.R; rc != nil {
				f.RecordOpen = len(rc.Programs)+len(rc.Connections)+len(rc.SensitiveReads)+len(rc.Files.Written)+len(rc.Files.Created)+len(rc.Files.Deleted)+len(rc.Files.Renamed)+len(rc.Refusals.List) <= 12
			}
		}
	}
	// The builder remains the real page while Review supplies its teaching context.
	if r.URL.Path == "/rules/new" && key == "review" {
		f.Builder = true
		f.Page = "New rules file"
		f.Title = "Choose and check its rules"
		f.Instruction = "Review the New rules file form below, then preview and save its rules."
		f.Action, f.Href = "Open the contract form", "#guide-product"
		f.Command, f.Form = "", ""
	}
	return f
}

// guidePreference is a browser preference only. The regular POST boundary has
// already checked peer, session, Origin, CSRF and governed status.
func (s *Server) guidePreference(w http.ResponseWriter, r *http.Request) {
	show := r.PostForm.Get("show")
	if show != "yes" && show != "no" {
		http.Error(w, "Choose whether to show the guide.", http.StatusBadRequest)
		return
	}
	c := &http.Cookie{Name: "tego-guide", Value: "hidden", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 365 * 24 * 60 * 60}
	dst := "/"
	if show == "yes" {
		c.Value = ""
		c.MaxAge = -1
		dst = "/guide"
	}
	http.SetCookie(w, c)
	http.Redirect(w, r, dst, http.StatusSeeOther)
}
