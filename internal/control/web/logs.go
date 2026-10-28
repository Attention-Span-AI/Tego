// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"strings"
)

// Logs: every ledger line of every run, searched three ways at once. q is a literal substring (the topbar search and
// the event page's "All in Logs" links send it, and it is never parsed, so a path with spaces or a leading - searches
// as written); the form's run, agent, kind, verdict and noise fields; and where, a query in the ledgerview query
// language (kind:exec host:chatgpt.com since:15m -word), which the facets and time presets add tokens to. group shows
// the matched lines gathered by process, target or rule instead of one row each. Every one of these is in the address,
// so a view is saved by keeping its link (static/logs.js also keeps named ones in the browser). The page is a GET form
// and links, so it works with JavaScript off; with it, logs.js adds new lines at the top as they come, older ones in
// place, opens a row in place, and moves through the rows with j and k (logs_rows.go serves its fragments).

// logsRunList is how many runs the Run select lists (the newest; the selected one is added when older): a ledger of
// thousands of runs made every Logs page carry them all.
const logsRunList = 50

func init() {
	funcs["countWord"] = countWord
}

// queryChip is one token of the where query, with the address that drops it.
type queryChip struct {
	Text      string
	RemoveURL string
	Neg       bool
}

// facetItem is one facet value: the address that adds it to the query (or drops it when the query already has it),
// the address that leaves it out, and its count.
type facetItem struct {
	Label, Title string
	Count        int
	AddURL       string
	NotURL       string
	Active       bool
}

// facetGroup is one facet: its heading, its values, and how many values it has beyond those listed.
type facetGroup struct {
	Name  string
	Items []facetItem
	More  int
}

// preset is one time preset or quick search: a link, marked when the page shows it.
type preset struct {
	Label, URL, Title string
	Current           bool
}

type logsData struct {
	Page ledgerview.Page
	// F is the form's own fields (the select and checkboxes show them); Where is the query text and Chips its tokens.
	F         ledgerview.Filter
	Where     string
	Chips     []queryChip
	QueryErr  string
	Runs      []*ledgerview.Run
	RunsMore  int // runs not in the Run select
	Agents    []string
	Verdicts  map[string]bool
	HideSys   bool
	ShowNoise bool
	// ShowNoiseURL is this search with the system reads shown.
	ShowNoiseURL string
	NextURL      string
	Filtered     bool
	// Facets is the matched lines counted by verdict, kind, program, host, rule and run; Times the time presets.
	Facets []facetGroup
	Times  []preset
	// ExportJSONL and ExportCSV download every matching line (logs_export.go). ExportLedger is the run's line count
	// when the search is one whole run and nothing else, so the JSONL is that run's events file; 0 otherwise.
	ExportJSONL, ExportCSV string
	ExportLedger           int
	// ExportLines is how many lines those downloads hold when it is not the whole run: the matched lines and the
	// system reads the page hides, which they keep. ExportMore is those system reads.
	ExportLines, ExportMore int
	// Rows is the page's rows with their links. RowsURL is where logs.js asks for more of them, After the newest
	// row's cursor (the live tail asks for rows after it) and Next the cursor of the older page.
	Rows        []rowView
	RowsURL     string
	After, Next string
	// Group is the grouping shown ("" for lines), GroupTabs the links that switch it, and Grouped its groups.
	Group     string
	GroupTabs []preset
	Grouped   []groupView
	GroupInfo ledgerview.Grouped
	// Presets are the built-in views.
	Presets []preset
	// Changes are the rule-change rows among the page's rows (changefeed.go).
	Changes changesAt
}

// groupView is one group row with the address of its lines.
type groupView struct {
	ledgerview.GroupRow
	// LinesURL is the search narrowed to the group's lines, "" when no query names them (lines with no rule, routine lines).
	LinesURL string
	// NewestURL is the group's newest line.
	NewestURL string
	// Home is the run's home when the group is of one run, for the path shortener; KindWords is a target group's
	// newest line's kind in words.
	Home, KindWords string
}

// groupLimit is how many groups the page lists.
const groupLimit = 200

// logsQuery is a Logs request read: the form's filter, the where query and the two joined.
type logsQuery struct {
	vals  url.Values
	form  ledgerview.Filter
	where string
	toks  []ledgerview.Token
	err   error
	f     ledgerview.Filter // form AND where: what the page and the exports match
}

// onPage is lq as the Logs page reads it: system noise (ledgerview.SystemNoise) hidden unless noise=show. Exports keep
// every line.
func (lq logsQuery) onPage() logsQuery {
	if lq.vals.Get("noise") != "show" {
		lq.form.HideNoise, lq.f.HideNoise = true, true
	}
	return lq
}

// readLogsQuery reads a Logs or export request's parameters, as of now.
func readLogsQuery(q url.Values, now time.Time) logsQuery {
	lq := logsQuery{vals: q, where: q.Get("where")}
	lq.form = ledgerview.Filter{Run: q.Get("run"), Agent: q.Get("agent"), Kind: q.Get("kind"), Text: q.Get("q"),
		HideSys: q.Get("sys") == "hide"}
	for _, v := range q["verdict"] {
		switch v {
		case "refused", "allow", "ask", "observed", "none":
			lq.form.Verdicts = append(lq.form.Verdicts, v)
		}
	}
	var wf ledgerview.Filter
	wf, lq.toks, lq.err = ledgerview.ParseQueryAt(lq.where, now, time.Local)
	lq.f = lq.form.And(wf)
	return lq
}

// with is the Logs address of this request with the where query set to toks (nil keeps it) and the given form
// fields replaced ("" drops one); the page cursor is always dropped.
func (lq *logsQuery) with(path string, toks []ledgerview.Token, set map[string]string) string {
	v := url.Values{}
	for k, xs := range lq.vals {
		if k != "before" && k != "t" && k != "flash" {
			v[k] = slices.Clone(xs)
		}
	}
	if toks != nil {
		set = cloneSet(set)
		set["where"] = ledgerview.FormatQuery(toks)
	}
	for k, x := range set {
		if x == "" {
			v.Del(k)
		} else {
			v.Set(k, x)
		}
	}
	if enc := v.Encode(); enc != "" {
		return path + "?" + enc
	}
	return path
}

func cloneSet(m map[string]string) map[string]string {
	out := make(map[string]string, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// without is lq's tokens without token i; toggled is them with t added, or without it when present.
func (lq *logsQuery) without(i int) []ledgerview.Token {
	out := append(slices.Clone(lq.toks[:i]), lq.toks[i+1:]...)
	if out == nil {
		out = []ledgerview.Token{}
	}
	return out
}

func (lq *logsQuery) toggled(t ledgerview.Token) ([]ledgerview.Token, bool) {
	for i, x := range lq.toks {
		if x.Key == t.Key && x.Value == t.Value && x.Neg == t.Neg {
			return lq.without(i), true
		}
	}
	return append(slices.Clone(lq.toks), t), false
}

// severityVerdicts is the verdict that holds each By severity group that stays in Logs.
var severityVerdicts = map[string]string{"Observed": "observed", "Asked": "ask", "Answered": "none", "Allowed": "allow", "Recorded": "none"}

// severityKinds tells apart the two groups of lines with no verdict, an answer being of kind ask in Logs.
var severityKinds = map[string]ledgerview.Token{"Answered": {Key: "kind", Value: "ask"}, "Recorded": {Key: "kind", Value: "ask", Neg: true}}

// narrowed is lq's tokens with any other verdict replaced by the one that holds a By severity group.
func (lq *logsQuery) narrowed(group string) []ledgerview.Token {
	out := []ledgerview.Token{}
	for _, t := range lq.toks {
		if t.Key != "verdict" {
			out = append(out, t)
		}
	}
	if k, ok := severityKinds[group]; ok && !slices.Contains(out, k) {
		out = append(out, k)
	}
	return append(out, ledgerview.Token{Key: "verdict", Value: severityVerdicts[group]})
}

// withTime is lq's tokens with since and until replaced by since:d ("" drops the time range).
func (lq *logsQuery) withTime(d string) []ledgerview.Token {
	out := []ledgerview.Token{}
	for _, t := range lq.toks {
		if t.Key != "since" && t.Key != "until" {
			out = append(out, t)
		}
	}
	if d != "" {
		out = append(out, ledgerview.Token{Key: "since", Value: d})
	}
	return out
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	lq := readLogsQuery(r.URL.Query(), s.cfg.Now()).onPage()
	f := lq.f
	f.Before, f.PageSize, f.Facets = r.URL.Query().Get("before"), logsPage, true
	vs := map[string]bool{}
	for _, v := range lq.form.Verdicts {
		vs[v] = true
	}
	d := logsData{F: lq.form, Where: lq.where, Agents: snap.Agents(), Verdicts: vs, HideSys: lq.form.HideSys, ShowNoise: !lq.form.HideNoise,
		Filtered: lq.form.Run != "" || lq.form.Agent != "" || lq.form.Kind != "" || lq.form.Text != "" ||
			len(lq.form.Verdicts) > 0 || lq.form.HideSys || len(lq.toks) > 0}
	d.F.PageSize = f.PageSize
	if lq.err != nil {
		d.QueryErr = lq.err.Error()
	}
	d.Runs, d.RunsMore = runChoices(snap.Runs, lq.form.Run)
	d.Page = snap.Query(f)
	d.Rows = s.rowViews(&lq, d.Page.Rows, snap)
	d.RowsURL, d.Next = lq.rowsURL(), d.Page.Next
	if len(d.Page.Rows) > 0 && f.Before == "" {
		d.After = d.Page.Rows[0].Cursor()
	}
	if d.Page.Next != "" {
		d.NextURL = lq.with("/logs", nil, map[string]string{"before": d.Page.Next})
	}
	if g := r.URL.Query().Get("group"); ledgerview.ValidGroup(g) {
		d.Group = g
		d.GroupInfo = snap.Group(lq.f, g, groupLimit, s.signals(snap.Runs).sensitive)
		d.Grouped = groupViews(&lq, d.GroupInfo.Rows, snap)
	}
	d.GroupTabs = groupTabs(&lq, d.Group)
	d.Presets = logsPresets(&lq)
	for i, t := range lq.toks {
		d.Chips = append(d.Chips, queryChip{Text: t.String(), Neg: t.Neg, RemoveURL: lq.with("/logs", lq.without(i), nil)})
	}
	d.Facets = facetGroups(&lq, d.Page.Facets, snap)
	d.Times = timePresets(&lq, snap)
	d.ExportJSONL, d.ExportCSV = lq.with("/logs.jsonl", nil, nil), lq.with("/logs.csv", nil, nil)
	d.ShowNoiseURL = lq.with("/logs", nil, map[string]string{"noise": "show", "sys": ""})
	exp := lq.f
	exp.HideNoise = false // the export links carry no noise filter: they hold every line
	if id, ok := exp.WholeRun(); ok {
		if run := snap.Find(id); run != nil {
			d.ExportLedger = len(run.AllEvents())
		}
	}
	d.ExportMore, d.ExportLines = d.Page.NoiseHidden, d.Page.Matched+d.Page.NoiseHidden
	d.Changes = placed(d.Page.Rows, logsChanges(s.feed(), f, snap), f.Before == "", d.Page.Next == "")
	c := s.chromeOf(snap, "Logs", "logs")
	c.Query = lq.form.Text
	s.render(w, http.StatusOK, "logs", c, d)
}

// runChoices is the runs the Run select lists: the newest logsRunList, and the selected one when it is older; more is
// how many it leaves out.
func runChoices(runs []*ledgerview.Run, selected string) (list []*ledgerview.Run, more int) {
	if len(runs) <= logsRunList {
		return runs, 0
	}
	list = slices.Clone(runs[:logsRunList])
	if selected != "" && !slices.ContainsFunc(list, func(r *ledgerview.Run) bool { return r.ID == selected }) {
		for _, r := range runs[logsRunList:] {
			if r.ID == selected {
				list = append(list, r)
				break
			}
		}
	}
	return list, len(runs) - logsRunList
}

// kindWords names the kinds as Logs groups them.
var kindWords = map[string]string{
	"fs": "Files", "net": "Network", "exec": "Commands", "refused": "Refused lines", "ask": "Asks and answers",
	"run": "Run start and end", "gap": "Notes", "limit": "Limits", "mcp": "MCP tools", "decision": "Steps",
	"ssl_request": "Model requests", "ssl_response": "Model answers",
}

// verdictWords names the verdicts Logs counts.
var verdictWords = map[string]string{
	"refused": "Refused", "allow": "Allowed", "ask": "Asked", "observed": "Observed", "none": "Recorded",
}

// facetGroups is the page's facets in words, each value with its add and leave-out addresses.
func facetGroups(lq *logsQuery, fs *ledgerview.Facets, snap *ledgerview.Snapshot) []facetGroup {
	if fs == nil {
		return nil
	}
	group := func(name, key string, f ledgerview.Facet, label func(string) (string, string)) facetGroup {
		g := facetGroup{Name: name, More: f.Distinct - len(f.Values)}
		for _, v := range f.Values {
			l, title := label(v.Value)
			add, active := lq.toggled(ledgerview.Token{Key: key, Value: v.Value})
			not, _ := lq.toggled(ledgerview.Token{Key: key, Value: v.Value, Neg: true})
			g.Items = append(g.Items, facetItem{Label: l, Title: title, Count: v.Count, Active: active,
				AddURL: lq.with("/logs", add, nil), NotURL: lq.with("/logs", not, nil)})
		}
		return g
	}
	words := func(m map[string]string, key string) func(string) (string, string) {
		return func(v string) (string, string) {
			if w, ok := m[v]; ok {
				return w, key + ":" + v
			}
			return v, key + ":" + v
		}
	}
	out := []facetGroup{
		group("Verdict", "verdict", fs.Verdict, words(verdictWords, "verdict")),
		group("Kind", "kind", fs.Kind, words(kindWords, "kind")),
		group("Program", "prog", fs.Program, func(v string) (string, string) { return v, "prog:" + v }),
		group("Host", "host", fs.Host, func(v string) (string, string) { return v, "host:" + v }),
		group("Rule", "rule", fs.Rule, func(v string) (string, string) { return facetRule(v, fs.WatchedRules[v]) }),
		group("Run", "run", fs.Run, func(v string) (string, string) {
			if r := snap.Find(v); r != nil && r.Agent != "" {
				return r.Agent + " · " + shortRun(v), "run:" + v
			}
			return shortRun(v), "run:" + v
		}),
	}
	return slices.DeleteFunc(out, func(g facetGroup) bool { return len(g.Items) == 0 })
}

// facetRule is a Rule facet value in words and its title. A rule whose every line is of a watched run (tier observe)
// decided none of them: tego watch only recorded them, as their rows say (watchedLabel), so the facet says so too.
func facetRule(v string, watched bool) (label, title string) {
	label, title = ruleName(v), "rule:"+v
	if !watched {
		return label, title
	}
	title += " · no rule decided these lines: their runs were watched, not enforced"
	if v == "unmatched" {
		return "Watched only", title
	}
	return "Watched only · " + label, title
}

// timePresets is the time range links: the last 5 minutes, hour and day, the newest run, and any time.
func timePresets(lq *logsQuery, snap *ledgerview.Snapshot) []preset {
	since := ""
	timed := false
	for _, t := range lq.toks {
		switch t.Key {
		case "since":
			since, timed = t.Value, true
		case "until":
			timed = true
		}
	}
	out := []preset{}
	for _, p := range []struct{ label, d, title string }{
		{"5 min", "5m", "Lines from the last 5 minutes"},
		{"1 hour", "1h", "Lines from the last hour"},
		{"24 hours", "24h", "Lines from the last 24 hours"},
	} {
		out = append(out, preset{Label: p.label, Title: p.title, URL: lq.with("/logs", lq.withTime(p.d), nil),
			Current: since == p.d})
	}
	if len(snap.Runs) > 0 {
		newest := snap.Runs[0]
		out = append(out, preset{Label: "Latest run", Title: "Every line of the newest run, " + newest.ID,
			URL:     lq.with("/logs", lq.withTime(""), map[string]string{"run": newest.ID}),
			Current: lq.form.Run == newest.ID && !timed})
	}
	out = append(out, preset{Label: "Any time", Title: "No time range", URL: lq.with("/logs", lq.withTime(""), nil),
		Current: !timed && lq.form.Run == ""})
	return out
}

// countWord is n with a thin grouping, for the facet counts: 17462 reads 17,462.
func countWord(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// groupTabs is the Lines / By process / By target / By rule switch, each keeping the search.
func groupTabs(lq *logsQuery, cur string) []preset {
	out := []preset{}
	for _, g := range []struct{ by, label, title string }{
		{"", "Lines", "Every matching line, newest first"},
		{ledgerview.GroupProcess, "By process", "The matching lines gathered by process: a pid and the program it ran"},
		{ledgerview.GroupTarget, "By target", "The matching lines gathered by the path, address or command they name"},
		{ledgerview.GroupRule, "By rule", "The matching lines gathered by the rule that decided them"},
		{ledgerview.GroupSeverity, "By severity", "High, Medium, Low and Routine blocks, then observed, asked, answered, allowed and recorded lines"},
	} {
		out = append(out, preset{Label: g.label, Title: g.title, Current: cur == g.by,
			URL: lq.with("/logs", nil, map[string]string{"group": g.by})})
	}
	return out
}

// groupViews gives each group the address of its lines: a process by its run, pid and program, a rule by its key,
// a target by its text (a literal search, so it may also match lines that name a longer target).
func groupViews(lq *logsQuery, rows []ledgerview.GroupRow, snap *ledgerview.Snapshot) []groupView {
	out := make([]groupView, len(rows))
	for i, g := range rows {
		v := groupView{GroupRow: g, KindWords: kindWords[logsKindOf(g.Kind)]}
		if g.NewestRun != "" {
			v.NewestURL = "/runs/" + url.PathEscape(g.NewestRun) + "/lines/" + strconv.FormatUint(g.NewestSeq, 10)
		}
		if g.Run != "" {
			if run := snap.Find(g.Run); run != nil {
				v.Home = ledgerview.RunHome(run)
			}
		}
		set := map[string]string{"group": ""}
		var toks []ledgerview.Token
		switch {
		case g.PID > 0:
			toks = append(slices.Clone(lq.toks), ledgerview.Token{Key: "run", Value: g.Run},
				ledgerview.Token{Key: "pid", Value: strconv.Itoa(g.PID)})
			if g.Program != "" {
				toks = append(toks, ledgerview.Token{Key: "prog", Value: g.Program})
			}
		case g.Severity != "":
			// Blocked severities open Detections, the severity view of blocked actions; the rest stay in Logs, narrowed
			// from the view they were read in.
			switch g.Severity {
			case "High", "Medium", "Low":
				v.LinesURL = "/detections?sev=" + strings.ToLower(g.Severity)
			case "Routine":
				// No query names these lines (LinesURL): verdict:refused, the nearest, lists every blocked line.
			default:
				set["verdict"] = ""
				v.LinesURL = lq.with("/logs", lq.narrowed(g.Severity), set)
			}
			out[i] = v
			continue
		case g.Rule != "":
			toks, _ = lq.toggled(ledgerview.Token{Key: "rule", Value: g.Rule})
		case g.Target != "":
			set["q"] = g.Target
			if lq.form.Text != "" && lq.form.Text != g.Target {
				// The search already has a literal text: the target joins the query as a quoted word instead.
				delete(set, "q")
				toks = append(slices.Clone(lq.toks), ledgerview.Token{Value: g.Target})
			}
		default:
			out[i] = v
			continue
		}
		v.LinesURL = lq.with("/logs", toks, set)
		out[i] = v
	}
	return out
}

// logsPresets is the built-in views: each a search a person often wants, kept in its link.
func logsPresets(lq *logsQuery) []preset {
	out := []preset{}
	for _, p := range []struct{ label, title, q string }{
		{"Refused only", "Every refused line", "verdict=refused"},
		{"Refused connections", "Refused network connections, without the system lookups every program makes",
			"where=" + url.QueryEscape("kind:net verdict:refused") + "&sys=hide"},
		{"Secret files", "Every line about a file the contract never lets the agent read", "where=" + url.QueryEscape("rule:fs.deny_read*")},
		{"Commands", "Every program the agents started or tried to", "where=" + url.QueryEscape("kind:exec")},
		{"Asks", "Every question Tego asked a person, and its answer", "where=" + url.QueryEscape("kind:ask")},
	} {
		u := "/logs?" + p.q
		out = append(out, preset{Label: p.label, Title: p.title, URL: u, Current: lq.vals.Encode() == mustQuery(p.q)})
	}
	return out
}

// mustQuery is q as url.Values encodes it (sorted keys), for comparing a request with a preset.
func mustQuery(q string) string {
	v, err := url.ParseQuery(q)
	if err != nil {
		return ""
	}
	return v.Encode()
}

// logsKindOf is a line kind as Logs groups them (kindWords' keys): run_start and run_end are "run", answer "ask".
func logsKindOf(k string) string {
	switch k {
	case "run_start", "run_end":
		return "run"
	case "answer":
		return "ask"
	}
	return k
}
