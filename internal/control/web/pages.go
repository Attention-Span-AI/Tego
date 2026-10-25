// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/liveblock"
)

var pageNames = []string{"overview", "detections", "investigate", "glossary", "severity", "runs", "run", "logs", "approvals", "error", "stop", "rules", "rule", "machine", "compare", "rules-change", "rules-preview", "rules-saved", "rules-new", "livefence"}

// pageSet is every page's parsed template set, and the layout twin of each (regions.go, layoutTwin) that a full
// page executes so each live region renders once.
type pageSet struct {
	pages map[string]*template.Template
	twins map[*template.Template]*template.Template
}

// parsedPages parses the pages once per process: the sets are read only after they are escaped, so every Server
// shares them.
var parsedPages = sync.OnceValues(func() (*pageSet, error) {
	ps := &pageSet{pages: map[string]*template.Template{}, twins: map[*template.Template]*template.Template{}}
	for _, n := range allPages() {
		t, err := template.New("layout.tmpl").Funcs(funcs).ParseFS(assets, "templates/layout.tmpl", "templates/rulelink.tmpl", "templates/highlights.tmpl", "templates/cmpform.tmpl", "templates/rules-parts.tmpl", "templates/rcrows.tmpl", "templates/charts.tmpl", "templates/"+n+".tmpl")
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", n, err)
		}
		if extra := pageParts[n]; extra != nil {
			if t, err = t.ParseFS(assets, extra...); err != nil {
				return nil, fmt.Errorf("template %s: %w", n, err)
			}
		}
		tw, err := layoutTwin(n, t) // before t executes: a set that has executed cannot be cloned
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", n, err)
		}
		if err := escapeRegions(n, t); err != nil {
			return nil, fmt.Errorf("template %s: %w", n, err)
		}
		ps.pages[n], ps.twins[t] = t, tw
	}
	return ps, nil
})

func parsePages() (map[string]*template.Template, error) {
	ps, err := parsedPages()
	if err != nil {
		return nil, err
	}
	return ps.pages, nil
}

// twinOf is t's layout twin; a set parsed apart (the event page) has none, and its layout renders its regions again.
func twinOf(t *template.Template) (*template.Template, bool) {
	if ps, err := parsedPages(); err == nil && ps.twins[t] != nil {
		return ps.twins[t], true
	}
	return nil, false
}

var funcs = template.FuncMap{
	"layerNav":       layerNav,
	"layerRouteNote": layerRouteNote,
	// sevLevels and sevGroups lay a run's refusal groups out by severity, High first (routine ones are folded apart).
	"sevLevels": func() []ledgerview.Severity {
		return []ledgerview.Severity{ledgerview.SevHigh, ledgerview.SevMedium, ledgerview.SevLow}
	},
	"sevGroups": func(gs []ledgerview.Group, v ledgerview.Severity) []ledgerview.Group {
		var out []ledgerview.Group
		for _, g := range gs {
			if !g.Background && g.Severity == v {
				out = append(out, g)
			}
		}
		return out
	},
	"ruleName": ruleName,
	"lower":    strings.ToLower,
	"baseName": path.Base,
	"fileKind": fileKind,
	// dtab is a detections table's rows and the time they are read at (for "Yesterday 20:58").
	"dtab": func(rows []detection, now time.Time) any {
		return struct {
			Rows []detection
			Now  time.Time
		}{rows, now}
	},
	"logsFor":      logsFor,
	"logsByTarget": logsByTarget,
	"portSpans":    portSpans,
	"someOf":       someOf,
	// presetLabel names a built-in preset by its outcome (ADR 0068's promises, as labels).
	"presetLabel": func(name string) string {
		switch strings.TrimPrefix(name, "tego/") {
		case "no-secrets":
			return "Keep secrets out"
		case "no-prod":
			return "Only hosts I list"
		case "repo-only-writes":
			return "Only write in the project"
		}
		return name
	},
	"clock": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.Local().Format("15:04:05")
	},
	"clockms": func(t time.Time) string { return t.Local().Format("15:04:05.000") },
	"stamp": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Local().Format("2006-01-02 15:04:05.000 MST")
	},
	"iso": func(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) },
	"day": func(t time.Time) string { return t.Local().Format("Mon 2 Jan 2006") },
	// tz names the zone the page shows times in: the machine's local zone, as the person reading it expects.
	"tz":   func() string { return time.Now().Format("MST") },
	"dur":  human,
	"rid":  shortRun,
	"cut":  cutMiddle,
	"tier": tierWord,
	// ckOf is a run's duration for the "ck" template (a ticking clock while it has no end line); runsQuery a Runs
	// page's address.
	"ckOf":      ckOf,
	"runsQuery": runsQuery,
	// endWord is a finished run's status word and endWhy the sentence under it (title and run page).
	"endWord": endWord,
	"endWhy":  endWhy,
	"verdictClass": func(e ledgerview.Event) string {
		switch {
		case e.Refused():
			return "refused"
		case e.Verdict == "allow":
			return "allowed"
		case e.Verdict == "ask":
			return "asked"
		case e.Verdict == "observed":
			return "observed"
		}
		return "neutral"
	},
	"verdictWord": func(e ledgerview.Event) string {
		switch {
		case e.Refused():
			return "Blocked"
		case e.Verdict == "allow":
			return "Allowed"
		case e.Verdict == "ask":
			return "Asked"
		case e.Verdict == "observed":
			return "Observed"
		}
		return "Recorded"
	},
	"verdictIcon": func(e ledgerview.Event) string {
		switch {
		case e.Refused():
			return "i-ban"
		case e.Verdict == "allow":
			return "i-check"
		case e.Verdict == "ask":
			return "i-hand"
		}
		return "i-eye"
	},
	"kindIcon": func(k string) string {
		switch k {
		case "fs":
			return "i-scroll-text"
		case "exec":
			return "i-terminal"
		case "net":
			return "i-activity"
		case "ask", "answer":
			return "i-hand"
		case "refused":
			return "i-ban"
		case "run_start", "run_end":
			return "i-square"
		}
		return "i-eye"
	},
	"reasonText": reasonText,
	"foldKey":    foldKey,
	"dict2":      func(runs []*ledgerview.Run, now time.Time) runTable { return runTable{Runs: runs, Now: now} },
	"pathEsc":    url.PathEscape,
	"queryEsc":   url.QueryEscape,
	"acts":       rowActsOf,
	"answerChip": answerChip,
	"tl":         tlOf,
	"askForm": func(a ledgerview.Ask, csrf string) map[string]any {
		// A stand-in file answers only a held file open (op read under fs.ask_read, or open): ADR 0057. A held read's
		// ask line may follow no verdict line, so its card can carry the hold (open) and no op.
		file := func(s string) bool { return s == "read" || s == "open" }
		return map[string]any{"Run": a.Run, "AskID": a.AskID, "CSRF": csrf, "Alternate": file(a.Op) || (a.Op == "" && file(a.Hold)),
			"Verb": askVerb(a.Op, a.Rule, a.Hold)}
	},
	"askVerb": askVerb,
	// card hands the askcard template one waiting request, the form token, whether to name its run, what is known of
	// the run (an askMeta from chrome.AskMeta, or its bare harness name: the note on how long the request waits and
	// the home its path is shortened against) and the time the page was read (for "asked 8 s ago").
	"card": func(a ledgerview.Ask, csrf string, show bool, run any, now time.Time) map[string]any {
		m := metaOf(run)
		return map[string]any{"V": a, "CSRF": csrf, "Show": show, "Harness": m.Harness, "Home": m.Home, "Cwd": m.Cwd,
			"Wait": waitOf(m, a.TS, now), "Now": now}
	},
	// wait is a waiting request's note on how long it is held (askWait), for the banner's rows.
	"wait":      waitOf,
	"askObject": askObject,
	"tilde":     tilde,
	"who":       who,
	"shown":     shown,
	"mask":      mask,
	"splitAsks": splitAsks,
	"shownOp":   shownOp,
	"blockWhat": blockWhat,
	"logsURL":   logsURL,
	"secretWhy": secretWhy,
	"tail":      tailCut,
	// firstPart is a rule label up to its " · " detail (the full label goes in a title).
	"firstPart": func(s string) string { a, _, _ := strings.Cut(s, " · "); return a },
	"join":      strings.Join,
	"baseNames": baseNames,
	// bind hands a sub-template the run id with one value (.Run and .V).
	"bind": func(run string, v any) map[string]any { return map[string]any{"Run": run, "V": v} },
	// refRow is one of the Overview's refusals (refrow): its run's home, the row, and its program fold if it has one.
	"refRow": func(home string, v ledgerview.Row, folds map[string]progFold) map[string]any {
		return map[string]any{"Run": home, "V": v, "Fold": folds[refKey(v)]}
	},
	"plural": func(n int, one, many string) string {
		if n == 1 {
			return one
		}
		return many
	},
}

type runTable struct {
	Runs []*ledgerview.Run
	Now  time.Time
	// V is each run's verdict, for the Secrets column (story.go); a run missing from it shows none.
	V map[string]ledgerview.Verdict
}

// clockDur is a run's duration as the "ck" template writes it. Ticks is a running run, whose duration is the wall
// clock's now minus Start (ledgerview.Run.Duration): live.js ticks it from Start every second, and its text stays out
// of the region's hash (regions.go, hashRegion). A lost run has stopped, so its time does not tick.
type clockDur struct {
	Ticks bool
	Start time.Time
	D     time.Duration
}

// ckOf is run r's duration at now for the "ck" template.
func ckOf(r *ledgerview.Run, now time.Time) clockDur {
	return clockDur{Ticks: !r.Start.IsZero() && r.State() == "running", Start: r.Start, D: r.Duration(now)}
}

// human is a duration in the design's words: 48 m 24 s, 12 h 0 m, 3 s.
func human(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Second:
		return fmt.Sprintf("%d ms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d m %d s", int(d.Minutes()), int(d.Seconds())%60)
	case d < 72*time.Hour:
		return fmt.Sprintf("%d h %d m", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%d d %d h", int(d.Hours())/24, int(d.Hours())%24)
}

func shortRun(id string) string {
	// r-<host>-<time>-<random>: the host part is the same for every run of a machine, so the short form keeps the
	// random tail.
	if i := strings.LastIndexByte(id, '-'); i > 1 && len(id)-i-1 >= 4 {
		return "r-…" + id[i+1:]
	}
	return id
}

func cutMiddle(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	h := n * 2 / 3
	return string(r[:h]) + "…" + string(r[len(r)-(n-h-1):])
}

// endWord is the status word of an ended run, from its run_end reason: Stopped is a run ended by tego stop or the
// dashboard's Stop; an exit keeps its code.
func endWord(r *ledgerview.Run) string {
	switch r.EndReason {
	case "exit":
		return "Exit " + strconv.Itoa(r.ExitCode)
	case "stopped":
		return "Stopped"
	case "signal":
		if r.Signal != 0 {
			return "Ended by " + signalName(r.Signal)
		}
		return "Ended by a signal"
	case "oom":
		return "Out of memory"
	case "pids":
		return "Too many processes"
	case "limit":
		return "Hit a limit"
	case "exec-failed":
		return "Could not start"
	case "orphaned":
		return "Orphaned"
	case "error":
		return "Tego error"
	case "":
		return "Ended"
	}
	return r.EndReason
}

// signalName is a signal's name when it is one a run ends on, else "signal N".
func signalName(n int) string {
	if s, ok := map[int]string{1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 6: "SIGABRT", 9: "SIGKILL", 11: "SIGSEGV", 15: "SIGTERM"}[n]; ok {
		return s
	}
	return "signal " + strconv.Itoa(n)
}

// endWhy says in a sentence what an ended run's word means, for the badge's title and the run page.
func endWhy(r *ledgerview.Run) string {
	switch r.EndReason {
	case "exit":
		if r.ExitCode == 0 {
			return "The agent finished and exited with code 0."
		}
		return "The agent exited with code " + strconv.Itoa(r.ExitCode) + ", which usually means it failed."
	case "stopped":
		if r.StoppedBy != "" {
			return "Stopped on request by " + r.StoppedBy + " (tego stop or the dashboard's Stop)."
		}
		return "Stopped on request (tego stop or the dashboard's Stop)."
	case "signal":
		if r.Signal == 1 {
			return "SIGHUP ended the agent: its terminal was closed or hung up."
		}
		return "A signal ended the agent."
	case "oom":
		return "The run used more memory than its limit and was ended."
	case "pids":
		return "The run started more processes than its limit and was ended."
	case "limit":
		return "The run reached a limit of its contract and was ended."
	case "exec-failed":
		return "The agent's program could not be started."
	case "orphaned":
		return "The run's supervisor was gone; Tego closed the run afterwards, and the record's last lines may be missing."
	case "error":
		return "Tego ended the run on an internal error."
	}
	return ""
}

// tierWord is a protection level's name: Basic, Strong, Strongest (tier 1 to 3), or Watched only.
func tierWord(t string) string {
	switch t {
	case "1", "tier1", "tier-1", "landlock":
		return "Basic"
	case "2", "tier2", "tier-2", "cgroup":
		return "Strong"
	case "3", "tier3", "tier-3", "bpflsm":
		return "Strongest"
	case "observe":
		return "Watched only"
	case "":
		return "—"
	}
	return t
}

// reasonText is the short label for a reason code (spec/reason/REASON-CHANNEL.md's set).
func reasonText(code string) string {
	switch code {
	case "write-outside-contract":
		return "Write outside policy"
	case "delete-outside-contract", "rename-outside-contract", "mkdir-outside-contract":
		return "Change outside policy"
	case "read-denied":
		return "Read blocked"
	case "path-unresolved":
		return "Unresolved path"
	case "exec-not-allowed":
		return "Program blocked"
	case "net-not-allowed":
		return "Connection blocked"
	case "net-http":
		return "Request blocked"
	case "fs-gate", "exec-gate", "net-gate":
		return "Blocked by a gate"
	case "ask-denied":
		return "Denied"
	case "ask-timeout":
		return "No answer"
	case "ask-unavailable", "ask-unreadable":
		return "The question could not be asked"
	case "limit-tokens", "limit-cost", "limit-wall", "limit-stall", "limit-repeats":
		return "A run limit was reached"
	case "oom":
		return "Out of memory"
	case "pids":
		return "Too many processes"
	case "":
		return ""
	}
	return code
}

// chrome is what every page's layout reads.
type chrome struct {
	Title  string
	Nav    string
	Host   string
	Ledger string
	Live   bool
	// Preview is Config.Preview: the nav lists the pages a first run leaves empty.
	Preview bool
	Pending int
	// Asks are the waiting asks the banner at the top of every page offers to answer (the first maxBanner).
	Asks []ledgerview.Ask
	// AskMeta is each run with a waiting ask's harness, home and ask timeout (askMeta): the banner, Waiting on you
	// and the ask cards shorten the path against the run's home and say how long the request is held.
	AskMeta map[string]askMeta
	// Now is the time the page was read, for the banner's "has likely given up" (askWait).
	Now time.Time
	// Refresh is the meta refresh a page keeps when JavaScript is off; static/live.js replaces it with in-place
	// updates of the page's live regions (regions.go). Sig and Rev are the live state at render time (live.go); a
	// page without them is one live.js leaves alone.
	Refresh  int
	Sig, Rev string
	Notes    []string
	Query    string
	// CSRF is the session's token, which every form that changes something carries.
	CSRF string
	// Flash is the line the action just taken left for this page (flash.go), nil on every other view.
	Flash *flash
}

type page struct {
	chrome
	Data any
	// L is the page's live regions, each rendered once with its hash (regions.go); the layout and the page's
	// template place them with {{template "live" (index $.L "<region>")}}.
	L map[string]*liveRegion
}

func (s *Server) render(w http.ResponseWriter, status int, name string, c chrome, data any) {
	c.Host, c.Ledger, c.CSRF, c.Preview = s.host, s.cfg.Ledger, s.csrf, s.cfg.Preview
	if fw, ok := w.(*flashWriter); ok {
		c.Flash = fw.flash
	}
	renderPage(w, status, s.pages[name], name, page{chrome: c, Data: data})
}

// renderPage writes page name of template set t: the page, or, for a region request (fragWriter), its changed live
// regions.
func renderPage(w http.ResponseWriter, status int, t *template.Template, name string, p page) {
	if fw, ok := w.(*fragWriter); ok {
		renderRegions(fw, status, t, name, p)
		return
	}
	var err error
	if p.L, err = regions(t, name, p, nil); err != nil {
		http.Error(w, "tego-control serve: render: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if tw, ok := twinOf(t); ok {
		var out bytes.Buffer
		err := tw.ExecuteTemplate(&out, "layout", p)
		if err == nil {
			err = spliceRegions(&buf, out.Bytes(), p.L)
		}
		if err != nil {
			http.Error(w, "tego-control serve: render: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else if err := t.ExecuteTemplate(&buf, "layout", p); err != nil {
		http.Error(w, "tego-control serve: render: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(visibleHTML(buf.Bytes()))
}

// maxBanner is how many waiting asks the banner shows; the rest are a link to Approvals.
const maxBanner = 3

func (s *Server) chromeOf(snap *ledgerview.Snapshot, title, nav string) chrome {
	c := chrome{Title: title, Nav: nav, Now: s.cfg.Now()}
	for _, r := range snap.Runs {
		if r.Live {
			c.Live = true
		}
	}
	c.Asks = snap.Pending()
	c.Pending = len(c.Asks)
	c.AskMeta = s.askMetas(snap, c.Asks)
	if len(c.Asks) > maxBanner {
		c.Asks = c.Asks[:maxBanner]
	}
	st := stateOf(snap)
	c.Sig, c.Rev = st.Sig, st.Rev
	if snap.RunsCut {
		c.Notes = append(c.Notes, fmt.Sprintf("Showing the newest %d of %d runs.", ledgerview.MaxRuns, snap.TotalRuns))
	}
	if snap.LinesCut {
		c.Notes = append(c.Notes, fmt.Sprintf("Read the first %d ledger lines of this request; older or later lines of long runs are not shown.", ledgerview.MaxLines))
	}
	return c
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == "/":
		s.overview(w, r)
	case p == "/detections":
		s.detections(w, r)
	case p == "/glossary":
		s.glossary(w, r)
	case p == "/severity":
		s.severity(w, r)
	case p == "/runs":
		s.runs(w, r)
	case p == "/status.json":
		s.status(w, r)
	case p == "/events":
		s.events(w, r)
	case strings.HasPrefix(p, "/runs/") && strings.HasSuffix(p, "/rows"):
		s.rows(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/runs/"), "/rows"))
	case strings.HasPrefix(p, "/runs/") && strings.HasSuffix(p, "/stop"):
		s.stopConfirm(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/runs/"), "/stop"))
	case strings.HasPrefix(p, "/runs/") && strings.Contains(p, "/investigate/"):
		s.investigate(w, r)
	case strings.HasPrefix(p, "/runs/") && strings.Contains(p, "/lines/"):
		s.eventDetail(w, r)
	case strings.HasPrefix(p, "/runs/") && strings.HasSuffix(p, "/lift"):
		s.liftPreview(w, r, strings.TrimSuffix(strings.TrimPrefix(p, "/runs/"), "/lift"))
	case strings.HasPrefix(p, "/runs/"):
		s.run(w, r, strings.TrimPrefix(p, "/runs/"))
	case p == "/logs":
		s.logs(w, r)
	case p == "/logs/rows":
		s.logsRows(w, r)
	case p == "/logs/line":
		s.logsLine(w, r)
	case p == "/logs.jsonl":
		s.logsJSONL(w, r)
	case p == "/logs.csv":
		s.logsCSV(w, r)
	case p == "/approvals":
		s.approvals(w, r)
	case p == "/rules":
		s.rules(w, r)
	case p == "/rules/change", p == "/rules/change/preview", p == "/rules/change/saved":
		s.rulesChange(w, r)
	case p == "/rules/new":
		s.rulesNew(w, r)
	case p == "/rule":
		s.rulePage(w, r)
	case p == "/compare":
		s.compare(w, r)
	case p == "/machine":
		s.machine(w, r)
	default:
		if !s.layerGet(w, r) {
			s.fail(w, http.StatusNotFound, "Not found", "There is no page at this address.")
		}
	}
}

func (s *Server) load(w http.ResponseWriter) (*ledgerview.Snapshot, bool) {
	snap, err := ledgerview.Load(s.cfg.Ledger)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "The ledger could not be read", err.Error())
		return nil, false
	}
	return snap, true
}

type errorData struct{ Heading, Text string }

func (s *Server) fail(w http.ResponseWriter, status int, heading, text string) {
	s.render(w, status, "error", chrome{Title: heading}, errorData{heading, text})
}

type overviewData struct {
	Live     []*ledgerview.Run
	Recent   []*ledgerview.Run
	Refusals []ledgerview.Row
	// Background are the refusals the run page's Highlights call background (ledgerview.Signal), folded under
	// Refusals; BgLines counts them all, Background lists the newest few.
	Background []ledgerview.Row
	BgLines    int
	Pending    []ledgerview.Ask
	Total      int
	Refused    int
	Now        time.Time
	SysRefuse  int
	Chain      ledgerview.LedgerChain
	MaxChain   int
	// V is each run's verdict, Leaked the runs whose verdict is a leak and Watched the runs whose verdict is
	// VerdictWatched: nothing says those went well, so the headline never reads All quiet over one. Matter and BgTotal
	// split the refused lines the way the run pages do (ledgerview.Signal: the ones that matter, the background ones).
	// Homes is each listed refusal's run home, for the path shortener. CmpURL compares the newest watched run with the
	// newest enforced one, "" without both.
	V               map[string]ledgerview.Verdict
	Leaked, Watched int
	Matter, BgTotal int
	Homes           map[string]string
	CmpURL          string
	// Folds are the listed refusals that stand for one program refused under several paths (progFold), by row key.
	Folds map[string]progFold
	// Charts are the tiles' sparklines and the two bars under them (ovcharts.go).
	Charts ovCharts
	// Grid is the detections counted by severity and channel; Top the newest High and Medium ones (detections.go).
	Grid sevGrid
	Top  []detection
}

// sevGrid is the Overview's figure: blocked actions that are not routine, by severity (rows) and channel (columns).
type sevGrid struct {
	Channels []string
	Rows     []sevRow
	High     int
	Medium   int
	Total    int
}

// sevRow is one severity's counts, one per channel, and their sum.
type sevRow struct {
	Sev   string
	Cells []int
	Sum   int
}

// gridOf counts all by severity and channel.
func gridOf(all []detection) sevGrid {
	g := sevGrid{Channels: []string{"Files", "Programs", "Network"}}
	for _, sev := range []ledgerview.Severity{ledgerview.SevHigh, ledgerview.SevMedium, ledgerview.SevLow} {
		row := sevRow{Sev: sev.String(), Cells: make([]int, len(g.Channels))}
		for _, x := range all {
			if x.Severity != sev {
				continue
			}
			row.Cells[slices.Index(g.Channels, x.Channel)]++
			row.Sum++
		}
		g.Rows = append(g.Rows, row)
		g.Total += row.Sum
	}
	g.High, g.Medium = g.Rows[0].Sum, g.Rows[1].Sum
	return g
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	d := overviewData{Now: s.cfg.Now(), Total: len(snap.Runs), Pending: snap.Pending()}
	for _, r := range snap.Runs {
		// Recent runs are the newest runs not running: a running run is under Running now, so its new lines move one
		// table, not two (each a live region of its own, regions.go).
		if r.Live {
			d.Live = append(d.Live, r)
		} else if len(d.Recent) < 8 {
			d.Recent = append(d.Recent, r)
		}
		d.Refused += r.Refusals
		d.SysRefuse += r.SysRefusals // counted as Refusals is, a mirror with its action
	}
	sigs := s.signals(snap.Runs) // one Signal per run for the whole page
	d.Refusals, d.Background, d.BgLines, d.Folds = s.overviewRefusals(snap, sigs, 8)
	s.labelRows(d.Refusals)
	s.labelRows(d.Background)
	relabelLive(d.Refusals, snap.Find)
	relabelLive(d.Background, snap.Find)
	s.overviewStory(snap, sigs, &d)
	d.Charts = overviewCharts(snap.Runs, d.V)
	all, _ := s.detectionList(snap, sigs)
	d.Grid = gridOf(all)
	for _, x := range all {
		if x.Severity >= ledgerview.SevMedium && len(d.Top) < 6 {
			d.Top = append(d.Top, x)
		}
	}
	d.Chain, d.MaxChain = ledgerview.VerifySnapshot(r.Context(), snap, s.cfg.Anchor), ledgerview.MaxChainRuns
	c := s.chromeOf(snap, "Overview", "overview")
	if c.Live {
		c.Refresh = 5
	}
	s.render(w, http.StatusOK, "overview", c, d)
}

// runsData is the Runs page: the running runs (on the first page only), then a page of the others, newest first.
type runsData struct {
	// Live are the running runs that match State, shown above the others on the first page; Runs is this page of
	// the others (ended and lost), newest first.
	Live, Runs []*ledgerview.Run
	// All is every run, for the Compare chooser.
	All   []*ledgerview.Run
	State string
	Count map[string]int
	Now   time.Time
	V     map[string]ledgerview.Verdict
	// Before is this page's cursor ("" on the first page): the others start after the run with that id. Older is the
	// next page's ("" when this is the last), and From, To and Rest place the page among the Rest others (1-based).
	Before, Older  string
	From, To, Rest int
}

// runsPage is how many runs other than the running ones a page of Runs lists; "Older runs" pages back by run id.
const runsPage = 100

// runsQuery is the address of a Runs page: the state filter and the cursor, either one left out when empty.
func runsQuery(state, before string) string {
	q := url.Values{}
	if state != "" {
		q.Set("state", state)
	}
	if before != "" {
		q.Set("before", before)
	}
	if len(q) == 0 {
		return "/runs"
	}
	return "/runs?" + q.Encode()
}

func (s *Server) runs(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	q := r.URL.Query()
	d := runsData{State: q.Get("state"), Before: q.Get("before"), Count: map[string]int{}, Now: s.cfg.Now(), All: snap.Runs}
	var live, rest []*ledgerview.Run
	for _, run := range snap.Runs {
		st := run.State()
		d.Count[st]++
		switch {
		case d.State != "" && d.State != st:
		case st == "running":
			live = append(live, run)
		default:
			rest = append(rest, run)
		}
	}
	d.Count["all"] = len(snap.Runs)
	start := 0
	if d.Before != "" {
		// A cursor whose run left the snapshot (evicted, deleted) starts again at the newest page.
		if i := slices.IndexFunc(rest, func(x *ledgerview.Run) bool { return x.ID == d.Before }); i >= 0 {
			start = i + 1
		} else {
			d.Before = ""
		}
	}
	if d.Before == "" {
		d.Live = live
	}
	end := min(start+runsPage, len(rest))
	d.Runs, d.From, d.To, d.Rest = rest[start:end], start+1, end, len(rest)
	if end < len(rest) {
		d.Older = rest[end-1].ID
	}
	d.V = s.verdicts(snap.Runs, slices.Concat(d.Live, d.Runs))
	c := s.chromeOf(snap, "Runs", "runs")
	if c.Live {
		c.Refresh = 5
	}
	s.render(w, http.StatusOK, "runs", c, d)
}

type runData struct {
	Run      *ledgerview.Run
	Tab      string
	Lines    []ledgerview.Row
	Refusals []ledgerview.Row
	Now      time.Time
	Shown    int
	Kinds    []kindCount
	Verdict  string
	// Total is the timeline's row count. Before is this page's cursor (0 on the newest page), Older the next page's
	// (0 when there is none), After the run's last line read, which a live page polls after.
	Total                int
	Before, Older, After uint64
	// Rows is the unfiltered timeline's row count, the number its tab and its All chip show: one per refusal and
	// per folded group, so it agrees with the rows below it (the receipt counts lines).
	Rows  int
	Chain ledgerview.Chain
	// Blocks are the run's live blocks; BlockErr says why they could not be read. Live is what each one does to the
	// run now (livechip.go): the run's live facts and the blocks' serials.
	Blocks     []liveblock.Entry
	BlockErr   string
	BlockKinds []liveblock.Kind
	Live       liveView
	// BlockKind and BlockValue prefill the Block now form (the Block link on a timeline row sets them).
	BlockKind, BlockValue string
	// Learn and Drift are the Least privilege and Unused permissions tabs, read only when one is open. On an
	// enforced run Least privilege reads Drift too: Cut is the grants to remove and Keep the protections it keeps.
	Learn     *rulesview.Learned
	Drift     *rulesview.Drifted
	Keep, Cut []string
	// Signal is the Highlights card and the grouped refusals; View is "lines" for the Refusals tab's every-line
	// view; BgOpen opens its Background fold.
	Signal *ledgerview.RunSignal
	View   string
	BgOpen bool
	// Changes are the rule-change rows among the timeline's (changefeed.go), on its unfiltered pages.
	Changes changesAt
	// Receipt is the Receipt tab's, from internal/check/receipt, read only when that tab is open.
	Receipt *receiptView
	// Procs is the Processes tab's tree (procs.go), built only when that tab is open.
	Procs *procsView
	// Stopping is a live run a stop was asked of (its stop marker is in place): the header says Stopping, not Stop.
	Stopping bool
	// Story is the run's verdict (the banner above Highlights) and Home its home for the path shortener.
	Story ledgerview.Verdict
	Home  string
	// Withheld are the leak destinations the Least privilege proposal leaves out (rulesview.Withhold).
	Withheld []string
	// Adjustable is a run whose run_start says live_mode adjustable (ADR 0125): its head shows the mode's chip.
	Adjustable bool
}

type kindCount struct {
	Kind string
	N    int
}

func (s *Server) run(w http.ResponseWriter, r *http.Request, id string) {
	tab := "timeline"
	if i := strings.IndexByte(id, '/'); i >= 0 {
		id, tab = id[:i], id[i+1:]
	}
	if tab == "least-privilege.yaml" {
		s.downloadProposal(w, r, id)
		return
	}
	if !slices.Contains([]string{"timeline", "refusals", "processes", "receipt", "least-privilege", "unused"}, tab) {
		s.fail(w, http.StatusNotFound, "Not found", "A run page has the tabs timeline, refusals, processes, receipt, least-privilege and unused.")
		return
	}
	run, err := ledgerview.LoadRun(s.cfg.Ledger, id)
	if errors.Is(err, os.ErrNotExist) {
		s.fail(w, http.StatusNotFound, "No such run", "No run "+id+" is in this ledger root.")
		return
	}
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "The run could not be read", err.Error())
		return
	}
	snap, ok := s.load(w)
	if !ok {
		return
	}
	d := runData{Run: run, Tab: tab, Now: s.cfg.Now(), Refusals: ledgerview.RunRefusals(run), Verdict: r.URL.Query().Get("verdict"),
		Chain: ledgerview.VerifyRun(r.Context(), s.cfg.Ledger, id, s.cfg.Anchor, run)}
	d.BlockKinds = liveblock.Kinds
	if k, err := liveblock.ParseKind(r.URL.Query().Get("block")); err == nil {
		if v := r.URL.Query().Get("value"); len(v) <= liveblock.MaxValueBytes {
			d.BlockKind, d.BlockValue = string(k), v
		}
	}
	switch tab {
	case "processes":
		d.Procs = procsFor(s.cfg.Ledger, run, d.Now)
	case "receipt":
		d.Receipt = loadReceipt(r.Context(), s.cfg.Ledger, id)
	case "least-privilege":
		d.Learn = rulesview.Learn(r.Context(), s.cfg.Ledger, s.cfg.Anchor, id)
		if run.Tier != "observe" {
			d.Drift = rulesview.Drift(r.Context(), s.cfg.Ledger, id, rulesview.Options{Machine: s.cfg.Machine, Anchor: s.cfg.Anchor})
			d.Keep, d.Cut = keepOf(rulesview.RunLists(s.cfg.Ledger, id)), cutOf(d.Drift)
		}
	case "unused":
		d.Drift = rulesview.Drift(r.Context(), s.cfg.Ledger, id, rulesview.Options{Machine: s.cfg.Machine, Anchor: s.cfg.Anchor})
	}
	d.Stopping = run.Live && runact.Stopping(s.cfg.Ledger, id)
	d.Adjustable = ledgerview.LiveFactsOf(run).Adjustable
	// The live facts (one pass over the run's lines per version) serve only the Block now panel and the head's
	// button, which show while the run runs; an ended run skips them. The overlay is still read for its blocks.
	if run.State() == "running" {
		d.Live.Facts = ledgerview.LiveFactsOf(run)
		d.Live.Pause = pauseAskOf(runact.PauseRequest(s.cfg.Ledger, id), d.Live.Facts)
	}
	if lb, err := runact.Live(s.cfg.Ledger, id); err != nil {
		d.BlockErr = err.Error()
	} else {
		d.Blocks, d.Live.Serials, d.Live.Serial = lb.Blocks, lb.Serials, lb.Serial
		d.Live.Now = s.cfg.Now()
	}
	// The timeline reads newest first, with identical refusals folded, so a live run's latest action is at the top.
	// It shows timelinePage rows at a time and "Older" pages back by seq (?before=<seq>), so a new line never shifts
	// a page; a live run's newest page adds its new rows itself (static/live.js fetching /runs/<id>/rows).
	tl := s.timelineOf(snap.Runs, run, d.Verdict)
	d.Total, d.After = tl.Len(), lastSeq(run)
	d.Rows = d.Total
	if d.Verdict != "" {
		d.Rows = timeline(run, "").Len()
	}
	start := 0
	if b, err := strconv.ParseUint(r.URL.Query().Get("before"), 10, 64); err == nil {
		d.Before = b
		start = tl.Below(b)
	}
	rows := tl.Rows(start, start+timelinePage)
	if tl.Len()-start > timelinePage {
		d.Older = rows[len(rows)-1].Seq
	}
	lists := rulesview.RunLists(s.cfg.Ledger, id)
	d.Signal = s.signalOf(snap.Runs, run)
	d.Story, d.Home = ledgerview.RunVerdict(run, d.Signal), ledgerview.RunHome(run)
	if tab == "least-privilege" && d.Learn != nil && d.Learn.Err == "" && d.Story.Kind == ledgerview.VerdictLeak {
		// A contract made from a run that leaked never allows where its secrets went (QA PW-1). Learned is the
		// shared cache's value, so the withheld text goes on a copy.
		l := *d.Learn
		l.Text, d.Withheld = rulesview.Withhold(l.Text, d.Story.Dests)
		d.Learn = &l
	}
	blocks := blockLabels(run)
	for i := range d.Signal.Groups {
		g := &d.Signal.Groups[i]
		g.Label = ruleLabel(g.Event, lists)
		if l, ok := blocks[g.Rule]; ok {
			g.Label = l
		}
	}
	d.View, d.BgOpen = r.URL.Query().Get("view"), r.URL.Query().Get("bg") == "open"
	for i := range rows {
		rows[i].Label = ruleLabel(rows[i].Event, lists)
		watchLabel(&rows[i], run)
	}
	for i := range d.Refusals {
		d.Refusals[i].Label = ruleLabel(d.Refusals[i].Event, lists)
	}
	relabelLive(rows, func(string) *ledgerview.Run { return run })
	relabelLive(d.Refusals, func(string) *ledgerview.Run { return run })
	d.Lines, d.Shown = rows, len(rows)
	if d.Verdict == "" {
		d.Changes = placed(rows, changesOfRun(s.feed(), run), d.Before == 0, d.Older == 0)
	}
	for _, k := range []string{"exec", "fs", "net", "refused", "ask", "answer", "gap", "limit", "mcp", "decision"} {
		if n := run.Kinds[k]; n > 0 {
			d.Kinds = append(d.Kinds, kindCount{k, n})
		}
	}
	title := run.Agent
	if title == "" {
		title = id
	}
	c := s.chromeOf(snap, title+" · run", "runs")
	// This run's asks are on this page in full (the ask cards above Highlights): the banner keeps only other runs'.
	// While this run has a card, no banner at all: the banner floats over the top of the page (mvp.css) and must never
	// cover the card's Allow once or Deny; the nav's Approvals count still says how many wait elsewhere.
	c.Asks = slices.DeleteFunc(slices.Clone(snap.Pending()), func(a ledgerview.Ask) bool { return a.Run == id })
	c.Asks = c.Asks[:min(len(c.Asks), maxBanner)]
	if slices.ContainsFunc(snap.Pending(), func(a ledgerview.Ask) bool { return a.Run == id }) {
		c.Asks = nil
	}
	if run.Live && d.Before == 0 {
		// The timeline adds its own rows and the rest of the page updates its live regions in place (live.js); the
		// meta refresh is for a browser without JavaScript.
		c.Refresh = 3
	}
	if run.Cut {
		c.Notes = append(c.Notes, fmt.Sprintf("This run has more than %d lines; the first %d are shown.", ledgerview.MaxLines, ledgerview.MaxLines))
	}
	s.render(w, http.StatusOK, "run", c, d)
}

type approvalsData struct {
	Pending []ledgerview.Ask
	Now     time.Time
	// Recent is the newest answers, from every run; Lost is the asks of runs that crashed before anyone answered.
	Recent []answered
	Lost   []ledgerview.Ask
	// Homes is the home of each run Recent and Lost list, and Cwds its working directory, so their paths read ~/… and
	// ./… as the cards' do. (The cards' harness, home and timeout come from chrome.AskMeta.)
	Homes, Cwds map[string]string
	// Tab is "" (Waiting) or "history"; Sessions is History's answers by run, newest run first, and Answers how many.
	Tab      string
	Sessions []answerSession
	Answers  int
}

// answerSession is one run's answers on the History tab.
type answerSession struct {
	Run, Agent, Project string
	Start               time.Time
	Allowed, Denied     int
	Answers             []answered
}

// recentAnswers is how many answers Approvals lists under "Answered recently"; historyAnswers how many History reads.
const (
	recentAnswers  = 8
	historyAnswers = 200
)

func (s *Server) approvals(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	c := s.chromeOf(snap, "Approvals", "approvals")
	if c.Live {
		c.Refresh = 5
	}
	d := approvalsData{Pending: snap.Pending(), Now: s.cfg.Now(), Recent: answersOf(snap, recentAnswers), Lost: snap.Lost(),
		Homes: map[string]string{}, Cwds: map[string]string{}}
	roots := func(run string) {
		r := snap.Find(run)
		d.Homes[run] = ledgerview.RunHome(r)
		if r != nil {
			d.Cwds[run] = r.Cwd
		}
	}
	for _, a := range d.Recent {
		roots(a.Run)
	}
	for _, a := range d.Lost {
		roots(a.Run)
	}
	all := answersOf(snap, historyAnswers)
	d.Answers = len(all)
	if r.URL.Query().Get("tab") == "history" {
		d.Tab = "history"
		at := map[string]int{}
		for _, a := range all { // newest first, so each run's first answer places it
			i, ok := at[a.Run]
			if !ok {
				i = len(d.Sessions)
				at[a.Run] = i
				ses := answerSession{Run: a.Run, Agent: a.Agent}
				if run := snap.Find(a.Run); run != nil {
					ses.Project, ses.Start = path.Base(run.Cwd), run.Start
				}
				d.Sessions = append(d.Sessions, ses)
				roots(a.Run)
			}
			ses := &d.Sessions[i]
			ses.Answers = append(ses.Answers, a)
			if a.Approved {
				ses.Allowed++
			} else {
				ses.Denied++
			}
		}
	}
	s.render(w, http.StatusOK, "approvals", c, d)
}

// tlRows is what the "tlrows" template renders: timeline rows, whether the run is live (its rows offer Block), and
// whether it names a contract file (its refusals and asks offer Rule).
type tlRows struct {
	Rows     []ledgerview.Row
	Live     bool
	Contract bool
	// Changes are the rule-change rows among them (changefeed.go).
	Changes changesAt
}

// rowActs is what a timeline or log row offers beside its verdict: Block, the link that opens the run page's Block
// now panel with the program or destination filled in ("" when the row offers none), and the Rule link (the event)
// when Rule is set.
type rowActs struct {
	E     ledgerview.Event
	Block string
	Rule  bool
}

// hostDst matches a net row's target "host (ip:port)": the host, and the destination's ":port".
var hostDst = regexp.MustCompile(`^(\S+) \([^ ()]*(:\d+)\)$`)

// rowActsOf is a row's actions. Block is offered only on a live run, for an exec or net row that was not already
// refused: blocking it again would change nothing. Rule is offered only where a rule can be made and is worth making:
// the run names a contract file (a tego watch run has none, and every Rule link led to an error page), and the row
// is a file, program or connection that was refused or asked about, not one of the many allowed writes.
func rowActsOf(e ledgerview.Event, live, contract bool) rowActs {
	a := rowActs{E: e}
	switch e.Kind {
	case "fs", "exec", "net", "refused":
		a.Rule = contract && (e.Refused() || e.Verdict == "ask")
	}
	if !live || e.Refused() || e.SystemLookup {
		return a
	}
	value := e.Target
	if e.Kind == "exec" {
		// An exec row's target is the command line; the program is its first word.
		value, _, _ = strings.Cut(strings.TrimSpace(e.Target), " ")
	} else if m := hostDst.FindStringSubmatch(e.Target); m != nil {
		// A named destination reads "host (ip:port)": block the host on that port.
		value = m[1] + m[2]
	}
	if (e.Kind == "exec" || e.Kind == "net") && value != "" {
		a.Block = "/runs/" + url.PathEscape(e.Run) + "?block=" + e.Kind + "&value=" + url.QueryEscape(value) + "#block"
	}
	return a
}

// ruleName turns a ledger rule key into words a person reads at a glance; the key itself stays in the page's title
// attribute and in the ledger. "unmatched" means no entry of the contract names the action, so the contract's
// default decided it: refused for writes, programs and connections, allowed for plain reads.
func ruleName(rule string) string {
	inner := func(prefix string) (string, bool) {
		if strings.HasPrefix(rule, prefix+"[") && strings.HasSuffix(rule, "]") {
			return rule[len(prefix)+1 : len(rule)-1], true
		}
		return "", false
	}
	switch rule {
	case "":
		return ""
	case "unmatched":
		return "Not in policy"
	case "net.resolver":
		return "DNS lookup"
	case "held-unsupported":
		return "Cannot hold"
	case "host-sockets":
		return "Host socket"
	}
	for _, m := range []struct{ key, label string }{
		{"fs.write", "Write: "}, {"fs.deny_read", "Never read: "}, {"fs.deny_write", "No changes: "},
		{"fs.ask", "Ask first: "}, {"fs.ask_read", "Ask first: "}, {"fs.read", "Read: "}, {"exec", "Program: "}, {"live.block", "Blocked live: "},
	} {
		if v, ok := inner(m.key); ok {
			return m.label + v
		}
	}
	if v, ok := inner("live.fence"); ok {
		// An Adjustable run's fence entry, live.fence[<kind>:<value>]: the kind is the row's own, so the label names
		// the value in the words the Rules page's fence panel uses.
		if _, val, cut := strings.Cut(v, ":"); cut {
			v = val
		}
		return "Fence: " + v
	}
	if v, ok := inner("net"); ok {
		v = strings.TrimPrefix(strings.TrimPrefix(v, "tcp://"), "udp://")
		if strings.HasPrefix(v, "unix:") {
			return "Socket: " + strings.TrimPrefix(v, "unix:")
		}
		return "Host: " + v
	}
	return rule
}

// overviewRefusals is the newest refusals with the ones that matter first: a line the run page's Highlights call
// background (its run's ledgerview.Signal) is folded apart, so an agent's own probes do not open the list. It returns
// up to limit of each, newest first, and the number of background lines.
func (s *Server) overviewRefusals(snap *ledgerview.Snapshot, sigs *sigMemo, limit int) (front, bg []ledgerview.Row, bgLines int, folds map[string]progFold) {
	runs := map[string]*ledgerview.Run{}
	for _, r := range snap.Runs {
		runs[r.ID] = r
	}
	folds = map[string]progFold{}
	at := map[string]int{} // a program's fold key: the front row its other paths fold into
	for _, row := range snap.Refusals(0) {
		var sig *ledgerview.RunSignal
		if r := runs[row.Run]; r != nil {
			sig = sigs.ownOf(r)
		}
		if sig != nil && sig.IsBackground(&row.Event) {
			bgLines += row.Count
			if len(bg) < limit {
				bg = append(bg, row)
			}
			continue
		}
		k, prog := progKey(row)
		if i, ok := at[k]; ok && k != "" {
			key := refKey(front[i])
			f := folds[key]
			f.Paths = append(f.Paths, prog)
			folds[key] = f
			front[i].Count = max(front[i].Count, row.Count)
			continue
		}
		if len(front) < limit {
			if k != "" {
				at[k] = len(front)
				folds[refKey(row)] = progFold{Name: path.Base(prog), Paths: []string{prog}}
			}
			front = append(front, row)
		}
	}
	for k, f := range folds {
		if len(f.Paths) < 2 {
			delete(folds, k) // one path: the row shows it as it is
		}
	}
	return front, bg, bgLines, folds
}

// progFold is one program refused under several paths in one run, by one rule: a shell tries each folder of PATH in
// turn, so one `curl` reads /usr/bin/curl and /bin/curl. The Overview lists it once, by its name ("curl"), the
// paths in the row's title, and counts it as often as the most refused path was (each attempt tries every path once).
type progFold struct {
	Name  string
	Paths []string
}

// progKey is the fold key of a refused program start (its run, rule, reason and program name) and the program's path;
// "" for any other refusal.
func progKey(row ledgerview.Row) (key, prog string) {
	if row.Kind != "exec" && row.Op != "exec" {
		return "", ""
	}
	f := strings.Fields(row.Target)
	if len(f) == 0 || !strings.HasPrefix(f[0], "/") {
		return "", ""
	}
	return row.Run + "\x00" + row.Rule + "\x00" + row.Reason + "\x00" + path.Base(f[0]), f[0]
}

// refKey names a listed row: its run and line.
func refKey(row ledgerview.Row) string { return row.Run + "-" + strconv.FormatUint(row.Seq, 10) }

// labelRows sets each row's Label (ruleLabel), reading each run's contract lists once.
func (s *Server) labelRows(rows []ledgerview.Row) {
	lists := map[string]rulesview.Lists{}
	for i := range rows {
		e := rows[i].Event
		l, ok := lists[e.Run]
		if !ok {
			l = rulesview.RunLists(s.cfg.Ledger, e.Run)
			lists[e.Run] = l
		}
		rows[i].Label = ruleLabel(e, l)
	}
}

// ruleLabel is the rule an event shows: for a decision the contract's default made ("unmatched"), the exact list it
// fell outside of, read from the run's contract copy; otherwise the rule key in words (ruleName).
func ruleLabel(e ledgerview.Event, l rulesview.Lists) string {
	if e.Rule == "unmatched" {
		if x := l.Explain(e.Kind, e.Op, e.Verdict); x != "" {
			return x
		}
	}
	return ruleName(e.Rule)
}
