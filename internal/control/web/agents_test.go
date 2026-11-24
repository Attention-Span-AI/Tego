// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/agentid"
	"github.com/attention-span-ai/tego/internal/control/agents"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
)

type agentsFixture struct{ v agents.View }

func (f agentsFixture) Load(context.Context, time.Time) agents.View { return f.v }

// TestAgentsHandlers uses the authenticated product handler and actual escaped
// HTML, without a listener, script, scan execution or host process inspection.
func TestAgentsHandlers(t *testing.T) {
	for _, n := range []int{0, 1, 32} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			s := newServer(t, t.TempDir())
			f := agentsFixture{v: agents.View{ScanStatus: "fresh", Privacy: "When Tego lists a setting, it keeps the name and never the value", RefreshCommand: "tego scan", Footer: "Not looked at: other-users, remote-agents, between-scans", OverviewURL: "/overview"}}
			if n == 0 {
				f.v.Empty = "No match among the rules and sources read."
			}
			for i := 0; i < n; i++ {
				a := agentid.Resolve([]agentid.Found{{ID: fmt.Sprint(i), Name: fmt.Sprintf("agent-%d<script>", i), Command: "/bin/claude", Folder: fmt.Sprintf("/work/%d", i), UID: 1, UIDKnown: true, Source: "last.json", Fact: "program named claude"}}, nil, nil)[0]
				f.v.Rows = append(f.v.Rows, agents.Row{Agent: a, ID: a.ID, Name: a.Name, URL: "/agents/" + a.ID, Stage: "Found", Membership: "Seen at scan time: outside a Tego run", RecordCommand: "cd /work && tego watch -- <the command you start it with>"})
			}
			s.cfg.Agents = f
			c := login(t, s)
			body := get(t, s, c, "/agents")
			if !strings.Contains(body, "tego scan") || !strings.Contains(body, "remote-agents") || strings.Contains(body, "<script>") {
				t.Fatalf("unsafe or incomplete response: %s", body)
			}
			if strings.Count(body, `<li class="ag-row `) != n {
				t.Fatalf("wanted %d rows: %s", n, body)
			}
			if n > 0 {
				detail := get(t, s, c, f.v.Rows[0].URL)
				if !strings.Contains(html.UnescapeString(detail), f.v.Rows[0].RecordCommand) {
					t.Fatal("watch template lost exact text")
				}
				if strings.Count(detail, `class="panel ag-detail"`) != 1 || strings.Contains(detail, `<li class="ag-row `) || !strings.Contains(detail, "Cannot tell:") {
					t.Fatal("detail does not recover one identity's facts")
				}
			}
			if w := do(s, "GET", "/agents/missing", "127.0.0.1:8484", c); w.Code != http.StatusNotFound {
				t.Fatalf("missing identity: %d", w.Code)
			}
			if w := do(s, "GET", "/agents", "127.0.0.1:8484", nil); w.Code != http.StatusUnauthorized {
				t.Fatalf("private scan unprotected: %d", w.Code)
			}
			w := do(s, "HEAD", "/agents", "127.0.0.1:8484", c)
			if w.Code != http.StatusOK || w.Body.Len() != 0 || w.Header().Get("Content-Security-Policy") == "" {
				t.Fatalf("HEAD/CSP: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestAgentsHomeUsesGuideFact(t *testing.T) {
	for _, done := range []bool{false, true} {
		s := newServer(t, t.TempDir())
		s.cfg.Agents = agentsFixture{v: agents.View{GuideDone: done, Privacy: "Agents home fixture"}}
		c := login(t, s)
		body := get(t, s, c, "/")
		if strings.Contains(body, "Agents home fixture") != done {
			t.Fatalf("home guide done=%v: %s", done, body)
		}
		if strings.Contains(get(t, s, c, "/overview"), "Agents home fixture") {
			t.Fatal("Overview is not reachable independently")
		}
	}
}

func TestAgentsWithRecordedVerifiedMachine(t *testing.T) {
	f := guidetest.Make(t, guidetest.Finished)
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, f.Ledger)
	s.cfg.Now = func() time.Time { return guidetest.CheckTime.Add(time.Minute) }
	s.cfg.Guide = func(context.Context) guide.Inputs { return f.Inputs(t) }
	c := login(t, s)
	list := get(t, s, c, "/agents")
	for _, want := range []string{"Verified", `href="/overview"`, `<li class="on">`} {
		if !strings.Contains(list, want) {
			t.Errorf("list missing %q", want)
		}
	}
	links := regexp.MustCompile(`href="(/agents/agent-[0-9a-f]+)"`).FindAllStringSubmatch(list, -1)
	if len(links) == 0 {
		t.Fatalf("no row links to its detail: %.300s", list)
	}
	var all strings.Builder
	for _, m := range links {
		all.WriteString(get(t, s, c, m[1]))
	}
	for _, want := range []string{"Verified", "records enforcing tier landlock", "record checks out", "compiles now in that run", `href="/overview"`} {
		if !strings.Contains(all.String(), want) {
			t.Errorf("details miss %q", want)
		}
	}
	if !strings.Contains(get(t, s, c, "/"), "Saved scan") {
		t.Error("the guide's completed fact does not make Agents the home")
	}
}

func TestAgentsShowsFactAndIndependentUncertainty(t *testing.T) {
	s := newServer(t, t.TempDir())
	a := agentid.Resolve(nil, []agentid.Run{{ID: "r-broken", Name: "bot", Command: []string{"sh"}, Folder: "/work", Verification: agentid.Broken}}, nil)[0]
	s.cfg.Agents = agentsFixture{v: agents.View{Rows: []agents.Row{{Agent: a, ID: a.ID, Name: a.Name, URL: "/agents/" + a.ID}}}}
	body := get(t, s, login(t, s), "/agents/"+a.ID)
	if !strings.Contains(body, "recorded, not checked") || !strings.Contains(html.UnescapeString(body), "This run's record does not check out") {
		t.Fatalf("independent uncertainty hidden: %s", body)
	}
}

// pageText is a page as a reader sees it: its text, tags dropped, spaces collapsed.
func pageText(t *testing.T, body string) string {
	t.Helper()
	return text(parseHTML(t, "agents page", body))
}

// richAgentsView is one of each kind of row the page lays out, with every field the A4-PAGE entry lists.
func richAgentsView() agents.View {
	at := testAgentsAt
	run := agentid.Resolve(nil, []agentid.Run{{ID: "r-20261109-run1", Name: "triage-worker", Command: []string{"/usr/bin/python3", "triage.py"}, Folder: "/work/triage", UID: 1000, UIDKnown: true,
		Tier: "landlock", Ended: true, Verification: agentid.Verified, Started: at, ContractPath: "/work/triage/agent.yaml"}}, nil)[0]
	seen := agentid.Resolve([]agentid.Found{{ID: "item-1", Name: "codex", Command: "/home/u/.local/bin/codex", Folder: "/home/u/src/shop", UID: 1000, UIDKnown: true, Source: "last.json",
		Fact: "program named codex", SeenAt: at.Add(time.Hour)}}, []agentid.Run{{ID: "r-20261108-other", Name: "other", Command: []string{"/home/u/.local/bin/codex"}, Folder: "/home/u/src/shop", UID: 1000, UIDKnown: true, Started: at.Add(-24 * time.Hour)}}, nil)
	var found agentid.Agent
	for _, a := range seen {
		if len(a.Found) > 0 {
			found = a
		}
	}
	gone := found
	gone.ID = "agent-discovery-gone"
	gone.Name = "claude"
	gone.Found = []agentid.Found{{ID: "item-2", Name: "claude", Command: "/home/u/.local/bin/claude", Folder: "/home/u/src/api", UID: 1000, UIDKnown: true, SeenAt: at}}
	gone.Folder = "/home/u/src/api"
	gone.Command = "/home/u/.local/bin/claude"
	gone.Current = ""
	return agents.View{
		Rows: []agents.Row{
			{Agent: run, ID: run.ID, Name: run.Name, URL: "/agents/" + run.ID, Stage: "Verified", Age: "1 day ago", Membership: "Recorded run r-20261109-run1", WhereAt: at, Refusals: 3, RefusalsKnown: true},
			{Agent: found, ID: found.ID, Name: found.Name, URL: "/agents/" + found.ID, Stage: "Seen by scan", Age: "Less than a minute ago", Membership: "Seen outside Tego", WhereAt: at.Add(time.Hour),
				Remembered: true, FirstSeen: at.Add(-time.Hour), LastSeen: at.Add(time.Hour), ScanResult: "scan-a", RecordCommand: "cd '/home/u/src/shop' && tego watch -- <the command you start it with>", RecordNotice: "Fill in the command you start it with.",
				Observations: []agents.Observation{{Kind: "process", Path: "/home/u/.local/bin/codex", Folder: "/home/u/src/shop", Fact: "agent-name: codex (proc)"}}},
			{Agent: gone, ID: gone.ID, Name: gone.Name, URL: "/agents/" + gone.ID, Stage: "Previously seen", Age: "2 days ago", Membership: "Not seen in the latest scan; last seen", WhereAt: at,
				Remembered: true, NotSeenLatest: true, FirstSeen: at.Add(-48 * time.Hour), LastSeen: at, ScanResult: "scan-old", RecordNotice: "No command is shown: the working folder is unknown or cannot be shown safely."},
		},
		Historical:    []agents.Observation{{Kind: "program", Path: "/old/bin/agent", Fact: "historical"}},
		Evidence:      []agents.Observation{{Kind: "settings", Name: "github", Path: "/home/u/.gemini/settings.json", Fact: "configured only"}},
		OtherPrograms: []agents.Observation{{Kind: "other_program", Path: "/usr/bin/make", Folder: "/work", Membership: "outside a Tego run"}},
		ScanStatus:    "fresh",
		ScanNotice:    "Saved observations, seen at the scan time; they do not say what is running now.",
		ScanAge:       "Less than a minute ago",
		ScanLabel:     "A program run by the same user outside Tego can change this saved scan.", ScanFinished: at.Add(time.Hour),
		ScanLines:          []string{"This scan looked at your own programs only.", "It read 9 places and could not read 1."},
		ScanNotLooked:      []string{"Other people's accounts on this computer.", "Agents that run on other computers."},
		Footer:             "The scan saw 2 programs inside a Tego run. They get no row here, because runs are listed from the record. Tego protects the saved scan and the list of remembered programs against ordinary writes.",
		InRunObservations:  2,
		DiscoveryNotice:    "The list of remembered programs is in use right now. This page shows the last saved copy and did not update it. Refresh to try again. The list of remembered programs reached its size limit, so it was cut short.",
		DiscoveryTruncated: true,
		RefreshCommand:     "tego scan", RefreshInstruction: "Run tego scan from the project folder you want to look at, then refresh this page.",
		Privacy: "When Tego lists a setting, it keeps the name and never the value", OtherKnown: true, OtherCount: 7, NotKnown: []string{"Other users' agents are not looked at."},
		RefusedToday: agents.Count{Value: 4, Partial: true, Notice: "Counted from the records Tego could read. Some records are incomplete, so the real number can be higher."},
	}
}

// testAgentsAt is the instant the rich fixture is built around.
var testAgentsAt = time.Date(2026, 11, 9, 14, 21, 0, 0, time.UTC)

// TestAgentsRendersEveryFieldOfTheSpec walks the A4-PAGE list over the real handler: the three facts of a row, the
// detail's run id and time, observation first and last seen, the not-seen, truncation and store warnings, the
// governed-observation count in the footer, Relationship, VerificationReason and NextStep, the related runs linked.
func TestAgentsRendersEveryFieldOfTheSpec(t *testing.T) {
	s := newServer(t, t.TempDir())
	v := richAgentsView()
	s.cfg.Agents = agentsFixture{v: v}
	c := login(t, s)
	rawList := get(t, s, c, "/agents")
	list := pageText(t, rawList)
	for _, want := range []string{
		"triage-worker", "Verified", "claude", "Previously seen", "Not in the latest scan", "codex", "Seen by scan",
		"The list of remembered programs is in use right now", "reached its size limit", "The scan saw 2 programs inside a Tego run", "Tego protects the saved scan and the list of remembered programs against ordinary writes", "This scan looked at your own programs only.", "Not looked at", "Other people's accounts on this computer.", "3 refusals",
		"Saved scan", "Fresh", "Scanned at", "A program run by the same user outside Tego can change this saved scan.", "tego scan", "Refresh saved result",
		"At least 4 refusals today.", "the real number can be higher", "Other programs", "When the scan ran, it saw 7 other programs running.", "/usr/bin/make", "Settings found", "/home/u/.gemini/settings.json",
		"Older scan results", "What this scan covered and what it did not", "/old/bin/agent", "Other users' agents are not looked at.", "1 recorded run · 2 seen by scan",
	} {
		if !strings.Contains(list, want) {
			t.Errorf("list missing %q", want)
		}
	}
	// a row is one link to its detail
	for _, row := range v.Rows {
		if !strings.Contains(rawList, `<a class="ag-link" href="`+row.URL+`">`) {
			t.Errorf("row %s has no link to its detail", row.ID)
		}
	}
	// the run's detail
	rawRun := get(t, s, c, v.Rows[0].URL)
	run := pageText(t, rawRun)
	for _, want := range []string{"Recorded run r-20261109-run1 at " + agentTime(testAgentsAt), "in /work/triage", "Command", "/usr/bin/python3", "Relationship", "Record check", "Next step", "Open this run's record to inspect its check and evidence.", "Stages", "Cannot tell:"} {
		if !strings.Contains(run, want) {
			t.Errorf("run detail missing %q", want)
		}
	}
	if strings.Contains(run, "Forget this sighting") {
		t.Error("a recorded run offers Forget")
	}
	// the observation's detail: where, folder, first and last seen, the scan result, the related runs linked
	rawObs := get(t, s, c, v.Rows[1].URL)
	obs := pageText(t, rawObs)
	for _, want := range []string{"Seen outside Tego at " + agentTime(testAgentsAt.Add(time.Hour)) + " in /home/u/src/shop", "First seen", "Last seen", "scan-a", "Possibly related runs",
		"Relationship", "Record check", "Only a recorded run has a record check.", "Next step", "Record it", "cd '/home/u/src/shop' &amp;&amp; tego watch", "What the scan saw", "agent-name: codex (proc)", "PATH search"} {
		if want == "cd '/home/u/src/shop' &amp;&amp; tego watch" {
			want = "cd '/home/u/src/shop' && tego watch"
		}
		if !strings.Contains(obs, want) {
			t.Errorf("observation detail missing %q", want)
		}
	}
	if !strings.Contains(rawRun, `href="/runs/r-20261109-run1"`) || !strings.Contains(rawObs, `href="/runs/r-20261108-other"`) {
		t.Error("a run id is not linked to its page")
	}
	gone := pageText(t, get(t, s, c, v.Rows[2].URL))
	for _, want := range []string{"Not in the latest scan. This is a remembered observation.", "Not seen in the latest scan; last seen at " + agentTime(testAgentsAt), "scan-old", "No command is shown"} {
		if !strings.Contains(gone, want) {
			t.Errorf("not-seen detail missing %q", want)
		}
	}
}

// A scan observation never ticks a stage: no row of the list and no stage of a detail is "reached" unless a recorded
// run established it, even when a forged row says the stage is established.
func TestAgentsNeverTicksAnObservation(t *testing.T) {
	s := newServer(t, t.TempDir())
	v := richAgentsView()
	for i := 1; i < len(v.Rows); i++ {
		for j := range v.Rows[i].Agent.Stages {
			v.Rows[i].Agent.Stages[j].Fact.Established = true
		}
	}
	s.cfg.Agents = agentsFixture{v: v}
	c := login(t, s)
	for _, row := range v.Rows[1:] {
		body := get(t, s, c, row.URL)
		if strings.Contains(body, `<li class="on">`) || strings.Contains(body, "Reached") || strings.Contains(body, "ag-strip") {
			t.Errorf("observation %s shows a tick: %s", row.ID, body)
		}
	}
	list := get(t, s, c, "/agents")
	if strings.Count(list, `<ol class="ag-strip"`) != 1 {
		t.Error("only the recorded run's row carries the stage strip")
	}
}

// Every saved-scan state says what it is and keeps its repair steps visible, in the page and not in a fold.
func TestAgentsScanStatesKeepTheirNotices(t *testing.T) {
	for _, tc := range []struct{ status, notice, word string }{
		{"fresh", "Saved observations, seen at the scan time", "Fresh"},
		{"stale", "The saved scan is older than five minutes. Its observations are historical.", "Old"},
		{"another-boot", "The saved scan is from another boot.", "Another boot"},
		{"failed", "The saved scan reports failure. Its observations are historical.", "Failed"},
		{"unreadable", "The saved scan could not be read: unsafe owner, mode, links or file type. Check the owner, mode and links at ~/.tego/scan and ~/.tego/scan/last.json. Then run tego scan from your project folder and refresh this page.", "Unreadable"},
		{"missing", "No saved scan. Run tego scan from your project folder.", "Not saved yet"},
		{"unavailable", "The scan location is not configured.", "Not configured"},
	} {
		t.Run(tc.status, func(t *testing.T) {
			s := newServer(t, t.TempDir())
			v := agents.View{ScanStatus: tc.status, ScanNotice: tc.notice, RefreshCommand: "tego scan", RefreshInstruction: "Run tego scan from the project folder you want to look at, then refresh this page.", Empty: "No current agent evidence can be shown. This does not establish that no agents exist."}
			s.cfg.Agents = agentsFixture{v: v}
			body := html.UnescapeString(get(t, s, login(t, s), "/agents"))
			for _, want := range []string{tc.notice, tc.word, v.Empty, "Scan again", v.RefreshInstruction} {
				if !strings.Contains(body, want) {
					t.Errorf("%s: missing %q", tc.status, want)
				}
			}
			if strings.Contains(body, `<li class="ag-row `) {
				t.Error("an empty view lists a row")
			}
		})
	}
}

// The state-protection disclosure and the store's repair steps are in the page's own text, never inside a fold.
func TestAgentsKeepsDisclosureAndRepairVisible(t *testing.T) {
	const warning = "Tego protects the saved scan and the list of remembered programs against ordinary writes by a program it governs. The stages shown for a run do not depend on this list."
	const repair = "The remembered programs could not be read: the folder or file has an unsafe owner, permissions or links. Nothing was changed. Check the owner, mode and links at ~/.tego/agents and ~/.tego/agents/discoveries.json."
	s := newServer(t, t.TempDir())
	s.cfg.Agents = agentsFixture{v: agents.View{Footer: warning, DiscoveryNotice: repair, ScanStatus: "fresh"}}
	body := get(t, s, login(t, s), "/agents")
	for {
		start := strings.Index(body, "<details")
		if start < 0 {
			break
		}
		end := strings.Index(body[start:], "</details>")
		if end < 0 {
			t.Fatal("unclosed details")
		}
		body = body[:start] + body[start+end+len("</details>"):]
	}
	for _, want := range []string{warning, repair} {
		if !strings.Contains(html.UnescapeString(body), want) {
			t.Errorf("collapsed or absent: %q", want)
		}
	}
}

// Rows whose relation is unknown still say so: Relationship, Record check and Next step are always rendered.
func TestAgentsAlwaysRendersRelationshipReasonAndNextStep(t *testing.T) {
	s := newServer(t, t.TempDir())
	a := agentid.Agent{ID: "agent-x", Name: "x", Stages: []agentid.Stage{{ID: agentid.FoundStage, Label: "Found"}}}
	s.cfg.Agents = agentsFixture{v: agents.View{Rows: []agents.Row{{Agent: a, ID: a.ID, Name: a.Name, URL: "/agents/agent-x"}}}}
	body := get(t, s, login(t, s), "/agents/agent-x")
	for _, want := range []string{"Relationship", "Not known.", "Record check", "Next step", "Not known."} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
}

// Every value the page writes is escaped.
func TestAgentsEscapesEveryField(t *testing.T) {
	s := newServer(t, t.TempDir())
	v := richAgentsView()
	bad := "<img src=x onerror=alert(1)>"
	v.Rows[1].Name, v.Rows[1].Agent.Folder, v.Rows[1].Agent.Command, v.Rows[1].Agent.Relationship = bad, bad, bad, bad
	v.Rows[1].Observations[0].Path, v.Rows[1].Observations[0].Fact = bad, bad
	v.DiscoveryNotice, v.ScanNotice, v.Footer = bad, bad, bad
	s.cfg.Agents = agentsFixture{v: v}
	c := login(t, s)
	for _, path := range []string{"/agents", v.Rows[1].URL} {
		if body := get(t, s, c, path); strings.Contains(body, "<img src=x") {
			t.Errorf("%s writes a field unescaped", path)
		}
	}
}

// rememberedFixture is a real saved scan, remembered by one Load, and the dashboard over it.
func rememberedFixture(t *testing.T) (*Server, *http.Cookie, *guidetest.Fixture, string) {
	t.Helper()
	f := guidetest.Make(t, guidetest.Fresh)
	f.PutScan(t, "a")
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, f.Ledger)
	s.cfg.Now = func() time.Time { return guidetest.CheckTime.Add(time.Minute) }
	s.cfg.Guide = func(context.Context) guide.Inputs { return f.Inputs(t) }
	c := login(t, s)
	list := get(t, s, c, "/agents")
	m := regexp.MustCompile(`href="/agents/(agent-discovery-[0-9a-f]+)"`).FindStringSubmatch(list)
	if m == nil {
		t.Fatalf("the scan's program is not remembered as a row: %s", list)
	}
	return s, c, f, m[1]
}

func storedDiscoveries(t *testing.T, f *guidetest.Fixture) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.Home, ".tego", "agents", "discoveries.json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestAgentsForget: the detail offers a confirm step; the POST needs the session, the origin and the token; it drops
// only the remembered discovery and never a run record; a later scan can remember the program again.
func TestAgentsForget(t *testing.T) {
	s, c, f, id := rememberedFixture(t)
	detail := get(t, s, c, "/agents/"+id)
	for _, want := range []string{`<details class="ag-forget">`, `action="/agents/forget"`, `name="agent" value="` + id + `"`, "Run records, saved scans and contracts stay as they are."} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail missing %q", want)
		}
	}
	tok := csrfOf(t, s, c, "/agents/"+id)
	before := storedDiscoveries(t, f)
	runs := func() []string {
		ents, _ := os.ReadDir(f.Ledger)
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		return names
	}
	runsBefore := runs()
	form := func(csrf string) url.Values { return url.Values{"csrf": {csrf}, "agent": {id}} }
	for name, w := range map[string]*httptest.ResponseRecorder{
		"no token":      post(s, "/agents/forget", url.Values{"agent": {id}}, own, "", c),
		"wrong token":   post(s, "/agents/forget", form("0000"), own, "", c),
		"other origin":  post(s, "/agents/forget", form(tok), "http://evil.example", "", c),
		"no session":    post(s, "/agents/forget", form(tok), own, "", nil),
		"no origin/ref": post(s, "/agents/forget", form(tok), "", "", c),
	} {
		if w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want refused", name, w.Code)
		}
		if storedDiscoveries(t, f) != before {
			t.Fatalf("%s changed the store", name)
		}
	}
	if w := do(s, "GET", "/agents/forget?agent="+id, "127.0.0.1:8484", c); w.Code == http.StatusOK && storedDiscoveries(t, f) != before {
		t.Fatal("GET forgot a discovery")
	}
	// an unknown id changes nothing and says so
	w := post(s, "/agents/forget", url.Values{"csrf": {tok}, "agent": {"agent-discovery-" + strings.Repeat("0", 64)}}, own, "", c)
	if body := follow(t, s, c, w); !strings.Contains(body, "Nothing was forgotten") || storedDiscoveries(t, f) != before {
		t.Fatalf("unknown id: %s", body)
	}
	// a path is not an id
	w = post(s, "/agents/forget", url.Values{"csrf": {tok}, "agent": {"../../etc/passwd"}}, own, "", c)
	if body := follow(t, s, c, w); !strings.Contains(body, "Nothing was forgotten") || storedDiscoveries(t, f) != before {
		t.Fatalf("path as id: %s", body)
	}
	w = post(s, "/agents/forget", form(tok), own, "", c)
	// read the store before the flash page loads: that load remembers a still-listed program again
	after := storedDiscoveries(t, f)
	if strings.Contains(after, `"observed"`) || after == before {
		t.Fatalf("the store still holds the discovery: %s", after)
	}
	if !slices.Equal(runs(), runsBefore) {
		t.Fatal("Forget changed the ledger")
	}
	if body := follow(t, s, c, w); !strings.Contains(body, "Forgot this remembered sighting. Recorded runs were not changed.") {
		t.Fatalf("no confirmation line: %.300s", body)
	}
	// the saved scan still lists the program, so the next load remembers it again, as the confirmation says
	if again := get(t, s, c, "/agents"); !strings.Contains(again, "/agents/"+id) {
		t.Fatalf("the page does not remember a still-listed program again: %s", again)
	}
}

// A store that cannot be read safely is not changed by Forget, and the answer says why.
func TestAgentsForgetRefusesAnUnsafeStore(t *testing.T) {
	s, c, f, id := rememberedFixture(t)
	tok := csrfOf(t, s, c, "/agents/"+id)
	path := filepath.Join(f.Home, ".tego", "agents", "discoveries.json")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	w := post(s, "/agents/forget", url.Values{"csrf": {tok}, "agent": {id}}, own, "", c)
	if body := follow(t, s, c, w); !strings.Contains(body, "Nothing was forgotten") || !strings.Contains(body, "could not be read safely") {
		t.Fatalf("unsafe store: %s", body)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), `"observed"`) {
		t.Fatal("an unsafe store was rewritten")
	}
}

// A service that cannot forget answers the form with a line, not an error page.
func TestAgentsForgetWithoutAService(t *testing.T) {
	s := newServer(t, t.TempDir())
	s.cfg.Agents = agentsFixture{v: richAgentsView()}
	c := login(t, s)
	tok := csrfOf(t, s, c, "/agents/"+richAgentsView().Rows[2].ID)
	w := post(s, "/agents/forget", url.Values{"csrf": {tok}, "agent": {"agent-discovery-gone"}}, own, "", c)
	if body := follow(t, s, c, w); !strings.Contains(body, "Nothing was forgotten") {
		t.Fatal(body)
	}
}

func TestAgentsInTheNavigationAndTheTour(t *testing.T) {
	s := newServer(t, t.TempDir())
	s.cfg.Agents = agentsFixture{v: richAgentsView()}
	c := login(t, s)
	body := get(t, s, c, "/agents")
	if !strings.Contains(body, `<a href="/agents" aria-current="page">`) {
		t.Errorf("Agents is not the current page in the navigation: %.600s", body)
	}
	if more := get(t, s, c, "/more"); !strings.Contains(more, `href="/agents">Agents</a>`) {
		t.Error("More does not link Agents")
	}
	f := guidetest.Make(t, guidetest.Fresh)
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	s2 := newServer(t, f.Ledger)
	s2.cfg.Now = func() time.Time { return guidetest.CheckTime.Add(time.Minute) }
	s2.cfg.Guide = func(context.Context) guide.Inputs { return f.Inputs(t) }
	c2 := login(t, s2)
	w := do(s2, "GET", "/guide?step=pick", "127.0.0.1:8484", c2)
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/agents?guide=pick") {
		t.Fatalf("the Pick step opens %q", w.Header().Get("Location"))
	}
	framed := get(t, s2, c2, "/agents?guide=pick")
	if !strings.Contains(framed, `id="gf-title"`) || !strings.Contains(framed, "Saved scan") || strings.Contains(framed, "<h1>Agents</h1>") {
		t.Errorf("the Pick step does not frame the Agents page: %.400s", framed)
	}
}

func TestAgentsRegionsMergeWithoutTheLayout(t *testing.T) {
	s := newServer(t, t.TempDir())
	s.cfg.Agents = agentsFixture{v: richAgentsView()}
	c := login(t, s)
	page := get(t, s, c, "/agents")
	for _, name := range []string{"r-ag-head", "r-ag-main", "r-ag-more"} {
		if !strings.Contains(page, `data-live="`+name+`"`) {
			t.Errorf("no live region %s", name)
		}
	}
	r := httptest.NewRequest("GET", "/agents", nil)
	r.Host = "127.0.0.1:8484"
	r.AddCookie(c)
	r.Header.Set(regionHeader, "r-ag-head:0000,r-ag-main:0000,r-ag-more:0000")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if body := w.Body.String(); w.Code != http.StatusOK || strings.Contains(body, "<html") || !strings.Contains(body, `<template data-live="r-ag-main"`) {
		t.Fatalf("regions answer: %d %.300s", w.Code, body)
	}
}

// The scan's footer reaches the page in plain words: a list of what the scan did and could not read, a list of what it
// never looked at, and nothing in the CLI's operator wording.
func TestAgentsShowsTheScanFooterInPlainWords(t *testing.T) {
	s := newServer(t, t.TempDir())
	s.cfg.Agents = agentsFixture{v: richAgentsView()}
	raw := get(t, s, login(t, s), "/agents")
	for _, want := range []string{`<ul class="ag-obs ag-scanwords" role="list">`, "It read 9 places and could not read 1.", `id="h-ag-notlooked">Not looked at</h3>`, `<ul class="ag-obs ag-notlooked" role="list" aria-labelledby="h-ag-notlooked">`, `>Agents that run on other computers.</span></li>`} {
		if !strings.Contains(raw, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	text := pageText(t, raw)
	for _, bad := range []string{"Scope:", "Sources: read", "Rules:", "Exited during the scan", "uid ", "NSS", "systemd", "cgroup"} {
		if strings.Contains(text, bad) {
			t.Errorf("page keeps operator wording %q", bad)
		}
	}
}

// Each recorded run row says how many actions were refused in it, in the list and in the detail; a program a scan saw
// has no such count, because no record is behind it.
func TestAgentsShowsEachRunsRefusalCount(t *testing.T) {
	s := newServer(t, t.TempDir())
	v := richAgentsView()
	s.cfg.Agents = agentsFixture{v: v}
	c := login(t, s)
	raw := get(t, s, c, "/agents")
	if got := strings.Count(raw, `class="ag-ref"`); got != 1 {
		t.Fatalf("%d rows carry a refusal count; want 1 (the recorded run)", got)
	}
	if text := pageText(t, raw); !strings.Contains(text, "3 refusals") {
		t.Errorf("list lacks the run's count: %s", text)
	}
	detail := pageText(t, get(t, s, c, v.Rows[0].URL))
	for _, want := range []string{"Refusals", "3 refusals in this run.", "See them in the run"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail lacks %q", want)
		}
	}
	if seen := pageText(t, get(t, s, c, v.Rows[1].URL)); strings.Contains(seen, "in this run.") {
		t.Errorf("a scan row claims a run count")
	}
	v.Rows[0].RefusalsPartial = true
	s.cfg.Agents = agentsFixture{v: v}
	if text := pageText(t, get(t, s, c, "/agents")); !strings.Contains(text, "At least 3 refusals") {
		t.Errorf("an incomplete record is not a lower bound: %s", text)
	}
	v.Rows[0].Refusals = 0
	s.cfg.Agents = agentsFixture{v: v}
	if text := pageText(t, get(t, s, c, "/agents")); !strings.Contains(text, "No refusals counted") {
		t.Errorf("zero in an incomplete record reads as a clean run")
	}
}

// Safari's VoiceOver stops announcing a list drawn without bullets unless it says role="list": every list the page's CSS
// strips of its markers carries the role.
func TestAgentsListsWithoutMarkersSayTheyAreLists(t *testing.T) {
	s := newServer(t, t.TempDir())
	v := richAgentsView()
	s.cfg.Agents = agentsFixture{v: v}
	c := login(t, s)
	re := regexp.MustCompile(`<(ol|ul) class="(ag-rows|ag-strip|ag-stages|ag-obs)[^"]*"([^>]*)>`)
	for _, path := range []string{"/agents", v.Rows[0].URL, v.Rows[1].URL} {
		raw := get(t, s, c, path)
		for _, m := range re.FindAllStringSubmatch(raw, -1) {
			if !strings.Contains(m[0], `role="list"`) {
				t.Errorf("%s: %s has no role=list", path, m[0])
			}
		}
	}
}

// Firefox and Safari cannot be run here. This pins the page's CSS to features both have, with the first version of each
// (as of the MDN compatibility data), so a new feature cannot slip in unreviewed.
func TestAgentsCSSFeaturesAreBaseline(t *testing.T) {
	raw, err := os.ReadFile("static/agents.css")
	if err != nil {
		t.Fatal(err)
	}
	css := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(string(raw), "")
	// What the CSS uses, with the first Firefox/Safari that has it (MDN compatibility data): grid with template areas
	// and minmax 52/10.1; gap in flex 63/14.1; display: contents 37/11.1 (an accessibility bug before Safari 16 hits
	// only elements with semantics, and the one use is a plain div); :focus-visible 85/15.4; :not() with a simple
	// selector; ::-webkit-details-marker (WebKit; Firefox hides the marker by list-style); overflow-wrap: anywhere
	// 65/15.4 with a break-word line before it; @media (forced-colors) 89/none, ignored where unsupported;
	// outline-offset, order, var(), list-style, justify-self in grid.
	for _, banned := range []string{":has(", "@container", "@layer", "color-mix(", "text-wrap", "subgrid", "@scope", "anchor(", "field-sizing", "dvh", "svh", "lvh", "nesting", "light-dark(", "inset:", "aspect-ratio", "accent-color", "scrollbar-gutter", ":is(", ":where("} {
		if strings.Contains(css, banned) {
			t.Errorf("agents.css uses %q, which needs a newer Firefox or Safari than the page's list allows", banned)
		}
	}
	if strings.Contains(css, "overflow-wrap: anywhere") {
		for _, rule := range strings.Split(css, "}") {
			if strings.Contains(rule, "overflow-wrap: anywhere") && !strings.Contains(rule, "overflow-wrap: break-word; overflow-wrap: anywhere") {
				t.Errorf("overflow-wrap: anywhere without its break-word line before it (Safari older than 15.4): %s", strings.TrimSpace(rule))
			}
		}
	}
	if !strings.Contains(css, "::-webkit-details-marker") || !strings.Contains(css, "list-style: none") {
		t.Errorf("the Forget summary must hide its marker for both engines (list-style for Firefox, the WebKit pseudo-element for Safari)")
	}
}
