// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"golang.org/x/net/html"
)

func TestMoreGuideDestinationExposesEveryGuideState(t *testing.T) {
	for _, name := range []string{guidetest.Fresh, guidetest.Finished} {
		for _, checked := range []bool{false, true} {
			t.Run(name+"/checked="+map[bool]string{false: "no", true: "yes"}[checked], func(t *testing.T) {
				f := guidetest.Make(t, name)
				if checked {
					if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
						t.Fatal(err)
					}
				}
				s := guideServer(t, f)
				c := login(t, s)
				href := ""
				walk(parseHTML(t, "more", get(t, s, c, "/more")), func(n *html.Node) {
					if n.Data == "a" && text(n) == "Guide" {
						href, _ = attr(n, "href")
					}
				})
				u, err := url.Parse(href)
				if err != nil || href == "" {
					t.Fatalf("Guide href %q: %v", href, err)
				}
				// The Guide button opens the guide itself: /guide redirects to the step the stored facts name, and that page
				// is the guide's frame (its title, its steps), which has no closed disclosure to open first.
				w := do(s, "GET", u.RequestURI(), "127.0.0.1:8484", c)
				if w.Code == 303 {
					w = do(s, "GET", w.Header().Get("Location"), "127.0.0.1:8484", c)
				}
				if w.Code != 200 {
					t.Fatalf("Guide destination %q: %d %s", href, w.Code, w.Body.String())
				}
				found := false
				walk(parseHTML(t, "guide", w.Body.String()), func(n *html.Node) {
					if id, _ := attr(n, "id"); id == "gf-title" {
						found = true
					}
				})
				if !found {
					t.Fatalf("Guide destination %q has no guide frame", href)
				}
			})
		}
	}
}

func TestContractFilterLinkPreservesSpecialQuery(t *testing.T) {
	f := newRulesFix(t)
	q := "agent + / ? & = %"
	href := ""
	walk(parseHTML(t, "contracts", get(t, f.s, f.c, "/rules?q="+url.QueryEscape(q))), func(n *html.Node) {
		if _, ok := attr(n, "data-filter-open"); ok {
			href, _ = attr(n, "href")
		}
	})
	u, err := url.Parse(href)
	if err != nil || href == "" {
		t.Fatalf("Filter href %q: %v", href, err)
	}
	if u.Query().Get("q") != q {
		t.Fatalf("Filter changed query to %q from %q", u.Query().Get("q"), q)
	}
	b := get(t, f.s, f.c, u.RequestURI())
	found := false
	walk(parseHTML(t, "filter fallback", b), func(n *html.Node) {
		name, _ := attr(n, "name")
		if n.Data == "input" && name == "q" {
			v, _ := attr(n, "value")
			found = v == q
		}
	})
	if !found {
		t.Fatal("native filter fallback did not keep exact query")
	}
}

func TestPhoneJournalNameDoesNotIncludeRuleTargets(t *testing.T) {
	p, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	row := changeRow{FeedEntry: rules.FeedEntry{Agent: "Agent Mira", Words: "Cannot read /private/customer.data", At: time.Now()}, Href: "/rules/change?c=fixture"}
	for _, region := range []string{"rctl", "rclog"} {
		var b bytes.Buffer
		if err := p["run"].ExecuteTemplate(&b, region, row); err != nil {
			t.Fatal(err)
		}
		names := phoneNames(t, b.String())
		if len(names) != 1 || names[0] != "Agent Mira" {
			t.Errorf("%s summary names: %v", region, names)
		}
		if !strings.Contains(b.String(), "Cannot read /private/customer.data") {
			t.Error("desktop change explanation was lost")
		}
	}
}

func TestPhoneRuleNameDoesNotIncludeTechnicalTargets(t *testing.T) {
	p, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	r := ruleRow{Sentence: "Cannot read /private/customer.data", Target: "/private/customer.data", Key: "fs.deny_read[/private/customer.data]", URL: "/rules?rule=fixture", Effect: "deny"}
	d := rulesData{Run: &ledgerview.Run{ID: harmRun, Start: time.Now()}, V: &rulesview.InForceView{}, Groups: []ruleGroup{{ID: "read", Rows: []ruleRow{r}}}, Live: &ruleGroup{Rows: []ruleRow{r}}}
	var b bytes.Buffer
	if err := p["rules"].ExecuteTemplate(&b, "content", page{Data: d}); err != nil {
		t.Fatal(err)
	}
	names := phoneNames(t, b.String())
	if len(names) != 2 {
		t.Fatalf("want live and normal rule phone rows, got %v", names)
	}
	for _, name := range names {
		if strings.Contains(name, "/") || strings.Contains(name, "customer") {
			t.Errorf("phone rule target outside detail: %q", name)
		}
	}
	if !strings.Contains(b.String(), r.Sentence) {
		t.Fatal("full desktop rule sentence lost")
	}
}

func TestPhoneAnsweredRequestNameContainsOnlyAgent(t *testing.T) {
	p, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	d := struct {
		answered
		Now time.Time
	}{answered: answered{Agent: "Agent Mira", Word: "allowed once by owner after 4 s", Approved: true, TS: time.Now()}, Now: time.Now()}
	if err := p["approvals"].ExecuteTemplate(&b, "ap-answer-row", d); err != nil {
		t.Fatal(err)
	}
	names := phoneNames(t, b.String())
	if len(names) != 1 || names[0] != "Agent Mira" {
		t.Errorf("answered phone name carries extra facts: %v", names)
	}
}

func phoneNames(t *testing.T, b string) []string {
	t.Helper()
	var out []string
	walk(parseHTML(t, "phone names", b), func(n *html.Node) {
		cl, _ := attr(n, "class")
		if strings.Contains(" "+cl+" ", " phone-who ") {
			out = append(out, text(n))
		}
	})
	return out
}

func TestOverviewUncheckedRecordReasonRecoversInDetails(t *testing.T) {
	s := newServer(t, fixture(t))
	s.cfg.Anchor = "/unavailable/record/chain.log"
	b := get(t, s, login(t, s), "/")
	found := false
	walk(parseHTML(t, "unchecked record", pageElement(t, b, "class", "record-copy")), func(n *html.Node) {
		if n.Data != "p" || !strings.Contains(text(n), s.cfg.Anchor) {
			return
		}
		found = true
		inDetails := false
		for p := n.Parent; p != nil; p = p.Parent {
			if p.Data == "details" {
				inDetails = true
			}
		}
		if !inDetails {
			t.Errorf("technical record reason outside details: %s", text(n))
		}
	})
	if !found {
		t.Fatalf("unchecked reason lost its full recovery value: %s", pageElement(t, b, "class", "overview-summary"))
	}
}
