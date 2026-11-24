// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"golang.org/x/net/html"
)

func tourNode(t *testing.T, body, selector string) *html.Node {
	t.Helper()
	var found *html.Node
	walk(parseHTML(t, selector, body), func(n *html.Node) {
		id, _ := attr(n, "id")
		cls, _ := attr(n, "class")
		if id == selector || hasClass(cls, selector) {
			found = n
		}
	})
	if found == nil {
		t.Fatalf("missing %s", selector)
	}
	return found
}

func TestTourEntryAlwaysUsesFacts(t *testing.T) {
	for _, name := range []string{guidetest.Fresh, guidetest.HalfDone, guidetest.Finished} {
		t.Run(name, func(t *testing.T) {
			f := guidetest.Make(t, name)
			s := guideServer(t, f)
			if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
				t.Fatal(err)
			}
			g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
			for _, saved := range []string{"check", "pick", "review", "enforce"} {
				r := httptest.NewRequest("GET", "/guide", nil)
				r.Host = "127.0.0.1:8484"
				r.AddCookie(login(t, s))
				r.AddCookie(&http.Cookie{Name: "tego-guide-step", Value: saved})
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				if want := tourURL(g, map[string]string{guidetest.Fresh: "pick", guidetest.HalfDone: "review", guidetest.Finished: "enforce"}[name]); w.Code != 303 || w.Header().Get("Location") != want {
					t.Errorf("saved %s: %d %s want %s", saved, w.Code, w.Header().Get("Location"), want)
				}
			}
		})
	}
}

func TestTourAccessibilityContracts(t *testing.T) {
	f := guidetest.Make(t, guidetest.HalfDone)
	s := guideServer(t, f)
	c := login(t, s)
	g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
	for _, stop := range tourStops {
		t.Run(stop.key, func(t *testing.T) {
			body := get(t, s, c, tourURL(g, stop.key))
			doc := parseHTML(t, "a11y", body)
			t.Run("live-region", func(t *testing.T) {
				n := tourNode(t, body, "gf-status")
				for k, want := range map[string]string{"role": "status", "aria-live": "polite", "aria-atomic": "true"} {
					if got, _ := attr(n, k); got != want {
						t.Errorf("%s=%q want %q", k, got, want)
					}
				}
			})
			t.Run("current-step", func(t *testing.T) {
				count := 0
				walk(doc, func(n *html.Node) {
					if a, _ := attr(n, "aria-current"); a == "step" {
						count++
						if href, _ := attr(n, "href"); href != "/guide?step="+stop.key {
							t.Errorf("wrong current step %s", href)
						}
					}
				})
				if count != 1 {
					t.Errorf("current steps: %d", count)
				}
			})
			t.Run("leave", func(t *testing.T) {
				n := tourNode(t, body, "gf-leave")
				got, _ := attr(n, "href")
				want, _ := tourPath(g, stop.key)
				if got != want {
					t.Fatalf("leave %q want %q", got, want)
				}
				if strings.Contains(get(t, s, c, got), `class="gf"`) {
					t.Fatal("Leave kept frame")
				}
			})
			t.Run("scripts-off", func(t *testing.T) {
				native, err := html.ParseWithOptions(strings.NewReader(body), html.ParseOptionEnableScripting(false))
				if err != nil {
					t.Fatal(err)
				}
				found := false
				walk(native, func(n *html.Node) {
					if n.Data != "noscript" {
						return
					}
					walk(n, func(a *html.Node) {
						if href, _ := attr(a, "href"); a.Data == "a" && href == "/guide?step="+stop.key {
							found = true
						}
					})
				})
				if !found {
					t.Fatal("missing native reload link")
				}
			})
		})
	}
}

func TestTourHiddenKeepsUncertainFactsAndCanBeRestored(t *testing.T) {
	for _, name := range []string{guidetest.Fresh, guidetest.NotReady, guidetest.Finished, "unknown-record"} {
		t.Run(name, func(t *testing.T) {
			kind := name
			if name == "unknown-record" {
				kind = guidetest.Finished
			}
			f := guidetest.Make(t, kind)
			if name == "unknown-record" {
				if err := os.Remove(f.Anchor); err != nil {
					t.Fatal(err)
				}
			}
			if name != guidetest.Fresh {
				if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
					t.Fatal(err)
				}
			}
			s := guideServer(t, f)
			c := login(t, s)
			request := func(path string) string {
				r := httptest.NewRequest("GET", path, nil)
				r.Host = "127.0.0.1:8484"
				r.AddCookie(c)
				r.AddCookie(&http.Cookie{Name: "tego-guide", Value: "hidden"})
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatalf("%s: %d", path, w.Code)
				}
				return w.Body.String()
			}
			body := request("/")
			if name != guidetest.Finished && !strings.Contains(body, `data-step="check"`) {
				t.Fatal("hidden preference concealed uncertain check")
			}
			for _, path := range []string{"/more", "/machine", "/machine?guide=check"} {
				body := request(path)
				found := false
				walk(parseHTML(t, path, body), func(n *html.Node) {
					if action, _ := attr(n, "action"); n.Data == "form" && action == "/guide/preference" {
						walk(n, func(n *html.Node) {
							name, _ := attr(n, "name")
							value, _ := attr(n, "value")
							if name == "show" && value == "yes" {
								found = true
							}
						})
					}
				})
				if !found {
					t.Errorf("%s has no restoration form", path)
				}
			}
		})
	}
}

func TestTourFinishedOverviewHasNoStartOffer(t *testing.T) {
	f := guidetest.Make(t, guidetest.Finished)
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	s := guideServer(t, f)
	body := get(t, s, login(t, s), "/")
	if strings.Contains(body, "Start the guide") {
		t.Fatal("finished overview still asks to start")
	}
}

func TestTourInstructionsDescribeRealActions(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	s := guideServer(t, f)
	c := login(t, s)
	body := get(t, s, c, "/machine?guide=check")
	if got := text(tourNode(t, body, "gf-instruction")); !strings.Contains(got, "terminal") || !strings.Contains(got, "tego setup") {
		t.Errorf("check instruction %q", got)
	}
	if got := text(tourNode(t, body, "gf-action")); got != "Reload stored check" {
		t.Errorf("reload action %q", got)
	}
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	body = get(t, s, c, "/runs?guide=pick")
	if !strings.Contains(text(tourNode(t, body, "gf-instruction")), "first run is recorded") {
		t.Fatal("Pick does not explain its completion fact")
	}
	form := tourNode(t, body, "gf-command")
	if !strings.Contains(text(form), "<the command") {
		t.Fatal("command form missing")
	}
	walk(form.Parent, func(n *html.Node) {
		if v, _ := attr(n, "data-copy"); v == "gf-command" {
			t.Error("placeholder form is copyable")
		}
	})
	if !strings.Contains(text(form.Parent), "Replace") {
		t.Error("placeholder form has no fill-in instruction")
	}
	body = get(t, s, c, "/runs?guide=watch")
	if !strings.Contains(body, "Watch and Recorded share") {
		t.Error("shared recording fact is not explained")
	}
	// Each source fact carries the same tour name used by the rail.
	for _, stop := range tourStops {
		if !strings.Contains(body, expectedTourTitle(stop.fact)+": ") {
			t.Errorf("missing consistent source title %s", stop.label)
		}
	}
}

func TestTourRecordedAndReviewLeadWithActions(t *testing.T) {
	f := tourValues(t, "recorded-values")
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	s := guideServer(t, f)
	c := login(t, s)
	g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
	for _, key := range []string{"recorded", "review"} {
		t.Run(key, func(t *testing.T) {
			body := get(t, s, c, tourURL(g, key))
			facts := tourNode(t, body, "gf-facts")
			rows := 0
			walk(facts, func(n *html.Node) {
				if n.Data == "dt" {
					rows++
				}
			})
			if rows != 3 {
				t.Errorf("facts rows %d", rows)
			}
			got := text(facts)
			for _, want := range []string{"sh", "2001:db8", "very-long-key-name"} {
				if !strings.Contains(got, want) {
					t.Errorf("first-screen actions omit %s: %s", want, got)
				}
			}
			first := tourNode(t, body, "gf-record")
			if _, ok := attr(first, "open"); !ok {
				t.Error("short record disclosure closed")
			}
			if key == "review" {
				action := tourNode(t, body, "gf-action")
				href, _ := attr(action, "href")
				if !strings.Contains(href, "guide=review") {
					t.Error("builder drops guide")
				}
				if text(tourNode(t, body, "gf-instruction")) != "Review What the run recorded. Create contract and the terminal learn command each make a contract from this run." {
					t.Error("command/button relationship missing")
				}
				if !strings.Contains(get(t, s, c, href), `class="gf"`) {
					t.Error("builder has no frame")
				}
			}
		})
	}
}

func expectedTourTitle(id string) string {
	return map[string]string{"install": "Install", "check": "Check", "find": "Pick", "record": "Watch and Recorded", "contract": "Review", "enforce": "Enforce"}[id]
}

func TestTourLongCommandHasBoundedSummaryAndFullEvidence(t *testing.T) {
	command := append([]string{"sh"}, strings.Fields(strings.Repeat("many short arguments ", 30))...)
	f := tourValues(t, "recorded-values", command...)
	s := guideServer(t, f)
	g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
	body := get(t, s, login(t, s), tourURL(g, "recorded"))
	facts := tourNode(t, body, "gf-facts")
	if got := text(facts); len(got) > 500 {
		t.Errorf("unbounded first-screen facts: %d bytes", len(got))
	}
	evidence := tourNode(t, body, "gf-record")
	if !strings.Contains(text(evidence), strings.Join(command, " ")) {
		t.Error("full command cannot be recovered from promised disclosure")
	}
}

func TestTourReviewInstructionMatchesRenderedAction(t *testing.T) {
	for _, tc := range []struct{ name, fixture, rule, instruction, action, command string }{
		{"unchecked", guidetest.HalfDone, guide.RuleCheckTodo, "Check this machine first, then return to review its rules.", "Check this machine first", ""},
		{"create", guidetest.HalfDone, guide.RuleRecordDone, "Review What the run recorded. Create contract and the terminal learn command each make a contract from this run.", "Create contract", "tego rules learn "},
		{"noncompiling", guidetest.ContractMade, guide.RuleContractBlocked, "Fix the existing contract using the terminal compile result, or choose Create contract to make another.", "Create contract", "tego rules check "},
		{"saved", guidetest.ContractMade, guide.RuleContractDone, "The contract is saved and compiles. Choose Enforce its rules to start a run under it.", "Enforce its rules", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := guidetest.Make(t, tc.fixture)
			if tc.name == "noncompiling" {
				if err := os.WriteFile(filepath.Join(f.Registry, "agents", "bot.yaml"), []byte("not: [valid"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.name != "unchecked" {
				if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
					t.Fatal(err)
				}
			}
			s := guideServer(t, f)
			g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
			if g.Next.Rule != tc.rule {
				t.Fatalf("rule %s, want %s", g.Next.Rule, tc.rule)
			}
			body := get(t, s, login(t, s), tourURL(g, "review"))
			if got := text(tourNode(t, body, "gf-action")); got != tc.action {
				t.Errorf("action %q, want %q", got, tc.action)
			}
			if got := text(tourNode(t, body, "gf-instruction")); got != tc.instruction {
				t.Errorf("instruction %q, want %q for action %q", got, tc.instruction, tc.action)
			}
			if tc.command == "" {
				if strings.Contains(body, `id="gf-command"`) {
					t.Error("saved contract unexpectedly shows a terminal command")
				}
			} else if got := text(tourNode(t, body, "gf-command")); !strings.Contains(got, tc.command) {
				t.Errorf("command %q, want %q", got, tc.command)
			}
		})
	}
}

func tourBuilderMode(t *testing.T, body, label string) string {
	t.Helper()
	var href string
	walk(tourNode(t, body, "nw-mode"), func(n *html.Node) {
		if n.Data == "a" && text(n) == label {
			href, _ = attr(n, "href")
		}
	})
	if href == "" {
		t.Fatalf("missing mode %s", label)
	}
	u, err := url.Parse(href)
	if err != nil || u.Query().Get("guide") != "review" {
		t.Fatalf("mode %s drops Review: %s", label, href)
	}
	return href
}

func TestTourReviewBuilderKeepsContextThroughPreviewAndSave(t *testing.T) {
	f := guidetest.Make(t, guidetest.HalfDone)
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	s := guideServer(t, f)
	s.cfg.Setup = &rules.Service{Ledger: f.Ledger, Home: f.Home, Machine: f.Machine(t), Anchor: f.Anchor, Compile: func(context.Context, rules.CheckContext, []byte) error { return nil }}
	c := login(t, s)
	g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
	body := get(t, s, c, tourURL(g, "review"))
	href, _ := attr(tourNode(t, body, "gf-action"), "href")
	preview := get(t, s, c, href)
	// Follow both mode links, including the selected mode, before preview and save.
	for _, stage := range []string{"before preview", "before save"} {
		for _, label := range []string{"From a run", "From presets", "From presets", "From a run"} {
			preview = get(t, s, c, tourBuilderMode(t, preview, label))
			if !strings.Contains(preview, `class="gf"`) {
				t.Fatalf("%s: %s loses frame", stage, label)
			}
		}
		formURL, err := url.Parse(tourBuilderMode(t, preview, "From a run"))
		if err != nil {
			t.Fatal(err)
		}
		q := formURL.Query()
		q.Set("from", tourFact(g, guide.StepRecord).Run)
		q.Set("preview", "1")
		q.Set("to", "registry")
		q.Set("reads", "on")
		formURL.RawQuery = q.Encode()
		preview = get(t, s, c, formURL.String())
	}
	product := tourNode(t, preview, "gf-product")
	if _, ok := attr(product, "open"); !ok {
		t.Error("phone builder is closed behind a self-link")
	}
	form := tourNode(t, preview, "nw-form")
	keep := false
	walk(form, func(n *html.Node) {
		name, _ := attr(n, "name")
		value, _ := attr(n, "value")
		if name == "guide" && value == "review" {
			keep = true
		}
	})
	if !keep {
		t.Error("preview drops guide")
	}
	// Registry preparation is now a guarded POST. Submit the rendered source
	// form, then save the exact reviewed proposal returned by that POST.
	source := builderRenderedSourceForm(t, preview)
	prepared := post(s, "/rules/new?guide=review&preview=1", source, own, "", c)
	if prepared.Code != http.StatusOK {
		t.Fatalf("prepare preview: %d %s", prepared.Code, prepared.Body.String())
	}
	preview = prepared.Body.String()
	if !strings.Contains(preview, `class="gf"`) {
		t.Fatal("preparation dropped guide")
	}
	values := builderRenderedSaveForm(t, preview)
	if values.Get("guide") != "review" {
		t.Error("save drops guide")
	}
	// Make the pre-save memo fresh for the entire test, independent of host load.
	s.guide.mu.Lock()
	s.guide.at = time.Now().Add(time.Hour)
	s.guide.mu.Unlock()
	for _, base := range []string{"invalid", values.Get("base")} {
		values.Set("base", base)
		w := post(s, "/rules/new", values, own, "", c)
		if base == "invalid" {
			if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), rules.ErrReviewGone.Error()) || !strings.Contains(w.Body.String(), `class="gf"`) {
				t.Fatalf("unknown review lost guide or refusal: %d %s", w.Code, w.Body.String())
			}
			continue
		}
		if w.Code != 303 {
			t.Fatalf("save: %d %s", w.Code, w.Body.String())
		}
		dst := w.Header().Get("Location")
		if !strings.Contains(dst, "guide=review") {
			t.Fatalf("save result loses guide: %s", dst)
		}
		result := get(t, s, c, dst)
		if !strings.Contains(result, `class="gf"`) {
			t.Fatal("save result has no frame")
		}
		if base != "invalid" {
			if text(tourNode(t, result, "gf-action")) != "Enforce its rules" {
				t.Error("saved contract still points at a form")
			}
			updated := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
			if tourFact(updated, guide.StepContract).State != guide.Done {
				t.Error("save left the guide on a stale contract fact")
			}
		}
	}
}

func TestTourOfferFollowsItsLiveRegion(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	s := guideServer(t, f)
	body := get(t, s, login(t, s), "/")
	offer := tourNode(t, body, "gf-offer")
	inRegion := false
	for n := offer.Parent; n != nil; n = n.Parent {
		if name, _ := attr(n, "data-live"); name == "r-guide" {
			inRegion = true
		}
	}
	if !inRegion {
		t.Error("guide offer cannot disappear when live facts finish")
	}
}

func TestTourSavedBuilderKeepsRequestPriority(t *testing.T) {
	f := tourValues(t, "pending")
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	s := guideServer(t, f)
	id := s.keep(newData{Created: &rules.Created{Name: "bot"}})
	body := get(t, s, login(t, s), "/rules/new?guide=review&created="+id)
	href, _ := attr(tourNode(t, body, "gf-action"), "href")
	if href != "/approvals" {
		t.Errorf("saved builder displaced waiting request with %s", href)
	}
}

func TestTourRecordedProgramsLeadTheFacts(t *testing.T) {
	f := tourValues(t, "recorded-programs")
	s := guideServer(t, f)
	g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
	body := get(t, s, login(t, s), tourURL(g, "recorded"))
	facts := tourNode(t, body, "gf-facts")
	var label, value string
	walk(facts, func(n *html.Node) {
		if n.Data == "dt" && label == "" {
			label = text(n)
		}
		if n.Data == "dd" && value == "" {
			value = text(n)
		}
	})
	if label != "Programs" || value != "Started /usr/bin/git" {
		t.Errorf("recorded program remains behind disclosure: %q %q", label, value)
	}
}

func TestTourNativeWatchDoesNotPromiseAutomaticMove(t *testing.T) {
	f := guidetest.Make(t, guidetest.HalfDone)
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	s := guideServer(t, f)
	g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
	body := get(t, s, login(t, s), tourURL(g, "watch"))
	status := text(tourNode(t, body, "gf-status"))
	if !strings.Contains(status, "Step 4 is ready") || strings.Contains(status, "Moving to") {
		t.Errorf("native Watch promises a scripted move: %s", status)
	}
}

func TestTourEarlyWatchKeepsTheMachineCheckFirst(t *testing.T) {
	f := guidetest.Make(t, guidetest.HalfDone)
	s := guideServer(t, f)
	g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
	body := get(t, s, login(t, s), tourURL(g, "watch"))
	frame := tourNode(t, body, "gf")
	if next, _ := attr(frame, "data-guide-move"); next != "" {
		t.Errorf("automatic move bypasses the missing machine check: %s", next)
	}
	if text(tourNode(t, body, "gf-action")) != "Check this machine first" {
		t.Error("missing check has no priority")
	}
}

func TestTourEntrySkipsOnlyCompletedOrSkippedFacts(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{guidetest.Fresh, "pick"}, {guidetest.Recording, "watch"}, {guidetest.HalfDone, "review"}, {guidetest.ContractMade, "enforce"}, {guidetest.Finished, "enforce"}, {guidetest.NotReady, "check"}, {guidetest.Outside, "check"}, {guidetest.Tampered, "enforce"}, {guidetest.HandWritten, "enforce"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := guidetest.Make(t, tc.name)
			if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
				t.Fatal(err)
			}
			s := guideServer(t, f)
			r := httptest.NewRequest("GET", "/guide", nil)
			r.Host = "127.0.0.1:8484"
			r.AddCookie(login(t, s))
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if dst := w.Header().Get("Location"); !strings.HasSuffix(dst, "guide="+tc.want) {
				t.Errorf("entry %s want %s", dst, tc.want)
			}
		})
	}
	// An unreadable recording is the first unfinished fact, before Recorded.
	f := guidetest.Make(t, guidetest.Finished)
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.Anchor); err != nil {
		t.Fatal(err)
	}
	s := guideServer(t, f)
	g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
	if got := tourCurrent(g); got != "watch" {
		t.Errorf("unknown recording entry %s want watch", got)
	}
	body := get(t, s, login(t, s), tourURL(g, "watch"))
	if got := text(tourNode(t, body, "gf-action")); got != "Inspect the record" {
		t.Errorf("unknown recording action %q", got)
	}
}

func TestTourSavedContractNeedsNoPlaceholderRecording(t *testing.T) {
	f := guidetest.Make(t, guidetest.ContractMade)
	if err := os.RemoveAll(f.Ledger); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.Ledger, 0700); err != nil {
		t.Fatal(err)
	}
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	s := guideServer(t, f)
	g := s.setupGuide(t.Context(), mustTourSnapshot(t, f))
	if tourFact(g, guide.StepFind).State != guide.Todo || tourFact(g, guide.StepRecord).State != guide.Skipped || tourFact(g, guide.StepContract).State != guide.Done {
		t.Fatal("fixture must have a saved contract and no runs")
	}
	for _, key := range []string{"pick", "watch"} {
		body := get(t, s, login(t, s), tourURL(g, key))
		action := tourNode(t, body, "gf-action")
		href, _ := attr(action, "href")
		if href != "/guide?step=enforce" {
			t.Errorf("%s leaves the first run without a command: %s", key, href)
		}
	}
}
