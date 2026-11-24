// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"golang.org/x/net/html"
)

const secondRequestRun = "r-bbbbbbbb-0000000000003-second"

func twoRequestFixture(t *testing.T) string {
	t.Helper()
	root := fixture(t)
	if err := os.MkdirAll(filepath.Join(root, secondRequestRun), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, secondRequestRun, "events.jsonl"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 25, 12, 3, 0, 0, time.UTC)
	appendLine(t, root, secondRequestRun, line(secondRequestRun, "Second agent", 0, at, "run_start", `"tier":"landlock","command":["sh"],"cwd":"/p"`))
	appendLine(t, root, secondRequestRun, line(secondRequestRun, "Second agent", 1, at.Add(time.Second), "ask", `"ask_id":"ask-B","op":"connect","hold":"net","target":"second.example:443"`))
	markLive(t, root, secondRequestRun)
	return root
}

// Follow the links as a browser with scripts disabled does, then submit the
// rendered form. Identity is checked at the broker boundary, not by copy alone.
func TestRequestNavigationAndDecisionIdentity(t *testing.T) {
	var decidedRun, decidedAsk string
	old := answerAsk
	t.Cleanup(func() { answerAsk = old })
	answerAsk = func(_ context.Context, _, run, ask string, _, _ bool) (runact.Answered, error) {
		decidedRun, decidedAsk = run, ask
		return runact.Answered{Run: run, Word: "Denied"}, nil
	}
	for _, from := range []string{"/", "/runs/" + secondRequestRun} {
		t.Run(from, func(t *testing.T) {
			s := newServer(t, twoRequestFixture(t))
			c := login(t, s)
			body := get(t, s, c, from)
			seen := 0
			walk(parseHTML(t, "source", body), func(n *html.Node) {
				href, _ := attr(n, "href")
				if n.Data != "a" || !strings.HasPrefix(href, "/approvals") {
					return
				}
				label := text(n)
				runWaitingCount := n.Parent != nil && n.Parent.Data == "dd" && strings.Contains(label, "waiting")
				if !runWaitingCount && !strings.Contains(label, "Review") && !strings.Contains(label, "waiting on you") && !(strings.Contains(href, "ask-B") || strings.Contains(label, "second.example")) {
					return
				}
				u, err := url.Parse(href)
				if err != nil {
					t.Fatal(err)
				}
				if u.Query().Get("run") == "" || u.Query().Get("ask") == "" {
					t.Errorf("request link loses identity: %s", href)
					return
				}
				if u.Query().Get("run") != secondRequestRun {
					return
				}
				seen++
				if seen > 1 {
					return
				}
				u.Fragment = ""
				detail := get(t, s, c, u.String())
				forms := decisionForms(t, detail)
				if len(forms) == 0 {
					t.Fatalf("no decision forms at %s: %s", href, detail)
				}
				for _, form := range forms {
					if form.Get("run") != secondRequestRun || form.Get("ask") != "ask-B" {
						t.Fatalf("B link rendered another identity: %v", form)
					}
				}
				form := forms[0]
				form.Set("decision", "deny")
				// A stale A address must never override the rendered B fields.
				w := post(s, "/approvals/answer?run="+harmRun+"&ask=ask-7", form, own, own+"/approvals?run="+harmRun+"&ask=ask-7", c)
				if w.Code != 303 || decidedRun != secondRequestRun || decidedAsk != "ask-B" {
					t.Fatalf("B form submitted %s/%s status %d", decidedRun, decidedAsk, w.Code)
				}
			})
			if seen == 0 {
				t.Error("did not find exact request B navigation")
			}
		})
	}
}

func decisionForms(t *testing.T, body string) []url.Values {
	t.Helper()
	var forms []url.Values
	walk(parseHTML(t, "forms", body), func(n *html.Node) {
		action, _ := attr(n, "action")
		if n.Data != "form" || action != "/approvals/answer" {
			return
		}
		f := url.Values{}
		walk(n, func(v *html.Node) {
			if v.Data == "input" {
				name, _ := attr(v, "name")
				value, _ := attr(v, "value")
				f.Set(name, value)
			}
		})
		forms = append(forms, f)
	})
	return forms
}

func TestMissingRequestSelectionHasNoOtherDecisionControls(t *testing.T) {
	s := newServer(t, twoRequestFixture(t))
	c := login(t, s)
	for _, q := range []string{"run=absent&ask=ask-B", "run=" + secondRequestRun + "&ask=absent", "run=" + secondRequestRun, "ask=ask-B", "run=&ask="} {
		b := get(t, s, c, "/approvals?"+q)
		if !strings.Contains(b, "This request is not waiting") {
			t.Errorf("%s lacks missing request explanation", q)
		}
		if fs := decisionForms(t, b); len(fs) != 0 {
			t.Errorf("%s offers other request forms: %v", q, fs)
		}
	}
}

func TestAttentionPriorityHeadlineAndBodyCombinations(t *testing.T) {
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	for mask := 0; mask < 16; mask++ {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			d := overviewData{Total: 1}
			r := runData{Run: &ledgerview.Run{ID: secondRequestRun, Live: true}, Now: time.Now()}
			want := "Nothing needs you"
			if mask&8 != 0 {
				d.Watched = 1
				r.Story.Read = []string{"/secret"}
				want = "Sensitive read recorded"
			}
			if mask&4 != 0 {
				d.Leaked = 1
				r.Story.Kind = ledgerview.VerdictLeak
				r.Story.Exposed = []string{"/secret"}
				r.Story.Dests = []string{"unexpected.example"}
				want = "Secret leak recorded"
			}
			if mask&2 != 0 {
				d.Chain.Broken = &ledgerview.Chain{Run: secondRequestRun, State: ledgerview.ChainBroken}
				r.Chain = *d.Chain.Broken
				want = "Record needs attention"
			}
			if mask&1 != 0 {
				d.Pending = []ledgerview.Ask{{Run: secondRequestRun, AskID: "ask-B"}}
				r.Run.Pending = d.Pending
				want = "1 request needs you"
			}
			for _, tc := range []struct {
				name, region string
				data         any
			}{{"overview", "r-ov-head", d}, {"run", "r-run-top", r}} {
				var b bytes.Buffer
				if err := pages[tc.name].ExecuteTemplate(&b, tc.region, page{Data: tc.data}); err != nil {
					t.Fatal(err)
				}
				body := b.String()
				heading := ""
				var kinds []string
				bodies := map[string]string{}
				walk(parseHTML(t, tc.name, body), func(n *html.Node) {
					class, _ := attr(n, "class")
					if heading == "" && ((tc.name == "overview" && n.Data == "h1") || (tc.name == "run" && class == "vt")) {
						heading = text(n)
					}
					if kind, _ := attr(n, "data-attention"); kind != "" {
						kinds = append(kinds, kind)
						bodies[kind] = text(n)
					}
				})
				if mask == 0 && tc.name == "run" && !strings.HasPrefix(heading, "No secret read or unexpected send recorded") {
					t.Errorf("quiet Run must qualify absence: %q", heading)
				}
				if mask != 0 || tc.name == "overview" {
					if heading != want {
						t.Errorf("%s headline got %q want %q", tc.name, heading, want)
					}
				}
				var wantKinds []string
				for _, condition := range []struct {
					bit         int
					kind, words string
				}{{1, "waiting", "1 waiting"}, {2, "broken", "Record needs attention"}, {4, "leak", "leaked secrets"}, {8, "read", "read secrets"}} {
					if mask&condition.bit != 0 {
						wantKinds = append(wantKinds, condition.kind)
						if !strings.Contains(bodies[condition.kind], condition.words) {
							t.Errorf("%s missing condition body %q", tc.name, condition.words)
						}
					}
				}
				if strings.Join(kinds, ",") != strings.Join(wantKinds, ",") {
					t.Errorf("%s condition priority %v want %v", tc.name, kinds, wantKinds)
				}
				if mask&4 != 0 && (strings.Contains(body, "send was not seen") || strings.Contains(body, "no new destination")) {
					t.Errorf("%s denies a recorded send: %s", tc.name, body)
				}
				if mask != 0 && (strings.Contains(body, "Nothing needs you") || strings.Contains(strings.ToLower(body), "safe")) {
					t.Errorf("%s contradicts conditions: %s", tc.name, body)
				}
			}
		})
	}
}

func TestAttentionUsesActualContractSensitiveReads(t *testing.T) {
	for i, tc := range []struct {
		name, path, verdict, extra string
		want                       bool
	}{
		{"contract read", "/p/workpapers/plan.data", "allow", `"flags":0`, true},
		{"own allowed login", "/home/u/.codex/auth.json", "allow", `"flags":0`, false},
		{"own observed login", "/home/u/.codex/auth.json", "observed", `"flags":0`, true},
		{"write only", "/p/workpapers/plan.data", "allow", `"flags":1`, false},
		{"failed read", "/p/workpapers/plan.data", "allow", `"flags":0,"errno":13`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Contains(tc.path, "workpapers") && ledgerview.IsSecretPath(tc.path) {
				t.Fatal("custom path must require contract context")
			}
			root := t.TempDir()
			id := fmt.Sprintf("r-bbbbbbbb-0000000000003-secon%d", i)
			dir := filepath.Join(root, id)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			at := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
			tier := "landlock"
			if tc.verdict == "observed" {
				tier = "observe"
			}
			events := line(id, "codex", 0, at, "run_start", `"tier":"`+tier+`","capture":"forwarder","command":["codex"],"cwd":"/p"`) + line(id, "codex", 1, at.Add(time.Second), "fs", `"rule":"unmatched","verdict":"`+tc.verdict+`","op":"open","path":"`+tc.path+`",`+tc.extra)
			if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(events), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte("version: 0\nagent: codex\nfs:\n  deny_read:\n    - ./workpapers/\n"), 0600); err != nil {
				t.Fatal(err)
			}
			markLive(t, root, id)
			s := newServer(t, root)
			c := login(t, s)
			for _, path := range []string{"/", "/runs/" + id} {
				b := get(t, s, c, path)
				if got := strings.Contains(b, `data-attention="read"`); got != tc.want {
					t.Errorf("%s sensitive read condition=%v want %v", path, got, tc.want)
				}
				if tc.want && !strings.Contains(b, "Sensitive read recorded") {
					t.Errorf("%s misses sensitive read headline", path)
				}
				if tc.want && strings.Contains(b, "Nothing needs you") {
					t.Errorf("%s claims all clear over protected read", path)
				}
			}
		})
	}
}

func TestRequestURLsPreserveSpecialIdentity(t *testing.T) {
	root := twoRequestFixture(t)
	const special = "ask+B/?&=%"
	file := filepath.Join(root, secondRequestRun, "events.jsonl")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, bytes.ReplaceAll(data, []byte("ask-B"), []byte(special)), 0600); err != nil {
		t.Fatal(err)
	}
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, time.Now(), "answer", `"ask_id":"ask-7","approved":false`))
	s := newServer(t, root)
	c := login(t, s)
	for _, from := range []string{"/", "/runs/" + secondRequestRun, "/approvals", "/approvals?run=" + secondRequestRun + "&ask=" + url.QueryEscape(special)} {
		found := 0
		walk(parseHTML(t, "links", get(t, s, c, from)), func(n *html.Node) {
			href, _ := attr(n, "href")
			if n.Data != "a" || !strings.HasPrefix(href, "/approvals?") {
				return
			}
			u, err := url.Parse(href)
			if err != nil {
				t.Fatal(err)
			}
			if u.Query().Get("run") != secondRequestRun {
				return
			}
			found++
			if got := u.Query().Get("ask"); got != special {
				t.Errorf("%s link query changed identity to %q: %s", from, got, href)
				return
			}
			u.Fragment = ""
			fs := decisionForms(t, get(t, s, c, u.String()))
			if len(fs) == 0 {
				t.Errorf("%s link lost selected form", from)
			}
			for _, f := range fs {
				if f.Get("run") != secondRequestRun || f.Get("ask") != special {
					t.Errorf("%s changed form identity %v", from, f)
				}
			}
		})
		if found == 0 {
			t.Errorf("%s no exact request navigation", from)
		}
	}
}

// Incompleteness is a condition in its own right, including when every retained
// request was answered but a request outside the display budget still waits.
func TestAttentionIncompleteSources(t *testing.T) {
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range incompleteAttentionCases() {
		t.Run(tc.name, func(t *testing.T) {
			for _, pg := range incompleteAttentionPages(tc.source, tc.pending) {

				var b bytes.Buffer
				if err := pages[pg.name].ExecuteTemplate(&b, pg.region, page{chrome: chrome{Numbers: pg.numbers}, Data: pg.data}); err != nil {
					t.Fatal(err)
				}
				body := text(parseHTML(t, pg.name, b.String()))
				if pg.name == "approvals" && tc.source.forApprovals() == (attentionSource{}) {
					if !strings.Contains(body, "Nothing waiting") {
						t.Errorf("Approvals qualified the headline by an unrelated source: %s", body)
					}
					continue
				}
				if !strings.Contains(body, tc.headline) || !strings.Contains(body, tc.reason) {
					t.Errorf("%s misses incompleteness headline/reason: %s", pg.name, body)
				}
				for _, claim := range []string{"Nothing needs you", "Nothing waiting", "No secret read or unexpected send recorded"} {
					if strings.Contains(body, claim) {
						t.Errorf("%s contradicts incomplete source with %q", pg.name, claim)
					}
				}
				if !strings.Contains(b.String(), `href="/runs`) && !strings.Contains(b.String(), `href="/approvals`) {
					t.Errorf("%s lacks recovery link", pg.name)
				}
			}
		})
	}
}

type incompleteAttentionCase struct {
	name             string
	source           attentionSource
	pending          []ledgerview.Ask
	headline, reason string
}

func incompleteAttentionCases() []incompleteAttentionCase {
	return []incompleteAttentionCase{
		{"pending cut, retained requests answered", attentionSource{PendingReason: "the list is too long to show"}, nil, "could not tell whether a request is waiting", "the list is too long to show"},
		{"pending cut, known request", attentionSource{PendingReason: "the list is too long to show"}, []ledgerview.Ask{{Run: secondRequestRun, AskID: "ask-B"}}, "at least 1 waiting", "the list is too long to show"},
		{"pending unreadable", attentionSource{PendingReason: "the request list could not be read", PendingUnreadable: true}, nil, "could not tell whether a request is waiting", "could not be read"},
		{"pending unreadable with known request", attentionSource{PendingReason: "the request list could not be read", PendingUnreadable: true}, []ledgerview.Ask{{Run: secondRequestRun, AskID: "ask-B"}}, "at least 1 waiting", "could not be read"},
		{"snapshot reader error", attentionSourceOf(&ledgerview.Snapshot{ReadError: "permission denied"}), nil, "could not tell whether a request is waiting", "permission denied"},
		{"snapshot reader error with known request", attentionSourceOf(&ledgerview.Snapshot{ReadError: "permission denied"}), []ledgerview.Ask{{Run: secondRequestRun, AskID: "ask-B"}}, "at least 1 waiting", "permission denied"},
		{"record unreadable", attentionSource{RecordReason: "a record contains unreadable lines"}, nil, "Could not read the full record", "unreadable lines"},
		{"counts lower bound", attentionSource{CountsReason: "only retained event windows were read"}, nil, "Some attention needs are not known", "retained event windows"},
	}
}

type attentionPage struct {
	name, region string
	data         any
	numbers      countScopes
}

func incompleteAttentionPages(source attentionSource, pending []ledgerview.Ask) []attentionPage {
	var numbers countScopes
	if source.PendingReason != "" {
		numbers.Pending = countScope{Lower: true, Reason: source.PendingReason}
	}
	if source.PendingUnreadable {
		numbers.Pending = countScope{Error: source.PendingReason}
	}
	if source.CountsReason != "" {
		numbers.Window = countScope{Lower: true, Reason: source.CountsReason}
	}
	if source.RecordReason != "" {
		numbers.Aggregate = countScope{Error: source.RecordReason}
		numbers.Window = numbers.Aggregate
	}
	numbers.Queue = numbers.Pending
	return []attentionPage{
		{"overview", "r-ov-head", overviewData{Total: 1, AttentionSource: source, Pending: pending}, numbers},
		{"run", "r-run-top", runData{AttentionSource: source, Run: &ledgerview.Run{ID: secondRequestRun, Live: true, Pending: pending}}, numbers},
		{"approvals", "content", approvalsData{AttentionSource: source, Pending: pending}, numbers},
	}
}

func TestAttentionCompletenessDerivesFromReadModel(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		snap                    *ledgerview.Snapshot
		pending, record, counts bool
	}{
		{"pending budget", &ledgerview.Snapshot{Runs: []*ledgerview.Run{{Live: true, PendingCut: true}}}, true, false, false},
		{"unreadable live record", &ledgerview.Snapshot{Runs: []*ledgerview.Run{{Live: true, Bad: 1}}}, true, true, false},
		{"unreadable ended record", &ledgerview.Snapshot{Runs: []*ledgerview.Run{{Ended: true, Bad: 1}}}, false, true, false},
		{"reader failed for live run", &ledgerview.Snapshot{Runs: []*ledgerview.Run{{Live: true, ReadError: "permission denied"}}}, true, true, false},
		{"reader failed for ended run", &ledgerview.Snapshot{Runs: []*ledgerview.Run{{Ended: true, ReadError: "permission denied"}}}, false, true, false},
		{"candidate reader failed", &ledgerview.Snapshot{ReadError: "permission denied"}, true, true, false},
		{"still reading", &ledgerview.Snapshot{Partial: true}, true, false, true},
		{"runs omitted", &ledgerview.Snapshot{RunsCut: true}, true, false, true},
		{"window truncated", &ledgerview.Snapshot{Runs: []*ledgerview.Run{{Cut: true}}}, false, false, true},
		{"events evicted", &ledgerview.Snapshot{LinesCut: true}, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := attentionSourceOf(tc.snap)
			if (got.PendingReason != "") != tc.pending || (got.RecordReason != "") != tc.record || (got.CountsReason != "") != tc.counts {
				t.Errorf("incomplete source = %+v", got)
			}
		})
	}
}

func TestAttentionPendingBudgetWithOnlyOmittedRequestWaiting(t *testing.T) {
	root := t.TempDir()
	id := secondRequestRun
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	var events strings.Builder
	events.WriteString(line(id, "Agent", 0, at, "run_start", `"tier":"observe","command":["agent"]`))
	// Large request details exhaust the separate pending-display byte budget
	// with only a small event fixture. The omitted request remains unanswered.
	for seq := 1; seq <= 20; seq++ {
		events.WriteString(line(id, "Agent", seq, at.Add(time.Duration(seq)*time.Second), "ask", fmt.Sprintf(`"ask_id":"q-%d","hold":"%s","op":"open","target":"/work/a"`, seq, strings.Repeat("h", 64<<10))))
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(events.String()), 0600); err != nil {
		t.Fatal(err)
	}
	markLive(t, root, id)
	r, err := ledgerview.LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if !r.PendingCut || len(r.Pending) == 0 || len(r.Pending) >= 20 {
		t.Fatalf("fixture did not cut the pending list: cut=%v retained=%d", r.PendingCut, len(r.Pending))
	}
	for i, a := range r.Pending {
		appendLine(t, root, id, line(id, "Agent", 21+i, at.Add(time.Minute), "answer", fmt.Sprintf(`"ask_id":%q,"approved":true,"by":"owner"`, a.AskID)))
	}
	r, err = ledgerview.LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if !r.PendingCut || len(r.Pending) != 0 {
		t.Fatalf("fixture must leave only omitted requests waiting: cut=%v retained=%d", r.PendingCut, len(r.Pending))
	}
	s := newServer(t, root)
	c := login(t, s)
	for _, path := range []string{"/", "/approvals", "/runs/" + id} {
		body := get(t, s, c, path)
		if !strings.Contains(body, "could not tell whether a request is waiting") || !strings.Contains(body, "The waiting list is too long to show.") {
			t.Errorf("%s omits waiting uncertainty", path)
		}
		for _, claim := range []string{"Nothing needs you", "Nothing waiting", "No secret read or unexpected send recorded"} {
			if strings.Contains(body, claim) {
				t.Errorf("%s claims %q with an omitted waiting request", path, claim)
			}
		}
	}
}

func TestAttentionKnownFactsSurviveIncompleteSources(t *testing.T) {
	pending := []ledgerview.Ask{{Run: secondRequestRun, AskID: "ask-B"}}
	for _, tc := range []struct {
		name                string
		source              attentionSource
		waiting, leak, read string
	}{
		{"lower bound", attentionSource{PendingReason: "the list is too long to show", CountsReason: "only retained event windows were read"}, "at least 1 waiting", "At least 1 run leaked secrets", "At least 1 run read secrets"},
		{"unreadable", attentionSource{PendingReason: "the list could not be read", PendingUnreadable: true, RecordReason: "unreadable lines"}, "at least 1 waiting", "Secret leak recorded", "Sensitive read recorded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := attentionOf(pending, nil, 1, 1, tc.source, nil)
			if got.Headline != tc.waiting {
				t.Errorf("headline %q want %q", got.Headline, tc.waiting)
			}
			bodies := map[string]string{}
			for _, item := range got.Items {
				bodies[item.Kind] = item.Body
			}
			for kind, want := range map[string]string{"waiting": tc.waiting, "leak": tc.leak, "read": tc.read} {
				if !strings.Contains(bodies[kind], want) {
					t.Errorf("%s body %q omits known fact %q", kind, bodies[kind], want)
				}
			}
			if tc.source.RecordReason != "" {
				for _, item := range got.Items {
					if item.Kind != "waiting" && strings.ContainsAny(item.Body, "0123456789") {
						t.Errorf("reader failure still displays a count: %q", item.Body)
					}
				}
			}
		})
	}
}

// TestApprovalsKeepsNothingWaitingOverCutWindows: the waiting list is kept over the whole run with its own budget,
// so a lower bound on event counts leaves Approvals' "Nothing waiting" true, while the Overview, which judges leaks and
// reads from the retained windows, says some attention needs are not known.
func TestApprovalsKeepsNothingWaitingOverCutWindows(t *testing.T) {
	source := attentionSourceOf(&ledgerview.Snapshot{Runs: []*ledgerview.Run{{Cut: true}}})
	if got := (approvalsData{AttentionSource: source}).Attention(); got.Headline != "Nothing needs you" || len(got.Items) != 0 {
		t.Errorf("Approvals over cut windows: %+v", got)
	}
	if got := (overviewData{AttentionSource: source}).Attention(); got.Headline != "Some attention needs are not known" {
		t.Errorf("Overview over cut windows: %+v", got)
	}
}
