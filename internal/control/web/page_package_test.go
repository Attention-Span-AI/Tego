// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"html"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestPagePackageSummaryContracts(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	for _, tc := range []struct {
		path  string
		words []string
	}{
		{"/logs", []string{`data-filter-open`, `dialog class="filter-sheet`, `class="phone-row"`, `class="phone-who"`, `class="phone-when"`, `summary-table`}},
		{"/logs?filters=1", []string{`filter-fallback`, `name="where"`, `name="verdict"`, `name="group"`}},
		{"/detections", []string{`data-filter-open`, `class="phone-row"`, `summary-table`}},
		{"/approvals", []string{`approval-queue`, `ap-detail`, `Allow once lets this request`, `Deny refuses this request`}},
		{"/compare?a=" + harmRun + "&b=" + cleanRun, []string{`What changed between runs?`, `cmp-details`, `Run A`, `Run B`}},
	} {
		b := get(t, s, c, tc.path)
		for _, w := range tc.words {
			if !strings.Contains(b, w) {
				t.Errorf("%s missing %s", tc.path, w)
			}
		}
	}
}

func TestApprovalQueueHasExactDetailDestinations(t *testing.T) {
	s := newServer(t, mutationAskFixture(t))
	c := login(t, s)
	queue := get(t, s, c, "/approvals")
	if strings.Count(queue, `<section class="ask"`) != 1 {
		t.Fatal("queue repeats full request cards")
	}
	for _, a := range mutAsks {
		if !strings.Contains(queue, "ask="+a.id) {
			t.Errorf("missing destination %s", a.id)
		}
		detail := get(t, s, c, "/approvals?run="+mutRun+"&ask="+a.id)
		for _, want := range []string{a.target, `name="ask" value="` + a.id + `"`, a.question[:8], "Why it asked", "when its time runs out"} {
			if !strings.Contains(f3Text(detail), want) && !strings.Contains(detail, want) {
				t.Errorf("%s missing %s", a.id, want)
			}
		}
	}
}

func TestLogsProtectedReadChipIsAnActualRead(t *testing.T) {
	root := fixture(t)
	for i, extra := range []string{
		`"verdict":"allow","op":"open","flags":0,"path":"/home/dana/.ssh/id_rsa"`,
		`"verdict":"allow","op":"open","flags":1,"path":"/home/dana/.ssh/id_rsa"`,
		`"verdict":"allow","op":"open","flags":0,"errno":13,"path":"/home/dana/.ssh/id_rsa"`,
		`"verdict":"observed","op":"open","flags":0,"path":"/home/dana/.ssh/id_rsa"`,
	} {
		appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7+i, time.Now().Add(time.Duration(i)*time.Second), "fs", extra))
	}
	s := newServer(t, root)
	c := login(t, s)
	body := get(t, s, c, "/logs?noise=show")
	for i, want := range []string{"through i-triangle-alert Read allowed", "allowed i-check Allowed", "allowed i-check Allowed", "through i-triangle-alert Read, not refused"} {
		from := fmt.Sprintf(`data-k="%s-%d"`, harmRun, 7+i)
		if got := chipIn(t, "Logs", body, from, "</tr>"); got != want {
			t.Errorf("line %d got %s, want %s", 7+i, got, want)
		}
	}
}

func TestLogGroupSummaryRecoversItsExactFacts(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	body := get(t, s, c, "/logs?group=target")
	links := regexp.MustCompile(`href="([^"]*group_detail=[^"]*)"`).FindAllStringSubmatch(body, -1)
	if len(links) == 0 {
		t.Fatal("groups have no native detail destinations")
	}
	for _, link := range links {
		detail := get(t, s, c, html.UnescapeString(link[1]))
		for _, fact := range []string{"Group details", "Lines", "Refused", "First", "Last", "Newest event"} {
			if !strings.Contains(detail, fact) {
				t.Errorf("%s missing %s", link[1], fact)
			}
		}
	}
}

func TestPagePackageContrastPairs(t *testing.T) {
	b, err := assets.ReadFile("static/tokens.css")
	if err != nil {
		t.Fatal(err)
	}
	for theme, marker := range map[string]string{"light": ":root {\n", "dark": `:root[data-theme="dark"] {`} {
		tk := tokenBlock(t, string(b), marker)
		for _, pair := range [][2]string{{"ask-text", "surface"}, {"ask-text", "ask-soft"}, {"text2", "surface"}, {"text3", "surface"}, {"text2", "ask-soft"}, {"refused", "refused-soft"}, {"on-through", "through"}} {
			r := contrast(tk[pair[0]], tk[pair[1]])
			t.Logf("%s %s/%s %.2f:1", theme, pair[0], pair[1], r)
			if r < 4.5 {
				t.Errorf("%s pair %v below 4.5", theme, pair)
			}
		}
	}
}

func TestSavedApprovalAnswerSurvivesHistoryPageLimit(t *testing.T) {
	root := fixture(t)
	at := time.Now()
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, at, "answer", `"ask_id":"ask-7","approved":false,"by":"Early Dana","op":"connect","target":"example.com:443"`))
	for i := 0; i < 210; i++ {
		appendLine(t, root, harmRun, line(harmRun, "demo-harm", 8+i, at.Add(time.Duration(i+1)*time.Second), "answer", fmt.Sprintf(`"ask_id":"later-%d","approved":false,"by":"Later Sam"`, i)))
	}
	s := newServer(t, root)
	c := login(t, s)
	body := get(t, s, c, "/approvals?run="+harmRun+"&ask=ask-7")
	for _, want := range []string{"Request answered", "Early Dana", "example.com:443"} {
		if !strings.Contains(body, want) {
			t.Errorf("saved answer missing %s", want)
		}
	}
	if strings.Contains(body, `name="decision" value="approve"`) {
		t.Error("answered request still offers a live answer")
	}
}

func TestCompareRefusedToneUsesRefusedChip(t *testing.T) {
	tone := funcs["cmpTone"].(func(ledgerview.CmpCell) string)
	for _, v := range []string{ledgerview.ToneGood, ledgerview.ToneMuted} {
		if got := tone(ledgerview.CmpCell{Tone: v}); got != "refused" {
			t.Errorf("refused outcome %s uses %s", v, got)
		}
	}
}

func TestCompareSummaryReflectsRecordedSensitiveReads(t *testing.T) {
	got := cmpStat(ledgerview.CmpSide{Run: &ledgerview.Run{Tier: "landlock"}, SecretsOpened: 1}, "A")
	if got.Head != "1 sensitive file touched" || got.Detail != "0 off-list connections recorded" {
		t.Errorf("recorded read summary: %+v", got)
	}
	protected := cmpStat(ledgerview.CmpSide{Run: &ledgerview.Run{Tier: "landlock"}, Verdict: ledgerview.Verdict{Kind: ledgerview.VerdictProtected, SecretReads: 2, Sends: 1}}, "B")
	if protected.Head != "3 attempts stopped" {
		t.Errorf("refusal summary makes an absence claim: %+v", protected)
	}
}

func TestPagePackageHeaderNamesStaySpecific(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	for path, want := range map[string]string{"/compare?a=" + harmRun + "&b=" + cleanRun: "Compare", "/runs/" + harmRun + "/investigate/1": "Investigate"} {
		if !strings.Contains(get(t, s, c, path), `class="page-name">`+want+`<`) {
			t.Errorf("%s lacks its compact page name", path)
		}
	}
}
