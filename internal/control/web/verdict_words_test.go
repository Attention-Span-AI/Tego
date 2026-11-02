// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/linewords"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// An ask or an answer line carries no verdict of its own, so its chip says what the line is: Asked on the ask, the
// person's Denied or Allowed on the answer. The run timeline, the line page (its headline and What happened), "Around
// it" and Logs show the same chip for a line, never the grey "Recorded" of a line nothing decided.

// otherAsk is chipRun's second question.
const otherAsk = "q-fedcba9876543210fedcba9876543210"

// chipRun rewrites actRun as two questions a person answered: #1 the ask to read vault/token, #2 the no, #3 the read
// it refused; #4 the ask to read vault/notes, #5 the yes, #6 the read it let through.
func chipRun(t *testing.T) (*Server, *http.Cookie) {
	t.Helper()
	s, c, contract, proj := askServer(t)
	ask := func(id, target string) *record.Event {
		return ledgertest.Event(t, record.KindAsk, map[string]any{"ask_id": id, "ask_rule": "fs.ask_read[./vault/]",
			"hold": "open", "op": "read", "target": target})
	}
	answer := func(id, target string, approved bool) *record.Event {
		p := map[string]any{"ask_id": id, "ask_rule": "fs.ask_read[./vault/]", "by": "uid:1000 pid:1 dashboard",
			"after_s": 0.077, "approved": approved, "op": "read", "target": target}
		if !approved {
			p["answer_reason"] = "ask-denied"
		}
		return ledgertest.Event(t, record.KindAnswer, p)
	}
	read := func(target string, verdict record.Verdict, reason record.Reason) *record.Event {
		return ledgertest.Event(t, record.KindFS, record.FSPayload{Op: "open", Path: target}, func(e *record.Event) {
			e.Source, e.Rule, e.Verdict, e.Reason = record.SourceSeccomp, "fs.ask_read[./vault/]", verdict, reason
			e.Authority = record.AuthorityHuman
			e.Attr = &record.Attribution{Confidence: "unattributed", Method: "none"}
		})
	}
	token, notes := filepath.Join(proj, "vault", "token"), filepath.Join(proj, "vault", "notes")
	writeLines(t, s.cfg.Ledger, actRun, []*record.Event{
		ledgertest.Event(t, record.KindRunStart, record.RunStartPayload{Tier: "landlock", Capture: "off",
			ContractHash: strings.Repeat("0", 64), Command: []string{"sh"}, Cwd: proj, Kernel: "6", StopGrace: "1s",
			ContractSource: &record.ContractSource{Path: contract}}),
		ask(testAsk, token), answer(testAsk, token, false), read(token, record.VerdictRefused, record.ReasonAskDenied),
		ask(otherAsk, notes), answer(otherAsk, notes, true), read(notes, record.VerdictAllow, ""),
	})
	return s, c
}

// chipRe is a verdict chip as the templates write it: its class, its icon and its word.
var chipRe = regexp.MustCompile(`<span class="b b-([a-z]+)"[^>]*><svg class="i" aria-hidden="true" focusable="false"><use href="/static/sprite.svg#(i-[a-z-]+)"/></svg>([A-Za-z]+)</span>`)

// chipIn is the one chip in the part of page from the first from up to the next to, as "class icon Word".
func chipIn(t *testing.T, what, page, from, to string) string {
	t.Helper()
	i := strings.Index(page, from)
	if i < 0 {
		t.Fatalf("%s: no %q on the page", what, from)
	}
	part := page[i:]
	if j := strings.Index(part, to); j >= 0 {
		part = part[:j]
	}
	m := chipRe.FindAllStringSubmatch(part, -1)
	if len(m) != 1 {
		t.Fatalf("%s: %d chips in %s", what, len(m), part)
	}
	return m[0][1] + " " + m[0][2] + " " + m[0][3]
}

// TestAskAndAnswerChipsAgree: each line has one chip on every page that shows it: the asks read Asked and the answers
// the person's Denied and Allowed on the run timeline, on the line page (headline and What happened), in "Around it"
// and in Logs. The yes is no decision of its own, so its decision panel gives no reason; the read it let through
// still reads "Not blocked".
func TestAskAndAnswerChipsAgree(t *testing.T) {
	s, c := chipRun(t)
	want := []string{
		"neutral i-eye Recorded",  // #0 the run's start: nothing decided it
		"asked i-hand Asked",      // #1 the ask
		"refused i-ban Denied",    // #2 the person's no
		"refused i-ban Blocked",   // #3 the read it refused
		"asked i-hand Asked",      // #4 the second ask
		"allowed i-check Allowed", // #5 the person's yes
		"allowed i-check Allowed", // #6 the read it let through
	}
	run := get(t, s, c, "/runs/"+actRun)
	logs := get(t, s, c, "/logs?run="+actRun)
	m := ctxRe.FindStringSubmatch(get(t, s, c, "/runs/"+actRun+"/lines/3"))
	if m == nil {
		t.Fatal("line #3's page has no Around it list")
	}
	around := m[1]
	lines := make([]string, len(want))
	for seq, w := range want {
		n := strconv.Itoa(seq)
		lines[seq] = get(t, s, c, "/runs/"+actRun+"/lines/"+n)
		for _, v := range []struct{ what, page, from, to string }{
			{"the timeline", run, `id="l` + n + `"`, "</div>"},
			{"Logs", logs, `data-k="` + actRun + "-" + n + `"`, "</tr>"},
			{"the line page's headline", lines[seq], `<p class="ev-lede">`, "</p>"},
			{"What happened", lines[seq], `<h2 id="h-facts">What happened</h2>`, "</div>"},
			{"Around it", around, ">#" + n + "<", "</li>"},
		} {
			if got := chipIn(t, v.what+" of #"+n, v.page, v.from, v.to); got != w {
				t.Errorf("%s of #%d: chip %q, want %q", v.what, seq, got, w)
			}
		}
		// The timeline row's edge colour is its chip's.
		class, _, _ := strings.Cut(w, " ")
		if !strings.Contains(run, `<div class="tl v-`+class+`" id="l`+n+`"`) {
			t.Errorf("the timeline row of #%d is not v-%s", seq, class)
		}
	}
	if strings.Contains(lines[5], "Not blocked") {
		t.Error("the person's yes reads as an action that was not blocked")
	}
	mustContain(t, "the read the yes let through", lines[6], `<dt>Reason</dt><dd><span class="soft">Not blocked</span></dd>`)
}

// TestLineVerdict: a line's own verdict decides its chip; an ask line reads Asked and an answer line the person's
// Allowed or Denied, or Answered when it does not say which; a line nothing decided reads Recorded. The verdictClass,
// verdictIcon and verdictWord funcs every template calls say the same.
func TestLineVerdict(t *testing.T) {
	answer := func(raw string) ledgerview.Event { return ledgerview.Event{Kind: "answer", Raw: raw} }
	for _, tc := range []struct {
		name string
		e    ledgerview.Event
		want string
	}{
		{"an allowed action", ledgerview.Event{Kind: "exec", Verdict: "allow"}, "allowed i-check Allowed"},
		{"a refused action", ledgerview.Event{Kind: "fs", Verdict: "refused"}, "refused i-ban Blocked"},
		{"a refusal note", ledgerview.Event{Kind: "refused"}, "refused i-ban Blocked"},
		{"an action held for a person", ledgerview.Event{Kind: "fs", Verdict: "ask"}, "asked i-hand Asked"},
		{"a watched action", ledgerview.Event{Kind: "net", Verdict: "observed"}, "observed i-eye Observed"},
		{"an ask line", ledgerview.Event{Kind: "ask"}, "asked i-hand Asked"},
		{"a person's yes", answer(`{"approved":true}`), "allowed i-check Allowed"},
		{"a person's no", answer(`{"approved":false,"answer_reason":"ask-denied"}`), "refused i-ban Denied"},
		// No person denied these (askwords' answered.TimedOut and Withdrawn), so neither reads Denied.
		{"nobody answered in time", answer(`{"approved":false,"answer_reason":"ask-timeout","by":"timeout"}`), "neutral i-hand Timed out"},
		{"withdrawn by a live block", answer(`{"approved":false,"by":"` + linewords.WithdrawnBy + `"}`), "neutral i-ban Withdrawn"},
		{"an answer that does not say", answer(`{"ask_id":"q-1"}`), "neutral i-hand Answered"},
		{"an answer that does not decode", answer(`{`), "neutral i-hand Answered"},
		{"a run's start", ledgerview.Event{Kind: "run_start"}, "neutral i-eye Recorded"},
		{"a gap", ledgerview.Event{Kind: "gap"}, "neutral i-eye Recorded"},
	} {
		class, icon, word := lineVerdict(tc.e)
		if got := class + " " + icon + " " + word; got != tc.want {
			t.Errorf("%s: lineVerdict %q, want %q", tc.name, got, tc.want)
		}
		f := func(name string) string { return funcs[name].(func(ledgerview.Event) string)(tc.e) }
		if got := f("verdictClass") + " " + f("verdictIcon") + " " + f("verdictWord"); got != tc.want {
			t.Errorf("%s: the template funcs say %q, want %q", tc.name, got, tc.want)
		}
	}
}
