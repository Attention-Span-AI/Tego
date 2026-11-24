// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"strings"
	"testing"
	"time"
)

// TestMalformedAsksAreShownNotResolved: a repeated ask id, an answer before its ask and an answer to an id never asked
// are shown as refused lines of the run in askpair's words, and no reader takes them as a question or an answer: the
// run's ask count, its approvals, the line page and the compare rows all follow the first ask and the answer that
// pairs with it.
func TestMalformedAsksAreShownNotResolved(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000081-askbad"
	t0 := time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)
	ask := func(seq int, id, target string) string {
		return line(run, "py", seq, t0.Add(time.Duration(seq)*time.Second), "ask", `"ask_id":"`+id+`","hold":"open","op":"open","target":"`+target+`","ask_rule":"fs.ask_read[/w/]"`)
	}
	answer := func(seq int, id string) string {
		return line(run, "py", seq, t0.Add(time.Duration(seq)*time.Second), "answer", `"ask_id":"`+id+`","by":"uid:1000 pid:9","after_s":1,"approved":true`)
	}
	for _, c := range []struct {
		name       string
		body       []string
		asks       int
		errWords   string // what the one refused line says, "" for none
		approvals  []string
		badSeq     int // the seq of the malformed line, 0 for none
		answerWord string
	}{
		{"well formed", []string{ask(1, "q-1", "/w/a"), answer(2, "q-1")}, 1, "", []string{"q-1 approved"}, 0, "approved"},
		{"a repeated ask id", []string{ask(1, "q-1", "/w/a"), ask(2, "q-1", "/w/other"), answer(3, "q-1")}, 1,
			"an ask was recorded twice", []string{"q-1 approved"}, 2, "approved"},
		{"an answer before its ask", []string{answer(1, "q-1"), ask(2, "q-1", "/w/a")}, 1,
			"an answer has no ask before it", []string{"q-1 unanswered"}, 1, "no answer"},
		{"an answer to an id never asked", []string{ask(1, "q-1", "/w/a"), answer(2, "q-9")}, 1,
			"an answer has no ask before it", []string{"q-1 unanswered"}, 2, "no answer"},
		{"an answer and no ask", []string{answer(1, "q-9")}, 0, "an answer has no ask before it", nil, 1, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			n := len(c.body) + 1
			lines := append([]string{line(run, "py", 0, t0, "run_start", `"tier":"landlock","command":["agent"],"cwd":"/w"`)}, c.body...)
			lines = append(lines, line(run, "py", n, t0.Add(time.Duration(n)*time.Second), "run_end", `"reason":"exit","exit_code":0`))
			writeRun(t, root, run, lines...)
			s := Open(root)
			r, err := s.Run(run)
			if err != nil {
				t.Fatal(err)
			}
			if r.Asks != c.asks || len(r.Pending) != 0 {
				t.Errorf("asks %d pending %d, want %d and none (the run ended)", r.Asks, len(r.Pending), c.asks)
			}
			if c.errWords == "" && (len(r.LineErrors) != 0 || r.Bad != 0) {
				t.Errorf("a well formed run has refused lines: %+v bad %d", r.LineErrors, r.Bad)
			}
			if c.errWords != "" && (len(r.LineErrors) != 1 || !strings.Contains(r.LineErrors[0].Reason, c.errWords) || r.Bad != 1) {
				t.Errorf("refused lines %+v bad %d, want one saying %q", r.LineErrors, r.Bad, c.errWords)
			}
			var got []string
			for _, a := range Signal(r, Sensitive{}).Approvals {
				got = append(got, a.AskID+" "+a.State)
			}
			if strings.Join(got, ",") != strings.Join(c.approvals, ",") {
				t.Errorf("approvals %v, want %v", got, c.approvals)
			}
			if c.badSeq != 0 {
				lv, err := Explain(root, r, uint64(c.badSeq))
				if err != nil {
					t.Fatal(err)
				}
				if lv.Ask != nil || !strings.Contains(strings.ToLower(lv.Sentence), c.errWords) {
					t.Errorf("line %d: question %+v, sentence %q: want no question and %q", c.badSeq, lv.Ask, lv.Sentence, c.errWords)
				}
			}
			rows, _ := collect(r, func(s string) string { return s })
			asks, answer := 0, ""
			for k, a := range rows {
				if k.class == ClassAsk {
					asks += a.ask
					answer = a.answer
				}
			}
			if asks != c.asks || answer != c.answerWord {
				t.Errorf("compare rows: %d asks, answer %q; want %d and %q", asks, answer, c.asks, c.answerWord)
			}
		})
	}
}
