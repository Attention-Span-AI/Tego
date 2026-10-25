// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const testAsk = "q-0123456789abcdef0123456789abcdef"

// sent is what one fake broker call was given.
type sent struct {
	approve, always bool
	file            string
	calls           int
}

// fakeBroker replaces the broker calls for one test and records what reaches them.
func fakeBroker(t *testing.T) *sent {
	t.Helper()
	got := &sent{}
	oldA, oldB := answerAsk, alternateAsk
	t.Cleanup(func() { answerAsk, alternateAsk = oldA, oldB })
	answerAsk = func(_ context.Context, _, run, id string, approve, always bool) (runact.Answered, error) {
		got.calls++
		got.approve, got.always = approve, always
		d := askproto.Decision{AskID: id, Approved: approve, Always: always}
		if !approve {
			d.Reason = string(record.ReasonAskDenied)
		}
		return runact.Answered{Run: run, Decision: d, Word: runact.AnswerWord(d, always)}, nil
	}
	alternateAsk = func(_ context.Context, _, run, id, file string, always bool) (runact.Answered, error) {
		got.calls++
		got.file, got.always = file, always
		return runact.Answered{Run: run, Word: "gave " + file + " in place of the file the agent asked for"}, nil
	}
	return got
}

// TestAnswerAlwaysReachesBroker: Allow for this run and Deny for this run send the answer with the always flag, as
// `tego approve|deny --always` does, and the page the person returns to says so in a line; a plain answer sends no
// flag.
func TestAnswerAlwaysReachesBroker(t *testing.T) {
	got := fakeBroker(t)
	s := newServer(t, fixture(t))
	c := login(t, s)
	tok := csrfOf(t, s, c, "/approvals")
	for _, tc := range []struct {
		decision, always string
		approve, flag    bool
		word             string
	}{
		{"approve", "yes", true, true, "Allowed for the rest of this run: the request"},
		{"deny", "yes", false, true, "Denied for the rest of this run: the request"},
		{"approve", "", true, false, "Allowed once: the request"},
	} {
		w := post(s, "/approvals/answer", url.Values{"csrf": {tok}, "run": {harmRun}, "ask": {testAsk}, "decision": {tc.decision}, "always": {tc.always}}, own, own+"/approvals", c)
		b := follow(t, s, c, w)
		if got.approve != tc.approve || got.always != tc.flag {
			t.Fatalf("%s always=%q: approve=%v always=%v", tc.decision, tc.always, got.approve, got.always)
		}
		if !strings.Contains(b, tc.word) || strings.Contains(b, `"after_s"`) {
			t.Errorf("%s always=%q: page lacks %q, or shows a raw ledger line", tc.decision, tc.always, tc.word)
		}
	}
}

// TestAlternateThroughHandler: a stand-in file reaches the broker call with its path; the real call refuses a path
// that is not absolute and clean before it looks for the run's broker, and the request stays pending.
func TestAlternateThroughHandler(t *testing.T) {
	got := fakeBroker(t)
	s := newServer(t, fixture(t))
	c := login(t, s)
	tok := csrfOf(t, s, c, "/approvals")
	form := func(file string) url.Values {
		return url.Values{"csrf": {tok}, "run": {harmRun}, "ask": {testAsk}, "decision": {"alternate"}, "file": {file}, "always": {"yes"}}
	}
	b := follow(t, s, c, post(s, "/approvals/answer", form("/tmp/stand-in.txt"), own, "", c))
	if got.file != "/tmp/stand-in.txt" || !got.always || !strings.Contains(b, "Gave /tmp/stand-in.txt instead") {
		t.Fatalf("alternate: file=%q always=%v", got.file, got.always)
	}
	alternateAsk = runact.Alternate
	for _, bad := range []string{"", "stand-in.txt", "/tmp/../etc/passwd", "/tmp/a\x01b"} {
		if b := follow(t, s, c, post(s, "/approvals/answer", form(bad), own, "", c)); !strings.Contains(b, "still waiting") {
			t.Errorf("file %q: the page does not say the request is still waiting", bad)
		}
	}
}

// TestNewAnswersNeedPostChecks: the always and alternate answers pass the same cookie, CSRF and Origin checks, and a
// refused request reaches no broker.
func TestNewAnswersNeedPostChecks(t *testing.T) {
	got := fakeBroker(t)
	s := newServer(t, fixture(t))
	c := login(t, s)
	tok := csrfOf(t, s, c, "/approvals")
	always := url.Values{"csrf": {tok}, "run": {harmRun}, "ask": {testAsk}, "decision": {"approve"}, "always": {"yes"}}
	alt := url.Values{"csrf": {tok}, "run": {harmRun}, "ask": {testAsk}, "decision": {"alternate"}, "file": {"/tmp/x"}}
	noCSRF := func(v url.Values) url.Values {
		o := url.Values{}
		for k, vs := range v {
			if k != "csrf" {
				o[k] = vs
			}
		}
		return o
	}
	for _, tc := range []struct {
		name   string
		form   url.Values
		origin string
		cookie *http.Cookie
		want   int
	}{
		{"always no cookie", always, own, nil, http.StatusUnauthorized},
		{"always no csrf", noCSRF(always), own, c, http.StatusForbidden},
		{"always cross origin", always, "http://evil.example", c, http.StatusForbidden},
		{"alternate no cookie", alt, own, nil, http.StatusUnauthorized},
		{"alternate no csrf", noCSRF(alt), own, c, http.StatusForbidden},
		{"alternate cross origin", alt, "http://evil.example", c, http.StatusForbidden},
	} {
		if w := post(s, "/approvals/answer", tc.form, tc.origin, "", tc.cookie); w.Code != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, w.Code, tc.want)
		}
	}
	if got.calls != 0 {
		t.Errorf("a refused request reached the broker %d times", got.calls)
	}
}
