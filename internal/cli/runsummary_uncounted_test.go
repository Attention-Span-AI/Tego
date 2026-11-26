// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRunEndSaysWhyABudgetCouldNotBeCounted: a run a token or cost budget ended for an answer whose usage could not be
// read said only "ended (ended: error)" under its closing line, the reason lying in the record's run_end detail. The
// closing lines now carry it in words: which request, that its usage could not be read, that a budget cannot be
// enforced on such answers, and the two ways out. The exit code and the record are not touched.
func TestRunEndSaysWhyABudgetCouldNotBeCounted(t *testing.T) {
	res := tegoruntime.Result{RunID: "r1", Reason: record.RunEndError,
		Uncounted: &tegoruntime.Uncounted{Exchanges: 1, Why: "POST /v1/chat/completions: usage unreadable"}}
	s := &endSummary{run: "r1", how: endedHow(res.Reason), err: errors.New("no such file"), chain: "chain not checked (no chain anchor)", uncounted: res.Uncounted}
	got := s.text()
	for _, want := range []string{
		"tego run: r1 ended (error)",
		"the model's answer to POST /v1/chat/completions stated no token usage that Tego can read",
		"a token or cost budget cannot be enforced on answers it cannot count",
		"fix: remove limits.tokens and limits.cost_usd from the contract, or use a model API whose usage Tego reads: " + agent.CountedAPIWords(),
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the closing lines do not say %q:\n%s", want, got)
		}
	}
	// --no-summary prints tego's one-line verdict, which carries the same words.
	var b bytes.Buffer
	writeRunSummary(&b, res)
	if !strings.Contains(b.String(), "stated no token usage that Tego can read") || !strings.Contains(b.String(), "fix: remove limits.tokens") {
		t.Errorf("--no-summary's line does not say why:\n%s", b.String())
	}
	// Another end says nothing of it.
	other := &endSummary{run: "r1", how: endedHow(record.RunEndError), err: errors.New("x"), chain: "c"}
	if strings.Contains(other.text(), "fix: remove limits.tokens") {
		t.Errorf("a run with no uncounted spend gets the budget message:\n%s", other.text())
	}
}

// An exchange that went uncounted for another reason is named as it was, with the same two ways out; several are said once.
func TestUncountedLinesNameOtherCausesAndCounts(t *testing.T) {
	got := uncountedLines(&tegoruntime.Uncounted{Exchanges: 4, Why: "POST /v1/messages: no response"})
	for _, want := range []string{"could not be counted (POST /v1/messages: no response)", "(4 exchanges were in that state)", "fix: remove limits.tokens"} {
		if !strings.Contains(got, want) {
			t.Errorf("uncountedLines lacks %q:\n%s", want, got)
		}
	}
	if uncountedLines(nil) != "" {
		t.Error("nil spend printed something")
	}
}

// A streamed answer that carried no usage tells the person the client option that makes the API state it (Tego
// never adds it to a request), and still the other ways out.
func TestUncountedLinesForAStreamWithoutUsage(t *testing.T) {
	got := uncountedLines(&tegoruntime.Uncounted{Exchanges: 1, Why: derive.UnreadableWhy("POST", "/v1/chat/completions", derive.NoteStreamWithoutUsage)})
	for _, want := range []string{
		"the model's answer to POST /v1/chat/completions was streamed and stated no token usage",
		"the API puts usage in a stream only when the client asks for it, and Tego never changes a request",
		`stream_options: {"include_usage": true}`,
		"or not stream",
		"or remove limits.tokens and limits.cost_usd",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the stream message lacks %q:\n%s", want, got)
		}
	}
}

// agent.CountedAPIs, which the rules check's warning and the closing lines name, is the providers of the parsers this
// binary links, so neither can name a style no parser reads or leave one out.
func TestCountedAPIsAreTheLinkedParsers(t *testing.T) {
	linked := map[string]bool{}
	for _, p := range linkedParsers(nil) {
		linked[p.Provider()] = true
		if !agent.BudgetCounts(p.Provider()) {
			t.Errorf("the %s parser is linked and agent.CountedAPIs does not say a budget counts it", p.Provider())
		}
	}
	for _, a := range agent.CountedAPIs {
		if !linked[a.Provider] {
			t.Errorf("agent.CountedAPIs names %s, which no linked parser reads", a.Provider)
		}
	}
}

// A stream cut short is not a stream the client forgot to ask usage for: the closing lines say it was interrupted, and
// do not tell the person to set the client's usage option.
func TestUncountedLinesForAnInterruptedAnswer(t *testing.T) {
	got := uncountedLines(&tegoruntime.Uncounted{Exchanges: 1, Why: derive.UnreadableWhy("POST", "/v1/chat/completions", derive.NoteAnswerCutOff)})
	for _, want := range []string{
		"the model's answer to POST /v1/chat/completions was interrupted before it stated its usage: the client or the agent closed the connection",
		"A token or cost budget cannot count an interrupted answer, so the run was ended",
		"fix: let each call finish before the agent stops it, or remove limits.tokens and limits.cost_usd",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the interrupted-answer message lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "include_usage") || strings.Contains(got, "ask the API") {
		t.Errorf("an interrupted answer is told to set a usage option:\n%s", got)
	}
}
