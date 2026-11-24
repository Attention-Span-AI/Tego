// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"net/url"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// attentionState owns both the headline and the conditions beneath it. Keeping
// one ordered list prevents an all-clear headline above a recorded warning.
type attentionState struct {
	Headline string
	Items    []attentionItem
}

type attentionItem struct {
	Kind, Headline, Body, URL, Link, Class string
}

// attentionSource is what the attention derivation could not know, beside what it knows: why the list of waiting
// requests may be incomplete, why a record could not be read in full, and why the counts it relies on are lower
// bounds. With any of them set, no headline says that nothing waits or that nothing needs the person.
type attentionSource struct {
	PendingReason, RecordReason, CountsReason string
	// PendingUnreadable means the source can hide more waiting requests. Known
	// actionable requests still form the visible lower bound.
	PendingUnreadable bool
}

// Incomplete reports whether anything the attention derivation relies on is not fully known.
func (s attentionSource) Incomplete() bool {
	return s.PendingReason != "" || s.RecordReason != "" || s.CountsReason != ""
}

// forApprovals keeps what bears on the waiting requests, and an unreadable record. Event-window retention does not
// limit the waiting list: it is kept over the whole run with its own display budget (Run.PendingCut), so a lower
// bound on event counts says nothing about whether a request waits.
func (s attentionSource) forApprovals() attentionSource {
	return attentionSource{PendingReason: s.PendingReason, PendingUnreadable: s.PendingUnreadable}
}

const (
	attnWindows  = "only retained event windows were read"
	attnBadLines = "a record contains unreadable lines"
)

// runAttentionSource is one run's uncertainty.
func runAttentionSource(run *ledgerview.Run) attentionSource {
	var source attentionSource
	if run == nil {
		return source
	}
	if run.Cut {
		source.CountsReason = attnWindows
	}
	if run.Bad > 0 || run.ReadError != "" {
		source.RecordReason = attnBadLines
		if run.ReadError != "" {
			source.RecordReason = run.ReadError
		}
	}
	scope := runNumbers(run).Queue
	source.PendingReason, source.PendingUnreadable = scope.Reason, scope.Error != ""
	if scope.Error != "" {
		source.PendingReason = scope.Error
	}

	return source
}

// attentionSourceOf is a whole snapshot's uncertainty: every run's, and the runs it could not list or read.
func attentionSourceOf(snap *ledgerview.Snapshot) attentionSource {
	var source attentionSource
	for _, run := range snap.Runs {
		r := runAttentionSource(run)
		if r.RecordReason != "" {
			source.RecordReason = r.RecordReason
		}
		if r.CountsReason != "" {
			source.CountsReason = r.CountsReason
		}
	}
	if snap.LinesCut {
		source.CountsReason = attnWindows
	}
	if snap.RunsCut {
		source.CountsReason = "some runs are outside the retained run list"
	}
	if snap.Partial {
		source.CountsReason = "some records are still being read"
	}
	if snap.ReadError != "" {
		source.RecordReason = snap.ReadError
	}
	scope := snapshotNumbers(snap).Queue
	source.PendingReason, source.PendingUnreadable = scope.Reason, scope.Error != ""
	if scope.Error != "" {
		source.PendingReason = scope.Error
	}

	return source
}

func attentionOf(pending []ledgerview.Ask, broken *ledgerview.Chain, leaked, read int, source attentionSource, extra []attentionItem) attentionState {
	a := attentionState{Headline: "Nothing needs you"}
	waiting := waitingOf(len(pending), source.waitingScope())
	if waiting.Show {
		dest, link := "/runs", "View records"
		if len(pending) > 0 {
			dest, link = approvalURL(pending[0].Run, pending[0].AskID), "Review request"
		}
		a.Items = append(a.Items, attentionItem{Kind: "waiting", Headline: waiting.Headline, Body: waiting.Sentence, URL: dest, Link: link, Class: "ov-risk"})
	}
	if broken != nil {
		a.Items = append(a.Items, attentionItem{Kind: "broken", Headline: "Record needs attention", Body: "Record needs attention. Review its details before relying on it.", URL: "/runs/" + url.PathEscape(broken.Run) + "/receipt", Link: "View record", Class: "ov-risk"})
	}
	if source.RecordReason != "" {
		a.Items = append(a.Items, attentionItem{Kind: "unreadable", Headline: "Could not read the full record", Body: "Could not read the full record: " + source.RecordReason + ". Other attention needs are not known.", URL: "/runs", Link: "View records", Class: "ov-risk"})
	}
	for _, condition := range []struct {
		n                    int
		kind, headline, verb string
	}{
		{leaked, "leak", "Secret leak recorded", "leaked secrets"},
		{read, "read", "Sensitive read recorded", "read secrets"},
	} {
		if condition.n == 0 {
			continue
		}
		noun := "runs"
		if condition.n == 1 {
			noun = "run"
		}
		body := fmt.Sprintf("%d %s %s", condition.n, noun, condition.verb)
		if source.RecordReason != "" {
			body = condition.headline
		} else if source.CountsReason != "" {
			body = "At least " + body
		}
		link, dest, class := "View runs", "/runs", "ov-risk"
		if condition.kind == "leak" {
			link, dest, class = "View detections", "/detections", "verdict verdict-leak ov-verdict"
		}
		a.Items = append(a.Items, attentionItem{Kind: condition.kind, Headline: condition.headline, Body: body, URL: dest, Link: link, Class: class})
	}
	// What a layer adds after the conditions above (layerAttention), before the note that some are not known.
	a.Items = append(a.Items, extra...)
	if source.CountsReason != "" {
		a.Items = append(a.Items, attentionItem{Kind: "incomplete", Headline: "Some attention needs are not known", Body: "Some attention needs are not known: " + source.CountsReason + ". Counts from these windows are lower bounds. Inspect the full record for all events.", URL: "/runs", Link: "View records", Class: "ov-risk"})
	}
	if len(a.Items) > 0 {
		a.Headline = a.Items[0].Headline
	}
	return a
}

// Attention is shared by the desktop and phone Overview headline and body.
func (d overviewData) Attention() attentionState {
	return attentionOf(d.Pending, d.Chain.Broken, d.Leaked, d.Watched, d.AttentionSource, d.Extra)
}

// Attention keeps the Run summary in the same priority order as Overview.
func (d runData) Attention() attentionState {
	var pending []ledgerview.Ask
	if d.Run != nil && d.Run.Live {
		pending = d.Run.Pending
	}
	var broken *ledgerview.Chain
	if d.Chain.Broken() {
		broken = &d.Chain
	}
	leaks, reads := 0, 0
	if d.Story.Kind == ledgerview.VerdictLeak {
		leaks = 1
	}
	if sensitiveReadRecorded(d.Run, d.Signal) || len(d.Story.Read) > 0 || d.Story.Kind == ledgerview.VerdictWatched {
		reads = 1
	}
	a := attentionOf(pending, broken, leaks, reads, d.AttentionSource, nil)
	for i := range a.Items {
		// The run's own outcome follows its leak or read: what left, what was only watched, or what Tego refused.
		protected := d.Story.Kind == ledgerview.VerdictWatched || d.Story.Kind == ledgerview.VerdictProtected
		if a.Items[i].Kind == "leak" || (a.Items[i].Kind == "read" && protected) {
			st := storyOfRun(d.Story, d.Run)
			a.Items[i].Body += ". " + st.Title
			if st.Sub != "" {
				a.Items[i].Body += ". " + st.Sub
			}
		}
		if a.Items[i].Kind == "read" && d.Run != nil {
			a.Items[i].URL = "/runs/" + url.PathEscape(d.Run.ID) + "/receipt"
			a.Items[i].Link = "View receipt"
		}
	}
	return a
}

// Attention gives Approvals the same known and unknown waiting state as Overview, from what bears on the waiting
// requests.
func (d approvalsData) Attention() attentionState {
	return attentionOf(d.Pending, nil, 0, 0, d.AttentionSource.forApprovals(), nil)
}

// approvalURL preserves the complete request identity even when different runs
// use the same request id.
func approvalURL(run, ask string) string {
	return "/approvals?run=" + url.QueryEscape(run) + "&ask=" + url.QueryEscape(ask)
}

func (s attentionSource) waitingScope() countScope {
	if s.PendingUnreadable {
		return countScope{Error: s.PendingReason}
	}
	if s.PendingReason != "" {
		return countScope{Lower: true, Reason: s.PendingReason}
	}
	return countScope{}
}

func (d approvalsData) Waiting() waitingState {
	return waitingOf(len(d.Pending), d.AttentionSource.waitingScope())
}
