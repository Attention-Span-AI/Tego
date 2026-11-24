// SPDX-License-Identifier: Apache-2.0

package web

import "strings"

// waitingState derives every representation of the actionable waiting count.
// A read failure can hide more requests, but cannot erase requests already known.
type waitingState struct {
	Short    string `json:"short"`
	Count    string `json:"count"`
	Sentence string `json:"sentence"`
	Headline string `json:"headline"`
	Reason   string `json:"reason,omitempty"`
	Show     bool   `json:"show"`
}

func waitingOf(n int, source countScope) waitingState {
	w := waitingState{Short: countWord(n), Count: countWord(n), Show: n > 0}
	if source.Error != "" {
		w.Reason = source.Error
	} else {
		w.Reason = source.Reason
	}
	switch {
	case source.incomplete() && n == 0:
		w.Short = "?"
		w.Count = "could not tell whether a request is waiting"
		w.Headline = w.Count
		w.Sentence = w.Count + ": " + w.Reason
		w.Show = true
	case source.incomplete():
		w.Short += "+"
		w.Count = "at least " + w.Count
		w.Headline = w.Count + " waiting"
		w.Sentence = w.Headline + ": " + w.Reason
	case n == 0:
		w.Headline = "Nothing waiting"
		w.Sentence = w.Headline
	default:
		w.Sentence = w.Count + " waiting"
		if n == 1 {
			w.Headline = "1 request needs you"
		} else {
			w.Headline = w.Count + " requests need you"
		}
	}
	return w
}

func (c chrome) Waiting() waitingState { return waitingOf(c.Pending, c.GlobalNumbers.Queue) }

func (c chrome) WaitingIncomplete() bool { return c.GlobalNumbers.Queue.incomplete() }

// PhoneSentence keeps the same known count and uncertainty, with a short reason.
// The complete diagnostic remains available in the recovery disclosure.
func (w waitingState) PhoneSentence() string {
	if w.Reason == "" {
		return w.Sentence
	}
	return strings.Replace(w.Sentence, w.Reason, w.PhoneReason(), 1)
}

func (w waitingState) PhoneReason() string {
	reason := w.Reason
	switch {
	case strings.Contains(reason, "record folder changed"):
		return "the record folder changed"
	case strings.Contains(reason, "live index"):
		return "the live index could not be read"
	case strings.Contains(reason, "ledger root"):
		return "the record folder could not be read"
	case strings.HasPrefix(reason, "read run "):
		return "a run record could not be read"
	case strings.Contains(reason, "could not be read"), strings.Contains(reason, "read ledger"), strings.Contains(reason, "read record"):
		return "some records could not be read"
	}
	return reason
}

// PhoneWaiting uses global chrome on full pages. A directly rendered fragment
// carries its explicit attention source in Data instead.
func (p page) PhoneWaiting() waitingState {
	if p.globalNumbersSet {
		return p.Waiting()
	}
	switch d := p.Data.(type) {
	case overviewData:
		return waitingOf(len(d.Pending), d.AttentionSource.waitingScope())
	case approvalsData:
		return d.Waiting()
	case runData:
		n := 0
		if d.Run != nil && d.Run.Live {
			n = len(d.Run.Pending)
		}
		return waitingOf(n, d.AttentionSource.waitingScope())
	}
	return p.Waiting()
}

// PhoneWaitingInContent avoids repeating a page's waiting explanation in chrome.
func (p page) PhoneWaitingInContent() bool {
	switch d := p.Data.(type) {
	case runData:
		return d.AttentionSource.PendingReason != ""
	case overviewData, approvalsData:
		return true
	}
	return false
}
