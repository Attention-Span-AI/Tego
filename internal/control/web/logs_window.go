// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// A time range set as "the last hour" (since:1h) is pinned when the person sets it: the Logs address is answered with
// the same search written with the times it means then (since:2026-10-27T09:05:00), and the page shows them. So a
// refresh, a reload or a shared link shows the same window, not one that slides under the reader, and a link moves it to
// now when the person wants that. The address keeps the words the person chose in span ("1h@<the time>", valid only
// while the query still holds that time), so the time presets know which one is current and Move to now keeps its length.

// pinnedAddress is the address of a Logs request with its relative times pinned (ledgerview.PinTimes), false when it
// holds none or its query cannot be read.
func pinnedAddress(q url.Values, now time.Time) (string, bool) {
	lq := readLogsQuery(q, now)
	if lq.err != nil {
		return "", false
	}
	toks, span, ok := ledgerview.PinTimes(lq.toks, now, time.Local)
	if !ok {
		return "", false
	}
	v := url.Values{}
	for k, xs := range q {
		if k != "span" {
			v[k] = append([]string(nil), xs...)
		}
	}
	v.Set("where", ledgerview.FormatQuery(toks))
	if span != "" {
		for _, t := range toks {
			if t.Key == "since" {
				v.Set("span", span+"@"+t.Value)
			}
		}
	}
	return "/logs?" + v.Encode(), true
}

// spanOf is the words a pinned since was set with ("1h") when span (the address's span) names the since that toks hold.
func spanOf(span string, toks []ledgerview.Token) (string, bool) {
	words, at, ok := strings.Cut(span, "@")
	if !ok || words == "" {
		return "", false
	}
	for _, t := range toks {
		if t.Key == "since" && t.Value == at {
			return words, true
		}
	}
	return "", false
}

// timeWindow is the page's time range in words and absolute times, and the address that moves it to now.
type timeWindow struct {
	// Words says the range ("From 2026-10-27 09:05:00 until now").
	Words string
	// Since and Until are its ends, zero when open.
	Since, Until time.Time
	// NowURL is the same length of time ending now; "" when the range has no start.
	NowURL string
}

// window is the search's time range as a timeWindow, nil without one.
func (lq *logsQuery) window(now time.Time) *timeWindow {
	f := lq.f
	if f.Since.IsZero() && f.Until.IsZero() {
		return nil
	}
	const layout = "2006-01-02 15:04:05"
	w := &timeWindow{Since: f.Since, Until: f.Until}
	switch {
	case !f.Since.IsZero() && !f.Until.IsZero():
		w.Words = "From " + f.Since.Local().Format(layout) + " to " + f.Until.Local().Format(layout)
	case !f.Since.IsZero():
		w.Words = "From " + f.Since.Local().Format(layout) + " until now"
	default:
		w.Words = "Up to " + f.Until.Local().Format(layout)
	}
	if !f.Since.IsZero() {
		length := now.Sub(f.Since)
		if !f.Until.IsZero() {
			length = f.Until.Sub(f.Since)
		}
		d := lq.spanWords(length)
		w.NowURL = lq.with("/logs", lq.withTime(d), nil)
	}
	return w
}

// spanWords is how long the window is as a since value: the words the person chose when the address still names them,
// else the length to the minute (at least one).
func (lq *logsQuery) spanWords(length time.Duration) string {
	if words, ok := spanOf(lq.vals.Get("span"), lq.toks); ok {
		return words
	}
	m := max(1, int(length.Round(time.Minute)/time.Minute))
	return strconv.Itoa(m) + "m"
}
