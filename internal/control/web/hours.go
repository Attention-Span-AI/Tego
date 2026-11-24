// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// The Refusals by hour page (/refusals, C111): when actions were refused, one bar for each local hour of the last day
// or the last week. It reads the snapshot through ledgerview.Snapshot.RefusalBuckets, the reader the Overview's
// "refused today" count is, so the two counts of one day are the same number by construction (hours_test.go holds it),
// and a bar's refusal is one as Event.Refusal counts it (an action and its mirror once). Nothing is read from the
// ledger twice and nothing is judged: the page counts times.

// hourSpans are the periods the page offers: its key in the address, its words, and how many hourly bars it draws.
var hourSpans = []struct {
	Key, Label string
	Hours      int
}{{"day", "Last day", 24}, {"week", "Last week", 7 * 24}}

// maxHourRows is how many hours with refusals the page lists before the rest fold under "All hours".
const maxHourRows = 8

// hourBar is one hour: its first instant, the refusals timed in it, and its Logs link.
type hourBar struct {
	Start time.Time
	End   time.Time
	N     int
	Href  string
}

// hourSpanLink is one period's chip.
type hourSpanLink struct {
	Key, Label string
	Current    bool
}

// hoursData is the Refusals by hour page.
type hoursData struct {
	Span  string
	Spans []hourSpanLink
	Bars  []hourBar
	Chart *svgChart
	// Total is every refusal in the period, Peak the most in one hour (PeakBar's) and Active the hours that hold any.
	Total, Peak, Active int
	PeakBar             hourBar
	// Rows are the hours with refusals, newest first; More the ones past maxHourRows, folded.
	Rows, More []hourBar
	From, To   time.Time
	Now        time.Time
	// LogsHref lists the period's refused lines in Logs.
	LogsHref string
	// Lower says a count is a lower bound (RefusalCounts.Lower) and Records the complete records that settle it.
	Lower      bool
	Unreadable bool
	Records    []hourRecord
	Week       bool
}

// hourRecord is a link to one run's complete record.
type hourRecord struct{ Label, URL string }

// hourBounds are the edges of the hourly buckets that end with the hour containing now: n buckets, n+1 edges, each
// bucket one hour long from the local hour's start.
func hourBounds(now time.Time, n int) []time.Time {
	first := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, now.Location()).Add(-time.Duration(n-1) * time.Hour)
	out := make([]time.Time, n+1)
	for i := range out {
		out[i] = first.Add(time.Duration(i) * time.Hour)
	}
	return out
}

// logsWindow is the Logs link of the refused lines timed from t0 up to t1.
func logsWindow(t0, t1 time.Time) string {
	return "/logs?" + url.Values{"verdict": {"refused"}, "where": {"since:" + t0.Format(time.RFC3339) + " until:" + t1.Format(time.RFC3339)}}.Encode()
}

// hoursOf is the page's data for the period span at now.
func hoursOf(snap *ledgerview.Snapshot, span string, now time.Time) hoursData {
	d := hoursData{Now: now, Span: hourSpans[0].Key}
	n := hourSpans[0].Hours
	for _, sp := range hourSpans {
		d.Spans = append(d.Spans, hourSpanLink{Key: sp.Key, Label: sp.Label, Current: sp.Key == span})
		if sp.Key == span {
			d.Span, n = sp.Key, sp.Hours
		}
	}
	for i := range d.Spans {
		d.Spans[i].Current = d.Spans[i].Key == d.Span
	}
	d.Week = d.Span == "week"
	bounds := hourBounds(now, n)
	c := snap.RefusalBuckets(bounds)
	d.From, d.To = bounds[0], bounds[n]
	d.LogsHref = logsWindow(d.From, d.To)
	d.Lower = c.Lower
	for _, r := range c.Records {
		d.Unreadable = d.Unreadable || r.Bad > 0 || r.ReadError != ""
		label := r.Agent
		if label == "" {
			label = "Run"
		}
		if len(d.Records) < maxCountLinks {
			d.Records = append(d.Records, hourRecord{Label: label, URL: recordLink(r)})
		}
	}
	for i, v := range c.Counts {
		b := hourBar{Start: bounds[i], End: bounds[i+1], N: v, Href: logsWindow(bounds[i], bounds[i+1])}
		d.Bars = append(d.Bars, b)
		d.Total += v
		if v > 0 {
			d.Active++
		}
		if v > d.Peak {
			d.Peak, d.PeakBar = v, b
		}
	}
	for i := len(d.Bars) - 1; i >= 0; i-- {
		if d.Bars[i].N == 0 {
			continue
		}
		if len(d.Rows) < maxHourRows {
			d.Rows = append(d.Rows, d.Bars[i])
		} else {
			d.More = append(d.More, d.Bars[i])
		}
	}
	d.Chart = hoursChart(d.Bars, d.Peak, d.Week)
	return d
}

// recordLink is where a run's complete record is: its receipt, or its raw lines when a line could not be read (as the
// Overview's coverage note links it).
func recordLink(r *ledgerview.Run) string {
	if r.Bad > 0 || r.ReadError != "" {
		return "/logs.jsonl?run=" + url.QueryEscape(r.ID)
	}
	return "/runs/" + url.PathEscape(r.ID) + "/receipt"
}

// hoursChart is the bars as an svgChart: one 10-wide column for each hour, the refused ones as bars to a common peak,
// the quiet ones as a short mark on the baseline so an empty hour reads as an hour with nothing, not a gap. Each bar
// with refusals links to its hour in Logs.
func hoursChart(bars []hourBar, peak int, week bool) *svgChart {
	const col, gap, h = 10.0, 2.0, 100.0
	label := "Refusals in each hour of the last day"
	if week {
		label = "Refusals in each hour of the last week"
	}
	c := &svgChart{Class: "ch-hours", W: num(col * float64(len(bars))), H: num(h), Label: label}
	vals := make([]int, len(bars))
	for i, b := range bars {
		vals[i] = b.N
		x := col * float64(i)
		if b.N == 0 {
			c.Parts = append(c.Parts, svgPart{Class: "ch-track", X: num(x + gap/2), Y: num(h - 2), W: num(col - gap), H: "2"})
			continue
		}
		bh := max(float64(b.N)/float64(max(peak, 1))*(h-4), 4)
		c.Parts = append(c.Parts, svgPart{Class: "ch-refused", X: num(x + gap/2), Y: num(h - bh), W: num(col - gap), H: num(bh),
			Href: b.Href, Title: fmt.Sprintf("%s: %d refused", b.Start.Format("Mon 15:04"), b.N)})
	}
	c.Desc = "Oldest hour to newest: " + joinInts(vals) + "."
	return c
}

func joinInts(v []int) string {
	out := make([]byte, 0, len(v)*3)
	for i, n := range v {
		if i > 0 {
			out = append(out, ',', ' ')
		}
		out = strconv.AppendInt(out, int64(n), 10)
	}
	return string(out)
}

// hourRow is one list row of the page: its hour, now for its words, and the page's number scopes for its count.
type hourRow struct {
	Bar     hourBar
	Now     time.Time
	Numbers countScopes
}

// hourWords is an hour's first instant in words, in the zone now is in: "Today 15:00", "Yesterday 09:00", the weekday
// within the last week, the date before.
func hourWords(t, now time.Time) string {
	t = t.In(now.Location())
	day := func(x time.Time) time.Time { y, m, d := x.Date(); return time.Date(y, m, d, 0, 0, 0, 0, x.Location()) }
	today := day(now)
	switch {
	case !day(t).Before(today):
		return "Today " + t.Format("15:04")
	case !day(t).Before(today.AddDate(0, 0, -1)):
		return "Yesterday " + t.Format("15:04")
	case !day(t).Before(today.AddDate(0, 0, -6)):
		return t.Format("Mon 15:04")
	}
	return t.Format("Jan 2 15:04")
}

func init() {
	funcs["hourWords"] = hourWords
	funcs["hourRowOf"] = func(b hourBar, now time.Time, n countScopes) hourRow { return hourRow{Bar: b, Now: now, Numbers: n} }
}

// refusalHours answers /refusals.
func (s *Server) refusalHours(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	d := hoursOf(snap, r.URL.Query().Get("span"), s.cfg.Now())
	c := s.chromeOf(snap, "Refusals by hour", "detections")
	// The counts are the Overview's daily aggregate: a refusal outside the retained windows may still be bounded to
	// an earlier hour, so the page's own lower bound is the one its numbers show, and the note below names why.
	switch {
	case c.Numbers.Daily.Error != "":
	case d.Lower:
		c.Numbers.Daily = countScope{Lower: true, Reason: "Some records needed for these counts are incomplete."}
	default:
		c.Numbers.Daily = countScope{}
	}
	qualifyChart(d.Chart, "hours.series", c.Numbers.Daily)
	s.render(w, http.StatusOK, "hours", c, d)
}
