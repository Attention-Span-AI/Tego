// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// C111: the Refusals by hour page. Its counts come from Snapshot.RefusalBuckets, the reader behind the Overview's
// "refused today".

// hoursRun writes one run whose lines are the refusals at ats (kind refused, as an exec that was not allowed) and a
// run_start 1 s before the first and a run_end 1 s after the last; extra lines go between.
func hoursRun(t *testing.T, root, id, agent string, ats []time.Time, extra ...func(add func(at time.Time, kind, body string))) {
	t.Helper()
	first, last := ats[0], ats[len(ats)-1]
	hoursLines(t, root, id, agent, first.Add(-time.Second), last.Add(time.Second), func(add func(at time.Time, kind, body string)) {
		for _, at := range ats {
			add(at, "refused", `"op":"exec","target":"curl","rule":"exec.deny[0]","reason":"exec-not-allowed"`)
		}
		for _, f := range extra {
			f(add)
		}
	})
}

// hoursLines writes one run: a run_start at start, the lines build adds, and a run_end at end.
func hoursLines(t *testing.T, root, id, agent string, start, end time.Time, build func(add func(at time.Time, kind, body string))) {
	t.Helper()
	var b strings.Builder
	seq := 0
	add := func(at time.Time, kind, body string) {
		fmt.Fprintf(&b, `{"v":1,"seq":%d,"id":"%064x","prev":"","ts":%q,"run":%q,"agent":%q,"pid":7,"tid":7,"cgroup":1,"mono_ns":%d,"source":"supervisor","kind":%q,%s}`+"\n",
			seq, seq+1, at.Format(time.RFC3339Nano), id, agent, seq+1, kind, body)
		seq++
	}
	add(start, "run_start", `"tier":"observe","command":["sh"]`)
	build(add)
	add(end, "run_end", `"reason":"exit","exit_code":0`)
	if err := os.MkdirAll(filepath.Join(root, id), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// mirroredRefusal adds a refused exec (an action line) and, right after it, the kind=refused line that mirrors it: one
// refusal as a person counts it, two lines in the ledger.
func mirroredRefusal(add func(at time.Time, kind, body string), action, mirror time.Time) {
	const rule = `"op":"exec","target":"curl","rule":"exec.deny[1]","reason":"exec-not-allowed"`
	add(action, "exec", rule+`,"verdict":"refused"`)
	add(mirror, "refused", rule)
}

// hoursFixture is two runs over the last days; now is 23:30 local on 13 Nov 2026, so the last day's 24 buckets are
// exactly that calendar day.
func hoursFixture(t *testing.T) (root string, now time.Time) {
	t.Helper()
	root = t.TempDir()
	now = time.Date(2026, 11, 13, 23, 30, 0, 0, time.UTC)
	day := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	hoursRun(t, root, "r-aaaaaaaa-0000000000101-hours1", "alpha", []time.Time{
		day.Add(9*time.Hour + 5*time.Minute), day.Add(9*time.Hour + 40*time.Minute), day.Add(14*time.Hour + 59*time.Minute), day.Add(15 * time.Hour)})
	hoursRun(t, root, "r-aaaaaaaa-0000000000102-hours2", "beta", []time.Time{
		day.Add(9*time.Hour + 59*time.Minute), day.Add(-30 * time.Hour), day.Add(-30*time.Hour + time.Minute)}[:1])
	// A run from two days before: seen in the week, not in the day.
	hoursRun(t, root, "r-aaaaaaaa-0000000000103-hours3", "gamma", []time.Time{day.Add(-48*time.Hour + 3*time.Hour), day.Add(-48*time.Hour + 3*time.Hour + 20*time.Minute)})
	return root, now
}

func TestHoursCountsAreTheDailyCountsByHour(t *testing.T) {
	root, now := hoursFixture(t)
	snap, err := ledgerview.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	d := hoursOf(snap, "day", now)
	if len(d.Bars) != 24 || !d.Bars[0].Start.Equal(time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)) || !d.Bars[23].End.Equal(time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("the day's buckets: %d, from %v to %v", len(d.Bars), d.From, d.To)
	}
	want := map[int]int{9: 3, 14: 1, 15: 1}
	for h, b := range d.Bars {
		if b.N != want[h] {
			t.Errorf("hour %02d: %d refused, want %d", h, b.N, want[h])
		}
	}
	// The same count the Overview shows for the same calendar day, and the same Lower and Records.
	n, lower, records := dailyRefusals(snap, now)
	if n != d.Total || lower != d.Lower || len(records) != len(d.Records) {
		t.Errorf("the page counts %d (lower %v), the Overview's refused today %d (lower %v)", d.Total, d.Lower, n, lower)
	}
	if d.Peak != 3 || d.PeakBar.Start.Hour() != 9 || d.Active != 3 || len(d.Rows) != 3 || d.Rows[0].Start.Hour() != 15 {
		t.Errorf("peak %d at %v, %d active, rows %d", d.Peak, d.PeakBar.Start, d.Active, len(d.Rows))
	}
	// The week holds every refusal the runs hold: the sum of each run's own counter, the one a run's receipt prints.
	w := hoursOf(snap, "week", now)
	sum := 0
	for _, r := range snap.Runs {
		sum += r.Refusals
	}
	if len(w.Bars) != 168 || w.Total != sum || sum != 7 || w.Lower {
		t.Errorf("the week counts %d in %d bars, the runs' own counters add up to %d", w.Total, len(w.Bars), sum)
	}
	barsMatchLogs(t, snap, w.Bars, now)
}

// barsMatchLogs holds each bar's Logs link to the bar's count: the link's window and the refused verdict select the
// same lines the page counted.
func barsMatchLogs(t *testing.T, snap *ledgerview.Snapshot, bars []hourBar, now time.Time) {
	t.Helper()
	for _, b := range bars {
		if b.N == 0 {
			continue
		}
		u, err := url.Parse(b.Href)
		if err != nil || u.Path != "/logs" {
			t.Fatalf("bar link %q", b.Href)
		}
		lq := readLogsQuery(u.Query(), now)
		if got := snap.Query(lq.f).Matched; got != b.N {
			t.Errorf("%s: Logs finds %d lines in the hour, the page says %d", b.Start.Format("Mon 15:04"), got, b.N)
		}
	}
}

// hoursMirrorFixture is hoursFixture and a run whose refusals are the cases the counting rule exists for: a refused
// action with its kind=refused mirror (one refusal, two lines), a pair that straddles an hour edge (the action at
// 11:59:59.9, its mirror at 12:00:00.1: counted once, in the action's hour), and a refused line that mirrors nothing
// (an orphan, a refusal of its own).
func hoursMirrorFixture(t *testing.T) (root string, now time.Time) {
	t.Helper()
	root, now = hoursFixture(t)
	day := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	hoursLines(t, root, "r-aaaaaaaa-0000000000105-hours5", "delta", day.Add(10*time.Hour+59*time.Minute+50*time.Second), day.Add(13*time.Hour+16*time.Minute),
		func(add func(at time.Time, kind, body string)) {
			mirroredRefusal(add, day.Add(11*time.Hour+20*time.Minute), day.Add(11*time.Hour+20*time.Minute+200*time.Millisecond))
			mirroredRefusal(add, day.Add(11*time.Hour+59*time.Minute+59*time.Second+900*time.Millisecond), day.Add(12*time.Hour+100*time.Millisecond))
			add(day.Add(13*time.Hour+15*time.Minute), "refused", `"op":"read","target":"/home/x/.ssh/id","rule":"fs.deny_read[0]","reason":"fs-denied"`)
		})
	return root, now
}

// The Logs link of a bar finds the lines the page counted when a refusal is two lines, when its mirror lies in the next
// hour, and when a refused line has no action. Logs with the refused verdict lists the action line only, so the
// mirror is not found twice.
func TestHoursCountMirroredRefusalsOnceAndMatchLogs(t *testing.T) {
	root, now := hoursMirrorFixture(t)
	snap, err := ledgerview.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	var delta *ledgerview.Run
	for _, r := range snap.Runs {
		if r.Agent == "delta" {
			delta = r
		}
	}
	if delta == nil {
		t.Fatal("the fixture's run is not in the snapshot")
	}
	if delta.Refusals != 3 {
		t.Fatalf("the fixture's run counts %d refusals, want 3: two pairs and one orphan", delta.Refusals)
	}
	d := hoursOf(snap, "day", now)
	want := map[int]int{9: 3, 11: 2, 13: 1, 14: 1, 15: 1}
	for h, b := range d.Bars {
		if b.N != want[h] {
			t.Errorf("hour %02d: %d refused, want %d (hour 12 holds the edge pair's mirror, not a refusal)", h, b.N, want[h])
		}
	}
	if n, _, _ := dailyRefusals(snap, now); n != d.Total || d.Total != 8 {
		t.Errorf("the page counts %d, the Overview's refused today %d, want 8", d.Total, n)
	}
	w := hoursOf(snap, "week", now)
	sum := 0
	for _, r := range snap.Runs {
		sum += r.Refusals
	}
	if w.Total != sum || sum != 10 {
		t.Errorf("the week counts %d, the runs' own counters add up to %d, want 10", w.Total, sum)
	}
	barsMatchLogs(t, snap, d.Bars, now)
	barsMatchLogs(t, snap, w.Bars, now)
	// The period link finds every refusal once.
	u, err := url.Parse(d.LogsHref)
	if err != nil {
		t.Fatal(err)
	}
	if got := snap.Query(readLogsQuery(u.Query(), now).f).Matched; got != d.Total {
		t.Errorf("the period's Logs link finds %d lines, the page says %d", got, d.Total)
	}
}

func TestHoursPage(t *testing.T) {
	root, now := hoursFixture(t)
	s := newServer(t, root)
	s.cfg.Now = func() time.Time { return now }
	c := login(t, s)
	body := getRaw(t, s, c, "/refusals")
	for _, want := range []string{"Refusals by hour", `class="ch-hours"`, "Hours with refusals", `href="/refusals?span=week"`, `aria-current="true"`, "/logs?verdict=refused&amp;where=since%3A2026-11-13T09%3A00%3A00Z"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	text := get(t, s, c, "/refusals")
	for _, want := range []string{"5 refused in this period", "3 refused in the busiest hour", "3 hours with a refusal", "Today 09:00"} {
		if !strings.Contains(text, want) {
			t.Errorf("the page does not say %q:\n%s", want, pageElement(t, text, "class", "hours-page"))
		}
	}
	if strings.Contains(text, "at least") {
		t.Error("a complete ledger's counts say at least")
	}
	week := get(t, s, c, "/refusals?span=week")
	if !strings.Contains(week, "7 refused in this period") {
		t.Errorf("the week does not say seven:\n%s", pageElement(t, week, "class", "hours-page"))
	}
	if again := get(t, s, c, "/refusals?span=bogus"); !strings.Contains(again, "5 refused in this period") {
		t.Error("an unknown period is not the last day")
	}
	// A ledger with no run says so, with no chart.
	empty := newServer(t, t.TempDir())
	empty.cfg.Now = s.cfg.Now
	if body := get(t, empty, login(t, empty), "/refusals"); !strings.Contains(body, "Nothing was refused in this period") || strings.Contains(body, "ch-hours") {
		t.Errorf("an empty ledger: %s", body)
	}
}

// A run whose events were cut: its counts are lower bounds, say so, and the complete record is linked. An agent name
// is the run's own text and is escaped.
func TestHoursLowerBoundAndEscaping(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 11, 13, 12, 30, 0, 0, time.UTC)
	hour := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	const agent = `<img src=x onerror=alert(1)>`
	// The early refusal and the first gap lines leave the retained window; the run spans hours, so its hours need events.
	hoursRun(t, root, "r-aaaaaaaa-0000000000104-hours4", agent, []time.Time{hour.Add(time.Minute)}, func(add func(time.Time, string, string)) {
		for range 33000 {
			add(hour.Add(2*time.Hour+2*time.Minute), "gap", `"what":"record","why":"routine"`)
		}
		add(hour.Add(2*time.Hour+3*time.Minute), "refused", `"op":"exec","target":"curl","rule":"exec.deny[0]","reason":"exec-not-allowed"`)
	})
	s := newServer(t, root)
	s.cfg.Now = func() time.Time { return now }
	c := login(t, s)
	snap, err := ledgerview.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if r := snap.Runs[0]; !r.Cut || r.Refusals != 2 {
		t.Fatalf("the fixture must cut the run's events: cut=%v refusals=%d", r.Cut, r.Refusals)
	}
	body := getRaw(t, s, c, "/refusals")
	if strings.Contains(body, agent) || !strings.Contains(body, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Error("the run's own agent name is not escaped")
	}
	text := get(t, s, c, "/refusals")
	for _, want := range []string{"Retained event windows omit part of this period", "at least 1 refused in this period", `href="/runs/r-aaaaaaaa-0000000000104-hours4/receipt"`} {
		if !strings.Contains(text, want) {
			t.Errorf("a lower bound lacks %q:\n%s", want, pageElement(t, text, "class", "hours-page"))
		}
	}
}

func TestHourBoundsAreWholeLocalHours(t *testing.T) {
	zone := time.FixedZone("half", 5*3600+1800) // a zone whose hours do not start on a UTC hour
	now := time.Date(2026, 3, 8, 12, 47, 31, 0, zone)
	b := hourBounds(now, 24)
	if len(b) != 25 || !b[24].Equal(time.Date(2026, 3, 8, 13, 0, 0, 0, zone)) || !b[0].Equal(time.Date(2026, 3, 7, 13, 0, 0, 0, zone)) {
		t.Fatalf("bounds %v .. %v", b[0], b[24])
	}
	for i := 1; i < len(b); i++ {
		if b[i].Sub(b[i-1]) != time.Hour {
			t.Fatalf("bucket %d is %v long", i, b[i].Sub(b[i-1]))
		}
	}
}

func TestRefusalBucketsEdges(t *testing.T) {
	at := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	bounds := []time.Time{at, at.Add(time.Hour), at.Add(2 * time.Hour)}
	ev := func(off time.Duration) ledgerview.Event { return ledgerview.Event{Kind: "refused", TS: at.Add(off)} }
	run := func(evs ...ledgerview.Event) *ledgerview.Run {
		r := &ledgerview.Run{Events: evs, Refusals: len(evs), RefusalFirst: evs[0].TS, RefusalLast: evs[len(evs)-1].TS}
		for _, e := range evs {
			if e.TS.Before(r.RefusalFirst) {
				r.RefusalFirst = e.TS
			}
			if e.TS.After(r.RefusalLast) {
				r.RefusalLast = e.TS
			}
		}
		return r
	}
	snap := &ledgerview.Snapshot{Runs: []*ledgerview.Run{
		run(ev(-time.Second), ev(0), ev(time.Hour-time.Nanosecond), ev(time.Hour), ev(2*time.Hour-time.Nanosecond), ev(2*time.Hour)), // either side of every edge
		run(ev(-time.Hour)),    // wholly before
		run(ev(5 * time.Hour)), // wholly after
	}}
	c := snap.RefusalBuckets(bounds)
	if len(c.Counts) != 2 || c.Counts[0] != 2 || c.Counts[1] != 2 || c.Lower || c.Total() != 4 {
		t.Errorf("counts %v lower=%v", c.Counts, c.Lower)
	}
	if n := (&ledgerview.Snapshot{}).RefusalBuckets(bounds[:1]); len(n.Counts) != 0 {
		t.Error("one edge is no bucket")
	}
}
