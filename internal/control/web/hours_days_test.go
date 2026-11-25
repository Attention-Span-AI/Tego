// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// At phone width the week is drawn by local calendar day (168 hourly bars are under 2 px each at 390 px and
// cannot be tapped). The days are the hours added up, never a second count.
func TestWeekDaysAreTheHoursAddedUp(t *testing.T) {
	root, _ := hoursFixture(t)
	snap, err := ledgerview.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	// 10:30 in the morning: the 168 hours start at 11:00 a week ago, so the first and the last day are part days.
	now := time.Date(2026, 11, 13, 10, 30, 0, 0, time.UTC)
	w := hoursOf(snap, "week", now)
	if len(w.Days) != 8 || w.DayChart == nil {
		t.Fatalf("%d days, chart %v; want 8 (a week that starts mid-day touches 8 calendar days)", len(w.Days), w.DayChart)
	}
	sum := 0
	for i, d := range w.Days {
		sum += d.N
		if i > 0 && !d.Start.Equal(w.Days[i-1].End) {
			t.Errorf("day %d starts %v, the day before ends %v", i, d.Start, w.Days[i-1].End)
		}
		if d.Href != logsWindow(d.Start, d.End) {
			t.Errorf("day %d links %s", i, d.Href)
		}
	}
	if sum != w.Total || !w.Days[0].Start.Equal(w.From) || !w.Days[7].End.Equal(w.To) {
		t.Errorf("the days add up to %d from %v to %v; the hours to %d from %v to %v", sum, w.Days[0].Start, w.Days[7].End, w.Total, w.From, w.To)
	}
	if w.Days[7].Name != "Today" || w.Days[6].Name != "Thu" {
		t.Errorf("day names: %q, %q", w.Days[6].Name, w.Days[7].Name)
	}
	// The day view has no day chart: its 24 bars are wide enough.
	if d := hoursOf(snap, "day", now); d.DayChart != nil || len(d.Days) != 0 {
		t.Errorf("the day view carries a day chart")
	}
}

// The page writes the days as links under their own chart, each a tap target with its count, and the hourly chart
// stays for the desktop.
func TestWeekPageHasDayLinks(t *testing.T) {
	root, now := hoursFixture(t)
	s := newServer(t, root)
	s.cfg.Now = func() time.Time { return now }
	c := login(t, s)
	body := getRaw(t, s, c, "/refusals?span=week")
	for _, want := range []string{`class="ch-hours"`, `class="ch-days"`, `class="hr-coarse"`, `class="hr-days"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the week lacks %q", want)
		}
	}
	if n := strings.Count(body, `class="hr-dn"`); n != 7 {
		t.Errorf("%d day links, want 7", n)
	}
	if day := getRaw(t, s, c, "/refusals?span=day"); strings.Contains(day, "hr-coarse") {
		t.Error("the day view writes the day chart")
	}
}
