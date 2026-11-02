// SPDX-License-Identifier: Apache-2.0

package livetime

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
)

func berlin(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skipf("no Europe/Berlin zone here: %v", err)
	}
	return loc
}

// TestParse: every form of --for and --until, read at a Tuesday afternoon in Berlin, to the instant it names in UTC.
func TestParse(t *testing.T) {
	loc := berlin(t)
	now := time.Date(2026, 10, 27, 14, 30, 0, 0, loc) // Tue 27 Oct 2026, CET (+01:00)
	local := func(y int, mo time.Month, d, h, m int) time.Time { return time.Date(y, mo, d, h, m, 0, 0, loc).UTC() }
	for _, tc := range []struct {
		name, forArg, untilArg string
		want                   time.Time
	}{
		{"none", "", "", time.Time{}},
		{"minutes", "45m", "", now.Add(45 * time.Minute).UTC()},
		{"hours", "72h", "", now.Add(72 * time.Hour).UTC()},
		{"days", "3d", "", now.Add(72 * time.Hour).UTC()},
		{"day and hours", "1d12h", "", now.Add(36 * time.Hour).UTC()},
		{"weeks", "7w", "", now.Add(7 * 7 * 24 * time.Hour).UTC()},
		{"week and days", "1w2d", "", now.Add(9 * 24 * time.Hour).UTC()},
		{"fraction of a day", "1.5d", "", now.Add(36 * time.Hour).UTC()},
		{"go mix", "1h30m", "", now.Add(90 * time.Minute).UTC()},
		{"spaces trimmed", " 2h ", "", now.Add(2 * time.Hour).UTC()},
		{"rfc3339", "", "2026-11-14T17:00:00Z", time.Date(2026, 11, 14, 17, 0, 0, 0, time.UTC)},
		{"rfc3339 offset", "", "2026-11-14T17:00:00+05:00", time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)},
		{"date and time", "", "2026-11-14 17:00", local(2026, 11, 14, 17, 0)},
		{"weekday ahead", "", "Fri 17:00", local(2026, 10, 30, 17, 0)},
		{"weekday whole name", "", "friday 17:00", local(2026, 10, 30, 17, 0)},
		{"same weekday still ahead", "", "Tue 17:00", local(2026, 10, 27, 17, 0)},
		{"same weekday passed", "", "Tue 09:00", local(2026, 11, 3, 9, 0)},
		{"weekday earlier in the week", "", "MON 08:00", local(2026, 11, 2, 8, 0)},
		{"time still ahead today", "", "17:00", local(2026, 10, 27, 17, 0)},
		{"time passed today", "", "9:15", local(2026, 10, 28, 9, 15)},
		{"tomorrow", "", "tomorrow 09:00", local(2026, 10, 28, 9, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.forArg, tc.untilArg, now, loc)
			if err != nil || !got.Equal(tc.want) || (!got.IsZero() && got.Location() != time.UTC) {
				t.Fatalf("Parse(%q, %q) = %v, %v; want %v", tc.forArg, tc.untilArg, got, err, tc.want)
			}
		})
	}
}

// TestParseAcrossDST: Berlin leaves summer time at 03:00 on Sunday 25 October 2026. A clock time is that day's clock
// (17:00 CET, 30 hours from Saturday noon CEST, not 29); a duration is elapsed time (1d is 24 hours, landing at 11:00
// on Sunday's clock).
func TestParseAcrossDST(t *testing.T) {
	loc := berlin(t)
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, loc) // Sat, CEST (+02:00)
	got, err := Parse("", "Sun 17:00", now, loc)
	if err != nil || got.Sub(now) != 30*time.Hour || got.In(loc).Hour() != 17 {
		t.Fatalf("Sun 17:00 = %v (%v away), %v; want 17:00 CET, 30 h away", got.In(loc), got.Sub(now), err)
	}
	got, err = Parse("1d", "", now, loc)
	if err != nil || got.Sub(now) != 24*time.Hour || got.In(loc).Hour() != 11 {
		t.Fatalf("1d = %v, %v; want 24 h later, 11:00 on Sunday's clock", got.In(loc), err)
	}
	// 02:30 on the spring-forward day (29 March 2026) does not exist; it is the first instant after the skip, 03:00
	// CEST, when the clock has passed 02:30 (TestParseInTheSkippedHour).
	spring := time.Date(2026, 3, 28, 12, 0, 0, 0, loc)
	got, err = Parse("", "2026-03-29 02:30", spring, loc)
	if err != nil || got.In(loc).Hour() != 3 || got.In(loc).Minute() != 0 {
		t.Fatalf("a skipped 02:30 = %v, %v; want 03:00 CEST", got.In(loc), err)
	}
}

// TestParseInTheRepeatedHour: a change back to standard time reads one hour twice, and an --until in it means the
// next time the clock reads that. time.Date picks one of the two instants, so on the second pass a limit ten minutes
// off landed a day later, and on the first pass in a zone east of Greenwich an hour late.
func TestParseInTheRepeatedHour(t *testing.T) {
	for _, tc := range []struct {
		zone, now, until, want string
	}{
		// New York, 2026-11-01: 01:59:59 EDT (05:59:59Z) is followed by 01:00:00 EST (06:00:00Z).
		{"America/New_York", "2026-11-01T05:40:00Z", "01:50", "2026-11-01T05:50:00Z"}, // first pass: the first 01:50
		{"America/New_York", "2026-11-01T05:55:00Z", "01:50", "2026-11-01T06:50:00Z"}, // first pass, past it: the second
		{"America/New_York", "2026-11-01T06:40:00Z", "01:50", "2026-11-01T06:50:00Z"}, // second pass: the second
		{"America/New_York", "2026-11-01T06:55:00Z", "01:50", "2026-11-02T06:50:00Z"}, // both gone: tomorrow's
		{"America/New_York", "2026-11-01T04:00:00Z", "Sun 01:50", "2026-11-01T05:50:00Z"},
		{"America/New_York", "2026-11-01T06:40:00Z", "Sun 01:50", "2026-11-01T06:50:00Z"},
		{"America/New_York", "2026-11-01T06:55:00Z", "Sun 01:50", "2026-11-08T06:50:00Z"},
		// Berlin, 2026-10-25: 02:59:59 CEST (00:59:59Z) is followed by 02:00:00 CET (01:00:00Z).
		{"Europe/Berlin", "2026-10-25T00:10:00Z", "02:30", "2026-10-25T00:30:00Z"}, // first pass: the first 02:30
		{"Europe/Berlin", "2026-10-25T00:40:00Z", "02:30", "2026-10-25T01:30:00Z"},
		{"Europe/Berlin", "2026-10-25T01:10:00Z", "02:30", "2026-10-25T01:30:00Z"},
		// Every other form takes the first reading still ahead too: each landed on the second, an hour late.
		{"Europe/Berlin", "2026-10-24T10:00:00Z", "tomorrow 02:30", "2026-10-25T00:30:00Z"},
		{"Europe/Berlin", "2026-10-24T01:00:00Z", "02:30", "2026-10-25T00:30:00Z"},     // today's gone: tomorrow's first
		{"Europe/Berlin", "2026-10-18T01:00:00Z", "Sun 02:30", "2026-10-25T00:30:00Z"}, // today's gone: next week's first
		{"Europe/Berlin", "2026-10-24T10:00:00Z", "2026-10-25 02:30", "2026-10-25T00:30:00Z"},
		{"Europe/Berlin", "2026-10-25T00:10:00Z", "2026-10-25 02:30", "2026-10-25T00:30:00Z"},
		{"Europe/Berlin", "2026-10-25T00:40:00Z", "2026-10-25 02:30", "2026-10-25T01:30:00Z"},
		{"America/New_York", "2026-11-01T06:40:00Z", "2026-11-01 01:50", "2026-11-01T06:50:00Z"}, // was refused as past
		// Lord Howe moves half an hour: 2026-04-05 01:59:59 +11 is followed by 01:30:00 +1030 (15:00:00Z).
		{"Australia/Lord_Howe", "2026-04-04T14:35:00Z", "01:45", "2026-04-04T14:45:00Z"},
		{"Australia/Lord_Howe", "2026-04-04T15:05:00Z", "01:45", "2026-04-04T15:15:00Z"},
		// An ordinary day and a zone with no changes at all.
		{"America/New_York", "2026-07-01T16:00:00Z", "13:00", "2026-07-01T17:00:00Z"},
		{"Asia/Kathmandu", "2026-11-01T01:00:00Z", "07:00", "2026-11-01T01:15:00Z"},
	} {
		loc, err := time.LoadLocation(tc.zone)
		if err != nil {
			t.Fatal(err)
		}
		now, err := time.Parse(time.RFC3339, tc.now)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse("", tc.until, now, loc)
		if err != nil {
			t.Errorf("%s at %s --until %q: %v", tc.zone, tc.now, tc.until, err)
			continue
		}
		if s := got.UTC().Format(time.RFC3339); s != tc.want {
			t.Errorf("%s at %s --until %q = %s, want %s", tc.zone, tc.now, tc.until, s, tc.want)
		}
	}
}

// TestParseInTheSkippedHour: a change to summer time skips an hour, and an --until in it is the first instant after
// the skip, when the clock has passed that time, on both sides of Greenwich. time.Date moves it by the skip, so west
// of Greenwich it landed an hour before: New York's 02:30 was 01:30 EST, lifting a block early.
func TestParseInTheSkippedHour(t *testing.T) {
	for _, tc := range []struct {
		zone, now, until, want string
	}{
		// New York, 2026-03-08: 01:59:59 EST (06:59:59Z) is followed by 03:00:00 EDT (07:00:00Z).
		{"America/New_York", "2026-03-08T05:00:00Z", "02:30", "2026-03-08T07:00:00Z"},
		{"America/New_York", "2026-03-08T05:00:00Z", "Sun 02:30", "2026-03-08T07:00:00Z"},
		{"America/New_York", "2026-03-08T05:00:00Z", "2026-03-08 02:30", "2026-03-08T07:00:00Z"},
		{"America/New_York", "2026-03-07T12:00:00Z", "tomorrow 02:30", "2026-03-08T07:00:00Z"},
		{"America/New_York", "2026-03-08T05:00:00Z", "03:00", "2026-03-08T07:00:00Z"},
		// Berlin, 2026-03-29: 01:59:59 CET (00:59:59Z) is followed by 03:00:00 CEST (01:00:00Z).
		{"Europe/Berlin", "2026-03-28T23:30:00Z", "02:30", "2026-03-29T01:00:00Z"},
		{"Europe/Berlin", "2026-03-28T23:30:00Z", "Sun 02:00", "2026-03-29T01:00:00Z"},
		{"Europe/Berlin", "2026-03-28T23:30:00Z", "01:59", "2026-03-29T00:59:00Z"},
	} {
		loc, err := time.LoadLocation(tc.zone)
		if err != nil {
			t.Fatal(err)
		}
		now, err := time.Parse(time.RFC3339, tc.now)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse("", tc.until, now, loc)
		if err != nil {
			t.Errorf("%s at %s --until %q: %v", tc.zone, tc.now, tc.until, err)
			continue
		}
		if s := got.UTC().Format(time.RFC3339); s != tc.want {
			t.Errorf("%s at %s --until %q = %s, want %s", tc.zone, tc.now, tc.until, s, tc.want)
		}
	}
}

// TestParseRefuses: both flags, unreadable spellings (each error lists the accepted forms), past times and the bounds
// (1 minute to 400 days, liveblock.CheckUntil's).
func TestParseRefuses(t *testing.T) {
	loc := berlin(t)
	now := time.Date(2026, 10, 27, 14, 30, 0, 0, loc)
	if _, err := Parse("1h", "17:00", now, loc); !errors.Is(err, ErrBoth) {
		t.Errorf("both flags: %v, want ErrBoth", err)
	}
	for _, tc := range []struct{ forArg, untilArg string }{
		{"3", ""}, {"3x", ""}, {"-1h", ""}, {"0h", ""}, {"1d 2h", ""}, {"h", ""}, {"1e3h", ""},
		{"", "25:00"}, {"", "17:60"}, {"", "someday 17:00"}, {"", "Fri"}, {"", "next Fri 17:00"}, {"", "2026-13-01 10:00"},
		{"", "noon"},
	} {
		_, err := Parse(tc.forArg, tc.untilArg, now, loc)
		if err == nil || !strings.HasSuffix(err.Error(), Forms) {
			t.Errorf("Parse(%q, %q) = %v; want an error listing the forms", tc.forArg, tc.untilArg, err)
		}
	}
	for _, tc := range []struct{ forArg, untilArg string }{
		{"30s", ""}, {"59s", ""}, {"401d", ""}, {"58w", ""},
		{"", "2026-10-27 14:00"}, {"", "2026-10-27T13:00:00Z"}, {"", "2027-12-31 10:00"},
	} {
		if _, err := Parse(tc.forArg, tc.untilArg, now, loc); !errors.Is(err, liveblock.ErrInvalid) {
			t.Errorf("Parse(%q, %q) = %v; want the bounds' ErrInvalid", tc.forArg, tc.untilArg, err)
		}
	}
	for _, ok := range []string{"1m", "400d"} {
		if _, err := Parse(ok, "", now, loc); err != nil {
			t.Errorf("Parse(%q) at the bound: %v", ok, err)
		}
	}
}

// TestDescribe: an instant as a limit, in the location's words, with how far away it is.
func TestDescribe(t *testing.T) {
	loc := berlin(t)
	now := time.Date(2026, 10, 28, 17, 0, 0, 0, loc)
	for _, tc := range []struct {
		t    time.Time
		want string
	}{
		{now.Add(72 * time.Hour), "until Sat 31 Oct 17:00 (in 3 days)"},
		{now.Add(45 * time.Minute), "until Wed 28 Oct 17:45 (in 45 minutes)"},
		{now.Add(61 * time.Second), "until Wed 28 Oct 17:01:01 (in 2 minutes)"},
		{now.Add(2*time.Hour + 30*time.Second), "until Wed 28 Oct 19:00 (in 2 hours)"},
		{now.Add(time.Minute), "until Wed 28 Oct 17:01 (in 1 minute)"},
		{now.Add(5 * time.Hour), "until Wed 28 Oct 22:00 (in 5 hours)"},
		{now.Add(24 * time.Hour), "until Thu 29 Oct 17:00 (in 24 hours)"},
		{now.Add(49 * 24 * time.Hour), "until Wed 16 Dec 17:00 (in 7 weeks)"},
		{now.Add(80 * 24 * time.Hour), "until Sat 16 Jan 2027 17:00 (in 11 weeks)"},
		{now.Add(-time.Minute), "until Wed 28 Oct 16:59 (passed)"},
	} {
		if got := Describe(tc.t, now, loc); got != tc.want {
			t.Errorf("Describe(%v) = %q, want %q", tc.t, got, tc.want)
		}
		if got, want := At(tc.t, now, loc), strings.TrimPrefix(tc.want, "until "); got != want {
			t.Errorf("At(%v) = %q, want %q", tc.t, got, want)
		}
	}
}
