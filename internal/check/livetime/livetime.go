// SPDX-License-Identifier: Apache-2.0

package livetime

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
)

// Forms is the accepted spellings, in the words every error of Parse ends with.
const Forms = `--for takes a duration such as 45m, 72h, 3d, 1d12h or 7w; ` +
	`--until takes a time such as 17:00, "tomorrow 09:00", "Fri 17:00", "2026-11-14 17:00" or 2026-11-14T17:00:00Z`

// ErrBoth is --for and --until given together.
var ErrBoth = errors.New("give --for or --until, not both")

// day and week are the units --for adds to Go's: elapsed time, not calendar days.
const (
	day  = 24 * time.Hour
	week = 7 * day
)

// Parse is the instant a live change's time limit ends, in UTC, from --for (forArg) or --until (untilArg) read at now
// in loc; the zero time when both are empty (no limit). Both together are ErrBoth. A spelling it does not read is an
// error ending with Forms; an instant outside liveblock.CheckUntil's bounds is that error (it wraps
// liveblock.ErrInvalid).
func Parse(forArg, untilArg string, now time.Time, loc *time.Location) (time.Time, error) {
	forArg, untilArg = strings.TrimSpace(forArg), strings.TrimSpace(untilArg)
	if loc == nil {
		loc = time.UTC
	}
	var t time.Time
	switch {
	case forArg == "" && untilArg == "":
		return time.Time{}, nil
	case forArg != "" && untilArg != "":
		return time.Time{}, ErrBoth
	case forArg != "":
		d, err := ParseDuration(forArg)
		if err != nil {
			return time.Time{}, fmt.Errorf("--for %q: %w; %s", forArg, err, Forms)
		}
		t = now.Add(d)
	default:
		var err error
		if t, err = parseUntil(untilArg, now, loc); err != nil {
			return time.Time{}, fmt.Errorf("--until %q: %w; %s", untilArg, err, Forms)
		}
	}
	if err := liveblock.CheckUntil(now, t); err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

// ParseDuration is liveblock.ParseDuration: time.ParseDuration with the units d (24 hours) and w (7 days) beside Go's,
// in any order and mix ("1d12h", "7w", "1w2d"). A sign, an empty string and a total of zero or less are refused. The
// parser lives in liveblock so the dashboard, which imports nothing under internal/check, reads a typed duration the
// same way --for does.
func ParseDuration(s string) (time.Duration, error) { return liveblock.ParseDuration(s) }

// clockForm is "HH:MM" (or "H:MM") on a 24-hour clock.
var clockForm = regexp.MustCompile(`^([0-9]{1,2}):([0-9]{2})$`)

// weekdays maps the spellings of a weekday (three letters or the whole name, any case) to it.
var weekdays = func() map[string]time.Weekday {
	m := make(map[string]time.Weekday, 14)
	for d := time.Sunday; d <= time.Saturday; d++ {
		name := strings.ToLower(d.String())
		m[name], m[name[:3]] = d, d
	}
	return m
}()

// parseUntil reads an --until spelling at now in loc.
func parseUntil(s string, now time.Time, loc *time.Location) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if d, err := time.Parse("2006-01-02 15:04", s); err == nil {
		// Read as a wall clock, then placed on loc's: a time a change skips or repeats is read as the other forms read it.
		t := wall(d.Year(), d.Month(), d.Day(), d.Hour(), d.Minute(), loc)
		if c, ok := firstAfter(t, now, loc); ok {
			return c, nil
		}
		return t, nil // gone: CheckUntil refuses it
	}
	fields := strings.Fields(s)
	local := now.In(loc)
	switch len(fields) {
	case 1:
		h, m, err := clock(fields[0])
		if err != nil {
			return time.Time{}, err
		}
		for days := 0; days < 2; days++ {
			if t, ok := nextOn(local, days, h, m, now, loc); ok {
				return t, nil
			}
		}
		return at(local, 1, h, m, loc), nil
	case 2:
		h, m, err := clock(fields[1])
		if err != nil {
			return time.Time{}, err
		}
		word := strings.ToLower(fields[0])
		if word == "tomorrow" {
			if t, ok := nextOn(local, 1, h, m, now, loc); ok {
				return t, nil
			}
			return at(local, 1, h, m, loc), nil
		}
		wd, ok := weekdays[word]
		if !ok {
			return time.Time{}, fmt.Errorf("%q is neither tomorrow nor a weekday", fields[0])
		}
		// The next instant on that weekday's clock strictly after now: today's when it is that weekday and still
		// ahead, else the coming one.
		ahead := (int(wd) - int(local.Weekday()) + 7) % 7
		for _, days := range [...]int{ahead, ahead + 7} {
			if t, ok := nextOn(local, days, h, m, now, loc); ok {
				return t, nil
			}
		}
		return at(local, ahead+7, h, m, loc), nil
	}
	return time.Time{}, errors.New("not a time this reads")
}

// clock is an "HH:MM" spelling's hour and minute.
func clock(s string) (h, m int, err error) {
	sub := clockForm.FindStringSubmatch(s)
	if sub == nil {
		return 0, 0, fmt.Errorf("%q is not HH:MM", s)
	}
	h, _ = strconv.Atoi(sub[1])
	m, _ = strconv.Atoi(sub[2])
	if h > 23 || m > 59 {
		return 0, 0, fmt.Errorf("%q is not a time of day (00:00 to 23:59)", s)
	}
	return h, m, nil
}

// at is h:m on the day days after local's, on loc's clock (wall).
func at(local time.Time, days, h, m int, loc *time.Location) time.Time {
	return wall(local.Year(), local.Month(), local.Day()+days, h, m, loc)
}

// wall is an instant loc's clock reads y-mo-d h:m at (time.Date's, which picks either one in an hour a change back to
// standard time repeats: firstAfter chooses between them), or, for a time a change to summer time skips, the first
// instant after the skip: the moment the clock passes h:m. time.Date moves a skipped time by the skip, forward east
// of Greenwich and back west of it, so "--until 02:30" on New York's spring-forward day was 01:30, an hour before
// the clock read anything past 02:00.
func wall(y int, mo time.Month, d, h, m int, loc *time.Location) time.Time {
	t := time.Date(y, mo, d, h, m, 0, 0, loc)
	want := time.Date(y, mo, d, h, m, 0, 0, time.UTC)
	lt := t.In(loc)
	read := time.Date(lt.Year(), lt.Month(), lt.Day(), lt.Hour(), lt.Minute(), 0, 0, time.UTC)
	if read.Equal(want) {
		return t
	}
	// The clock never reads h:m that day: t is on one side of the skip, and the change is t's zone's edge on the
	// other side of it.
	start, end := t.ZoneBounds()
	edge := start
	if read.Before(want) {
		edge = end
	}
	if edge.IsZero() {
		return t
	}
	return edge
}

// nextOn is the first instant after now that loc's clock reads h:m on the day days after local's, and whether there
// is one. A change back to standard time reads the hour before it twice, and time.Date picks either of the two
// instants: at 01:40 on the second pass through the hour, "--until 01:50" was the first 01:50, already gone, so the limit
// landed a day later, and on the first pass in a zone east of Greenwich it landed on the second 01:50, an hour late.
func nextOn(local time.Time, days, h, m int, now time.Time, loc *time.Location) (time.Time, bool) {
	return firstAfter(at(local, days, h, m, loc), now, loc)
}

// firstAfter is the earlier of t and its clockTwin that is after now, and whether either is.
func firstAfter(t, now time.Time, loc *time.Location) (time.Time, bool) {
	first, ok := time.Time{}, false
	for _, c := range [...]time.Time{t, clockTwin(t, loc)} {
		if c.After(now) && (!ok || c.Before(first)) {
			first, ok = c, true
		}
	}
	return first, ok
}

// clockTwin is the other instant loc's clock reads the same hour and minute as t, or t itself when there is none: the
// reading of a zone change's repeated hour on its other pass.
func clockTwin(t time.Time, loc *time.Location) time.Time {
	t = t.In(loc)
	_, offset := t.Zone()
	start, end := t.ZoneBounds()
	for _, edge := range [...]time.Time{start.Add(-time.Nanosecond), end} {
		if edge.Before(minClockTime) {
			continue // the zone has no change on this side
		}
		_, other := edge.In(loc).Zone()
		c := t.Add(time.Duration(offset-other) * time.Second).In(loc)
		if c.Hour() == t.Hour() && c.Minute() == t.Minute() && c.Day() == t.Day() {
			return c
		}
	}
	return t
}

// minClockTime is before every time a limit is set at, so a ZoneBounds zero time (no change on that side) falls below it.
var minClockTime = time.Unix(0, 0)

// Describe says the instant t, seen at now in loc, as the limit of a change: "until Fri 31 Oct 17:00 (in 3 days)",
// the year added when it is not now's, "(passed)" when it has come. An instant less than an hour away that is not
// on a whole minute keeps its seconds ("until Tue 27 Oct 14:47:17 (in 1 minute)"): "--for 1m" said as "14:47" was up
// to a minute off.
func Describe(t, now time.Time, loc *time.Location) string { return "until " + At(t, now, loc) }

// At is Describe without its leading "until": "Fri 31 Oct 17:00 (in 3 days)", for a line that has its own verb
// ("ends Fri 31 Oct 17:00 (in 3 days)").
func At(t, now time.Time, loc *time.Location) string {
	if loc == nil {
		loc = time.UTC
	}
	lt := t.In(loc)
	clk := "15:04"
	if t.Sub(now).Abs() < time.Hour && !lt.Truncate(time.Minute).Equal(lt) {
		clk = "15:04:05"
	}
	layout := "Mon 2 Jan " + clk
	if lt.Year() != now.In(loc).Year() {
		layout = "Mon 2 Jan 2006 " + clk
	}
	return lt.Format(layout) + " (" + Away(t.Sub(now)) + ")"
}

// Away says how far ahead a span d is: "in 45 minutes", "in 5 hours", "in 3 days", "in 7 weeks"; "passed" when it is
// not ahead.
func Away(d time.Duration) string {
	switch {
	case d <= 0:
		return "passed"
	case d < 90*time.Minute:
		return "in " + count(int(math.Ceil(d.Minutes())), "minute")
	case d < 48*time.Hour:
		return "in " + count(int(d.Round(time.Hour)/time.Hour), "hour")
	case d < 14*day:
		return "in " + count(int(d.Round(day)/day), "day")
	}
	return "in " + count(int(d.Round(week)/week), "week")
}

// count is n and the unit, plural when n is not 1.
func count(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}
