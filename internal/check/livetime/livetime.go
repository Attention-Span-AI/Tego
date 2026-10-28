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
	if t, err := time.ParseInLocation("2006-01-02 15:04", s, loc); err == nil {
		return t, nil
	}
	fields := strings.Fields(s)
	local := now.In(loc)
	switch len(fields) {
	case 1:
		h, m, err := clock(fields[0])
		if err != nil {
			return time.Time{}, err
		}
		t := at(local, 0, h, m, loc)
		if !t.After(now) {
			t = at(local, 1, h, m, loc)
		}
		return t, nil
	case 2:
		h, m, err := clock(fields[1])
		if err != nil {
			return time.Time{}, err
		}
		word := strings.ToLower(fields[0])
		if word == "tomorrow" {
			return at(local, 1, h, m, loc), nil
		}
		wd, ok := weekdays[word]
		if !ok {
			return time.Time{}, fmt.Errorf("%q is neither tomorrow nor a weekday", fields[0])
		}
		// The next instant on that weekday's clock strictly after now: today's when it is that weekday and still
		// ahead, else the coming one.
		ahead := (int(wd) - int(local.Weekday()) + 7) % 7
		t := at(local, ahead, h, m, loc)
		if !t.After(now) {
			t = at(local, ahead+7, h, m, loc)
		}
		return t, nil
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

// at is h:m on the day days after local's, on loc's clock (time.Date normalizes a time a daylight-saving change
// skips).
func at(local time.Time, days, h, m int, loc *time.Location) time.Time {
	return time.Date(local.Year(), local.Month(), local.Day()+days, h, m, 0, 0, loc)
}

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
