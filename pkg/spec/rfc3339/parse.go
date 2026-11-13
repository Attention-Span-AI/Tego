// SPDX-License-Identifier: Apache-2.0

package rfc3339

import (
	"errors"
	"fmt"
	"time"
)

// ErrNotRFC3339 is Parse's error for a value outside the profile.
var ErrNotRFC3339 = errors.New("not an RFC 3339 date-time")

// Parse reads s as the profile's date-time: YYYY-MM-DDTHH:MM:SS, an optional "." and one or more digits, then "Z" or
// +HH:MM / -HH:MM, with a real day of the proleptic Gregorian calendar, hours 00 to 23, minutes and seconds 00 to 59,
// and an offset's hours 00 to 23 and minutes 00 to 59. Within RFC 3339 the profile takes two choices the RFC leaves to
// a specification: "T" and "Z" upper case only (RFC 3339 §5.6 allows lower case and lets a specification require
// upper case), and no leap second 60 (no Tego writer can write one: Go's time holds none). Tego's writers write
// time.RFC3339Nano in UTC, which is always inside the profile.
func Parse(s string) (time.Time, error) {
	if !valid(s) {
		return time.Time{}, fmt.Errorf("%w: %q", ErrNotRFC3339, s)
	}
	// A numeric offset must not initialize time.Local from the host's timezone or environment.
	t, err := time.ParseInLocation(time.RFC3339Nano, s, time.UTC)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %q: %w", ErrNotRFC3339, s, err)
	}
	return t, nil
}

// valid checks s against the profile's shape and ranges.
func valid(s string) bool {
	if len(s) < len("2006-01-02T15:04:05Z") {
		return false
	}
	num := func(from, to, lo, hi int) (int, bool) {
		n := 0
		for i := from; i < to; i++ {
			c := s[i]
			if c < '0' || c > '9' {
				return 0, false
			}
			n = n*10 + int(c-'0')
		}
		return n, n >= lo && n <= hi
	}
	if s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' {
		return false
	}
	year, okY := num(0, 4, 0, 9999)
	month, okM := num(5, 7, 1, 12)
	if !okY || !okM {
		return false
	}
	if _, ok := num(8, 10, 1, daysIn(month, year)); !ok {
		return false
	}
	for _, f := range [][4]int{{11, 13, 0, 23}, {14, 16, 0, 59}, {17, 19, 0, 59}} {
		if _, ok := num(f[0], f[1], f[2], f[3]); !ok {
			return false
		}
	}
	rest := s[19:]
	if len(rest) > 0 && rest[0] == '.' {
		n := 1
		for n < len(rest) && rest[n] >= '0' && rest[n] <= '9' {
			n++
		}
		if n == 1 {
			return false
		}
		rest = rest[n:]
	}
	switch {
	case rest == "Z":
		return true
	case len(rest) == 6 && (rest[0] == '+' || rest[0] == '-') && rest[3] == ':':
		return numIn(rest[1:3], 23) && numIn(rest[4:6], 59)
	}
	return false
}

// numIn reports whether d is two digits naming no more than hi.
func numIn(d string, hi int) bool {
	if len(d) != 2 || d[0] < '0' || d[0] > '9' || d[1] < '0' || d[1] > '9' {
		return false
	}
	return int(d[0]-'0')*10+int(d[1]-'0') <= hi
}

// daysIn is the days of month in year, Gregorian leap years included.
func daysIn(month, year int) int {
	switch month {
	case 2:
		if (year%4 == 0 && year%100 != 0) || year%400 == 0 {
			return 29
		}
		return 28
	case 4, 6, 9, 11:
		return 30
	}
	return 31
}
