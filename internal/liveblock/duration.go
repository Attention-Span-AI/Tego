// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// day and week are the units a typed duration adds to Go's: elapsed time, not calendar days.
const (
	day  = 24 * time.Hour
	week = 7 * day
)

// durationPart is one number and unit of a duration: "1.5d", "12h", "30m".
var durationPart = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)(ns|us|µs|ms|s|m|h|d|w)`)

// ParseDuration is time.ParseDuration with the units d (24 hours) and w (7 days) beside Go's, in any order and mix
// ("1d12h", "7w", "1w2d"). A sign, an empty string and a total of zero or less are refused: a limit lies ahead. It is
// how both the CLI's --for (internal/check/livetime) and the dashboard's typed "for" read a time limit; CheckUntil
// holds the result to the bounds.
func ParseDuration(s string) (time.Duration, error) {
	rest := strings.TrimSpace(s)
	if rest == "" {
		return 0, errors.New("empty duration")
	}
	var total time.Duration
	for rest != "" {
		m := durationPart.FindStringSubmatch(rest)
		if m == nil {
			return 0, fmt.Errorf("%q is not a number followed by a unit (ns, us, ms, s, m, h, d or w)", rest)
		}
		rest = rest[len(m[0]):]
		var d time.Duration
		switch m[2] {
		case "d", "w":
			n, err := strconv.ParseFloat(m[1], 64)
			unit := map[string]time.Duration{"d": day, "w": week}[m[2]]
			if err != nil || n*float64(unit) > math.MaxInt64 {
				return 0, fmt.Errorf("%s%s is too long", m[1], m[2])
			}
			d = time.Duration(n * float64(unit))
		default:
			var err error
			if d, err = time.ParseDuration(m[0]); err != nil {
				return 0, err
			}
		}
		if total > math.MaxInt64-d {
			return 0, errors.New("too long")
		}
		total += d
	}
	if total <= 0 {
		return 0, errors.New("a time limit lies ahead: the duration must be above zero")
	}
	return total, nil
}
