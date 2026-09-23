// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ByteSize is a size in bytes. Its YAML form is an integer with an IEC suffix (B, KiB, MiB, GiB,
// TiB, PiB) or a bare integer meaning bytes; decimal suffixes (KB, MB, GB) are rejected so that
// identical-looking values never mean different byte counts.
type ByteSize int64

// ErrUnit is the sentinel wrapped by the unit parsers.
var ErrUnit = errors.New("config: invalid unit")

// The cores counts a cpu.max write accepts. Every run writes cores as "<round(cores*100000)> 100000"
// (internal/runtime/cgroup FormatCPUMax), and the kernel refuses a quota below 1 ms a period or above
// MAX_BW, 2^44-1 µs, the bound that keeps the bandwidth shift from overflowing (kernel/sched/core.c,
// tg_set_bandwidth): EINVAL, at the start of every run. MinCPUCores and MaxCPUCores are that range in
// cores; CPUCoresInRange is the exact test on the rounded quota. A limits.cpu outside it passed compile
// and then failed each run with exit 125, so the machine config and the contract refuse it where it is
// written, as they refuse a cpu_weight outside 1..10000.
const (
	MinCPUCores = 0.01
	MaxCPUCores = 175921860
)

// CPUCoresInRange reports whether cores, written as a cpu.max quota over a 100 ms period, is a quota the
// kernel accepts.
func CPUCoresInRange(cores float64) bool {
	const periodUS, minQuotaUS, maxQuotaUS = 100000, 1000, 1<<44 - 1
	q := math.Round(cores * periodUS)
	return q >= minQuotaUS && q <= maxQuotaUS
}

var byteUnits = []struct {
	suffix string
	mult   int64
}{
	{"PiB", 1 << 50}, {"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1},
}

// ParseByteSize parses "32GiB", "8MiB", "4096" and the like. Negative values, decimal suffixes,
// fractions and overflow are errors wrapping ErrUnit.
func ParseByteSize(s string) (ByteSize, error) {
	text := strings.TrimSpace(s)
	if text == "" {
		return 0, fmt.Errorf("%w: empty byte size", ErrUnit)
	}
	mult := int64(1)
	digits := text
	for _, u := range byteUnits {
		if strings.HasSuffix(text, u.suffix) {
			mult, digits = u.mult, strings.TrimSpace(strings.TrimSuffix(text, u.suffix))
			break
		}
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || strings.HasPrefix(digits, "+") {
		return 0, fmt.Errorf("%w: %q is not an integer with an IEC suffix (B, KiB, MiB, GiB, TiB)", ErrUnit, s)
	}
	if n < 0 {
		return 0, fmt.Errorf("%w: %q is negative", ErrUnit, s)
	}
	if n > math.MaxInt64/mult {
		return 0, fmt.Errorf("%w: %q overflows", ErrUnit, s)
	}
	return ByteSize(n * mult), nil
}

// String renders the size with the largest IEC suffix that divides it exactly.
func (b ByteSize) String() string {
	if b < 0 {
		return strconv.FormatInt(int64(b), 10)
	}
	for _, u := range byteUnits[:len(byteUnits)-1] {
		if b != 0 && int64(b)%u.mult == 0 {
			return strconv.FormatInt(int64(b)/u.mult, 10) + u.suffix
		}
	}
	return strconv.FormatInt(int64(b), 10)
}

// UnmarshalYAML parses a scalar node through ParseByteSize.
func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("%w: byte size must be a scalar", ErrUnit)
	}
	v, err := ParseByteSize(n.Value)
	if err != nil {
		return err
	}
	*b = v
	return nil
}

// IsPowerOfTwo reports whether b is a positive power of two.
func (b ByteSize) IsPowerOfTwo() bool { return b > 0 && b&(b-1) == 0 }

// day is the length of the d suffix.
const day = 24 * time.Hour

// ParseDuration parses a duration with an optional leading day component: "30d", "1d12h", "10s",
// "5m", "0s", "1h30m". The rest follows time.ParseDuration. Negative durations are errors.
func ParseDuration(s string) (time.Duration, error) {
	text := strings.TrimSpace(s)
	if text == "" {
		return 0, fmt.Errorf("%w: empty duration", ErrUnit)
	}
	var days int64
	rest := text
	if i := strings.IndexByte(text, 'd'); i >= 0 {
		n, err := strconv.ParseInt(text[:i], 10, 64)
		if err != nil || n < 0 || n > math.MaxInt64/int64(day) {
			return 0, fmt.Errorf("%w: %q is not a duration (use d, h, m, s, ms)", ErrUnit, s)
		}
		days, rest = n, text[i+1:]
	}
	var d time.Duration
	if rest != "" {
		var err error
		d, err = time.ParseDuration(rest)
		if err != nil {
			return 0, fmt.Errorf("%w: %q is not a duration (use d, h, m, s, ms)", ErrUnit, s)
		}
	}
	if d < 0 {
		return 0, fmt.Errorf("%w: %q is negative", ErrUnit, s)
	}
	total := time.Duration(days) * day
	if total > math.MaxInt64-d {
		return 0, fmt.Errorf("%w: %q overflows", ErrUnit, s)
	}
	return total + d, nil
}

// FormatDuration renders d compactly: whole days as "Nd", then hours, minutes, seconds and
// milliseconds, omitting zero components ("30d", "1d12h", "10s", "0s").
func FormatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	var b strings.Builder
	if days := d / day; days > 0 {
		b.WriteString(strconv.FormatInt(int64(days), 10) + "d")
		d -= days * day
	}
	if h := d / time.Hour; h > 0 {
		b.WriteString(strconv.FormatInt(int64(h), 10) + "h")
		d -= h * time.Hour
	}
	if m := d / time.Minute; m > 0 {
		b.WriteString(strconv.FormatInt(int64(m), 10) + "m")
		d -= m * time.Minute
	}
	if d > 0 {
		if d%time.Second == 0 {
			b.WriteString(strconv.FormatInt(int64(d/time.Second), 10) + "s")
		} else {
			b.WriteString(d.String())
		}
	}
	return b.String()
}
