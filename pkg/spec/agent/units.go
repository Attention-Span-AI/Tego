// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// CPUCores is a cores count such as "2" or "2.0", the numerator of cgroup
// cpu.max. It stays a string so that "2.0" and "2" hash differently only when
// the author wrote them differently (Canonical is a re-serialization, not a
// normalization).
type CPUCores string

var cpuCoresRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

// ParseCPUCores validates a cores string against ^[0-9]+(\.[0-9]+)?$ and
// rejects zero and any count outside the range cpu.max takes.
func ParseCPUCores(s string) (CPUCores, error) {
	if !cpuCoresRE.MatchString(s) {
		return "", fmt.Errorf("cpu %q: want a decimal cores count such as \"2\" or \"0.5\"", s)
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f <= 0 || math.IsInf(f, 0) {
		return "", fmt.Errorf("cpu %q: must be greater than zero", s)
	}
	// Below 0.01 cores or above what cpu.max holds, every run of the contract failed at start with
	// EINVAL, exit 125; config.CPUCoresInRange is the kernel's range.
	if !config.CPUCoresInRange(f) {
		return "", fmt.Errorf("cpu %q: must be %v to %v cores, the range the kernel's cpu.max takes", s, config.MinCPUCores, config.MaxCPUCores)
	}
	return CPUCores(s), nil
}

// Quota returns the cores count as the cpu.max quota a run writes, microseconds a 100 ms period
// (round(cores*100000), internal/runtime/cgroup FormatCPUMax): the unit ceilings are compared in (R11),
// so a contract that writes a larger quota than its ceiling is clamped. Hundredths of a core let "1.014"
// pass a 1.01 ceiling and write 101400 over 101000. A zero-value CPUCores yields 0.
func (c CPUCores) Quota() int64 {
	if c == "" {
		return 0
	}
	f, err := strconv.ParseFloat(string(c), 64)
	if err != nil {
		return 0
	}
	return int64(math.Round(f * 100000))
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (c *CPUCores) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseCPUCores(n.Value)
	if err != nil {
		return err
	}
	*c = v
	return nil
}

// MarshalYAML implements yaml.Marshaler; the value is always quoted so that a
// reload sees a string, never a float.
func (c CPUCores) MarshalYAML() (any, error) {
	return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: string(c)}, nil
}

// ByteSize is a byte count. The YAML form is "<n>" or "<n>(B|KiB|MiB|GiB|TiB)",
// IEC only: decimal GB/MB are rejected so that identical-looking contracts never
// mean different byte counts (E33).
type ByteSize int64

var byteSizeRE = regexp.MustCompile(`^([0-9]+)\s*(B|KiB|MiB|GiB|TiB)?$`)

var byteUnits = map[string]int64{
	"":    1,
	"B":   1,
	"KiB": 1 << 10,
	"MiB": 1 << 20,
	"GiB": 1 << 30,
	"TiB": 1 << 40,
}

// ErrDecimalUnit is returned by ParseByteSize for GB/MB/KB/TB spellings.
var ErrDecimalUnit = errors.New("decimal unit")

// ParseByteSize parses an IEC byte size. A decimal unit (GB, MB) is an
// ErrDecimalUnit so the caller can suggest the IEC spelling.
func ParseByteSize(s string) (ByteSize, error) {
	s = strings.TrimSpace(s)
	m := byteSizeRE.FindStringSubmatch(s)
	if m == nil {
		if dec := decimalUnitRE.FindStringSubmatch(s); dec != nil {
			return 0, fmt.Errorf("%w %q: write %s%s", ErrDecimalUnit, s, dec[1], strings.ToUpper(dec[2][:1])+"iB")
		}
		return 0, fmt.Errorf("size %q: want <n> or <n>(B|KiB|MiB|GiB|TiB)", s)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("size %q: %w", s, errOverflow)
	}
	mul := byteUnits[m[2]]
	if n > math.MaxInt64/mul {
		return 0, fmt.Errorf("size %q: %w", s, errOverflow)
	}
	return ByteSize(n * mul), nil
}

var decimalUnitRE = regexp.MustCompile(`^([0-9]+)\s*([kKmMgGtT][bB]?)$`)

var errOverflow = errors.New("overflows int64")

// String renders the size in the largest exact IEC unit ("8GiB", "1536MiB", "7B").
func (b ByteSize) String() string {
	units := []struct {
		name string
		mul  int64
	}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}}
	for _, u := range units {
		if b != 0 && int64(b)%u.mul == 0 {
			return strconv.FormatInt(int64(b)/u.mul, 10) + u.name
		}
	}
	return strconv.FormatInt(int64(b), 10) + "B"
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseByteSize(n.Value)
	if err != nil {
		return err
	}
	*b = v
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (b ByteSize) MarshalYAML() (any, error) { return b.String(), nil }

// Duration is a time span written as "<n>(ms|s|m|h|d)", d = 24h. Only a single
// unit is accepted, so a reload of Canonical() output is byte-stable.
type Duration time.Duration

var durationRE = regexp.MustCompile(`^([0-9]+)(ms|s|m|h|d)$`)

var durationUnits = map[string]time.Duration{
	"ms": time.Millisecond,
	"s":  time.Second,
	"m":  time.Minute,
	"h":  time.Hour,
	"d":  24 * time.Hour,
}

// ParseDuration parses "<n>(ms|s|m|h|d)".
func ParseDuration(s string) (Duration, error) {
	m := durationRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, fmt.Errorf("duration %q: want <n>(ms|s|m|h|d), such as 2h or 10m", s)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("duration %q: %w", s, errOverflow)
	}
	unit := durationUnits[m[2]]
	if n > int64(math.MaxInt64/unit) {
		return 0, fmt.Errorf("duration %q: %w", s, errOverflow)
	}
	return Duration(time.Duration(n) * unit), nil
}

// String renders the duration in the largest exact unit ("2h", "90m", "500ms").
func (d Duration) String() string {
	v := time.Duration(d)
	for _, u := range []struct {
		name string
		unit time.Duration
	}{{"d", 24 * time.Hour}, {"h", time.Hour}, {"m", time.Minute}, {"s", time.Second}} {
		if v != 0 && v%u.unit == 0 {
			return strconv.FormatInt(int64(v/u.unit), 10) + u.name
		}
	}
	return strconv.FormatInt(int64(v/time.Millisecond), 10) + "ms"
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseDuration(n.Value)
	if err != nil {
		return err
	}
	*d = v
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }
