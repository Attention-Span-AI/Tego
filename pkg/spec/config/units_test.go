// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestParseByteSize(t *testing.T) {
	cases := []struct {
		in   string
		want ByteSize
		ok   bool
	}{
		{"0", 0, true},
		{"4096", 4096, true},
		{"8MiB", 8 << 20, true},
		{"32GiB", 32 << 30, true},
		{"1KiB", 1024, true},
		{"2TiB", 2 << 40, true},
		{"1PiB", 1 << 50, true},
		{"512B", 512, true},
		{" 8MiB ", 8 << 20, true},
		{"8GB", 0, false},
		{"8MB", 0, false},
		{"8 MiB", 8 << 20, true},
		{"-1", 0, false},
		{"-1MiB", 0, false},
		{"1.5GiB", 0, false},
		{"", 0, false},
		{"MiB", 0, false},
		{"+5", 0, false},
		{"99999999999999999999", 0, false},
		{"9000000PiB", 0, false},
	}
	for _, tc := range cases {
		got, err := ParseByteSize(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("ParseByteSize(%q) = %d, %v; want %d ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrUnit) {
			t.Errorf("ParseByteSize(%q): error does not wrap ErrUnit", tc.in)
		}
	}
}

func TestByteSizeString(t *testing.T) {
	cases := []struct {
		in   ByteSize
		want string
	}{
		{0, "0"}, {4096, "4KiB"}, {8 << 20, "8MiB"}, {32 << 30, "32GiB"}, {1536, "1536"}, {3 << 40, "3TiB"}, {-5, "-5"},
	}
	for _, tc := range cases {
		if got := tc.in.String(); got != tc.want {
			t.Errorf("%d.String() = %q, want %q", tc.in, got, tc.want)
		}
		if tc.in >= 0 {
			back, err := ParseByteSize(tc.want)
			if err != nil || back != tc.in {
				t.Errorf("round trip %q -> %d, %v", tc.want, back, err)
			}
		}
	}
	if !ByteSize(8<<20).IsPowerOfTwo() || ByteSize(3<<20).IsPowerOfTwo() || ByteSize(0).IsPowerOfTwo() {
		t.Error("IsPowerOfTwo")
	}
}

func TestByteSizeYAML(t *testing.T) {
	var v struct {
		Size ByteSize `yaml:"size"`
	}
	if err := yaml.Unmarshal([]byte("size: 8MiB"), &v); err != nil || v.Size != 8<<20 {
		t.Errorf("unmarshal: %d, %v", v.Size, err)
	}
	if err := yaml.Unmarshal([]byte("size: [1]"), &v); err == nil {
		t.Error("sequence accepted as byte size")
	}
	if err := yaml.Unmarshal([]byte("size: 8GB"), &v); err == nil {
		t.Error("decimal suffix accepted")
	}
}

func TestParseDuration(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"30d", 30 * day, true},
		{"1d12h", 36 * time.Hour, true},
		{"10s", 10 * time.Second, true},
		{"5m", 5 * time.Minute, true},
		{"24h", 24 * time.Hour, true},
		{"0s", 0, true},
		{"1h30m", 90 * time.Minute, true},
		{"250ms", 250 * time.Millisecond, true},
		{"0d", 0, true},
		{"", 0, false},
		{"d", 0, false},
		{"-1s", 0, false},
		{"-1d", 0, false},
		{"1w", 0, false},
		{"10", 0, false},
		{"1d1d", 0, false},
		{"99999999999999d", 0, false},
	}
	for _, tc := range cases {
		got, err := ParseDuration(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{30 * day, "30d"}, {36 * time.Hour, "1d12h"}, {10 * time.Second, "10s"}, {5 * time.Minute, "5m"},
		{0, "0s"}, {90 * time.Minute, "1h30m"}, {1500 * time.Millisecond, "1.5s"}, {-time.Second, "0s"},
		{day + time.Second, "1d1s"},
	}
	for _, tc := range cases {
		if got := FormatDuration(tc.in); got != tc.want {
			t.Errorf("FormatDuration(%v) = %q, want %q", tc.in, got, tc.want)
		}
		if tc.in >= 0 {
			if back, err := ParseDuration(tc.want); err != nil || back != tc.in {
				t.Errorf("round trip %q -> %v, %v", tc.want, back, err)
			}
		}
	}
}

func FuzzByteSize(f *testing.F) {
	for _, s := range []string{"8MiB", "32GiB", "0", "-1", "8GB", "", "1PiB", "9223372036854775807"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParseByteSize(s)
		if err != nil {
			return
		}
		if v < 0 {
			t.Fatalf("negative size %d from %q", v, s)
		}
		back, err := ParseByteSize(v.String())
		if err != nil || back != v {
			t.Fatalf("round trip %q -> %q -> %d, %v", s, v.String(), back, err)
		}
	})
}

func FuzzDuration(f *testing.F) {
	for _, s := range []string{"30d", "1d12h", "10s", "-1s", "", "1w", "99999999999999d"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, err := ParseDuration(s)
		if err != nil {
			return
		}
		if d < 0 {
			t.Fatalf("negative duration %v from %q", d, s)
		}
		if back, err := ParseDuration(FormatDuration(d)); err != nil || back != d {
			t.Fatalf("round trip %q -> %q -> %v, %v", s, FormatDuration(d), back, err)
		}
	})
}
