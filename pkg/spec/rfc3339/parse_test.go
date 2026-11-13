// SPDX-License-Identifier: Apache-2.0

package rfc3339

import (
	"errors"
	"testing"
	"time"
)

// TestParseRejects holds the profile's refusals, including forms time.Parse(time.RFC3339Nano)
// accepts: a comma fraction, a one-digit hour, offset hour 24 and offset minute 60 (ADR 0146).
func TestParseRejects(t *testing.T) {
	for name, s := range map[string]string{
		"comma fraction":           "2026-09-22T09:00:00,002Z",
		"one-digit hour":           "2026-09-22T9:00:00.002Z",
		"one-digit minute":         "2026-09-22T09:0:00Z",
		"one-digit day":            "2026-09-2T09:00:00Z",
		"missing seconds":          "2026-09-22T09:00Z",
		"lower-case t":             "2026-09-22t09:00:00Z",
		"lower-case z":             "2026-09-22T09:00:00z",
		"space for T":              "2026-09-22 09:00:00Z",
		"leap second":              "2026-12-31T23:59:60Z",
		"no zone":                  "2026-09-22T09:00:00",
		"empty fraction":           "2026-09-22T09:00:00.Z",
		"offset without colon":     "2026-09-22T09:00:00+0100",
		"offset hour 24":           "2026-09-22T09:00:00+24:00",
		"offset minute 60":         "2026-09-22T09:00:00+01:60",
		"hour 24":                  "2026-09-22T24:00:00Z",
		"29 February, common year": "2026-02-29T09:00:00Z",
		"31 September":             "2026-09-31T09:00:00Z",
		"month 13":                 "2026-13-01T09:00:00Z",
		"five-digit year":          "12026-09-22T09:00:00Z",
		"signed year":              "+2026-09-22T09:00:00Z",
		"trailing text":            "2026-09-22T09:00:00Zx",
		"leading space":            " 2026-09-22T09:00:00Z",
		"empty":                    "",
	} {
		if _, err := Parse(s); !errors.Is(err, ErrNotRFC3339) {
			t.Errorf("%s: Parse(%q) = %v, want ErrNotRFC3339", name, s, err)
		}
	}
}

// TestParseReads holds what the profile reads, and that it reads what time.RFC3339Nano writes in UTC, the format every
// Tego writer uses, across the clock's whole range and the fraction's lengths.
func TestParseReads(t *testing.T) {
	for _, s := range []string{
		"2026-09-22T09:00:00.001Z", "2026-09-22T09:00:00Z", "2024-02-29T23:59:59.123456789123Z",
		"2000-02-29T00:00:00+05:30", "0000-01-01T00:00:00-23:59", "2026-09-22T11:00:00.002+02:00",
	} {
		if _, err := Parse(s); err != nil {
			t.Errorf("Parse(%q): %v", s, err)
		}
	}
	for _, at := range []time.Time{
		time.Unix(0, 0), time.Unix(0, 1), time.Unix(1_700_000_000, 120_000_000), time.Date(2262, 4, 11, 23, 47, 16, 854775807, time.UTC),
		{}, time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC),
	} {
		s := at.UTC().Format(time.RFC3339Nano)
		got, err := Parse(s)
		if err != nil || !got.Equal(at) {
			t.Errorf("Parse(%q) = %v, %v; want %v", s, got, err, at)
		}
	}
}

// TestParseDoesNotConsultLocal makes a matching host location visible. A numeric offset must
// keep its instant and offset without acquiring that location or initializing the host timezone.
func TestParseDoesNotConsultLocal(t *testing.T) {
	original := time.Local
	t.Cleanup(func() { time.Local = original })
	for _, tc := range []struct {
		stamp  string
		offset int
	}{
		{"2026-09-22T09:00:00+01:00", 60 * 60},
		{"2026-09-22T09:00:00-07:30", -(7*60 + 30) * 60},
		{"2026-09-22T09:00:00+00:00", 0},
		{"2026-09-22T09:00:00-00:00", 0},
	} {
		t.Run(tc.stamp, func(t *testing.T) {
			time.Local = time.FixedZone("host-location-must-not-be-used", tc.offset)
			got, err := Parse(tc.stamp)
			if err != nil {
				t.Fatal(err)
			}
			if got.Location() == time.Local {
				t.Fatal("numeric offset consulted time.Local")
			}
			_, offset := got.Zone()
			if offset != tc.offset {
				t.Fatalf("offset = %d, want %d", offset, tc.offset)
			}
			want := time.Date(2026, 9, 22, 9, 0, 0, 0, time.FixedZone("", tc.offset))
			if !got.Equal(want) {
				t.Fatalf("instant = %v, want %v", got, want)
			}
		})
	}
}

// FuzzParseIsTimeParseNarrowed: whatever Parse reads, time.Parse(time.RFC3339Nano) reads too, as the same instant, so
// the profile only ever narrows what the reader took before.
func FuzzParseIsTimeParseNarrowed(f *testing.F) {
	for _, s := range []string{"2026-09-22T09:00:00.001Z", "2026-09-22T09:00:00,002Z", "2000-02-29T00:00:00+05:30"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := Parse(s)
		if err != nil {
			return
		}
		want, werr := time.Parse(time.RFC3339Nano, s)
		if werr != nil || !got.Equal(want) {
			t.Errorf("Parse(%q) = %v; time.Parse = %v, %v", s, got, want, werr)
		}
	})
}
