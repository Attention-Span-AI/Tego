// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"sort"
	"strings"
	"testing"
	"time"
)

var testHost = HostID([]byte("0123456789abcdef0123456789abcdef\n"))

// Shape, host8 and time36 (R1, R2).
func TestNewRunIDShape(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	id, err := NewRunID(testHost, now, bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff}))
	if err != nil {
		t.Fatal(err)
	}
	if !id.Valid() {
		t.Fatalf("id %q not valid", id)
	}
	parts := strings.Split(string(id), "-")
	if len(parts) != 4 || parts[0] != "r" {
		t.Fatalf("unexpected parts %v", parts)
	}
	if got, want := parts[1], id.Host8(); got != want || len(got) != 8 {
		t.Errorf("host8 = %q, Host8() = %q", got, want)
	}
	if len(parts[2]) != 13 {
		t.Errorf("time36 width = %d, want 13", len(parts[2]))
	}
	// 0xffffffff >> 2 = 0x3fffffff = 30 one-bits -> six 'z'.
	if parts[3] != "zzzzzz" {
		t.Errorf("rand6 = %q, want zzzzzz", parts[3])
	}
	if slug := id.Slug(); strings.Contains(slug, "-") || len(slug) != len(id)-3 {
		t.Errorf("slug %q", slug)
	}
}

// Rand6 drops exactly the low two bits (R1) and pads high zeros.
func TestNewRunIDRand6(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{"zero", []byte{0, 0, 0, 0}, "000000"},
		{"low two bits dropped", []byte{0, 0, 0, 3}, "000000"},
		{"bit 2 is the lowest kept", []byte{0, 0, 0, 4}, "000001"},
		{"all ones", []byte{0xff, 0xff, 0xff, 0xff}, "zzzzzz"},
		{"top char", []byte{0x80, 0, 0, 0}, "g00000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := NewRunID(testHost, time.Unix(1, 0), bytes.NewReader(tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			if got := string(id)[len(id)-6:]; got != tc.want {
				t.Errorf("rand6 = %q, want %q", got, tc.want)
			}
		})
	}
}

// Errors from rnd are wrapped, never a partial id (E1); pre-epoch time is refused.
// identity-config.md E32: a pre-epoch now is the named error and no id, after reading rnd.
// identity-config.md E1: a failed or short rnd read is the wrapped error and no id, never a short or zero-padded one.
func TestNewRunIDErrors(t *testing.T) {
	short := bytes.NewReader([]byte{1, 2})
	if id, err := NewRunID(testHost, time.Unix(1, 0), short); err == nil || id != "" {
		t.Fatalf("short read: id=%q err=%v", id, err)
	}
	boom := errors.New("boom")
	if _, err := NewRunID(testHost, time.Unix(1, 0), failingReader{boom}); !errors.Is(err, boom) {
		t.Fatalf("error not wrapped: %v", err)
	}
	rnd := bytes.NewReader(make([]byte, 16))
	id, err := NewRunID(testHost, time.Unix(-1, 0), rnd)
	if err == nil || id != "" || !strings.Contains(err.Error(), "before the Unix epoch") {
		t.Fatalf("pre-epoch time: id=%q err=%v", id, err)
	}
	if rnd.Len() == 16 {
		t.Error("rnd not read before the pre-epoch refusal")
	}
}

type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) { return 0, f.err }

// I2 / E24: ids are unique and sort by mint time on one host.
// identity-config.md I2: every generated id satisfies Valid (E24 uniqueness at scale).
func TestNewRunIDUniqueAndSortable(t *testing.T) {
	n := 1_000_000
	if testing.Short() {
		n = 50_000
	}
	seen := make(map[RunID]struct{}, n)
	ids := make([]string, 0, n)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		id, err := NewRunID(testHost, base.Add(time.Duration(i)*time.Microsecond), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if !id.Valid() {
			t.Fatalf("invalid id %q", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = struct{}{}
		ids = append(ids, string(id))
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatal("ids minted at increasing times are not sorted")
	}
}

// identity-config.md R2: Valid matches the run-id pattern exactly.
func TestRunIDValid(t *testing.T) {
	cases := []struct {
		id   RunID
		want bool
	}{
		{"r-0123abcd-0000000000000-abcdef", true},
		{"r-0123abcd-0000000000000-abcde", false},
		{"r-0123ABCD-0000000000000-abcdef", false},
		{"x-0123abcd-0000000000000-abcdef", false},
		{"", false},
		{"r-0123abcd-0000000000000-abcdef\n", false},
	}
	for _, tc := range cases {
		if got := tc.id.Valid(); got != tc.want {
			t.Errorf("%q.Valid() = %v, want %v", tc.id, got, tc.want)
		}
	}
	if RunID("nope").Host8() != "" {
		t.Error("Host8 of an invalid id must be empty")
	}
}

// T-slug-1.
// identity-config.md R2: RunSlug strips every dash.
func TestRunSlug(t *testing.T) {
	if got := RunSlug("r-aa-bb-cc"); got != "raabbcc" {
		t.Errorf("RunSlug = %q", got)
	}
}

func TestHostID(t *testing.T) {
	a := HostID([]byte("abc\n"))
	b := HostID([]byte("abc"))
	c := HostID([]byte("abd"))
	if a != b {
		t.Error("trailing newline changed the digest")
	}
	if a == c {
		t.Error("different ids hashed equal")
	}
}

// Pid reuse yields distinct exec ids (E30 within one pid namespace).
// identity-config.md E30: the exec id keys on run, pid and start time within one pid namespace only.
func TestNewExecID(t *testing.T) {
	run := RunID("r-0123abcd-0000000000000-abcdef")
	cases := []struct {
		pid   int
		start uint64
		want  ExecID
	}{
		{42, 1000, "r-0123abcd-0000000000000-abcdef/42/1000"},
		{42, 2000, "r-0123abcd-0000000000000-abcdef/42/2000"},
		{1, 0, "r-0123abcd-0000000000000-abcdef/1/0"},
	}
	for _, tc := range cases {
		if got := NewExecID(run, tc.pid, tc.start); got != tc.want {
			t.Errorf("NewExecID(%d,%d) = %q, want %q", tc.pid, tc.start, got, tc.want)
		}
	}
	if NewExecID(run, 42, 1000) == NewExecID(run, 42, 2000) {
		t.Error("pid reuse not disambiguated")
	}
}

func TestParseAgentID(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{"retriever", true},
		{"a", true},
		{strings.Repeat("a", 40), true},
		{strings.Repeat("a", 41), false},
		{"", false},
		{"Upper", false},
		{"has_underscore", false},
		{"has.dot", false},
	}
	for _, tc := range cases {
		id, err := ParseAgentID(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("ParseAgentID(%q) err=%v, want ok=%v", tc.in, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrAgentID) {
			t.Errorf("error not wrapping ErrAgentID: %v", err)
		}
		if tc.ok && id.String() != tc.in {
			t.Errorf("id = %q", id)
		}
	}
}

func BenchmarkNewRunID(b *testing.B) {
	now := time.Now()
	rnd := bytes.NewReader(bytes.Repeat([]byte{7}, 4*b.N+4))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := NewRunID(testHost, now, rnd); err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			b.Fatal(err)
		}
	}
}

// TestNewRunIDSharedMachineIDCollidesOnHost8Only is identity-config.md E3: two hosts cloned from one image
// hash the same machine-id, so their host8 is the same, and only rand6 (and the clock) tells their ids apart.
func TestNewRunIDSharedMachineIDCollidesOnHost8Only(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	a, err := NewRunID(testHost, now, bytes.NewReader([]byte{1, 2, 3, 4}))
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewRunID(testHost, now, bytes.NewReader([]byte{9, 8, 7, 6}))
	if err != nil {
		t.Fatal(err)
	}
	if a.Host8() != b.Host8() {
		t.Errorf("host8 %q vs %q: the same machine-id must give the same host8", a.Host8(), b.Host8())
	}
	if a == b {
		t.Error("two hosts sharing a machine-id minted the same id in the same tick: rand6 must tell them apart")
	}
}
