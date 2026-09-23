// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"testing"
	"time"
)

func TestParseByteSize(t *testing.T) {
	tests := []struct {
		in      string
		want    ByteSize
		wantErr bool
		decimal bool
	}{
		{in: "0", want: 0},
		{in: "7", want: 7},
		{in: "7B", want: 7},
		{in: "8KiB", want: 8 << 10},
		{in: "8 MiB", want: 8 << 20},
		{in: "8GiB", want: 8 << 30},
		{in: "2TiB", want: 2 << 40},
		{in: "8GB", wantErr: true, decimal: true},
		{in: "8gb", wantErr: true, decimal: true},
		{in: "8M", wantErr: true, decimal: true},
		{in: "8Gi", wantErr: true},
		{in: "eight", wantErr: true},
		{in: "-1", wantErr: true},
		{in: "99999999999999999999", wantErr: true},
		{in: "9000000000TiB", wantErr: true},
	}
	for _, tc := range tests {
		got, err := ParseByteSize(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseByteSize(%q) err=%v want error %v", tc.in, err, tc.wantErr)
			continue
		}
		if tc.decimal && !errors.Is(err, ErrDecimalUnit) {
			t.Errorf("ParseByteSize(%q): want ErrDecimalUnit, got %v", tc.in, err)
		}
		if err == nil && got != tc.want {
			t.Errorf("ParseByteSize(%q)=%d want %d", tc.in, got, tc.want)
		}
	}
}

func TestByteSizeString(t *testing.T) {
	tests := []struct {
		in   ByteSize
		want string
	}{
		{0, "0B"}, {7, "7B"}, {1 << 10, "1KiB"}, {1536 << 10, "1536KiB"}, {8 << 30, "8GiB"}, {3 << 40, "3TiB"},
	}
	for _, tc := range tests {
		if got := tc.in.String(); got != tc.want {
			t.Errorf("%d.String()=%q want %q", tc.in, got, tc.want)
		}
		back, err := ParseByteSize(tc.want)
		if err != nil || back != tc.in {
			t.Errorf("round trip %q: %v %d", tc.want, err, back)
		}
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{in: "500ms", want: 500 * time.Millisecond},
		{in: "10s", want: 10 * time.Second},
		{in: "10m", want: 10 * time.Minute},
		{in: "2h", want: 2 * time.Hour},
		{in: "3d", want: 72 * time.Hour},
		{in: "2 hours", wantErr: true},
		{in: "1h30m", wantErr: true},
		{in: "", wantErr: true},
		{in: "-1s", wantErr: true},
		{in: "99999999999999999999s", wantErr: true},
		{in: "9999999999999d", wantErr: true},
	}
	for _, tc := range tests {
		got, err := ParseDuration(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseDuration(%q) err=%v want error %v", tc.in, err, tc.wantErr)
			continue
		}
		if err == nil && time.Duration(got) != tc.want {
			t.Errorf("ParseDuration(%q)=%v want %v", tc.in, time.Duration(got), tc.want)
		}
	}
	for _, s := range []string{"500ms", "90m", "2h", "3d", "45s"} {
		d, _ := ParseDuration(s)
		if d.String() != s {
			t.Errorf("Duration(%s).String()=%q", s, d.String())
		}
	}
}

func TestParseCPUCores(t *testing.T) {
	tests := []struct {
		in      string
		wantErr bool
		quota   int64
	}{
		{"2", false, 200000}, {"2.0", false, 200000}, {"0.5", false, 50000}, {"0.25", false, 25000},
		{"1.014", false, 101400},
		{"0", true, 0}, {"two", true, 0}, {"-1", true, 0}, {"1e3", true, 0}, {"", true, 0},
		// cpu.max takes a quota of 1 ms to 2^44-1 µs a 100 ms period: below or above it
		// every run of the contract failed at start with EINVAL.
		{"0.01", false, 1000}, {"0.009", true, 0}, {"0.001", true, 0},
		{"175921860", false, 17592186000000}, {"175921861", true, 0}, {"999999999", true, 0},
	}
	for _, tc := range tests {
		got, err := ParseCPUCores(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseCPUCores(%q) err=%v", tc.in, err)
			continue
		}
		if err == nil && got.Quota() != tc.quota {
			t.Errorf("ParseCPUCores(%q).Quota()=%d want %d", tc.in, got.Quota(), tc.quota)
		}
	}
	if CPUCores("").Quota() != 0 || CPUCores("x").Quota() != 0 {
		t.Error("invalid cores must yield a 0 quota")
	}
}
