// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"strings"
	"testing"
)

func TestParseKernelRelease(t *testing.T) {
	tests := []struct {
		in      string
		want    Version
		wantErr bool
	}{
		{"6.17.0-41-generic", Version{6, 17, 0}, false},
		{"5.15.0", Version{5, 15, 0}, false},
		{"5.14", Version{5, 14, 0}, false},
		{"6.1.0-rc3+", Version{6, 1, 0}, false},
		{"4.19.283-1-amd64", Version{4, 19, 283}, false},
		{"", Version{}, true},
		{"6", Version{}, true},
		{"x.y", Version{}, true},
		{"6..1", Version{}, true},
		{"6.1.x", Version{6, 1, 0}, false},
		{"9999999999.1", Version{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseKernelRelease(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, ErrRelease) {
				t.Fatalf("does not wrap ErrRelease: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestAtLeast(t *testing.T) {
	tests := []struct {
		v, o Version
		want bool
	}{
		{Version{5, 14, 0}, MinKernel, true},
		{Version{5, 13, 99}, MinKernel, false},
		{Version{6, 0, 0}, MinKernel, true},
		{Version{4, 20, 0}, MinKernel, false},
		{Version{5, 14, 1}, Version{5, 14, 2}, false},
	}
	for _, tc := range tests {
		if got := tc.v.AtLeast(tc.o); got != tc.want {
			t.Errorf("%v.AtLeast(%v) = %v", tc.v, tc.o, got)
		}
	}
	if MinKernel.String() != "5.14.0" {
		t.Fatal(MinKernel.String())
	}
}

func FuzzParseKernelRelease(f *testing.F) {
	f.Add("6.17.0-41-generic")
	f.Add("")
	f.Add("1.2.3.4.5")
	f.Add("06.017-rc1+")
	f.Add("999999999.0.1")
	// A release that parses has three non-negative numbers and reads back from its own String as itself; one
	// that does not is ErrRelease (this target checked nothing).
	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParseKernelRelease(s)
		if err != nil {
			if !errors.Is(err, ErrRelease) {
				t.Fatalf("ParseKernelRelease(%q) = %v, which is not ErrRelease", s, err)
			}
			return
		}
		if v.Major < 0 || v.Minor < 0 || v.Patch < 0 {
			t.Fatalf("ParseKernelRelease(%q) = %+v", s, v)
		}
		if again, err := ParseKernelRelease(v.String()); err != nil || again != v {
			t.Fatalf("ParseKernelRelease(%q) = %v, whose String reads back as %v, %v", s, v, again, err)
		}
	})
}

// TestMechanismsListOnlyWhatThisBinaryUses: D1 tells an older kernel what it lacks, so a row for a
// feature nothing here uses is a false finding. FAN_DENY_ERRNO was such a row ("6.13, a tier-2
// refusal is a coarse EPERM"): the kernel takes a reply errno only from a FAN_CLASS_PRE_CONTENT group
// and never EACCES, and tier 2's FAN_CLASS_CONTENT listener sends the bare FAN_DENY on every kernel
// (docs/p0/enforce-cgroup-observe.md §6 E2), so no release gains or loses anything by it.
func TestMechanismsListOnlyWhatThisBinaryUses(t *testing.T) {
	for _, m := range MissingMechanisms(Version{5, 14, 0}) {
		if strings.Contains(m.Name, "FAN_DENY_ERRNO") {
			t.Errorf("D1 reports %s (%s) missing on 5.14, a feature no part of tego uses", m.Name, m.Since)
		}
	}
}
