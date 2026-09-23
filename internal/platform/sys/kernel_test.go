// SPDX-License-Identifier: Apache-2.0

package sys

import "testing"

func TestParseKernelRelease(t *testing.T) {
	tests := []struct {
		in        string
		want      KernelVersion
		err       bool
		roundTrip bool // String() reproduces the input (only full a.b.c releases do)
	}{
		{"6.17.0-41-generic", KernelVersion{6, 17, 0, "-41-generic"}, false, true},
		{"5.14.0", KernelVersion{5, 14, 0, ""}, false, true},
		{"7.0-rc3", KernelVersion{7, 0, 0, "-rc3"}, false, false},
		{"6.1", KernelVersion{6, 1, 0, ""}, false, false},
		{"6", KernelVersion{6, 0, 0, ""}, false, false},
		{"6.8.0-1015-aws", KernelVersion{6, 8, 0, "-1015-aws"}, false, true},
		{"5.15.167.4-microsoft-standard-WSL2", KernelVersion{5, 15, 167, ".4-microsoft-standard-WSL2"}, false, true},
		{"", KernelVersion{}, true, false},
		{"abc", KernelVersion{}, true, false},
		{"6.x", KernelVersion{6, 0, 0, ".x"}, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseKernelRelease(tc.in)
			if (err != nil) != tc.err {
				t.Fatalf("err = %v, want error %v", err, tc.err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			if tc.roundTrip && got.String() != tc.in {
				t.Fatalf("String() = %q, want %q", got.String(), tc.in)
			}
		})
	}
}

func TestKernelVersionAtLeast(t *testing.T) {
	v := KernelVersion{Major: 6, Minor: 1, Patch: 9}
	tests := []struct {
		major, minor int
		want         bool
	}{
		{6, 1, true}, {6, 0, true}, {5, 19, true}, {6, 2, false}, {7, 0, false},
	}
	for _, tc := range tests {
		if got := v.AtLeast(tc.major, tc.minor); got != tc.want {
			t.Errorf("AtLeast(%d,%d) = %v, want %v", tc.major, tc.minor, got, tc.want)
		}
	}
}

func TestKernel(t *testing.T) {
	v, err := Kernel()
	if err != nil {
		t.Fatal(err)
	}
	if !v.AtLeast(5, 0) {
		t.Fatalf("running kernel %s parsed below 5.0", v)
	}
}
