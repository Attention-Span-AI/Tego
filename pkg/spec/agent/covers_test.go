// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"slices"
	"testing"
)

// TestCovers pins the one containment test Evaluate, the runtime's run-directory check and the recorder's fs
// index share. The three copies it replaced disagreed on an empty entry and a trailing slash; a ledger root
// under /work/out must be covered by that write entry, and one under /work/outside must not.
func TestCovers(t *testing.T) {
	for _, tc := range []struct {
		entry, path string
		want        bool
	}{
		// empty
		{"", "/x", false},
		{"", "", false},
		{"/", "", false},
		// the root
		{"/", "/", true},
		{"/", "/anything", true},
		{"/", "/a/b/c", true},
		// itself and beneath, on whole components
		{"/work", "/work", true},
		{"/work", "/work/a", true},
		{"/work", "/work/a/b", true},
		{"/work/a", "/work", false},
		{"/work/out", "/work/out/runs/r-1", true},
		// a trailing slash on the entry changes nothing
		{"/work/", "/work", true},
		{"/work/", "/work/a", true},
		{"/work/", "/workshop", false},
		{"/a/", "/a/b", true},
		// a prefix that is not a component
		{"/work", "/work-secret", false},
		{"/work", "/work-secret/x", false},
		{"/work", "/workshop", false},
		{"/work", "/wor", false},
		{"/a", "/ab", false},
		{"/work/out", "/work/outside/runs/r-1", false},
	} {
		if got := Covers(tc.entry, tc.path); got != tc.want {
			t.Errorf("Covers(%q, %q) = %v, want %v", tc.entry, tc.path, got, tc.want)
		}
	}
	if n := testing.AllocsPerRun(100, func() { _ = Covers("/work/out", "/work/out/runs/r-1") }); n != 0 {
		t.Errorf("Covers allocated %v times on a clean entry, want 0: the recorder's drain asks it per event", n)
	}
}

// TestSpellings: a rule is matched under its declared path and, when it resolves elsewhere, its resolved one,
// each cleaned; Canonical is the resolved one when there is one.
func TestSpellings(t *testing.T) {
	for _, tc := range []struct {
		r             FSRule
		want          []string
		wantCanonical string
	}{
		{FSRule{Path: "/work"}, []string{"/work"}, "/work"},
		{FSRule{Path: "/work/", Resolved: "/work"}, []string{"/work"}, "/work"},
		{FSRule{Path: "/home/u/link", Resolved: "/data/target/"}, []string{"/home/u/link", "/data/target"}, "/data/target"},
		{FSRule{Path: "/a/./b", Resolved: ""}, []string{"/a/b"}, "/a/b"},
	} {
		if got := tc.r.Spellings(); !slices.Equal(got, tc.want) {
			t.Errorf("%+v.Spellings() = %q, want %q", tc.r, got, tc.want)
		}
		if got := tc.r.Canonical(); got != tc.wantCanonical {
			t.Errorf("%+v.Canonical() = %q, want %q", tc.r, got, tc.wantCanonical)
		}
	}
	if got := Spellings("/usr/bin/python3", "/usr/bin/python3.12"); !slices.Equal(got, []string{"/usr/bin/python3", "/usr/bin/python3.12"}) {
		t.Errorf("Spellings of a linked binary = %q", got)
	}
}
