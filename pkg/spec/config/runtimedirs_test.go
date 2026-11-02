// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"slices"
	"strconv"
	"testing"
)

// TestRuntimeDirBases is R10a's list of the parents every compile and every launch protects: the invoking user's
// logind directory whatever the environment says, then XDG_RUNTIME_DIR, cleaned, when it is absolute and names
// another. The list is lexical, so the paths need not exist.
func TestRuntimeDirBases(t *testing.T) {
	uid, _ := InvokingUID()
	const root, other = "/test-logind", "/elsewhere/xdg"
	logind := filepath.Join(root, strconv.Itoa(uid))
	for _, tc := range []struct {
		xdg  string
		want []string
	}{
		{"", []string{logind}},
		{"relative/dir", []string{logind}},
		{logind, []string{logind}},
		{logind + "/", []string{logind}},
		{other, []string{logind, other}},
		{other + "/./", []string{logind, other}},
	} {
		t.Setenv("XDG_RUNTIME_DIR", tc.xdg)
		if got := RuntimeDirBasesUnder(root); !slices.Equal(got, tc.want) {
			t.Errorf("XDG_RUNTIME_DIR=%q: RuntimeDirBasesUnder(%q) = %q, want %q", tc.xdg, root, got, tc.want)
		}
	}
	t.Setenv("XDG_RUNTIME_DIR", other)
	if got, want := RuntimeDirBases(), []string{filepath.Join(LogindRuntimeRoot, strconv.Itoa(uid)), other}; !slices.Equal(got, want) {
		t.Errorf("RuntimeDirBases() = %q, want %q", got, want)
	}
}
