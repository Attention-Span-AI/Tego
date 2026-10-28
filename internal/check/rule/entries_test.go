// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"reflect"
	"slices"
	"testing"
)

// TestEntries: every list an edit may change is listed in file order with the entries the file spells; a list the file
// lacks is absent, a non-string entry is not offered, and text that is not a mapping is an error.
func TestEntries(t *testing.T) {
	got, err := Entries([]byte(editBase))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"./out/"}; !reflect.DeepEqual(got["fs.write"], want) {
		t.Errorf("fs.write = %q, want %q", got["fs.write"], want)
	}
	if want := []string{"api.example.com:443"}; !reflect.DeepEqual(got["net.allow"], want) {
		t.Errorf("net.allow = %q, want %q", got["net.allow"], want)
	}
	for k := range got {
		if !slices.Contains(EditKeys(), k) {
			t.Errorf("Entries lists %q, not a key an edit may change", k)
		}
	}
	got, err = Entries([]byte("version: 0\nexec:\n  allow: [git, 12, \"ls\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"git", "ls"}; !reflect.DeepEqual(got["exec.allow"], want) {
		t.Errorf("exec.allow = %q, want %q (a number is no entry a form can name)", got["exec.allow"], want)
	}
	if _, ok := got["fs.write"]; ok {
		t.Error("an absent list is listed")
	}
	if _, err := Entries([]byte("- a list\n")); err == nil {
		t.Error("a YAML list is not an error")
	}
}
