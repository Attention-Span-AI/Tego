// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestDeclaredOverAProfileStatesNoDefaults (C155): read as text, a file that extends a profile lists its own rules
// alone. A default stated under them ("Cannot run any other program", "Can connect to any address") would claim what
// the profile may or may not add, which the view does not read, so none is stated and the note says why.
func TestDeclaredOverAProfileStatesNoDefaults(t *testing.T) {
	text := "version: 0\nname: ext\nextends: base/mini\ncommand: [bash]\nexec:\n  allow: [bash]\n"
	d, err := Declared([]byte(text), "agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range d.Groups {
		if g.Default != "" || g.Open {
			t.Errorf("group %s states a default over a profile it did not read: %q (open %v)", g.ID, g.Default, g.Open)
		}
	}
	found := false
	for _, n := range d.Notes {
		found = found || strings.Contains(n, "base/mini") && strings.Contains(n, "only this file's own rules")
	}
	if !found {
		t.Errorf("no note says only this file's rules are listed: %q", d.Notes)
	}
	// Without extends the defaults stay: the file is the whole contract.
	whole, _ := Declared([]byte("version: 0\nname: whole\ncommand: [bash]\nexec:\n  allow: [bash]\n"), "agent.yaml")
	if g := whole.Group(GroupPrograms); g.Default != "Cannot run any other program." {
		t.Errorf("a file with no extends lost its default: %q", g.Default)
	}
}

// TestNoteProfilesSaysWhereEachWasRead (C155): the profiles run_start recorded are named with their source, so a view
// never lets a profile's rules pass as the top file's.
func TestNoteProfilesSaysWhereEachWasRead(t *testing.T) {
	v := newView()
	v.NoteProfiles(nil)
	if len(v.Notes) != 0 {
		t.Fatalf("a run with no profiles got a note: %q", v.Notes)
	}
	v.NoteProfiles([]record.ProfileRef{
		{Name: "base/mini", Source: record.ProfileSourceBuiltin, SHA256: "aa"},
		{Name: "team", Source: record.ProfileSourceDir, SHA256: "0123456789abcdef0123456789abcdef"},
	})
	want := "The run merged the profiles base/mini (built into tego), team (the profiles folder, sha256 0123456789ab)."
	if len(v.Notes) != 1 || v.Notes[0] != want {
		t.Errorf("notes %q, want %q", v.Notes, want)
	}
}
